import itertools
import sys
from binascii import unhexlify

import datetime
import scrypt
import threading
from Crypto.Cipher import AES
from simplebitcoinfuncs import normalize_input, b58d, hexstrlify, dechex, privtopub, compress, pubtoaddress, b58e, \
    multiplypriv
from simplebitcoinfuncs.ecmath import N
from simplebitcoinfuncs.hexhashes import hash256


def simple_aes_decrypt(msg, key):
    assert len(msg) == 16
    assert len(key) == 32
    cipher = AES.new(key, AES.MODE_ECB)
    msg = hexstrlify(cipher.decrypt(msg))
    while msg[-2:] == '7b':  # Can't use rstrip for multiple chars
        msg = msg[:-2]
    for i in range((32 - len(msg)) // 2):
        msg = msg + '7b'
    assert len(msg) == 32
    return unhexlify(msg)


def bip38decrypt(password, encpriv, outputlotsequence=False):
    password = normalize_input(password, False, True)
    encpriv = b58d(encpriv)
    assert len(encpriv) == 78
    prefix = encpriv[:4]
    assert prefix == '0142' or prefix == '0143'
    flagbyte = encpriv[4:6]
    if prefix == '0142':
        salt = unhexlify(encpriv[6:14])
        msg1 = unhexlify(encpriv[14:46])
        msg2 = unhexlify(encpriv[46:])
        scrypthash = hexstrlify(scrypt.hash(password, salt, 16384, 8, 8, 64))
        key = unhexlify(scrypthash[64:])
        msg1 = hexstrlify(simple_aes_decrypt(msg1, key))
        msg2 = hexstrlify(simple_aes_decrypt(msg2, key))
        half1 = int(msg1, 16) ^ int(scrypthash[:32], 16)
        half2 = int(msg2, 16) ^ int(scrypthash[32:64], 16)
        priv = dechex(half1, 16) + dechex(half2, 16)
        if int(priv, 16) == 0 or int(priv, 16) >= N:
            if outputlotsequence:
                return False, False, False
            else:
                return False
        pub = privtopub(priv, False)
        if flagbyte in COMPRESSION_FLAGBYTES:
            privcompress = '01'
            pub = compress(pub)
        else:
            privcompress = ''
        address = pubtoaddress(pub, '00')
        try:
            addrhex = hexstrlify(address)
        except:
            addrhex = hexstrlify(bytearray(address, 'ascii'))
        addresshash = hash256(addrhex)[:8]
        if addresshash == encpriv[6:14]:
            priv = b58e('80' + priv + privcompress)
            if outputlotsequence:
                return priv, False, False
            else:
                return priv
        else:
            if outputlotsequence:
                return False, False, False
            else:
                return False
    else:
        owner_entropy = encpriv[14:30]
        enchalf1half1 = encpriv[30:46]
        enchalf2 = encpriv[46:]
        if flagbyte in LOTSEQUENCE_FLAGBYTES:
            lotsequence = owner_entropy[8:]
            owner_salt = owner_entropy[:8]
        else:
            lotsequence = False
            owner_salt = owner_entropy
        salt = unhexlify(owner_salt)
        prefactor = hexstrlify(scrypt.hash(password, salt, 16384, 8, 8, 32))
        if lotsequence is False:
            passfactor = prefactor
        else:
            passfactor = hash256(prefactor + owner_entropy)
        if int(passfactor, 16) == 0 or int(passfactor, 16) >= N:
            if outputlotsequence:
                return False, False, False
            else:
                return False
        passpoint = privtopub(passfactor, True)
        password = unhexlify(passpoint)
        salt = unhexlify(encpriv[6:14] + owner_entropy)
        encseedb = hexstrlify(scrypt.hash(password, salt, 1024, 1, 1, 64))
        key = unhexlify(encseedb[64:])
        tmp = hexstrlify(simple_aes_decrypt(unhexlify(enchalf2), key))
        enchalf1half2_seedblastthird = int(tmp, 16) ^ int(encseedb[32:64], 16)
        enchalf1half2_seedblastthird = dechex(enchalf1half2_seedblastthird, 16)
        enchalf1half2 = enchalf1half2_seedblastthird[:16]
        enchalf1 = enchalf1half1 + enchalf1half2
        seedb = hexstrlify(simple_aes_decrypt(unhexlify(enchalf1), key))
        seedb = int(seedb, 16) ^ int(encseedb[:32], 16)
        seedb = dechex(seedb, 16) + enchalf1half2_seedblastthird[16:]
        assert len(seedb) == 48  # I want to except for this and be alerted to it
        try:
            factorb = hash256(seedb)
            assert int(factorb, 16) != 0
            assert not int(factorb, 16) >= N
        except:
            if outputlotsequence:
                return False, False, False
            else:
                return False
        priv = multiplypriv(passfactor, factorb)
        pub = privtopub(priv, False)
        if flagbyte in COMPRESSION_FLAGBYTES:
            privcompress = '01'
            pub = compress(pub)
        else:
            privcompress = ''
        address = pubtoaddress(pub, '00')
        try:
            addrhex = hexstrlify(address)
        except:
            addrhex = hexstrlify(bytearray(address, 'ascii'))
        addresshash = hash256(addrhex)[:8]
        if addresshash == encpriv[6:14]:
            priv = b58e('80' + priv + privcompress)
            if outputlotsequence:
                if lotsequence is not False:
                    lotsequence = int(lotsequence, 16)
                    sequence = lotsequence % 4096
                    lot = (lotsequence - sequence) // 4096
                    return priv, lot, sequence
                else:
                    return priv, False, False
            else:
                return priv
        else:
            if outputlotsequence:
                return False, False, False
            else:
                return False


def testPassword(pwd):
    try:
        if bip38decrypt(pwd, encryptedSecret) != False:
            pwdLenth = 22 + len(pwd)
            print("\n\n" + "#" * pwdLenth + "\n## PASSWORD FOUND: {pwd} ##\n".format(pwd=pwd) + "#" * pwdLenth + "\n")
            global flag
            flag = 1
    except:
        pass
    finally:
        td.release()


if __name__ == '__main__':
    COMPRESSION_FLAGBYTES = ['20', '24', '28', '2c', '30', '34', '38', '3c', 'e0', 'e8', 'f0', 'f8']
    LOTSEQUENCE_FLAGBYTES = ['04', '0c', '14', '1c', '24', '2c', '34', '3c']

    encryptedSecret = input(
        "Input The EncryptedSecret(eg: 6PYLPNjNnGg9ofuKydMvGDxqTEwxDqfykvGesNHQyRkFTpkjmvzSXmHLnc)\ndefault is 6PYK9gL2qKNYatT6Jrong5CaAJ2d6mv5iNBYfrjwuTbDXLaYvzcncZ3uVQ\n--> ")
    if len(encryptedSecret) == 0:
        encryptedSecret = "6PYK9gL2qKNYatT6Jrong5CaAJ2d6mv5iNBYfrjwuTbDXLaYvzcncZ3uVQ"

    threadNum = input("Input The Number Of Threads(eg: 25)\ndefault is 25\n--> ")
    if len(threadNum) == 0:
        threadNum = 25

    pwdKeys = input(
        "Input All The Characters If Your Password Might Contain(eg: 123 test 1024 . p@ss lol 0-0 shit)\ndefault is 0 1 2 3 4 5 6 7 8 9\n--> ").split()
    if len(pwdKeys) == 0:
        pwdKeys = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

    maxCombination = input("Max Combination(eg: 6)\ndefault is 6\n--> ")
    if len(maxCombination) == 0:
        maxCombination = 6

    maxLength = input("Maximum Password Length(eg: 18)\ndefault is 18\n--> ")
    if len(maxLength) == 0:
        maxLength = 18

    td = threading.BoundedSemaphore(int(threadNum))
    threadlist = []

    print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    num = 0
    flag = 0
    for i in range(len(pwdKeys)):
        if flag == 1:
            break

        if i + 1 > int(maxCombination):
            break
        for pwd in itertools.product(pwdKeys, repeat=i + 1):
            if flag == 1:
                break

            password = "".join(pwd)
            if len(password) <= int(maxLength):
                num += 1
                msg = 'Test Password {num} , {password}'.format(num=num, password=password)
                sys.stdout.write('\r' + msg)
                sys.stdout.flush()
                td.acquire()
                t = threading.Thread(target=testPassword, args=(password,))
                t.start()
                threadlist.append(t)
    for x in threadlist:
        x.join()

    print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
