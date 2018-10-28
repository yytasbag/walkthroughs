This is a write up for the Whistle (Crypto 250 + 220) task in [P.W.N. CTF](https://uni.hctf.fun)

#Introduction
For the last couple of months I have been interested in Cryptography and whenever I have the time I try to solve crypto tasks in ctfs. Anyway I hope you like it.
Contact: @yamantasbagv2

#Challenge Description
```
Our university has a new on campus [whistle blowing system](http://dl1.uni.hctf.fun/whistle/whistle_blower.zip). I want to get the latest campus leakz first hand, so I sniffed the network traffic of the latest submission. 
Unfortunately the system uses 31337 crypto. Can you still recover the message? 
[Download Traffic](http://dl1.uni.hctf.fun/whistle/whistle.pcap)
[System MIRROR Traffic MIRROR](http://dl2.uni.hctf.fun/whistle/whistle.pcap)
```

#Unpacking

Contents of the whistle_blower.zip is the following: blow_whistle.py and pubkey.pem
```
import os
from ftplib import FTP
from sys import argv
from tempfile import TemporaryFile
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES


class Encrypter:
    """
    Encrypts a given message or file with a random AES key.
    This AES key is then encrypted using the given RSA public key.
    """
    BLOCK_SIZE = 16
    KEY_SIZE = 16

    def __init__(self, rsa_path):
        self.rsa_key = RSA.importKey(open(rsa_path).read())

    def _pad_symmetric(self, msg):
        """
        Adds PKCS#7 padding for symmetric encryption to given message.
        """
        missing = 16 - (len(msg) % self.BLOCK_SIZE)

        return msg + missing.to_bytes(1, "big") * missing

    def _pad_asymmetric(self, msg):
        """
        Adds PKCS 1 v1.5 padding for assymetric encryption to given message.
        """
        BT = b"\x01"
        PS = b"\xFF" * ((self.rsa_key.size()//8) - 3 - len(msg))
        return b"\x00" + BT + PS + b"\x00" + msg

    def _encrypt_aes(self, key, iv, plaintext):
        """
        Encrypts plaintext with AES CBC
        """
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(self._pad_symmetric(plaintext))

    def _encrypt_aes_randkey(self, plaintext):
        """
        Encrypts plaintext with random AES key.
        """
        key = os.urandom(self.KEY_SIZE)
        iv = os.urandom(self.BLOCK_SIZE)

        return key, self._encrypt_aes(key, iv, plaintext)

    def _encrypt_rsa(self, msg):
        """
        Encrypts message with given RSA public key.
        """
        return self.rsa_key.encrypt(self._pad_asymmetric(msg), -1)[0]

    def encrypt_msg(self, msg):
        """
        Encrypt a message with random key AES CBC and return ciphertext
        together with RSA encrypted key.
        """
        key, ct = self._encrypt_aes_randkey(msg)
        key_enc = self._encrypt_rsa(key)
        return key_enc, ct


def get_tempfile(content):
    fp = TemporaryFile()
    fp.write(content)
    fp.seek(0)
    return fp


class Communicator:
    """
    Takes message or file and sends it encrypted to remote ftp server.
    """

    def __init__(self, server, pubkey):
        self.server = server
        self.encrypter = Encrypter(pubkey)

    def _send(self, key, ct):
        with FTP(self.server) as ftp:
            ftp.login()
            ftp.cwd("submit")
            remote_name = sha256(ct).hexdigest()

            with get_tempfile(ct) as content_file:
                ftp.storbinary("STOR {}".format(remote_name), content_file)
            with get_tempfile(key) as key_file:
                ftp.storbinary("STOR {}".format(remote_name + "_key"), key_file)

    def send_msg(self, msg):
        key, ct = self.encrypter.encrypt_msg(msg)
        self._send(key, ct)

    def send_file(self, path):
        with open(path, "rb") as f:
            content = f.read()
        self.send_msg(content)


def main():
    if len(argv) != 2:
        print("Call {} FILE_TO_SEND".format(argv[0]))
        exit(1)
    com = Communicator('192.168.69.123', 'pubkey.pem')
    print("Encrypting and sending file!")
    com.send_file(argv[1])
    print("Done!")


if __name__ == '__main__':
    main()
```

In pubkey we have the public key for the RSA part of the challange.

In the given pcap file there are two files transfered over ftp which I extracted them using NetworkMiner and renamed them to flag and key. This will make sense in the next section.

#Understanding the Protocol
The protocol works as the following:

1. Encrypt the given file with AES128-CBC, random key, IV and PKCS#7 padding
2. Pack IV with ciphertext and send it to the ftp server
3. Pad aes key with PKCS 1 v1.5
4. Encrypt it with the RSA public key
5. Send Encrypted AES key to the ftp server

#The Vulnerability

I am not capable of breaking AES128 without a oracle of some sorts if the key is generated properly. So I focused on breaking the RSA encryption. After examining the public key I noticed that e = 3 and modulus was 4096 bits long. Since aes key is 128 bits long we could easily take the cube root of the encrypted aes key and decipher it. However, RSA padding is present therefore cube root method will not work but seeing e=3 makes me a happy man because there are many attacks taking advantage of low public exponent.

Since our last plan was stopped by the RSA padding I have taken a close look into it.
```
    def _pad_asymmetric(self, msg):
        """
        Adds PKCS 1 v1.5 padding for assymetric encryption to given message.
        """
        BT = b"\x01"
        PS = b"\xFF" * ((self.rsa_key.size()//8) - 3 - len(msg))
        return b"\x00" + BT + PS + b"\x00" + msg
```

If I am not wrong this is actually a "wrong" or "mixed" implementation. This is the padding for signing not encryption. The problem here is the following, if the lenght of the message is known the padding is deterministic and we can calculate it. Consider the following polynomial:
f(x) = ((PAD + x) ^ e - CT) % N
PAD is the deterministic padding, e is the public exponent, N is the public modulus and CT is the cipher text.

One of the root of f is our AES-key (Think about it). Coppersmith's attack allows us to find such root. However the folowing must be true.
root X must be smaller than N^(1/e)
This is true since log(N,2)/3 > 1000 > 128 (Key is 128 bits long)

#The Attack
I have conducted the attack using sagemath since it already implements coppersmit attack as small_roots()

```
 from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from math import log
from Crypto.Cipher import AES

p = open('pubkey.pem').read()
ak = open('key', 'rb').read()
ak = bytes_to_long(ak)
ct = open('flag', 'rb').read()
r = RSA.importKey(p)

def pad(msg):
    global r
    """
    Adds PKCS 1 v1.5 padding for assymetric encryption to given message.
    """
    BT = b"\x01"
    PS = b"\xFF" * ((r.size()//8) - 3 - len(msg))
    return b"\x00" + BT + PS + b"\x00" + msg

base = pad(b"\x00" * 16)
base = bytes_to_long(base)

K = Zmod(r.n)
P.<x> = PolynomialRing(K, implementation='NTL')
f = (base + x) ^ r.e - ak
ak = f.small_roots()[0]
ak = long_to_bytes(ak)

iv = ct[:16]
ct = ct[16:]
c = AES.new(ak, AES.MODE_CBC, iv)
out = open('flag.png', 'wb')
out.write(c.decrypt(ct))

```
The flag turned out to be a png file which had the flag written on it.
![Flag](https://raw.githubusercontent.com/yytasbag/walkthroughs/master/P.W.N.%20CTF/whistle/flag.png)
#Conclusion
I had fun particapating the P.W.N. CTF. This task was not that hard but there were 6 solves at the end of the ctf. I would recommend this CTF its diffuculty was ok and the tasks were fun.

Relevant files can be found [here](https://github.com/yytasbag/walkthroughs/tree/master/P.W.N.%20CTF/whistle)
