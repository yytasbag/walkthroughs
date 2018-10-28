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