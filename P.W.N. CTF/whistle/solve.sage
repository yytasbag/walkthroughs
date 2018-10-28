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
out = open('out.txt', 'wb')
out.write(c.decrypt(ct))
