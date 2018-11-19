from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes



def rotl(c):
    return ((c << 1) | (c >> 7)) & 0xff


def rotr(c):
    return ((c >> 1) | (c << 7)) & 0xff


def pad(s):
    ll = len(s) % 4

    if ll == 0:
        return s
    else:
        return s + b'\x00' * (4 - ll)


def group(s, l=4):
    return [s[i: i + l] for i in range(0, len(s), l)]


def alpha(w):
    return [w[1], w[0]]


def beta(w):
    w[0][0] ^= w[1][3]
    w[0][1] ^= w[1][2]
    w[0][2] ^= w[1][1]
    w[0][3] ^= w[1][0]
    return w


def gamma(w):
    n = []
    for r in w:
        for c in r:
            n.append(c)

    n = group(bytearray(n))
    n[0][3] = w[0][0]
    n[1][2] = w[0][1]
    n[1][3] = w[0][2]
    n[1][1] = w[0][3]
    n[0][1] = w[1][0]
    n[1][0] = w[1][1]
    n[0][2] = w[1][2]
    n[0][0] = w[1][3]
    return n


def delta(w):
    w[0][0] = rotl(w[0][0])
    w[1][0] = rotl(w[1][0])
    w[0][2] = rotl(w[0][2])
    w[1][2] = rotl(w[1][2])
    w[0][1] = rotr(w[0][1])
    w[1][1] = rotr(w[1][1])
    w[0][3] = rotr(w[0][3])
    w[1][3] = rotr(w[1][3])
    return w


def f(w):
    for i in range(50):
            w = alpha(w)
            w = beta(w)
            w = gamma(w)
            w = delta(w)
    return w


def hash(m):
    s = bytearray([31, 56, 156, 167, 38, 240, 174, 248])
    m = bytearray(m)
    m = pad(m)
    m = group(m)
    w = [s[:4], s[4:]]
    for g in m:
        w[0] = bytearray(strxor(w[0], g))
        w = f(w)
        s = w[0] + w[1]
    from binascii import hexlify
    return hexlify(s[:4])


def solve():
    hashes = set()
    table = dict()
    i = 0
    while True:
        if i % 1000 == 0:
            print(len(hashes))

        m = get_random_bytes(10)
        from base64 import b64encode as encode
        m = encode(m)
        h = hash(m)

        if h in hashes and table[h] != m:
            print("Found Collision:")
            print(m)
            print(table[h])
            break
        table[h] = m
        hashes.add(h)
        i += 1


solve()
