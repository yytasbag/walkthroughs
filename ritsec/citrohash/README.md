#CitroHash Crypto 150
##Introduction
This weekend I attended RITSEC CTF. Most of the crypto tasks were not for me because most of them were ciphertext only which I don't like and think it does not make much sense. However this task was fun because it used a sponge-like (as in SHA3 keccak) system which I was trying to get familiar with. The idea behind the task was simple the hash function had entropy of 4 bytes and the task was to find (ascii printable?) collision. 
##Task Description
```
See the attached PDF for an amazing new Cryptographic Hash Function called CictroHash. For this challenge you must implement the described Hash Function and then find a collision of two strings. Once a collision is found send both strings to fun.ritsec.club:8003 as a HTTP POST request like below:

curl -X POST http://fun.ritsec.club:8003/checkCollision \
--header "Content-Type: application/json" \
--data '{"str1": "{{INSERT_STR1}}", "str2": "{{INSERT_STR2}}"}'
If the strings are a valid collision then the flag will be returned.

NOTE: requests to this server are being rate-limited for obvious reasons.

Author: Cictrone
```

[PDF](https://github.com/yytasbag/walkthroughs/blob/master/ritsec/citrohash/CictroHash.pdf)

##Vulnerability
The problem with this hash function was its small hash space there were 2^32 unique hashes. We can perform a (birthday attack)[https://en.wikipedia.org/wiki/Birthday_attack] and find a collision in a reasonable time.

I have generated 10 randombytes and base64 encoded them to get a ascii printable collision

The following is my implementation of CitroHash and the attack.


```
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
```

##Collision

Found Collision:
oKB178HHTrKMjg==
utq+fCljIeDLdg==


##Flag
RITSEC{I_am_th3_gr3@t3st_h@XOR_3v@}

##Final Thoughts
Trying to implement a sponge-like system was fun and I'd recommend doing so for crypto enthusiasts but during the ctf the sample plaintext-hash pairs were wrong and the algorithm behaved differently in the documents and in the server-side which was not fun for the participants. In the end, this was a fun challange.
Relevant file can be found (here)[https://github.com/yytasbag/walkthroughs/blob/master/ritsec/citrohash/]
