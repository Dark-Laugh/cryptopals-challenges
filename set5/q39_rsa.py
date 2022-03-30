"""
@author rpthi
"""

from Crypto.Util.number import getPrime
import sys
sys.path.append('C:/Users/rpthi/PycharmProjects/cryptopals-challenges/')
from util import modular_pow


def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def gcd(a, b):  # Euclidean algorithm
    while b != 0:
        a, b = b, a % b
    return a


def lcm(a, b):
    return (a * b) // gcd(a, b)


def inv_mod(a, n):  # extended Euclidean algorithm
    t, s = 0, n
    t_, s_ = 1, a

    while s_ != 0:
        q = s // s_
        t, t_  = t_, t - q * t_
        r, r_ = r_, r - q * r_

    if r > 1:
        raise Exception('Given "a" is not invertible')
    if t < 0:
        t += n

    return t


class RSA:
    def __init__(self, key_length):
        self.e = 3  # fixed e

        phi = 0
        while gcd(self.e, phi) != 1:
            p, q = getPrime(key_length//2), getPrime(key_length//2)
            phi = lcm(p-1, q-1)
            self.n = p * q

        self.d = inv_mod(self.e, phi)

    def encrypt(self, ptxt):
        data = int.from_bytes(ptxt, byteorder='big')
        return modular_pow(data, self.e, self.n)

    def decrypt(self, ctxt):
        data = modular_pow(ctxt, self.d, self.n)
        return int_to_bytes(data)


if __name__ == 'main':
    assert inv_mod(17, 3120) == 2753
    rsa = RSA(1024)
    ptxt = b'Yellow Submarine'
    assert rsa.decrypt(rsa.encrypt(ptxt)) == ptxt
