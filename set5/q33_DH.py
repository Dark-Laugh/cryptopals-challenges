"""
@author rpthi
"""

from Crypto.Random.random import randint
import sys
sys.path.append('C:/Users/rpthi/PycharmProjects/cryptopals-challenges/')
from util import modular_pow


class KeyExchangeException(Exception):
    pass


def diffie_hellman(p, g, q):
    """executes diffie-hellman key exchange algorithm; adjusted from problem description due to the bias induced
    with their implementation generating a number mod p, instead of mod (p-1)"""
    a = randint(0, q-1)
    A = modular_pow(g, a, p)
    b = randint(0, q-1)
    B = modular_pow(g, b, p)
    return a, A, b, B


def key_exchange(p, g, q):
    """test method"""
    a, A, b, B = diffie_hellman(p, g, q)
    s_A = modular_pow(B, a, p)
    s_B = modular_pow(A, b, p)
    if s_A != s_B:
        raise KeyExchangeException


"""
# test:
p = 37
g = 5
q = p - 1
key_exchange(p, g, q)
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
q = p // 2 - 1
key_exchange(p, g, q)
"""