"""
@author rpthi
"""

import sys
from base64 import b64decode
sys.path.append('C:/Users/rpthi/PycharmProjects/cryptopals-challenges/')
from util import modular_pow, hash_to_int, hash_to_bytes, hmac


I = ''
P = ''
salt = 0
v = 0

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3

b = 5
B = modular_pow(g, b, N)
u = 1


# mitm dict attack on simple SRP
if __name__ == 'main':
    A = int(sys.argv[1])
    client_hmac = b64decode(sys.argv[2])
    wordlist = open('/usr/share/dict/words').readlines() # wordlist
    l = ''
    for w in wordlist:
        w = w.strip().lower()
        if w[0] != l:
            l = w[0]
            print(l + '...')
        x = hash_to_int(str(salt) + w)
        v = pow(g, x, N)
        S = pow(pow(v, u, N) * A, b, N)
        K = hash_to_bytes(str(S))
        server_hmac = hmac(salt, K)
        if client_hmac == server_hmac:
            print('password', w)
            exit()
    raise Exception('Error: Did not crack password. Reason: Not in wordlist')

