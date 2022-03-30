"""
@author rpthi
"""

from Crypto.Random.random import randint
import socketserver
from os import urandom
import sys
sys.path.append('C:/Users/rpthi/PycharmProjects/cryptopals-challenges/')
from util import Connector, modular_pow, hash_to_bytes, get_salt, hash_to_int, hmac


I = ''
P = ''
salt = 0
v = 0

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3

class SRPTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        global I
        global P
        conn = Connector(self)

        print('S: reading email')
        read_I = conn.read_line()
        print('S: reading A')
        A = conn.read_num()

        print('S: writing salt')
        conn.write_num(salt)

        b = randint(0, N)
        B = modular_pow(g, b, N)
        print('S: writing B')
        conn.write_num(B)

        u = urandom(128)
        print('S: writing u')
        conn.write_num(u)

        S = modular_pow(modular_pow(v, u, N) * A, b, N)
        K = hash_to_bytes(str(S))
        server_hmac = hmac(salt, K)
        print('S: reading hmac')
        client_hmac = conn.read_bytes()

        if server_hmac == client_hmac:
            print('S: writing success')
            conn.write_line(b'Success')
        else:
            conn.read_line(b'Unsuccessful')


if __name__ == 'main':
    host = sys.argv[1]
    port = sys.arv[2]
    I = sys.argv[3]
    P = sys.argv[4]
    salt = get_salt()
    x = hash_to_int(str(salt) + P)
    v = modular_pow(g, x, N)

    print('Listening on ' + host + ':' + str(port))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer((host, port), SRPTCPHandler)
    server.serve_forever()




