"""
@author rpthi
"""
import sys
import socketserver
from base64 import b64encode
sys.path.append('C:/Users/rpthi/PycharmProjects/cryptopals-challenges/')
from util import modular_pow, Connector

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
        print('S: writing B')
        conn.write_num(B)
        print('S: writing u')
        conn.write_num(u)

        print('S: reading hmac')
        client_hmac = conn.read_bytes()

        print('S writing success')
        print(b'Success')
        print('A: ', A)
        print('client hmac', b64encode(client_hmac))


if __name__ == 'main':
    host = sys.argv[1]
    port = int(sys.argv[2])
    I = sys.argv[3]
    P = sys.argv[4]

    print('Listening on ' + host + ':' + str(port))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer((host, port), SRPTCPHandler)
    server.serve_forever()

