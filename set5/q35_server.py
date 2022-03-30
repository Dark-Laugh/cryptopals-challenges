"""
@author rpthi
"""
import socketserver
import sys
sys.path.append('C:/Users/rpthi/PycharmProjects/cryptopals-challenges/')
from util import Connector, modular_pow, derive_key, CBC
from Crypto.Random.random import randint


class DH_TCPHandler(socketserver.StreamRequestHandler):
    cbc = CBC()

    def handle(self) -> None:
        conn = Connector(self)

        print('S: Reading p')
        p = conn.read_num()
        print('S: Reading g')
        g = conn.read_num()

        print('S: Writing p')
        conn.write_num(p)
        print('S: Writing g')
        conn.write_num(g)

        print('S: Reading A')
        A = conn.read_num()
        b = randint(0, p)
        B = modular_pow(g, b, p)

        print('S: Writing B')
        conn.write_num(B)

        s = modular_pow(A, b, p)
        key = derive_key(s)

        print('S: Reading ctxt')
        ctxt = conn.read_bytes()
        print('S: Reading iv')
        iv = conn.read_bytes()
        msg = self.cbc.decrypt_aes128(ctxt, key, iv)
        print('S: Message: ', msg)

        ctxt2 = self.cbc.encrypt_aes128(msg,key, iv)
        if ctxt != ctxt2:
            raise Exception(ctxt2 + b' != ' + ctxt)

        print('S: Writing ctxt')
        conn.write_bytes(ctxt2)


host = sys.argv[1]
port = int(sys.argv[2])

print('listening on ' + host + ':' + str(port))
socketserver.TCPServer.allow_reuse_address = True
server = socketserver.TCPServer((host, port), DH_TCPHandler)

server.serve_forever()
