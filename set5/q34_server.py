"""
@author rpthi
"""
import socketserver
import sys
from Crypto.Random.random import randint
sys.path.append('C:/Users/rpthi/PycharmProjects/cryptopals-challenges/')
from util import CBC, Connector, derive_key, modular_pow


class DH_TCPHandler(socketserver.StreamRequestHandler):
    cbc = CBC()

    def handle(self) -> None:
        conn = Connector(self)
        print('S: reading p')
        p = conn.read_num()
        print('S: reading g')
        g = conn.read_num()
        print('S: reading A')
        A = conn.read_num()

        b = randint(0, p)
        B = modular_pow(g, b, p)

        print('S: writing B')
        conn.write_num(B)

        s = modular_pow(A, b, p)
        key = derive_key(s)

        print('S: reading ctxt')
        ctxt = conn.read_bytes()
        print('S: reading iv')
        iv = conn.read_bytes()
        msg = self.cbc.decrypt_aes128(ctxt, key, iv)
        print('S: message:', msg)

        ctxt2 = self.cbc.encrypt_aes128(msg, key, iv)
        if ctxt != ctxt2:
            raise Exception(ctxt + b'!=' + ctxt2)

        print('S: writing encrypted message')
        conn.write_bytes(ctxt2)


if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    print('listening on ' + host + ':' + str(port))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer((host, port), DH_TCPHandler)
    server.serve_forever()

