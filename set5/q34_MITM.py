"""
@author rpthi
"""
import socket
import socketserver
import sys
sys.path.append('C:/Users/rpthi/PycharmProjects/cryptopals-challenges/')
from util import CBC, Connector, derive_key, modular_pow

cbc = CBC()
target_host = None
target_port = None


class MITM_TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        global target_host
        global target_port

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((target_host, target_port))
            server_conn = Connector(sock)
            client_conn = Connector(self)

            print('C->A: reading p')
            p = client_conn.read_num()

            print('C->A: reading g')
            g = client_conn.read_num()

            print('C->A: reading A')
            A = client_conn.read_num()

            print('A->S: writing p')
            server_conn.write_num(p)

            print('A->S: writing g')
            server_conn.write_num(g)

            print('A->S: writing p')
            server_conn.write_num(p)

            print('S->A: reading B')
            B = server_conn.read_num()

            print('A->C: writing p')
            client_conn.write_num(p)

            print('C->A: reading encrypted message')
            ctxt = client_conn.read_bytes()

            print('A->S: writing encrypted message')
            server_conn.writebytes(ctxt)

            print('C->A: reading iv')
            iv = client_conn.read_bytes()

            print('A->S: writing iv')
            server_conn.write_bytes(iv)

            print('S->A: reading encrypted message')
            ctxt2 = server_conn.read_bytes()

            print('A->C: writing encrypted message')
            client_conn.write_bytes(ctxt2)

            print('S->A: reading iv')
            iv2 = server_conn.read_bytes()

            print('A->C: writing iv')
            client_conn.write_bytes(iv2)

            key = derive_key(0)
            message = cbc.decrypt_aes128(ctxt, key, iv)

            print('A: message: ' + message)

        finally:
            sock.close()


if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    target_host = sys.argv[3]
    target_port = int(sys.argv[4])

    print('listening on ' + host + ':' + str(port) + ', attacking ' + target_host + ':' + str(target_port))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer((host, port), MITM_TCPHandler)

    server.serve_forever()