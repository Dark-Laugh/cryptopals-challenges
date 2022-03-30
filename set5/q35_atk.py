"""
@author rpthi
"""
import socketserver
import socket
import sys
sys.path.append('C:/Users/rpthi/PycharmProjects/cryptopals-challenges/')
from util import Connector, derive_key, CBC


target_host = None
target_port = None
target_g = None
cbc = CBC()


class ATK_TCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        global target_host
        global target_port
        global target_g
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((target_host, target_port))
            server_conn = Connector(sock)
            client_conn = Connector(self)
            print('C->A: Reading p')
            p = client_conn.read_num()
            print('C->A: Reading g')
            g = client_conn.read_num()

            print('A->S: Writing p')
            server_conn.write_num(p)

            if target_g > 0:
                malicious_g = 1
            elif target_g < 0:
                malicious_g = p-1
            else:
                malicious_g = p

            print('A->S: Writing malicious g')
            server_conn.write_num(malicious_g)

            print('S->A: Reading p')
            server_conn.read_num()  # value doesn't matter, just execute it
            print('S->A: Reading g')
            server_conn.read_num()

            print('A->C: Writing p')
            client_conn.write_num(p)
            print('A->C: Writing malicious g')
            client_conn.write_num(malicious_g)

            print('C->A: Reading A')
            A = client_conn.read_num()
            print('A->S: Writing A')
            server_conn.write_num(A)

            print('S->A: Reading B')
            B = server_conn.read_num()
            print('A->C: Writing B')
            client_conn.write_num(B)

            print('C->A: Reading ctxt')
            ctxt = client_conn.read_bytes()
            print('A->S: Writing ctxt')
            server_conn.write_bytes(ctxt)

            print('C->A: Reading iv')
            iv = client_conn.read_bytes()
            print('A->S: Writing iv')
            server_conn.write_bytes(iv)

            print('S->A: Reading ctxt')
            ctxt2 = server_conn.read_bytes()
            print('A->C: Writing ctxt')
            client_conn.write_bytes(ctxt2)

            print('S->A: Reading iv')
            iv2 = server_conn.read_bytes()
            print('A->C: Writing iv')
            client_conn.write_bytes(iv2)

            if target_g > 0:
                s = 1
            elif target_g < 0:
                if A == p-1 and B == p-1:
                    s = p-1
                else:
                    s = 1
            else:
                s = 0
            key = derive_key(s)
            msg = cbc.decrypt_aes128(ctxt, key, iv)
            print('A: Message: ', msg)

        finally:
            sock.close()


if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    target_host = sys.argv[3]
    target_port = int(sys.argv[4])
    target_g = int(sys.argv[5])
    print('Listening for ' + host + ':' + str(port) + ', attacking ' + target_host + ':' + str(target_port))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer((host, port), ATK_TCPHandler)
    server.serve_forever()