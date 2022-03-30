"""
@author rpthi
"""
import socket
import sys
sys.path.append('C:/Users/rpthi/PycharmProjects/cryptopals-challenges/')
from util import Connector, hash_to_bytes, hmac

host = sys.argv[1]
port = int(sys.argv[2])
I = sys.argv[3]
P = sys.argv[4]
m = int(sys.argv[5])

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect((host, port))
    conn = Connector(sock)

    print('C: writing email')
    conn.write_line(I.encode('ascii'))

    A = m * N
    print('C: writing A')
    conn.write_num(A)

    print('C: reading salt')
    salt = conn.read_num()

    print('C: reading B')
    B = conn.read_num()

    S = 0  # attack with zero key
    K = hash_to_bytes(str(S))
    client_hmac = hmac(salt, K)

    print('C: writing hmac')
    conn.write_bytes(client_hmac)

    print('C: reading result')
    res = conn.read_line()

    print('result: ', res)

finally:
    sock.close()






