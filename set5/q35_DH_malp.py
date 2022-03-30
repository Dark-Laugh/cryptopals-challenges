"""
@author rpthi
"""

import sys
import socket
from Crypto.Random.random import randint
from os import urandom
sys.path.append('C:/Users/rpthi/PycharmProjects/cryptopals-challenges/')
from util import CBC, Connector, modular_pow, derive_key


host = sys.argv[1]
port = int(sys.argv[2])
msg = sys.argv[3]
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
a = randint(0, p)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cbc = CBC()
try:
    sock.connect((host, port))
    conn = Connector(sock)
    print('C: Writing p')
    conn.write_num(p)
    print('C: Writing g')
    conn.write_num(g)

    print('C: Reading p')
    ev_p = conn.read_num()
    print('C: Reading g')
    ev_g = conn.read_num()
    A = modular_pow(ev_g, a, ev_p)

    print('C: Writing A')
    conn.write_num(A)
    print('C: Reading B')
    B = conn.read_num()
    s = modular_pow(B, a, ev_p)
    key = derive_key(s)

    iv = urandom(16)
    ctxt = cbc.encrypt_aes128(msg, key, iv)
    print('C: Writing ctxt')
    conn.write_bytes(ctxt)
    print('C: Writing iv')
    conn.write_bytes(iv)

    print('C: Reading ctxt')
    ctxt2 = conn.read_bytes()
    msg2 = cbc.decrypt_aes128(ctxt2, key, iv)
    if msg != msg2:
        raise Exception(msg2 + ' != ' + msg)

finally:
    sock.close()




