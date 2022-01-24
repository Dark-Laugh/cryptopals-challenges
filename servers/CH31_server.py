"""
@author rpthi
"""


from time import sleep
from binascii import unhexlify
from util.utils import SHA1, bitwise_xor
from urllib import request
from web import application, ctx, input as web_input
urls = (
    '/ping', 'pinger',
    '/hmac', 'hmac_page'
)

KEY = b'YELLOW SUBMARINE'
BLOCK_SIZE = 64
DELAY = 0.050  # sleep 50 ms
IP = 'localhost'
PORT = 8080


def sha1(txt):  # lowercase letters to differentiate between class
    return SHA1(txt).get_hash()


def HMAC_SHA1(key, msg):
    """HMAC SHA1 according to the wiki: https://en.wikipedia.org/wiki/HMAC"""
    if len(key) > BLOCK_SIZE:
        key = unhexlify(sha1(key))
    if len(key) < BLOCK_SIZE:
        key += b'\x00' * (BLOCK_SIZE - len(key))
    o_pad = bitwise_xor(b'\x5c'*64, key)
    i_pad = bitwise_xor(b'\x36'*64, key)
    return sha1(o_pad + unhexlify(sha1(i_pad+msg)))


def insecure_compare(x, y):
    """per instructions, implements the == operation by doing byte-at-a-time comparisons with early exit"""
    if len(x) != len(y):
        return False
    for i, j in zip(x, y):
        if i != j:
            return False
        sleep(DELAY)
    return True


def validate_signature(file, signature):
    global KEY
    try:
        response = request.urlopen(f'http://{IP}:{PORT}/test?file={file}&signature={signature}').read()
        if response == b'200':
            return True
        elif response == b'500':
            return False
        else:
            raise
    except Exception as e:
        print(e)


class pinger:
    def GET(self) -> str:
        ctx.status = '200 OK'
        return 'explicit 200'


class hmac_page:
    def POST(self) -> str:
        data = web_input()
        valid = validate_signature(data.file, data.sig)
        if valid:
            ctx.status = '200 OK'
            return 'explicit 200'
        else:
            ctx.status = '500 Internal Server Error'
            return 'explicit 500'


def main():
    app = application(urls, globals())
    app.run()
