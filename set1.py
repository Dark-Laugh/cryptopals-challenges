"""
@author rpthi
"""
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode


# challenge 1
def hex_to_b64(hex_str):
    return b64encode(unhexlify(hex_str))


def b64_to_hex(b64_str):  # extra method, not in challenge
    return hexlify(b64decode(b64_str))

# challenge 2


"""
# challenge 1 test:
hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
b64_str = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
assert hex_to_b64(hex_str) == b64_str
assert b64_to_hex(b64_str) == hex_str.encode()
"""
