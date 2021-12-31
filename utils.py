"""
@author rpthi
"""
from bitstring import BitArray
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from math import ceil
from base64 import b64decode
from os import urandom
from random import randint
from urllib import parse


def bitwise_xor(A, B):
    """returns bitwise XOR of 2 bytestrings, denoted 'A' and 'B'"""
    # note: python built in '^' only works with integers
    return bytes([a ^ b for (a, b) in zip(A, B)])


def parse_txt_file(ctxt_file):
    """returns list representation of a ciphertext file assuming each new line is a new ciphertext"""
    return [line.strip() for line in ctxt_file]


class NotSingleCharXORException(Exception):
    pass


def hamming_distance(A, B):  # where A and B are byte arrays
    return sum(bit for bit in BitArray(bitwise_xor(A, B)))


def find_vigenere_edit_dist(candidate_length, ctxt):
    """returns normalized hamming distance of a candidate key length"""
    # per instructions: take blocks larger than candidate length
    block_length = candidate_length * 2
    nb_measurements = len(ctxt) // block_length - 1
    sum_dist = 0
    for i in range(nb_measurements):
        # could have done this with list comprehension as well
        block_A = ctxt[slice(i*block_length, i*block_length + candidate_length)]
        block_B = ctxt[slice(i*block_length + candidate_length, i*block_length + 2*candidate_length)]
        sum_dist += hamming_distance(block_A, block_B)
    # normalize hamming distance sum
    sum_dist /= (candidate_length * nb_measurements)
    return sum_dist


def estimate_vigenere_key_length(ctxt):  # create blocks for repeated keystream
    """return candidate key length with minimum hamming distances between created blocks"""
    return min(range(2, 41), key=lambda x: find_vigenere_edit_dist(x, ctxt))


def pad_PKCSN7(txt, block_length):
    pad_length = block_length - (len(txt) % block_length)
    if pad_length == 0:
        pad_length = block_length
    padded = txt + bytes([pad_length]) * pad_length
    return padded


def unpad_PKCSN7(txt):
    padding = txt[-1]
    return txt[:-padding]


def slice_to_blocks(txt, block_length):
    return [txt[i*block_length:(i+1)*block_length] for i in range(ceil(len(txt)/block_length))]


class ECB:
    def __init__(self):
        self.backend = default_backend()
        self.block_length = 16

    def encrypt_aes128_unpadded(self, msg, key):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        return encryptor.update(msg) + encryptor.finalize()

    def decrypt_aes128_unpadded(self, ctxt, key):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        ptxt = decryptor.update(ctxt) + decryptor. finalize()
        return ptxt

    def encrypt_aes128(self, msg, key):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        ptxt = pad_PKCSN7(msg, self.block_length)
        return encryptor.update(ptxt) + encryptor.finalize()

    def decrypt_aes128(self, ctxt, key):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        ptxt = decryptor.update(ctxt) + decryptor. finalize()
        return unpad_PKCSN7(ptxt)


class CBC:
    def __init__(self):
        self.backend = default_backend()
        self.block_length = 16
        self.ecb = ECB()

    def encrypt_aes128(self, msg, key, iv):
        ptxt = pad_PKCSN7(msg, self.block_length)
        blocks = slice_to_blocks(ptxt, self.block_length)
        ctxt = b''
        prev_ctxt = iv
        for block in blocks:
            tmp = bitwise_xor(block, prev_ctxt)
            new_ctxt = self.ecb.encrypt_aes128_unpadded(tmp, key)
            ctxt += new_ctxt
            prev_ctxt = new_ctxt
        return ctxt

    def decrypt_aes128_simple(self, ctxt, key, iv):
        blocks = slice_to_blocks(ctxt, self.block_length)
        ptxt = b''
        prev_ctxt = iv
        for block in blocks:
            tmp = self.ecb.decrypt_aes128_unpadded(block, key)
            ptxt += bitwise_xor(tmp, prev_ctxt)
            prev_ctxt = block
        return unpad_PKCSN7(ptxt)

    def decrypt_aes128(self, ctxt, key, iv):
        blocks = slice_to_blocks(ctxt, self.block_length)
        ptxt = b''
        prev_ctxt = iv
        for block in blocks:
            tmp = self.ecb.decrypt_aes128_unpadded(block, key)
            ptxt += bitwise_xor(tmp, prev_ctxt)
            prev_ctxt = block
        return unpad_valid_PKCSN7(ptxt, self.block_length)


class Simple_ECB_Oracle:
    def __init__(self):
        self.ecb = ECB()
        self.target = b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                                'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                                'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                                'YnkK')
        self.key = urandom(16)

    def encrypt(self, msg):
        return self.ecb.encrypt_aes128(msg + self.target, self.key)


class Hard_ECB_Oracle:
    def __init__(self):
        self.ecb = ECB()
        self.target = b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                                'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                                'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                                'YnkK')
        self.key = urandom(16)
        self.prefix = urandom(randint(0, 256))  # there could be no prefix

    def encrypt(self, msg):
        return self.ecb.encrypt_aes128(self.prefix + msg + self.target, self.key)


class PadError(Exception):
    pass


def unpad_valid_PKCSN7(txt, block_length):
    if len(txt) % block_length != 0:
        raise PadError
    padding = txt[-1]
    pad_length = int(padding)
    if not txt.endswith(bytes([padding])*pad_length) or padding == 0 or pad_length == 0:  # having both is redundant
        raise PadError
    return txt[:-pad_length]




