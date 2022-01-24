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
from itertools import zip_longest
from struct import unpack, pack
from binascii import hexlify


def bitwise_xor(A, B, longest=True):
    # longest is modification for set3 challenge 18 (and beyond)
    # necessary since generator is infinite, so take the string length corresponding to non-generator parameter length
    """returns bitwise XOR of 2 bytestrings, denoted 'A' and 'B'"""
    # note: python built in '^' only works with integers
    if longest:
        return bytes([a ^ b for (a, b) in zip_longest(A, B, fillvalue=0)])
    else:
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

    def encrypt_aes128_block(self, msg, key):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        return encryptor.update(msg) + encryptor.finalize()

    def decrypt_aes128_block(self, ctxt, key):
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
            new_ctxt = self.ecb.encrypt_aes128_block(tmp, key)
            ctxt += new_ctxt
            prev_ctxt = new_ctxt
        return ctxt

    def decrypt_aes128_simple(self, ctxt, key, iv):
        blocks = slice_to_blocks(ctxt, self.block_length)
        ptxt = b''
        prev_ctxt = iv
        for block in blocks:
            tmp = self.ecb.decrypt_aes128_block(block, key)
            ptxt += bitwise_xor(tmp, prev_ctxt)
            prev_ctxt = block
        return unpad_PKCSN7(ptxt)

    def decrypt_aes128(self, ctxt, key, iv):
        blocks = slice_to_blocks(ctxt, self.block_length)
        ptxt = b''
        prev_ctxt = iv
        for block in blocks:
            tmp = self.ecb.decrypt_aes128_block(block, key)
            ptxt += bitwise_xor(tmp, prev_ctxt)
            prev_ctxt = block
        return unpad_valid_PKCSN7(ptxt, self.block_length)

    def decrypt_aes128_keep_PCSN7(self, ctxt, key, iv):
        blocks = slice_to_blocks(ctxt, self.block_length)
        ptxt = b''
        prev_ctxt = iv
        for block in blocks:
            tmp = self.ecb.decrypt_aes128_block(block, key)
            ptxt += bitwise_xor(tmp, prev_ctxt)
            prev_ctxt = block
        return ptxt


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


# for the MT19937_32 class in set3 where upon further reflection it makes no sense to have it as a static method of said
# class since it's a utility method applicable elsewhere
def lowest_bits(bits, nb_bits):
    mask = (1 << nb_bits) - 1
    return bits & mask


def left_rotate(val, shift):
    return ((val << shift) & 0xffffffff) | (val >> (32-shift))


class SHA1:
    def_h0, def_h1, def_h2, def_h3, def_h4, = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

    def __init__(self, msg, ml=None, h0=def_h0, h1=def_h1, h2=def_h2, h3=def_h3, h4=def_h4):
        self.h0 = h0
        self.h1 = h1
        self.h2 = h2
        self.h3 = h3
        self.h4 = h4

        # pre- processing:
        if ml is None:
            ml = len(msg) * 8
        msg += b'\x80'
        while (len(msg) * 8) % 512 != 448:
            msg += b'\x00'
        msg += pack('>Q', ml)  # unsigned 64-bit int big-endian

        # Process the message in successive 512-bit chunks:
        for i in range(0, len(msg), 64):
            self.process_chunk(i, msg)

    def process_chunk(self, i, msg):
        w = [0] * 80
        for j in range(16):
            w[j] = unpack('>I', msg[slice(i + 4 * j, i + 4 * j + 4)])[0]
        # Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
        for j in range(16, 80):
            w[j] = left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)
        # Initialize hash value for this chunk:
        a = self.h0
        b = self.h1
        c = self.h2
        d = self.h3
        e = self.h4
        # Main loop:
        for j in range(80):
            if j <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (d & (b | c))
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            tmp = left_rotate(a, 5) + f + e + k + w[j] & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = tmp

        self.h0 = (self.h0 + a) & 0xffffffff
        self.h1 = (self.h1 + b) & 0xffffffff
        self.h2 = (self.h2 + c) & 0xffffffff
        self.h3 = (self.h3 + d) & 0xffffffff
        self.h4 = (self.h4 + e) & 0xffffffff

    def get_vars(self):
        return self.h0, self.h1, self.h2, self.h3, self.h4

    def get_hash(self):
        # Produce the final hash value (big-endian) as a 160 bit number, hex formatted:
        return '%08x%08x%08x%08x%08x' % self.get_vars()


class MD4:
    buf = [0x00] * 64

    _F = lambda self, x, y, z: ((x & y) | (~x & z))
    _G = lambda self, x, y, z: ((x & y) | (x & z) | (y & z))
    _H = lambda self, x, y, z: (x ^ y ^ z)

    def __init__(self, message, ml=None, A=0x67452301, B=0x67452301, C=0x98badcfe, D=0x10325476):
        self.A, self.B, self.C, self.D = (A, B, C, D)
        if ml is None:
            ml = len(message) * 8
        length = pack('<Q', ml)
        while len(message) > 64:
            self._handle(message[:64])
            message = message[64:]
        message += b'\x80'
        message += bytes((56 - len(message) % 64) % 64)
        message += length
        while len(message):
            self._handle(message[:64])
            message = message[64:]

    def _handle(self, chunk):
        X = list(unpack('<' + 'I' * 16, chunk))
        A, B, C, D = self.A, self.B, self.C, self.D

        for i in range(16):
            k = i
            if i % 4 == 0:
                A = left_rotate((A + self._F(B, C, D) + X[k]) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._F(A, B, C) + X[k]) & 0xffffffff, 7)
            elif i % 4 == 2:
                C = left_rotate((C + self._F(D, A, B) + X[k]) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = left_rotate((B + self._F(C, D, A) + X[k]) & 0xffffffff, 19)

        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            if i % 4 == 0:
                A = left_rotate((A + self._G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, 5)
            elif i % 4 == 2:
                C = left_rotate((C + self._G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, 9)
            elif i % 4 == 3:
                B = left_rotate((B + self._G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, 13)

        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                A = left_rotate((A + self._H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, 9)
            elif i % 4 == 2:
                C = left_rotate((C + self._H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = left_rotate((B + self._H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, 15)

        self.A = (self.A + A) & 0xffffffff
        self.B = (self.B + B) & 0xffffffff
        self.C = (self.C + C) & 0xffffffff
        self.D = (self.D + D) & 0xffffffff

    def digest(self):
        return pack('<IIII', self.A, self.B, self.C, self.D)

    def hexdigest(self):
        return hexlify(self.digest()).decode()


