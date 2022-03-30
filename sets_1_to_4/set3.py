"""
@author rpthi
"""
from base64 import b64decode
from os import urandom
from Crypto.Cipher import AES
from util import (CBC, PadError, slice_to_blocks, unpad_PKCSN7, ECB, bitwise_xor, lowest_bits)
from random import choice, randint
from struct import unpack
from set1 import crack_one_char_multiple_pads
from time import time


# challenge 17
class CBC_Padding_Oracle:
    MSGS = list(map(b64decode,[
        b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
    ]))

    def __init__(self):
        self.key = urandom(AES.block_size)
        self.cbc = CBC()

    def encrypt(self):
        iv = urandom(AES.block_size)
        ctxt = self.cbc.encrypt_aes128(choice(self.MSGS), self.key, iv)
        return {'ctxt': ctxt, 'iv': iv}

    def verify_pad(self, ctxt_data):
        # decryption has unpad_valid_PKCSN7 which throws/raises PadError if invalid padding
        try:
            self.cbc.decrypt_aes128(ctxt_data['ctxt'], self.key, ctxt_data['iv'])
            return True
        except PadError:
            return False


def corrupt_prev_block(block, pad_length, ptxt_block, byte):
    i = len(block) - pad_length
    corrupted = block[i] ^ ord(byte) ^ pad_length  # corrupt to pad_length (0x01 ...)
    res = block[:i] + bytes([corrupted])  # ie res is the ctxt
    # continue chain
    j = 0
    for k in range(AES.block_size-pad_length+1, AES.block_size):
        corrupted = block[k] ^ ptxt_block[j] ^ pad_length  # corrupt to pad_length
        res += bytes([corrupted])
        j += 1
    return res


# block is 16 bytes long as per usual with AES; the idea is that with CBC, "corruption" ie bitflip by XOR, carries
# on to the next blocks (obvious property since it's a chain).
# (*) So, given a block defined as the first block in the cbc chain: First, find padding length
# flip the value of its last byte: block1_byte =  block1_byte ⊕ (guess_block2_byte ⊕ 0x01) so that we can iterate over all
# bytes for the guess and end up with 0x01 which would be correct PKCSN7 padding for a pad of 1 byte at the end.
# Continue until whole block is guessed and then continue until whole ctxt is guessed
def crack_CBC_Pad_Oracle(ctxt_data, oracle):
    # split ctxt into blocks (clearly iv is already a block by itself)
    ctxt_blocks = [ctxt_data['iv']] + slice_to_blocks(ctxt_data['ctxt'], AES.block_size)
    ptxt = b''
    for nb_block in range(1, len(ctxt_blocks)):  # clearly don't iterate over iv
        # (*)
        ptxt_block = b''
        for i in range(AES.block_size-1, -1, -1):
            pad_length = len(ptxt_block) + 1  # iterating backwards makes it so we don't have to explicitly find pad_length
            suffix = []  # take suffix to mean last byte, and clearly there is a range of possibilities
            # meaning, we iterate over all possibilities and 'score'
            for byte in list(unpack('256c', bytes(j for j in range(2 ** 8)))):
                prev_block = corrupt_prev_block(ctxt_blocks[nb_block-1], pad_length, ptxt_block, byte)
                # correct padding means 0x01 and the subsequent bytes
                if oracle.verify_pad({'ctxt': ctxt_blocks[nb_block], 'iv': prev_block}):
                    suffix.append(byte)
            # retry since valid padding was ambiguous
            if len(suffix) != 1:
                for byte in suffix:
                    for k in list(unpack('256c', bytes(l for l in range(2 ** 8)))):
                        # last block is just a different name for prev_block
                        last_block = corrupt_prev_block(ctxt_blocks[nb_block-1], pad_length, byte+ptxt_block, k)
                        if oracle.verify_pad({'ctxt': ctxt_blocks[nb_block-1], 'iv': last_block}):
                            suffix = [byte]
                            # print(suffix)
                            break
            ptxt_block = suffix[0] + ptxt_block  # recall we iterate backwards
        ptxt += ptxt_block
    print(unpad_PKCSN7(ptxt))


# challenge 18
def aes128_ctr_keystream_generator(key, nonce):
    ecb = ECB()
    count = 0
    while True:
        ptxt = (nonce.to_bytes(length=8, byteorder='little')+count.to_bytes(length=8, byteorder='little'))
        keystream_block = ecb.encrypt_aes128_block(ptxt, key)
        # for byte in keystream_block:
        #   yield byte
        yield from keystream_block  # alternative to commented code above
        count += 1


def aes128_ctr(ptxt, key, nonce):
    return bitwise_xor(ptxt, aes128_ctr_keystream_generator(key, nonce), longest=False)


# challenge 19
# It is said the only purpose of this challenge is to demonstrate how better the solution to challenge 20 is, so
# I'll just skip this since it takes too much manual effort to be work the time spent

# challenge 20: a better solution to challenge 19
# instructions say that with a fixed nonce, CTR encryption is effectively the same as a repeating-key XOR
# (repeating-key multiple-time pad). Meaning, it is nearly the same as a Vigenere cipher, but of course we can't use
# the crack_vigenere function since it applies to 1 ctxt, not the list we have here, but all the crack_vigenere function
# does really is call crack_one_char_multiple_pads and append the result (then decrypt).
# Idea: since the nonce is fixed  all that's needed to be done is to iterate over each byte in each ctxt ie 1st byte, 2nd,
# 3rd ...and call crack_one_char_multiple_pads on the ctxt defined as all n_ctxt_byte of each ctxt in file
def crack_fixed_nonce_CTR(ctxts):
    n_bytes = [crack_one_char_multiple_pads(n_ctxt_byte)['ptxt'] for n_ctxt_byte in zip(*ctxts)]
    res = ''
    for msg_data in zip(*n_bytes):
        res += bytes(msg_data).decode() + '\n'
    return res


# challenge 21
# idea: https: // en.m.wikipedia.org / wiki / Mersenne_Twister
# really I just copied the pseudocode part
class MT19937_32:  # 32-bit version
    W, N, M, R = 32, 624, 397, 31
    A = 0x9908B0DF
    U, D = 11, 0xFFFFFFFF
    S, B = 7, 0x9D2C5680
    T, C = 15, 0xEFC60000
    L = 18
    F = 1812433253
    LOWER_MASK = (1 << R) - 1  # binary num of 1's in R
    UPPER_MASK = lowest_bits(not LOWER_MASK, W)  # binary num of 1's in W without 1's in R

    def __init__(self, seed):  # is the seed_mt function from wiki; initializes generator from a seed
        self.index = self.N
        self.MT = [seed]
        for i in range(1, self.index):
            self.MT.append(lowest_bits((self.F * (self.MT[i-1] ^ (self.MT[i-1] >> (self.W-2))) + i), self.W))

    def twist(self):
        for i in range(self.N):
            x = (self.MT[i] & self.UPPER_MASK) + (self.MT[(i+1) % self.N] & self.LOWER_MASK)
            x_A = x >> 1
            if x % 2 != 0:
                x_A ^= self.A
            self.MT[i] = self.MT[(i + self.M) % self.N] ^ x_A
        self.index = 0

    def extract_number(self):
        if self.index >= self.N:
            # if self.index > self.N:   # unnecessary since the __init___ is called before extract_number in all circumstances
            #    raise Exception('Generator was never seeded')
            self.twist()
        y = self.MT[self.index]
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= (y >> self.L)
        self.index += 1
        return lowest_bits(y, self.W)


# challenge 22
# the challenge instructions says the seed is the UNIX timestamp
def MT19937_32_routine():
    global current_time
    delta_1, delta_2 = randint(40, 1000), randint(40, 1000)  # range per instructions' suggestion

    current_time += delta_1
    seed = int(current_time)  # redundant
    prng = MT19937_32(seed)
    current_time += delta_2
    return seed, prng.extract_number()


def crack_MT19937_32_seed(prng_nb):
    global current_time
    for i in range(2000):  # arbitrary decision, 2000 is the max of both delta's ie max of added time to current
        guessed_seed = current_time - i
        if MT19937_32(guessed_seed).extract_number() == prng_nb:
            return guessed_seed
    raise Exception('Could not crack seed')


# challenge 23
# tempering is discussed in the wiki https://en.wikipedia.org/wiki/Mersenne_Twister and instructions say it's invertible
# the instructions are wrong in my case since I copied from the wiki where there lies an additional complication in that
# there is a right shift with with another parameter

def temper(num):
    # essentially a copy-paste of temper found in extract_number function in MT19937_32 class
    y = num
    y ^= (y >> MT19937_32.U) & MT19937_32.D
    y ^= (y << MT19937_32.S) & MT19937_32.B
    y ^= (y << MT19937_32.T) & MT19937_32.C
    y ^= (y >> MT19937_32.L)
    return y


# idea: y ^= [y ^ (y >> s)] ^ [k >> s]; if left shift, '&' by the mask pre shifting (shifting left obviously)
# interesting property of [y ^ (y >> s)] is that there is a discovery of s known bytes of y
# (clearly based since a shift causes m zeroes) and so where k is the s known bits in their respective positions in a
# string of all zeroes everywhere else, we can move along y and discover all bits subsequently
def untemper(y):
    # I imagine this could have been done a lot cleaner with a list
    def inverse_right_shift_xor(y, s):
        bit_mask = ((1 << s) - 1) << (32 - s)  # bit mask: lowest bits of shift, left-shifted by relation to bit-string length
        # for readability let's say that x -> y in the temper (even though y -> y)
        # x ^= [x ^ (x >> s)] ^ [k >> s] ~
        x = y
        s_known_bits = 0  # [k >> s]
        while bit_mask > 0:
            x ^= s_known_bits
            k = x & bit_mask
            bit_mask >>= s
            s_known_bits = k >> s
        return x

    def inverse_left_shift_xor_and(y, s, m):  # m is yet another mask (applied to s_known_bits)
        bit_mask = ((1 << s) - 1) # lowest bits of shift
        x = y
        s_known_bits = 0
        while bit_mask & MT19937_32.D > 0:
            x ^= s_known_bits & m
            k = x & bit_mask
            bit_mask <<= s
            s_known_bits = k << s
        return x

    y = inverse_right_shift_xor(y, MT19937_32.L)
    y = inverse_left_shift_xor_and(y, MT19937_32.T, MT19937_32.C)
    y = inverse_left_shift_xor_and(y, MT19937_32.S, MT19937_32.B)
    y = inverse_right_shift_xor(y, MT19937_32.U)
    return y


def get_MT19937_32_clone(og):
    MT = []
    for i in range(og.N):  # 624
        MT.append(untemper(og.extract_number()))
    clone = MT19937_32(0)
    clone.MT = MT
    return clone


# challenge 24
class MT19937_32_Stream_Cipher:
    def __init__(self, key):  # where key is seed
        self.prng = MT19937_32(key)

    def keystream_generator(self, length):
        keystream = bytearray()
        while len(keystream) < length:
            keystream.extend(int.to_bytes(self.prng.extract_number(), 4, byteorder='big'))  # 32 bits == 4 bytes
        return keystream

    def encrypt(self, ptxt):
        keystream = self.keystream_generator(len(ptxt))
        return bitwise_xor(ptxt, keystream, longest=False)

    def decrypt(self, ctxt):
        return self.encrypt(ctxt)  # since it's literally the same


def crack_MT19937_32_Stream_Cipher_key(ctxt, k_ptxt):  # k_ptxt denotes known ptxt
    for seed in range(2**16):  # 16-bit key
        ptxt = MT19937_32_Stream_Cipher(seed).encrypt(ctxt)
        if k_ptxt in ptxt:
            return seed
    raise Exception('Could not find seed')


def encrypt_and_recover_key(k_ptxt):  # method as per instructions
    key = randint(1, 2**16-1)
    stream_cipher = MT19937_32_Stream_Cipher(key)
    ctxt = stream_cipher.encrypt(urandom(randint(1,100)) + k_ptxt)  # prefix + ptxt
    recovered_key = crack_MT19937_32_Stream_Cipher_key(ctxt, k_ptxt)
    print(key, recovered_key)
    print(key == recovered_key)


# instructions weren't all that clear on what the token is supposed to be, so I return the generator
def generate_MT19937_32_password_reset_token():
    key = int(time()) & (2**16-1)
    return bytes(MT19937_32_Stream_Cipher(key).keystream_generator(16))


def is_MT19937_32_with_time_seed(token):
    for seed in range(1, (2**16-1)):
        guess = MT19937_32_Stream_Cipher(seed).keystream_generator(len(token))
        if guess == token:
            return True
    else:
        return False


"""
# challenge 17 test
oracle = CBC_Padding_Oracle()
data = oracle.encrypt()
# print(oracle.verify_pad(data))
# print(oracle.verify_pad({'ctxt': urandom(AES.block_size), 'iv': data['iv']}))  # 'corrupted', so error is expected
# print(crack_CBC_Pad_Oracle(data, oracle))
crack_CBC_Pad_Oracle(data, oracle)

# challenge 18 test
ctxt = b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
print(aes128_ctr(ctxt, b'YELLOW SUBMARINE', 0))

# challenge 20 test
with open('data/20.txt') as data:
    msgs = [b64decode(line) for line in data]
key = urandom(AES.block_size)
CTXTS = [aes128_ctr(msg, key, nonce=0) for msg in msgs]
print(crack_fixed_nonce_CTR(CTXTS))

# challenge 21 test
print(MT19937_32(1234).extract_number())

# challenge 22 test
current_time = int(time())
seed, nb = MT19937_32_routine()
guess = crack_MT19937_32_seed(nb)
print(nb)
print(seed == guess)

# challenge 23 test
# test whether untemper works (w/ repeated 10,000 I hope it does)
for _ in range(10000):
    x = randint(0, 0xFFFFFFF)
    y = temper(x)
    x_2 = untemper(y)
    assert x == x_2
# test clone
prng = MT19937_32(randint(0, 2**32 - 1))
cloned = get_MT19937_32_clone(prng)
for i in range(10000):
    assert prng.extract_number() == cloned.extract_number()

# challenge 24 test
encrypt_and_recover_key(b'A'*14)
print(is_MT19937_32_with_time_seed(generate_MT19937_32_password_reset_token()))
"""
