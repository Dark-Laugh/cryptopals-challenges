"""
@author rpthi
"""
import time
from os import urandom
from urllib import parse
from requests import get, post
from Crypto.Cipher import AES
from set2 import cbc_encryption_oracle
from set3 import aes128_ctr
from util import ECB, bitwise_xor, CBC, SHA1, MD4
from struct import pack, unpack
from random import randint
from binascii import unhexlify
from sets_1_to_4.CH31_server import HMAC_SHA1, validate_signature

# from hashlib import sha1  # just to test implementation
# from base64 import b64decode


# challenge 25
class CTR_Oracle:
    def __init__(self):
        self.key = urandom(AES.block_size)
        self.ECB = ECB()

    def edit(self, ctxt, offset, new_txt):
        keystream = b''
        for nb_block in range(offset // AES.block_size, (offset + len(new_txt) - 1) // AES.block_size + 1):
            keystream += self.ECB.encrypt_aes128_block(pack('<QQ', 0, nb_block), self.key)
            # might have error from padding, in that case use encrypt block function. EDIT: This was the case.
        key_offset = offset % AES.block_size
        keystream = keystream[slice(key_offset, key_offset+len(new_txt))]
        payload = bitwise_xor(keystream, new_txt)
        return ctxt[:offset] + payload + ctxt[offset+len(payload):]

    def encrypt(self, ptxt):
        return aes128_ctr(ptxt, self.key, 0)


def crack_random_access_read_write_CTR(oracle, ctxt):
    return oracle.edit(ctxt, 0, ctxt)


# challenge 26
class CTR_Oracle_26:  # didn't know what else to call it
    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'

    def __init__(self):
        self.key = urandom(AES.block_size)
        self.nonce = randint(0, 2**32-1)  # 2**32-1 is int32 max value

    def encrypt(self, data):
        tmp = parse.quote_from_bytes(data).encode()
        ptxt = self.prefix + tmp + self.suffix
        return aes128_ctr(ptxt, self.key, self.nonce)

    def is_admin(self, ctxt):
        ptxt = aes128_ctr(ctxt, self.key, self.nonce)
        print('ptxt: ', ptxt)
        return b';admin=true;' in ptxt


def get_shared_prepend_length(oracle):  # adapted from set 2 challenge 14
    # idea: encrypt two different payloads of same length (1, to be simple). Prefix length should be the the number
    # of equal bytes in the beginning of returned ctxts; so, loop until different.
    ctxtX = oracle.encrypt(b'X')
    ctxtY = oracle.encrypt(b'Y')
    prepend_len = 0
    while ctxtX[prepend_len] == ctxtY[prepend_len]:
        prepend_len += 1
    return prepend_len


def ctr_bitflip(oracle):
    aim = b';admin=true;'
    malicious_data = b'XadminXtrueX'
    payload = bitwise_xor(aim, malicious_data)

    prefix_len = get_shared_prepend_length(oracle)  # position of payload
    ctxt = oracle.encrypt(malicious_data)
    prefix = ctxt[:prefix_len]  # everything left of payload (just the prefix)
    append = ctxt[prefix_len+len(malicious_data):]   # everything right of payload
    return prefix + bitwise_xor(ctxt[slice(prefix_len, prefix_len+len(malicious_data))], payload) + append


# challenge 27
def is_ASCII_compliant(txt):
    return all(char < 128 for char in txt)


class CBC_Oracle_Insecure:
    def __init__(self):
        self.key = urandom(AES.block_size)
        self.iv = self.key
        self.cbc = CBC()

    def encrypt(self, data):
        return cbc_encryption_oracle(data, self.key, self.iv)['ctxt']

    def is_admin(self, ctxt):
        ptxt = self.cbc.decrypt_aes128_keep_PCSN7(ctxt, self.key, self.iv)
        if not is_ASCII_compliant(ptxt):
            raise Exception('Invalid msg: ', ptxt)
        print('ptxt: ', ptxt)
        return b';admin=true;' in ptxt


def get_block_length(oracle):
    ctxt_len = len(oracle.encrypt(b''))
    i = 1
    while True:
        block_length = len(oracle.encrypt(b'X' * i)) - ctxt_len
        if block_length:
            return block_length
        i += 1


def get_prefix_length(oracle, block_length):  # using block length, adapted from set2 ECB cracker
    shared_len = (get_shared_prepend_length(oracle) // block_length) * block_length
    for i in range(1, block_length+1):
        ctxtX = oracle.encrypt(b'X' * i + b'Y')
        ctxtY = oracle.encrypt(b'X' * i + b'Z')
        if ctxtX[slice(shared_len, shared_len+block_length)] == ctxtY[slice(shared_len, shared_len+block_length)]:
            return shared_len + (block_length - i)
    raise Exception('Could not find prefix length')


def crack_insecure_CBC_oracle(oracle):
    block_len = get_block_length(oracle)
    prefix_len = get_prefix_length(oracle, block_len)
    # per the challenge instructions:
    p_1 = b'X' * block_len
    p_2 = b'Y' * block_len
    p_3 = b'Z' * block_len
    ctxt = oracle.encrypt(p_1 + p_2 + p_3)
    tmp = ctxt[slice(prefix_len, prefix_len+block_len)]
    modded_ctxt = tmp + b'\x00' * block_len + tmp
    try:
        oracle.is_admin(modded_ctxt)
    except Exception as expected:
        # print(expected)
        cracked_ptxt = expected.args[1]
        return bitwise_xor(cracked_ptxt[:block_len], cracked_ptxt[-block_len:])
    raise Exception('Could not crack Oracle')


# challenge 28: https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
def sha1_mac(key, msg):
    return SHA1(key+msg).get_hash()


# challenge 29:
class SHA1_Oracle:
    def __init__(self):
        self.key = urandom(randint(1, 101))

    def gen_digest(self, msg):
        return sha1_mac(self.key, msg)

    def validate(self, msg, digest):
        return sha1_mac(self.key, msg) == digest


def pad_MD_SHA1(msg):
    # pre-processing of SHA1
    ml = len(msg) * 8
    msg += b'\x80'
    while (len(msg) * 8) % 512 != 448:
        msg += b'\x00'
    msg += pack('>Q', ml)
    return msg


def length_extension_atk_SHA1(oracle, msg, digest):
    """attack on SHA1 MAC via msg extension with desired appendage"""
    extension = b';admin=true'
    for i in range(100):
        forged_msg = pad_MD_SHA1(b'X'*i+msg)[i:] + extension
        # (h1, h2, h3, h4, h5) via reversing get_hash
        h = unpack('>5I', unhexlify(digest))
        # compute hash of extension so we can check validity with msg
        forged_digest = SHA1(extension, (i + len(forged_msg)) * 8, h[0], h[1], h[2], h[3], h[4]).get_hash()
        if oracle.validate(forged_msg, forged_digest): return forged_msg, forged_digest
    raise Exception('Length extension attack unsuccessful')


# challenge 30: MD4 implementation copied from https://github.com/FiloSottile/crypto.py/blob/master/3/md4.py
# with minor changes for convenience


class MD4_Oracle:
    def __init__(self):
        self.key = urandom(randint(1, 101))

    def gen_digest(self, msg):
        return MD4(self.key+msg).hexdigest()

    def validate(self, msg, digest):
        return MD4(self.key+msg).hexdigest() == digest


def pad_MD_MD4(msg):
    ml = len(msg) * 8
    msg += b'\x80'
    msg += bytes((56-len(msg) % 64) % 64)
    msg += pack('<Q', ml)
    return msg


def length_extension_atk_MD4(oracle, msg, digest):
    """length extension atk on MD4, essentially a copy-paste of length_extension_atk_SHA1"""
    extension = b';admin=true'
    for i in range(100):
        forged_msg = pad_MD_MD4(b'X' * i + msg)[i:] + extension
        h = unpack('<4I', unhexlify(digest))
        forged_digest = MD4(extension, (i + len(forged_msg)) * 8, h[0], h[1], h[2], h[3]).hexdigest()
        if oracle.validate(forged_msg, forged_digest): return forged_msg, forged_digest
    raise Exception('Length extension attack unsuccessful')


# challenge 31:
def verify_network():
    """quick verification"""
    try:
        get(f'http://127.0.0.1:8080/ping')
        return True
    except ConnectionError:  # server isn't running
        return False


hmac_len = 20  # public knowledge
KEY = b'YELLOW SUBMARINE'  # this is for testing purposes, it's the key of the server


def crack_mac_timing_attack(file):
    expected = HMAC_SHA1(KEY, file)
    print(f'Expected HMAC_SHA1 - {expected}')  # for testing
    running = verify_network()
    known_bytes = b''
    while len(known_bytes) < len(expected):
        suffix = (len(expected) - len(known_bytes) - 2) * b'?'
        longest_timing, best_byte = 0.0, b''
        for i in range(0xff+1):
            signature = known_bytes + bytes([i]) + suffix
            url = f'http://localhost:8080/test?file={file}&signature={signature}'
            # timing attack the next byte
            start = time.perf_counter()
            if running:
                print('post: ' + url)  # for visualization
                post(url)
            else:
                validate_signature(file, signature)
            end = time.perf_counter()
            runtime = end - start
            if runtime > longest_timing:
                longest_timing = runtime
                best_byte = bytes([i])
        known_bytes += best_byte
        print(known_bytes)
    return f'Cracked HMAC-SHA1 - {known_bytes}'


# challenge 32
def crack_mac_timing_attack_2(file):
    expected = HMAC_SHA1(KEY, file)
    print(f'Expected HMAC_SHA1 - {expected}')
    rounds = 10
    running = verify_network()
    known_bytes = b''
    while len(known_bytes) < len(expected):
        suffix = (len(expected) - len(known_bytes) - 2) * b'?'  # just for visualization purposes I put b'?'*suffix_len
        longest_timing, best_byte = 0.0, b''
        for i in range(0xff+1):
            timing = 0.0
            for _ in range(rounds):
                signature = known_bytes + bytes([i]) + suffix
                url = f'http://localhost:8080/test?file={file}&signature={signature}'
                # timing attack the next byte
                start = time.perf_counter()
                if running:
                    print('post: ' + url)  # for visualization
                    post(url)
                else:
                    validate_signature(file, signature)
                end = time.perf_counter()
                timing += end-start
            if timing > longest_timing:
                longest_timing = timing
                best_byte = bytes([i])
        known_bytes += best_byte
    return f'Cracked HMAC-SHA1 - {known_bytes}'


"""
# challenge 25 test
# with open('data/25.txt') as file:
#     data = b64decode(file.read())
#     ptxt = ECB().decrypt_aes128(data, b'YELLOW SUBMARINE')
#     oracle = CTR_Oracle()
#     ctxt = oracle.encrypt(ptxt)
#     cracked_ptxt = crack_random_access_read_write_CTR(oracle, ctxt)
#     assert cracked_ptxt == ptxt

# challenge 26 test
oracle = CTR_Oracle_26()
res = ctr_bitflip(oracle)
print(oracle.is_admin(res))

# challenge 27 test
o = CBC_Oracle_Insecure()
cracked_key = crack_insecure_CBC_oracle(o)
assert o.key == cracked_key

# challenge 28 test
for i in range(100):
    key = urandom(10)
    msg = urandom(100)
    hash0 = sha1_mac(key, msg)
    hash1 = SHA1(key+msg).get_hash()
    assert(hash0 == hash1)

# challenge 29 test:
oracle = SHA1_Oracle()
message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
digest = oracle.gen_digest(message)
assert oracle.validate(message, digest)
forged_message, forged_digest = length_extension_atk_SHA1(oracle, message, digest)
assert b';admin=true' in forged_message

# challenge 30 test
oracle = MD4_Oracle()
message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
digest = oracle.gen_digest(message)
assert oracle.validate(message, digest)
forged_message, forged_digest = length_extension_atk_MD4(oracle, message, digest)
assert b';admin=true' in forged_message

# challenge 31 test
# note, this attack attack takes hours. To run: run tester in one prompt/in ide, then run set4.py in another prompt
print(crack_mac_timing_attack(b'foo'))
"""
# challenge 32 test
print(crack_mac_timing_attack_2(b'foo'))
