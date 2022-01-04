"""
@author rpthi
"""
from utils import ECB, CBC, Simple_ECB_Oracle, pad_PKCSN7, slice_to_blocks, Hard_ECB_Oracle, bitwise_xor
from random import randint, choice
from os import urandom
from set1 import repeating_blocks
from struct import unpack
from binascii import unhexlify
from urllib import parse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES


# challenge 9
# methods added to utils.py to avoid circular imports

# challenge 10
# CBC class added to utils.py to avoid circular import

# challenge 11
# following the instructions exactly
def encryption_oracle(msg, mode=None):
    ecb = ECB()
    cbc = CBC()
    length = 16
    txt = urandom(randint(5, 10)) + msg + urandom(randint(5, 10))
    # both ECB and CBC pad the txt
    if mode is None:
        mode = choice('ECB', 'CBC')
    if mode == 'ECB':
        return ecb.encrypt_aes128(txt, urandom(length))
    elif mode == 'CBC':
        return cbc.encrypt_aes128(txt, urandom(length), urandom(length))
    else:
        raise Exception('Incorrect mode input')


# set 1 challenge 8 method repeating_blocks
def is_ecb(ctxt):
    return repeating_blocks(ctxt) > 0


# challenge 12
class Simple_ECB_Cracker:
    def __init__(self, oracle):
        self.oracle = oracle

    @staticmethod  # changed to static for challenge 14
    def get_block_length(oracle):
        # instructions: feed the same character (1 byte) at a time ie 'A', 'AA', 'AAA' ...
        ctxt_length = len(oracle.encrypt(b''))
        i = 1
        # iterate until ctxt starts changing ie since ECB uses PKCSN7 padding, the ctxt jumping up in length means
        # a jump of a block length
        # ie difference of ctxt sizes of 2 inputs is multiple (1x) of block_length
        while True:
            input_ = b'A' * i
            new_ctxt_length = len(oracle.encrypt(input_))
            block_length = new_ctxt_length - ctxt_length
            if block_length:
                return block_length
            i += 1

    # note ECB uses PKCSN7 padding so msg length /= ptxt length ie ctxt length
    @staticmethod  # changed to static for challenge 14
    def get_string_length(oracle):
        # idea: the same as determining block length: loop until the ctxt length jumps up
        ctxt_length = len(oracle.encrypt(b''))
        i = 1
        while True:
            input_ = b'A' * i
            new_ctxt_length = len(oracle.encrypt(input_))
            if new_ctxt_length != ctxt_length:
                return new_ctxt_length - i  # ie the ctxt length without all the added bytes
            i += 1

    def suffix_decryption(self, block, block_length):
        # determine which block the unknown suffix is the last char of, and slice it.
        nb_block = len(block) // block_length
        block_slice = slice(nb_block*block_length, (nb_block+1)*block_length)
        # now, determine what the block is:
        # instructions: Knowing the block size, craft an input block that is exactly 1 byte short
        # ie len(block [ie msg]) + pad_length + 1 modulo block_length = 0 rewritten as m+p+1 MOD b = 0 ~ p = -(m+1) mod b
        pad_length = (-1) * (len(block) + 1) % block_length
        pad = b'A' * pad_length
        block = self.oracle.encrypt(pad)[block_slice]
        bs = bytes(i for i in range(2 ** 8))
        for byte in list(unpack('256c', bs)):
            tmp = pad + block + byte
            if block == self.oracle.encrypt(tmp)[block_slice]:
                return byte

    def crack_simple_ECB(self):
        block_length = self.get_block_length(self.oracle)  # detect block length
        assert is_ecb(self.oracle.encrypt(b'A' * 100))  # determine if ECB mode
        # byte-at-a-time decryption:
        str_length = self.get_string_length(self.oracle)
        msg = b''
        for _ in range(str_length):
            byte = self.suffix_decryption(msg, block_length)
            if byte is None:
                return msg
            msg += byte
        return msg


# challenge 13
class Structured_Cookie:
    def __init__(self):
        self.key = urandom(16)
        self.ecb = ECB()

    @staticmethod
    def kv_parse(bs):  # bs as in byte string
        """k=v parsing routine taking a byte string and outputting a dict"""
        return dict(kv.split('=') for kv in bs.decode().split('&'))

    @staticmethod
    def profile_for(email_addr):  # by instructions specifications
        email = bytes(email_addr).replace(b'&', b'').replace(b'=', b'')
        return b'email=' + email + b'&uid=10&role=user'

    def get_encrypted_profile(self, email_addr):
        return self.ecb.encrypt_aes128(self.profile_for(email_addr), self.key)

    def decrypt_parse_profile(self, profile):
        return self.kv_parse(self.ecb.decrypt_aes128(profile, self.key))


def privesc_struct_cookie(cookie):
    # idea: make a lengthy email so that 'admin' is automatically in the "user"'s position
    # payload = payload_prefix || payload_suffix
    # prefix is b'email=XXXXXXXXXXXXX&uid=10&role=', suffix is padded admin
    block_length = 16  # arbitrary; all that's necessary is that 'user' is last in the block
    fixed = 'email=&uid=10&role='
    nb_fill = (len(fixed) // block_length + 1) * block_length
    nb_bytes = nb_fill - len(fixed)
    prefix = cookie.get_encrypted_profile(b'X' * nb_bytes)[:nb_fill]

    fixed = 'email='
    nb_fill = (len(fixed) // block_length + 1) * block_length
    nb_bytes = nb_fill - len(fixed)
    suffix_data = b'X' * nb_bytes + pad_PKCSN7(b'admin', block_length)
    suffix = cookie.get_encrypted_profile(suffix_data)[nb_fill:nb_fill+block_length]
    payload = prefix + suffix
    return cookie.decrypt_parse_profile(payload)


# challenge 14
class Hard_ECB_Cracker:
    def __init__(self, oracle):
        self.oracle = oracle

    @staticmethod
    def get_prefix_length(oracle, block_length):
        # idea: recall the issue with ECB is repeating blocks, so pass a repeating message normalized to block_length
        # and detect the repeating blocks. The first index of repeating block should be prefix length unless the prefix
        # isn't normalized to block_length (which it probably isn't) so increase size of input and try again
        # which is essentially just looping through block_length to find alignment with respect to PKCSN7 padding
        for pad_length in range(block_length):
            n = randint(5, 15)
            # n is num of repeating blocks that should be determined if aligned with current pad_length
            # completely arbitrary; just didn't want to have manual input
            msg = urandom(block_length)
            payload = (b'X' * pad_length) + (msg * n)
            ctxt = oracle.encrypt(payload)
            # find repetitions in ctxt
            prev_block = None
            num = prefix_total_length = 0
            for i in range(0, len(ctxt), block_length):
                block = ctxt[i:i+block_length]
                if block == prev_block:
                    num += 1
                else:
                    num = 1  # reset num
                    prev_block = block
                    prefix_total_length = i
                if num == n:  # determined correct num of repeating blocks, so pad_length is aligned
                    return prefix_total_length - pad_length  # prefix length
        raise Exception('Could not detect prefix length')

    def crack_hard_ECB(self):
        block_length = Simple_ECB_Cracker.get_block_length(self.oracle)  # detect block length
        str_length = Simple_ECB_Cracker.get_string_length(self.oracle)  # detect string length
        prefix_length = self.get_prefix_length(self.oracle, block_length)
        assert prefix_length == len(self.oracle.prefix)
        target_length = str_length - block_length - prefix_length
        assert target_length == len(self.oracle.target)
        target = b''
        # similar to challenge 12: prefix_len+padding_len+len(msg)+1 = 0 mod block_length (+1 for suffix decryption)
        # so pad_len = -prefix_len-len(msg)-1 mod block_length
        # the way this algorithm is designed splitting the complexity with a suffix_decryption method would be more
        # difficult than keeping the complexity in one method
        for _ in range(target_length):
            pad_length = (-prefix_length-len(target)-1) % block_length
            pad = b'X' * pad_length
            nb_block = (prefix_length+len(target)) // block_length
            block_slice = slice(nb_block*block_length, (nb_block+1)*block_length)
            block = self.oracle.encrypt(pad)[block_slice]
            for byte in list(unpack('256c', bytes(i for i in range(2 ** 8)))):
                if block == self.oracle.encrypt(pad+target+byte)[block_slice]:
                    target += byte
                    break
        return target


# challenge 15
# unpad_valid_PKCSN7 moved to utils to avoid circular imports

# challenge 16
# could have made a class as I usually did, but the oracle is a method this time
def cbc_encryption_oracle(data, key, iv):
    cbc = CBC()
    tmp = parse.quote_from_bytes(data).encode()
    msg = b'comment1=cooking%20MCs;userdata=' + tmp + b';comment2=%20like%20a%20pound%20of%20bacon'
    return {'ctxt': cbc.encrypt_aes128(msg, key, iv), 'iv': iv}  # dict is used for is_admin, but it is annoying


def is_admin(ctxt, key):
    cbc = CBC()
    ptxt = cbc.decrypt_aes128(ctxt['ctxt'], key, ctxt['iv'])
    print('ptxt: ', ptxt)
    return b';admin=true;' in ptxt


def crack_cbc_oracle(oracle, block_length, key, iv):
    prefix = b'X' * block_length * 2
    ctxt_data = oracle(prefix, key, iv)
    ctxt = ctxt_data['ctxt']
    malicious_data = pad_PKCSN7(b';admin=true;', block_length)
    payload = bitwise_xor(malicious_data, b'X' * len(malicious_data))
    # normalize payload
    appendage = len(ctxt) - len(payload) - len(prefix)
    normalized = bytes(len(prefix)) + payload + bytes(appendage)
    # input normalized payload
    res = bitwise_xor(ctxt, normalized)
    print(is_admin({'ctxt': res, 'iv': iv}, key))


"""
# challenge 9 test:
assert pad_PKCSN7(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'
assert unpad_PKCSN7(b'YELLOW SUBMARINE\x04\x04\x04\x04') == b'YELLOW SUBMARINE'

# challenge 10 test
from utils import CBC
cbc = CBC()
for _ in range(100):
    length = randint(5,50)
    msg = urandom(length)
    key = urandom(16)
    iv = urandom(16)
    ctxt = cbc.encrypt_aes128(msg, key, iv)
    assert cbc.decrypt_aes128_simple(ctxt, key, iv) == msg

# challenge 11 test
for _ in range(100):
    mode = choice(['ECB', 'CBC'])
    message = b'X'*50
    detected_mode = 'ECB' if is_ecb(encryption_oracle(message, mode)) else 'CBC'
    # print(mode, detected_mode)
    assert detected_mode == mode

# challenge 12 test
oracle = Simple_ECB_Oracle()
cracker = Simple_ECB_Cracker(oracle)
msg = cracker.crack_simple_ECB()
print(msg.decode())

# challenge 13 test
cookie = Structured_Cookie()
assert cookie.profile_for(b"email@example.com") ==b'email=email@example.com&uid=10&role=user'
assert cookie.kv_parse(b'email=email@example.com&uid=10&role=user')=={'email': 'email@example.com', 'role': 'user', 'uid': '10'}
assert privesc_struct_cookie(cookie)['role'] == 'admin'

# challenge 14 test
oracle = Hard_ECB_Oracle()
cracker = Hard_ECB_Cracker(oracle)
print(cracker.crack_hard_ECB().decode())

# challenge 15 test
assert unpad_valid_PKCSN7(b'ICE ICE BABY\x04\x04\x04\x04', 16) == b'ICE ICE BABY'
try:
    print(unpad_valid_PKCSN7(b'ICE ICE BABY\x04\x04\x04\x00', 16))
except PadError:
    print('here')

# challenge 16 test
KEY = urandom(AES.block_size)
IV = urandom(AES.block_size)
# ctxt = cbc_encryption_oracle(b'', KEY, IV)
# print(is_admin(ctxt, KEY))
crack_cbc_oracle(cbc_encryption_oracle, AES.block_size, KEY, IV)
"""
