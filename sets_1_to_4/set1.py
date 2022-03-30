"""
@author rpthi
"""
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
from util import bitwise_xor, parse_txt_file, NotSingleCharXORException, estimate_vigenere_key_length, ECB
from struct import unpack
from collections import defaultdict


# challenge 1
def hex_to_b64(hex_str):
    """converts hex string to b64 string"""
    return b64encode(unhexlify(hex_str))


def b64_to_hex(b64_str):  # extra method, not in challenge
    """converts b64 string to hex string"""
    return hexlify(b64decode(b64_str))


# challenge 2
def xor_hex(hex_str1, hex_str2):
    """takes two equal length buffers (hex) and returns XOR combination, buffered"""
    return hexlify(bitwise_xor(unhexlify(hex_str1), unhexlify(hex_str2)))


# challenge 3
# idea: (ptxt⊕byte)⊕byte=ptxt means original ptxt should be recovered by XORing with all bytes; to find answer, score
# results by some metric.  I choose to score by number of letters. Also, seems optimal for readability to return dict
def crack_one_char_multiple_pads(ctxt):
    candidate = {'ptxt': None, 'key': None, 'nb_letters': None}
    bs = bytes(i for i in range(2**8))
    ascii_letters = list(range(97, 122)) + [32]  # 'letters' may be confusing, this is the int representation of them
    for candidate_key in list(unpack('256c', bs)):  # iterating over every possible byte
        keystream = candidate_key * len(ctxt)  # keystream of equal length to ciphertext
        candidate_ptxt = bitwise_xor(ctxt, keystream)
        nb_letters = sum([letter in ascii_letters for letter in candidate_ptxt])
        if candidate['nb_letters'] is None or nb_letters > candidate['nb_letters']:  # update dict
            candidate['ptxt'] = candidate_ptxt
            candidate['key'] = candidate_key
            candidate['nb_letters'] = nb_letters
    if candidate['nb_letters'] < 0.7*len(ctxt):
        raise NotSingleCharXORException('')
    return candidate


# challenge 4
# assuming ciphertext is given in a file where each line is a new ciphertext
# idea: update 'crack_one_char_multiple_pads' to return error if the nb_letters does not meet a threshold
# this works since in this case, the ciphertext is purely text; wouldn't work if there were a lot of numbers
# update is above
def detect_one_char_multiple_pads(ctxt_file):
    CTXTS = parse_txt_file(ctxt_file)
    detected = []  # detected is a list for a) future modification (if any) and b) error check with length
    # could have used a counter but a list seemed easier
    # could have also implemented a way to see which line number of which ciphertext the detection corresponds to, but
    # didn't.
    for ctxt in CTXTS:
        try:
            detected.append(crack_one_char_multiple_pads(unhexlify(ctxt)))
        except NotSingleCharXORException:
            pass
    if len(detected) > 1 or len(detected) == 0:
        raise NotSingleCharXORException('Descriptive error message')
    return detected[0]


# challenge 5
# assumes ptxt is formatted nicely
def repeating_multiple_time_pad(ptxt, key):
    keystream = key * (len(ptxt) // len(key) + 1)
    return bitwise_xor(ptxt, keystream)


# challenge 6
def crack_vigenere(ctxt):
    """cracks a repeating XOR given the ciphertext and key length"""
    # transpose blocks of ctxt into respective keys, turning into a one-char multiple-time pad
    # join decoded blocks of ptxt
    key = bytes()
    decoded_ptxt = list()
    ptxt = bytes()  # result
    key_len = estimate_vigenere_key_length(ctxt)
    for i in range(key_len):  # don't think this can be done as efficiently with list comprehension
        decoded = crack_one_char_multiple_pads(bytes(ctxt[i::key_len]))  # ie range(a,len(ctxt), b)
        key += decoded['key']
        decoded_ptxt.append(decoded['ptxt'])
    for i in range(max(map(len, decoded_ptxt))):
        ptxt += bytes([part[i] for part in decoded_ptxt if len(part) >= i+1])
    return {'ptxt': ptxt.decode(), 'key': key}


# challenge 7 (code moved to utils)
# key = b'YELLOW SUBMARINE'
# ecb = ECB()
# print(ecb.decrypt_aes128(b64decode(open('data/7.txt').read()), key).decode())


# challenge 8
#
def repeating_blocks(ctxt, block_length=16):
    """returns sum of repetitions"""
    # Idea 1: issue with ECB: repeating blocks. So, if block is repeated, here we say that it's encrypted w/ ECB mode
    # Idea 2: same issue obviously, but the ctxt with minimum hamming distance would be the one encrypted w/ ECB mode
    # Idea 1 is implemented
    repetition_count = defaultdict(lambda: -1)  # could also been done with len(set(list)) == len(list) but I want a count
    for i in range(0, len(ctxt), block_length):
        repetition_count[bytes(ctxt[i:i+block_length])] += 1
    return sum(repetition_count.values())


"""
# challenge 1 test:
hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
b64_str = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
assert hex_to_b64(hex_str) == b64_str
assert b64_to_hex(b64_str) == hex_str.encode()

# challenge 2 test:
ans = b'746865206b696420646f6e277420706c6179'
assert xor_hex('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965') == ans

# challenge 3 test:
print(crack_one_char_multiple_pads(unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')))

# challenge 4 test: 
with open('data/4.txt') as data:
    print(detect_one_char_multiple_pads(data))


# challenge 5 test:
ptxt = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = b'ICE'
answer = unhexlify(
    b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d6'
    b'3343c2a26226324272765272a282b2f20430a652e2c652a3124'
    b'333a653e2b2027630c692b20283165286326302e27282f'
)
assert repeating_multiple_time_pad(ptxt, key) == answer

# challenge 6 test:
print(crack_vigenere(b64decode(open('data/6.txt').read())))

# challenge 7 test: (*OUTDATED*)
# key = b'YELLOW SUBMARINE'
# print(ECB.decrypt_aes128_ecb(b64decode(open('data/7.txt').read()), key).decode())

# challenge 8 test:
CTXTS = parse_txt_file(open('data/8.txt'))
max_count = 0
for ctxt in CTXTS:
    if repeating_blocks(unhexlify(ctxt)) > max_count:
        print(ctxt)
"""






