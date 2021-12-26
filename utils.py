"""
@author rpthi
"""
from binascii import unhexlify
from bitstring import BitArray


def bitwise_xor(A, B):
    """returns bitwise XOR of 2 bytestrings, denoted 'A' and 'B'"""
    # note: python built in '^' only works with integers
    return bytes([a ^ b for (a, b) in zip(A, B)])


def parse_txt_file(ctxt_file):
    """returns list representation of a ciphertext file assuming each new line is a new ciphertext"""
    return [unhexlify(line.strip()) for line in ctxt_file]


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

# create AES-ECB class
