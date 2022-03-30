"""
@author rpthi
"""

from q39_rsa import RSA, inv_mod, int_to_bytes


def get_cube_root(n):  # binary search
    low = 0
    high = n
    while low < high:
        median = (low + high) // 2
        if median**3 < n:
            low = median + 1
        else:
            high = median
    return low


def rsa_broadcast_atk(ctxts):  # chinese remainder theorem
    ctxt_0, ctxt_1, ctxt_2 = ctxts[0][0], ctxts[1][0], ctxts[2][0]
    n_0, n_1, n_2 = ctxts[0][1], ctxts[1][1], ctxts[2][1]

    m_0, m_1, m_2 = n_1 * n_2, n_0 * n_2, n_0 * n_1

    t_0 = (ctxt_0 * m_0 * inv_mod(m_0, n_0))
    t_1 = (ctxt_1 * m_1 * inv_mod(m_1, n_1))
    t_2 = (ctxt_2 * m_2 * inv_mod(m_2, n_2))

    c = (t_0 + t_1 + t_2) % (n_0 + n_1 + n_2)
    return int_to_bytes(get_cube_root(c))


if __name__ == 'main':
    ptxt = b"Assume you're a Javascript programmer. That is, you're using a naive handrolled RSA to encrypt without padding."
    ctxts = []
    for _ in range(3):
        rsa = RSA(1024)
        ctxts.append((rsa.encrypt(ptxt), rsa.n))
    assert rsa_broadcast_atk(ctxts) == ptxt
