"""
forge a signature to pretend that you are Satoshi
当验签算法在不验证m的情况下,能够通过公钥来伪造合法签名
前提数据:Satoshi的公钥,这里我们通过随机生成来代替Satoshi的真实公钥
"""
import secrets
import random
from gmssl import sm3, func

# 定义椭圆曲线参数、基点和阶
A = 0
B = 7
G_X = 55066263022277343669578718895168534326250603453777594175500187360389116729240
G_Y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (G_X, G_Y)
P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
h = 1


def inv(a, n):
    '''求逆'''

    def ext_gcd(a, b, arr):
        '''扩展欧几里得算法'''
        if b == 0:
            arr[0] = 1
            arr[1] = 0
            return a
        g = ext_gcd(b, a % b, arr)
        t = arr[0]
        arr[0] = arr[1]
        arr[1] = t - int(a / b) * arr[1]
        return g

    arr = [0, 1, ]
    gcd = ext_gcd(a, n, arr)
    if gcd == 1:
        return (arr[0] % n + n) % n
    else:
        return -1


# 椭圆曲线加法
def EC_add(p, q):
    # 0 means inf
    if p == 0 and q == 0:
        return 0  # 0 + 0 = 0
    elif p == 0:
        return q  # 0 + q = q
    elif q == 0:
        return p  # p + 0 = p
    else:
        if p[0] == q[0]:
            if (p[1] + q[1]) % P == 0:
                return 0  # mutually inverse
            elif p[1] == q[1]:
                return EC_double(p)
        elif p[0] > q[0]:  # swap if px > qx
            tmp = p
            p = q
            q = tmp
        r = []
        slope = (q[1] - p[1]) * inv(q[0] - p[0], P) % P  # 斜率
        r.append((slope ** 2 - p[0] - q[0]) % P)
        r.append((slope * (p[0] - r[0]) - p[1]) % P)
        return (r[0], r[1])


def EC_inv(p):
    """椭圆曲线逆元"""
    r = [p[0]]
    r.append(P - p[1])
    return r


# 椭圆曲线减法:p - q
def EC_sub(p, q):
    q_inv = EC_inv(q)
    return EC_add(p, q_inv)


# 自加p+p
def EC_double(p):
    r = []
    slope = (3 * p[0] ** 2 + A) * inv(2 * p[1], P) % P
    r.append((slope ** 2 - 2 * p[0]) % P)
    r.append((slope * (p[0] - r[0]) - p[1]) % P)
    return (r[0], r[1])


# 椭圆曲线多倍点运算
def EC_multi(s, p):
    """
    :param s: 倍数
    :param p: 点
    :return: 运算结果
    """
    n = p
    r = 0
    s_bin = bin(s)[2:]
    s_len = len(s_bin)

    for i in reversed(range(s_len)):  # 类快速幂思想
        if s_bin[i] == '1':
            r = EC_add(r, n)
        n = EC_double(n)

    return r


def get_bit_num(x):
    """获得x的比特长度"""
    if isinstance(x, int):  # when int
        num = 0
        tmp = x >> 64
        while tmp:
            num += 64
            tmp >>= 64
        tmp = x >> num >> 8
        while tmp:
            num += 8
            tmp >>= 8
        x >>= num
        while x:
            num += 1
            x >>= 1
        return num
    elif isinstance(x, str):  # when string
        return len(x.encode()) << 3
    elif isinstance(x, bytes):  # when bytes
        return len(x) << 3
    return 0


# 产生公私钥对
def key_gen():
    sk = int(secrets.token_hex(32), 16)  # private key
    pk = EC_multi(sk, G)  # public key
    return sk, pk


# ECDSA签名
def ECDSA_sign(m, sk):
    """ECDSA signature algorithm
    :param m: message
    :param sk: private key
    :return signature: (r, s)
    """
    while 1:
        k = secrets.randbelow(N)  # N is prime, then k <- Zn*
        R = EC_multi(k, G)
        r = R[0] % N  # Rx mod n
        if r != 0:
            break
    e = sm3.sm3_hash(func.bytes_to_list(bytes(m, encoding='utf-8')))  # e = hash(m)
    e = int(e, 16)
    s = inv(k, N) * (e + sk * r) % N
    return (r, s)


# ECDSA验签:不使用message
def ECDSA_verify_m_not_check(signature, e, pk):
    r, s = signature
    x = EC_multi(inv(s, N), EC_add(EC_multi(e, G), EC_multi(r, pk)))
    return x[0] % N == r


# 伪造中本聪的签名
def Pretend_Satoshi(pk):
    u = random.randrange(1, N - 1)
    v = random.randrange(1, N - 1)
    R = EC_add(EC_multi(u, G), EC_multi(v, pk))
    r = R[0] % N
    e = (r * u * inv(v, N)) % N
    s = (r * inv(v, N)) % N
    signature_forge = (r, s)
    print("伪造的签名为:")
    print((hex(r), hex(s)))
    return ECDSA_verify_m_not_check(signature_forge, e, pk)


if __name__ == '__main__':
    # Satoshi的公私钥对,公钥公开可以获取
    sk, pk = key_gen()
    # 伪造Satoshi的签名
    print("-------------------------------------------------------------------------------------")
    print("                   forge a signature to pretend that you are Satoshi                 ")
    print("-------------------------------------------------------------------------------------")
    print("伪造的签名是否是合法签名:", Pretend_Satoshi(pk))
