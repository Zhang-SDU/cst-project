"""
report on the application of this deduce technique in Ethereum with ECDSA
本code旨在由ECDSA签名推出公钥
"""
import secrets
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


# Tonelli_Shanks求二次剩余
def Legendre(n, p):  # 这里用勒让德符号来表示判断二次（非）剩余的过程
    return pow(n, (p - 1) // 2, p)


def Tonelli_Shanks(n, p):
    assert Legendre(n, p) == 1
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q = p - 1
    s = 0
    while q % 2 == 0:
        q = q // 2
        s += 1
    for z in range(2, p):
        if Legendre(z, p) == p - 1:
            c = pow(z, q, p)
            break
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    if t % p == 1:
        return r
    else:
        i = 0
        while t % p != 1:  # 外层循环的判断条件
            temp = pow(t, 2 ** (i + 1), p)  # 这里写作i+1是为了确保之后内层循环用到i值是与这里的i+1的值是相等的
            i += 1
            if temp % p == 1:  # 内层循环的判断条件
                b = pow(c, 2 ** (m - i - 1), p)
                r = r * b % p
                c = b * b % p
                t = t * c % p
                m = i
                i = 0  # 注意每次内层循环结束后i值要更新为0
        return r


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
    tmp1 = inv(k, N)
    tmp2 = (e + sk * r) % N
    s = tmp1 * tmp2 % N
    return (r, s)


# ECDSA验签
def ECDSA_verify(signature, m, pk):
    """ECDSA algorithm
    :param signature: (r, s)
    :param m: message
    :param pk: public key
    :return:True or False
    """
    r, s = signature
    e = sm3.sm3_hash(func.bytes_to_list(bytes(m, encoding='utf-8')))  # e = hash(m)
    e = int(e, 16)
    w = inv(s, N)
    tmp1 = EC_multi(e * w, G)
    tmp2 = EC_multi(r * w, pk)
    dot = EC_add(tmp1, tmp2)
    x = dot[0]
    return x == r


# 由签名推得公钥pk
# s * kG = eG + rP mod n
def deduce_pk_from_sig(signature, msg):
    r, s = signature
    # kG = R = (x, y)
    x = r % P
    y2 = pow(x, 3) + A * x + B
    y = Tonelli_Shanks(y2, P)
    # 两个候选点
    R1 = (x, y)
    R2 = (x, P - y)
    # 求e = hash(m)
    e = sm3.sm3_hash(func.bytes_to_list(bytes(msg, encoding='utf-8')))
    # 由R1求pk1
    pk1 = EC_multi(inv(r, N), EC_sub(EC_multi(s, R1), EC_multi(int(e, 16), G)))
    print("候选公钥pk1:", pk1)
    print("--------------------------------------------------------------------------------------------")
    # 由R2求pk2
    pk2 = EC_multi(inv(r, N), EC_sub(EC_multi(s, R2), EC_multi(int(e, 16), G)))
    print("候选公钥pk2:", pk2)
    print("--------------------------------------------------------------------------------------------")


if __name__ == '__main__':
    print("--------------------------------------------------------------------------------------------")
    print("                            deduce pk from signature  with ECDSA                            ")
    print("--------------------------------------------------------------------------------------------")
    sk, pk = key_gen()
    print("正确的公钥为:", pk)
    print("--------------------------------------------------------------------------------------------")
    msg = "sdu_cst_project!"
    signature = ECDSA_sign(msg, sk)
    print("对消息的签名为:", signature)
    print("--------------------------------------------------------------------------------------------")
    deduce_pk_from_sig(signature, msg)
