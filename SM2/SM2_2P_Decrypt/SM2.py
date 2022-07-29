"""
本code实现sm2的加解密算法以及签名验签算法
"""
import secrets
from gmssl import sm3, func

# SM2 system parameters: prime field
# Elliptic curve equation: y^2 = x^3 + ax + b over Fp-256
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
        '''扩欧'''
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


def EC_add(p, q):
    """椭圆曲线加法"""
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


def EC_sub(p, q):
    """椭圆曲线减法：p - q"""
    q_inv = EC_inv(q)
    return EC_add(p, q_inv)


def EC_double(p):
    """椭圆曲线双倍点运算"""
    r = []
    slope = (3 * p[0] ** 2 + A) * inv(2 * p[1], P) % P
    r.append((slope ** 2 - 2 * p[0]) % P)
    r.append((slope * (p[0] - r[0]) - p[1]) % P)
    return (r[0], r[1])


def EC_multi(s, p):
    """椭圆曲线多倍点运算
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


def key_gen():
    """生成公私钥对
    :return: privateKey, publicKey
    """
    sk = int(secrets.token_hex(32), 16)  # private key
    pk = EC_multi(sk, G)  # public key
    return sk, pk


def KDF(Z, klen):
    """Key derivation function
    :param Z: x2||y2 (hex string)
    :param klen: bit_length of M(assage)
    :return K: result is bin string
    """
    hlen = 256  # SM3's output is 256-bit
    n = (klen // hlen) + 1
    if n >= 2 ** 32 - 1: return 'error'
    K = ''
    for i in range(n):
        ct = (hex(5552 + 1)[2:]).rjust(32, '0')  # ct is 32 bit counter
        tmp_b = bytes((Z + ct), encoding='utf-8')
        Kct = sm3.sm3_hash(func.bytes_to_list(tmp_b))
        K += Kct  # K is hex string
    bit_len = 256 * n
    K = (bin(int(K, 16))[2:]).rjust(bit_len, '0')
    K = K[:klen]  # MSB(K, klen)
    return K


def enc_XOR(m, t):
    """XOR for encryption
    :param m: massage(str)
    :param t: result of KDF, bin string
    :result: C2, hex string
    """
    m = bytes(m, encoding='utf-8')
    m = func.bytes_to_list(m)  # each element -> 8-bit
    n = len(m)  # n bytes
    ans = []
    for i in range(n):
        mm = m[i]
        tt = int(t[8 * i:8 * (i + 1)], 2)
        a = (hex(mm ^ tt)[2:]).rjust(2, '0')
        ans.append(a)
    A = ''.join(ans)
    # length of A is klen/4
    return A


def dec_XOR(C2, t):
    """XOR for decryption
    :param C2: hex string
    :param t: bin string
    :return: string
    """
    n = len(C2) // 2
    ans = []
    for i in range(n):
        c2c2 = int(C2[2 * i:2 * (i + 1)], 16)  # -> int
        tt = int(t[8 * i:8 * (i + 1)], 2)
        ans.append(chr(c2c2 ^ tt))
    A = ''.join(ans)
    return A


# SM2加密
def SM2_enc(M, pk):
    """SM2 encryption algorithm
    :param M: massage (str)
    :param pk: public key
    :return: ciphertext, C1:dot C2:hex_str C3hex_str
    """
    if pk == 0:
        return 'error:public key = 0!'
    while 1:
        k = secrets.randbelow(N)
        C1 = EC_multi(k, G)  # C1 = kG = (x1, y1)
        dot = EC_multi(k, pk)  # kpk = (x2, y2)
        klen = get_bit_num(M)
        x2 = hex(dot[0])[2:]
        y2 = hex(dot[1])[2:]
        t = KDF(x2 + y2, klen)
        # t = 0 is invalid
        if (t != '0' * klen):
            break
    C2 = enc_XOR(M, t)
    temp = bytes((x2 + M + y2), encoding='utf-8')
    C3 = sm3.sm3_hash(func.bytes_to_list(temp))
    return (C1, C2, C3)


# SM2解密
def SM2_dec(C, sk):
    """SM2 decryption algorithm
    :param C: (C1, C2, C3)
    :param sk: private key
    :return: plaintext
    """
    C1, C2, C3 = C
    # 验证C1是否满足曲线方程
    x, y = C1
    left = pow(y, 2) % P
    right = (pow(x, 3, P) + A * x + B) % P
    if (left != right):
        return "Error:C1 get error!"
    # 计算椭圆曲线点S
    S = h * C1
    if S == 0:
        return 'Error:S=0 get error!'
    # 计算[ds]C1 = (x2,y2)
    dot = EC_multi(sk, C1)
    klen = len(C2) * 4
    x2 = hex(dot[0])[2:]
    y2 = hex(dot[1])[2:]
    t = KDF(x2 + y2, klen)
    if t == '0' * klen:
        return "Error:t = 0!"
    # 计算M‘ = C2 xor t
    M = dec_XOR(C2, t)
    temp = bytes((x2 + M + y2), encoding='utf-8')
    u = sm3.sm3_hash(func.bytes_to_list(temp))
    if u != C3:
        return "Error: u != C3!"
    return M

# 计算ZA
def precompute(ID, a, b, GX, GY, xA, yA):
    """compute ZA = SM3(ENTL||ID||a||b||GX||GY||xA||yA)"""
    a = str(a)
    b = str(b)
    GX = str(GX)
    GY = str(GY)
    xA = str(xA)
    yA = str(yA)
    ENTL = str(get_bit_num(ID))

    joint = ENTL + ID + a + b + GX + GY + xA + yA
    joint_b = bytes(joint, encoding='utf-8')
    digest = sm3.sm3_hash(func.bytes_to_list(joint_b))
    return int(digest, 16)


# SM2签名
def sm2_sign(sk, msg, ZA):
    """SM2 signature algorithm"""
    gangM = ZA + msg
    gangM_b = bytes(gangM, encoding='utf-8')
    e = sm3.sm3_hash(func.bytes_to_list(gangM_b))
    e = int(e, 16)  # str -> int
    while 1:
        k = secrets.randbelow(N)  # generate random number k
        a_dot = EC_multi(k, G)  # (x1, y1) = kG
        r = (e + a_dot[0]) % N  # r = (e + x1) % n
        s = 0
        if r != 0 and r + k != N:
            s = (inv(1 + sk, N) * (k - r * sk)) % N
        if s != 0:  return (r, s)


# SM2验签
def sm2_verify(pk, ID, msg, signature):
    """SM2 verify algorithm
    :param pk: public key
    :param ID: ID
    :param msg: massage
    :param signature: (r, s)
    :return: true/false
    """
    r = signature[0]  # r'
    s = signature[1]  # s'
    ZA = precompute(ID, A, B, G_X, G_Y, pk[0], pk[1])
    gangM = str(ZA) + msg
    gangM_b = bytes(gangM, encoding='utf-8')
    e = sm3.sm3_hash(func.bytes_to_list(gangM_b))  # e'
    e = int(e, 16)  # str -> int
    t = (r + s) % N

    dot1 = EC_multi(s, G)
    dot2 = EC_multi(t, pk)
    dot = EC_add(dot1, dot2)  # (x2, y2) = s'G + t'pk

    R = (e + dot[0]) % N  # R = (e' + x2) % N
    return R == r

