"""
UTXO Commitment: Elliptic curve MultiSet Hash
将hash值作为椭圆曲线上的x点,根据椭圆曲线方程y^2 = x^3 + Ax + B来计算y值会存在无解的情况
本code将消息hash到椭圆曲线上的方法:
    (1) 首先计算消息的sm3 hash值
    (2) 将sm3 hash值作为k值
    (3) (x, y) = k * G
本code完成的测试:
    (1) hash({a,b}) == hash({b,a})
    (2) hash(a) + hash(b) == hash({a,b})
    (3) hash({a,b,c}) - hash(c) == hash({a,b})
"""
from gmssl import sm3, func

A = 0
B = 7
G_X = 55066263022277343669578718895168534326250603453777594175500187360389116729240
G_Y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (G_X, G_Y)
P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
h = 1


# 扩展欧几里得算法求逆
def inv(a, n):
    def ext_gcd(a, b, arr):
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
    # 0 代表无穷远点
    if p == 0 and q == 0:
        return 0  # 0 + 0 = 0
    elif p == 0:
        return q  # 0 + q = q
    elif q == 0:
        return p  # p + 0 = p
    else:
        if p[0] == q[0]:
            if (p[1] + q[1]) % P == 0:
                return 0
            elif p[1] == q[1]:
                return EC_double(p)
        elif p[0] > q[0]:
            tmp = p
            p = q
            q = tmp
        r = []
        slope = (q[1] - p[1]) * inv(q[0] - p[0], P) % P
        r.append((slope ** 2 - p[0] - q[0]) % P)
        r.append((slope * (p[0] - r[0]) - p[1]) % P)
        return (r[0], r[1])


# 椭圆曲线逆元
def EC_inv(p):
    r = [p[0]]
    r.append(P - p[1])
    return r


# 椭圆曲线减法:p - q
def EC_sub(p, q):
    q_inv = EC_inv(q)
    return EC_add(p, q_inv)


# 椭圆曲线双倍点
def EC_double(p):
    r = []
    slope = (3 * p[0] ** 2 + A) * inv(2 * p[1], P) % P
    r.append((slope ** 2 - 2 * p[0]) % P)
    r.append((slope * (p[0] - r[0]) - p[1]) % P)
    return (r[0], r[1])


# 椭圆曲线多倍点
def EC_multi(s, p):
    n = p
    r = 0
    s_bin = bin(s)[2:]
    s_len = len(s_bin)

    for i in reversed(range(s_len)):  # 类快速幂思想
        if s_bin[i] == '1':
            r = EC_add(r, n)
        n = EC_double(n)

    return r


# 将消息hash到椭圆曲线上
def hash_to_dot(msg):
    # 将sm3的hash值作为x点
    x = sm3.sm3_hash(func.bytes_to_list(bytes(msg, encoding='utf-8')))
    x = int(x, 16) % N
    # 求y
    # hash为椭圆曲线上的点
    hash_value = EC_multi(x, G)
    return hash_value


# Elliptic curve MultiSet Hash ------ Combine/add/remove elements
# combine操作:生成集合的hash值
def combine(msg_set):
    hash_set = EC_add(0, 0)
    for i in range(len(msg_set)):
        hash_set = EC_add(hash_set, hash_to_dot(msg_set[i]))
    return hash_set


# add操作:hash({a,b}) + hash(c) --- 集合的hash值 + 单个消息的hash值
def add(hash_set, msg):
    hash_value = hash_to_dot(msg)
    hash_set = EC_add(hash_set, hash_value)
    return hash_set


# remove操作:hash({a,b,c}) - hash(c) --- 集合的hash值 - 单个消息的hash值
def remove(hash_set, msg):
    hash_value = hash_to_dot(msg)
    hash_set = EC_sub(hash_set, hash_value)
    return hash_set



if __name__=='__main__':
    a = "sdu_cst"
    b = "project"
    c = "Zhang_201900180019"
    print("-------------------------------------------------------------------------------")
    print("                                计算a,b,c的hash值                               ")
    print("-------------------------------------------------------------------------------")
    # 计算hash(a),hash(b),hash(c)
    hash_a = hash_to_dot(a)
    print("hash(a):")
    print(hash_a)
    hash_b = hash_to_dot(b)
    print("hash(b):")
    print(hash_b)
    hash_c = hash_to_dot(c)
    print("hash(c):")
    print(hash_c)
    print("-------------------------------------------------------------------------------")
    print("                         测试hash({a,b}) == hash({b, a})                        ")
    print("-------------------------------------------------------------------------------")
    # 测试hash({a,b}) == hash({b, a})
    set_ab = [a, b]
    hash_ab = combine(set_ab)
    print("hash({a,b}):")
    print(hash_ab)
    set_ba = [b, a]
    hash_ba = combine(set_ba)
    print("hash({b,a}):")
    print(hash_ba)
    print("-------------------------------------------------------------------------------")
    print("hash({a,b}) == hash({b, a})?:", hash_ab == hash_ba)
    print("-------------------------------------------------------------------------------")
    print("                  测试add操作:hash(a) + hash(b) == hash({a,b})                  ")
    print("-------------------------------------------------------------------------------")
    # 测试add操作:hash(a) + hash(b) == hash({a,b})
    hash_add_ab = add(combine([a]), b)
    print("hash(a) + hash(b):")
    print(hash_add_ab)
    print("hash({a,b}):")
    print(hash_ab)
    print("-------------------------------------------------------------------------------")
    print("hash(a) + hash(b) == hash({a,b})?", hash_add_ab == hash_ab)
    print("-------------------------------------------------------------------------------")
    print("               测试sub操作:hash({a,b,c}) - hash(c) == hash({a,b})               ")
    print("-------------------------------------------------------------------------------")
    # 测试sub操作:hash({a,b,c}) - hash(c) == hash({a,b})
    set_abc = [a, b, c]
    hash_abc = combine(set_abc)
    print("hash({a,b,c}):")
    print(hash_abc)
    hash_abc_remove_c = remove(hash_abc, c)
    print("hash({a,b,c}) - hash(c):")
    print(hash_abc_remove_c)
    print("hash({a,b}):")
    print(hash_ab)
    print("-------------------------------------------------------------------------------")
    print("hash({a,b,c}) - hash(c) == hash({a,b})?", hash_abc_remove_c == hash_ab)
    print("-------------------------------------------------------------------------------")
