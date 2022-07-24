"""
ECDSA signature pitfalls
本code主要完成了以下4个task:
1. Leaking k leads to leaking of d
2. Reusing k leads to leaking of d
3. Two users, using k leads to leaking of d, that is they can deduce each other's d
4. Malleability, e.g. (r,s) and (r,-s) are both valid signatures
"""

from ECDSA import *
import secrets
from gmssl import sm3, func


# ECDSA签名,并返回签名以及k
def ECDSA_sign_and_return_k(m, sk):
    """ECDSA signature algorithm
    :param m: message
    :param sk: private key
    :return signature: (r, s),k
    """
    while 1:
        k = secrets.randbelow(N)  # N is prime, then k <- Zn*
        R = EC_multi(k, G)
        r = R[0] % N  # Rx mod n
        if r != 0: break
    e = sm3.sm3_hash(func.bytes_to_list(bytes(m, encoding='utf-8')))  # e = hash(m)
    e = int(e, 16)
    s = (inv(k, N) * (e + sk * r) % N) % N
    return (r, s), k


# 使用给定的k进行签名
def ECDSA_sign_and_assign_k(m, k, sk):
    """ECDSA signature algorithm
    :param m: message
    :param sk: private key
    :return signature: (r, s),k
    """
    R = EC_multi(k, G)
    r = R[0] % N  # Rx mod n
    e = sm3.sm3_hash(func.bytes_to_list(bytes(m, encoding='utf-8')))  # e = hash(m)
    e = int(e, 16)
    tmp1 = inv(k, N)
    tmp2 = (e + sk * r) % N
    s = tmp1 * tmp2 % N
    return (r, s), k


# ----------------------------------------------------------------------------------- #
# leaking k leads to leaking of d
# k的泄露会导致泄露d
def ECDSA_leaking_k():
    # Alice生成公私钥对并对消息进行签名
    sk, pk = key_gen()  # A publish pk for others to verify
    print("Alice的私钥为:", "0x" + hex(sk)[2:].rjust(64, '0'))
    message_A = "message of A"
    # return k为leaking k
    signature, k = ECDSA_sign_and_return_k(message_A, sk)
    # Bob通过Alice的signature、message以及k推测Alice的d即私钥
    # d = (s * k - e) / r
    r, s = signature
    e = sm3.sm3_hash(func.bytes_to_list(bytes(message_A, encoding='utf-8')))  # e = hash(m)
    e = int(e, 16)
    d = (s * k - e) % N * inv(r, N) % N
    print("Bob推测的d为:", '0x' + hex(d)[2:].rjust(64, '0'))
    # 验证Bob得到的d是否与Alice的sk相等
    print("验证Bob推测的d是否与Alice的sk相等:", True if d == sk else False)

    # Bob根据推测的d伪造Alice的签名
    message_for_forge = "message of B"
    # 伪造签名
    forged_signature = ECDSA_sign(message_for_forge, d)
    # 用Alice的公钥验证Bob伪造的签名
    print("验证Bob是否通过d伪造签名成功:", True if ECDSA_verify(forged_signature, message_for_forge, pk) == 1 else False)
    if ECDSA_verify(forged_signature, message_for_forge, pk) == 1:
        print('leaking k leads to leaking of d is successful.')


# ----------------------------------------------------------------------------------- #

# Reusing k leads to leaking of d
# 对不同的消息使用相同的k进行签名会泄露d
def ECDSA_reusing_k():
    # Alice使用相同的k生成两个消息的签名
    sk, pk = key_gen()  # A publish pk for others to verify
    print("Alice的私钥为:", "0x" + hex(sk)[2:].rjust(64, '0'))
    message_A1 = "message1 of A"
    message_A2 = "message2 of A"
    signature1, k1 = ECDSA_sign_and_return_k(message_A1, sk)
    signature2, k2 = ECDSA_sign_and_assign_k(message_A2, k1, sk)
    # Bob通过Alice的两个signature、message以及k推测Alice的d即私钥
    # d = [(s1 - s2) * k - (e1 - e2)] / (r1 - r2)
    r1, s1 = signature1
    r2, s2 = signature2
    # 重复使用k,r1 = r2
    r = r1
    e1 = sm3.sm3_hash(func.bytes_to_list(bytes(message_A1, encoding='utf-8')))  # e = hash(m)
    e1 = int(e1, 16)
    e2 = sm3.sm3_hash(func.bytes_to_list(bytes(message_A2, encoding='utf-8')))  # e = hash(m)
    e2 = int(e2, 16)
    d = (((e1 - e2) * s2) % N * inv((s1 - s2) % N, N) - e2) * inv(r, N) % N
    print("Bob推测的d为:", '0x' + hex(d)[2:].rjust(64, '0'))
    print("验证Bob推测的d是否与Alice的sk相等:", True if d == sk else False)
    print("检验两个签名是否使用相同的k值:", True if k1 == k2 else False)
    # Bob根据推测的d伪造Alice的签名
    message_for_forge = "message of B"
    # 伪造签名
    forged_signature = ECDSA_sign(message_for_forge, d)
    # 用Alice的公钥验证Bob伪造的签名
    print("验证Bob是否通过d伪造签名成功:", True if ECDSA_verify(forged_signature, message_for_forge, pk) == 1 else False)
    if ECDSA_verify(forged_signature, message_for_forge, pk) == 1:
        print('Reusing k leads to leaking of d is successful.')


# ----------------------------------------------------------------------------------- #
# Reusing k by different users can deduce each other's d
# 两个不同的user使用相同的k:此类情况下相当于leaking k,所以可以相互推测对方的私钥d
# 伪造签名同上,所以这一步省略了伪造签名的步骤
def same_k_of_different_users():
    # Alice和Bob使用相同的k分别生成消息签名
    # Alice
    sk_A, pk_A = key_gen()  # A publish pk for others to verify
    print("Alice的私钥为:", "0x" + hex(sk_A)[2:].rjust(64, '0'))
    message_A = "message of A"
    signature_A, k = ECDSA_sign_and_return_k(message_A, sk_A)
    # Bob
    sk_B, pk_B = key_gen()  # A publish pk for others to verify
    print("Bob的私钥为:", "0x" + hex(sk_B)[2:].rjust(64, '0'))
    message_B = "message of B"
    signature_B, k = ECDSA_sign_and_assign_k(message_B, k, sk_B)

    # Bob通过Alice的signature、message以及k推测Alice的d即私钥
    # d = (s * k - e) / r
    r1, s1 = signature_A
    e1 = sm3.sm3_hash(func.bytes_to_list(bytes(message_A, encoding='utf-8')))  # e = hash(m)
    e1 = int(e1, 16)
    d_A = (s1 * k - e1) % N * inv(r1, N) % N
    print("Bob推测的Alice的d为:", '0x' + hex(d_A)[2:].rjust(64, '0'))

    # Alice通过Bob的signature、message以及k推测Bob的d即私钥
    # d = (s * k - e) / r
    r2, s2 = signature_B
    e2 = sm3.sm3_hash(func.bytes_to_list(bytes(message_B, encoding='utf-8')))  # e = hash(m)
    e2 = int(e2, 16)
    d_B = (s2 * k - e2) % N * inv(r2, N) % N
    print("Alice推测的Bob的d为:", '0x' + hex(d_B)[2:].rjust(64, '0'))

    # 验证Alice和Bob的猜测是否正确
    print("验证Bob推测的d是否与Alice的sk相等:", True if d_A == sk_A else False)
    print("验证Alice推测的d是否与Bob的sk相等:", True if d_B == sk_B else False)


# ----------------------------------------------------------------------------------- #
# Malleability, e.g. (r,s) and (r,-s) are both valid signatures
# 即验证(r,s) and (r,-s)均为合法签名
def verify_Malleability():
    # Alice生成消息签名
    sk, pk = key_gen()  # A publish pk for others to verify
    message = "message of A"
    signature = ECDSA_sign(message, sk)
    r, s = signature
    signature_test = (r, -s)
    print("验证(r,-s)是否是合法签名:", True if ECDSA_verify(signature_test, message, pk) == 1 else Flase)


if __name__ == '__main__':
    print("-------------------------------------------------------------------------------------")
    print("                          1.leaking k leads to leaking of d                          ")
    print("-------------------------------------------------------------------------------------")
    ECDSA_leaking_k()
    print("-------------------------------------------------------------------------------------")
    print("                          2.Reusing k leads to leaking of d                          ")
    print("-------------------------------------------------------------------------------------")
    ECDSA_reusing_k()
    print("-------------------------------------------------------------------------------------")
    print("                3.Reusing k by different users can deduce each other's d             ")
    print("-------------------------------------------------------------------------------------")
    same_k_of_different_users()
    print("-------------------------------------------------------------------------------------")
    print("             4.Malleability, e.g. (r,s) and (r,-s) are both valid signatures         ")
    print("-------------------------------------------------------------------------------------")
    verify_Malleability()
    print("-------------------------------------------------------------------------------------")
