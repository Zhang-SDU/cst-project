"""
SM2 signature pitfalls
本code主要完成了以下4个task:
1. Leaking k leads to leaking of d
2. Reusing k leads to leaking of d
3. Two users, using k leads to leaking of d, that is they can deduce each other's d
4. Same d and k between ECDSA and SM2, leads to leaking d
"""
from SM2 import *
from gmssl import sm3, func
import secrets


# 使用给定的k进行签名
def sm2_sign_and_assign_k(k, sk, msg, ZA):
    gangM = ZA + msg
    gangM_b = bytes(gangM, encoding='utf-8')
    e = sm3.sm3_hash(func.bytes_to_list(gangM_b))
    e = int(e, 16)  # str -> int
    a_dot = EC_multi(k, G)  # (x1, y1) = kG
    r = (e + a_dot[0]) % N  # r = (e + x1) % n
    s = 0
    if r != 0 and r + k != N:
        s = (inv(1 + sk, N) * (k - r * sk)) % N
    if s != 0:
        return (r, s)


# 使用给定的k进行签名
def ECDSA_sign_and_assign_k(k, m, sk):
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
    return (r, s)


# ----------------------------------------------------------------------------------- #
# leaking k leads to leaking of d
# k的泄露会导致泄露d
def sm2_leaking_k():
    # Alice生成公私钥对并对消息进行签名
    sk, pk = key_gen()  # A publish pk for others to verify
    print("Alice的私钥为:", "0x" + hex(sk)[2:].rjust(64, '0'))
    k = secrets.randbelow(N)  # 该k为泄露的k
    message = "test: SM2 leaking k"
    ID = 'SM2_leaking_k_userA'
    ZA = precompute(ID, A, B, G_X, G_Y, pk[0], pk[1])
    signature = sm2_sign_and_assign_k(k, sk, message, str(ZA))
    # Bob通过Alice的signature、message以及k推测Alice的d即私钥
    # d = (k - s) / (s + r)
    r, s = signature
    d = (k - s) * inv(s + r, N) % N
    print("Bob推测的d为:", '0x' + hex(d)[2:].rjust(64, '0'))
    # 验证Bob得到的d是否与Alice的sk相等
    print("验证Bob推测的d是否与Alice的sk相等:", True if d == sk else False)

    # Bob根据推测的d伪造Alice的签名
    message_for_forge = "test: SM2 leaking k: B forge a signature"
    # 伪造签名
    ID_for_forge = ID
    pk_from_d = EC_multi(d, G)
    ZA_for_forge = precompute(ID_for_forge, A, B, G_X, G_Y, pk_from_d[0], pk_from_d[1])
    forged_signature = sm2_sign(d, message_for_forge, str(ZA_for_forge))
    # 用Alice的公钥验证Bob伪造的签名
    print("验证Bob是否通过d伪造签名成功:",
          True if sm2_verify(pk, ID_for_forge, message_for_forge, forged_signature) == 1 else False)
    if sm2_verify(pk, ID_for_forge, message_for_forge, forged_signature) == 1:
        print('leaking k leads to leaking of d is successful.')


# ----------------------------------------------------------------------------------- #

# Reusing k leads to leaking of d
# 对不同的消息使用相同的k进行签名会泄露d
def sm2_reusing_k():
    # Alice使用相同的k生成两个消息的签名
    sk, pk = key_gen()  # A publish pk for others to verify
    print("Alice的私钥为:", "0x" + hex(sk)[2:].rjust(64, '0'))
    message1 = "test: SM2 reusing k_1"
    message2 = "test: SM2 reusing k_2"
    k = secrets.randbelow(N)  # 相同的k值
    ID = 'SM2_reusing_k_userA'
    ZA = precompute(ID, A, B, G_X, G_Y, pk[0], pk[1])
    signature1 = sm2_sign_and_assign_k(k, sk, message1, str(ZA))
    signature2 = sm2_sign_and_assign_k(k, sk, message2, str(ZA))
    # Bob通过Alice的两个signature、message以及k推测Alice的d即私钥
    # d = (s2 - s1) / (s1 - s2 + r1 - r2) mod N
    r1, s1 = signature1
    r2, s2 = signature2
    d = (s2 - s1) * inv((s1 - s2 + r1 - r2), N) % N
    print("Bob推测的d为:", '0x' + hex(d)[2:].rjust(64, '0'))
    print("验证Bob推测的d是否与Alice的sk相等:", True if d == sk else False)
    # Bob根据推测的d伪造Alice的签名
    message_for_forge = "test: SM2 reusing k: B forge a signature"
    # 伪造签名
    ID_for_forge = ID
    pk_from_d = EC_multi(d, G)
    ZA_for_forge = precompute(ID_for_forge, A, B, G_X, G_Y, pk_from_d[0], pk_from_d[1])
    forged_signature = sm2_sign(d, message_for_forge, str(ZA_for_forge))
    # 用Alice的公钥验证Bob伪造的签名
    print("验证Bob是否通过d伪造签名成功:",
          True if sm2_verify(pk, ID_for_forge, message_for_forge, forged_signature) == 1 else False)
    if sm2_verify(pk, ID_for_forge, message_for_forge, forged_signature) == 1:
        print('Reusing k leads to leaking of d is successful.')


# ----------------------------------------------------------------------------------- #
# Reusing k by different users can deduce each other's d
# 两个不同的user使用相同的k:此类情况下相当于leaking k,所以可以相互推测对方的私钥d
# 伪造签名同上,所以这一步省略了伪造签名的步骤
def same_k_of_different_users():
    # Alice和Bob使用相同的k分别生成消息签名
    k = secrets.randbelow(N)  # 相同的k值
    # Alice
    sk_A, pk_A = key_gen()  # Alice publish pk for others to verify
    print("Alice的私钥为:", "0x" + hex(sk_A)[2:].rjust(64, '0'))
    message_A = "test: SM2 reusing k_1"
    ID_A = 'SM2_reusing_k_userA'
    ZA = precompute(ID_A, A, B, G_X, G_Y, pk_A[0], pk_A[1])
    signature_A = sm2_sign_and_assign_k(k, sk_A, message_A, str(ZA))
    # Bob
    sk_B, pk_B = key_gen()  # Bob publish pk for others to verify
    print("BOb的私钥为:", "0x" + hex(sk_B)[2:].rjust(64, '0'))
    message_B = "test: SM2 reusing k_1"
    ID_B = 'SM2_reusing_k_userA'
    ZB = precompute(ID_B, A, B, G_X, G_Y, pk_B[0], pk_B[1])
    signature_B = sm2_sign_and_assign_k(k, sk_B, message_B, str(ZB))

    # Bob通过Alice的signature、message以及k推测Alice的d即私钥
    # d = (k - s) / (s + r)
    r1, s1 = signature_A
    d_A = (k - s1) * inv(s1 + r1, N) % N
    print("Bob推测的d为:", '0x' + hex(d_A)[2:].rjust(64, '0'))

    # Alice通过Bob的signature、message以及k推测Bob的d即私钥
    # d = (k - s) / (s + r)
    r2, s2 = signature_B
    d_B = (k - s2) * inv(s2 + r2, N) % N
    print("Alice推测的d为:", '0x' + hex(d_B)[2:].rjust(64, '0'))

    # 验证Alice和Bob的推测是否正确
    print("验证Bob推测的d是否与Alice的sk相等:", True if d_A == sk_A else False)
    print("验证Alice推测的d是否与Bob的sk相等:", True if d_B == sk_B else False)


# ----------------------------------------------------------------------------------- #
# Same d and k between ECDSA and SM2, leads to leaking d
# ECDSA与SM2使用相同的d和k从而泄露d
def same_dk_of_ECDSA_SM2():
    # same d and k
    sk, pk = key_gen()
    print("共同的私钥为:", "0x" + hex(sk)[2:].rjust(64, '0'))
    k = secrets.randbelow(N)
    # ECDSA签名
    message1 = "signature1 from ECSDA with sk, k"
    signature1 = ECDSA_sign_and_assign_k(k, message1, sk)
    # SM2签名
    message2 = "signature2 from ECSDA with sk, k1"
    ID = 'SM2_same_dk_with_ECDSA'
    ZA = precompute(ID, A, B, G_X, G_Y, pk[0], pk[1])
    signature2 = sm2_sign_and_assign_k(k, sk, message2, str(ZA))
    # 由ECDSA和SM2签名以及两个消息推测d
    # d = (s1s2 - e1) / (r1 - s1s1 - s1r2)
    """ECDSA->1  SM2->2"""
    r1, s1 = signature1
    r2, s2 = signature2
    e1 = int(sm3.sm3_hash(func.bytes_to_list(bytes(message1, encoding='utf-8'))), 16)
    tmp1 = s1 * s2 - e1 % N
    tmp2 = r1 - s1 * s2 - s1 * r2 % N
    tmp2 = inv(tmp2, N)
    d = tmp1 * tmp2 % N
    print("推测的d为:", "0x" + hex(d)[2:].rjust(64, '0'))
    print("验证推测的d是否与sk相等:", True if d == sk else False)


if __name__ == '__main__':
    print("-------------------------------------------------------------------------------------")
    print("                          1.leaking k leads to leaking of d                          ")
    print("-------------------------------------------------------------------------------------")
    sm2_leaking_k()
    print("-------------------------------------------------------------------------------------")
    print("                          2.Reusing k leads to leaking of d                          ")
    print("-------------------------------------------------------------------------------------")
    sm2_reusing_k()
    print("-------------------------------------------------------------------------------------")
    print("                3.Reusing k by different users can deduce each other's d             ")
    print("-------------------------------------------------------------------------------------")
    same_k_of_different_users()
    print("-------------------------------------------------------------------------------------")
    print("                4.Same d and k between ECDSA and SM2, leads to leaking d             ")
    print("-------------------------------------------------------------------------------------")
    same_dk_of_ECDSA_SM2()
    print("-------------------------------------------------------------------------------------")
