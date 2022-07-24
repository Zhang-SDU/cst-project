"""
Schnorr signature pitfalls
本code主要完成了以下5个task:
1. Leaking k leads to leaking of d
2. Reusing k leads to leaking of d
3. Two users, using k leads to leaking of d, that is they can deduce each other's d
4. Malleability, e.g. (r,s) and (r,-s) are both valid signatures
5. Same d and k between ECDSA and Schnorr, leads to leaking d
"""

from Schnorr import *
from gmssl import sm3, func
import secrets


# 使用给定的k进行签名
def Schnorr_sign_and_assign_k(k, M, sk):
    """
    :return signature: (R, s)
    """
    R = EC_multi(k, G)
    tmp = str(R[0]) + str(R[1]) + M
    e = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    s = k + e * sk % N
    return (R, s)


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
def Schnorr_leaking_k():
    # Alice生成公私钥对并对消息进行签名
    sk, pk = key_gen()  # A publish pk for others to verify
    print("Alice的私钥为:", "0x" + hex(sk)[2:].rjust(64, '0'))
    message_A = "message of A"
    k = secrets.randbelow(N)  # 该k为泄露的k
    signature = Schnorr_sign_and_assign_k(k, message_A, sk)

    # Bob通过Alice的signature、message以及k推测Alice的d即私钥
    # d = (s - k) / d mod N
    R, s = signature
    tmp = str(R[0]) + str(R[1]) + message_A
    e = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    d = (s - k % N) * inv(e, N) % N
    print("Bob推测的d为:", '0x' + hex(d)[2:].rjust(64, '0'))
    # 验证Bob得到的d是否与Alice的sk相等
    print("验证Bob推测的d是否与Alice的sk相等:", True if d == sk else False)

    # Bob根据推测的d伪造Alice的签名
    message_for_forge = "message of B"
    # 伪造签名
    forged_signature = Schnorr_sign(message_for_forge, d)
    # 用Alice的公钥验证Bob伪造的签名
    print("验证Bob是否通过d伪造签名成功:", True if Schnorr_verify(forged_signature, message_for_forge, pk) == 1 else False)
    if Schnorr_verify(forged_signature, message_for_forge, pk) == 1:
        print('leaking k leads to leaking of d is successful.')


# ----------------------------------------------------------------------------------- #

# Reusing k leads to leaking of d
# 对不同的消息使用相同的k进行签名会泄露d
def Schnorr_reusing_k():
    # Alice使用相同的k生成两个消息的签名
    sk, pk = key_gen()  # A publish pk for others to verify
    print("Alice的私钥为:", "0x" + hex(sk)[2:].rjust(64, '0'))
    message_A1 = "message1 of A"
    message_A2 = "message2 of A"
    k = secrets.randbelow(N)  # 相同的k值
    signature1 = Schnorr_sign_and_assign_k(k, message_A1, sk)
    signature2 = Schnorr_sign_and_assign_k(k, message_A2, sk)
    # Bob通过Alice的两个signature、message以及k推测Alice的d即私钥
    # d = (s1 - s2) / (e1 - e2)
    R1, s1 = signature1
    R2, s2 = signature2
    if R1 != R2: return 'error'
    R = R1
    tmp = str(R[0]) + str(R[1]) + message_A1
    e1 = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    tmp = str(R[0]) + str(R[1]) + message_A2
    e2 = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    d = ((s1 - s2) % N) * inv((e1 - e2), N) % N
    print("Bob推测的d为:", '0x' + hex(d)[2:].rjust(64, '0'))
    print("验证Bob推测的d是否与Alice的sk相等:", True if d == sk else False)
    # Bob根据推测的d伪造Alice的签名
    message_for_forge = "message of B"
    # 伪造签名
    forged_signature = Schnorr_sign(message_for_forge, d)
    # 用Alice的公钥验证Bob伪造的签名
    print("验证Bob是否通过d伪造签名成功:", True if Schnorr_verify(forged_signature, message_for_forge, pk) == 1 else False)
    if Schnorr_verify(forged_signature, message_for_forge, pk) == 1:
        print('Reusing k leads to leaking of d is successful.')


# ----------------------------------------------------------------------------------- #
# Reusing k by different users can deduce each other's d
# 两个不同的user使用相同的k:此类情况下相当于leaking k,所以可以相互推测对方的私钥d
# 伪造签名同上,所以这一步省略了伪造签名的步骤
def same_k_of_different_users():
    # Alice和Bob使用相同的k分别生成消息签名
    k = secrets.randbelow(N)  # 相同的k值
    # Alice
    sk_A, pk_A = key_gen()  # A publish pk for others to verify
    print("Alice的私钥为:", "0x" + hex(sk_A)[2:].rjust(64, '0'))
    message_A = "message of A"
    signature_A = Schnorr_sign_and_assign_k(k, message_A, sk_A)
    # Bob
    sk_B, pk_B = key_gen()  # A publish pk for others to verify
    print("Bob的私钥为:", "0x" + hex(sk_B)[2:].rjust(64, '0'))
    message_B = "message of B"
    signature_B = Schnorr_sign_and_assign_k(k, message_B, sk_B)

    # Bob通过Alice的signature、message以及k推测Alice的d即私钥
    # d = (s - k) / d mod N
    R1, s1 = signature_A
    tmp = str(R1[0]) + str(R1[1]) + message_A
    e1 = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    d_A = (s1 - k % N) * inv(e1, N) % N
    print("Bob推测的Alice的d为:", '0x' + hex(d_A)[2:].rjust(64, '0'))

    # Alice通过Bob的signature、message以及k推测Bob的d即私钥
    # d = (s - k) / d mod N
    R2, s2 = signature_B
    tmp = str(R2[0]) + str(R2[1]) + message_B
    e2 = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    d_B = (s2 - k % N) * inv(e2, N) % N
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
    signature = Schnorr_sign(message, sk)
    r, s = signature
    signature_test = (r, -s)
    print("验证(r,-s)是否是合法签名:", True if Schnorr_verify(signature_test, message, pk) == 1 else Flase)


# ----------------------------------------------------------------------------------- #
# Same d and k between ECDSA and Schnorr, leads to leaking d
# ECDSA与Schnorr使用相同的d和k而泄露d
def same_dk_of_ECDSA_Schnorr():
    # same d and k
    sk, pk = key_gen()
    print("共同的私钥为:", "0x" + hex(sk)[2:].rjust(64, '0'))
    k = secrets.randbelow(N)
    # ECDSA签名
    message1 = "signature1 from ECSDA with sk, k"
    signature1 = ECDSA_sign_and_assign_k(k, message1, sk)
    # Schnorr签名
    message2 = "signature2 from Schnorr with sk, k"
    signature2 = Schnorr_sign_and_assign_k(k, message2, sk)
    # 由ECDSA和Schnorr签名以及两个消息推测d
    # d = (s2 - e1 / s1) / (r / s1 + e2)
    """ECDSA->1  Schnorr->2"""
    r, s1 = signature1
    R, s2 = signature2
    e1 = int(sm3.sm3_hash(func.bytes_to_list(bytes(message1, encoding='utf-8'))), 16)
    tmp = str(R[0]) + str(R[1]) + message2
    e2 = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    tmp1 = (s2 - inv(s1, N) * e1) % N
    tmp2 = (inv(s1, N) * r + e2) % N
    d = tmp1 * inv(tmp2, N) % N
    print("推测的d为:", "0x" + hex(d)[2:].rjust(64, '0'))
    print("验证推测的d是否与sk相等:", True if d == sk else False)


if __name__ == '__main__':
    print("-------------------------------------------------------------------------------------")
    print("                          1.leaking k leads to leaking of d                          ")
    print("-------------------------------------------------------------------------------------")
    Schnorr_leaking_k()
    print("-------------------------------------------------------------------------------------")
    print("                          2.Reusing k leads to leaking of d                          ")
    print("-------------------------------------------------------------------------------------")
    Schnorr_reusing_k()
    print("-------------------------------------------------------------------------------------")
    print("                3.Reusing k by different users can deduce each other's d             ")
    print("-------------------------------------------------------------------------------------")
    same_k_of_different_users()
    print("-------------------------------------------------------------------------------------")
    print("             4.Malleability, e.g. (r,s) and (r,-s) are both valid signatures         ")
    print("-------------------------------------------------------------------------------------")
    verify_Malleability()
    print("-------------------------------------------------------------------------------------")
    print("               5.Same d and k between ECDSA and Schnorr, leads to leaking d          ")
    print("-------------------------------------------------------------------------------------")
    same_dk_of_ECDSA_Schnorr()
    print("-------------------------------------------------------------------------------------")
