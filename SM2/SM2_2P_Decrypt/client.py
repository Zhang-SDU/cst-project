"""
implement sm2 2P decrypt with real network communication
Client端:
  1. 生成私钥d1以及P1 = d1^-1 * G
  2. 接收密文
  3. 与server进行交互共同解密：
    (1) 检查C1 != 0并且计算T1 = d1^-1 * C1
    (2) 接收T2并恢复明文
"""
import secrets
from gmssl import sm3, func
import socket
from SM2 import *


# 生成私钥与P = d^-1 * G
def d_and_P():
    d = secrets.randbelow(N)
    P = EC_multi(inv(d, N), G)
    return d, P


# 检查C1 != 0并且计算T1 = d1^-1 * C1
def check_and_comp(d1, C1):
    if C1 == 0:
        return 'error'
    T1 = EC_multi(inv(d1, N), C1)
    return T1


# 恢复明文消息
def recover_msg(T2, C1, C2, C3):
    # T2 - C1 = (x2, y2) = kP
    x2, y2 = EC_sub(T2, C1)
    x2 = hex(x2)[2:]
    y2 = hex(y2)[2:]
    klen = len(C2) * 4
    # t = KDF(x2 || y2, klen)
    t = KDF(x2 + y2, klen)
    # M = C2 xor t
    M = dec_XOR(C2, t)
    # u = Hash(x2 || M || y2)
    u = sm3.sm3_hash(func.bytes_to_list(bytes((x2 + M + y2), encoding='utf-8')))
    if u == C3:
        return M
    return "Wrong!"


# 实现与server的交互
def interact():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 生成私钥与P1 = d^-1 * G
    d1, P1 = d_and_P()
    data = str(P1[0]) + ',' + str(P1[1])
    # 将P1 = d^-1 * G发送给server
    client.sendto(data.encode(), ("127.0.0.1", 13800))
    # 接收密文
    data, addr = client.recvfrom(4096)
    data = eval(data)
    C1, C2, C3 = data
    print("接收的密文为:")
    print("C1:", C1)
    print("C2:", C2)
    print("C3:", C3)
    print("--------------------------------------------------------------------------------")
    # 检查C1 != 0并且计算T1 = d1^-1 * C1
    T1 = check_and_comp(d1, C1)
    # 将T1发送给server
    data = str(T1[0]) + ',' + str(T1[1])
    client.sendto(data.encode(), addr)
    # 接收T2
    data, addr = client.recvfrom(1024)
    data = data.decode()
    index1 = data.index(',')
    T2 = (int(data[:index1]), int(data[index1 + 1:]))
    # 由密文恢复明文消息
    plaintext = recover_msg(T2, C1, C2, C3)
    print("恢复的明文为:", plaintext)
    print("--------------------------------------------------------------------------------")
    client.close()


if __name__ == '__main__':
    print("--------------------------------------------------------------------------------")
    print("                                   Client端                                     ")
    print("--------------------------------------------------------------------------------")
    interact()
