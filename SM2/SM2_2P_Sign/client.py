"""
 implement sm2 2P sign with real network communication
Client端:
  1. 生成私钥d1以及P1 = d1^-1 * G,将P1发送给server
  2. 与server进行交互共同签名：
    (1) 规定两方ID以及消息msg
    (2) 计算Q1,e并发送给server
    (3) 接收r,s2,s3并计算最终签名(r, s)
"""

import secrets
from gmssl import sm3, func
import socket
from SM2 import *


# 生成私钥d1与P1 = d^-1 * G
def d_and_P():
    d1 = secrets.randbelow(N)
    P1 = EC_multi(inv(d1, N), G)
    return d1, P1


# 接收公钥P
def receive_P(client):
    data, addr = client.recvfrom(1024)
    data = data.decode()
    index1 = data.index(',')
    P = (int(data[:index1]), int(data[index1 + 1:]))
    return P


# 发送Q1,e
def send_Q1_e(client):
    server_ID = "ID0"
    client_ID = "ID1"
    Z = server_ID + client_ID
    msg = "Zhang_SDU_201900180019"
    print("消息为:", msg)
    print("--------------------------------------------------------------------------------")
    # M' = Z || M
    m = Z + msg
    # e = Hash(M')
    e = sm3.sm3_hash(func.bytes_to_list(bytes(m, encoding='utf-8')))
    # select k1 from [1, N-1]
    k1 = secrets.randbelow(N)
    # Q1 = k1 * G
    Q1 = EC_multi(k1, G)
    # 发送Q1和e
    data = str(Q1[0]) + ',' + str(Q1[1]) + ';' + e
    client.sendto(data.encode(), ("127.0.0.1", 8090))
    return k1


# 接收r,s2,s3
def receive_r_s2_s3(client):
    data, addr = client.recvfrom(1024)
    data = data.decode()
    index1 = data.index(',')
    index2 = data.index(';')
    r = int(data[:index1])
    s2 = int(data[index1 + 1:index2])
    s3 = int(data[index2 + 1:])
    return r, s2, s3


# 生成签名
def create_sign(d1, k1, r, s2, s3):
    s = ((d1 * k1) % N * s2 % N + d1 * s3 - r) % N
    if s != 0 or s != N - r:
        return r, s
    else:
        return "Wrong!"


# 实现与server的交互
def interact():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 生成私钥与P1 = d^-1 * G
    d1, P1 = d_and_P()
    data = str(P1[0]) + ',' + str(P1[1])
    # 将P1 = d^-1 * G发送给server
    client.sendto(data.encode(), ("127.0.0.1", 8090))
    # 接收公钥P
    P = receive_P(client)
    # 发送Q1,e
    k1 = send_Q1_e(client)
    # 接收r,s2,s3
    r, s2, s3 = receive_r_s2_s3(client)
    # 生成最终签名
    signature = create_sign(d1, k1, r, s2, s3)
    r, s = signature
    print("签名为:")
    print("r:", r)
    print("s:", s)
    client.close()


if __name__ == '__main__':
    print("--------------------------------------------------------------------------------")
    print("                                   Client端                                     ")
    print("--------------------------------------------------------------------------------")
    interact()
    print("--------------------------------------------------------------------------------")
