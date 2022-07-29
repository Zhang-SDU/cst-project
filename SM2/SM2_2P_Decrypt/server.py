"""
implement sm2 2P decrypt with real network communication
公钥:P = [(d1d2)^-1 - 1] * G   私钥:d = (d1d2)^-1 - 1
对于密文,Server与Client需要协作才能进行解密,因为二者均不能独自计算得到私钥
Server端:
  1. 接收Client端P1 = d1^-1 * G
  2. 生成私钥d2并计算公钥P = [(d1d2)^-1 - 1] * G
  3. 这里Server端自己生成密文并将密文返回给client
  4. 与client进行交互共同解密:接收client发送的T1并返回T2给client
"""

import socket
import secrets
from SM2 import *


# 接收P1和client IP
def receive_P1(server):
    data, addr = server.recvfrom(1024)
    data = data.decode()
    index1 = data.index(',')
    P1 = (int(data[:index1]), int(data[index1 + 1:]))
    return P1, addr


# 生成私钥d以及公钥P = [(d1d2)^-1 - 1] * G
def d_and_P(P1):
    """
    :param P1: d1^-1 * G
    :return: d2, P
    """
    d = secrets.randbelow(N)
    P = EC_sub(EC_multi(inv(d, N), P1), G)
    return d, P


# 接收T1,计算T2并发送给client
def recv_T1_and_comp_T2(d2, server):
    data, addr = server.recvfrom(1024)
    data = data.decode()
    index1 = data.index(',')
    T1 = (int(data[:index1]), int(data[index1 + 1:]))
    T2 = EC_multi(inv(d2, N), T1)
    data = str(T2[0]) + ',' + str(T2[1])
    server.sendto(data.encode(), addr)


# 实现与client的交互
def interact():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('', 13800))
    while 1:
        # 接收P1 = d1^-1 * G以及client IP
        P1, addr = receive_P1(server)
        # 生成私钥d以及公钥P = [(d1d2)^-1 - 1] * G
        d2, P = d_and_P(P1)
        # 对消息进行加密,生成密文
        msg = "Zhang_SDU_201900180019"
        print("Client需要恢复的明文消息为:", msg)
        ciphertext = SM2_enc(msg, P)
        # 将密文发送给client
        data = str(ciphertext)
        server.sendto(data.encode(), addr)
        # 接收T1,计算T2并发送给client
        recv_T1_and_comp_T2(d2, server)
        print("-----------------------------------------------------------------")
    server.close()


if __name__ == '__main__':
    print("-----------------------------------------------------------------")
    print("                           Server端                              ")
    print("-----------------------------------------------------------------")
    interact()
