"""
 implement sm2 2P sign with real network communication
公钥:P = [(d1d2)^-1 - 1] * G   私钥:d = (d1d2)^-1 - 1
对于消息,Server与Client需要协作才能进行签名,因为二者均不能独自计算得到私钥
Server端:
  1. 接收Client端P1 = d1^-1 * G
  2. 生成私钥d2,计算公钥P = [(d1d2)^-1 - 1] * G并公开公钥P
  3. 与client进行交互共同签名:接收client发送的Q1,e并返回r,s2,s3给client
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
    d = secrets.randbelow(N)
    P = EC_sub(EC_multi(inv(d, N), P1), G)
    return d, P


# 计算r,s2,s3
def comp_r_s2_s3(d2, Q1, e):
    e = int(e, 16)
    # select k2,k3 from [1, N-1]
    k2 = secrets.randbelow(N)
    k3 = secrets.randbelow(N)
    # Q2 = k2 * G
    Q2 = EC_multi(k2, G)
    # k3Q1 + Q2 = (x2, y2)
    x1, y1 = EC_add(EC_multi(k3, Q1), Q2)
    # r = (x1 + e) % N
    r = (x1 + e) % N
    if r == 0:
        return "Wrong: r = 0!"
    # s2 = d2 * k3 % N
    s2 = d2 * k3 % N
    # s3 = d2 * (r + k2) % N
    s3 = d2 * (r + k2) % N
    return r, s2, s3


# 接收Q1 and e
def receive_Q1_e(server):
    data, addr = server.recvfrom(1024)
    data = data.decode()
    index1 = data.index(',')
    index2 = data.index(';')
    Q1 = (int(data[:index1]), int(data[index1 + 1:index2]))
    e = data[index2 + 1:]
    return Q1, e, addr


# 实现与client的交互
def interact():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('', 8090))
    while 1:
        # 接收P1 = d1^-1 * G以及client IP
        P1, addr = receive_P1(server)
        # 生成私钥d以及公钥P = [(d1d2)^-1 - 1] * G
        d2, P = d_and_P(P1)
        # 公开公钥P,将公钥发给client
        print("公钥为:")
        print(P)
        print("--------------------------------------------------------------------------------")
        data = str(P[0]) + ',' + str(P[1])
        server.sendto(data.encode(), addr)
        # 接收Q1,e
        Q1, e, addr = receive_Q1_e(server)
        # 计算r,s2,s3
        r, s2, s3 = comp_r_s2_s3(d2, Q1, e)
        # 发送r,s2,s3给client
        data = str(r) + ',' + str(s2) + ';' + str(s3)
        server.sendto(data.encode(), addr)
    s.close()


if __name__ == '__main__':
    print("--------------------------------------------------------------------------------")
    print("                                   Server端                                     ")
    print("--------------------------------------------------------------------------------")
    interact()
