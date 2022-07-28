"""
Google_Password_Checkup  Client端
"""
import string
from argon2 import PasswordHasher
from socket import *

# 将hash值转化为10进制
def str_2_int(hash):
    int_value = 0
    base = 1
    for i in hash:
        temp = ord(i) * base
        base = base + 1
        int_value += temp
    return int_value

# 设置两个用户名和密码:一个已泄露,一个未泄露
def set_Uid_Pwd():
    ph = PasswordHasher()
    # sk = a
    a = 2
    # case 1:已泄露的用户名和密码
    Uid_Pwd_1 = ("admin", "admin")
    hash_1 = ph.hash(Uid_Pwd_1[0] + Uid_Pwd_1[1])[55:]
    k1 = hash_1[:2]
    h1 = str_2_int(hash_1)
    v1 = pow(h1, a)
    # case 2:未泄露的用户名和密码
    Uid_Pwd_2 = ("Zhang_SDU", "cst_project")
    hash_2 = ph.hash(Uid_Pwd_2[0] + Uid_Pwd_2[1])[55:]
    k2 = hash_2[:2]
    h2 = str_2_int(hash_2)
    v2 = pow(h2, a)
    return k1 + str(v1), k2 + str(v2), a

# 根据交互判断信息是否泄露
def judge(recv_data, a):
    data = eval(recv_data)
    if data[0] == []:
        print("返回空列表!")
        print("您的账户信息暂未泄露!")
        print("--------------------------------------------------------------")
    else:
        hab = int(data[1])
        hb = int(pow(hab, 1/a))
        print("客户端计算的h^b:", hb)
        if hb in data[0]:
            print("您的账户信息存在泄露风险!")
            print("-------------------------------------------------------------------------")

if __name__=='__main__':
    while 1:
        client = socket(AF_INET, SOCK_STREAM)
        client.connect(('127.0.0.1', 8090))
        # 获得已泄露和未泄露的数据以及私钥
        data1, data2, a = set_Uid_Pwd()
        # case 1:已泄露的数据
        print("-------------------------------------------------------------------------")
        print("                            case 1:数据已泄露                              ")
        client.send(data1.encode('utf-8'))
        recv_data = client.recv(65536 * 16).decode('UTF-8', 'ignore')
        print("-------------------------------------------------------------------------")
        print("服务器端返回数据(S,h^ab):", recv_data)
        print("-------------------------------------------------------------------------")
        judge(recv_data, a)

        # case 2:未泄露的数据
        # print("--------------------------------------------------------------")
        # print("                      case 2:数据未泄露                         ")
        # client.send(data2.encode('utf-8'))
        # recv_data = client.recv(65536 * 16).decode('UTF-8', 'ignore')
        # print("--------------------------------------------------------------")
        # print("服务器端返回数据(S,h^ab):", recv_data)
        # print("--------------------------------------------------------------")
        # judge(recv_data, a)
        break
    client.close()