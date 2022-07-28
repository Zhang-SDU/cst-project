"""
Google_Password_Checkup  Server端
"""
from argon2 import PasswordHasher
from socket import *
from socketserver import TCPServer, StreamRequestHandler, ThreadingMixIn
import string


# 手动设置用户名和密码集合
def set_Uid_Pwd():
    # Uid与Pwd一一对应
    Uid_Pwd = [("test", "test123"), ("test1", "testing"), ("admin", "admin"),
               ("admin1", "admin123"), ("user", "username")]
    return Uid_Pwd


# Argon2 hash
def Argon2_hash(Uid_Pwd):
    Uid_Pwd_hash = []
    ph = PasswordHasher()
    for i in range(len(Uid_Pwd)):
        # 将Uid与Pwd拼接起来hash
        hash_value = ph.hash(Uid_Pwd[i][0] + Uid_Pwd[i][1])
        # 截取hash的一部分
        Uid_Pwd_hash.append(hash_value[55:])
    return Uid_Pwd_hash


# 将hash值转化为10进制
def str_2_int(hash):
    hash_int = []
    for j in hash:
        int_value = 0
        base = 1
        for i in j:
            temp = ord(i) * base
            base = base + 1
            int_value += temp
        hash_int.append(int_value)
    return hash_int


# 求ki以及vi
def create_Key_Value(Uid_Pwd_hash):
    # sk = b
    b = 3
    # ki
    ki = []
    for i in range(len(Uid_Pwd_hash)):
        ki.append(Uid_Pwd_hash[i][0:2])
    # vi
    vi = []
    hash_int = str_2_int(Uid_Pwd_hash)
    for hi in hash_int:
        vi.append(pow(hi, b))
    # Key_Value table
    KV_table = []
    for i in range(len(ki)):
        KV_table.append((ki[i], vi[i]))
    return ki, vi, b


# 按照键值ki划分Key_Value表
def divide_table(ki, vi):
    V_Table = []
    key = list(set(ki))
    for i in key:
        temp = []
        for j in range(len(ki)):
            if ki[j] == i:
                temp.append(vi[j])
        V_Table.append(temp)
    divi_hash = dict(zip(key, V_Table))
    return divi_hash, key


class BaseRequestHandler(StreamRequestHandler):
    def handle(self):
        self.addr = self.request.getpeername()
        self.server.users[self.addr[1]] = self.request
        IP_msg = "IP " + self.addr[0] + ":" + str(self.addr[1]) + " Connected..."
        print(IP_msg)
        # 建立数据库
        Uid_Pwd = set_Uid_Pwd()
        Uid_Pwd_hash = Argon2_hash(Uid_Pwd)
        ki, vi, b = create_Key_Value(Uid_Pwd_hash)
        Divi_Table, key = divide_table(ki, vi)
        while True:
            # 接收client发送的消息(k,v=h^a)
            data = self.request.recv(2048).decode('UTF-8', 'ignore').strip()
            # 解析数据
            k = data[:2]
            v = int(data[2:])
            # 计算h^ab
            hab = pow(v, b)
            # 如果数据库中有该键,则返回该键对应的列表,否则返回空列表
            if k in key:
                sdata = (Divi_Table[k], str(hab))
                sdata = str(sdata)
            else:
                sdata = str(([], str(hab)))
            self.request.sendall(sdata.encode())
            print('finished.')
            break


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    def __init__(self, server_address, RequestHandlerClass):
        TCPServer.__init__(self, server_address, RequestHandlerClass)
        self.users = {}


class TCPserver():
    def __init__(self, server_addr='127.0.0.1', server_port=8090):
        self.server_address = server_addr
        self.server_port = server_port
        self.server_tuple = (self.server_address, self.server_port)

    def run(self):
        server = ThreadingTCPServer(self.server_tuple, BaseRequestHandler)
        server.serve_forever()


if __name__ == '__main__':
    server = TCPserver()
    server.run()
