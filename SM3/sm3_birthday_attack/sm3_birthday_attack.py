"""
SM3生日攻击
    1. 随机生成2^(n/2)个消息
    2. 对2^(n/2)个消息计算hash值
    3. 寻找碰撞,并输出原像以及原像的hash值
由于Memory的限制,只能通过截取SM3的56-bit输出来实现生日攻击
"""
from gmssl import sm3, func
from faker import Faker
import time

# 截取SM3 hash值的部分bit来实现生日攻击
# 二进制位数
bin_length = 32
# 十六进制位数
hex_length = bin_length // 4


# 随机生成消息
def getRandomList():
    str_list = []
    faker = Faker(locale='zh_CN')
    for i in range(pow(2, bin_length//2)):
        str_list.append(faker.name() + ',' + faker.address() + ',' + faker.email() + ',' + faker.phone_number())
    return str_list

# 一次攻击
def one_attack():
    # 存储随机字符串
    str_list = getRandomList()
    # 存储字符串对应的hash值
    hash_list = []
    for i in range(len(str_list)):
        hash_value = sm3.sm3_hash(func.bytes_to_list(bytes(str_list[i], encoding='utf-8')))[0:hex_length]
        if hash_value in hash_list:
            print("找到碰撞,hash值为:{}!".format(hash_value))
            print("-----------------------------------------------------")
            print("原像为:")
            print("消息1:", str_list[hash_list.index(hash_value)])
            print("消息1的hash值:", sm3.sm3_hash(func.bytes_to_list(bytes(str_list[hash_list.index(hash_value)], encoding='utf-8'))))
            print("消息2:", str_list[i])
            print("消息2的hash值:", sm3.sm3_hash(func.bytes_to_list(bytes(str_list[i], encoding='utf-8'))))
            print("-----------------------------------------------------")
            return True
        hash_list.append(hash_value)

if __name__ == '__main__':
    print("-----------------------------------------------------")
    print("                  {}bits hash值碰撞!".format(bin_length))
    print("-----------------------------------------------------")
    # 统计攻击次数
    count = 0
    start = time.time()
    while 1:
        count += 1
        ret = one_attack()
        if ret:
            break
    end = time.time()
    print("为了找到碰撞执行了{}次攻击".format(count))
    print("为了找到碰撞所花费的时间:{}".format(end - start) + "s")
    print("-----------------------------------------------------")
