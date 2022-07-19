"""
SM3生日攻击
    1. 随机生成2^(n/2)个消息
    2. 对2^(n/2)个消息计算hash值
    3. 寻找碰撞,并输出原像
由于Memory的限制,只能通过截取SM3的54-bit输出来实现生日攻击
"""
from gmssl import sm3, func
import random
import time

# 截取SM3 hash值的部分bit来实现生日攻击
bin_length = 54
hex_length = bin_length // 4


# 随机生成消息
def getRandomList(bin_length):
    str_list = []
    for i in range(pow(2, bin_length // 2)):
        x = random.randint(0, pow(2,20))
        str_list.append(str(x))
    return str_list

# 一次攻击
def one_attack():
    # 存储随机字符串
    str_list = getRandomList(bin_length)
    # 存储字符串对应的hash值
    hash_list = []
    for i in range(len(str_list)):
        hash_value = sm3.sm3_hash(func.bytes_to_list(bytes(str_list[i], encoding='utf-8')))[0:hex_length]
        if hash_value in hash_list:
            print("-----------------------------------------------------")
            print("找到碰撞,hash值为:{}!".format(hash_value))
            print("-----------------------------------------------------")
            print("原像为:")
            print("str1:", str(hash_list.index(hash_value)))
            print("str2:", str_list[i])
            print("-----------------------------------------------------")
            return True
        hash_list.append(hash_value)

if __name__ == '__main__':
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