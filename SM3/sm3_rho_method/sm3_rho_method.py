from gmssl import sm3, func
import random
import time

# 截取SM3 hash值的部分bit来实现rho_method
# 二进制位数
bin_length = 16
# 十六进制位数
hex_length = bin_length // 4


def rho_method():
    # 生成随机数
    x = str(random.randint(0, pow(2, bin_length)))
    # x_a = x_1
    x_a = sm3.sm3_hash(func.bytes_to_list(bytes(x, encoding='utf-8')))
    # x_b = x_2
    x_b = sm3.sm3_hash(func.bytes_to_list(bytes(x_a, encoding='utf-8')))
    # 记录原像
    msg1 = x
    msg2 = x_a
    while x_a[:hex_length] != x_b[:hex_length]:
        # x_a = x_i
        msg1 = x_a
        x_a = sm3.sm3_hash(func.bytes_to_list(bytes(x_a, encoding='utf-8')))
        # x_b = x_2i
        temp = sm3.sm3_hash(func.bytes_to_list(bytes(x_b, encoding='utf-8')))
        x_b = sm3.sm3_hash(func.bytes_to_list(bytes(temp, encoding='utf-8')))
        msg2 = temp
    print("找到碰撞,hash值为:{}!".format(x_a[:hex_length]))
    print("-----------------------------------------------------")
    print("原像为:")
    print("消息1:", msg1)
    print("消息1的hash值:", sm3.sm3_hash(func.bytes_to_list(bytes(msg1, encoding='utf-8'))))
    print()
    print("消息2:", msg2)
    print("消息2的hash值:", sm3.sm3_hash(func.bytes_to_list(bytes(msg2, encoding='utf-8'))))


if __name__ == '__main__':
    print("-----------------------------------------------------")
    print("                {}bits hash值碰撞!".format(bin_length))
    print("-----------------------------------------------------")
    start = time.time()
    rho_method()
    end = time.time()
    print("-----------------------------------------------------")
    print("为了找到碰撞所花费的时间:{}".format(end - start) + "s")
    print("-----------------------------------------------------")
