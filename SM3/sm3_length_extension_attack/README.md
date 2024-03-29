# SM3 Length Extension Attack

201900180019 张卓龙

## 实验思路

    要实现长度扩展攻击，主要需要完成以下步骤:    
        1. 首先计算原消息(secret)的hash值  
        2. 在secret+padding之后附加一段消息,用原消息的hash值作为IV计算附加消息之后的hash值,得到消息扩展后的hash1   
        3. 用sm3加密伪造后的整体消息，得到hash2    
        4. 验证hash1 与 hash2 是否相等   
    
**攻击原理**

    SM3的消息长度是64字节或者它的倍数，如果消息的长度不足则需要padding。在padding时，首先填充一个1，随后填充0，直到消息长度为56(或者再加整数倍的64)字节，最后8字节用来填充消息的长度。

    在SM3函数计算时，首先对消息进行分组，每组64字节，每一次加密一组，并更新8个初始向量(初始值已经确定)，下一次用新向量去加密下一组，以此类推。我们可以利用这一特性去实现攻击。当我们得到第一次加密后的向量值时，再人为构造一组消息用于下一次加密，就可以在不知道secret的情况下得到合法的hash值。

## 实现细节见代码注释

## 实验结果如下图
![攻击结果](https://github.com/Zhang-SDU/cst-project/blob/main/SM3/sm3_length_extension_attack/result.png)
