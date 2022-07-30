# SM3 Birthday Attack

201900180019 张卓龙

## 实验思路
    要实现生日攻击，主要需要完成以下步骤:    
        1. 随机生成2^(n/2)个消息  
        2. 对2^(n/2)个消息计算hash值   
        3. 寻找碰撞并输出原像以及原像的hash值   
    由于Memory的限制,只能通过截取SM3的56-bit输出来实现生日攻击    

## 攻击原理
    生日攻击是碰撞攻击通用的攻击方法，源于一种概率论问题。如果hash值的长度为n，根据生日悖论，每个集合含有2^(n/2)个元素就可以以约1/2的概率找到一对碰撞。

## 实现细节见代码注释

## 实验结果如下图(以32bit hash碰撞为例)    
![攻击结果](https://github.com/Zhang-SDU/cst-project/blob/main/SM3/sm3_birthday_attack/result.png)

