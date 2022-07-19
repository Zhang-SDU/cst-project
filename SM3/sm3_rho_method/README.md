# SM3 Rho Method

201900180019 张卓龙

## 实验思路

要实现Rho Method，主要需要完成以下步骤:    
    1. 随机生成1个消息  
    2. 由前面消息的hash作为新的消息，并求hash值   
    3. 判断是否构成环   
    
**攻击原理**

Rho Method是一种随机化算法，每一个数都由前一个数决定，可以生成的数是有限的，所以会进入循环。   
因为Rho Method是一种随机化算法，所以每次寻找碰撞的时间也不确定。

## 实现细节见代码注释

**实验结果如下图(以16bits hash碰撞为例):**    
![攻击结果](https://github.com/Zhang-SDU/cst-project/blob/main/SM3/sm3_rho_method/result.png)
