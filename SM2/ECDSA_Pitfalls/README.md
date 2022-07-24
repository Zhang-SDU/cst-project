# ECDSA_Pitfalls

201900180019 张卓龙

## 实验内容
ECDSA signature pitfalls
本code主要完成了以下4个task:
    1. Leaking k leads to leaking of d (k的泄露会导致泄露d)     
    2. Reusing k leads to leaking of d (对不同的消息使用相同的k进行签名会泄露d)   
    3. Two users, using k leads to leaking of d, that is they can deduce each other's d (两个不同的user使用相同的k,可以相互推测对方的私钥d)     
    4. Malleability, e.g. (r,s) and (r,-s) are both valid signatures (验证(r,s) and (r,-s)均为合法签名)


**攻击原理**
    1. Leaking k leads to leaking of d (k的泄露会导致泄露d)    
     $$
    \ s = k^-1(e+dr) mod n
     $$
## 实现细节见代码注释

**实验结果如下图:**
![攻击结果](https://github.com/Zhang-SDU/cst-project/blob/main/SM3/sm3_length_extension_attack/result.png)
