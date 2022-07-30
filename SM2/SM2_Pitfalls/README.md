# SM2_Pitfalls

201900180019 张卓龙

## 实验内容:
    SM2 signature pitfalls
    本code主要完成了以下4个task:        
        1. Leaking k leads to leaking of d (k的泄露会导致泄露d)     
        2. Reusing k leads to leaking of d (对不同的消息使用相同的k进行签名会泄露d)   
        3. Two users, using k leads to leaking of d, that is they can deduce each other's d (两个不同的user使用相同的k,可以相互推测对方的私钥d)          
        4. Same d and k between ECDSA and SM2, leads to leaking d (ECDSA与SM2使用相同的d和k而泄露d)    
        其中1和2还分别根据推测得到的d值进行了消息的伪造并成功通过验签      
    
## 文件内容      
    1. SM2.py:包含了SM2密钥生成、签名、验签算法      
    2. SM2_pitfalls:完成4个task


## 攻击原理       
        1. Leaking k leads to leaking of d (k的泄露会导致泄露d)    
        由签名算法中s = (1 + d)^-1 * (k - rd) mod n 推得 d = (s + r) ^ -1 * (k - s)      
        2. Reusing k leads to leaking of d (对不同的消息使用相同的k进行签名会泄露d)      
        s1 = (1 + d)^-1 * (k - r1d) mod n      
        s2 = (1 + d)^-1 * (k - r2d) mod n      
        推得 d = (s2 - s1) / (s1 - s2 + r1 - r2)                 
        3. Two users, using k leads to leaking of d, that is they can deduce each other's d (两个不同的user使用相同的k,可以相互推测对方的私钥d)         
        两个不同的user使用相同的k:此类情况下相当于leaking k,所以可以相互推测对方的私钥d                     
        4. Same d and k between ECDSA and SM2, leads to leaking d (ECDSA与SM2使用相同的d和k而泄露d)       
        s1 = k^-1(e1 + dr1) mod n      
        s2 = (1 + d)^-1 * (k - r2d) mod n        
        推得 d = (s1s2 - e1) / (r1 - s1s1 - s1r2)     
    
    

## 实现细节见代码注释

**实验结果如下图:**
![攻击结果](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/SM2_Pitfalls/result1.png)
![攻击结果](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/SM2_Pitfalls/result2.png)
