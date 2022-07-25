# Forge_signature_Pretend_Satoshi

201900180019 张卓龙

## 实验内容
forge a signature to pretend that you are Satoshi
本code主要完成了以下task:             
      当ECDSA验签算法在不验证m的情况下,能够通过公钥来伪造合法签名       
      
    
## 攻击前提      
    1. 验签算法:不验证消息m        
    e * s^-1 * G + r * s^-1 * P = kG = R             
    2. 前提数据:Satoshi的公钥,这里我们通过随机生成来代替Satoshi的真实公钥


**攻击原理**         
    1. 在 Fn* 上随机选择u,v,计算R = (x,y) = uG + vP   (P为公钥)                 
    2. r = x mod n       
    3. e = ruv^-1 mod n          
    4. s = rv^-1 mod n      
    5. signature = (r,s)
    
    

## 实现细节见代码注释

**实验结果如下图:**
![攻击结果](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/forge_signature_pretend_Satoshi/result.png)
