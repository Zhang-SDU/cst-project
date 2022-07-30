# deduce pk from signature  with ECDSA

201900180019 张卓龙

## 实验内容
    deduce pk from signature  with ECDSA          
    本code旨在由ECDSA签名来恢复相应的公钥即由(r, s)来推出公钥pk                           
    

## 恢复原理         
        1. ECDSA签名算法                    
        (1) KeyGen: P = dG           
        (2) select k from Zn*, R = KG = (x, y)           
        (3) r = Rx mod n, r != 0             
        (4) e = hash(m)          
        (5) s = k^-1 * (e + dr) mod n         
        (6) signature = (r, s)               
        2. 数学推导       
        (1) 由s = k^-1 * (e + dr) mod n 可推得 sk = (e + dr) mod n，P 为公钥 = dG, 所以两边同时乘以G得: s * kG = (eG + rP) mod n        
        (2) 由r可计算出R点的横坐标x, 通过曲线方程可以求得R点的纵坐标y, 可求得两个椭圆曲线点R1、R2, R1与R2关于X轴对称            
        (3) 此时s、kG、G、r均已知, e = hash(m)可通过计算得出               
        (4) P = r^-1 * (s * kG  - eG)         

## 实现细节见代码注释

## 实验结果如下图
![恢复结果](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/deduce_pk/result.png)
