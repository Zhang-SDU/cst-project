# UTXO Commitment: Elliptic curve MultiSet Hash

201900180019 张卓龙


## 实验内容
原始思路:将hash值作为椭圆曲线上的x点,根据椭圆曲线方程y^2 = x^3 + Ax + B来计算y值会存在无解的情况                
本code将消息hash到椭圆曲线上的方法:              
    (1) 首先计算消息的sm3 hash值             
    (2) 将sm3 hash值作为k值              
    (3) (x, y) = k * G             
本code完成的测试:           
    (1) hash({a,b}) == hash({b,a})             
    (2) hash(a) + hash(b) == hash({a,b})              
    (3) hash({a,b,c}) - hash(c) == hash({a,b})               
                          
         
## 实现细节见代码注释      

**实验结果如下图:**                
![result1](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/ECMH/result1.png)
![result2](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/ECMH/result2.png)
![result3](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/ECMH/result3.png)
![result4](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/ECMH/result4.png)
