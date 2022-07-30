# SM3 Optimization            

201900180019 张卓龙               

**实验思路**         
        1. 消息处理优化      
        (1) 初始化时，消息扩展只计算W0-W3四个32-bit字     
        (2) 在优化后的轮函数中首先计算W[i+4]，然后再计算W'[i]=W[i]^W[i+4]                
        经过这样的调整,去掉了字W'0,…,W'63,减少了字W0,…,W67和W'0,…,W'63的加载和存储次数,提高了消息扩展的速度       
        2. 每一轮压缩函数优化：          
        (1) 为了减少循环移位导致的不必要的赋值运算,可以将字的循环右移变更每轮输入字顺序的变动,且这个顺序变动会在4轮后还原      
        ![参考图1](https://github.com/Zhang-SDU/cst-project/blob/main/SM3/sm3_optimization/ref1.png)          
        (2) 优化压缩函数的中间变量的生成流程,去除不必要的赋值,减少中间变量个数     
        ![参考图2](https://github.com/Zhang-SDU/cst-project/blob/main/SM3/sm3_optimization/ref2.png)            
        (3) 利用上述调整以及消息扩展部分的调整可以将原来计算TT1、TT2、D和H的过程进行如下的进一步简化:    
        ![参考图3](https://github.com/Zhang-SDU/cst-project/blob/main/SM3/sm3_optimization/ref3.png)             
    
    
## 实现细节见代码注释

## 测试结果如下图    
![测试结果](https://github.com/Zhang-SDU/cst-project/blob/main/SM3/sm3_optimization/result.png)      


## 参考指南

[1]杨先伟,康红娟.SM3杂凑算法的软件快速实现研究[J].智能系统学报,2015,10(06):954-959.
