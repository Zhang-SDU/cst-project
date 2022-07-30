#  implement sm2 2P sign with real network communication

201900180019 张卓龙


## 文件内容      
    1. SM2.py:包含SM2加解密算法以及签名验签算法       
    2. server.py:server端        
    3. client.py:client端      
    4. 运行指导:在pycharm中先运行server.py,然后运行client.py           
    
    
## 实验内容
    implement sm2 2P sign with real network communication          
    公钥:P = [(d1d2)^-1 - 1] * G          
    私钥:d = (d1d2)^-1 - 1                  
    对于消息,Server与Client需要协作才能进行签名,因为二者均不能独自计算得到私钥                         
    ![image](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/SM2_2P_Sign/ref.png)           
                          

## 交互流程             
      (一)Server端:        
      1. 接收Client端P1 = d1^-1 * G           
      2. 生成私钥d2,计算公钥P = [(d1d2)^-1 - 1] * G并公开公钥P         
      3. 与client进行交互共同签名:接收client发送的Q1,e并返回r,s2,s3给client               

      (二)Client端:       
      1. 生成私钥d1以及P1 = d1^-1 * G,将P1发送给server      
      2. 与server进行交互共同签名：      
        (1) 规定两方ID以及消息msg     
        (2) 计算Q1,e并发送给server       
        (3) 接收r,s2,s3并计算最终签名(r, s)          
    
## 实现细节见代码注释      

**实验结果如下图:**                
![server](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/SM2_2P_Sign/result1.png)
![client](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/SM2_2P_Sign/result2.png)
