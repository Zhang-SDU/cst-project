# implement sm2 2P decrypt with real network communication

201900180019 张卓龙


## 文件内容      
    1. SM2.py:包含SM2加解密算法以及签名验签算法
    2. server.py:server端        
    3. client.py:client端      
    4. 运行指导:在pycharm中先运行server.py,然后运行client.py           
    
    
## 实验内容
implement sm2 2P decrypt with real network communication          
公钥:P = [(d1d2)^-1 - 1] * G   私钥:d = (d1d2)^-1 - 1                
对于密文,Server与Client需要协作才能进行解密,因为二者均不能独自计算得到私钥                        
![image](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/SM2_2P_Decrypt/ref.png)           
                          

## 交互流程             
  (一)Server端:
  1. 接收Client端P1 = d1^-1 * G        
  2. 生成私钥d2并计算公钥P = [(d1d2)^-1 - 1] * G         
  3. 这里Server端自己生成密文并将密文返回给client         
  4. 与client进行交互共同解密:接收client发送的T1并返回T2给client             
  
  (二)Client端:       
  1. 生成私钥d1以及P1 = d1^-1 * G          
  2. 接收密文           
  3. 与server进行交互共同解密：         
    (1) 检查C1 != 0并且计算T1 = d1^-1 * C1           
    (2) 接收T2并恢复明文            
    
## 实现细节见代码注释      

**实验结果如下图:**                
![server](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/SM2_2P_Decrypt/result1.png)
![client](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/SM2_2P_Decrypt/result2.png)
