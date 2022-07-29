# Google_Passwd_Checkup

201900180019 张卓龙


## 文件内容      
    1. server.py:server端      
    2. client.py:client端
    
    
## 实验内容
Google_Passwd_Checkup          
本code模拟google检测用户名和密码是否泄露;通过该方法,用户可以在不知道server集合的情况下得知自己的用户名和密码是否泄露.                
![image](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/Google_Passwd_Checkup/ref.png)           
                          
           
## 上图已给出详细的交互过程,实现细节见代码注释

**code的一些说明事项**    
1. 本code在server手动设置了五个username与相应的passwd,用来模拟数据库       
2. 在测试中,分别使用已在数据库中的用户名和密码以及未在数据库中的用户名和密码进行测试,即分别针对已泄露的信息以及未泄露的信息进行了测试             
3. 在实现过程中用到Argon算法,在库函数的实现过程中,salt的值是随机的,这会导致同样的msg会计算出不同的hash值,所以修改了库函数,固定salt          
4. 运行指导,在pycharm中首先运行server.py,然后运行client.py         


**实验结果如下图:**
![result1](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/Google_Passwd_Checkup/result1.png)
![result2](https://github.com/Zhang-SDU/cst-project/blob/main/SM2/Google_Passwd_Checkup/result2.png)
