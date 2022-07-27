# Meow_Symmetry

201900180019 张卓龙

## 实验内容
Find a 64-byte message under some 𝒌 fulfilling that their hash value is symmetrical.              
本code利用Meow Hash算法的对称特性, 通过构造相应的密钥key以及消息msg, 使得hash值呈现对称性                        
      
    
**攻击原理**                
    1. Meow Hash主要由三个操作来构建:       
    (1) One-Round AES Decryption        
    (2) 128-bit XOR Operation                    
    (3) Two Parallel 64-bit Modular Addition          
    然后三个操作都具有对称特性,我们可以通过确保读取每个消息块时保持对称性,从而确保在absorb函数中保持对称性,最终生成对称的Meow_Hash.               
    2. Absorb函数          
    ![参考](https://github.com/Zhang-SDU/cst-project/blob/main/Real_World_Cryptanalyses/Meow_Symmetry/ref1.png)         
    图中的00、01、10、0f代表消息块的偏移,以10为例意味着以下操作:        
    (1) 读取message_block[0x10:0x10+16]           
    (2) 将读取的16字节消息划分为高64-bit和低64-bit              
    (3) 高64-bit和低64-bit分别进行相应的操作        
    3. 根据Absorb函数,要保证读取的每个消息块的对称性,即保证每个读取的16字节消息的高64-bit和低64-bit相同,所以构造以下消息:              
    ![参考](https://github.com/Zhang-SDU/cst-project/blob/main/Real_World_Cryptanalyses/Meow_Symmetry/ref2.png)                
    如图,读取的四个16-byte消息块均为左右对称.                   
    4. 这里有一个注意点:即消息的absorb顺序:先以8个32-byte为一组吸收,不足8个后,先把padded字节吸收,再吸收长度block,再吸收剩下那不足8个的blocks;但是长度block(0,0,length,0)            
    并没有对称特性,所以我们在构造时要保证absorb长度block后仍保持对称性.                       
    这里有两个思路:      
    (1) 消息length = 0,这种情况下只需要保证Key的对称性即可         
    (2) 当消息长度小于8个32-byte时,这里以[3]中消息为例,此时先吸收padding字节即32-byte 0,再吸收长度block,所以此时需要通过Key来保证吸收长度block之后仍然保持对称性,最后吸收
    32-byte消息,从而保证hash值的对称性.


## 实现细节见代码注释

**实验结果如下图:**
![攻击结果](https://github.com/Zhang-SDU/cst-project/blob/main/Real_World_Cryptanalyses/Meow_Symmetry/result.png)
