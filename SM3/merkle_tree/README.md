# Impl Merkle Tree following RFC6962

201900180019 张卓龙


## 项目内容
    1. Construct a Merkle tree with 10w leaf nodes.         
    
    2. Build inclusion proof for specified element.    
    
    3. Build exclusion proof for specified element.        
    
 
 ## 运行指导

    添加tree.h、sha256.h、node.h作为头文件，运行merkle_tree.cpp即可
    

 ## 实验原理

    1.Bitcoin’s Merkle Tree

    当叶子节点个数为奇数时，会复制最后一个叶子节点使得节点个数为偶数，如下图：

   ![image](https://user-images.githubusercontent.com/105548921/180649579-0fe570a3-34ae-406a-800a-d6fc7c54c67a.png)

    2.Merkle Tree（RFC 6962）

    允许叶子节点个数为奇数，如下图：

   ![image](https://user-images.githubusercontent.com/105548921/180649667-76d9312b-a120-4761-b604-aac7a43b93f0.png)


## 代码说明和运行结果

    代码基于Bitcoin’s Merkle Tree进行改写，而二者的实现差异主要在构建Merkle Tree的过程中：

    （注意：在测试前3种情况时，因为所构建的叶子节点个数较少，所以过程中的一些细节进行了输出，但是在构建10w叶子节点时，我将输出的语句进行了注释，这些输出的语句上一行标有注释“不显示输出”，如果想看细节部分的输出，可以取消注释）

    1.如果叶子节点个数为偶数，首先将叶子节点两两合并，合并之后，节点个数减半，树的高度加一，然后在树新的一层再进行合并，直到只剩下一个节点，即根节点在构建树的过程中，每次合并完一层的节点后，要检测新一层的节点个数的奇偶性，如10/2=5，再采取不同的合并方法.
    
    测试结果如下：（实现了验证节点存在功能）

   ![image](https://user-images.githubusercontent.com/105548921/180649980-dc0cee58-c0c4-4b82-805c-21e7f4cd6702.png)

    2.如果叶子节点个数为奇数，计算（个数-1）%4的值，如果为0，则首先将最后一个节点保存下来，然后将最后一个节点之前的所有节点合成一棵树，再用最后一个节点与刚刚合成的树的根节点再进行一次合并，得到新的根节点.
    测试结果如下：（实现了验证节点不存在功能）

   ![image](https://user-images.githubusercontent.com/105548921/180650211-bc006a0f-7816-4727-8b09-a0a609df593b.png)


    3.如果叶子节点个数为奇数，计算（个数-1）%4的值，如果为2，则首先将最后一个节点保存下来，然后将最后一个节点之前的所有节点两两合并一次，此时树的高度加一，然后在新的一层中加入原来的最后一个节点，进行两两合并，直到只剩下一个节点，即根节点.
    测试结果如下：

   ![image](https://user-images.githubusercontent.com/105548921/180650241-486460c3-3643-4310-9986-ac3fc1c5809f.png)

    4.10w叶子节点的运行结果：

   ![image](https://user-images.githubusercontent.com/77322617/181919116-21f46ca3-1a93-4ff7-b0fd-e6eb90b393cd.png)


## 参考指南
    [1] https://rfc2cn.com/rfc6962.html
