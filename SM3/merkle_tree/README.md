# Impl Merkle Tree following RFC6962

**项目内容**

1.构建一个有10w个叶子节点的Merkle Tree

2.有验证节点存在功能

3.有验证节点不存在功能

**实验原理**

1.Bitcoin’s Merkle Tree

当叶子节点个数为奇数时，会复制最后一个叶子节点使得节点个数为偶数，如下图：

![image](https://user-images.githubusercontent.com/105548921/180649579-0fe570a3-34ae-406a-800a-d6fc7c54c67a.png)

2.Merkle Tree（RFC 6962）

允许叶子节点个数为奇数，如下图：

![image](https://user-images.githubusercontent.com/105548921/180649667-76d9312b-a120-4761-b604-aac7a43b93f0.png)

**运行指导**

添加tree.h、sha256.h、node.h作为头文件，运行merkle_tree.cpp即可

**代码说明和测试结果**

代码基于Bitcoin’s Merkle Tree进行改写，而二者的实现差异主要在构建Merkle Tree的过程中：（项目要求节点个数为10w个，此处为了方便展示结果，叶子节点个数较少）

1.如果叶子节点个数为偶数，首先将叶子节点两两合并，合并之后，节点个数减半，树的高度加一，然后在树新的一层再进行合并，直到只剩下一个节点，即根节点。测试结果如下：（实现了验证节点存在功能）

![image](https://user-images.githubusercontent.com/105548921/180649980-dc0cee58-c0c4-4b82-805c-21e7f4cd6702.png)

2.如果叶子节点个数为奇数，计算（个数-1）%4的值，如果为0，则首先将最后一个节点保存下来，然后将最后一个节点之前的所有节点合成一棵树，再用最后一个节点与刚刚合成的树的根节点再进行一次合并，得到新的根节点。测试结果如下：（实现了验证节点不存在功能）

![image](https://user-images.githubusercontent.com/105548921/180650211-bc006a0f-7816-4727-8b09-a0a609df593b.png)


3.如果叶子节点个数为奇数，计算（个数-1）%4的值，如果为2，则首先将最后一个节点保存下来，然后将最后一个节点之前的所有节点两两合并一次，此时树的高度加一，然后在新的一层中加入原来的最后一个节点，进行两两合并，直到只剩下一个节点，即根节点。测试结果如下：

![image](https://user-images.githubusercontent.com/105548921/180650241-486460c3-3643-4310-9986-ac3fc1c5809f.png)
