#pragma once
#include "node.h"
#include <iostream>
#include "sha256.h"

using namespace std;

class tree
{
private:
	string merkleRoot;
	int makeBinary(vector<node*>& node_vector);
	void printTreeLevel(vector<node*> v);
	vector<vector<node*>> base; //里面存的是一个个节点列表
public:
	tree();
	void buildTree();//创建Merkel Tree
	void buildBaseLeafes(vector<string> base_leafs);
	int verify(string hash);//确认某一个叶子节点在不在树上
	virtual ~tree();//虚函数
};

tree::tree() {}

int tree::makeBinary(vector<node*>& node_vector) //使叶子节点成为双数
{
	int vectSize = node_vector.size();
	if ((vectSize % 2) != 0) //如果元素个数为奇数，就把再最后一个节点push_back一次
	{
		node_vector.push_back(node_vector.end()[-1]);
		vectSize++;
	}
	return vectSize;
}

void tree::printTreeLevel(vector<node*> v)
{
	for (node* el : v)
	{
		cout << el->getHash() << endl;
	}
	cout << endl;
}


void tree::buildTree() //建造merkle tree
{
	int re = (base.end()[-1].size()-1) % 4;
	int parity = (base.end()[-1].size()) % 2;
	//如果叶子节点个数为偶数，那就按照原来的办法
	//如果叶子节点个数为奇数，计算（个数-1）%4的值，如果为0，则首先将最后一个节点之前的所有节点合成一棵树，再用最后一个
	//节点和根节点合并，如果为2，则首先将最后一个节点之前的所有节点合成一次，再把最后一个节点加入到这一层中
	if (parity == 0)
	{
		do
		{
			vector<node*> new_nodes;
			if (parity == 0)
			{
				for (int i = 0; i < base.end()[-1].size(); i += 2)
				{
					node* new_parent = new node; //设置父亲节点 传入最后一个元素 即一个节点列表的第i和i+1个
					base.end()[-1][i]->setParent(new_parent);
					base.end()[-1][i + 1]->setParent(new_parent);
					//通过两个孩子节点的哈希值设置父节点哈希值
					new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
					//将该父节点的左右孩子节点设置为这两个
					new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
					//将new_parent压入new_nodes
					new_nodes.push_back(new_parent);
					//不显示输出
					//cout << "将 " << base.end()[-1][i]->getHash() << " 和 " << base.end()[-1][i + 1]->getHash() << " 连接,得到对应父节点的哈希值 " << endl;
				}
				//不显示输出
				//cout << endl;
				//不显示输出
				//cout << "得到的对应父节点的哈希值:" << endl;
				//不显示输出
				//printTreeLevel(new_nodes);
				base.push_back(new_nodes); //将新一轮的父节点new_nodes压入base
				//不显示输出
				//cout << "该层的结点有 " << base.end()[-1].size() << " 个:" << endl;
			}
			else//奇数的时候
			{
				re = (base.end()[-1].size() - 1) % 4;
				if (re == 0)
				{
					node* temp = base.end()[-1][base.end()[-1].size() - 1];//记录最后一个节点
					while (1)
					{
						vector<node*> new_nodes;
						if (base.end()[-1].size() > 1)
						{
							for (int i = 0; i < base.end()[-1].size() - 1; i += 2)
							{
								node* new_parent = new node; //设置父亲节点 传入最后一个元素 即一个节点列表的第i和i+1个
								base.end()[-1][i]->setParent(new_parent);
								base.end()[-1][i + 1]->setParent(new_parent);
								//通过两个孩子节点的哈希值设置父节点哈希值
								new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
								//将该父节点的左右孩子节点设置为这两个
								new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
								//将new_parent压入new_nodes
								new_nodes.push_back(new_parent);
								//不显示输出
								//cout << "将 " << base.end()[-1][i]->getHash() << " 和 " << base.end()[-1][i + 1]->getHash() << " 连接,得到对应父节点的哈希值 " << endl;
							}
							//不显示输出
							//cout << endl;
							//不显示输出
							//cout << "得到的对应父节点的哈希值:" << endl;
							//不显示输出
							//printTreeLevel(new_nodes);
							base.push_back(new_nodes); //将新一轮的父节点new_nodes压入base
							//不显示输出
							/*if (base.end()[-1].size() > 1)
							{
								cout << "该层的结点有 " << base.end()[-1].size() << " 个:" << endl;
							}
							else
							{
								cout << "该层的结点有 " << base.end()[-1].size()+1 << " 个:" << endl;
							}*/
						}
						else
						{
							//将最后一个节点和根节点合并
							node* new_parent = new node; //设置新的父节点
							base.end()[-1][0]->setParent(new_parent);
							temp->setParent(new_parent);
							//通过两个孩子节点的哈希值设置父节点哈希值
							new_parent->setHash(base.end()[-1][0]->getHash() + temp->getHash());
							//将该父节点的左右孩子节点设置为这两个
							new_parent->setChildren(base.end()[-1][0], temp);
							//将new_parent压入new_nodes
							new_nodes.push_back(new_parent);
							//不显示输出
							//cout << "将 " << base.end()[-1][0]->getHash() << " 和 " << temp->getHash() << " 连接,得到对应父节点的哈希值 " << endl;
							//不显示输出
							//cout << endl;
							//不显示输出
							//cout << "得到的对应父节点的哈希值:" << endl;
							//不显示输出
							//printTreeLevel(new_nodes);
							base.push_back(new_nodes); //将新一轮的父节点new_nodes压入base
							//不显示输出
							//cout << "该层的结点有 " << base.end()[-1].size() << " 个:" << endl;
							break;
						}
					}  //这样每一轮得到新一层的父节点，知道得到根节点 退出循环
				}
				else
				{
					int length = base.end()[-1].size() - 1;//记录初始长度
					node* temp = base.end()[-1][base.end()[-1].size() - 1];//记录最后一个节点
					while (base.end()[-1].size() > 1)
					{
						vector<node*> new_nodes;
						if (base.end()[-1].size() - 1 == length)
						{
							for (int i = 0; i < base.end()[-1].size() - 1; i += 2)
							{
								node* new_parent = new node; //设置父亲节点 传入最后一个元素 即一个节点列表的第i和i+1个
								base.end()[-1][i]->setParent(new_parent);
								base.end()[-1][i + 1]->setParent(new_parent);
								//通过两个孩子节点的哈希值设置父节点哈希值
								new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
								//将该父节点的左右孩子节点设置为这两个
								new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
								//将new_parent压入new_nodes
								new_nodes.push_back(new_parent);
								//不显示输出
								//cout << "将 " << base.end()[-1][i]->getHash() << " 和 " << base.end()[-1][i + 1]->getHash() << " 连接,得到对应父节点的哈希值 " << endl;
							}
							//不显示输出
							//cout << endl;
							//不显示输出
							//cout << "得到的对应父节点的哈希值:" << endl;
							//不显示输出
							//printTreeLevel(new_nodes);
							new_nodes.push_back(temp);//将最后一个节点压入base
							base.push_back(new_nodes); //将新一轮的父节点new_nodes压入base
							//不显示输出
							//cout << "该层的结点有 " << base.end()[-1].size() << " 个:" << endl;

						}
						else
						{
							for (int i = 0; i < base.end()[-1].size(); i += 2)
							{
								node* new_parent = new node; //设置父亲节点 传入最后一个元素 即一个节点列表的第i和i+1个
								base.end()[-1][i]->setParent(new_parent);
								base.end()[-1][i + 1]->setParent(new_parent);
								//通过两个孩子节点的哈希值设置父节点哈希值
								new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
								//将该父节点的左右孩子节点设置为这两个
								new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
								//将new_parent压入new_nodes
								new_nodes.push_back(new_parent);
								//不显示输出
								//cout << "将 " << base.end()[-1][i]->getHash() << " 和 " << base.end()[-1][i + 1]->getHash() << " 连接,得到对应父节点的哈希值 " << endl;
							}
							//不显示输出
							//cout << endl;
							//不显示输出
							//cout << "得到的对应父节点的哈希值:" << endl;
							//不显示输出
							//printTreeLevel(new_nodes);
							base.push_back(new_nodes); //将新一轮的父节点new_nodes压入base
							//不显示输出
							//cout << "该层的结点有 " << base.end()[-1].size() << " 个:" << endl;
						}
					}
				}
			}
			//再次计算奇偶，因为可能发生变化，比如10/2=5
			parity = (base.end()[-1].size()) % 2;
		} while (base.end()[-1].size() > 1); //这样每一轮得到新一层的父节点，知道得到根节点 退出循环
	}
	else
	{
		if (re == 0)
		{
			node* temp = base.end()[-1][base.end()[-1].size() - 1];//记录最后一个节点
			while(1)
			{
				vector<node*> new_nodes;
				if (base.end()[-1].size() > 1)
				{
					for (int i = 0; i < base.end()[-1].size() - 1; i += 2)
					{
						node* new_parent = new node; //设置父亲节点 传入最后一个元素 即一个节点列表的第i和i+1个
						base.end()[-1][i]->setParent(new_parent);
						base.end()[-1][i + 1]->setParent(new_parent);
						//通过两个孩子节点的哈希值设置父节点哈希值
						new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
						//将该父节点的左右孩子节点设置为这两个
						new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
						//将new_parent压入new_nodes
						new_nodes.push_back(new_parent);
						//不显示输出
						//cout << "将 " << base.end()[-1][i]->getHash() << " 和 " << base.end()[-1][i + 1]->getHash() << " 连接,得到对应父节点的哈希值 " << endl;
					}
					//不显示输出
					//cout << endl;
					//不显示输出
					//cout << "得到的对应父节点的哈希值:" << endl;
					//不显示输出
					//printTreeLevel(new_nodes);
					base.push_back(new_nodes); //将新一轮的父节点new_nodes压入base
					//不显示输出
					/*if (base.end()[-1].size() > 1)
					{
						cout << "该层的结点有 " << base.end()[-1].size() << " 个:" << endl;
					}
					else
					{
						cout << "该层的结点有 " << base.end()[-1].size()+1 << " 个:" << endl;
					}*/
				}
				else
				{
					//将最后一个节点和根节点合并
					node* new_parent = new node; //设置新的父节点
					base.end()[-1][0]->setParent(new_parent);
					temp->setParent(new_parent);
					//通过两个孩子节点的哈希值设置父节点哈希值
					new_parent->setHash(base.end()[-1][0]->getHash() + temp->getHash());
					//将该父节点的左右孩子节点设置为这两个
					new_parent->setChildren(base.end()[-1][0], temp);
					//将new_parent压入new_nodes
					new_nodes.push_back(new_parent);
					//不显示输出
					//cout << "将 " << base.end()[-1][0]->getHash() << " 和 " << temp->getHash() << " 连接,得到对应父节点的哈希值 " << endl;
					//不显示输出
					//cout << endl;
					//不显示输出
					//cout << "得到的对应父节点的哈希值:" << endl;
					//不显示输出
					//printTreeLevel(new_nodes);
					base.push_back(new_nodes); //将新一轮的父节点new_nodes压入base
					//不显示输出
					//cout << "该层的结点有 " << base.end()[-1].size() << " 个:" << endl;
					break;
				}
			}  //这样每一轮得到新一层的父节点，知道得到根节点 退出循环
		}
		else
		{
			int length = base.end()[-1].size() - 1;//记录初始长度
			node* temp = base.end()[-1][base.end()[-1].size() - 1];//记录最后一个节点
			while (base.end()[-1].size() > 1)
			{
				vector<node*> new_nodes;
				if (base.end()[-1].size() - 1 == length)
				{
					for (int i = 0; i < base.end()[-1].size() - 1; i += 2)
					{
						node* new_parent = new node; //设置父亲节点 传入最后一个元素 即一个节点列表的第i和i+1个
						base.end()[-1][i]->setParent(new_parent);
						base.end()[-1][i + 1]->setParent(new_parent);
						//通过两个孩子节点的哈希值设置父节点哈希值
						new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
						//将该父节点的左右孩子节点设置为这两个
						new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
						//将new_parent压入new_nodes
						new_nodes.push_back(new_parent);
						//不显示输出
						//cout << "将 " << base.end()[-1][i]->getHash() << " 和 " << base.end()[-1][i + 1]->getHash() << " 连接,得到对应父节点的哈希值 " << endl;
					}
					//不显示输出
					//cout << endl;
					//不显示输出
					//cout << "得到的对应父节点的哈希值:" << endl;
					//不显示输出
					//printTreeLevel(new_nodes);
					new_nodes.push_back(temp);//将最后一个节点压入base
					base.push_back(new_nodes); //将新一轮的父节点new_nodes压入base
					//不显示输出
					//cout << "该层的结点有 " << base.end()[-1].size() << " 个:" << endl;

				}
				else
				{
					for (int i = 0; i < base.end()[-1].size(); i += 2)
					{
						node* new_parent = new node; //设置父亲节点 传入最后一个元素 即一个节点列表的第i和i+1个
						base.end()[-1][i]->setParent(new_parent);
						base.end()[-1][i + 1]->setParent(new_parent);
						//通过两个孩子节点的哈希值设置父节点哈希值
						new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
						//将该父节点的左右孩子节点设置为这两个
						new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
						//将new_parent压入new_nodes
						new_nodes.push_back(new_parent);
						//不显示输出
						//cout << "将 " << base.end()[-1][i]->getHash() << " 和 " << base.end()[-1][i + 1]->getHash() << " 连接,得到对应父节点的哈希值 " << endl;
					}
					//不显示输出
					//cout << endl;
					//不显示输出
					//cout << "得到的对应父节点的哈希值:" << endl;
					//不显示输出
					//printTreeLevel(new_nodes);
					base.push_back(new_nodes); //将新一轮的父节点new_nodes压入base
					//不显示输出
					//cout << "该层的结点有 " << base.end()[-1].size() << " 个:" << endl;
				}
			}
		}
	}
	

	merkleRoot = base.end()[-1][0]->getHash(); //根节点的哈希值

	cout << "Merkle Root : " << merkleRoot << endl << endl;
}

void tree::buildBaseLeafes(vector<string> base_leafs) //建立叶子节点列表
{
	vector<node*> new_nodes;
	//不显示输出
	//cout << "叶子结点及对应的哈希值: " << endl;

	for (auto leaf : base_leafs) //给每一个字符串创建对应节点，并通过这个字符串设置哈希值
	{
		node* new_node = new node;
		new_node->setHash(leaf);
		//不显示输出
		//cout << leaf << ":" << new_node->getHash() << endl;

		new_nodes.push_back(new_node);
	}

	base.push_back(new_nodes);
	cout << endl;
}

int tree::verify(string hash)
{
	node* el_node = nullptr;
	string act_hash = hash;

	for (int i = 0; i < base[0].size(); i++)
	{
		if (base[0][i]->getHash() == hash)
		{
			el_node = base[0][i];
		}
	}
	if (el_node == nullptr)
	{
		return 0;
	}

	//不显示输出
	//cout << "使用到的哈希值:" << endl;
	//不显示输出
	//cout << act_hash << endl;

	do  //验证merkle tree是否改变过 
	{
		//父节点的哈希是左孩子的哈希string+右孩子的哈希string
		//如果el_node的父节点的左节点是el_node
		if (el_node->checkDir() == 0)
		{
			//是左孩子就 做孩子的哈希string+右孩子的哈希string
			act_hash = sha2::hash256_hex_string(act_hash + el_node->getSibling()->getHash());
		}
		else
		{
			act_hash = sha2::hash256_hex_string(el_node->getSibling()->getHash() + act_hash);
		}

		//std::cout << act_hash << endl;

		el_node = el_node->getParent();
	} while ((el_node->getParent()) != NULL); //到达根节点

	return act_hash == merkleRoot ? 1 : 0;
}

tree::~tree() {}
