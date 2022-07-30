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
	vector<vector<node*>> base; //��������һ�����ڵ��б�
public:
	tree();
	void buildTree();//����Merkel Tree
	void buildBaseLeafes(vector<string> base_leafs);
	int verify(string hash);//ȷ��ĳһ��Ҷ�ӽڵ��ڲ�������
	virtual ~tree();//�麯��
};

tree::tree() {}

int tree::makeBinary(vector<node*>& node_vector) //ʹҶ�ӽڵ��Ϊ˫��
{
	int vectSize = node_vector.size();
	if ((vectSize % 2) != 0) //���Ԫ�ظ���Ϊ�������Ͱ������һ���ڵ�push_backһ��
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


void tree::buildTree() //����merkle tree
{
	int re = (base.end()[-1].size()-1) % 4;
	int parity = (base.end()[-1].size()) % 2;
	//���Ҷ�ӽڵ����Ϊż�����ǾͰ���ԭ���İ취
	//���Ҷ�ӽڵ����Ϊ���������㣨����-1��%4��ֵ�����Ϊ0�������Ƚ����һ���ڵ�֮ǰ�����нڵ�ϳ�һ�������������һ��
	//�ڵ�͸��ڵ�ϲ������Ϊ2�������Ƚ����һ���ڵ�֮ǰ�����нڵ�ϳ�һ�Σ��ٰ����һ���ڵ���뵽��һ����
	if (parity == 0)
	{
		do
		{
			vector<node*> new_nodes;
			if (parity == 0)
			{
				for (int i = 0; i < base.end()[-1].size(); i += 2)
				{
					node* new_parent = new node; //���ø��׽ڵ� �������һ��Ԫ�� ��һ���ڵ��б�ĵ�i��i+1��
					base.end()[-1][i]->setParent(new_parent);
					base.end()[-1][i + 1]->setParent(new_parent);
					//ͨ���������ӽڵ�Ĺ�ϣֵ���ø��ڵ��ϣֵ
					new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
					//���ø��ڵ�����Һ��ӽڵ�����Ϊ������
					new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
					//��new_parentѹ��new_nodes
					new_nodes.push_back(new_parent);
					//����ʾ���
					//cout << "�� " << base.end()[-1][i]->getHash() << " �� " << base.end()[-1][i + 1]->getHash() << " ����,�õ���Ӧ���ڵ�Ĺ�ϣֵ " << endl;
				}
				//����ʾ���
				//cout << endl;
				//����ʾ���
				//cout << "�õ��Ķ�Ӧ���ڵ�Ĺ�ϣֵ:" << endl;
				//����ʾ���
				//printTreeLevel(new_nodes);
				base.push_back(new_nodes); //����һ�ֵĸ��ڵ�new_nodesѹ��base
				//����ʾ���
				//cout << "�ò�Ľ���� " << base.end()[-1].size() << " ��:" << endl;
			}
			else//������ʱ��
			{
				re = (base.end()[-1].size() - 1) % 4;
				if (re == 0)
				{
					node* temp = base.end()[-1][base.end()[-1].size() - 1];//��¼���һ���ڵ�
					while (1)
					{
						vector<node*> new_nodes;
						if (base.end()[-1].size() > 1)
						{
							for (int i = 0; i < base.end()[-1].size() - 1; i += 2)
							{
								node* new_parent = new node; //���ø��׽ڵ� �������һ��Ԫ�� ��һ���ڵ��б�ĵ�i��i+1��
								base.end()[-1][i]->setParent(new_parent);
								base.end()[-1][i + 1]->setParent(new_parent);
								//ͨ���������ӽڵ�Ĺ�ϣֵ���ø��ڵ��ϣֵ
								new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
								//���ø��ڵ�����Һ��ӽڵ�����Ϊ������
								new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
								//��new_parentѹ��new_nodes
								new_nodes.push_back(new_parent);
								//����ʾ���
								//cout << "�� " << base.end()[-1][i]->getHash() << " �� " << base.end()[-1][i + 1]->getHash() << " ����,�õ���Ӧ���ڵ�Ĺ�ϣֵ " << endl;
							}
							//����ʾ���
							//cout << endl;
							//����ʾ���
							//cout << "�õ��Ķ�Ӧ���ڵ�Ĺ�ϣֵ:" << endl;
							//����ʾ���
							//printTreeLevel(new_nodes);
							base.push_back(new_nodes); //����һ�ֵĸ��ڵ�new_nodesѹ��base
							//����ʾ���
							/*if (base.end()[-1].size() > 1)
							{
								cout << "�ò�Ľ���� " << base.end()[-1].size() << " ��:" << endl;
							}
							else
							{
								cout << "�ò�Ľ���� " << base.end()[-1].size()+1 << " ��:" << endl;
							}*/
						}
						else
						{
							//�����һ���ڵ�͸��ڵ�ϲ�
							node* new_parent = new node; //�����µĸ��ڵ�
							base.end()[-1][0]->setParent(new_parent);
							temp->setParent(new_parent);
							//ͨ���������ӽڵ�Ĺ�ϣֵ���ø��ڵ��ϣֵ
							new_parent->setHash(base.end()[-1][0]->getHash() + temp->getHash());
							//���ø��ڵ�����Һ��ӽڵ�����Ϊ������
							new_parent->setChildren(base.end()[-1][0], temp);
							//��new_parentѹ��new_nodes
							new_nodes.push_back(new_parent);
							//����ʾ���
							//cout << "�� " << base.end()[-1][0]->getHash() << " �� " << temp->getHash() << " ����,�õ���Ӧ���ڵ�Ĺ�ϣֵ " << endl;
							//����ʾ���
							//cout << endl;
							//����ʾ���
							//cout << "�õ��Ķ�Ӧ���ڵ�Ĺ�ϣֵ:" << endl;
							//����ʾ���
							//printTreeLevel(new_nodes);
							base.push_back(new_nodes); //����һ�ֵĸ��ڵ�new_nodesѹ��base
							//����ʾ���
							//cout << "�ò�Ľ���� " << base.end()[-1].size() << " ��:" << endl;
							break;
						}
					}  //����ÿһ�ֵõ���һ��ĸ��ڵ㣬֪���õ����ڵ� �˳�ѭ��
				}
				else
				{
					int length = base.end()[-1].size() - 1;//��¼��ʼ����
					node* temp = base.end()[-1][base.end()[-1].size() - 1];//��¼���һ���ڵ�
					while (base.end()[-1].size() > 1)
					{
						vector<node*> new_nodes;
						if (base.end()[-1].size() - 1 == length)
						{
							for (int i = 0; i < base.end()[-1].size() - 1; i += 2)
							{
								node* new_parent = new node; //���ø��׽ڵ� �������һ��Ԫ�� ��һ���ڵ��б�ĵ�i��i+1��
								base.end()[-1][i]->setParent(new_parent);
								base.end()[-1][i + 1]->setParent(new_parent);
								//ͨ���������ӽڵ�Ĺ�ϣֵ���ø��ڵ��ϣֵ
								new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
								//���ø��ڵ�����Һ��ӽڵ�����Ϊ������
								new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
								//��new_parentѹ��new_nodes
								new_nodes.push_back(new_parent);
								//����ʾ���
								//cout << "�� " << base.end()[-1][i]->getHash() << " �� " << base.end()[-1][i + 1]->getHash() << " ����,�õ���Ӧ���ڵ�Ĺ�ϣֵ " << endl;
							}
							//����ʾ���
							//cout << endl;
							//����ʾ���
							//cout << "�õ��Ķ�Ӧ���ڵ�Ĺ�ϣֵ:" << endl;
							//����ʾ���
							//printTreeLevel(new_nodes);
							new_nodes.push_back(temp);//�����һ���ڵ�ѹ��base
							base.push_back(new_nodes); //����һ�ֵĸ��ڵ�new_nodesѹ��base
							//����ʾ���
							//cout << "�ò�Ľ���� " << base.end()[-1].size() << " ��:" << endl;

						}
						else
						{
							for (int i = 0; i < base.end()[-1].size(); i += 2)
							{
								node* new_parent = new node; //���ø��׽ڵ� �������һ��Ԫ�� ��һ���ڵ��б�ĵ�i��i+1��
								base.end()[-1][i]->setParent(new_parent);
								base.end()[-1][i + 1]->setParent(new_parent);
								//ͨ���������ӽڵ�Ĺ�ϣֵ���ø��ڵ��ϣֵ
								new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
								//���ø��ڵ�����Һ��ӽڵ�����Ϊ������
								new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
								//��new_parentѹ��new_nodes
								new_nodes.push_back(new_parent);
								//����ʾ���
								//cout << "�� " << base.end()[-1][i]->getHash() << " �� " << base.end()[-1][i + 1]->getHash() << " ����,�õ���Ӧ���ڵ�Ĺ�ϣֵ " << endl;
							}
							//����ʾ���
							//cout << endl;
							//����ʾ���
							//cout << "�õ��Ķ�Ӧ���ڵ�Ĺ�ϣֵ:" << endl;
							//����ʾ���
							//printTreeLevel(new_nodes);
							base.push_back(new_nodes); //����һ�ֵĸ��ڵ�new_nodesѹ��base
							//����ʾ���
							//cout << "�ò�Ľ���� " << base.end()[-1].size() << " ��:" << endl;
						}
					}
				}
			}
			//�ٴμ�����ż����Ϊ���ܷ����仯������10/2=5
			parity = (base.end()[-1].size()) % 2;
		} while (base.end()[-1].size() > 1); //����ÿһ�ֵõ���һ��ĸ��ڵ㣬֪���õ����ڵ� �˳�ѭ��
	}
	else
	{
		if (re == 0)
		{
			node* temp = base.end()[-1][base.end()[-1].size() - 1];//��¼���һ���ڵ�
			while(1)
			{
				vector<node*> new_nodes;
				if (base.end()[-1].size() > 1)
				{
					for (int i = 0; i < base.end()[-1].size() - 1; i += 2)
					{
						node* new_parent = new node; //���ø��׽ڵ� �������һ��Ԫ�� ��һ���ڵ��б�ĵ�i��i+1��
						base.end()[-1][i]->setParent(new_parent);
						base.end()[-1][i + 1]->setParent(new_parent);
						//ͨ���������ӽڵ�Ĺ�ϣֵ���ø��ڵ��ϣֵ
						new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
						//���ø��ڵ�����Һ��ӽڵ�����Ϊ������
						new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
						//��new_parentѹ��new_nodes
						new_nodes.push_back(new_parent);
						//����ʾ���
						//cout << "�� " << base.end()[-1][i]->getHash() << " �� " << base.end()[-1][i + 1]->getHash() << " ����,�õ���Ӧ���ڵ�Ĺ�ϣֵ " << endl;
					}
					//����ʾ���
					//cout << endl;
					//����ʾ���
					//cout << "�õ��Ķ�Ӧ���ڵ�Ĺ�ϣֵ:" << endl;
					//����ʾ���
					//printTreeLevel(new_nodes);
					base.push_back(new_nodes); //����һ�ֵĸ��ڵ�new_nodesѹ��base
					//����ʾ���
					/*if (base.end()[-1].size() > 1)
					{
						cout << "�ò�Ľ���� " << base.end()[-1].size() << " ��:" << endl;
					}
					else
					{
						cout << "�ò�Ľ���� " << base.end()[-1].size()+1 << " ��:" << endl;
					}*/
				}
				else
				{
					//�����һ���ڵ�͸��ڵ�ϲ�
					node* new_parent = new node; //�����µĸ��ڵ�
					base.end()[-1][0]->setParent(new_parent);
					temp->setParent(new_parent);
					//ͨ���������ӽڵ�Ĺ�ϣֵ���ø��ڵ��ϣֵ
					new_parent->setHash(base.end()[-1][0]->getHash() + temp->getHash());
					//���ø��ڵ�����Һ��ӽڵ�����Ϊ������
					new_parent->setChildren(base.end()[-1][0], temp);
					//��new_parentѹ��new_nodes
					new_nodes.push_back(new_parent);
					//����ʾ���
					//cout << "�� " << base.end()[-1][0]->getHash() << " �� " << temp->getHash() << " ����,�õ���Ӧ���ڵ�Ĺ�ϣֵ " << endl;
					//����ʾ���
					//cout << endl;
					//����ʾ���
					//cout << "�õ��Ķ�Ӧ���ڵ�Ĺ�ϣֵ:" << endl;
					//����ʾ���
					//printTreeLevel(new_nodes);
					base.push_back(new_nodes); //����һ�ֵĸ��ڵ�new_nodesѹ��base
					//����ʾ���
					//cout << "�ò�Ľ���� " << base.end()[-1].size() << " ��:" << endl;
					break;
				}
			}  //����ÿһ�ֵõ���һ��ĸ��ڵ㣬֪���õ����ڵ� �˳�ѭ��
		}
		else
		{
			int length = base.end()[-1].size() - 1;//��¼��ʼ����
			node* temp = base.end()[-1][base.end()[-1].size() - 1];//��¼���һ���ڵ�
			while (base.end()[-1].size() > 1)
			{
				vector<node*> new_nodes;
				if (base.end()[-1].size() - 1 == length)
				{
					for (int i = 0; i < base.end()[-1].size() - 1; i += 2)
					{
						node* new_parent = new node; //���ø��׽ڵ� �������һ��Ԫ�� ��һ���ڵ��б�ĵ�i��i+1��
						base.end()[-1][i]->setParent(new_parent);
						base.end()[-1][i + 1]->setParent(new_parent);
						//ͨ���������ӽڵ�Ĺ�ϣֵ���ø��ڵ��ϣֵ
						new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
						//���ø��ڵ�����Һ��ӽڵ�����Ϊ������
						new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
						//��new_parentѹ��new_nodes
						new_nodes.push_back(new_parent);
						//����ʾ���
						//cout << "�� " << base.end()[-1][i]->getHash() << " �� " << base.end()[-1][i + 1]->getHash() << " ����,�õ���Ӧ���ڵ�Ĺ�ϣֵ " << endl;
					}
					//����ʾ���
					//cout << endl;
					//����ʾ���
					//cout << "�õ��Ķ�Ӧ���ڵ�Ĺ�ϣֵ:" << endl;
					//����ʾ���
					//printTreeLevel(new_nodes);
					new_nodes.push_back(temp);//�����һ���ڵ�ѹ��base
					base.push_back(new_nodes); //����һ�ֵĸ��ڵ�new_nodesѹ��base
					//����ʾ���
					//cout << "�ò�Ľ���� " << base.end()[-1].size() << " ��:" << endl;

				}
				else
				{
					for (int i = 0; i < base.end()[-1].size(); i += 2)
					{
						node* new_parent = new node; //���ø��׽ڵ� �������һ��Ԫ�� ��һ���ڵ��б�ĵ�i��i+1��
						base.end()[-1][i]->setParent(new_parent);
						base.end()[-1][i + 1]->setParent(new_parent);
						//ͨ���������ӽڵ�Ĺ�ϣֵ���ø��ڵ��ϣֵ
						new_parent->setHash(base.end()[-1][i]->getHash() + base.end()[-1][i + 1]->getHash());
						//���ø��ڵ�����Һ��ӽڵ�����Ϊ������
						new_parent->setChildren(base.end()[-1][i], base.end()[-1][i + 1]);
						//��new_parentѹ��new_nodes
						new_nodes.push_back(new_parent);
						//����ʾ���
						//cout << "�� " << base.end()[-1][i]->getHash() << " �� " << base.end()[-1][i + 1]->getHash() << " ����,�õ���Ӧ���ڵ�Ĺ�ϣֵ " << endl;
					}
					//����ʾ���
					//cout << endl;
					//����ʾ���
					//cout << "�õ��Ķ�Ӧ���ڵ�Ĺ�ϣֵ:" << endl;
					//����ʾ���
					//printTreeLevel(new_nodes);
					base.push_back(new_nodes); //����һ�ֵĸ��ڵ�new_nodesѹ��base
					//����ʾ���
					//cout << "�ò�Ľ���� " << base.end()[-1].size() << " ��:" << endl;
				}
			}
		}
	}
	

	merkleRoot = base.end()[-1][0]->getHash(); //���ڵ�Ĺ�ϣֵ

	cout << "Merkle Root : " << merkleRoot << endl << endl;
}

void tree::buildBaseLeafes(vector<string> base_leafs) //����Ҷ�ӽڵ��б�
{
	vector<node*> new_nodes;
	//����ʾ���
	//cout << "Ҷ�ӽ�㼰��Ӧ�Ĺ�ϣֵ: " << endl;

	for (auto leaf : base_leafs) //��ÿһ���ַ���������Ӧ�ڵ㣬��ͨ������ַ������ù�ϣֵ
	{
		node* new_node = new node;
		new_node->setHash(leaf);
		//����ʾ���
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

	//����ʾ���
	//cout << "ʹ�õ��Ĺ�ϣֵ:" << endl;
	//����ʾ���
	//cout << act_hash << endl;

	do  //��֤merkle tree�Ƿ�ı�� 
	{
		//���ڵ�Ĺ�ϣ�����ӵĹ�ϣstring+�Һ��ӵĹ�ϣstring
		//���el_node�ĸ��ڵ����ڵ���el_node
		if (el_node->checkDir() == 0)
		{
			//�����Ӿ� �����ӵĹ�ϣstring+�Һ��ӵĹ�ϣstring
			act_hash = sha2::hash256_hex_string(act_hash + el_node->getSibling()->getHash());
		}
		else
		{
			act_hash = sha2::hash256_hex_string(el_node->getSibling()->getHash() + act_hash);
		}

		//std::cout << act_hash << endl;

		el_node = el_node->getParent();
	} while ((el_node->getParent()) != NULL); //������ڵ�

	return act_hash == merkleRoot ? 1 : 0;
}

tree::~tree() {}
