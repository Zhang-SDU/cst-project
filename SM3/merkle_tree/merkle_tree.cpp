#include <iostream>
#include "tree.h"
#include "sha256.h"
using namespace std;

#define number 100000

int main()
{
	string check_str = "";
	//cout << "输入 Merkle Tree的叶子结点的数据，形式为：a b c d\n以~键作为结束符: " << endl;
	vector<string> v(number);
	int i = 0;
	int count = 0;
	while (count<number)
	{
		string str = to_string(i);
		i++;
		v.push_back(str);
		count++;
	}
	cout << "Merkle Tree的叶子节点为0-" << number-1<<endl;
	
	//便于展示输出的代码
	//while (1) //输入叶子节点
	//{
	//	string str;
	//	cin >> str;
	//	if (str != "~")
	//	{
	//		v.push_back(str);//在vector最后添加一个新元素
	//	}
	//	else
	//	{
	//		break;
	//	}
	//}

	tree ntree;
	ntree.buildBaseLeafes(v);
	//不显示输出
	cout << "完成"<<number<<"个叶子节点Merkle树的构建过程。" << endl << endl;
	ntree.buildTree();

	cout << "验证数据是否在Merkle树中:" << endl << endl;
	while (true) {
		cout << "想验证的数据: " << endl;
		cin >> check_str; //输入想验证的叶子节点
		cout << endl;
		check_str = sha2::hash256_hex_string(check_str);

		cout << "想验证的数据的哈希值: " << check_str << endl;

		if (ntree.verify(check_str))//验证有无这个节点 树有无改变
		{
			cout << endl;
			cout << "Merkle树上存在验证的数据的叶子结点" << endl;
		}
		else
		{
			cout << "Merkle树上不存在验证的数据" << endl;
		}
		cout << endl;
	}
	return 0;
}