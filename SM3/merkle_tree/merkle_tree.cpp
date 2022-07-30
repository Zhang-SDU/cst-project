#include <iostream>
#include "tree.h"
#include "sha256.h"
using namespace std;

#define number 100000

int main()
{
	string check_str = "";
	//cout << "���� Merkle Tree��Ҷ�ӽ������ݣ���ʽΪ��a b c d\n��~����Ϊ������: " << endl;
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
	cout << "Merkle Tree��Ҷ�ӽڵ�Ϊ0-" << number-1<<endl;
	
	//����չʾ����Ĵ���
	//while (1) //����Ҷ�ӽڵ�
	//{
	//	string str;
	//	cin >> str;
	//	if (str != "~")
	//	{
	//		v.push_back(str);//��vector������һ����Ԫ��
	//	}
	//	else
	//	{
	//		break;
	//	}
	//}

	tree ntree;
	ntree.buildBaseLeafes(v);
	//����ʾ���
	cout << "���"<<number<<"��Ҷ�ӽڵ�Merkle���Ĺ������̡�" << endl << endl;
	ntree.buildTree();

	cout << "��֤�����Ƿ���Merkle����:" << endl << endl;
	while (true) {
		cout << "����֤������: " << endl;
		cin >> check_str; //��������֤��Ҷ�ӽڵ�
		cout << endl;
		check_str = sha2::hash256_hex_string(check_str);

		cout << "����֤�����ݵĹ�ϣֵ: " << check_str << endl;

		if (ntree.verify(check_str))//��֤��������ڵ� �����޸ı�
		{
			cout << endl;
			cout << "Merkle���ϴ�����֤�����ݵ�Ҷ�ӽ��" << endl;
		}
		else
		{
			cout << "Merkle���ϲ�������֤������" << endl;
		}
		cout << endl;
	}
	return 0;
}