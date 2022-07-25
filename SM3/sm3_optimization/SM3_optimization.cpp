#include <string.h>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <iomanip>
#include <memory>
#include <stdint.h>
#include <ctime>
#include <ratio>
#include <chrono>
#include <time.h>
#include <stdlib.h>

#pragma once

#define SM3_HASH_SIZE 32
namespace SM3 {
	/*哈希值向量大小，单位为字节*/
	typedef struct SM3Context {
		unsigned int intermediateHash[SM3_HASH_SIZE / 4];
		unsigned char messageBlock[64];//512位的数据块，是迭代压缩的对象
	} SM3Context;

	unsigned char* SM3_optimize(unsigned char* message,
		unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE]);
	unsigned char* SM3(unsigned char* message,
		unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE]);
	std::vector<uint32_t> sm3_hash();
	std::vector<uint32_t> sm3_hash_optimize();
}
using namespace std;

unsigned int t[64];//提前计算出常量t的值进行存储

/*判断运行环境是否为小端*/
static const int endianTest = 1;
#define IsLittleEndian() (*(char *)&endianTest == 1)
/*向左循环移位*/
#define LeftRotate(word, bits) ( (word) << (bits) | (word) >> (32 - (bits)) )
/* 反转四字节整型字节序*/
unsigned int* ReverseWord(unsigned int* word)
{
	unsigned char* byte, temp;

	byte = (unsigned char*)word;
	temp = byte[0];
	byte[0] = byte[3];
	byte[3] = temp;

	temp = byte[1];
	byte[1] = byte[2];
	byte[2] = temp;
	return word;

}
/*T常量*/
unsigned int T(int i)
{
	if (i >= 0 && i <= 15)
		return 0x79CC4519;
	else if (i >= 16 && i <= 63)
		return 0x7A879D8A;
	else
		return 0;
}

/*提前计算要使用的T常量*/
void caculT() {
	for (int i = 0; i < 64; i++) {
		t[i] = LeftRotate(T(i), i);
	}
	return;
}

/*FF*/
unsigned int FF(unsigned int X, unsigned int Y, unsigned int Z, int i)
{
	if (i >= 0 && i <= 15)
		return X ^ Y ^ Z;
	else if (i >= 16 && i <= 63)
		return (X & Y) | (X & Z) | (Y & Z);
	else
		return 0;
}

/*GG*/
unsigned int GG(unsigned int X, unsigned int Y, unsigned int Z, int i)
{
	if (i >= 0 && i <= 15)
		return X ^ Y ^ Z;
	else if (i >= 16 && i <= 63)
		return (X & Y) | (~X & Z);
	else
		return 0;
}

/*P0*/
unsigned int P0(unsigned int X)
{
	return X ^ LeftRotate(X, 9) ^ LeftRotate(X, 17);
}

/*P1*/
unsigned int P1(unsigned int X)
{
	return X ^ LeftRotate(X, 15) ^ LeftRotate(X, 23);
}

/*初始化函数*/
void SM3Init(SM3::SM3Context* context) {
	context->intermediateHash[0] = 0x7380166F;
	context->intermediateHash[1] = 0x4914B2B9;
	context->intermediateHash[2] = 0x172442D7;
	context->intermediateHash[3] = 0xDA8A0600;
	context->intermediateHash[4] = 0xA96F30BC;
	context->intermediateHash[5] = 0x163138AA;
	context->intermediateHash[6] = 0xE38DEE4D;
	context->intermediateHash[7] = 0xB0FB0E4E;
}


/*新的一轮压缩算法*/
void sm3_oneround_optimize(int i, unsigned int& A, unsigned int& B, unsigned int& C, unsigned int& D,
	unsigned int& E, unsigned int& F, unsigned int& G, unsigned int& H, unsigned int W[68], SM3::SM3Context* context)
{
	unsigned int SS1 = 0, SS2 = 0, TT1 = 0, TT2 = 0;
	//计算消息扩展字W[i+4]
	if (i < 12) {
		W[i + 4] = *(unsigned int*)(context->messageBlock + (i + 4) * 4);
		if (IsLittleEndian())
			ReverseWord(W + i + 4);
	}
	else {
		W[i + 4] = P1(W[i - 12] ^ W[i - 5] ^ LeftRotate(W[i + 1], 15)) ^ LeftRotate(W[i - 9], 17) ^ W[i - 2];
	}

	//计算中间变量TT1和TT2
	TT2 = LeftRotate(A, 12);
	TT1 = TT2 + E + t[i];
	TT1 = LeftRotate(TT1, 7);
	TT2 = TT2 ^ TT1;

	//仅更新字寄存器B、D、F、H
	D = D + FF(A, B, C, i) + TT2 + (W[i] ^ W[i + 4]);//W'[i]=W[i] ^ W[i + 4]
	H = H + GG(E, F, G, i) + TT1 + W[i];
	B = LeftRotate(B, 9);
	F = LeftRotate(F, 19);
	H = P0(H);
}

void sm3_oneroune(int i, unsigned int& A, unsigned int& B, unsigned int& C, unsigned int& D,
	unsigned int& E, unsigned int& F, unsigned int& G, unsigned int& H, unsigned int W[68], unsigned int W1[64], SM3::SM3Context* context)
{
	for (int i = 0; i < 64; i++) {
		t[i] = LeftRotate(T(i), i);
	}
	unsigned int SS1 = 0, SS2 = 0, TT1 = 0, TT2 = 0;
	SS1 = LeftRotate(LeftRotate(A, 12) ^ E ^ LeftRotate(t[i], i), 7);
	SS2 = SS1 ^ LeftRotate(A, 12);
	TT1 = FF(A, B, C, i) ^ D ^ SS2 ^ W1[i];
	TT2 = GG(E, F, G, i) ^ H ^ SS1 ^ W[i];
	D = C;
	C = LeftRotate(B, 9);
	B = A;
	A = TT1;
	H = G;
	G = LeftRotate(F, 19);
	F = E;
	E = P0(TT2);

}



void sm3_cf(SM3::SM3Context* context)
{
	int i;
	unsigned int W[68];
	unsigned int W1[64];
	//A-H是8个字寄存器
	unsigned int A, B, C, D, E, F, G, H;

	/* 消息扩展 */
	//首先计算出W[0]-W[15]
	for (i = 0; i < 16; i++)
	{
		W[i] = *(unsigned int*)(context->messageBlock + i * 4);
		//sm3算法要求是大端存储，所以如果是小端的话需要进行字节逆序
		if (IsLittleEndian())
			ReverseWord(W + i);
	}
	for (i; i < 68; i++)
	{
		W[i] = P1(W[i - 16] ^ W[i - 9] ^ LeftRotate(W[i - 3], 15)) ^ LeftRotate(W[i - 13], 17) ^ W[i - 6];
		if (IsLittleEndian())
			ReverseWord(W + i);
	}
	for (i = 0; i < 64; i++)
	{
		W1[i] = W[i] ^ W[i + 4];
		if (IsLittleEndian())
			ReverseWord(W + i);
	}
	/* 消息压缩 */
	A = context->intermediateHash[0];
	B = context->intermediateHash[1];
	C = context->intermediateHash[2];
	D = context->intermediateHash[3];
	E = context->intermediateHash[4];
	F = context->intermediateHash[5];
	G = context->intermediateHash[6];
	H = context->intermediateHash[7];
	for (i = 0; i <= 64; i++)
	{
		sm3_oneroune(i, A, B, C, D, E, F, G, H, W, W1, context);
	}
	context->intermediateHash[0] ^= A;
	context->intermediateHash[1] ^= B;
	context->intermediateHash[2] ^= C;
	context->intermediateHash[3] ^= D;
	context->intermediateHash[4] ^= E;
	context->intermediateHash[5] ^= F;
	context->intermediateHash[6] ^= G;
	context->intermediateHash[7] ^= H;

}

/* 处理消息块*/
void sm3_cf_optimize(SM3::SM3Context* context)
{
	int i;
	unsigned int W[68];
	unsigned int A, B, C, D, E, F, G, H;

	/* 消息扩展 */
	//首先计算出W[0]-W[3]
	for (i = 0; i < 4; i++)
	{
		W[i] = *(unsigned int*)(context->messageBlock + i * 4);
		//sm3算法要求是大端存储，所以如果是小端的话需要进行字节逆序
		if (IsLittleEndian())
			ReverseWord(W + i);
	}

	/* 消息压缩 */
	A = context->intermediateHash[0];
	B = context->intermediateHash[1];
	C = context->intermediateHash[2];
	D = context->intermediateHash[3];
	E = context->intermediateHash[4];
	F = context->intermediateHash[5];
	G = context->intermediateHash[6];
	H = context->intermediateHash[7];
	for (i = 0; i <= 60; i += 4)
	{
		sm3_oneround_optimize(i, A, B, C, D, E, F, G, H, W, context);
		sm3_oneround_optimize(i + 1, D, A, B, C, H, E, F, G, W, context);
		sm3_oneround_optimize(i + 2, C, D, A, B, G, H, E, F, W, context);
		sm3_oneround_optimize(i + 3, B, C, D, A, F, G, H, E, W, context);
	}
	context->intermediateHash[0] ^= A;
	context->intermediateHash[1] ^= B;
	context->intermediateHash[2] ^= C;
	context->intermediateHash[3] ^= D;
	context->intermediateHash[4] ^= E;
	context->intermediateHash[5] ^= F;
	context->intermediateHash[6] ^= G;
	context->intermediateHash[7] ^= H;
}

/*
* SM3算法主函数:
	message代表需要加密的消息字节串;
	messagelen是消息的字节数;
	digset表示返回的哈希值
*/
unsigned char* SM3::SM3_optimize(unsigned char* message,
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE])
{
	SM3::SM3Context context;
	unsigned int i, remainder, bitLen;

	/* 初始化上下文 */
	SM3Init(&context);//设置IV的初始值
	remainder = messageLen % 64;
	/* 对满足512bit的消息分组进行处理 */
	for (i = 0; i < messageLen / 64; i++)
	{
		memcpy(context.messageBlock, message + i * 64, 64);
		sm3_cf_optimize(&context);
	}

	/* 填充消息分组，并处理 */
	bitLen = messageLen * 8;
	if (IsLittleEndian())
		ReverseWord(&bitLen);
	memcpy(context.messageBlock, message + i * 64, remainder);
	context.messageBlock[remainder] = 0x80;//添加bit‘0x1000 0000’到末尾
	if (remainder <= 55)//如果剩下的bit数少于440
	{
		/* 长度按照大端法占8个字节，只考虑长度在 2**32 - 1（单位：比特）以内的情况，
		* 故将高 4 个字节赋为 0 。*/
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1 - 8 + 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		sm3_cf_optimize(&context);
	}
	else
	{
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1);
		sm3_cf_optimize(&context);
		/* 长度按照大端法占8个字节，只考虑长度在 2**32 - 1（单位：比特）以内的情况，
		* 故将高 4 个字节赋为 0 。*/
		memset(context.messageBlock, 0, 64 - 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		sm3_cf_optimize(&context);
	}

	/* 返回结果 */
	if (IsLittleEndian())
		for (i = 0; i < 8; i++)
			ReverseWord(context.intermediateHash + i);
	memcpy(digest, context.intermediateHash, SM3_HASH_SIZE);

	return digest;
}

//普通sm3
unsigned char* SM3::SM3(unsigned char* message,
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE])
{
	SM3::SM3Context context;
	unsigned int i, remainder, bitLen;

	/* 初始化上下文 */
	SM3Init(&context);//设置IV的初始值
	remainder = messageLen % 64;
	/* 对前面的消息分组进行处理 */
	for (i = 0; i < messageLen / 64; i++)
	{
		memcpy(context.messageBlock, message + i * 64, 64);
		sm3_cf(&context);
	}

	/* 填充消息分组，并处理 */
	bitLen = messageLen * 8;
	if (IsLittleEndian())
		ReverseWord(&bitLen);
	memcpy(context.messageBlock, message + i * 64, remainder);
	context.messageBlock[remainder] = 0x80;//添加bit‘0x1000 0000’到末尾
	if (remainder <= 55)//如果剩下的bit数少于440
	{
		/* 长度按照大端法占8个字节，只考虑长度在 2**32 - 1（单位：比特）以内的情况，
		* 故将高 4 个字节赋为 0 。*/
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1 - 8 + 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		sm3_cf(&context);
	}
	else
	{
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1);
		sm3_cf(&context);
		/* 长度按照大端法占8个字节，只考虑长度在 2**32 - 1（单位：比特）以内的情况，
		* 故将高 4 个字节赋为 0 。*/
		memset(context.messageBlock, 0, 64 - 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		sm3_cf(&context);
	}

	/* 返回结果 */
	if (IsLittleEndian())
		for (i = 0; i < 8; i++)
			ReverseWord(context.intermediateHash + i);
	memcpy(digest, context.intermediateHash, SM3_HASH_SIZE);

	return digest;
}


/*
sm3主函数：包括消息填充、扩展、压缩步骤，返回最后的hash值
*/
std::vector<uint32_t> SM3::sm3_hash_optimize()
{
	caculT();//预计算压缩函数中要用到的T[i]<<i的值
	std::vector<uint32_t> hash_result(32, 0);//（0，0，0，……，0）32个0，用来存放hash结果
	unsigned char buffer[4] = { 0x01,0x03,0x4a,0x95 };//要处理的明文
	unsigned char hash_output[32];//存放结果的中间变量
	SM3::SM3_optimize(buffer, 4, hash_output);//sm3的主函数，包括消息填充、扩展、压缩函数
	hash_result.assign(&hash_output[0], &hash_output[32]);//要返回一个vector变量所以把值赋到hash_result
	return hash_result;
}



std::vector<uint32_t> SM3::sm3_hash()
{
	std::vector<uint32_t> hash_result(32, 0);//（0，0，0，……，0）32个0，用来存放hash结果
	unsigned char buffer[4] = { 0x01,0x03,0x4a,0x95 };//要处理的明文
	unsigned char hash_output[32];//存放结果的中间变量
	SM3::SM3(buffer, 4, hash_output);//sm3的主函数，包括消息填充、扩展、压缩函数
	hash_result.assign(&hash_output[0], &hash_output[32]);//要返回一个vector变量所以把值赋到hash_result
	return hash_result;
}


int main() {
	std::cout << "                        SM3优化                   " << endl;
	std::vector<uint32_t> hash_result1;//创建一个空对象——SM3优化版本
	std::vector<uint32_t> hash_result2;//创建一个空对象——SM3未优化版本
	auto start1 = std::chrono::high_resolution_clock::now();//记录时间
	for (int i = 0; i < 100; i++)
	{
		hash_result1 = SM3::sm3_hash_optimize();
	}
	auto end1 = std::chrono::high_resolution_clock::now();
	cout << "=======================================================" << endl;
	std::cout << "优化之后平均每次运算所需的时间:";
	std::chrono::duration<double, std::ratio<1, 1000>> diff1 = (end1 - start1) / 100;
	std::cout << diff1.count() << " ms\n";
	cout << "=======================================================" << endl;
	auto start2 = std::chrono::high_resolution_clock::now();
	for (int i = 0; i < 100; i++)
	{
		hash_result2 = SM3::sm3_hash();
	}
	auto end2 = std::chrono::high_resolution_clock::now();
	std::cout << "未优化时平均每次运算所需的时间:";
	std::chrono::duration<double, std::ratio<1, 1000>> diff2 = (end2 - start2) / 100;
	std::cout << diff2.count() << " ms\n";
	cout << "=======================================================" << endl;
	double rate = diff2.count() / diff1.count();
	cout << "平均加速倍数为:" << rate << endl;
	cout << "=======================================================" << endl;

	return 0;
}