#pragma once

#include <iostream>
#include <String.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>

#include "Format.h"
namespace BlockCipherCode
{
	//filling method code 填充方式代码
	const int PKCS7 = 0;//all fill value of length less than 16B 全部填充少于16B的长度值
	const int ZERO = 1;//all fill 0 全部填充0
	const int ANSI923 = 2;//all fill 0 but the last one fill value of length less than 16B 全部填充0，但是最后一个填充的是少于16B的长度值
	const int ISO7816_4 = 3;//all fill 0 but the first one fill value 0x80 全部填充0，但是第一个填充的是0x80
	const int ISO10126 = 4;//all fill randon value but the last one fill value of length less than 16B 全部填充随机数，但是最后一个填充的是少于16B的长度值

	//encrypt mode code 加密模式代码
	const int ECB = 0;//no use iv 不使用iv
	const int CBC = 1;//use iv 使用iv
	const int OFB = 2;//use iv 使用iv
	const int CTR = 3;//use iv 使用iv
	const int CFB1 = 4;//use iv 使用iv
	const int CFB8 = 5;//use iv 使用iv
	const int CFB128 = 6;//use iv 使用iv
}

namespace UniqueKeyPublic
{
	//only for test	
	void ShowBlock(Bytes show);
	void ShowLine(Bytes show);
	Byte randomByte();

	//fill method 填充函数
	Bytes padding(Bytes data, int dataEnd, int fillingMethod);
	Bytes unpadding(Bytes data, int fillingMethod);

	Bytes squareXOR(Bytes a, Bytes b);
}

namespace AES
{
	class AESCiphers
	{
	private:
		int length;
		int mode;
		int fillingMethod;
		Bytes iv;
		Bytes OriginalKey;
		Bytes key;
	public:
		AESCiphers(int lenght, int mode, int fillingMethod, Bytes key);
		void setIV(Bytes iv);
		void changeIV();
		void setKey(Bytes key);
		void setFillingMethod(int fillingMethod);
		void setLength(int length);
		void setMode(int mode);
		Bytes getKey();
		Bytes encrypt(Bytes data, bool isWithIV);
		Bytes decrypt(Bytes dataIN, bool isWithIV);
		Bytes encrypt(Bytes data);
		Bytes decrypt(Bytes data);
	};
}
namespace SM4
{
	class SM4Ciphers
	{
	private:
		int mode;
		int fillingMethod;
		Bytes iv;
		Bytes OriginalKey;
		Bytes key;
	public:
		SM4Ciphers(int mode, int fillingMethod, Bytes key);
		void setIV(Bytes iv);
		void changeIV();
		void setKey(Bytes key);
		void setFillingMethod(int fillingMethod);
		void setMode(int mode);
		Bytes getKey();
		Bytes encrypt(Bytes data, bool isWithIV);
		Bytes decrypt(Bytes dataIN, bool isWithIV);
		Bytes encrypt(Bytes data);
		Bytes decrypt(Bytes dataIN);
	};
}