#include <iostream>
#include <sstream>
#include <iomanip>
#include "Format.h"
#include <fstream>
#include <random>
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
	void ShowBlock(Bytes show)
	{
		Ullong time = show.size() / 4;
		for (Ullong i0 = 0; i0 < show.size(); i0 += 64)
		{
			int sign = 1;
			for (int i1 = 0; i1 < 16; i1 += 4)
			{
				printf("%02d %02d %02d %02d |", i1, i1 + 1, i1 + 2, i1 + 3);
			}
			printf("\n");
			for (Ullong i2 = 0; i2 < 4; i2++)
			{
				int sign1 = 0;
				if (sign == 0)
				{
					break;
				}
				for (Ullong i3 = 0; i3 < (16 > time ? time : 16); i3++)
				{
					if (i0 + 4 * i3 + i2 >= show.size())
					{
						break;
					}
					printf("%02X ", (Byte)show.at(i0 + 4 * i3 + i2));
					sign1++;
					if (sign1 == 4)
					{
						printf("|");
						sign1 = 0;
					}
				}
				printf("\n");
			}
			if (sign == 0)
			{
				printf("\n");
				break;
			}
			printf("\n");
		}

	}
	void ShowLine(Bytes show)
	{
		for (Ullong i = 0; i < show.size(); i++)
		{
			printf("%02X", (Byte)show.at(i));
		}
		printf("\n");
	}
	Byte randomByte()
	{
		std::random_device rd;
		return (Byte)rd() % 128;
	}

	//fill method 填充函数
	Bytes padding(Bytes data, int dataEnd, int fillingMethod)
	{
		Bytes tempBlock(data);
		//末尾填充
		if (fillingMethod == 0)
		{
			Byte value = (Byte)(16 - dataEnd);
			for (int i = dataEnd; i < 16; i++)
			{
				tempBlock.push_back(value);
			}
		}
		else if (fillingMethod == 1)
		{
			for (Uint i = dataEnd; i < 16; i++)
			{
				tempBlock.push_back((Byte)0);
			}
		}
		else if (fillingMethod == 2)
		{
			for (Uint i = dataEnd; i < 15; i++)
			{
				tempBlock.push_back((Byte)0);
			}
			Byte value = (Byte)(16 - dataEnd);
			tempBlock.push_back(value);
		}
		else if (fillingMethod == 3)
		{
			tempBlock.push_back((Byte)(0x80));
			for (Uint i = dataEnd + 1; i < 16; i++)
			{
				tempBlock.push_back((Byte)(0));
			}
		}
		else if (fillingMethod == 4)
		{
			for (Uint i = dataEnd; i < 15; i++)
			{
				tempBlock.push_back(UniqueKeyPublic::randomByte());
			}
			Byte value = (Byte)(16 - dataEnd);
			tempBlock.push_back(value);
		}
		else
		{
			throw std::exception("wrong filling method");
		}
		return tempBlock;
	}
	Bytes unpadding(Bytes data, int fillingMethod)
	{
		Bytes res = data;
		if ((Uint)res.at(res.size() - 1) > 16 && (Uint)res.at(res.size() - 1) != 0x80)
		{
			throw std::exception("错误:错误的密文 密钥或解密方式\nError:Wrong ciphertext,passwords or method for decryption");
		}
		//末尾填充
		if (fillingMethod == 0 || fillingMethod == 2 || fillingMethod == 4)
		{
			Byte value = res.at(res.size() - 1);
			if ((Uint)value > 16)
			{
				return res;
			}
			for (Uint i = 0; i < value; i++)
			{
				res.pop_back();
			}
		}
		else if (fillingMethod == 1)
		{
			while (res.at(res.size() - 1) == 0)
			{
				res.pop_back();
			}
		}
		else if (fillingMethod == 3)
		{
			while (res.at(res.size() - 1) == 0)
			{
				res.pop_back();
			}
			res.pop_back();
		}
		else
		{
			throw std::exception("wrong filling method");
		}
		return res;
	}

	//加密块异或方法
	Bytes squareXOR(Bytes a, Bytes b)
	{
		Bytes res(16);
		Ullong n = a.size() < b.size() ? a.size() : b.size();
		for (Ullong i = 0; i < (n > 16 ? 16 : n); i++)
		{
			res.push_back(a.at(i) ^ b.at(i));
		}
		return res;
	}
}

namespace AES 
{

	//extend key 密钥扩展
	const Byte SBox[16][16] = {
		//0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
		{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},//0
		{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},//1
		{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},//2
		{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},//3
		{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},//4
		{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},//5
		{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},//6
		{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},//7
		{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},//8
		{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},//9
		{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},//A
		{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},//B
		{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},//C
		{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},//D
		{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},//E
		{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };//F
	const Byte InvSBox[16][16] = {
		//0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
		{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},//0
		{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},//1
		{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},//2
		{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},//3
		{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},//4
		{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},//5
		{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},//6
		{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},//7
		{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},//8
		{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},//9
		{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},//A
		{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},//B
		{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},//C
		{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},//D
		{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},//E
		{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} };//F

	const Byte round[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
	Bytes extendKey128(Bytes key)
	{
		Bytes res(176);
		try
		{
			if (key.size() < 16)
			{
				std::string s = std::string("Error:Invalid Key Size ") + std::to_string(key.size()) + std::string(" < 16\n错误:密钥长度过短 ") + std::to_string(key.size()) + std::string(" < 16");
				throw std::exception(&s[0]);
			}
			for (int i = 0; i < 16; i++)
			{
				res.push_back(key.at(i));
			}
			for (int i = 16; i < 176; i += 4)
			{
				if (i % 16 == 0)
				{
					//取当前列-1
					Byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
					//列位移
					Byte typeB = temp1[0];
					for (int i = 0; i < 3; i++)
					{
						temp1[i] = temp1[i + 1];
					}
					temp1[3] = typeB;
					//字节代还
					for (int i = 0; i < 4; i++)
					{
						temp1[i] = SBox[temp1[i] >> 4][temp1[i] & 0x0f];
					}
					//轮常量异或
					temp1[0] = temp1[0] ^ round[(i / 16) - 1];
					//取当前列-4并异或
					Byte temp2[4] = { res.at(i - 16), res.at(i - 15), res.at(i - 14), res.at(i - 13) };
					for (int i = 0; i < 4; i++)
					{
						res.push_back(temp1[i] ^ temp2[i]);
					}
				}
				else
				{
					//取当前列-1
					Byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
					//取当前列-4并异或
					Byte temp2[4] = { res.at(i - 16), res.at(i - 15), res.at(i - 14), res.at(i - 13) };
					for (int i = 0; i < 4; i++)
					{
						res.push_back(temp1[i] ^ temp2[i]);
					}
				}
			}
		}
		catch (const std::exception& e)
		{
			std::cout << e.what() << std::endl;
		}
		return res;
	}
	Bytes extendKey192(Bytes key)
	{
		Bytes res(208);
		try
		{
			if (key.size() < 24)
			{
				std::string s = std::string("Error:Invalid Key Size ") + std::to_string(key.size()) + std::string(" < 24\n错误:密钥长度过短 ") + std::to_string(key.size()) + std::string(" < 24");
				throw std::exception(&s[0]);
			}
			for (int i = 0; i < 24; i++)
			{
				res.push_back(key.at(i));
			}
			for (int i = 24; i < 208; i += 4)
			{
				if (i % 24 == 0)
				{
					//取当前列-1
					Byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
					//列位移
					Byte typeB = temp1[0];
					for (int i = 0; i < 3; i++)
					{
						temp1[i] = temp1[i + 1];
					}
					temp1[3] = typeB;
					//字节代还
					for (int i = 0; i < 4; i++)
					{
						temp1[i] = SBox[temp1[i] >> 4][temp1[i] & 0x0f];
					}
					//轮常量异或
					temp1[0] = temp1[0] ^ round[(i / 24) - 1];
					//取当前列-6并异或
					Byte temp2[4] = { res.at(i - 24), res.at(i - 23), res.at(i - 22), res.at(i - 21) };
					for (int i = 0; i < 4; i++)
					{
						res.push_back(temp1[i] ^ temp2[i]);
					}
				}
				else
				{
					//取当前列-1
					Byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
					//取当前列-6并异或
					Byte temp2[4] = { res.at(i - 24), res.at(i - 23), res.at(i - 22), res.at(i - 21) };
					for (int i = 0; i < 4; i++)
					{
						res.push_back(temp1[i] ^ temp2[i]);
					}
				}
			}
		}
		catch (const std::exception& e)
		{
			std::cout << e.what() << std::endl;
		}
		return res;
	}
	Bytes extendKey256(Bytes key)
	{
		Bytes res(240);
		try
		{
			if (key.size() < 32)
			{
				std::string s = std::string("Error:Invalid Key Size ") + std::to_string(key.size()) + std::string(" < 32\n错误:密钥长度过短 ") + std::to_string(key.size()) + std::string(" < 32");
				throw std::exception(&s[0]);
			}
			for (int i = 0; i < 32; i++)
			{
				res.push_back(key.at(i));
			}
			for (int i = 32; i < 240; i += 4)
			{
				if (i % 32 == 0)
				{
					//取当前列-1
					Byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
					//列位移
					Byte typeB = temp1[0];
					for (int i0 = 0; i0 < 3; i0++)
					{
						temp1[i0] = temp1[i0 + 1];
					}
					temp1[3] = typeB;
					//字节代还
					for (int i0 = 0; i0 < 4; i0++)
					{
						temp1[i0] = SBox[temp1[i0] >> 4][temp1[i0] & 0x0f];
					}
					//轮常量异或
					temp1[0] = temp1[0] ^ round[(i / 32) - 1];
					//取当前列-8并异或
					Byte temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
					for (int i0 = 0; i0 < 4; i0++)
					{
						res.push_back(temp1[i0] ^ temp2[i0]);
					}
				}
				else if (i % 16 == 0)
				{
					//取当前列-1
					Byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
					for (int i0 = 0; i0 < 4; i0++)
					{
						temp1[i0] = SBox[temp1[i0] >> 4][temp1[i0] & 0x0f];
					}
					//取当前列-8并异或
					Byte temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
					for (int i0 = 0; i0 < 4; i0++)
					{
						res.push_back(temp1[i0] ^ temp2[i0]);
					}
				}
				else
				{
					//取当前列-1
					Byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
					//取当前列-8并异或
					Byte temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
					for (int i0 = 0; i0 < 4; i0++)
					{
						res.push_back(temp1[i0] ^ temp2[i0]);
					}
				}
			}
		}
		catch (const std::exception& e)
		{
			std::cout << e.what() << std::endl;
		}
		return res;
	}
	Bytes extendKey(Bytes key, int mode)
	{
		if (mode == 128)
		{
			Ullong size = key.size();
			if (size < 16)
			{
				std::string s = std::string("Error:Invalid Key Size ") + std::to_string(size) + std::string(" < 16\n错误:密钥长度过短 ") + std::to_string(size) + std::string(" < 16");
				throw std::exception(&s[0]);
			}
			return extendKey128(key);
		}
		else if (mode == 192)
		{
			Ullong size = key.size();
			if (size < 24)
			{
				std::string s = std::string("Error:Invalid Key Size ") + std::to_string(size) + std::string(" < 24\n错误:密钥长度过短 ") + std::to_string(size) + std::string(" < 24");
				throw std::exception(&s[0]);
			}
			return extendKey192(key);
		}
		else if (mode == 256)
		{
			Ullong size = key.size();
			if (size < 32)
			{
				std::string s = std::string("Error:Invalid Key Size ") + std::to_string(size) + std::string(" < 32\n错误:密钥长度过短 ") + std::to_string(size) + std::string(" < 32");
				throw std::exception(&s[0]);
			}
			return extendKey256(key);
		}
		else
		{
			throw std::exception("wrong mode of ket size");
		}
	}

	//each block encrypt and using funcation 区块加密及内部算法
	Byte MixTable[16] = { 0x02,0x03,0x01,0x01, 0x01,0x02,0x03,0x01, 0x01,0x01,0x02,0x03, 0x03,0x01,0x01,0x02 };
	Byte UMixTable[16] = { 0x0E,0x0B,0x0D,0x09, 0x09,0x0E,0x0B,0x0D, 0x0D,0x09,0x0E,0x0B, 0x0B,0x0D,0x09,0x0E };
	//the value of a must be 0x01 0x02 0x03 a的值只能为0x01,0x02,0x03

//the value of a must be 0x01 0x02 0x03,0x09,0x0B,0x0D,0x0E a的值只能为0x01,0x02,0x03,0x09,0x0B,0x0D,0x0E
	Byte Xtime(Byte a, Byte b)
	{
		//1 2 4 8
		if (a == 0x01)
		{
			return b;
		}
		else if (a == 0x02)
		{
			if (b >> 7 == 0)
			{
				return b << 1;
			}
			else//  <==> else if (b >> 7 == 1)
			{
				return (b << 1) ^ 0x1b;
			}
		}
		else if (a == 0x04)
		{
			return Xtime(0x02, Xtime(0x02, b));
		}
		else if (a == 0x08)
		{
			return Xtime(0x02, Xtime(0x02, Xtime(0x02, b)));
		}
		else if (a == 0x03) //02+01
		{
			return Xtime(0x02, b) ^ b;
		}
		else if (a == 0x09) //08+01=09
		{
			return Xtime(0x08, b) ^ b;
		}
		else if (a == 0x0b) //08+02+01=13=0b
		{
			return Xtime(0x08, b) ^ Xtime(0x02, b) ^ b;
		}
		else if (a == 0x0d) //08+04+01
		{
			return Xtime(0x08, b) ^ Xtime(0x04, b) ^ b;
		}
		else if (a == 0x0e) //08+04+02=0e=14
		{
			return Xtime(0x08, b) ^ Xtime(0x04, b) ^ Xtime(0x02, b);
		}
		else
		{
			throw std::exception("wrong value of a");
		}
	}
	Bytes AESEncodingBlock(Bytes datablock, int flag, int mode)
	{
		Bytes res(16);
		//字节代换(00 04 08 12)
		for (int i = 0; i < 16; i++)
		{
			datablock.change(i, AES::SBox[datablock.at(i) >> 4][datablock.at(i) & 0x0f]);
		}

		/*printf("字节代换后数据\n");
		ShowBlock(datablock);*/

		//行位移
		//01 05 09 13 左移1位
		Byte b1, b2;
		b1 = datablock.at(1);
		datablock.change(1, datablock.at(5));
		datablock.change(5, datablock.at(9));
		datablock.change(9, datablock.at(13));
		datablock.change(13, b1);
		//02 06 10 14 左移2位
		b1 = datablock.at(2);
		b2 = datablock.at(6);
		datablock.change(2, datablock.at(10));
		datablock.change(6, datablock.at(14));
		datablock.change(10, b1);
		datablock.change(14, b2);
		//03 07 11 15 右移1位代替左移3位
		b1 = datablock.at(15);
		datablock.change(15, datablock.at(11));
		datablock.change(11, datablock.at(7));
		datablock.change(7, datablock.at(3));
		datablock.change(3, b1);

		/*printf("行移位后数据\n");
		ShowBlock(datablock);*/

		//列混合
		if ((mode == 128 && flag != 9) || (mode == 192 && flag != 11) || (mode == 256 && flag != 13))
		{
			for (int i0 = 0; i0 < 16; i0 += 4)
			{
				for (int i1 = 0; i1 < 16; i1 += 4)
				{
					Byte tempB = 0;
					for (int i2 = 0; i2 < 4; i2++)
					{
						tempB ^= Xtime(MixTable[i1 + i2], datablock.at(i0 + i2));
					}
					res.push_back(tempB);
				}
			}
		}
		else
		{
			for (int i0 = 0; i0 < 16; i0++)
			{
				res.push_back(datablock.at(i0));
			}
		}

		/*printf("列混合后数据\n");
		ShowBlock(res);*/


		return res;
	}
	Bytes AESDecodingBlock(Bytes datablock, int flag, int mode)
	{
		Bytes res(16);
		//列混合
		if (flag != 0)
		{
			for (int i0 = 0; i0 < 16; i0 += 4)
			{
				for (int i1 = 0; i1 < 16; i1 += 4)
				{
					Byte tempB = 0;
					for (int i2 = 0; i2 < 4; i2++)
					{
						tempB ^= Xtime(UMixTable[i1 + i2], datablock.at(i0 + i2));
					}
					res.push_back(tempB);
				}
			}
		}
		else
		{
			for (int i0 = 0; i0 < 16; i0++)
			{
				res.push_back(datablock.at(i0));
			}
		}

		/*printf("列混合后数据\n");
		ShowBlock(res);*/

		//行位移
		Byte b1, b2;
		//01 05 09 13 右移1位
		b1 = res.at(13);
		res.change(13, res.at(9));
		res.change(9, res.at(5));
		res.change(5, res.at(1));
		res.change(1, b1);
		//02 06 10 14 右移2位
		b1 = res.at(14);
		b2 = res.at(10);
		res.change(14, res.at(6));
		res.change(10, res.at(2));
		res.change(2, b2);
		res.change(6, b1);
		//03 07 11 15 左移1位代替右移3位
		b1 = res.at(3);
		res.change(3, res.at(7));
		res.change(7, res.at(11));
		res.change(11, res.at(15));
		res.change(15, b1);

		/*printf("行移位后数据\n");
		ShowBlock(res);*/

		//字节代换
		for (int i = 0; i < 16; i++)
		{
			res.change(i, AES::InvSBox[res.at(i) >> 4][res.at(i) & 0x0f]);
		}

		/*printf("字节代换后数据\n");
		ShowBlock(res);*/


		return res;
	}
	Bytes AESEncodingMachine(Bytes tempBlock, Bytes key, int mode)
	{
		Bytes tempKey = key.cut(0, 16);
		tempBlock = UniqueKeyPublic::squareXOR(tempBlock, tempKey);
		for (int i = 0; i < ((mode / 32) + 6); i++)
		{
			tempBlock = AES::AESEncodingBlock(tempBlock, i, mode);
			tempKey = key.cut(16 * (i + 1), 16 * (i + 2));
			tempBlock = UniqueKeyPublic::squareXOR(tempBlock, tempKey);
		}
		return tempBlock;
	}
	Bytes AESDecodingMachine(Bytes tempBlock, Bytes key, int mode)
	{
		tempBlock.inversionBIN();
		Bytes tempKey = key.cut((mode / 2) + 96, (mode / 2) + 112);
		tempBlock = UniqueKeyPublic::squareXOR(tempBlock, tempKey);
		for (int i = 0; i < ((mode / 32) + 6); i++)
		{
			tempBlock = AESDecodingBlock(tempBlock, i, mode);
			tempKey = key.cut(16 * ((mode / 32) + 5 - i), 16 * ((mode / 32) + 6 - i));//取当前轮密钥
			tempBlock = UniqueKeyPublic::squareXOR(tempBlock, tempKey);//轮密钥加
		}
		return tempBlock;
	}

	//128/16字节加密
	Bytes encrypt128ECB(Bytes data, Bytes key, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock = UniqueKeyPublic::padding(tempBlock, dataEnd, fillingMethod);
			}
			tempBlock = AESEncodingMachine(tempBlock, key, 128);
			res = res + tempBlock;
			tempBlock.clear();
		}
		return res;
	}
	Bytes decrypt128ECB(Bytes data, Bytes key, int fillingMethod)
	{
		Bytes res(data.size());
		Bytes tempBlock(16);
		data.inversionBIN();
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}
			tempBlock = AESDecodingMachine(tempBlock, key, 128);
			tempBlock.inversionBIN();
			res = res + tempBlock;
			tempBlock.clear();
		}
		res.inversionBIN();
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt128CBC(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock(16);
		Bytes tempKey(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock = UniqueKeyPublic::padding(tempBlock, dataEnd, fillingMethod);
			}
			//CBC模式iv异或
			tempKey = (i0 == 0 ? InitialVector : res.cut(i0 - 16, i0));
			tempBlock = UniqueKeyPublic::squareXOR(tempBlock, tempKey);

			tempBlock = AESEncodingMachine(tempBlock, key, 128);
			res = res + tempBlock;
			tempBlock.clear();
		}
		return res;
	}
	Bytes decrypt128CBC(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(data.size());
		Bytes tempBlock(16);
		Bytes tempKey(16);
		data.inversionBIN();
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			for (Uint i1 = 0; i1 < 16; i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}

			tempBlock = AESDecodingMachine(tempBlock, key, 128);
			//CBC模式iv异或
			tempKey = (i0 == data.size() - 16 ? InitialVector : data.cut(i0 + 16, i0 + 32).inversionBOUT());
			tempBlock = UniqueKeyPublic::squareXOR(tempBlock, tempKey);
			tempBlock.inversionBIN();
			res = res + tempBlock;
			tempBlock.clear();
		}
		res.inversionBIN();
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt128OFB(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			tempBlock0 = AESEncodingMachine(tempBlock0, key, 128);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock1 = UniqueKeyPublic::padding(tempBlock1, dataEnd, fillingMethod);
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock0, tempBlock1);
			tempBlock1.clear();
		}
		return res;
	}
	Bytes decrypt128OFB(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(data.size());
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			tempBlock0 = AESEncodingMachine(tempBlock0, key, 128);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock0, tempBlock1);
			tempBlock1.clear();
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt128CTR(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Ullong endNum = 0;
		for (Ullong i0 = 0; i0 < 8; i0++)
		{
			endNum += (Ullong)tempBlock0.at(i0 + 8) << (8 * (7 - i0));
		}
		Bytes tempBlock1(16);
		Bytes tempBlock2(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			tempBlock2 = AESEncodingMachine(tempBlock0, key, 128);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock1 = UniqueKeyPublic::padding(tempBlock1, dataEnd, fillingMethod);
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock2, tempBlock1);
			tempBlock1.clear();
			endNum++;
			for (int i1 = 0; i1 < 8; i1++)
			{
				tempBlock0.change(i1 + 8, (Byte)(endNum >> (8 * (7 - i1))));
			}
			tempBlock2 = tempBlock0;
		}
		return res;
	}
	Bytes decrypt128CTR(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Ullong endNum = 0;
		for (Ullong i0 = 0; i0 < 8; i0++)
		{
			endNum += (Ullong)tempBlock0.at(i0 + 8) << (8 * (7 - i0));
		}
		Bytes tempBlock1(16);
		Bytes tempBlock2(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			tempBlock2 = AESEncodingMachine(tempBlock0, key, 128);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock2, tempBlock1);
			tempBlock1.clear();
			endNum++;
			for (int i1 = 0; i1 < 8; i1++)
			{
				tempBlock0.change(i1 + 8, (Byte)(endNum >> (8 * (7 - i1))));
			}
			tempBlock2 = tempBlock0;
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt128CFB8(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			tempBlock1 = AESEncodingMachine(tempBlock0, key, 128);
			Byte b = data.at(i0) ^ tempBlock1.at(0);
			res.push_back(b);
			tempBlock0 = tempBlock0.cut(0, 15);
			tempBlock0.push_back(b);
		}
		return res;
	}
	Bytes decrypt128CFB8(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			tempBlock1 = AESEncodingMachine(tempBlock0, key, 128);
			Byte b = data.at(i0) ^ tempBlock1.at(0);
			res.push_back(b);
			tempBlock0 = tempBlock0.cut(0, 15);
			tempBlock0.push_back(data.at(i0));
		}
		return res;
	}

	Bytes encrypt128CFB1(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			Byte B = 0x00;
			for (int j = 0; j < 8; j++)
			{
				tempBlock1 = AESEncodingMachine(tempBlock0, key, 128);
				Byte b = (data.at(i0) >> (7 - j) & 0x01) ^ (tempBlock1.at(0) >> (7 - j) & 0x01);
				B += b << (7 - j);
				Byte c = b, d = 0x00;
				for (int i1 = 0; i1 < 16; i1++)
				{
					d = tempBlock0.at(15 - i1) >> 7;
					tempBlock0.change((15 - i1), (tempBlock0.at(15 - i1) << 1) + c);
					c = d;
				}
			}
			res.push_back(B);
		}
		return res;
	}
	Bytes decrypt128CFB1(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			Byte B = 0x00;
			for (int j = 0; j < 8; j++)
			{
				tempBlock1 = AESEncodingMachine(tempBlock0, key, 128);
				Byte b = (data.at(i0) >> (7 - j) & 0x01) ^ (tempBlock1.at(0) >> (7 - j) & 0x01);
				B += b << (7 - j);
				Byte c = data.at(i0) >> (7 - j) & 0x01, d = 0x00;
				for (int i1 = 0; i1 < 16; i1++)
				{
					d = tempBlock0.at(15 - i1) >> 7;
					tempBlock0.change((15 - i1), (tempBlock0.at(15 - i1) << 1) + c);
					c = d;
				}
			}
			res.push_back(B);
		}
		return res;
	}

	Bytes encrypt128CFB128(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			tempBlock1 = AESEncodingMachine(tempBlock0, key, 128);
			tempBlock0.clear();
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock0.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock0 = UniqueKeyPublic::padding(tempBlock0, dataEnd, fillingMethod);
			}
			tempBlock0 = UniqueKeyPublic::squareXOR(tempBlock1, tempBlock0);
			res = res + tempBlock0;
		}
		return res;
	}
	Bytes decrypt128CFB128(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			tempBlock1 = AESEncodingMachine(tempBlock0, key, 128);
			res = res + UniqueKeyPublic::squareXOR(tempBlock1, data.cut(i0, i0 + 16));
			tempBlock0 = data.cut(i0, i0 + 16);
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	//192/24字节加密
	Bytes encrypt192ECB(Bytes data, Bytes key, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock = UniqueKeyPublic::padding(tempBlock, dataEnd, fillingMethod);
			}

			tempBlock = AESEncodingMachine(tempBlock, key, 192);
			res = res + tempBlock;
			tempBlock.clear();
		}
		return res;
	}
	Bytes decrypt192ECB(Bytes data, Bytes key, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock(16);
		Bytes tempKey(16);
		data.inversionBIN();
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}

			tempBlock = AESDecodingMachine(tempBlock, key, 192);
			tempBlock.inversionBIN();
			res = res + tempBlock;
			tempBlock.clear();
			tempKey.clear();
		}
		res.inversionBIN();
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt192CBC(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock(16);
		Bytes tempKey(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock = UniqueKeyPublic::padding(tempBlock, dataEnd, fillingMethod);
			}
			//CBC模式iv异或
			tempKey = (i0 == 0 ? InitialVector : res.cut(i0 - 16, i0));
			tempBlock = UniqueKeyPublic::squareXOR(tempBlock, tempKey);

			tempBlock = AESEncodingMachine(tempBlock, key, 192);
			res = res + tempBlock;
			tempBlock.clear();
		}
		return res;
	}
	Bytes decrypt192CBC(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock(16);
		Bytes tempKey(16);
		data.inversionBIN();
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}
			tempBlock = AESDecodingMachine(tempBlock, key, 192);
			//CBC模式iv异或
			tempKey = (i0 == data.size() - 16 ? InitialVector : data.cut(i0 + 16, i0 + 32).inversionBOUT());
			tempBlock = UniqueKeyPublic::squareXOR(tempBlock, tempKey);
			tempBlock.inversionBIN();
			res = res + tempBlock;
			tempBlock.clear();
			tempKey.clear();
		}
		res.inversionBIN();
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt192OFB(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempKey(16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			tempBlock0 = AESEncodingMachine(tempBlock0, key, 192);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock1 = UniqueKeyPublic::padding(tempBlock1, dataEnd, fillingMethod);
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock0, tempBlock1);
			tempBlock1.clear();
		}
		return res;
	}
	Bytes decrypt192OFB(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempKey(16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			tempBlock0 = AESEncodingMachine(tempBlock0, key, 192);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock0, tempBlock1);
			tempBlock1.clear();
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt192CTR(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Ullong endNum = 0;
		for (Ullong i0 = 0; i0 < 8; i0++)
		{
			endNum += (Ullong)tempBlock0.at(i0 + 8) << (8 * (7 - i0));
		}
		Bytes tempBlock1(16);
		Bytes tempBlock2(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			tempBlock2 = AESEncodingMachine(tempBlock0, key, 192);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock1 = UniqueKeyPublic::padding(tempBlock1, dataEnd, fillingMethod);
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock2, tempBlock1);
			tempBlock1.clear();
			endNum++;
			for (int i1 = 0; i1 < 8; i1++)
			{
				tempBlock0.change(i1 + 8, (Byte)(endNum >> (8 * (7 - i1))));
			}
			tempBlock2 = tempBlock0;
		}
		return res;
	}
	Bytes decrypt192CTR(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Ullong endNum = 0;
		for (Ullong i0 = 0; i0 < 8; i0++)
		{
			endNum += (Ullong)tempBlock0.at(i0 + 8) << (8 * (7 - i0));
		}
		Bytes tempBlock1(16);
		Bytes tempBlock2(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			tempBlock2 = AESEncodingMachine(tempBlock0, key, 192);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock2, tempBlock1);
			tempBlock1.clear();
			endNum++;
			for (int i1 = 0; i1 < 8; i1++)
			{
				tempBlock0.change(i1 + 8, (Byte)(endNum >> (8 * (7 - i1))));
			}
			tempBlock2 = tempBlock0;
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt192CFB8(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			tempBlock1 = AESEncodingMachine(tempBlock0, key, 192);
			Byte b = data.at(i0) ^ tempBlock1.at(0);
			res.push_back(b);
			tempBlock0 = tempBlock0.cut(0, 15);
			tempBlock0.push_back(b);
		}
		return res;
	}
	Bytes decrypt192CFB8(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			tempBlock1 = AESEncodingMachine(tempBlock0, key, 192);
			Byte b = data.at(i0) ^ tempBlock1.at(0);
			res.push_back(b);
			tempBlock0 = tempBlock0.cut(0, 15);
			tempBlock0.push_back(data.at(i0));
		}
		return res;
	}

	Bytes encrypt192CFB1(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			Byte B = 0x00;
			for (int j = 0; j < 8; j++)
			{
				tempBlock1 = AESEncodingMachine(tempBlock0, key, 192);
				Byte b = (data.at(i0) >> (7 - j) & 0x01) ^ (tempBlock1.at(0) >> (7 - j) & 0x01);
				B += b << (7 - j);
				Byte c = b, d = 0x00;
				for (int i1 = 0; i1 < 16; i1++)
				{
					d = tempBlock0.at(15 - i1) >> 7;
					tempBlock0.change((15 - i1), (tempBlock0.at(15 - i1) << 1) + c);
					c = d;
				}
			}
			res.push_back(B);
		}
		return res;
	}
	Bytes decrypt192CFB1(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			Byte B = 0x00;
			for (int j = 0; j < 8; j++)
			{
				tempBlock1 = AESEncodingMachine(tempBlock0, key, 192);
				Byte b = (data.at(i0) >> (7 - j) & 0x01) ^ (tempBlock1.at(0) >> (7 - j) & 0x01);
				B += b << (7 - j);
				Byte c = data.at(i0) >> (7 - j) & 0x01, d = 0x00;
				for (int i1 = 0; i1 < 16; i1++)
				{
					d = tempBlock0.at(15 - i1) >> 7;
					tempBlock0.change((15 - i1), (tempBlock0.at(15 - i1) << 1) + c);
					c = d;
				}
			}
			res.push_back(B);
		}
		return res;
	}

	Bytes encrypt192CFB128(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			tempBlock1 = AESEncodingMachine(tempBlock0, key, 192);
			tempBlock0.clear();
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock0.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock0 = UniqueKeyPublic::padding(tempBlock0, dataEnd, fillingMethod);
			}
			tempBlock0 = UniqueKeyPublic::squareXOR(tempBlock1, tempBlock0);
			res = res + tempBlock0;
		}
		return res;
	}
	Bytes decrypt192CFB128(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			tempBlock1 = AESEncodingMachine(tempBlock0, key, 192);
			res = res + UniqueKeyPublic::squareXOR(tempBlock1, data.cut(i0, i0 + 16));
			tempBlock0 = data.cut(i0, i0 + 16);
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	//256/32字节加密
	Bytes encrypt256ECB(Bytes data, Bytes key, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock(16);
		Bytes tempKey(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock = UniqueKeyPublic::padding(tempBlock, dataEnd, fillingMethod);
			}

			tempBlock = AESEncodingMachine(tempBlock, key, 256);
			res = res + tempBlock;
			tempBlock.clear();
		}
		return res;
	}
	Bytes decrypt256ECB(Bytes data, Bytes key, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock(16);
		Bytes tempKey(16);
		data.inversionBIN();
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}

			tempBlock = AESDecodingMachine(tempBlock, key, 256);
			tempBlock.inversionBIN();
			res = res + tempBlock;
			tempBlock.clear();
			tempKey.clear();
		}
		res.inversionBIN();
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt256CBC(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock(16);
		Bytes tempKey(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock = UniqueKeyPublic::padding(tempBlock, dataEnd, fillingMethod);
			}
			//CBC模式iv异或
			tempKey = (i0 == 0 ? InitialVector : res.cut(i0 - 16, i0));
			tempBlock = UniqueKeyPublic::squareXOR(tempBlock, tempKey);

			tempBlock = AESEncodingMachine(tempBlock, key, 256);
			res = res + tempBlock;
			tempBlock.clear();
		}
		return res;
	}
	Bytes decrypt256CBC(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock(16);
		Bytes tempKey(16);
		data.inversionBIN();
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}
			tempBlock = AESDecodingMachine(tempBlock, key, 256);
			//CBC模式iv异或
			tempKey = (i0 == data.size() - 16 ? InitialVector : data.cut(i0 + 16, i0 + 32).inversionBOUT());
			tempBlock = UniqueKeyPublic::squareXOR(tempBlock, tempKey);

			tempBlock.inversionBIN();
			res = res + tempBlock;
			tempBlock.clear();
			tempKey.clear();
		}
		res.inversionBIN();
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt256OFB(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempKey(16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			tempBlock0 = AESEncodingMachine(tempBlock0, key, 256);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock1 = UniqueKeyPublic::padding(tempBlock1, dataEnd, fillingMethod);
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock0, tempBlock1);
			tempBlock1.clear();
		}
		return res;
	}
	Bytes decrypt256OFB(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempKey(16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			tempBlock0 = AESEncodingMachine(tempBlock0, key, 256);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock0, tempBlock1);
			tempBlock1.clear();
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt256CTR(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Ullong endNum = 0;
		for (Ullong i0 = 0; i0 < 8; i0++)
		{
			endNum += (Ullong)tempBlock0.at(i0 + 8) << (8 * (7 - i0));
		}
		Bytes tempBlock1(16);
		Bytes tempBlock2(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			tempBlock2 = AESEncodingMachine(tempBlock0, key, 256);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock1 = UniqueKeyPublic::padding(tempBlock1, dataEnd, fillingMethod);
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock2, tempBlock1);
			tempBlock1.clear();
			endNum++;
			for (int i1 = 0; i1 < 8; i1++)
			{
				tempBlock0.change(i1 + 8, (Byte)(endNum >> (8 * (7 - i1))));
			}
			tempBlock2 = tempBlock0;
		}
		return res;
	}
	Bytes decrypt256CTR(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Ullong endNum = 0;
		for (Ullong i0 = 0; i0 < 8; i0++)
		{
			endNum += (Ullong)tempBlock0.at(i0 + 8) << (8 * (7 - i0));
		}
		Bytes tempBlock1(16);
		Bytes tempBlock2(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			tempBlock2 = AESEncodingMachine(tempBlock0, key, 256);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock2, tempBlock1);
			tempBlock1.clear();
			endNum++;
			for (int i1 = 0; i1 < 8; i1++)
			{
				tempBlock0.change(i1 + 8, (Byte)(endNum >> (8 * (7 - i1))));
			}
			tempBlock2 = tempBlock0;
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt256CFB8(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			tempBlock1 = AESEncodingMachine(tempBlock0, key, 256);
			Byte b = data.at(i0) ^ tempBlock1.at(0);
			res.push_back(b);
			tempBlock0 = tempBlock0.cut(0, 15);
			tempBlock0.push_back(b);
		}
		return res;
	}
	Bytes decrypt256CFB8(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			tempBlock1 = AESEncodingMachine(tempBlock0, key, 256);
			Byte b = data.at(i0) ^ tempBlock1.at(0);
			res.push_back(b);
			tempBlock0 = tempBlock0.cut(0, 15);
			tempBlock0.push_back(data.at(i0));
		}
		return res;
	}

	Bytes encrypt256CFB1(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			Byte B = 0x00;
			for (int j = 0; j < 8; j++)
			{
				tempBlock1 = AESEncodingMachine(tempBlock0, key, 256);
				Byte b = (data.at(i0) >> (7 - j) & 0x01) ^ (tempBlock1.at(0) >> (7 - j) & 0x01);
				B += b << (7 - j);
				Byte c = b, d = 0x00;
				for (int i1 = 0; i1 < 16; i1++)
				{
					d = tempBlock0.at(15 - i1) >> 7;
					tempBlock0.change((15 - i1), (tempBlock0.at(15 - i1) << 1) + c);
					c = d;
				}
			}
			res.push_back(B);
		}
		return res;
	}
	Bytes decrypt256CFB1(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			Byte B = 0x00;
			for (int j = 0; j < 8; j++)
			{
				tempBlock1 = AESEncodingMachine(tempBlock0, key, 256);
				Byte b = (data.at(i0) >> (7 - j) & 0x01) ^ (tempBlock1.at(0) >> (7 - j) & 0x01);
				B += b << (7 - j);
				Byte c = data.at(i0) >> (7 - j) & 0x01, d = 0x00;
				for (int i1 = 0; i1 < 16; i1++)
				{
					d = tempBlock0.at(15 - i1) >> 7;
					tempBlock0.change((15 - i1), (tempBlock0.at(15 - i1) << 1) + c);
					c = d;
				}
			}
			res.push_back(B);
		}
		return res;
	}

	Bytes encrypt256CFB128(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			tempBlock1 = AESEncodingMachine(tempBlock0, key, 256);
			tempBlock0.clear();
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock0.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock0 = UniqueKeyPublic::padding(tempBlock0, dataEnd, fillingMethod);
			}
			tempBlock0 = UniqueKeyPublic::squareXOR(tempBlock1, tempBlock0);
			res = res + tempBlock0;
		}
		return res;
	}
	Bytes decrypt256CFB128(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			tempBlock1 = AESEncodingMachine(tempBlock0, key, 256);
			res = res + UniqueKeyPublic::squareXOR(tempBlock1, data.cut(i0, i0 + 16));
			tempBlock0 = data.cut(i0, i0 + 16);
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

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
AES::AESCiphers::AESCiphers(int lenght, int mode, int fillingMethod, Bytes key)
{
	this->length = lenght;
	this->mode = mode;
	this->fillingMethod = fillingMethod;
	for (int i = 0; i < 16; i++)
	{
		this->iv.push_back(UniqueKeyPublic::randomByte());
	}
	this->OriginalKey = key;
	this->key = extendKey(key, lenght);
}
void AES::AESCiphers::setIV(Bytes iv)
{
	this->iv = iv;
}
void AES::AESCiphers::changeIV()
{
	this->iv.clear();
	for (int i = 0; i < 16; i++)
	{
		this->iv.push_back(UniqueKeyPublic::randomByte());
	}
}
void AES::AESCiphers::setKey(Bytes key)
{
	this->key = extendKey(key, length);
}
void AES::AESCiphers::setFillingMethod(int fillingMethod)
{
	this->fillingMethod = fillingMethod;
}
void AES::AESCiphers::setLength(int length)
{
	this->key = extendKey(this->OriginalKey, length);
	this->length = length;
}
void AES::AESCiphers::setMode(int mode)
{
	this->mode = mode;
}
Bytes AES::AESCiphers::getKey()
{
	return this->OriginalKey;
}
Bytes AES::AESCiphers::encrypt(Bytes data, bool isWithIV)
{
	Bytes res;
	if (length == 128)
	{
		if (mode == BlockCipherCode::ECB)
		{
			res = encrypt128ECB(data, this->key, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CBC)
		{
			res = encrypt128CBC(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::OFB)
		{
			res = encrypt128OFB(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CTR)
		{
			res = encrypt128CTR(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CFB1)
		{
			res = encrypt128CFB1(data, this->key, this->iv);
		}
		else if (mode == BlockCipherCode::CFB8)
		{
			res = encrypt128CFB8(data, this->key, this->iv);
		}
		else if (mode == BlockCipherCode::CFB128)
		{
			res = encrypt128CFB128(data, this->key, this->iv, this->fillingMethod);
		}
	}
	else if (length == 192)
	{
		if (mode == BlockCipherCode::ECB)
		{
			res = encrypt192ECB(data, this->key, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CBC)
		{
			res = encrypt192CBC(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::OFB)
		{
			res = encrypt192OFB(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CTR)
		{
			res = encrypt192CTR(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CFB1)
		{
			res = encrypt192CFB1(data, this->key, this->iv);
		}
		else if (mode == BlockCipherCode::CFB8)
		{
			res = encrypt192CFB8(data, this->key, this->iv);
		}
		else if (mode == BlockCipherCode::CFB128)
		{
			res = encrypt192CFB128(data, this->key, this->iv, this->fillingMethod);
		}
	}
	else if (length == 256)
	{
		if (mode == BlockCipherCode::ECB)
		{
			res = encrypt256ECB(data, this->key, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CBC)
		{
			res = encrypt256CBC(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::OFB)
		{
			res = encrypt256OFB(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CTR)
		{
			res = encrypt256CTR(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CFB1)
		{
			res = encrypt256CFB1(data, this->key, this->iv);
		}
		else if (mode == BlockCipherCode::CFB8)
		{
			res = encrypt256CFB8(data, this->key, this->iv);
		}
		else if (mode == BlockCipherCode::CFB128)
		{
			res = encrypt256CFB128(data, this->key, this->iv, this->fillingMethod);
		}
	}
	if (isWithIV)
	{
		return this->iv + res;
	}
	else
	{
		return res;
	}
}
Bytes AES::AESCiphers::decrypt(Bytes dataIN, bool isWithIV)
{
	Bytes res;
	Bytes data = dataIN;
	if (isWithIV)
	{
		this->iv = dataIN.cut(0, 16);
		data.erase(0, 16);
	}
	if (length == 128)
	{
		if (mode == BlockCipherCode::ECB)
		{
			res = decrypt128ECB(data, this->key, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CBC)
		{
			res = decrypt128CBC(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::OFB)
		{
			res = decrypt128OFB(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CTR)
		{
			res = decrypt128CTR(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CFB1)
		{
			res = decrypt128CFB1(data, this->key, this->iv);
		}
		else if (mode == BlockCipherCode::CFB8)
		{
			res = decrypt128CFB8(data, this->key, this->iv);
		}
		else if (mode == BlockCipherCode::CFB128)
		{
			res = decrypt128CFB128(data, this->key, this->iv, this->fillingMethod);
		}
	}
	else if (length == 192)
	{
		if (mode == BlockCipherCode::ECB)
		{
			res = decrypt192ECB(data, this->key, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CBC)
		{
			res = decrypt192CBC(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::OFB)
		{
			res = decrypt192OFB(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CTR)
		{
			res = decrypt192CTR(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CFB1)
		{
			res = decrypt192CFB1(data, this->key, this->iv);
		}
		else if (mode == BlockCipherCode::CFB8)
		{
			res = decrypt192CFB8(data, this->key, this->iv);
		}
		else if (mode == BlockCipherCode::CFB128)
		{
			res = decrypt192CFB128(data, this->key, this->iv, this->fillingMethod);
		}
	}
	else if (length == 256)
	{
		if (mode == BlockCipherCode::ECB)
		{
			res = decrypt256ECB(data, this->key, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CBC)
		{
			res = decrypt256CBC(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::OFB)
		{
			res = decrypt256OFB(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CTR)
		{
			res = decrypt256CTR(data, this->key, this->iv, this->fillingMethod);
		}
		else if (mode == BlockCipherCode::CFB1)
		{
			res = decrypt256CFB1(data, this->key, this->iv);
		}
		else if (mode == BlockCipherCode::CFB8)
		{
			res = decrypt256CFB8(data, this->key, this->iv);
		}
		else if (mode == BlockCipherCode::CFB128)
		{
			res = decrypt256CFB128(data, this->key, this->iv, this->fillingMethod);
		}
	}
	return res;
}
Bytes AES::AESCiphers::encrypt(Bytes data)
{
	return encrypt(data, true);
}
Bytes AES::AESCiphers::decrypt(Bytes data)
{
	return decrypt(data, true);
}



namespace SM4
{
	const Byte SBox[16][16] = {
		//0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
		{0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},//0
		{0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},//1
		{0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},//2
		{0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},//3
		{0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},//4
		{0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},//5
		{0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},//6
		{0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},//7
		{0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},//8
		{0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},//9
		{0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},//A
		{0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},//B
		{0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},//C
		{0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},//D
		{0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},//E
		{0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48} };//F
	    //2024.10.10把F6的4d错打成了4b导致结果错误一直没发现，调试了10h。第二天才解决
	const Uint FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
	const Uint CK[32] = { 0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
						  0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
						  0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
						  0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279 };

	//循环左移
	Uint cLm(Uint i, int n)
	{
		int temp = n % 32;
		return  (i >> (32 - temp)) | (i << temp);
	}

	Uint TMixChange1(Uint n)
	{
		Uint res = 0;
		for (int i = 0; i < 4; i++)
		{
			Byte bs = (n >> (24 - i * 8)) & 0xff;
			bs = SBox[bs >> 4][(bs & 0x0f)];
			res += (Uint)bs << (24 - i * 8);
		}
		return res ^ cLm(res, 13) ^ cLm(res, 23);
	}
	Uint TMixChange2(Uint n)
	{
		Uint res = 0;
		for (int i = 0; i < 4; i++)
		{
			Byte bs = (n >> (24 - i * 8)) & 0xff;
			bs = SBox[bs >> 4][(bs & 0x0f)];
			res += (Uint)bs << (24 - i * 8);
		}
		Uint e = res ^ cLm(res, 2) ^ cLm(res, 10) ^ cLm(res, 18) ^ cLm(res, 24);
		return e;
	}

	Bytes extendKey128(Bytes key)
	{
		Bytes res(128);
		Uint K[36];
		for (Ullong i = 0; i < 16; i += 4)
		{
			K[i / 4] = (Uint)key.at(i) << 24 | (Uint)key.at(i + 1) << 16 | (Uint)key.at(i + 2) << 8 | (Uint)key.at(i + 3);
			K[i / 4] ^= FK[i / 4];
		}
		for (Ullong i = 4; i < 36; i++)
		{
			K[i] = K[i - 4] ^ TMixChange1(K[i - 3] ^ K[i - 2] ^ K[i - 1] ^ CK[i - 4]);
			for (int i0 = 0; i0 < 4; i0++)
			{
				res.push_back((Byte)(K[i] >> (24 - i0 * 8) & 0xff));
			}
		}
		return res;
	}

	Bytes SM4EncodingMachine(Bytes tempBlock, Bytes key)
	{
		Uint temp[4] = { 0,0,0,0 };
		for (int i = 0; i < 16; i += 4)
		{
			for (int i0 = 0; i0 < 4; i0++)
			{
				temp[i / 4] += (Uint)tempBlock.at(i + i0) << (24 - i0 * 8);
			}
		}
		for (int i = 0; i < 128; i += 4)
		{
			Uint tempRK = 0;
			for (int j = 0; j < 4; j++)
			{
				tempRK += (Uint)key.at(i + j) << (24 - j * 8);//
			}
			int n0 = (i / 4) % 4;
			int n1 = n0 + 1 < 4 ? n0 + 1 : n0 - 3;
			int n2 = n0 + 2 < 4 ? n0 + 2 : n0 - 2;
			int n3 = n0 + 3 < 4 ? n0 + 3 : n0 - 1;
			temp[n0] = temp[n0] ^ TMixChange2(temp[n1] ^ temp[n2] ^ temp[n3] ^ tempRK);
		}
		Bytes res(16);
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				res.push_back((Byte)(temp[3 - i] >> (24 - j * 8) & 0xff));
			}
		}
		return res;
	}
	Bytes SM4DecodingMachine(Bytes tempBlock, Bytes key)
	{
		Uint temp[36] = { 0,0,0,0 };
		for (int i = 0; i < 16; i += 4)
		{
			for (int i0 = 0; i0 < 4; i0++)
			{
				temp[i / 4] += (Uint)tempBlock.at(i + i0) << (24 - i0 * 8);
			}
		}
		for (int i = 0; i < 128; i += 4)
		{
			Uint tempRK = 0;
			for (int j = 0; j < 4; j++)
			{
				tempRK += (Uint)key.at(124 - i + j) << (24 - j * 8);
			}
			int n0 = (i / 4) % 4;
			int n1 = n0 + 1 < 4 ? n0 + 1 : n0 - 3;
			int n2 = n0 + 2 < 4 ? n0 + 2 : n0 - 2;
			int n3 = n0 + 3 < 4 ? n0 + 3 : n0 - 1;
			temp[n0] = temp[n0] ^ TMixChange2(temp[n1] ^ temp[n2] ^ temp[n3] ^ tempRK);
		}
		Bytes res(16);
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				res.push_back((Byte)(temp[3 - i] >> (24 - j * 8) & 0xff));
			}
		}
		return res;
	}

	//128/16字节加密
	Bytes encrypt128ECB(Bytes data, Bytes key, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock = UniqueKeyPublic::padding(tempBlock, dataEnd, fillingMethod);
			}
			tempBlock = SM4EncodingMachine(tempBlock, key);
			res = res + tempBlock;
			tempBlock.clear();
		}
		return res;
	}
	Bytes decrypt128ECB(Bytes data, Bytes key, int fillingMethod)
	{
		Bytes res(data.size());
		Bytes tempBlock(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}
			tempBlock = SM4DecodingMachine(tempBlock, key);
			res = res + tempBlock;
			tempBlock.clear();
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt128CBC(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock1 = UniqueKeyPublic::padding(tempBlock1, dataEnd, fillingMethod);
			}
			tempBlock0 = UniqueKeyPublic::squareXOR(tempBlock0, tempBlock1);
			tempBlock0 = SM4EncodingMachine(tempBlock0, key);
			res = res + tempBlock0;
			tempBlock1.clear();
		}
		return res;
	}
	Bytes decrypt128CBC(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(data.size());
		Bytes tempBlock(16);
		Bytes tempKey = InitialVector;
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			for (Uint i1 = 0; i1 < 16; i1++)
			{
				tempBlock.push_back(data.at(i0 + i1));
			}
			res = res + UniqueKeyPublic::squareXOR(tempKey, SM4DecodingMachine(tempBlock, key));
			tempKey = tempBlock;
			tempBlock.clear();
		}
		UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt128OFB(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			tempBlock0 = SM4EncodingMachine(tempBlock0, key);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock1 = UniqueKeyPublic::padding(tempBlock1, dataEnd, fillingMethod);
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock0, tempBlock1);
			tempBlock1.clear();
		}
		return res;
	}
	Bytes decrypt128OFB(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(data.size());
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			tempBlock0 = SM4EncodingMachine(tempBlock0, key);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock0, tempBlock1);
			tempBlock1.clear();
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt128CTR(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Ullong endNum = 0;
		for (Ullong i0 = 0; i0 < 8; i0++)
		{
			endNum += (Ullong)tempBlock0.at(i0 + 8) << (8 * (7 - i0));
		}
		Bytes tempBlock1(16);
		Bytes tempBlock2(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			tempBlock2 = SM4EncodingMachine(tempBlock0, key);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock1 = UniqueKeyPublic::padding(tempBlock1, dataEnd, fillingMethod);
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock2, tempBlock1);
			tempBlock1.clear();
			endNum++;
			for (int i1 = 0; i1 < 8; i1++)
			{
				tempBlock0.change(i1 + 8, (Byte)(endNum >> (8 * (7 - i1))));
			}
			tempBlock2 = tempBlock0;
		}
		return res;
	}
	Bytes decrypt128CTR(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Ullong endNum = 0;
		for (Ullong i0 = 0; i0 < 8; i0++)
		{
			endNum += (Ullong)tempBlock0.at(i0 + 8) << (8 * (7 - i0));
		}
		Bytes tempBlock1(16);
		Bytes tempBlock2(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			tempBlock2 = SM4EncodingMachine(tempBlock0, key);
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < 16; i1++)
			{
				tempBlock1.push_back(data.at(i0 + i1));
			}
			res = res + UniqueKeyPublic::squareXOR(tempBlock2, tempBlock1);
			tempBlock1.clear();
			endNum++;
			for (int i1 = 0; i1 < 8; i1++)
			{
				tempBlock0.change(i1 + 8, (Byte)(endNum >> (8 * (7 - i1))));
			}
			tempBlock2 = tempBlock0;
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

	Bytes encrypt128CFB8(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			tempBlock1 = SM4EncodingMachine(tempBlock0, key);
			Byte b = data.at(i0) ^ tempBlock1.at(0);
			res.push_back(b);
			tempBlock0 = tempBlock0.cut(0, 15);
			tempBlock0.push_back(b);
		}
		return res;
	}
	Bytes decrypt128CFB8(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			tempBlock1 = SM4EncodingMachine(tempBlock0, key);
			Byte b = data.at(i0) ^ tempBlock1.at(0);
			res.push_back(b);
			tempBlock0 = tempBlock0.cut(0, 15);
			tempBlock0.push_back(data.at(i0));
		}
		return res;
	}

	Bytes encrypt128CFB1(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			Byte B = 0x00;
			for (int j = 0; j < 8; j++)
			{
				tempBlock1 = SM4EncodingMachine(tempBlock0, key);
				Byte b = (data.at(i0) >> (7 - j) & 0x01) ^ (tempBlock1.at(0) >> (7 - j) & 0x01);
				B += b << (7 - j);
				Byte c = b, d = 0x00;
				for (int i1 = 0; i1 < 16; i1++)
				{
					d = tempBlock0.at(15 - i1) >> 7;
					tempBlock0.change((15 - i1), (tempBlock0.at(15 - i1) << 1) + c);
					c = d;
				}
			}
			res.push_back(B);
		}
		return res;
	}
	Bytes decrypt128CFB1(Bytes data, Bytes key, Bytes InitialVector)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0++)
		{
			Byte B = 0x00;
			for (int j = 0; j < 8; j++)
			{
				tempBlock1 = SM4EncodingMachine(tempBlock0, key);
				Byte b = (data.at(i0) >> (7 - j) & 0x01) ^ (tempBlock1.at(0) >> (7 - j) & 0x01);
				B += b << (7 - j);
				Byte c = data.at(i0) >> (7 - j) & 0x01, d = 0x00;
				for (int i1 = 0; i1 < 16; i1++)
				{
					d = tempBlock0.at(15 - i1) >> 7;
					tempBlock0.change((15 - i1), (tempBlock0.at(15 - i1) << 1) + c);
					c = d;
				}
			}
			res.push_back(B);
		}
		return res;
	}

	Bytes encrypt128CFB128(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 <= data.size(); i0 += 16)
		{
			tempBlock1 = SM4EncodingMachine(tempBlock0, key);
			tempBlock0.clear();
			Ullong dataEnd = data.size() - i0;
			for (int i1 = 0; i1 < (dataEnd >= 16 ? 16 : dataEnd); i1++)
			{
				tempBlock0.push_back(data.at(i0 + i1));
			}
			if (dataEnd <= 16)
			{
				tempBlock0 = UniqueKeyPublic::padding(tempBlock0, dataEnd, fillingMethod);
			}
			tempBlock0 = UniqueKeyPublic::squareXOR(tempBlock1, tempBlock0);
			res = res + tempBlock0;
		}
		return res;
	}
	Bytes decrypt128CFB128(Bytes data, Bytes key, Bytes InitialVector, int fillingMethod)
	{
		Bytes res(((data.size() / 16) + 1) * 16);
		Bytes tempBlock0 = InitialVector;
		Bytes tempBlock1(16);
		for (Ullong i0 = 0; i0 < data.size(); i0 += 16)
		{
			tempBlock1 = SM4EncodingMachine(tempBlock0, key);
			res = res + UniqueKeyPublic::squareXOR(tempBlock1, data.cut(i0, i0 + 16));
			tempBlock0 = data.cut(i0, i0 + 16);
		}
		res = UniqueKeyPublic::unpadding(res, fillingMethod);
		return res;
	}

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
SM4::SM4Ciphers::SM4Ciphers(int mode, int fillingMethod, Bytes key)
{
	this->mode = mode;
	this->fillingMethod = fillingMethod;
	this->OriginalKey = key;
	this->key = SM4::extendKey128(key);
}
void SM4::SM4Ciphers::setIV(Bytes iv)
{
	this->iv = iv;
}
void SM4::SM4Ciphers::changeIV()
{
	this->iv.clear();
	for (int i = 0; i < 16; i++)
	{
		iv.push_back(UniqueKeyPublic::randomByte());
	}
}
void SM4::SM4Ciphers::setKey(Bytes key)
{
	this->OriginalKey = key;
	this->key = SM4::extendKey128(key);
}
void SM4::SM4Ciphers::setFillingMethod(int fillingMethod)
{
	this->fillingMethod = fillingMethod;
}
void SM4::SM4Ciphers::setMode(int mode)
{
	this->mode = mode;
}
Bytes SM4::SM4Ciphers::getKey()
{
	return this->OriginalKey;
}
Bytes SM4::SM4Ciphers::encrypt(Bytes data, bool isWithIV)
{
	Bytes res;
	for (int i = 0; i < 16; i++)
	{
		this->iv.push_back(UniqueKeyPublic::randomByte());
	}
	if (mode == BlockCipherCode::ECB)
	{
		res = encrypt128ECB(data, this->key, this->fillingMethod);
	}
	else if (mode == BlockCipherCode::CBC)
	{
		res = encrypt128CBC(data, this->key, this->iv, this->fillingMethod);
	}
	else if (mode == BlockCipherCode::OFB)
	{
		res = encrypt128OFB(data, this->key, this->iv, this->fillingMethod);
	}
	else if (mode == BlockCipherCode::CTR)
	{
		res = encrypt128CTR(data, this->key, this->iv, this->fillingMethod);
	}
	else if (mode == BlockCipherCode::CFB1)
	{
		res = encrypt128CFB1(data, this->key, this->iv);
	}
	else if (mode == BlockCipherCode::CFB8)
	{
		res = encrypt128CFB8(data, this->key, this->iv);
	}
	else if (mode == BlockCipherCode::CFB128)
	{
		res = encrypt128CFB128(data, this->key, this->iv, this->fillingMethod);
	}
	if (isWithIV)
	{
		return this->iv + res;
	}
	else
	{
		return res;
	}
}
Bytes SM4::SM4Ciphers::decrypt(Bytes dataIN, bool isWithIV)
{
	Bytes res;
	Bytes data = dataIN;
	if (isWithIV)
	{
		this->iv = dataIN.cut(0, 16);
		data.erase(0, 16);
	}
	if (mode == BlockCipherCode::ECB)
	{
		res = decrypt128ECB(data, this->key, this->fillingMethod);
	}
	else if (mode == BlockCipherCode::CBC)
	{
		res = decrypt128CBC(data, this->key, this->iv, this->fillingMethod);
	}
	else if (mode == BlockCipherCode::OFB)
	{
		res = decrypt128OFB(data, this->key, this->iv, this->fillingMethod);
	}
	else if (mode == BlockCipherCode::CTR)
	{
		res = decrypt128CTR(data, this->key, this->iv, this->fillingMethod);
	}
	else if (mode == BlockCipherCode::CFB1)
	{
		res = decrypt128CFB1(data, this->key, this->iv);
	}
	else if (mode == BlockCipherCode::CFB8)
	{
		res = decrypt128CFB8(data, this->key, this->iv);
	}
	else if (mode == BlockCipherCode::CFB128)
	{
		res = decrypt128CFB128(data, this->key, this->iv, this->fillingMethod);
	}
	return res;
}
Bytes SM4::SM4Ciphers::encrypt(Bytes data)
{
	return encrypt(data, true);
}
Bytes SM4::SM4Ciphers::decrypt(Bytes data)
{
	return decrypt(data, true);
}