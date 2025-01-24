/*
#include <iostream>
#include <string>
#include <vector>
#include <time.h>
#include <regex>

#include "Hash.h"
#include "Format.h"
#include "UniqueKey.h"
#include <chrono>

using namespace std;

int main0() 
{
	ifstream passwords("password.txt", ios::in);
	ifstream exams("exam.txt", ios::in);
	ofstream results("result.txt", ios::out);
	if (!passwords.is_open() || !exams.is_open() || !results.is_open())
	{
		cout << "Open file failed!" << endl;
		return 1;
	}
	string passwordStr = "0123456789abcdef";
	string examStr;
	Ullong len = 1;
	while (getline(passwords, passwordStr) && getline(exams, examStr))
	{
		Bytes passwordB(passwordStr, 2);
		Bytes examB(examStr, 2);
		for (int size = 128; size <= 256; size += 64)
		{
			for (int mode = 0; mode < 7; mode++)
			{
				for (int method = 0; method < 5; method++)
				{
					AES::AESCiphers aes(size, mode, method, passwordB);
					auto start = std::chrono::high_resolution_clock::now();
					Bytes result1 = aes.encrypt(examB);
					Bytes result2 = aes.decrypt(result1);
					auto end = std::chrono::high_resolution_clock::now();
					std::chrono::duration<double, std::milli> time = end - start;
					string modeStr;
					string methodStr;
					string resultStr;
					string timeStr = to_string(time.count());
					switch (mode)
					{
					case 0: modeStr = "ECB"; break;
					case 1: modeStr = "CBC"; break;
					case 2: modeStr = "OFB"; break;
					case 3: modeStr = "CTR"; break;
					case 4: modeStr = "CFB1"; break;
					case 5: modeStr = "CFB8"; break;
					case 6: modeStr = "CFB128"; break;
					}
					switch (method)
					{
					case 0: methodStr = "PKCS7"; break;
					case 1: methodStr = "ZERO"; break;
					case 2: methodStr = "ANSI923"; break;
					case 3: methodStr = "ISO7816_4"; break;
					case 4: methodStr = "ISO10126"; break;
					}
					switch (result2==examB)
					{
					case false: resultStr = "解密错误"; break;
					case true: resultStr = "解密正确"; break;
					}
					cout << format("{0:d}|{1:d}|{2:d}|{3:s}|{4:-^9s}|{5:.3f}|{6:s}\n", len, size, examB.size(), modeStr, methodStr, time.count(), resultStr);
					results << format("{0:d}|{1:d}|{2:d}|{3:s}|{4:-^9s}|{5:.3f}|{6:s}\n", len, size, examB.size(), modeStr, methodStr, time.count(), resultStr);
					results.flush();
				}
			}
		}
	}
	return 0;
}
*/