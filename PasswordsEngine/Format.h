#pragma once
#include <iostream>
#include <vector>
#include <cstring>
#define Uchar unsigned char
#define Uint unsigned int
#define Byte unsigned char
#define Ullong unsigned long long
const std::string Base64List("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+\=");
const std::string Hex16List("0123456789ABCDEF");
const std::string Hex16LOWList("0123456789abcdef");
struct Cstring
{
	char* point;
	int size;
};
class Bytes//编码
{
private:
	std::vector<Uchar> Inside;
public:
	const static int NORMAL = 0;
	const static int BASE64 = 1;
	const static int HEX = 2;

	Bytes();
	Bytes(int size);
	Bytes(char* p);
	Bytes(std::string str);
	Bytes(std::string str, int n);
	friend Bytes operator+(Bytes a, Bytes b);
	friend bool operator==(Bytes a, Bytes b);
	friend bool operator!=(Bytes a, Bytes b);
	std::vector<char> getNormalVector();
	std::vector<char> getBase64Vector();
	std::vector<char> getBase64Vector(char a, char b);
	std::vector<char> getBase64Vector(char a, char b, char c);
	std::vector<char> getLOWHex16Vector();
	std::vector<char> getUPHex16Vector();
	std::string getNormalString();
	std::string getBase64String();
	std::string getBase64String(char a, char b);
	std::string getBase64String(char a, char b, char c);
	std::string getLOWHex16String();
	std::string getUPHex16String();
	Cstring getNormalCString();
	Cstring getBase64CString();
	Cstring getBase64CString(char a, char b);
	std::vector<Uchar> getInsideVextor();
	bool change(Ullong i, Uchar c);
	Uchar at(Ullong i);
	unsigned long long size();
	void push_back(Uchar c);
	void reserve(unsigned long long n);
	void setString(std::string str);
	Bytes cut(Ullong start, Ullong end);
	Bytes cut(int start, int end);
	void clear();
	bool inversionBIN();
	Bytes inversionBOUT();
	void pop_back();
	void erase(Ullong start, Ullong end);

	static Bytes turnBytes(Ullong n);
	static Bytes turnBytes(Uint n);
};