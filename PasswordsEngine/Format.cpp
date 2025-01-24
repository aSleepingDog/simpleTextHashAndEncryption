#include <iostream>
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>

#define Uchar unsigned char
#define Byte unsigned char
#define Uint unsigned char
#define Ullong unsigned long long

const std::string Base64List("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+\\");
const std::string Hex16UPList("0123456789ABCDEF");
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
	Bytes(std::vector<Uchar> PUTIN);
	Bytes(std::string str);
	Bytes(std::string str, int n);
	friend Bytes operator+(Bytes a, Bytes b);
	friend bool operator==(Bytes a, Bytes b);
	friend bool operator!=(Bytes a, Bytes b);
	std::vector<char> getNormalVector();
	std::vector<char> getBase64Vector();
	std::vector<char> getBase64Vector(char a,char b);
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
	Cstring getBase64CString(char a,char b);
	//char* getHex16CString();
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
Bytes::Bytes()
{}
Bytes::Bytes(int n)//获取固定的数组
{
	this->Inside.reserve(n);
}
Bytes::Bytes(char* p)
{
	Ullong i=0;
	while(p[i]!='\0')
	{
		this->Inside[i] = p[i];
		i++;
	}
}
Bytes::Bytes(std::string str)//将字符串转为编码
{
	this->Inside.resize(str.size());
	for (int i = 0; i < str.size(); i++)
	{
		this->Inside[i] = str[i];
	}
}
Bytes::Bytes(std::vector<Uchar> PUTIN)
{
	this->Inside = PUTIN;
}
void Bytes::setString(std::string str)
{
	this->Inside.resize(str.size());
	for (int i = 0; i < str.size(); i++)
	{
		this->Inside[i] = str[i];
	}
}
Bytes::Bytes(std::string str, int n)
{
	if (n == 0)//常规字符串
	{
		this->Inside.resize(str.size());
		for (int i = 0; i < str.size(); i++)
		{
			this->Inside[i] = str[i];
		}
	}
	else if (n == 1)//Base64
	{
		int m = str.size() * 3 / 4;
		this->Inside.reserve(m);
		for (int i = 0; i < str.size(); i+=4)
		{
			Uint b[4] = { 0,0,0,0 };
			for (int i0 = 0; i0 < 4; i0++) 
			{
				if (str[i + i0] >= (Uint)'A' && str[i + i0] <= (Uint)'Z')
				{
					b[i0] = str[i + i0] - (Uint)'A';
				}
				else if (str[i + i0] >= (Uint)'a' && str[i + i0] <= (Uint)'z')
				{
					b[i0] = str[i + i0] - (Uint)'a' + (Uint)26;
				}
				else if (str[i + i0] >= (Uint)'0' && str[i + i0] <= (Uint)'9')
				{
					b[i0] = str[i + i0] - (Uint)'0' + (Uint)52;
				}
				else if (str[i + i0] == (Uint)'+')
				{
					b[i0] = (Uint)62;
				}
				else if (str[i + i0] == (Uint)'/')
				{
					b[i0] = (Uint)63;
				}
				else if (str[i + i0] == (Uint)'=')
				{
					b[i0] = (Uint)64;
				}
			}
			this->Inside.push_back((Byte)((b[0] << 2) | (b[1] >> 4)));
			if (b[2] == (Uint)64) { break; }
			this->Inside.push_back((Byte)((b[1] << 4) | (b[2] >> 2)));
			if (b[3] == (Uint)64) { break; }
            this->Inside.push_back((Byte)((b[2] << 6) | b[3]));
		}
	}
	else if (n == 2)//16进制
	{
		this->Inside.reserve(str.size() / 2);
		for (int i = 0; i < str.size(); i+=2)
		{
			Uint b0 = 0;
			if (str[i] >= (Uint)'A' && str[i] <= (Uint)'F')
			{
				b0 = str[i] - (Uint)'A' + (Uint)10;
			}
			else if (str[i] >= (Uint)'a' && str[i] <= (Uint)'f')
			{
				b0 = str[i] - (Uint)'a' + (Uint)10;
			}
			else if (str[i] >= '0' && str[i] <= '9')
			{
				b0 = str[i] - (Uint)'0';
			}
			Uint b1 = 0;
			if (str[i+1] >= (Uint)'A' && str[i+1] <= (Uint)'F')
			{
				b1 = str[i+1] - (Uint)'A' + (Uint)10;
			}
			else if (str[i+1] >= (Uint)'a' && str[i+1] <= (Uint)'f')
			{
				b1 = str[i+1] - (Uint)'a' + (Uint)10;
			}
			else if (str[i+1] >= '0' && str[i+1] <= '9')
			{
				b1 = str[i+1] - (Uint)'0';
			}
			this->Inside.push_back((Byte)(b0 * 16 + b1));
		}
	}
}
std::vector<char> Bytes::getNormalVector()
{
	std::vector<char> res (this->Inside.size());
	for (int i = 0; i < this->Inside.size(); i++)
	{
		res.push_back(this->Inside[i]);
	}
	return res;
}
std::vector<char> Bytes::getBase64Vector()
{
	std::vector<char> res;
	res = this->getBase64Vector('+', '/', '=');
	return res;
}
std::vector<char> Bytes::getBase64Vector(char a, char b)
{
	std::vector<char> res;
	res=this->getBase64Vector(a, b, '=');
	return res;
}
std::vector<char> Bytes::getBase64Vector(char a, char b, char c)
{
	char tempList[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	tempList[62] = a; tempList[63] = b;
	std::vector<char> res;
	int bit[4] = { 0,0,0,0 };
	int TDfull = this->Inside.size() - this->Inside.size() % 3;
	for (int i = 0; i < TDfull; i += 3)
	{
		bit[0] = (this->Inside[i] >> 2) & 0x3f;
		bit[1] = ((this->Inside[i] << 6 >> 2) + (this->Inside[i + 1] >> 4)) & 0x3f;
		bit[2] = ((this->Inside[i + 1] << 4 >> 2) + (this->Inside[i + 2] >> 6)) & 0x3f;
		bit[3] = (this->Inside[i + 2] << 2 >> 2) & 0x3f;
		res.push_back(tempList[bit[0]]);
		res.push_back(tempList[bit[1]]);
		res.push_back(tempList[bit[2]]);
		res.push_back(tempList[bit[3]]);
	}
	if (this->Inside.size() % 3 == 1)
	{
		bit[0] = (this->Inside[TDfull] >> 2) & 0x3f;
		bit[1] = (this->Inside[TDfull] << 6 >> 2) & 0x3f;
		res.push_back(tempList[bit[0]]);
		res.push_back(tempList[bit[1]]);
		res.push_back(c);
		res.push_back(c);
	}
	else if (this->Inside.size() % 3 == 2)
	{
		bit[0] = (this->Inside[TDfull] >> 2) & 0x3f;
		bit[1] = ((this->Inside[TDfull] << 6 >> 2) + (this->Inside[TDfull + 1] >> 4)) & 0x3f;
		bit[2] = (this->Inside[TDfull + 1] << 4 >> 2) & 0x3f;
		res.push_back(tempList[bit[0]]);
		res.push_back(tempList[bit[1]]);
		res.push_back(tempList[bit[2]]);
		res.push_back(c);
	}
	return res;
}
std::vector<char> Bytes::getLOWHex16Vector()
{
	std::vector<char> res;
	res.reserve(this->Inside.size() * 2);
	for (int i = 0; i < this->Inside.size(); i++)
	{
		res.push_back(Hex16LOWList[(Uint)this->Inside[i] >> 4]);
		res.push_back(Hex16LOWList[(Uint)this->Inside[i]&0x0f]);
	}
	return res;
}
std::vector<char> Bytes::getUPHex16Vector()
{
	std::vector<char> res;
	res.reserve(this->Inside.size() * 2);
	for (int i = 0; i < this->Inside.size(); i++)
	{
		res.push_back(Hex16UPList[(Uint)this->Inside[i] >> 4]);
		res.push_back(Hex16UPList[(Uint)this->Inside[i] & 0x0f]);
	}
	return res;
}
std::string Bytes::getBase64String()
{
	std::vector<char> temp = this->getBase64Vector();
	std::string res((char*)temp.data(), temp.size());
	return res;
}
std::string Bytes::getNormalString()
{
	std::string res((char*)this->Inside.data(), this->Inside.size());
	return res;
}
std::string Bytes::getBase64String(char a, char b)
{
	std::vector<char> temp = this->getBase64Vector(a, b);
	std::string res((char*)temp.data(), temp.size());
	return res;
}
std::string Bytes::getBase64String(char a, char b, char c)
{
	std::vector<char> temp = this->getBase64Vector(a, b, c);
	std::string res((char*)temp.data(), temp.size());
	return res;
}
std::string Bytes::getLOWHex16String()
{
	std::vector<char> temp = this->getLOWHex16Vector();
	std::string res((char*)temp.data(), temp.size());
	return res;
}
std::string Bytes::getUPHex16String()
{
	std::vector<char> temp = this->getUPHex16Vector();
	std::string res((char*)temp.data(), temp.size());
	return res;
}
Cstring Bytes::getNormalCString()
{
	Cstring res;
	res.point= (char*)this->Inside.data();
	res.size = this->Inside.size();
	return res;
}
Cstring Bytes::getBase64CString()
{
	Cstring res;
	std::vector<char> temp = this->getBase64Vector();
	res.point = temp.data();
	res.size = temp.size();
	return res;
}
Cstring Bytes::getBase64CString(char a, char b)
{
	Cstring res;
	std::vector<char> temp = this->getBase64Vector(a, b);
	res.point = temp.data();
	res.size = temp.size();
	return res;
}
Uchar Bytes::at(Ullong i)
{
	return (char)this->Inside.at(i);
}
unsigned long long Bytes::size()
{
	return this->Inside.size();
}
void Bytes::push_back(Uchar c)
{
	this->Inside.push_back(c);
}
void Bytes::reserve(unsigned long long n)
{
	this->Inside.reserve(this->Inside.size() + n);
}
Bytes operator+(Bytes a, Bytes b)
{
	Bytes res(a.size() + b.size());
	for (unsigned long long i = 0; i < a.size(); i++)
	{
		res.push_back(a.at(i));
	}
	for (unsigned long long i = 0; i < b.size(); i++)
	{
		res.push_back(b.at(i));
	}
	return res;
}
bool operator==(Bytes a, Bytes b)
{
	if (a.size() != b.size())
	{
		return false;
	}
	for (unsigned long long i = 0; i < a.size(); i++)
	{
		if (a.at(i) != b.at(i))
		{
			return false;
		}
	}
	return true;
}
bool operator!=(Bytes a, Bytes b)
{
	if (a.size() != b.size())
	{
		return false;
	}
	for (unsigned long long i = 0; i < a.size(); i++)
	{
		if (a.at(i) != b.at(i))
		{
			return true;
		}
	}
	return false;
}
bool Bytes::change(Ullong i,Uchar c)
{
	this->Inside[i] = c;
	return true;
}
std::vector<Uchar> Bytes::getInsideVextor()
{
	return this->Inside;
}
Bytes Bytes::cut(Ullong start, Ullong end)
{
	Ullong size = end - start;
	Bytes res(size);
	for (;start < end; start++)
	{
		res.push_back((Byte)this->Inside.at(start));
	}
	return res;
}
Bytes Bytes::cut(int start, int end)
{
	int size = end - start;
	Bytes res(size);
	for (; start < end; start++)
	{
		res.push_back((Byte)this->Inside.at(start));
	}
	return res;
}
void Bytes::clear()
{
	this->Inside.clear();
}
bool Bytes::inversionBIN()
{
	Uchar temp;
	for (Ullong i = 0; i < this->Inside.size()/2; i++)
	{
		temp = this->Inside[i];
		this->Inside[i] = this->Inside[this->Inside.size() - i - 1];
		this->Inside[this->Inside.size() - i - 1]= temp;
	}
	return true;
}
Bytes Bytes::inversionBOUT()
{
	Bytes res(this->Inside);
	res.inversionBIN();
	return res;
}
void Bytes::pop_back()
{
	this->Inside.pop_back();
}
void Bytes::erase(Ullong start, Ullong end)
{
	this->Inside.erase(this->Inside.begin() + start, this->Inside.begin() + end);
}

Bytes Bytes::turnBytes(Ullong n)
{
	Bytes res(4);
	for (int i = 0; i < 8; i++)
	{
		res.push_back((Byte)((n >> (56 - i * 8)) & 0xFF));
	}
	return res;
}
Bytes Bytes::turnBytes(Uint n)
{
	Bytes res(4);
	for (int i = 0; i < 8; i++)
	{
		res.push_back((Byte)((n >> (24 - i * 8)) & 0xFF));
	}
	return res;
}