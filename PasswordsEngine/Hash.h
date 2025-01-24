#include <iostream>
#include <String.h>
#include <vector>

#include "Format.h"
#define uchar unsigned char;
#pragma once
class SHA2Exception : std::exception
{
	const char* what() const throw ();
};
//std::string SHA256(std::string str);
namespace HashTest
{
	/*only for test 测试用*/
	void ShowBit(Bytes show);
	void ShowBit(std::vector<Uchar> show);
	void ShowHash(Ullong h[], int size);
	void ShowHash(Uint h[], int size);
}
namespace SHA2
{
	Bytes SHA256(Bytes str);
	Bytes SHA224(Bytes str);
	Bytes SHA384(Bytes str);
	Bytes SHA512(Bytes str);

	//
	class BigSize
	{
	private:
		Ullong low;
		Ullong high;//MAX::0xffffffffffffffff
	public:
		BigSize(Ullong a);
		BigSize(Ullong a, Ullong b);
		BigSize(Uint a);
		friend bool operator>(BigSize a, BigSize b);
		friend bool operator>=(BigSize a, BigSize b);
		friend bool operator<(BigSize a, BigSize b);
		friend bool operator<=(BigSize a, BigSize b);
		friend bool operator==(BigSize a, BigSize b);
		friend bool operator!=(BigSize a, BigSize b);

		friend BigSize operator+(BigSize a, BigSize b);

		std::string toLOWHEX16String();
		std::string toUPHEX16String();
	};

}
namespace SM3
{
	Bytes SM3(Bytes str);
}