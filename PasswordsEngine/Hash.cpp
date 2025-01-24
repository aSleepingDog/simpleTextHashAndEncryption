#include <iostream>
#include <String.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include "format.h"
#include <fstream>
#define Uchar unsigned char
#define Uint unsigned int
#define Ullong unsigned long long
namespace HashTest
{
	/*only for test 测试用*/
	void ShowBit(Bytes show)
	{
		printf("   ");
		for (int j = 0; j < 32; j++)
		{
			printf("%02d ", j);
			if (j % 4 == 3)
			{
				printf("|");
			}
		}
		printf("\n00:");
		for (int j = 0; j < show.size(); j++)
		{
			printf("%02X ", show.at(j));
			if (j % 4 == 3)
			{
				printf("|");
			}
			if (j % 32 == 31)
			{
				if ((j / 32) + 1 != 8)
				{
					printf("\n%02d:", (j / 32) + 1);
				}
			}
		}
		printf("\n\n");
	}
	void ShowBit(std::vector<Uchar> show)
	{
		printf("   ");
		for (int j = 0; j < 32; j++)
		{
			printf("%02d ", j);
			if (j % 4 == 3)
			{
				printf("|");
			}
		}
		printf("\n00:");
		for (int j = 0; j < show.size(); j++)
		{
			printf("%02X ", show[j]);
			if (j % 4 == 3)
			{
				printf("|");
			}
			if (j % 32 == 31)
			{
				if ((j / 32) + 1 != 8)
				{
					printf("\n%02d:", (j / 32) + 1);
				}
			}
		}
		printf("\n\n");
	}
	void ShowHash(Ullong h[], int size)
	{
		for (int j = 0; j < size; j++)
		{
			printf("%016llX|", h[j]);
		}
		printf("\n");
	}
	void ShowHash(Uint h[], int size)
	{
		for (int j = 0; j < size; j++)
		{
			printf("%08X|", h[j]);
		}
		printf("\n");
	}
}
namespace SHA2
{
	class SHA2Exception : std::exception
	{
		const char* what() const throw ()
		{
			return "Error:The size or length of inpution is over 2^61-8(2,305,843,009,213,693,944)B or 2^125-8B";
		}
	};
	
	const Uint k_256[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
							 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
							 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
							 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
							 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
							 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
							 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
							 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
	const Uint h_256[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	const Uint h_224[8] = { 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 };

	Ullong reverseOrder(Ullong n)
	{
		Ullong a = 0;
		for (int i = 0; i < 64; i++)
		{
			a += n << i >> 64;
		}
		return a;
	}
	Uchar circleRightMoveBit(Uchar c, int n)
	{
		int temp = n % 8;
		return (c >> temp) | (c << 8 - temp);
	}
	Uint circleRightMoveBit(Uint i, int n)
	{
		int temp = n % 32;
		return (i >> temp) | (i << 32 - temp);
	}
	Uint tick4B(Bytes str, int size, int n)
	{
		return (Uint)(str.at(size - n * 4) << 24) + (str.at(size - n * 4 + 1) << 16) + (str.at(size - n * 4 + 2) << 8) + (str.at(size - n * 4 + 3));
	}
	Uint function1_64(Uint e, Uint f, Uint g, Uint h, Bytes block, int size, int n)
	{
		Uint S1 = circleRightMoveBit(e, 6) ^ circleRightMoveBit(e, 11) ^ circleRightMoveBit(e, 25);//移动位数出错,原为
		//printf("%0x\n", S1);
		Uint ch = (e & f) ^ ((~e) & g);
		Uint k = k_256[n];
		Uint w = tick4B(block, size, (64 - n));
		//printf("%0x\n", w);
		return h + S1 + ch + k + w;
	}
	Uint function2_64(Uint a, Uint b, Uint c)
	{
		Uint S0 = circleRightMoveBit(a, 2) ^ circleRightMoveBit(a, 13) ^ circleRightMoveBit(a, 22);
		Uint maj = (a & b) ^ (a & c) ^ (b & c);
		return S0 + maj;
	}
	Bytes SHA256(Bytes str)
	{
		Bytes res(64);
		Uint tempN[9] = { h_256[0], h_256[1], h_256[2], h_256[3], h_256[4], h_256[5], h_256[6], h_256[7] ,0 };
		Uint tempH[8] = { h_256[0], h_256[1], h_256[2], h_256[3], h_256[4], h_256[5], h_256[6], h_256[7] };
		if (str.size() > (Ullong)0x2000000000000000)
		{
			throw SHA2Exception();
		}
		bool isFill08 = false;
		bool isEnd = false;
		for (Ullong i = 0; i <= ((str.size() / 64) + 1) * 64; i += 64)
		{
			if (isEnd) { break; }
			Bytes tempBlock(256);
			Ullong dataEnd = str.size() > i ? str.size() - i : 0;
			for (Ullong j = 0; j < (dataEnd > 64 ? 64 : dataEnd); j++)
			{
				tempBlock.push_back(str.at(i + j));
			}
			if (dataEnd <= 55)//dataEnd < 56
			{
				if (!isFill08)
				{
					tempBlock.push_back((Uchar)(0x80));
					dataEnd++;
					isFill08 = true;
				}
				for (int j = dataEnd; j < 56; j++)
				{
					tempBlock.push_back((Uchar)(0x00));
				}
				tempBlock = tempBlock + Bytes::turnBytes(str.size() * 8);
				isEnd = true;
			}
			else if (dataEnd > 55 && dataEnd < 64)//dataEnd >= 56
			{
				if (!isFill08)
				{
					tempBlock.push_back((Uchar)(0x80));
					dataEnd++;
					isFill08 = true;
				}
				for (int j = dataEnd; j < 64; j++)
				{
					tempBlock.push_back((Uchar)(0x00));
				}
			}


			while (tempBlock.size() < 256)
			{
				Uint s0 = tick4B(tempBlock, tempBlock.size(), 15);
				Uint s1 = tick4B(tempBlock, tempBlock.size(), 2);
				Uint s2 = tick4B(tempBlock, tempBlock.size(), 16);
				Uint s3 = tick4B(tempBlock, tempBlock.size(), 7);
				s0 = circleRightMoveBit(s0, 7) ^ circleRightMoveBit(s0, 18) ^ (s0 >> 3);
				s1 = circleRightMoveBit(s1, 17) ^ circleRightMoveBit(s1, 19) ^ (s1 >> 10);
				Uint append = s0 + s1 + s2 + s3;
				for (int i0 = 0; i0 < 4; i0++)
				{
					tempBlock.push_back((Uchar)(append << i0 * 8 >> 24));
				}
			}
			for (int i0 = 0; i0 < 64; i0++)
			{
				Uint T1 = function1_64(tempN[4], tempN[5], tempN[6], tempN[7], tempBlock, tempBlock.size(), i0);
				Uint T2 = function2_64(tempN[0], tempN[1], tempN[2]);
				tempN[3] += T1;
				tempN[7] = T1 + T2;
				for (int j = 8; j > 0; j--)
				{
					tempN[j] = tempN[j - 1];
				}
				tempN[0] = tempN[8];
			}
			for (int i1 = 0; i1 < 8; i1++)
			{
				tempH[i1] += tempN[i1];
				tempN[i1] = tempH[i1];
			}
			tempBlock.clear();
		}

		for (int i = 0; i < 8; i++)
		{
			for (int i0 = 0; i0 < 4; i0++)
			{
				res.push_back((Byte)((tempH[i] >> (24 - i0 * 8)) & 0xFF));
			}
		}
		return res;
	}
	Bytes SHA224(Bytes str)
	{
		Bytes res(64);
		Uint tempN[9] = { h_224[0], h_224[1], h_224[2], h_224[3], h_224[4], h_224[5], h_224[6], h_224[7],0 };
		Uint tempH[8] = { h_224[0], h_224[1], h_224[2], h_224[3], h_224[4], h_224[5], h_224[6], h_224[7] };
		if (str.size() > (Ullong)0x2000000000000000)
		{
			throw SHA2Exception();
		}
		bool isFill08 = false;
		bool isEnd = false;
		for (Ullong i = 0; i <= ((str.size() / 64) + 1) * 64; i += 64)
		{
			if (isEnd) { break; }
			Bytes tempBlock(256);
			Ullong dataEnd = str.size() > i ? str.size() - i : 0;
			for (Ullong j = 0; j < (dataEnd > 64 ? 64 : dataEnd); j++)
			{
				tempBlock.push_back(str.at(i + j));
			}
			if (dataEnd <= 55)
			{
				if (!isFill08)
				{
					tempBlock.push_back((Uchar)(0x80));
					dataEnd++;
					isFill08 = true;
				}
				for (int j = dataEnd; j < 56; j++)
				{
					tempBlock.push_back((Uchar)(0x00));
				}
				tempBlock = tempBlock + Bytes::turnBytes(str.size() * 8);
				isEnd = true;
			}
			else if (dataEnd > 55 && dataEnd < 64)
			{
				if (!isFill08)
				{
					tempBlock.push_back((Uchar)(0x80));
					dataEnd++;
					isFill08 = true;
				}
				for (int j = dataEnd; j < 64; j++)
				{
					tempBlock.push_back((Uchar)(0x00));
				}
			}
			while (tempBlock.size() < 256)
			{
				Uint s0 = tick4B(tempBlock, tempBlock.size(), 15);
				Uint s1 = tick4B(tempBlock, tempBlock.size(), 2);
				Uint s2 = tick4B(tempBlock, tempBlock.size(), 16);
				Uint s3 = tick4B(tempBlock, tempBlock.size(), 7);
				s0 = circleRightMoveBit(s0, 7) ^ circleRightMoveBit(s0, 18) ^ (s0 >> 3);
				s1 = circleRightMoveBit(s1, 17) ^ circleRightMoveBit(s1, 19) ^ (s1 >> 10);
				Uint append = s0 + s1 + s2 + s3;
				for (int i0 = 0; i0 < 4; i0++)
				{
					tempBlock.push_back((Uchar)(append << i0 * 8 >> 24));
				}
			}
			for (int i0 = 0; i0 < 64; i0++)
			{
				Uint T1 = function1_64(tempN[4], tempN[5], tempN[6], tempN[7], tempBlock, tempBlock.size(), i0);
				Uint T2 = function2_64(tempN[0], tempN[1], tempN[2]);
				tempN[3] += T1;
				tempN[7] = T1 + T2;
				for (int j = 8; j > 0; j--)
				{
					tempN[j] = tempN[j - 1];
				}
				tempN[0] = tempN[8];
			}
			for (int i1 = 0; i1 < 8; i1++)
			{
				tempH[i1] += tempN[i1];
				tempN[i1] = tempH[i1];
			}
			tempBlock.clear();
		}
		for (int i = 0; i < 7; i++)
		{
			for (int i0 = 0; i0 < 4; i0++)
			{
				res.push_back((Byte)((tempH[i] >> (24 - i0 * 8)) & 0xFF));
			}
		}
		return res;
	}

	const Ullong k_512[80] = { 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
										   0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
										   0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
										   0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
										   0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
										   0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
										   0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
										   0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
										   0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
										   0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
										   0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
										   0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
										   0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
										   0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
										   0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
										   0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
										   0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
										   0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
										   0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
										   0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };
	const Ullong h_384[8] = { 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
										  0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4 };
	const Ullong h_512[8] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
										  0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };

	class BigSize
	{
	private:
		Ullong high;//MAX::0xffffffffffffffff
		Ullong low;
	public:
		const static int FILLSET = 0;
		const static int FILLADD = 1;

		BigSize(Ullong a)
		{
			this->high = 0;
			this->low = a;
		}
		BigSize(Ullong a, Ullong b, int i)
		{
			if (i == 0)
			{
				this->high = a;
				this->low = b;
			}
			else if (i == 1)
			{
				if (0xffffffffffffffff - a >= b)
				{
					high = 0;
					low = a + b;
				}
				else
				{
					high = 1;
					low = b - (0xffffffffffffffff - a) - 1;
				}
			}
			else
			{
				high = 0;
				low = 0;
			}
		}
		BigSize(Uint a)
		{
			this->high = 0;
			this->low = (Ullong)a;
		}
		friend bool operator>(BigSize a, BigSize b)
		{
			if (a.high > b.high)
			{
				return true;
			}
			else if (a.high < b.high)
			{
				return false;
			}
			if (a.low > b.low)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		friend bool operator>=(BigSize a, BigSize b)
		{
			if (a.high > b.high)
			{
				return true;
			}
			else if (a.high < b.high)
			{
				return false;
			}
			if (a.low > b.low)
			{
				return true;
			}
			else
			{
				return true;
			}
		}
		friend bool operator<(BigSize a, BigSize b)
		{
			if (a.high < b.high)
			{
				return true;
			}
			else if (a.high > b.high)
			{
				return false;
			}
			if (a.low < b.low)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		friend bool operator<=(BigSize a, BigSize b)
		{
			if (a.high < b.high)
			{
				return true;
			}
			else if (a.high > b.high)
			{
				return false;
			}
			if (a.low < b.low)
			{
				return true;
			}
			else
			{
				return true;
			}
		}
		friend bool operator==(BigSize a, BigSize b)
		{
			if (a.high == b.high && a.low == b.low)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		friend bool operator!=(BigSize a, BigSize b)
		{
			return !(a == b);
		}

		friend BigSize operator+(BigSize a, BigSize b)
		{
			Ullong hign = a.high + b.high;
			Ullong low = 0;
			if (0xffffffffffffffff - a.low >= b.low)
			{
				low = a.low + b.low;
			}
			else
			{
				low = b.low - (0xffffffffffffffff - a.low) - 1;
				hign++;
			}
			return BigSize(hign, low, FILLSET);
		}

		std::string toLOWHEX16String()
		{
			return (Bytes::turnBytes(this->high) + Bytes::turnBytes(this->low)).getLOWHex16String();
		}
		std::string toUPHEX16String()
		{
			return (Bytes::turnBytes(this->high) + Bytes::turnBytes(this->low)).getUPHex16String();
		}
	};

	Ullong tick8B(std::vector<Uchar> str, int size, int n)
	{
		Ullong res = 0;
		for (int i = 0; i < 8; i++)
		{
			res += ((Ullong)str[size - n * 8 + i] << (56 - 8 * i));
		}
		return res;
	}
	Ullong tick8B(Bytes str, int size, int n)
	{
		Ullong res = 0;
		for (int i = 0; i < 8; i++)
		{
			res += ((Ullong)str.at(size - n * 8 + i) << (56 - 8 * i));
		}
		return res;
	}
	Ullong circleRightMoveBit(Ullong i, int n)
	{
		int temp = n % 64;
		return (i >> temp) | (i << 64 - temp);
	}
	Ullong function1_128(Ullong e, Ullong f, Ullong g, Ullong h, std::vector<Uchar> block, int size, int n)
	{
		Ullong S1 = circleRightMoveBit(e, 14) ^ circleRightMoveBit(e, 18) ^ circleRightMoveBit(e, 41);
		Ullong ch = (e & f) ^ ((~e) & g);
		Ullong temp = h + S1 + ch + k_512[n] + tick8B(block, size, (80 - n));
		return temp;
	}
	Ullong function1_128(Ullong e, Ullong f, Ullong g, Ullong h, Bytes block, int size, int n)
	{
		Ullong S1 = circleRightMoveBit(e, 14) ^ circleRightMoveBit(e, 18) ^ circleRightMoveBit(e, 41);
		Ullong ch = (e & f) ^ ((~e) & g);
		Ullong temp = h + S1 + ch + k_512[n] + tick8B(block, size, (80 - n));
		return temp;
	}
	Ullong function2_128(Ullong a, Ullong b, Ullong c)
	{
		Ullong S0 = circleRightMoveBit(a, 28) ^ circleRightMoveBit(a, 34) ^ circleRightMoveBit(a, 39);
		Ullong maj = (a & b) ^ (a & c) ^ (b & c);
		return S0 + maj;

	}
	Bytes SHA384(Bytes str)

	{
		Ullong size = str.size();
		size++;
		while (size % 128 != 112)
		{
			size++;
			if (size == (Ullong)(0xffffffffffffffff))
			{
				throw SHA2Exception();
			}
		}
		std::vector<Uchar> tempStr;
		tempStr.reserve(size);
		int i = 0;
		for (i = 0; i < str.size(); i++)
		{
			tempStr.push_back(str.at(i));
		}
		tempStr.push_back((Uchar)(0x80));
		for (i = i; i < size - 1; i++)
		{
			tempStr.push_back((Uchar)(0x00));
		}
		for (i = 0; i < 8; i++)
		{
			tempStr.push_back((Uchar)(0x00));
		}
		for (int i = 0; i < 8; i++)
		{
			tempStr.push_back((Ullong)str.size() * 8 << i * 8 >> 56);
		}
		size = tempStr.size();
		Ullong tempN[9] = { h_384[0], h_384[1], h_384[2], h_384[3], h_384[4], h_384[5], h_384[6], h_384[7],0 };
		Ullong tempH[8] = { h_384[0], h_384[1], h_384[2], h_384[3], h_384[4], h_384[5], h_384[6], h_384[7] };
		std::vector<Uchar> tempBlockStr;
		tempBlockStr.reserve(640);
		for (Ullong i = 0; i < size; i += 128)
		{
			for (int i0 = 0; i0 < 128; i0++)
			{
				tempBlockStr.push_back(tempStr[i + i0]);
			}
			while (tempBlockStr.size() < 640)
			{
				Ullong s0 = tick8B(tempBlockStr, tempBlockStr.size(), 15);
				Ullong s1 = tick8B(tempBlockStr, tempBlockStr.size(), 2);
				Ullong s2 = tick8B(tempBlockStr, tempBlockStr.size(), 16);
				Ullong s3 = tick8B(tempBlockStr, tempBlockStr.size(), 7);
				s0 = circleRightMoveBit(s0, 1) ^ circleRightMoveBit(s0, 8) ^ (s0 >> 7);
				s1 = circleRightMoveBit(s1, 19) ^ circleRightMoveBit(s1, 61) ^ (s1 >> 6);
				Ullong append = s0 + s1 + s2 + s3;
				for (int i0 = 0; i0 < 8; i0++)
				{
					tempBlockStr.push_back((Uchar)(append << i0 * 8 >> 56));
				}
			}
			for (int i0 = 0; i0 < 80; i0++)//
			{
				Ullong T1 = function1_128(tempN[4], tempN[5], tempN[6], tempN[7], tempBlockStr, tempBlockStr.size(), i0);
				Ullong T2 = function2_128(tempN[0], tempN[1], tempN[2]);
				tempN[3] += T1;
				tempN[7] = T1 + T2;
				for (int j = 8; j > 0; j--)
				{
					tempN[j] = tempN[j - 1];
				}
				tempN[0] = tempN[8];
			}
			for (int i1 = 0; i1 < 8; i1++)
			{
				tempH[i1] += tempN[i1];
				tempN[i1] = tempH[i1];
			}
			tempBlockStr.clear();
		}
		Bytes res;
		for (int i = 0; i < 6; i++)
		{
			for (int i0 = 0; i0 < 8; i0++)
			{
				res.push_back((Uchar)(tempH[i] << i0 * 8 >> 56));
			}
		}
		return res;
	}
	Bytes SHA512(Bytes str)
	{
		try
		{
			Ullong size = str.size();
			size++;
			while (size % 128 != 112)
			{
				size++;
				if (size == (Ullong)(0xffffffffffffffff))
				{
					throw SHA2Exception();
				}
			}
			std::vector<Uchar> tempStr;
			tempStr.reserve(size);
			int i = 0;
			for (i = 0; i < str.size(); i++)
			{
				tempStr.push_back(str.at(i));
			}
			tempStr.push_back((Uchar)(0x80));
			for (i = i; i < size - 1; i++)
			{
				tempStr.push_back((Uchar)(0x00));
			}
			for (i = 0; i < 8; i++)
			{
				tempStr.push_back((Uchar)(0x00));
			}
			for (int i = 0; i < 8; i++)
			{
				tempStr.push_back((Ullong)str.size() * 8 << i * 8 >> 56);
			}

			size = tempStr.size();
			Ullong tempN[9] = { h_512[0], h_512[1], h_512[2], h_512[3], h_512[4], h_512[5], h_512[6], h_512[7],0 };
			Ullong tempH[8] = { h_512[0], h_512[1], h_512[2], h_512[3], h_512[4], h_512[5], h_512[6], h_512[7] };
			std::vector<Uchar> tempBlockStr;
			tempBlockStr.reserve(640);
			for (Ullong i = 0; i < size; i += 128)
			{
				for (int i0 = 0; i0 < 128; i0++)
				{
					tempBlockStr.push_back(tempStr[i + i0]);
				}
				while (tempBlockStr.size() < 640)
				{
					Ullong s0 = tick8B(tempBlockStr, tempBlockStr.size(), 15);
					Ullong s1 = tick8B(tempBlockStr, tempBlockStr.size(), 2);
					Ullong s2 = tick8B(tempBlockStr, tempBlockStr.size(), 16);
					Ullong s3 = tick8B(tempBlockStr, tempBlockStr.size(), 7);
					s0 = circleRightMoveBit(s0, 1) ^ circleRightMoveBit(s0, 8) ^ (s0 >> 7);
					s1 = circleRightMoveBit(s1, 19) ^ circleRightMoveBit(s1, 61) ^ (s1 >> 6);
					Ullong append = s0 + s1 + s2 + s3;
					for (int i0 = 0; i0 < 8; i0++)
					{
						tempBlockStr.push_back((Uchar)(append << i0 * 8 >> 56));
					}
				}
				for (int i0 = 0; i0 < 80; i0++)//
				{
					Ullong T1 = function1_128(tempN[4], tempN[5], tempN[6], tempN[7], tempBlockStr, tempBlockStr.size(), i0);
					Ullong T2 = function2_128(tempN[0], tempN[1], tempN[2]);
					tempN[3] += T1;
					tempN[7] = T1 + T2;
					for (int j = 8; j > 0; j--)
					{
						tempN[j] = tempN[j - 1];
					}
					tempN[0] = tempN[8];
				}
				for (int i1 = 0; i1 < 8; i1++)
				{
					tempH[i1] += tempN[i1];
					tempN[i1] = tempH[i1];
				}
				tempBlockStr.clear();
			}
			Bytes res;
			for (int i = 0; i < 8; i++)
			{
				for (int i0 = 0; i0 < 8; i0++)
				{
					res.push_back((Uchar)(tempH[i] << i0 * 8 >> 56));
				}
			}
			return res;
		}
		catch (std::exception& e)
		{
			std::cout << e.what() << std::endl;
		}
	}

}
namespace SM3
{
	class SM3Exception : std::exception
	{
		const char* what() const throw ()
		{
			return "Error:The size or length of inpution is over 2^61-8(2,305,843,009,213,693,944)B";
		}
	};
	Uint H_SM3[8] = { 0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e };
	Uint circleLeftMoveBit(Uint i, int n)
	{
		int temp = n % 32;
		return (i << temp) | i >> (32 - temp);
	}
	Uint SM3tick4B(Bytes str, int n)
	{
		return (Uint)(str.at(4 * n) << 24) + (Uint)(str.at(4 * n + 1) << 16) + (Uint)(str.at(4 * n + 2) << 8) + (Uint)(str.at(4 * n + 3));
	}
	Uint functionP1_SM3(Bytes str, int i)
	{
		Uint w1 = SM3tick4B(str, i - 16);
		Uint w2 = SM3tick4B(str, i - 9);
		Uint w3 = SM3tick4B(str, i - 3);
		Uint w4 = SM3tick4B(str, i - 13);
		Uint w5 = SM3tick4B(str, i - 6);
		Uint W0 = (w1 ^ w2 ^ (circleLeftMoveBit(w3, 15)));
		Uint _P = W0 ^ circleLeftMoveBit(W0, 15) ^ circleLeftMoveBit(W0, 23);
		return _P ^ circleLeftMoveBit(w4, 7) ^ w5;
	}
	Uint functionFF1_SM3(Uint a, Uint b, Uint c, int i)
	{
		if (i < 16)
		{
			return a ^ b ^ c;
		}
		else
		{
			return (a & b) | (a & c) | (b & c);
		}
	}
	Uint functionGG1_SM3(Uint a, Uint b, Uint c, int i)
	{
		if (i < 16)
		{
			return a ^ b ^ c;
		}
		else
		{
			return (a & b) | (~a & c);
		}
	}

	Bytes SM3(Bytes str)
	{
		Bytes res(64);
		Uint tempH[9] = { H_SM3[0],H_SM3[1],H_SM3[2],H_SM3[3],H_SM3[4],H_SM3[5],H_SM3[6],H_SM3[7] };
		Uint tempN[9] = { H_SM3[0],H_SM3[1],H_SM3[2],H_SM3[3],H_SM3[4],H_SM3[5],H_SM3[6],H_SM3[7] };
		if (str.size() > (Ullong)0x2000000000000000)
		{
			throw SM3Exception();
		}
		bool isFill08 = false;
		bool isEnd = false;
		for (Ullong i = 0; i <= ((str.size() / 64) + 1) * 64; i += 64)
		{
			if (isEnd) { break; }
			Bytes tempBlock(256);
			Ullong dataEnd = str.size() > i ? str.size() - i : 0;
			for (Ullong j = 0; j < (dataEnd > 64 ? 64 : dataEnd); j++)
			{
				tempBlock.push_back(str.at(i + j));
			}
			if (dataEnd <= 55)
			{
				if (!isFill08)
				{
					tempBlock.push_back((Uchar)(0x80));
					dataEnd++;
					isFill08 = true;
				}
				for (int j = dataEnd; j < 56; j++)
				{
					tempBlock.push_back((Uchar)(0x00));
				}
				tempBlock = tempBlock + Bytes::turnBytes(str.size() * 8);
				isEnd = true;
			}
			else if (dataEnd > 55 && dataEnd < 64)
			{
				if (!isFill08)
				{
					tempBlock.push_back((Uchar)(0x80));
					dataEnd++;
					isFill08 = true;
				}
				for (int j = dataEnd; j < 64; j++)
				{
					tempBlock.push_back((Uchar)(0x00));
				}
			}
			for (int i0 = 16; i0 < 68; i0++)
			{
				Uint W = functionP1_SM3(tempBlock, i0);
				for (int i1 = 0; i1 < 4; i1++)
				{
					tempBlock.push_back((Uchar)(W << i1 * 8 >> 24));
				}
			}
			for (int i0 = 0; i0 < 64; i0++)
			{
				Uint W = SM3tick4B(tempBlock, i0) ^ SM3tick4B(tempBlock, i0 + 4);
				for (int i1 = 0; i1 < 4; i1++)
				{
					tempBlock.push_back((Uchar)(W << i1 * 8 >> 24));
				}
			}
			for (int i0 = 0; i0 < 64; i0++)
			{
				Uint T = (i0 < 16) ? (0x79cc4519) : (0x7a879d8a);
				Uint SS1 = circleLeftMoveBit((circleLeftMoveBit(tempN[0], 12) + tempN[4] + circleLeftMoveBit(T, i0)), 7);
				Uint SS2 = SS1 ^ circleLeftMoveBit(tempN[0], 12);
				Uint TT1 = functionFF1_SM3(tempN[0], tempN[1], tempN[2], i0) + tempN[3] + SS2 + SM3tick4B(tempBlock, i0 + 68);
				Uint TT2 = functionGG1_SM3(tempN[4], tempN[5], tempN[6], i0) + tempN[7] + SS1 + SM3tick4B(tempBlock, i0);
				tempN[3] = tempN[2];
				tempN[2] = circleLeftMoveBit(tempN[1], 9);
				tempN[1] = tempN[0];
				tempN[0] = TT1;
				tempN[7] = tempN[6];
				tempN[6] = circleLeftMoveBit(tempN[5], 19);
				tempN[5] = tempN[4];
				tempN[4] = TT2 ^ circleLeftMoveBit(TT2, 9) ^ circleLeftMoveBit(TT2, 17);
			}
			for (int i0 = 0; i0 < 8; i0++)
			{
				tempH[i0] = tempH[i0] ^ tempN[i0];
				tempN[i0] = tempH[i0];
			}
			tempBlock.clear();
		}
		for (int i = 0; i < 8; i++)
		{
			for (int i0 = 0; i0 < 4; i0++)
			{
				res.push_back((Byte)((tempH[i] >> (24 - i0 * 8)) & 0xFF));
			}
		}
		return res;
	}
}
