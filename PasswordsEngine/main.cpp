#include <iostream>
#include <String.h>
#include <vector>
#include <time.h>
#include <fstream>
#include <regex>

#include "Format.h"
#include "UniqueKey.h"
#include "Hash.h"
#include <chrono>

using namespace std;

int main(int argc, char* argv[])
{
	vector<string> Command;
	auto start = std::chrono::high_resolution_clock::now();
	char** receiveCmd = argv;
	for (int i = 0; i < argc; i++)
	{
		Command.push_back(string(argv[i]));
	}
	//Command.emplace_back(string("-UniqueKeyDecrypt"));
	//Command.emplace_back(string("-AES128"));
	//Command.emplace_back(string("-CBC"));
	//Command.emplace_back(string("-PKCS7"));
	//Command.emplace_back(string("0123456789abcdef"));
	//Command.emplace_back(string("-normal"));
	//Command.emplace_back(string("YDdTBFYAfEx+aVMdWyEnbpJj7IVpijl5BRZnBHE7uAE="));
	//Command.emplace_back(string("-base64"));
	//Command.emplace_back(string("-normal"));
	regex rMultBase64str("^-[Bb][Aa][Ss][Ee]64.{2,3}$");
	regex rNoneBase64str("^-[Bb][Aa][Ss][Ee]64");
	regex rHex("^-[Hh][Ee][Xx]$");
	regex r16a("^-16[Aa]$");
	regex rNormal("^-[Nn][Oo][Rr][Mm][Aa][Ll]$");
	if (Command.size() <= 1)
	{
		cout << "There may be some reason for showing error Chinese." << endl;
		cout << "可能因为某些原因导致错误显示中文" << endl;
		cout << endl;
		cout << "This is Core fot the final tool named AdminPSW_Manager." << endl;
		cout << "这是账密管理器的内核" << endl;
		cout << endl;
		cout << "Only apply some basic funcation to handle data" << endl;
		cout << "只提供基础的方法来处理数据" << endl;

		return 0;
	}
	if (Command[1] == string("-h") || Command[1] == string("-help"))
	{
		cout << "There are some methods and a format to input Data" << endl;
		cout << "以下是一些方法和输入数据的格式" << endl;
		cout << endl;
		cout << " -hash [Hash] [Data] [outputCode]" << endl;
		cout << " -hash [哈希算法名] [数据] [输出编码]" << endl;
		cout << "       [Hash] may be" << endl;
		cout << "       [Hash] 可以为" << endl;
		cout << "                     SHA256" << endl;
		cout << "                     SHA224" << endl;
		cout << "                     SHA512" << endl;
		cout << "                     SHA384" << endl;
		cout << "                     SM3" << endl;
		cout << "       [Data] may be string" << endl;
		cout << "       [Data] 可以为字符串" << endl;
		cout << "       [outputCode] may be " << endl;
		cout << "       [outputCode] 可以为 " << endl;
		cout << "                    -hex or -a16" << endl;
		cout << "                    Output in hex with lowercase letters" << endl;
		cout << "                    按字母小写的16进制输出" << endl;
		cout << "                    -Hex or -A16" << endl;
		cout << "                    Output in hex with uppercase letters" << endl;
		cout << "                    按字母大写的16进制输出" << endl;
		cout << endl;
        cout << "                    -base64 [letter in 62] [letter in 63] [letter in sitting]" << endl;
		cout << "                    Output in base64 with special letters" << endl;
		cout << "                    [letter in 62] is a letter to replace default letter \'+\' in No. 62 letter" << endl;
		cout << "                    [letter in 63] is a letter to replace default letter \'/\' in No. 63 letter" << endl;
		cout << "                    [letter in sitting] is a letter to replace default letter \'=\' in sitting" << endl;
		cout << "                    [letter in 62] and [letter in 63] must be setting together and not be like each other with [letter in sitting],otherwize result will not include this letter" << endl;
		cout << "                    [letter in 62] may be one of \"(space) ! \" # $ % & \' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    [letter in 63] may be one of \"(space) ! \" # $ % & \' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    [letter in sitting] may be one of \"(space) ! \" # $ % & \' ( ) * + , - / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    if do not use these letter,ths output message may be garbled code" << endl;
		cout << endl;
		cout << "                    -base64 [62字符] [62字符] [占位字符]" << endl;
		cout << "                    [62字符]用来替换原来的第62位\'+\'字符" << endl;
		cout << "                    [63字符]用来替换原来的第63位\'/\'字符" << endl;
		cout << "                    [占位字符]用来替换原来的占位\'=\'字符" << endl;
		cout << "                    [62字符]和[63字符]必须一起设置且和[占位字符]两两不一样，否则结果不会包含这些字符" << endl;
		cout << "                    [62字符]可以为\"(空格) ! \" # $ % & \' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    [63字符]可以为\"(空格) ! \" # $ % & \' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    [占位字符]可以为\"(空格) ! \" # $ % & \' ( ) * + , - / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    如果不使用这些字符，输出消息可能是乱码" << endl;
		cout << endl;
		cout << "example示例" << endl;
		cout << "input输入  >PINEngine -hash -SHA256 \"abc\" -normal -hex" << endl;
		cout << "output输出 >ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad spend耗时:-----s" << endl;
		cout << "input输入  >PINEngine -hash -SHA256 \"abc\" -normal -base64[]- " << endl;
		cout << "output输出 >ungWv48Bz[pBQUDeXa4iI7ADYaOWF3qctBD]YfIAFa0- spend耗时:-----s" << endl;
		cout << endl;
		cout << "-UniqueKeyEncrypt [hetmod] [mode] [filling] [password] [inputCode] [plaintext] [inputCode] [outputCode]" << endl;
		cout << "-UniqueKeyEncrypt [加密方法] [加密模式] [填充方法] [密钥] [明文]" << endl;
		cout << "                  [hetmod] may be" << endl;
		cout << "                  [加密方法] 可以为" << endl;
		cout << "                                  AES128" << endl;
		cout << "                                  AES192" << endl;
		cout << "                                  AES256" << endl;
		cout << "                                  SM4" << endl;
		cout << endl;
		cout << "                  [mode] may be" << endl;
		cout << "                  [加密模式] 可以为" << endl;
		cout << "                                  ECB" << endl;
		cout << "                                  CBC" << endl;
		cout << "                                  OFB" << endl;
		cout << "                                  CTR" << endl;
		cout << "                                  CFB1" << endl;
		cout << "                                  CFB8" << endl;
		cout << "                                  CFB128" << endl;
		cout << endl;
		cout << "                  [filling] may be" << endl;
		cout << "                  [填充方法] 可以为" << endl;
		cout << "                                  PKCS7" << endl;
		cout << "                                  ZERO" << endl;
		cout << "                                  ANSI923" << endl;
		cout << "                                  ISO10126" << endl;
		cout << "                                  ISO7816_4" << endl;
		cout << endl;
		cout << "                  [password] must be 16,24,32 bytes" << endl;
		cout << "                  [密钥] 必须为16,24,32字节" << endl;
		cout << endl;
		cout << "                  [plaintext] may be string" << endl;
		cout << "                  [明文] 可以为字符串" << endl;
        cout << endl;
		cout << "					[inputCode][outputCode] may be " << endl;
		cout << "       			[inputCode][outputCode] 可以为 " << endl;
		cout << "                    			-hex or -a16" << endl;
		cout << "                    			Output in hex with lowercase letters" << endl;
		cout << "                    			按字母小写的16进制输出" << endl;
		cout << "                    			-Hex or -A16" << endl;
		cout << "                    			Output in hex with uppercase letters" << endl;
		cout << "                    			按字母大写的16进制输出" << endl;
		cout << "                    -base64 [letter in 62] [letter in 63] [letter in sitting]" << endl;
		cout << "                    Output in base64 with special letters" << endl;
		cout << "                    [letter in 62] is a letter to replace default letter \'+\' in No. 62 letter" << endl;
		cout << "                    [letter in 63] is a letter to replace default letter \'/\' in No. 63 letter" << endl;
		cout << "                    [letter in sitting] is a letter to replace default letter \'=\' in sitting" << endl;
		cout << "                    [letter in 62] and [letter in 63] must be setting together and not be like each other with [letter in sitting],otherwize result will not include this letter" << endl;
		cout << "                    [letter in 62] may be one of \"(space) ! \" # $ % & \' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    [letter in 63] may be one of \"(space) ! \" # $ % & \' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    [letter in sitting] may be one of \"(space) ! \" # $ % & \' ( ) * + , - / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    if do not use these letter,ths output message may be garbled code" << endl;
		cout << endl;
		cout << "                    -base64 [62字符] [62字符] [占位字符]" << endl;
		cout << "                    [62字符]用来替换原来的第62位\'+\'字符" << endl;
		cout << "                    [63字符]用来替换原来的第63位\'/\'字符" << endl;
		cout << "                    [占位字符]用来替换原来的占位\'=\'字符" << endl;
		cout << "                    [62字符]和[63字符]必须一起设置且和[占位字符]两两不一样，否则结果不会包含这些字符" << endl;
		cout << "                    [62字符]可以为\"(空格) ! \" # $ % & \' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    [63字符]可以为\"(空格) ! \" # $ % & \' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    [占位字符]可以为\"(空格) ! \" # $ % & \' ( ) * + , - / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    如果不使用这些字符，输出消息可能是乱码" << endl;
		cout << endl;
		cout << "                    -normal　使用系统化默认编码" << endl;
		cout << "                    -normal　use system default encoding" << endl;
		cout << endl;
		cout << "example示例" << endl;
		cout << "input输入  >PINEngine -UniqueKeyEncrypt -AES128 -CBC -PKCS7 \"0123456789abcdef\" -normal \"abc\" -normal -Hex" << endl;
		cout << "output输出 >1A2501300626540D0879686F46601B2A279BBA0353EE49F2D238B69833F824F9" << endl;
		cout << endl;
		cout << "-UniqueKeyDecrypt [hetmod] [mode] [filling] [password] [plaintext] [outputCode]" << endl;
		cout << "-UniqueKeyDecrypt [解密方法] [解密模式] [解密方法] [密钥] [明文]" << endl;
		cout << "                  [hetmod] may be" << endl;
		cout << "                  [解密方法] 可以为" << endl;
		cout << "                                  AES128" << endl;
		cout << "                                  AES192" << endl;
		cout << "                                  AES256" << endl;
		cout << "                                  SM4" << endl;
		cout << endl;
		cout << "                  [mode] may be" << endl;
		cout << "                  [解密模式] 可以为" << endl;
		cout << "                                  ECB" << endl;
		cout << "                                  CBC" << endl;
		cout << "                                  OFB" << endl;
		cout << "                                  CTR" << endl;
		cout << "                                  CFB1" << endl;
		cout << "                                  CFB8" << endl;
		cout << "                                  CFB128" << endl;
		cout << endl;
		cout << "                  [filling] may be" << endl;
		cout << "                  [解密方法] 可以为" << endl;
		cout << "                                  PKCS7" << endl;
		cout << "                                  ZERO" << endl;
		cout << "                                  ANSI923" << endl;
		cout << "                                  ISO10126" << endl;
		cout << "                                  ISO7816_4" << endl;
		cout << endl;
		cout << "                  [password] must be 16,24,32 bytes" << endl;
		cout << "                  [密钥] 必须为16,24,32字节" << endl;
		cout << endl;
		cout << "                  [plaintext] may be string" << endl;
		cout << "                  [明文] 可以为字符串" << endl;
		cout << endl;
		cout << "					[inputCode][outputCode] may be " << endl;
		cout << "       			[inputCode][outputCode] 可以为 " << endl;
		cout << "                    			-hex or -a16" << endl;
		cout << "                    			Output in hex with lowercase letters" << endl;
		cout << "                    			按字母小写的16进制输出" << endl;
		cout << "                    			-Hex or -A16" << endl;
		cout << "                    			Output in hex with uppercase letters" << endl;
		cout << "                    			按字母大写的16进制输出" << endl;
		cout << "                    -base64[letter in 62][letter in 63][letter in sitting]" << endl;
		cout << "                    Output in base64 with special letters" << endl;
		cout << "                    [letter in 62] is a letter to replace default letter \'+\' in No. 62 letter" << endl;
		cout << "                    [letter in 63] is a letter to replace default letter \'/\' in No. 63 letter" << endl;
		cout << "                    [letter in sitting] is a letter to replace default letter \'=\' in sitting" << endl;
		cout << "                    [letter in 62] and [letter in 63] must be setting together and not be like each other with [letter in sitting],otherwize result will not include this letter" << endl;
		cout << "                    [letter in 62] may be one of \"(space) ! \" # $ % & \' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    [letter in 63] may be one of \"(space) ! \" # $ % & \' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    [letter in sitting] may be one of \"(space) ! \" # $ % & \' ( ) * + , - / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    if do not use these letter,ths output message may be garbled code" << endl;
		cout << endl;
		cout << "                    -base64 [62字符] [62字符] [占位字符]" << endl;
		cout << "                    [62字符]用来替换原来的第62位\'+\'字符" << endl;
		cout << "                    [63字符]用来替换原来的第63位\'/\'字符" << endl;
		cout << "                    [占位字符]用来替换原来的占位\'=\'字符" << endl;
		cout << "                    [62字符]和[63字符]必须一起设置且和[占位字符]两两不一样，否则结果不会包含这些字符" << endl;
		cout << "                    [62字符]可以为\"(空格) ! \" # $ % & \' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    [63字符]可以为\"(空格) ! \" # $ % & \' ( ) * + , - .  / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    [占位字符]可以为\"(空格) ! \" # $ % & \' ( ) * + , - / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\"" << endl;
		cout << "                    如果不使用这些字符，输出消息可能是乱码" << endl;
		cout << endl;
		cout << "                    -normal　使用系统化默认编码" << endl;
		cout << "                    -normal　use system default encoding" << endl;
		cout << endl;
		cout << "example示例" << endl;
		cout << "input输入  >PINEngine -UniqueKeyDecrypt -AES128 -CBC -PKCS7 \"0123456789abcdef\" -normal \"1A2501300626540D0879686F46601B2A279BBA0353EE49F2D238B69833F824F9\" -hex -Hex" << endl;
		cout << "output输出 >abc" << endl;
	}
	else if (Command[1] == string("-hash"))
	{	//-hash [Hash] [Data] [inputCode] [outputCode]

		//参数数量判断
		if (Command.size() < 6)
		{
			cout << "Error: not enough arguments" << endl;
			cout << "错误:参数不足" << endl;
			cout << "Now arguments 当前参数数量:" << endl;
			cout << Command.size() << endl;
			cout << "Need arguments 需要参数数量:" << endl;
			cout << 5 << endl;
			return 1;
		}
		//输入编码判断
		int inputCode;
		if (regex_match(Command[4], rNormal))
		{
			inputCode = 0;
		}
		else if (regex_match(Command[4], rHex))
		{
			if (Command[4][0] == 'H')
			{
				inputCode = 1;
			}
			else if (Command[4][0] == 'h')
			{
				inputCode = 2;
			}
		}
		else if (regex_match(Command[4], r16a))
		{
			if (Command[4][3] == 'A')
			{
				inputCode = 1;
			}
			else if (Command[4][3] == 'a')
			{
				inputCode = 2;
			}
		}
		else if (regex_match(Command[4], rNoneBase64str))
		{
			inputCode = 3;
		}
		else
		{
            cout << "Error:No suppurtted outputCode" << endl;
			cout << "错误:不支持的输入编码" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[4] << endl;
			return 1;
		}
		//输出编码判断
		int outputCode;
		char a;
		char b;
		char c;
		if (regex_match(Command[5], rNormal))
		{
			outputCode = 0;
		}
		else if (regex_match(Command[5], rHex))
		{
			if (Command[5][1] == 'H')
			{
				outputCode = 1;
			}
			else if (Command[5][1] == 'h')
			{
				outputCode = 2;
			}
		}
		else if (regex_match(Command[5], r16a))
		{
			if (Command[5][3] == 'A')
			{
				outputCode = 1;
			}
			else if (Command[5][3] == 'a')
			{
				outputCode = 2;
			}
		}
		else if (regex_match(Command[5], rNoneBase64str))
		{
			outputCode = 3;
		}
		else if (regex_match(Command[5], rMultBase64str))
		{
			if (Command[5].length() == 9)
			{
				a = Command[5][7];
				b = Command[5][8];
				outputCode = 4;
			}
			else if (Command[5].length() == 10)
			{
				a = Command[5][7];
				b = Command[5][8];
				c = Command[5][9];
				outputCode = 5;
			}
		}
		else
		{
			cout << "Error:No suppurtted outputCode" << endl;
			cout << "错误:不支持的输出编码" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[5] << endl;
			return 1;
		}

		//散列函数判断
		int hashMethod;
		regex rSHA256("^-[Ss][Hh][Aa]256$");
		regex rSHA224("^-[Ss][Hh][Aa]224$");
		regex rSHA384("^-[Ss][Hh][Aa]384$");
		regex rSHA512("^-[Ss][Hh][Aa]512$");
		regex rSM3("^-[Ss][Mm]3$");
		if (regex_match(Command[2], rSHA224))
		{
			hashMethod = 224;
		}
		else if (regex_match(Command[2], rSHA256))
		{
			hashMethod = 256;
		}
		else if (regex_match(Command[2], rSHA384))
		{
			hashMethod = 384;
		}
		else if (regex_match(Command[2], rSHA512))
		{
			hashMethod = 512;
		}
		else if (regex_match(Command[2], rSM3))
		{
			hashMethod = 3;
		}
		else
		{
			cout << "Error:No suppurtted hash" << endl;
			cout << "错误:不支持的散列函数" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[2] << endl;
			return 1;
		}

		Bytes* oright = nullptr;
		switch (inputCode)
		{
		case 0:oright = new Bytes(Command[3]); break;
		case 1:
		case 2:oright = new Bytes(Command[3], 2); break;
		case 3:oright = new Bytes(Command[3], 3); break;
		}
		Bytes* res = nullptr;
		switch (hashMethod)
		{
		case 3:res = new Bytes(SM3::SM3(*oright)); break;
		case 224: res = new Bytes(SHA2::SHA224(*oright)); break;
		case 256: res = new Bytes(SHA2::SHA256(*oright)); break;
		case 384: res = new Bytes(SHA2::SHA384(*oright)); break;
		case 512: res = new Bytes(SHA2::SHA512(*oright)); break;
		}
		string* resStr = nullptr;
		switch (outputCode)
		{
		case 0: resStr = new string(res->getNormalString()); break;
		case 1: resStr = new string(res->getUPHex16String()); break;
		case 2: resStr = new string(res->getLOWHex16String()); break;
		case 3: resStr = new string(res->getBase64String()); break;
		case 4: resStr = new string(res->getBase64String(a, b)); break;
		case 5: resStr = new string(res->getBase64String(a, b, c)); break;
		}

		cout << "plaintext原文: 输出编码" << endl;
		cout << Command[3] << '\n' << Command[4].substr(1, Command[4].length() - 1) << endl;
		cout << "hase散列算法:" << endl;
		cout << Command[2].substr(1, Command[2].length() - 1) << endl;
		cout << "hashed value散列值:" << endl;
		cout << *resStr << '\n' << Command[5].substr(1, Command[5].length() - 1) << endl;
	}
	else if (Command[1] == string("-UniqueKeyEncrypt"))
	{   //1                 2        3      4         5          6           7           8          9
		//-UniqueKeyEncrypt [hetmod] [mode] [filling] [password] [inputCode] [plaintext] [inputCode] [outputCode]
		//判断参数
		if (Command.size() < 9)
		{
			cout << "Error: not enough arguments" << endl;
			cout << "错误:参数不足" << endl;
			cout << "Now arguments 当前参数数量:" << endl;
			cout << Command.size() << endl;
			cout << "Need arguments 需要参数数量:" << endl;
			cout << 9 << endl;
			return 1;
		}
		//判断密码输入编码
		int pswCode;
		if (regex_match(Command[6], rNormal))
		{
			pswCode = 0;
		}
		else if (regex_match(Command[6], rHex))
		{
			pswCode = 2;
		}
		else if (regex_match(Command[6], r16a))
		{
			pswCode = 2;
		}
		else if (regex_match(Command[6], rNoneBase64str))
		{
			pswCode = 1;
		}
		else
		{
			cout << "Error:No suppurtted inputCode" << endl;
			cout << "错误:不支持的输入编码" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[6] << endl;
			return 1;
		}
		//判断明文输入编码
		int plaintextCode;
		if (regex_match(Command[8], rNormal))
		{
			plaintextCode = 0;
		}
		else if (regex_match(Command[8], rHex))
		{
			pswCode = 2;
		}
		else if (regex_match(Command[8], r16a))
		{
			pswCode = 2;
		}
		else if (regex_match(Command[8], rNoneBase64str))
		{
			plaintextCode = 1;
		}
		else
		{
			cout << "Error:No suppurtted inputCode" << endl;
			cout << "错误:不支持的输入编码" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[8] << endl;
			return 1;
		}
		//判断密文输出编码
		int outputCode;
		char a;
		char b;
		char c;
		if (regex_match(Command[9], rNormal))
		{
			outputCode = 0;
		}
		else if (regex_match(Command[9], rHex))
		{
			if (Command[9][1] == 'H')
			{
				outputCode = 1;
			}
			else if (Command[9][1] == 'h')
			{
				outputCode = 2;
			}
		}
		else if (regex_match(Command[9], r16a))
		{
			if (Command[9][3] == 'A')
			{
				outputCode = 1;
			}
			else if (Command[9][3] == 'a')
			{
				outputCode = 2;
			}
		}
		else if (regex_match(Command[9], rNoneBase64str))
		{
			outputCode = 3;
		}
		else if (regex_match(Command[9], rMultBase64str))
		{
			if (Command[9].length() == 9)
			{
				a = Command[9][7];
				b = Command[9][8];
				outputCode = 4;
			}
			else if (Command[9].length() == 10)
			{
				a = Command[9][7];
				b = Command[9][8];
				c = Command[9][9];
				outputCode = 5;
			}
		}
		else
		{
			cout << "Error:No suppurtted outputCode" << endl;
			cout << "错误:不支持的输出编码" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[9] << endl;
			return 1;
		}
		//判断加密算法
		int length;
		regex rAES128("^-[Aa][Ee][Ss]128$");
		regex rAES192("^-[Aa][Ee][Ss]192$");
		regex rAES256("^-[Aa][Ee][Ss]256$");
		regex rSM4("^-[Ss][Mm]4$");
		if (regex_match(Command[2], rAES128))
		{
			length = 128;
		}
		else if (regex_match(Command[2], rAES192))
		{
			length = 192;
		}
		else if (regex_match(Command[2], rAES256))
		{
			length = 256;
		}
		else if (regex_match(Command[2], rSM4))
		{
			length = 0;
		}
		else
		{
			cout << "Error:No suppurtted encrypt method" << endl;
			cout << "错误:不支持的加密算法" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[2] << endl;
            return 1;
		}
		//判断加密模式
		int mode;
		if (regex_match(Command[3], regex("^-[Ee][Cc][Bc]$")))
		{
			mode = BlockCipherCode::ECB;
		}
		else if (regex_match(Command[3], regex("^-[Cc][Bb][Cc]$")))
		{
			mode = BlockCipherCode::CBC;
		}
		else if (regex_match(Command[3], regex("^-[Oo][Ff][Bb]$")))
		{
			mode = BlockCipherCode::OFB;
		}
		else if (regex_match(Command[3], regex("^-[Cc][Tt][Rr]$")))
		{
			mode = BlockCipherCode::CTR;
		}
		else if (regex_match(Command[3], regex("^-[Cc][Ff][Bb]1$")))
		{
			mode = BlockCipherCode::CFB1;
		}
		else if (regex_match(Command[3], regex("^-[Cc][Ff][Bb]8$")))
		{
			mode = BlockCipherCode::CFB8;
		}
		else if (regex_match(Command[3], regex("^-[Cc][Ff][Bb]128$")))
		{
			mode = BlockCipherCode::CFB128;
		}
		else
		{
			cout<< "Error:No suppurtted mode" << endl;
			cout << "错误:不支持的加密模式" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[3] << endl;
			return 1;
		}
		//判断填充方式
		int fillMethod;
		if (regex_match(Command[4], regex("^-[Pp][Kk][Cc][Ss]7$")))
		{
			fillMethod = BlockCipherCode::PKCS7;
		}
		else if (regex_match(Command[4], regex("^-[Zz][Ee][Rr][Oo]$")))
		{
			fillMethod = BlockCipherCode::ZERO;
		}
		else if (regex_match(Command[4], regex("^-[Aa][Nn][Ss][Ii]923$")))
		{
			fillMethod = BlockCipherCode::ANSI923;
		}
		else if (regex_match(Command[4], regex("^-[Ii][Ss][Oo]7816_4$")))
		{
            fillMethod = BlockCipherCode::ISO7816_4;
		}
		else if (regex_match(Command[4], regex("^-[Ii][Ss][Oo]10126$")))
		{
			fillMethod = BlockCipherCode::ISO10126;
		}
		else
		{
			cout << "Error:No suppurtted filling method" << endl;
			cout << "错误:不支持的填充方式" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[4] << endl;
			return 1;
		}
		Bytes* psw = new Bytes(Command[5], pswCode);
		Bytes* plaintext = new Bytes(Command[7], plaintextCode);
		Bytes* encrypttext = nullptr;
		AES::AESCiphers* c1 = nullptr;
		SM4::SM4Ciphers* c2 = nullptr;
		Bytes* res = nullptr;
		try
		{
			switch (length)
			{
			case 0:c2 = new SM4::SM4Ciphers(mode, fillMethod, *psw); break;
			case 128:c1 = new AES::AESCiphers(128, mode, fillMethod, *psw); break;
			case 192:c1 = new AES::AESCiphers(192, mode, fillMethod, *psw); break;
			case 256:c1 = new AES::AESCiphers(256, mode, fillMethod, *psw); break;
			}
			if (c2 != nullptr)
			{
				res = new Bytes(c2->encrypt(*plaintext));
			}
			else
			{
				res = new Bytes(c1->encrypt(*plaintext));
			}
			string* resStr = nullptr;
			switch (outputCode)
			{
			case 0: resStr = new string(res->getNormalString()); break;
			case 1: resStr = new string(res->getUPHex16String()); break;
			case 2: resStr = new string(res->getLOWHex16String()); break;
			case 3: resStr = new string(res->getBase64String()); break;
			case 4: resStr = new string(res->getBase64String(a, b)); break;
			case 5: resStr = new string(res->getBase64String(a, b, c)); break;
			}

			cout << "plaintext原文:" << endl;
			cout << Command[7] << endl;
			cout << "coding原文编码:" << endl;
			cout << Command[8].substr(1, Command[8].size() - 1) << endl;
			cout << "encrypt method加密方式:" << endl;
			cout << Command[2].substr(1, Command[2].size() - 1) << endl;
			cout << "encrypt mode加密模式:" << endl;
			cout << Command[3].substr(1, Command[3].size() - 1) << endl;
			cout << "filling method填充方式:" << endl;
			cout << Command[4].substr(1, Command[4].size() - 1) << endl;
			cout << "ciphertext密文:" << endl;
			cout << *resStr << endl;
		}
		catch (exception& e)
		{
			cout << "Error:" << e.what() << endl;
			cout << "未知错误" << endl;
			return 1;
		}
	}
	else if (Command[1] == string("-UniqueKeyDecrypt"))
	{   //1                 2        3      4         5          6           7           8          9
		//-UniqueKeyEncrypt [hetmod] [mode] [filling] [password] [inputCode] [plaintext] [inputCode] [outputCode]
		//判断参数
		if (Command.size() < 9)
		{
			cout << "Error: not enough arguments" << endl;
			cout << "错误:参数不足" << endl;
			cout << "Now arguments 当前参数数量:" << endl;
			cout << Command.size() << endl;
			cout << "Need arguments 需要参数数量:" << endl;
			cout << 9 << endl;
			return 1;
		}
		//判断密码输入编码
		int pswCode;
		if (regex_match(Command[6], rNormal))
		{
			pswCode = 0;
		}
		else if (regex_match(Command[6], rHex))
		{
			pswCode = 2;
		}
		else if (regex_match(Command[6], r16a))
		{
			pswCode = 2;
		}
		else if (regex_match(Command[6], rNoneBase64str))
		{
			pswCode = 1;
		}
		else
		{
			cout << "Error:No suppurtted inputCode" << endl;
			cout << "错误:不支持的输入编码" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[6] << endl;
			return 1;
		}
		//判断明文输入编码
		int plaintextCode;
		if (regex_match(Command[8], rNormal))
		{
			plaintextCode = 0;
		}
		else if (regex_match(Command[8], rHex))
		{
			plaintextCode = 2;
		}
		else if (regex_match(Command[8], r16a))
		{
			plaintextCode = 2;
		}
		else if (regex_match(Command[8], rNoneBase64str))
		{
			plaintextCode = 1;
		}
		else
		{
			cout << "Error:No suppurtted inputCode" << endl;
			cout << "错误:不支持的输入编码" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[8] << endl;
			return 1;
		}
		//判断密文输出编码
		int outputCode;
		char a;
		char b;
		char c;
		if (regex_match(Command[9], rNormal))
		{
			outputCode = 0;
		}
		else if (regex_match(Command[9], rHex))
		{
			if (Command[9][1] == 'H')
			{
				outputCode = 1;
			}
			else if (Command[9][1] == 'h')
			{
				outputCode = 2;
			}
		}
		else if (regex_match(Command[9], r16a))
		{
			if (Command[9][3] == 'A')
			{
				outputCode = 1;
			}
			else if (Command[9][3] == 'a')
			{
				outputCode = 2;
			}
		}
		else if (regex_match(Command[9], rNoneBase64str))
		{
			outputCode = 3;
		}
		else if (regex_match(Command[9], rMultBase64str))
		{
			if (Command[9].length() == 9)
			{
				a = Command[9][7];
				b = Command[9][8];
				outputCode = 4;
			}
			else if (Command[9].length() == 10)
			{
				a = Command[9][7];
				b = Command[9][8];
				c = Command[9][9];
				outputCode = 5;
			}
		}
		else
		{
			cout << "Error:No suppurtted outputCode" << endl;
			cout << "错误:不支持的输出编码" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[9] << endl;
			return 1;
		}
		//判断加密算法
		int length;
		regex rAES128("^-[Aa][Ee][Ss]128$");
		regex rAES192("^-[Aa][Ee][Ss]192$");
		regex rAES256("^-[Aa][Ee][Ss]256$");
		regex rSM4("^-[Ss][Mm]4$");
		if (regex_match(Command[2], rAES128))
		{
			length = 128;
		}
		else if (regex_match(Command[2], rAES192))
		{
			length = 192;
		}
		else if (regex_match(Command[2], rAES256))
		{
			length = 256;
		}
		else if (regex_match(Command[2], rSM4))
		{
			length = 0;
		}
		else
		{
			cout << "Error:No suppurtted encrypt method" << endl;
			cout << "错误:不支持的加密算法" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[2] << endl;
			return 1;
		}
		//判断加密模式
		int mode;
		if (regex_match(Command[3], regex("^-[Ee][Cc][Bc]$")))
		{
			mode = BlockCipherCode::ECB;
		}
		else if (regex_match(Command[3], regex("^-[Cc][Bb][Cc]$")))
		{
			mode = BlockCipherCode::CBC;
		}
		else if (regex_match(Command[3], regex("^-[Oo][Ff][Bb]$")))
		{
			mode = BlockCipherCode::OFB;
		}
		else if (regex_match(Command[3], regex("^-[Cc][Tt][Rr]$")))
		{
			mode = BlockCipherCode::CTR;
		}
		else if (regex_match(Command[3], regex("^-[Cc][Ff][Bb]1$")))
		{
			mode = BlockCipherCode::CFB1;
		}
		else if (regex_match(Command[3], regex("^-[Cc][Ff][Bb]8$")))
		{
			mode = BlockCipherCode::CFB8;
		}
		else if (regex_match(Command[3], regex("^-[Cc][Ff][Bb]128$")))
		{
			mode = BlockCipherCode::CFB128;
		}
		else
		{
			cout << "Error:No suppurtted mode" << endl;
			cout << "错误:不支持的加密模式" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[3] << endl;
			return 1;
		}
		//判断填充方式
		int fillMethod;
		if (regex_match(Command[4], regex("^-[Pp][Kk][Cc][Ss]7$")))
		{
			fillMethod = BlockCipherCode::PKCS7;
		}
		else if (regex_match(Command[4], regex("^-[Zz][Ee][Rr][Oo]$")))
		{
			fillMethod = BlockCipherCode::ZERO;
		}
		else if (regex_match(Command[4], regex("^-[Aa][Nn][Ss][Ii]923$")))
		{
			fillMethod = BlockCipherCode::ANSI923;
		}
		else if (regex_match(Command[4], regex("^-[Ii][Ss][Oo]7816_4$")))
		{
			fillMethod = BlockCipherCode::ISO7816_4;
		}
		else if (regex_match(Command[4], regex("^-[Ii][Ss][Oo]10126$")))
		{
			fillMethod = BlockCipherCode::ISO10126;
		}
		else
		{
			cout << "Error:No suppurtted filling method" << endl;
			cout << "错误:不支持的填充方式" << endl;
			cout << "Wrong arguments错误参数:" << endl;
			cout << Command[4] << endl;
			return 1;
		}
		Bytes* psw = new Bytes(Command[5], pswCode);
		Bytes* plaintext = new Bytes(Command[7], plaintextCode);
		Bytes* encrypttext = nullptr;
		AES::AESCiphers* c1 = nullptr;
		SM4::SM4Ciphers* c2 = nullptr;
		Bytes* res = nullptr;
		try
		{
			switch (length)
			{
			case 0:c2 = new SM4::SM4Ciphers(mode, fillMethod, *psw); break;
			case 128:c1 = new AES::AESCiphers(128, mode, fillMethod, *psw); break;
			case 192:c1 = new AES::AESCiphers(192, mode, fillMethod, *psw); break;
			case 256:c1 = new AES::AESCiphers(256, mode, fillMethod, *psw); break;
			}
			if (c2 != nullptr)
			{
				res = new Bytes(c2->decrypt(*plaintext));
			}
			else
			{
				res = new Bytes(c1->decrypt(*plaintext));
			}

			string* resStr = nullptr;
			switch (outputCode)
			{
			case 0: resStr = new string(res->getNormalString()); break;
			case 1: resStr = new string(res->getUPHex16String()); break;
			case 2: resStr = new string(res->getLOWHex16String()); break;
			case 3: resStr = new string(res->getBase64String()); break;
			case 4: resStr = new string(res->getBase64String(a, b)); break;
			case 5: resStr = new string(res->getBase64String(a, b, c)); break;
			}

			cout << "ciphertext密文:" << endl;
			cout << Command[7] << endl;
			cout << "coding原文编码:" << endl;
			cout << Command[8].substr(1, Command[8].size() - 1) << endl;
			cout << "encrypt method加密方式:" << endl;
			cout << Command[2].substr(1, Command[2].size() - 1) << endl;
			cout << "encrypt mode加密模式:" << endl;
			cout << Command[3].substr(1, Command[3].size() - 1) << endl;
			cout << "filling method填充方式:" << endl;
			cout << Command[4].substr(1, Command[4].size() - 1) << endl;
			cout << "plaintext原文:" << endl;
			cout << *resStr << endl;
		}
		catch (exception& e)
		{
			cout << "Error:" << e.what() << endl;
			cout << "未知错误" << endl;
			return 1;
		}
	}

	auto end = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double, std::milli> time = end - start;
	cout << "spend耗时:" << endl;
	cout << time.count() << "ms" << endl;

	return 0;
}