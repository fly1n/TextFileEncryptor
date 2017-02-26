#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "sha.h"
#include "hex.h"
#include "cryptlib.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <tchar.h>
#include "files.h"
#include <fstream>
#include <iomanip>
#include "PEInfo.h"

using namespace std;
using namespace CryptoPP;

std::string getexepath()
{
	char result[MAX_PATH];
	return std::string(result, GetModuleFileNameA(NULL, result, MAX_PATH));
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		return 0;

	string exePath = getexepath();
	string dirPath = exePath.substr(0, exePath.find_last_of("/\\") + 1);

	ifstream fin;
	size_t blockSize = 0;
	byte *origContent = nullptr;

	fin.open(dirPath + argv[1], ios::in | ios::binary | ios::ate);

	if (fin.is_open())
	{
		size_t txtFileSize = fin.tellg();
		fin.seekg(0, ios::beg);

		blockSize = ((txtFileSize - 1) / 16 + 1) * 16;
		origContent = new byte[blockSize];
		memset(origContent, 0, blockSize);
		fin.read((char *)origContent, txtFileSize);
	}
	else
	{
		return 0;
	}

	cout << "Input password:" << endl;
	string passwd;
	cin >> passwd;
	byte *key = new byte[32];

	SHA256 sha256;
	sha256.CalculateDigest(key, (const byte *)passwd.c_str(), passwd.size());

	for (size_t i = 0; i < 32; ++i)
	{
		cout << hex << (int)(*(key + i));
	}
	cout << endl;

	byte *encryptedContent = new byte[blockSize + 8];
	memset(encryptedContent, 0, blockSize + 8);

	byte iv[AES::BLOCKSIZE] =
	{ 0x18, 0x27, 0x65, 0x3F, 0xB4, 0xB2, 0xA3, 0x51, 0xE6, 0x5C, 0xC2, 0x12, 0x34, 0x56, 0x78, 0xED };

	AES::Encryption aesEncryption(key, AES::MAX_KEYLENGTH);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	ArraySource(origContent, blockSize, true,
		new StreamTransformationFilter(
				cbcEncryption, 
				new ArraySink(encryptedContent + 8, blockSize), 
				StreamTransformationFilter::NO_PADDING));

	delete[] key;

	*((DWORD *)encryptedContent) = blockSize;
	*((DWORD *)encryptedContent + 1) = ((DWORD *)origContent)[0];

	delete[] origContent;

	HANDLE hFile;
	string decipherProgPath = dirPath + "decrypter.exe";

	hFile = ::CreateFileA(decipherProgPath.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);    //用这个函数比OpenFile好
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "打开文件失败", "Error", MB_OK);
		CloseHandle(hFile);        //一定注意在函数退出之前对句柄进行释放。
		return 0;
	}
	DWORD decipherProgSize = GetFileSize(hFile, NULL);
	unsigned char *decipherProg = new unsigned char[decipherProgSize + 1];        //最后一位为'/0',C-Style字符串的结束符。
	DWORD readsize;
	ReadFile(hFile, decipherProg, decipherProgSize, &readsize, NULL);
	decipherProg[decipherProgSize] = 0;
	CloseHandle(hFile);//关闭句柄。
	AddSection(decipherProg, decipherProgSize, _T(".fly1n"), 6, blockSize + 8, encryptedContent);

	string newDecipherProgPath = dirPath + "decrypter_1.exe";
	ofstream fout;
	fout.open(newDecipherProgPath, ios::binary | ios::out);
	fout.write((const char *)decipherProg, decipherProgSize);
	fout.close();

	delete[] encryptedContent;
	delete[] decipherProg;
	return 0;
}