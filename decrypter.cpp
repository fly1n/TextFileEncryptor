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

using namespace std;
using namespace CryptoPP;

HWND    gTargetWindowHwnd = NULL;

BOOL CALLBACK myWNDENUMPROC(HWND hwCurHwnd, LPARAM lpMylp)
{
	DWORD dwCurPid = 0;

	GetWindowThreadProcessId(hwCurHwnd, &dwCurPid);

	if (dwCurPid == (DWORD)lpMylp)
	{
		gTargetWindowHwnd = hwCurHwnd;
		return FALSE;
	}

	return TRUE;
}

int main()
{
	cout << "Input password:" << endl;
	string passwd;
	cin >> passwd;
	byte *key = new byte[32];

	SHA256 sha256;
	sha256.CalculateDigest(key, (const byte *)passwd.c_str(), passwd.size());

	HMODULE pHandle = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pHandle;
	cout << hex << pDosHeader->e_lfanew << endl;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	cout << hex << *(DWORD *)pNtHeader << endl;
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 0x4);
	long numSec = pFileHeader->NumberOfSections;
	cout << numSec << endl;
	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);
	PIMAGE_SECTION_HEADER pTxtSec = &(pSecHeader[numSec - 1]);
	cout << (char *)pTxtSec->Name << endl;
	if (strcmp((const char *)(pTxtSec->Name), ".fly1n") != 0)
	{
		exit(0);
	}
	byte *pTxtData = (byte *)((DWORD)pHandle + pTxtSec->VirtualAddress);
	size_t bufSize = *(DWORD *)(pTxtData);
	DWORD firstDword = *(((DWORD *)(pTxtData)) + 1);
	cout << bufSize << endl;
	cout << firstDword << endl;

	byte *buf = new byte[bufSize+1];
	memset(buf, 0, bufSize+1);

	byte iv[AES::BLOCKSIZE] =
	{ 0x18, 0x27, 0x65, 0x3F, 0xB4, 0xB2, 0xA3, 0x51, 0xE6, 0x5C, 0xC2, 0x12, 0x34, 0x56, 0x78, 0xED };

	AES::Decryption aesDecryption(key, AES::MAX_KEYLENGTH);
	CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
	ArraySource(pTxtData + 8, bufSize, true, new StreamTransformationFilter(cbcDecryption, new ArraySink(buf, bufSize), StreamTransformationFilter::NO_PADDING));

	cout << "Decrypted" << endl;

	if (((DWORD *)buf)[0] != firstDword)
	{
		exit(0);
	}
	cout << "Checked" << endl;

	PROCESS_INFORMATION pi; // This is what we get as an [out] parameter

	STARTUPINFO si; // This is an [in] parameter

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si); // Only compulsory field

	if (!CreateProcess(_T("C:\\Windows\\notepad.exe"), _T(""), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
		exit(0);
	}
	else
	{
		WaitForInputIdle(pi.hProcess, INFINITE);
	}
	EnumWindows(&myWNDENUMPROC, pi.dwProcessId);// Iterate all windows
	HWND hEdit = FindWindowEx(gTargetWindowHwnd, NULL, _T("Edit"), NULL);

	SendMessageA(hEdit, WM_SETTEXT, NULL, LPARAM(buf));

	SendMessageA(hEdit, EM_SETMODIFY, TRUE, NULL);

	delete[] buf;
	return 0;
}