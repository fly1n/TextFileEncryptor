#pragma once
#include <windows.h>

// 获取NT头
#define		NTHEADER_T(lpBuff) (PIMAGE_NT_HEADERS32)((PBYTE)(lpBuff) + ((PIMAGE_DOS_HEADER)(lpBuff))->e_lfanew)
#define		NTHEADER(lpBuff)	(NTHEADER_T(lpBuff))

// 获取NT文件头
#define		NTFILEHEADER(lpBuff)	((NTHEADER(lpBuff))->FileHeader) 

// 获取扩展NT头
#define		NTOPTIONALHEADER_T(lpBuff) &(((PIMAGE_NT_HEADERS32)((PBYTE)lpBuff +	\
										((PIMAGE_DOS_HEADER)lpBuff)->e_lfanew))->OptionalHeader)

#define		NTOPTIONALHEADER(lpBuff)	(NTOPTIONALHEADER_T(lpBuff))

#define		SECTION_HEAD	1

typedef	struct _Typeoffset
{
	WORD wOffset : 12;
	WORD wType : 4;
}Typeoffset,*PTypeoffset;


/// 将整形的数组转换成十六进制字符串
void	byteArr2HexStr(const LPBYTE& lpbArr,
					   DWORD dwBSize,TCHAR* pszHexStr,
					   const TCHAR wcSpace = 0
					   );

/// 实际大小转对齐后大小 , 
DWORD size2AligentSize(DWORD n64FileSize,DWORD n64Aligent);

/// 判断是否是PE文件
BOOL	IsPEFile(const LPVOID lpBuff);

///获取PE头指针
const PIMAGE_NT_HEADERS32 GetPEHeader(const LPVOID& lpBuff);

///获取扩展头的指针
const PIMAGE_OPTIONAL_HEADER32	GetOptionalHeader(const LPVOID& lpBuff);

///获取头部大小
//DWORD	GetHeadSize(const LPVOID lpFile);
/// 获取头部大小
DWORD	GetHeaderSize(const LPBYTE lpFile);
///获取头部在内存中的大小
DWORD	GetHeadSizeOnMem(const LPVOID lpFile);


/// RVA转Offset
DWORD64	RVA2Offset(const LPVOID lpFile,DWORD64 dwRVA);
/// 文件偏移转RVA
//DWORD	Offset2RVA(const LPBYTE lpFile,DWORD dwOffset);

////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
///编辑区段信息
BOOL	EditSectionInfo(const LPVOID lpFile,
						PIMAGE_SECTION_HEADER pSec,
						const TCHAR* pszName,
						DWORD dwSize,
						DWORD dwRVA,
						DWORD dwChara
						);
BOOL	EditSectionInfo(const LPVOID lpFile,
						PIMAGE_SECTION_HEADER pSec,
						const char* pszName,
						TCHAR* pszSize,
						TCHAR* pszRVA,
						TCHAR* pszChara
						);
// 区段名
BOOL	EditSectionName(PIMAGE_SECTION_HEADER pSec ,const TCHAR* pszName);
BOOL	EditSectionName(PIMAGE_SECTION_HEADER pSec ,const char* pszName);
// 区段大小(未文件对齐)
BOOL	EditSectionFileSize(const LPVOID lpFile,PIMAGE_SECTION_HEADER pSec ,DWORD dwSize);
BOOL	EditSectionFileSize(const LPVOID lpFile,PIMAGE_SECTION_HEADER pSec ,TCHAR* pszSize);
// 区段内存偏移
BOOL	EditSectionRVA(PIMAGE_SECTION_HEADER pSec ,DWORD dwRVA);
BOOL	EditSectionRVA(PIMAGE_SECTION_HEADER pSec ,TCHAR* pszRVA);
// 区段属性
BOOL	EditSectionChara(PIMAGE_SECTION_HEADER pSec ,DWORD dwChara);
BOOL	EditSectionChara(PIMAGE_SECTION_HEADER pSec ,TCHAR* pszChara);

// 区段的文件偏移
BOOL	EditSectionFileOffset(PIMAGE_SECTION_HEADER pSec,TCHAR* pszOffset);
BOOL	EditSectionFileOffset(PIMAGE_SECTION_HEADER pSec,DWORD	dwOffset);
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
/// 添加一个新的区段.
/// 返回1,pNewSection是新区段的位置
/// 返回2,pNewSection是新区段的位置,lpFile是以旧空间内容填充并修改的新的内存空间
PIMAGE_SECTION_HEADER	AddSection(_Inout_ LPBYTE& lpFile,DWORD& dwSize,const TCHAR* pszName,DWORD	dwNameLen,DWORD	dwSecSize, unsigned char *newSection);

/// 获取最后一个区段
PIMAGE_SECTION_HEADER	GetLastSection(const LPBYTE lpFile);

/// 删除指定位置的区段
BOOL	DeleteSection(LPBYTE& lpFile,DWORD& dwSize , DWORD	dwIndex);

///获取指定区段
PIMAGE_SECTION_HEADER	GetSection(const LPBYTE lpFile,DWORD dwIndwx);

///获取RVA在哪一个区段,返回这个区段的地址, 没有则返回NULL,返回SECTION_HEAD时指的是头部
PIMAGE_SECTION_HEADER	GetSectionRVA(const LPVOID lpFile,DWORD64 dwRva);
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
