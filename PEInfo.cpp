#include "PEInfo.h"
#include <cstdio>
#include <cwchar>
#include <tchar.h>
#include <cstdlib>

//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: IsPEFile
///功  能: 判断是否是PE文件
// 形  参: const LPVOID lpBuff
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
BOOL	IsPEFile(const LPVOID lpBuff)
{
	if(lpBuff == NULL)
	{
		return FALSE;
	}
	// 判断MZ头
	PIMAGE_DOS_HEADER	pDos = (PIMAGE_DOS_HEADER)lpBuff;
	if(pDos->e_magic != IMAGE_DOS_SIGNATURE) // MZ头
		return FALSE;
	// 判断PE头
	PIMAGE_NT_HEADERS32	pNT = (PIMAGE_NT_HEADERS32)((PBYTE)lpBuff + pDos->e_lfanew);
	if(pNT->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	return TRUE;
}



//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: GetPEHeader
///功  能: 获取PE头指针
// 形  参: const LPVOID & lpBuff
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
const PIMAGE_NT_HEADERS32 GetPEHeader(const LPVOID& lpBuff)
{
	return (PIMAGE_NT_HEADERS32)((PBYTE)lpBuff + ((PIMAGE_DOS_HEADER)lpBuff)->e_lfanew);
}



//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: GetOptionalHeader
///功  能: 获取扩展头的指针
// 形  参: const LPVOID & lpBuff
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
const PIMAGE_OPTIONAL_HEADER32	GetOptionalHeader(const LPVOID& lpBuff)
{
	//得到PE头
	//PIMAGE_NT_HEADERS32 pNtHead = (PIMAGE_NT_HEADERS32)((PBYTE)lpBuff + ((PIMAGE_DOS_HEADER)lpBuff)->e_lfanew);
	// 返回扩展头指针
	return	&(((PIMAGE_NT_HEADERS32)((PBYTE)lpBuff + ((PIMAGE_DOS_HEADER)lpBuff)->e_lfanew))->OptionalHeader);
}



//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: GetHeadSize
///功  能: 获取头部大小
// 形  参: const LPVOID lpFile
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
 DWORD	GetHeadSize(const LPVOID lpFile)
 {
 	PIMAGE_FILE_HEADER	pFilHea = &((NTHEADER(lpFile))->FileHeader);
 	//获取dos头大小 + 标准头大小 + 扩展头大小
 	return	(sizeof(IMAGE_DOS_HEADER)+sizeof(IMAGE_FILE_HEADER)+pFilHea->SizeOfOptionalHeader);
 }



//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: GetHeadSizeOnMem
///功  能: 获取头部在内存中的大小
// 形  参: const LPVOID lpFile
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
DWORD	GetHeadSizeOnMem(const LPVOID lpFile)
{
	DWORD	dwSize = GetHeadSize(lpFile);
	//
	// 获取内存对齐粒度
	DWORD	dwAlignment = (NTOPTIONALHEADER(lpFile))->SectionAlignment;
	//
	//检查头部是否超过了对齐粒度
	if(dwSize <= dwAlignment)
	{
		return dwAlignment-1;
	}
	//检查头部的尺寸超出了多少倍的对齐粒度
	return	 (dwSize / dwAlignment)*dwAlignment + (dwSize % dwAlignment == 0 ? 0 : dwAlignment)-1;
}

//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: GetSectionRVA
///功  能: 获取RVA在哪一个区段,返回这个区段的地址, 
///		   没有则返回NULL,返回SECTION_HEAD时指的是头部
// 形  参: const LPVOID lpFile
// 形  参: DWORD64 dwRva
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
PIMAGE_SECTION_HEADER	GetSectionRVA(const LPVOID lpFile,DWORD64 dwRva)
{

	//获取头部大小, 判断是否是在头部
	DWORD	dwSizeOfHead = GetHeadSizeOnMem(lpFile);
	//计算头部在内存中的大小

	if(dwRva >= 0 && dwRva <= dwSizeOfHead)
	{
		return (PIMAGE_SECTION_HEADER)SECTION_HEAD;
	}
	//开始遍历区段查找包含RVA地址的区段
	//获取扩展头指针
	PIMAGE_OPTIONAL_HEADER32 pOptHea = NTOPTIONALHEADER(lpFile);
	//获取标准头指针,以获取区段数目
	PIMAGE_FILE_HEADER	pFilHea = &((NTHEADER(lpFile))->FileHeader);
	//获取区段数目
	DWORD	dwSecTotal = pFilHea->NumberOfSections;
	//获取第一个区段
	PIMAGE_SECTION_HEADER	pSecList = IMAGE_FIRST_SECTION(NTHEADER(lpFile));

	//遍历区段
	for(DWORD i = 0; i < dwSecTotal; i++)
	{
		if(dwRva >= pSecList->VirtualAddress 
		   && dwRva < pSecList->VirtualAddress+pSecList->Misc.VirtualSize)
		{
			return	pSecList; /*找到区段,返回区段地址*/
		}
		++pSecList;
	}

	return NULL;
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: RVA2Offset
///功  能: RVA转Offset
// 形  参: DWORD64 dwRVA
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
DWORD64 RVA2Offset(const LPVOID lpFile,DWORD64 dwRVA)
{
	
	// 找到RVA所在的区段.
	PIMAGE_SECTION_HEADER pSecHeader =GetSectionRVA(lpFile,dwRVA);
	if(pSecHeader == NULL || (DWORD)pSecHeader == SECTION_HEAD)
	{
		return 0;
	}
	//得到偏移差
	DWORD	dwSub = dwRVA - pSecHeader->VirtualAddress;
	//再然后得到这个区段在文件中的文件偏移
	//用这个文件偏移加上RVA与区段的偏移差就是文件偏移
	//DWORD	dwVA = dwSub + pSecHeader->PointerToRawData;

	return dwSub + pSecHeader->PointerToRawData; /*偏移差 + 区段在文件中的偏移*/
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: byteArr2HexStr
///功  能: 将整形的数组转换成十六进制字符串
// 形  参: const LPBYTE lpbArr
// 形  参: DWORD dwSize
// 形  参: TCHAR * pszHexStr
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
void byteArr2HexStr(const LPBYTE& lpbArr,DWORD dwBSize,TCHAR* pszHexStr,const TCHAR wcSpace)
{
	// 一个字节转换成一个TCHAR
	DWORD	i = 0;
	char*	pszStr = (char*)pszHexStr;
	TCHAR ucNum[3] = {0};
	BYTE	byteNum = 0;
	DWORD	dwIndex = wcSpace == 0 ? 2 : 3;
	DWORD	j = 0;
	while(j<dwBSize)
	{
		byteNum = *((PBYTE)(lpbArr+j));
		// 转成字符串
		swprintf_s(pszHexStr + i,3+1,L"%02x%c",byteNum,wcSpace);
		i += dwIndex;
		++j;
	}
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: fileSize2MemSize
///功  能: 文件大小转内存大小
// 形  参: DWORD dwFileSize
// 形  参: DWORD dwAligent
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
DWORD size2AligentSize(DWORD dwFileSize,DWORD dwAligent)
{
	// 超出了多少倍的内存对齐,超出多少倍,就有多少倍内存对齐单位 ;  
	// 零头是否超出内存对齐,超出则是一个内存对齐单位
	return 
		((dwFileSize / dwAligent)*dwAligent) 
		+ 
		(dwFileSize%dwAligent > 0 ? dwAligent : 0);
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: EditSectionName
///功  能: 编辑区段名
// 形  参: const LPVOID lpFile
// 形  参: PIMAGE_SECTION_HEADER pSec 
// 形  参: const char * pszName
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
BOOL EditSectionName(PIMAGE_SECTION_HEADER pSec ,const char* pszName)
{
	// 获取区段地址
	DWORD	dwNameLen = strlen(pszName);
	if(dwNameLen > IMAGE_SIZEOF_SHORT_NAME)
	{
		return FALSE;
	}
	if(pSec->Name == NULL)return FALSE;
	return strcpy_s((char*)pSec->Name,IMAGE_SIZEOF_SHORT_NAME,pszName);
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: EditSectionName
///功  能: 编辑区段名
// 形  参: const LPVOID lpFile
// 形  参: PIMAGE_SECTION_HEADER pSec 
// 形  参: const TCHAR * pszName
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
BOOL EditSectionName(PIMAGE_SECTION_HEADER pSec ,const TCHAR* pszName)
{
	DWORD	dwNameLen = _tcslen(pszName);
	char*	pszMultiName = new char[dwNameLen+1];
	memset(pszMultiName,0,dwNameLen*sizeof(char));
	WideCharToMultiByte(CP_ACP,0,
						pszName,dwNameLen,
						pszMultiName,dwNameLen,
						NULL,NULL);
	pszMultiName[dwNameLen] = 0;
	return EditSectionName(pSec ,pszMultiName);
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: EditSectionFileSize
///功  能: 修改区段的大小(为经过文件对齐),同时会修改区段的对齐后的文件大小
// 形  参: const LPVOID lpFile
// 形  参: PIMAGE_SECTION_HEADER pSec 
// 形  参: DWORD dwSize
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
BOOL EditSectionFileSize(const LPVOID lpFile,PIMAGE_SECTION_HEADER pSec ,DWORD dwSize)
{
	// 获取区段地址
	//PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((DWORD)lpFile + dwSectionOffset);
	if(pSec == NULL)return FALSE;
	pSec->Misc.VirtualSize = dwSize;
	pSec->SizeOfRawData = size2AligentSize(dwSize,(NTOPTIONALHEADER(lpFile)->FileAlignment));
	return TRUE;
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: EditSectionFileSize
///功  能: 修改区段的大小(为经过文件对齐),同时会修改区段的对齐后的文件大小
// 形  参: const LPVOID lpFile
// 形  参: PIMAGE_SECTION_HEADER pSec 
// 形  参: TCHAR * pszSize
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
BOOL EditSectionFileSize(const LPVOID lpFile,PIMAGE_SECTION_HEADER pSec ,TCHAR* pszSize)
{
	DWORD	dwSize = 0;
	swscanf_s(pszSize,L"%x",&dwSize);
	return	EditSectionFileSize(lpFile,pSec ,dwSize);
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: EditSectionRVA
///功  能: 修改区段内存偏移
// 形  参: const LPVOID lpFile
// 形  参: PIMAGE_SECTION_HEADER pSec 
// 形  参: DWORD dwRVA
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
BOOL EditSectionRVA(PIMAGE_SECTION_HEADER pSec ,DWORD dwRVA)
{
	// 获取区段地址
	//PIMAGE_SECTION_HEADER	pSec = (PIMAGE_SECTION_HEADER)((DWORD)lpFile + dwSectionOffset);
	if(pSec == NULL)return FALSE;
	pSec->VirtualAddress = dwRVA;
	return TRUE;
}

BOOL EditSectionRVA(PIMAGE_SECTION_HEADER pSec ,TCHAR* pszRVA)
{
	if(pSec == NULL)return FALSE;
	DWORD	dwRVA = 0;
	swscanf_s(pszRVA,L"%x",&dwRVA);
	return EditSectionRVA(pSec ,dwRVA);

}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: EditSectionChara
///功  能: 区段属性
// 形  参: const LPVOID lpFile
// 形  参: PIMAGE_SECTION_HEADER pSec 
// 形  参: DWORD dwChara
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
BOOL EditSectionChara(PIMAGE_SECTION_HEADER pSec ,DWORD dwChara)
{
	// 获取区段地址
	//PIMAGE_SECTION_HEADER	pSec = (PIMAGE_SECTION_HEADER)((DWORD)lpFile + dwSectionOffset);
	if(pSec == NULL)return FALSE;
	pSec->Characteristics = dwChara;
	return TRUE;
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: EditSectionChara
///功  能: 区段属性
// 形  参: const LPVOID lpFile
// 形  参: PIMAGE_SECTION_HEADER pSec 
// 形  参: TCHAR * pszChara
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
BOOL EditSectionChara(PIMAGE_SECTION_HEADER pSec ,TCHAR* pszChara)
{
	if(pSec == NULL)return FALSE;
	DWORD	dw = 0;
	swscanf_s(pszChara,L"%x",&dw);
	return EditSectionChara(pSec ,dw);
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: EditSectionInfo
///功  能: 修改区段信息: 区段名, 区段大小(对齐和未对齐的大小),区段内存偏移,区段属性,区段文件偏移
// 形  参: const LPVOID lpFile
// 形  参: PIMAGE_SECTION_HEADER pSec
// 形  参: const TCHAR * pszName
// 形  参: DWORD dwSize
// 形  参: DWORD dwRVA
// 形  参: DWORD dwChara
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
BOOL EditSectionInfo(const LPVOID lpFile,
					 PIMAGE_SECTION_HEADER pSec,
					 const TCHAR* pszName,
					 DWORD dwSize,
					 DWORD dwRVA,
					 DWORD dwChara
					 )
{
	if(pSec == NULL)return FALSE;
	BOOL	b = FALSE;
	b= EditSectionName(pSec,pszName);
	b=EditSectionFileSize(lpFile,pSec,dwSize);
	b=EditSectionRVA(pSec,dwRVA);
	b=EditSectionChara(pSec,dwChara);
	// 根据新的内存偏移计算新文件偏移,改写
	DWORD	dwOffset = RVA2Offset(lpFile,dwRVA);
	b = EditSectionFileOffset(pSec,dwOffset);
	return TRUE;
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: EditSectionInfo
///功  能: 修改区段信息: 区段名, 区段大小(对齐和未对齐的大小),区段内存偏移,区段属性,区段文件偏移
// 形  参: const LPVOID lpFile
// 形  参: PIMAGE_SECTION_HEADER pSec
// 形  参: const char * pszName
// 形  参: TCHAR * pszSize
// 形  参: TCHAR * pszRVA
// 形  参: TCHAR * pszChara
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
BOOL EditSectionInfo(const LPVOID lpFile, // PE文件read进内存的指针
					 PIMAGE_SECTION_HEADER pSec, // 要修改的区段头指针
					 const char* pszName, // 区段名
					 TCHAR* pszSize, // 区段大小(未对齐)
					 TCHAR* pszRVA, // 区段内存偏移
					 TCHAR* pszChara// 区段属性
					 )
{
	if(pSec == NULL)return FALSE;
	BOOL	b = FALSE;
	b = EditSectionName(pSec,pszName);
	b = EditSectionFileSize(lpFile,pSec,pszSize);
	b = EditSectionRVA(pSec,pszRVA);
	b = EditSectionChara(pSec,pszChara);
	// 根据新的内存偏移计算新文件偏移,改写

	DWORD	dwRVA = 0;
	swscanf_s(pszRVA,L"%x",&pSec->PointerToRawData);
	return TRUE;
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: EditSectionFileOffset
///功  能: 修改区段的文件偏移
// 形  参: PIMAGE_SECTION_HEADER pSec
// 形  参: DWORD dwOffset
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
BOOL EditSectionFileOffset(PIMAGE_SECTION_HEADER pSec,DWORD dwOffset)
{
	if(pSec == NULL)return FALSE;
	pSec->PointerToRawData = dwOffset;
	return TRUE;
}

BOOL EditSectionFileOffset(PIMAGE_SECTION_HEADER pSec,TCHAR* pszOffset)
{
	if(pSec == NULL)return FALSE;
	DWORD	dw = 0;
	swscanf_s(pszOffset,L"%x",&dw);
	return	EditSectionFileOffset(pSec,dw);
}

DWORD GetHeaderSize(const LPBYTE lpFile )
{
	return ((PIMAGE_DOS_HEADER)lpFile)->e_lfanew//dos 大小
		+ sizeof(IMAGE_FILE_HEADER) +sizeof(DWORD) // 文件头大小
		+(NTHEADER(lpFile))->FileHeader.SizeOfOptionalHeader;//扩展头
}

void	datacpy(LPBYTE lpDes,const LPBYTE lpSrc,DWORD64 dw64Size)
{
	DWORD64 i = 0;
	while (i<dw64Size)
	{
		lpDes[i] = lpSrc[i];
		++i;
	}
}

//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: AddSection
///功  能: 成功时返回新区段的指针,失败返回NULL
// 形  参: _Inout_ LPBYTE lpFile
// 形  参: _Out_ PIMAGE_SECTION_HEADER pNewSection
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
PIMAGE_SECTION_HEADER	AddSection(_Inout_ LPBYTE& lpFile,
								   _Inout_ DWORD& dwSize,
								   const  TCHAR* pszName,
								   DWORD	dwNameLen,
								   DWORD	dwSecSize,
                                   unsigned char *newSection
								   )
{

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	// 获取nt头
	// 获取扩展nt头
	PIMAGE_FILE_HEADER		pFileNt = &(NTHEADER(lpFile))->FileHeader;
	PIMAGE_OPTIONAL_HEADER	pOptNt = NTOPTIONALHEADER(lpFile);
	// 获取对齐后的区段描述表对齐后的总大小
	DWORD	dwAligentSectionSize = pOptNt->SizeOfHeaders;
	// 得到所有区段描述表的实际占用字节数
	DWORD	dwLengthOfAllSection = pFileNt->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	// 判断是否有空间容纳新的区段描述表
	if((dwLengthOfAllSection + sizeof(IMAGE_SECTION_HEADER) <= dwAligentSectionSize))
	{
		// 1. 修改PE标准文件头的Numberofsection +1 
		// 2. 修改PE扩展头的SizeofImage 增加一个内存对齐粒度
		// 3. 找打最后一个区段描述表
		//		3.1 修改Misc.Virtualaddress 为一个内存对齐粒度
		//		3.2	修改SizeOfRawData 0x200(实际大小文件对齐后的大小)
		//		3.3	修改PointerToRawData 为上一个PointerToRawData+Pointer +SizeOfRawData的位置
		//		3.3	修改VirtualAddress 为上一个VirtualAddress+SizeOfRawData 内存对齐后的位置
		// 有空间
		//在最后一个全段描述表末尾添加一个新的区段描述表
		PIMAGE_SECTION_HEADER	pNewSection = &(IMAGE_FIRST_SECTION(NTHEADER(lpFile))[pFileNt->NumberOfSections]);
		/// 修改新的区段的读数
		// 修改区段名
		WideCharToMultiByte(CP_ACP,0,
							pszName,dwNameLen,
							(char*)pNewSection->Name,dwNameLen,
							NULL,NULL);
		pNewSection->Name[dwNameLen] = 0;
		pNewSection->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;
		// 修改大小
		pNewSection->Misc.VirtualSize = size2AligentSize(dwSecSize,pOptNt->SectionAlignment);
		// 修改区段文件对齐后文件大小
		pNewSection->SizeOfRawData = size2AligentSize(dwSecSize,pOptNt->FileAlignment);
		// 修改区段的位置
		PIMAGE_SECTION_HEADER pOldSec = &(IMAGE_FIRST_SECTION(NTHEADER(lpFile))[pFileNt->NumberOfSections - 1]);
		pNewSection->PointerToRawData = pOldSec->PointerToRawData + pOldSec->SizeOfRawData;
		// 修改区段的RVA
		pNewSection->VirtualAddress = size2AligentSize(pOldSec->VirtualAddress + pOldSec->SizeOfRawData,pOptNt->SectionAlignment);

		// 增加一个区段描述表计数
		++pFileNt->NumberOfSections;
		// 增加映像大小为新增区段大小内存对齐后的大小
		pOptNt->SizeOfImage += size2AligentSize(dwSecSize,pOptNt->SectionAlignment);
		/// 申请空间追加新增的区段
		DWORD	dwSecAligSize = size2AligentSize(dwSecSize,pOptNt->FileAlignment);
		LPBYTE lpNewFile = new BYTE[dwSize + dwSecAligSize];
		//memset(lpNewFile,0,dwSize + dwSecAligSize);
		// 将原有内容拷贝回去
		memcpy_s(lpNewFile,dwSize + dwSecAligSize,lpFile,dwSize);
		memset(lpNewFile + dwSize, 0, dwSecAligSize);
		memcpy_s(lpNewFile + dwSize, dwSecAligSize, newSection, dwSecSize);
		delete[]	lpFile;
		lpFile = lpNewFile;
		dwSize += dwSecAligSize;
		return pNewSection;

	}
	return	NULL;
}



//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: GetLastSection
///功  能: 获取最后一个区段描述表的指针
// 形  参: const LPBYTE lpFile
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
PIMAGE_SECTION_HEADER GetLastSection(const LPBYTE lpFile)
{
	PIMAGE_FILE_HEADER		pFileNt = &(NTHEADER(lpFile))->FileHeader;
	return &(IMAGE_FIRST_SECTION(NTHEADER(lpFile))[pFileNt->NumberOfSections - 1]);
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: DeleteSection
///功  能: 删除指定位置的区段
// 形  参: LPBYTE & lpFile 读进内存的PE文件
// 形  参: DWORD & dwSize PE文件的字节数
// 形  参: DWORD dwIndex 要删除的区段在区段描述表的索引值
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
BOOL DeleteSection(LPBYTE& lpFile,DWORD& dwSize,DWORD dwIndex)
{
	/*
		*	要删除的地方
		*	1.	区段描述表
		*		|---1.	将下一个的区段描述表往前移动,并修改前移的区段描述表所指向的区块的文件偏移和RVA
		*			|---1.	区块文件偏移等于上一个(被删除的区块的上一个)的文件偏移+sizeOfRawDatas
		*			|---	2.	RVA等于上一个(被删除的区块的上一个)的RVA + sizeOfRawData的内存对齐值
		*	2.	区段描述表所指向的区块
		*	要改变的值
		*	1.	映像大小
		*	2.	NT文件头NumberOfSection的区段计数
		2
		*/
	PIMAGE_FILE_HEADER		pFileNt = &(NTHEADER(lpFile))->FileHeader;
	DWORD dwTotal = pFileNt->NumberOfSections;
	if(dwIndex >= dwTotal)
	{
		return FALSE;
	}
	// 保存被删除的描述表所描述的区块的文件偏移,RVA,大小
	PIMAGE_SECTION_HEADER pSec = &(IMAGE_FIRST_SECTION(NTHEADER(lpFile))[dwIndex]);

	DWORD	dwLastOffset = pSec->PointerToRawData;
	DWORD	dwLastRVA = pSec->VirtualAddress;
	DWORD	dwLastSize = pSec->SizeOfRawData;
	
	DWORD	dwSecSize = sizeof(IMAGE_SECTION_HEADER);
	dwTotal -= dwIndex;
	// 移动区块描述表
	for(int i = 0; i < dwTotal; ++i)
	{
		memcpy_s(pSec,dwSecSize,pSec + 1,dwSecSize);
		++pSec;
	}
	dwTotal = --pFileNt->NumberOfSections ;
	// 将区段描述表描述的区块所在的位置进行迁移.

	pSec = &(IMAGE_FIRST_SECTION(NTHEADER(lpFile))[dwIndex]);
	// 删除最后一个区段描述时,将sizeofImage改变,并刷新PE文件数据就可以
	if(dwIndex == dwTotal)
	{
		PIMAGE_OPTIONAL_HEADER popt= NTOPTIONALHEADER(lpFile);
		popt->SizeOfImage -= size2AligentSize(dwLastSize,popt->SectionAlignment);
		dwSize -= dwLastSize;
		LPBYTE	lpNewFile = new BYTE[dwSize];
		memcpy_s(lpNewFile,dwSize,lpFile,dwSize);
		delete[]	lpFile;
		lpFile = lpNewFile;
		return TRUE;
	}
	// 不是最后一个需要把剩余的区段的数据剪切到被删除的区段的空间
	pSec = (IMAGE_FIRST_SECTION(NTHEADER(lpFile)));
	for (int i=dwIndex;i<dwTotal;++i)
	{
		//将区段描述表指向的的区块迁移到被删除的区块的开始位置
		memcpy(lpFile + dwLastOffset,lpFile + pSec[i].PointerToRawData,pSec[i].SizeOfRawData);
		DWORD	dwTempOffset = dwLastOffset;
		DWORD	dwTempRVA = dwLastRVA;
		dwLastOffset = pSec[i].PointerToRawData + pSec[i].SizeOfRawData;
		dwLastRVA = pSec[i].VirtualAddress;

		// 修改迁移区段描述表的PointToRawData,VirtualAddress
		pSec[i].PointerToRawData = dwTempOffset;
		pSec[i].VirtualAddress = dwTempRVA;
	}
	// 修改镜像大小
	PIMAGE_OPTIONAL_HEADER popt = NTOPTIONALHEADER(lpFile);
	popt->SizeOfImage -= size2AligentSize(dwLastSize,popt->SectionAlignment);
	// 申请新空间保存新的PE文件数据
	dwSize -= dwLastSize;
	LPBYTE	lpNewFile = new BYTE[dwSize];
	memcpy_s(lpNewFile,dwSize,lpFile,dwSize);
	delete[]	lpFile;
	lpFile = lpNewFile;
	return TRUE;				
}


//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
// 函数名: GetSection
///功  能: 获取指定区段
// 形  参: DWORD dwIndwx
//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
PIMAGE_SECTION_HEADER GetSection(const LPBYTE lpFile,DWORD dwIndwx)
{
	PIMAGE_FILE_HEADER		pFileNt = &(NTHEADER(lpFile))->FileHeader;
	if(pFileNt->NumberOfSections < dwIndwx)
	{
		return NULL;
	}
	return &(IMAGE_FIRST_SECTION(NTHEADER(lpFile))[dwIndwx]);
}
