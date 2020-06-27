#include<stdio.h>
#include<windows.h>

int main()
{
	LPVOID lpvBase;	// Base address of the test memory
	LPTSTR lpPtr;
	SYSTEM_INFO sSysInfo;	// Useful information about the system

	GetSystemInfo(&sSysInfo);
	DWORD dwPageSize = sSysInfo.dwPageSize;

	lpvBase = VirtualAlloc(
		(LPVOID)0x60000000,	// The starting address of the region to allocate
		dwPageSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	lpPtr = (LPTSTR)lpvBase;
	for (DWORD i = 0; i < dwPageSize; i++)
	{
		lpPtr[i] = 'a'; // ProjectA 使用字符a，ProjectB 使用字符b
		printf("%c", lpPtr[i]);
	}
	VirtualFree(lpvBase, 0, MEM_RELEASE);
	return 0;
}