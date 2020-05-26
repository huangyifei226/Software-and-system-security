#include <windows.h>
#include<stdio.h>
void main()
{
	SYSTEM_INFO sf;
	GetSystemInfo(&sf);
	//分配内存，标记为提交、可读可写
	LPVOID lpvBase = VirtualAlloc(
		NULL,                 // system selects address
		4096,     // size of allocation
		MEM_COMMIT,   // allocate reserved pages
		PAGE_READWRITE);       // protection = no access
	if (lpvBase == NULL)
		return;

	//向该内存里面写些东西
	unsigned char *ustr = (unsigned char *)lpvBase;
	ustr[0] = 0x89;

	//修改为“只读”属性，验证是否能写入
	DWORD dw;
	VirtualProtect(lpvBase, 4096, PAGE_READONLY, &dw);
	// ustr[0]=0x44; //失败

	//修改为“不可访问”，验证是否能读出
	VirtualProtect(lpvBase, 4096, PAGE_NOACCESS, &dw);
	// dw = ustr[0]; //失败
	bool flag = VirtualFree(lpvBase, 4096, MEM_DECOMMIT);
	if (flag == TRUE)
	{
		printf("释放成功！\n");
	}
	else
	{
		printf("释放失败！\n");
	}
	// ustr[0]=0x44; //失败
	return;
}