#include <windows.h>
#include<stdio.h>
void main()
{
	SYSTEM_INFO sf;
	GetSystemInfo(&sf);
	//�����ڴ棬���Ϊ�ύ���ɶ���д
	LPVOID lpvBase = VirtualAlloc(
		NULL,                 // system selects address
		4096,     // size of allocation
		MEM_COMMIT,   // allocate reserved pages
		PAGE_READWRITE);       // protection = no access
	if (lpvBase == NULL)
		return;

	//����ڴ�����дЩ����
	unsigned char *ustr = (unsigned char *)lpvBase;
	ustr[0] = 0x89;

	//�޸�Ϊ��ֻ�������ԣ���֤�Ƿ���д��
	DWORD dw;
	VirtualProtect(lpvBase, 4096, PAGE_READONLY, &dw);
	// ustr[0]=0x44; //ʧ��

	//�޸�Ϊ�����ɷ��ʡ�����֤�Ƿ��ܶ���
	VirtualProtect(lpvBase, 4096, PAGE_NOACCESS, &dw);
	// dw = ustr[0]; //ʧ��
	bool flag = VirtualFree(lpvBase, 4096, MEM_DECOMMIT);
	if (flag == TRUE)
	{
		printf("�ͷųɹ���\n");
	}
	else
	{
		printf("�ͷ�ʧ�ܣ�\n");
	}
	// ustr[0]=0x44; //ʧ��
	return;
}