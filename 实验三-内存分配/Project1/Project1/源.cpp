#include<stdio.h>
#include<stdlib.h>

int main()
{
	int i = 0, anum;
	char *p;

	p = (char *)malloc(100);  //ֻ����100���ֽڵĿռ�
	if (p)
		printf("Memory Allocated at: %x\n", p);
	else
		printf("Not Enough Memory!\n");
	for (i = 0; i<4096; i++)
	{
		p[i] = 'a';
	}
	anum = i;
	printf("��д��%d�ֽ�\n", anum);
	
	for (i = 0; i<4096; i++)
	{
		if (p[i] != 'a')
		{
			anum--;
		}
	}
	printf("��%d�ֽڶ�ȡ��ȷ\n", anum);

	free(p);
	return 0;
}