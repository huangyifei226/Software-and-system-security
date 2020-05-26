#include<stdio.h>
#include<stdlib.h>

int main()
{
	int i = 0, anum;
	char *p;

	p = (char *)malloc(100);  //只分配100个字节的空间
	if (p)
		printf("Memory Allocated at: %x\n", p);
	else
		printf("Not Enough Memory!\n");
	for (i = 0; i<4096; i++)
	{
		p[i] = 'a';
	}
	anum = i;
	printf("共写入%d字节\n", anum);
	
	for (i = 0; i<4096; i++)
	{
		if (p[i] != 'a')
		{
			anum--;
		}
	}
	printf("共%d字节读取正确\n", anum);

	free(p);
	return 0;
}