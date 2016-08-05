#include "header.h"
/*
* modify strcpy function.
*/
void mystrcpy(unsigned char *dest, unsigned char *src)
{
	int index = 0;
	// 원본이 NULL 이거나 대상이 NULL 이면 종료

	if (!src || !dest) exit(1);
	while ((*(src + index) != 13)){
		*(dest + index) = *(src + index);
		index++;

	}
	*(dest + index) = '\n';
	*(dest + index) = '\0';
}

/*
* modify strstr function.
*/
char *findStr(unsigned char *str1, char *str2)
{
	char *cp = (char *)str1;
	char *s1, *s2;

	if (!*str2) return (char *)str1;

	while (*cp)
	{
		s1 = cp;
		s2 = (char *)str2;

		while (*s1 && *s2 && !(*s1 - *s2)) s1++, s2++;
		if (!*s2) return cp;
		cp++;
	}
}
