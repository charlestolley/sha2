#include "./string.h"

size_t strlen(const char * const str)
{
	const char * temp = str;
	while(*temp)
		++temp;
	return temp - str;
}
