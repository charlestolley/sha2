#include <stdio.h>
#include "rotate.h"

int rrotate(unsigned int x, int n)
{
	n %= INT_SIZE_BITS;
	int result = (x << (INT_SIZE_BITS - n)) | (x >> n);
	/*printf("n=%d\t%08x : %08x\n", n, x, result);*/
	return result;
}

int lrotate(unsigned int x, int n)
{
	n %= INT_SIZE_BITS;
	return (x >> (INT_SIZE_BITS - n)) | (x << n);
}
