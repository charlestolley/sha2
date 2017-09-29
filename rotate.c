#include <stdio.h>
#include "rotate.h"

int rrotate(unsigned int x, unsigned int n)
{
	n %= INT_SIZE_BITS;
	return (x << (INT_SIZE_BITS - n)) | (x >> n);
}

int lrotate(unsigned int x, unsigned int n)
{
	n %= INT_SIZE_BITS;
	return (x >> (INT_SIZE_BITS - n)) | (x << n);
}
