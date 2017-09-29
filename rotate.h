#ifndef _ROTATE_H
#define _ROTATE_H 1

#define INT_SIZE_BITS 8*sizeof(int)

/* in these macros, x is unsigned int, n >= 0 (and ideally n < INT_SIZE_BITS) */
#define RROTATE(x, n) ((x << (INT_SIZE_BITS - n)) | (x >> n))
#define LROTATE(x, n) ((x >> (INT_SIZE_BITS - n)) | (x << n))

int rrotate(unsigned int x, unsigned int n);
int lrotate(unsigned int x, unsigned int n);
#endif
