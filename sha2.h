#ifndef _SHA2_H
#define _SHA2_H 1

#include <stdlib.h>
#include "rotate.h"

#define SHA224_LENGTH 28
#define SHA256_LENGTH 32

typedef enum {
	SHA224,
	SHA256
} hash_alg;

extern const unsigned int k[];

/* takes a char array of size 4 big endian and stores it to an int */
static inline unsigned int ctoi(const unsigned char * const);

/* turns integer to big-endian char[4] */
static inline void itoc(unsigned int, char * const);

/* stores a long to big-endian char[8] */
static inline void ltoc(unsigned long, char * const);

/* dest must be an array of at least the size specified for the given algorithm */
/* it is also safe to store the output to the same location as the input */
/* ie. sha2(arr, len, arr, alg) */
void sha2(const unsigned char * const msg, const unsigned long len,
				unsigned char * const dest, hash_alg h);
#endif
