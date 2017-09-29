#ifndef _SHA2_H
#define _SHA2_H 1

#include <stdlib.h>
#include "rotate.h"

typedef enum {
	SHA224, /*requires 28 bytes*/
	SHA256 /*requires 32 bytes*/
} hash_alg;

extern const unsigned int k[];

/*takes a char array of size 4 big endian and stores it to an int*/
static inline unsigned int ctoi(const unsigned char * const);

/* turns integer to big-endian char[4]*/
static inline void itoc(unsigned int, char * const);

/* stores a long to big-endian char[8]*/
static inline void ltoc(unsigned long, char * const);

/*hash must be an array of at least the size specified for h (see hash_alg typedef)*/
void sha2(const unsigned char * const, const unsigned long, unsigned char * const, hash_alg);
#endif