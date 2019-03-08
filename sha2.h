#ifdef _SHA2_H
#define _SHA2_H

typedef enum {
	SHA224=28,
	SHA256=32,
} sha2_algorithm_t;

/* dest must be an array of at least the size specified for the given algorithm */
/* it is also safe to store the output to the same location as the input */
/* ie. sha2(arr, len, arr, alg) */
void sha2(const unsigned char * const msg, const unsigned long len,
				unsigned char * const dest, sha2_algorithm_t alg);

#endif
