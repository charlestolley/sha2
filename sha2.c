#include <stdint.h>
#include "sha2.h"

#define INT_SIZE_BITS (8*sizeof(uint32_t))

/* in these macros, x is uint32_t, n >= 0 (and ideally n < INT_SIZE_BITS) */
#define RROTATE(x, n) ((x << (INT_SIZE_BITS - n)) | (x >> n))
#define LROTATE(x, n) ((x >> (INT_SIZE_BITS - n)) | (x << n))

const uint32_t k[] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* takes a big-endian uint8_t array of size 4 and stores it to a uint32_t */
static inline uint32_t ctoi(const uint8_t * const c)
{
	return c[0] << 24 | c[1] << 16 | c[2] << 8 | c[3];
}

/* turns uint32_t to big-endian uint8_t[4] */
static inline void itoc(uint32_t i, uint8_t * const c)
{
	c[0] = (uint8_t) (i >> 24);
	c[1] = (uint8_t) (i >> 16);
	c[2] = (uint8_t) (i >> 8);
	c[3] = (uint8_t) i;
}

/* stores a uint64_t to big-endian uint8_t[8] */
static inline void ltoc(uint64_t l, uint8_t * const c)
{
	c[0] = (uint8_t) (l >> 56);
	c[1] = (uint8_t) (l >> 48);
	c[2] = (uint8_t) (l >> 40);
	c[3] = (uint8_t) (l >> 32);
	c[4] = (uint8_t) (l >> 24);
	c[5] = (uint8_t) (l >> 16);
	c[6] = (uint8_t) (l >> 8);
	c[7] = (uint8_t) l;
}

void sha2(const uint8_t * const msg, const uint64_t len, uint8_t * const dest, sha2_algorithm_t alg)
{
	uint32_t H[8];
	uint32_t w[64];
	uint8_t tail[128];

	uint32_t i, j;
	const uint64_t l = 8 * len;

	const uint32_t excess = len % 64;
	const uint8_t * const blocks_end = msg + len - excess;

	const uint8_t * temp = msg;
	const uint32_t TAIL_SIZE = excess > 55 ? 128 : 64;

	switch (alg) {
	case SHA224:
		H[0] = 0xc1059ed8;
		H[1] = 0x367cd507;
		H[2] = 0x3070dd17;
		H[3] = 0xf70e5939;
		H[4] = 0xffc00b31;
		H[5] = 0x68581511;
		H[6] = 0x64f98fa7;
		H[7] = 0xbefa4fa4;
		break;

	case SHA256:
		H[0] = 0x6a09e667;
		H[1] = 0xbb67ae85;
		H[2] = 0x3c6ef372;
		H[3] = 0xa54ff53a;
		H[4] = 0x510e527f;
		H[5] = 0x9b05688c;
		H[6] = 0x1f83d9ab;
		H[7] = 0x5be0cd19;
		break;

	default:
		return;
	}

	while (temp != tail + TAIL_SIZE)
	{
		if (temp == blocks_end)
		{
			uint8_t* tail_tmp = tail;
			uint8_t* const l_ptr = tail + TAIL_SIZE - 8;
			uint32_t count = 0;
			while(count++ < excess)
				*tail_tmp++ = *temp++;
			*tail_tmp++ = 0x80;
			while (tail_tmp < l_ptr)
				*tail_tmp++ = 0;
			ltoc(l, l_ptr);
			temp = tail;
		}
		for (i = 0; i < 16; ++i)
		{
			w[i] = ctoi(temp);
			temp += 4;
		}
		for (; i < 64; ++i)
		{
			uint32_t s0 = RROTATE(w[i-15], 7) ^ RROTATE(w[i-15], 18) ^ (w[i-15] >> 3);
			uint32_t s1 = RROTATE(w[i-2], 17) ^ RROTATE(w[i-2], 19) ^ (w[i-2] >> 10);
			w[i] = w[i-16] + s0 + w[i-7] + s1;
		}

		uint32_t a = H[0];
		uint32_t b = H[1];
		uint32_t c = H[2];
		uint32_t d = H[3];
		uint32_t e = H[4];
		uint32_t f = H[5];
		uint32_t g = H[6];
		uint32_t h = H[7];

		for (i = 0; i < 64; ++i)
		{
			uint32_t s1 = RROTATE(e, 6) ^ RROTATE(e, 11) ^ RROTATE(e, 25);
			uint32_t ch = (e & f) ^ ((~e) & g);
			uint32_t temp1 = h + s1 + ch + k[i] + w[i];
			uint32_t s0 = RROTATE(a, 2) ^ RROTATE(a, 13) ^ RROTATE(a, 22);
			uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint32_t temp2 = s0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;
	}

	for (i=0, j=0; j < alg; i++, j+=sizeof(uint32_t)) {
		itoc(H[i], dest+j);
	}
}
