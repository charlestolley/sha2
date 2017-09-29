#include "sha2.h"

const unsigned int k[] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline unsigned int ctoi(const unsigned char * const c)
{
	return c[0] << 24 | c[1] << 16 | c[2] << 8 | c[3];
}

static inline void itoc(unsigned int i, char * const c)
{
	c[0] = (char) (i >> 24);
	c[1] = (char) (i >> 16);
	c[2] = (char) (i >> 8);
	c[3] = (char) i;
}

static inline void ltoc(unsigned long l, char * const c)
{
	c[0] = (char) (l >> 56);
	c[1] = (char) (l >> 48);
	c[2] = (char) (l >> 40);
	c[3] = (char) (l >> 32);
	c[4] = (char) (l >> 24);
	c[5] = (char) (l >> 16);
	c[6] = (char) (l >> 8);
	c[7] = (char) l;
}

void sha2(const unsigned char * const msg, const unsigned long len, unsigned char * const hash, hash_alg h)
{
	unsigned int h0;
	unsigned int h1;
	unsigned int h2;
	unsigned int h3;
	unsigned int h4;
	unsigned int h5;
	unsigned int h6;
	unsigned int h7;

	if (h == SHA224)
	{
		h0 = 0xc1059ed8;
		h1 = 0x367cd507;
		h2 = 0x3070dd17;
		h3 = 0xf70e5939;
		h4 = 0xffc00b31;
		h5 = 0x68581511;
		h6 = 0x64f98fa7;
		h7 = 0xbefa4fa4;
	}
	else if (h == SHA256)
	{
		h0 = 0x6a09e667;
		h1 = 0xbb67ae85;
		h2 = 0x3c6ef372;
		h3 = 0xa54ff53a;
		h4 = 0x510e527f;
		h5 = 0x9b05688c;
		h6 = 0x1f83d9ab;
		h7 = 0x5be0cd19;
	}
	else
	{
		return;
	}

	unsigned int w[64];
	unsigned char tail[128];

	const unsigned long l = 8 * len;

	const unsigned int excess = len % 64;
	const unsigned char * const blocks_end = msg + len - excess;

	const unsigned char * temp = msg;
	const unsigned int TAIL_SIZE = excess > 55 ? 128 : 64;

	unsigned int i;

	while (temp != tail + TAIL_SIZE)
	{
		if (temp == blocks_end)
		{
			char* tail_tmp = tail;
			char* const l_ptr = tail + TAIL_SIZE - 8;
			while(*temp)
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
			unsigned int s0 = rrotate(w[i-15], 7) ^ rrotate(w[i-15], 18) ^ (w[i-15] >> 3);
			unsigned int s1 = rrotate(w[i-2], 17) ^ rrotate(w[i-2], 19) ^ (w[i-2] >> 10);
			w[i] = w[i-16] + s0 + w[i-7] + s1;
		}

		unsigned int a = h0;
		unsigned int b = h1;
		unsigned int c = h2;
		unsigned int d = h3;
		unsigned int e = h4;
		unsigned int f = h5;
		unsigned int g = h6;
		unsigned int h = h7;

		for (i = 0; i < 64; ++i)
		{
			unsigned int s1 = rrotate(e, 6) ^ rrotate(e, 11) ^ rrotate(e, 25);
			unsigned int ch = (e & f) ^ ((~e) & g);
			unsigned int temp1 = h + s1 + ch + k[i] + w[i];
			unsigned int s0 = rrotate(a, 2) ^ rrotate(a, 13) ^ rrotate(a, 22);
			unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
			unsigned int temp2 = s0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}
	itoc(h0, hash);
	itoc(h1, hash + 4);
	itoc(h2, hash + 8);
	itoc(h3, hash + 12);
	itoc(h4, hash + 16);
	itoc(h5, hash + 20);
	itoc(h6, hash + 24);
	if (h == SHA256)
		itoc(h7, hash + 28);
}
