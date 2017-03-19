#include <sodium/utils.h>

void
sodium_memzero(void * const pnt, const size_t len)
{
	volatile unsigned char *volatile pnt_ =
		(volatile unsigned char * volatile)pnt;
	size_t i = (size_t) 0U;

	while (i < len) pnt_[i++] = 0U;
}

int
sodium_memcmp(const void * const b1_, const void * const b2_, size_t len)
{
	const volatile unsigned char *volatile b1 = (const volatile unsigned char * volatile) b1_;
	const volatile unsigned char *volatile b2 = (const volatile unsigned char * volatile) b2_;
	size_t i;
	unsigned char d = (unsigned char) 0U;

	for (i = 0U; i < len; i++) {
		d |= b1[i] ^ b2[i];
	}
	return (1 & ((d - 1) >> 8)) - 1;
}
