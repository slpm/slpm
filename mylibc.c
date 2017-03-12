#include <string.h>
#include <termios.h>
#include <sys/ioctl.h>

void*
memchr(const void* s, int c, size_t n)
{
	char* p = (char*)s;
	for (char* q = p; q != p + n; ++q) {
		if (*q == c) return q;
	}
	return 0;
}

int
isatty(int fd)
{
	struct termios t;
	return !ioctl(fd, TCGETS, &t);
}

size_t
strlen(const char* s)
{
	const char* p = s;
	while (*p) ++p;
	return p - s;
}

int
strcmp(const char* s1, const char* s2)
{
	for (; *s1 || *s2; ++s1, ++s2) {
		if (!*s1 ^ !*s2) return *s2 ? -1 : 1;
		if (*s1 < *s2) return -1;
		if (*s2 < *s1) return 1;
	}
	return 0;
}

int
strncmp(const char* s1, const char* s2, size_t n)
{
	for (; n && (*s1 || *s2); ++s1, ++s2, --n) {
		if (!*s1 ^ !*s2) return *s2 ? -1 : 1;
		if (*s1 < *s2) return -1;
		if (*s2 < *s1) return 1;
	}
	return 0;
}

char*
strncpy(char* dest, const char* src, size_t n)
{
	size_t i;

	for (i = 0; i < n && src[i] != '\0'; ++i) {
		dest[i] = src[i];
	}
	for (; i < n; ++i) {
		dest[i] = '\0';
	}

	return dest;
}

int
atoi(const char* nptr)
{
	int result = 0;
	for (; nptr && *nptr >= '0' && *nptr <= '9'; ++nptr) {
		result = result * 10 + *nptr - '0';
	}
	return result;
}

int *
__errno_location(void)
{
	static int e = 0;
	return &e;
}
