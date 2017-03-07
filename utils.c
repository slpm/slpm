#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stddef.h>

void*
__memcpy_chk(void *dstpp, const void *srcpp, size_t len, size_t dstlen)
{
	if (dstlen < len) _exit(1);
	char* dp = dstpp;
	const char* sp = srcpp;
	for (; len; --len) *dp++ = *sp++;
	return dstpp;
}

#if __i386__
ssize_t
write(int fd, const void* buf, size_t count)
{
	ssize_t result;
	__asm__(
		"int $0x80"
		: "=a" (result)
		: "a" (4), "b" (fd), "c" (buf), "d" (count)
	);
	return result;
}

ssize_t
read(int fd, void* buf, size_t count)
{
	ssize_t result;
	__asm__(
		"int $0x80"
		: "=a" (result)
		: "a" (3), "b" (fd), "c" (buf), "d" (count)
	);
	return result;
}

struct mmap_arg_struct {
	uint32_t addr;
	uint32_t len;
	uint32_t prot;
	uint32_t flags;
	uint32_t fd;
	uint32_t offset;
} __attribute__((packed));

void*
mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	struct mmap_arg_struct arg = { (uint32_t)addr, length, prot, flags, fd, offset };
	void* result;
	__asm__(
		"int $0x80"
		: "=a" (result)
		: "a" (0x5a), "b" (&arg)
		: "memory"
	);
	return result;
}

int
munmap(void *addr, size_t length)
{
	int result;
	__asm__(
		"int $0x80"
		: "=a" (result)
		: "a" (0x5b), "b" (addr), "c" (length)
	);
	return result;
}

void
__attribute__ ((noreturn))
_exit(int status)
{
	__asm__(
		"int $0x80"
		:
		: "a" (1), "b" (status)
	);
	__builtin_unreachable();
}

int
open(const char* pathname, int flags, int mode)
{
	int result;
	__asm__(
		"int $0x80"
		: "=a" (result)
		: "a" (5), "b" (pathname), "c" (flags), "d" (mode)
	);
	return result;
}

int
close(int fd)
{
	int result;
	__asm__(
		"int $0x80"
		: "=a" (result)
		: "a" (6), "b" (fd)
	);
	return result;
}

int
ioctl(int fd, unsigned long request, unsigned long arg)
{
	int result;
	__asm__(
		"int $0x80"
		: "=a" (result)
		: "a" (0x36), "b" (fd), "c" (request), "d" (arg)
	);
	return result;
}

#endif // __i386__
