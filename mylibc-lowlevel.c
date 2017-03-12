#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <linux/net.h>

// http://stackoverflow.com/a/9508738

#if __i386__
ssize_t
write(int fd, const void* buf, size_t count)
{
	ssize_t result;
	__asm__ volatile(
		"int $0x80"
		: "=a" (result)
		: "0" (4), "b" (fd), "c" (buf), "d" (count)
		: "cc", "edi", "esi", "memory"
	);
	return result;
}

ssize_t
read(int fd, void* buf, size_t count)
{
	ssize_t result;
	__asm__ volatile(
		"int $0x80"
		: "=a" (result)
		: "0" (3), "b" (fd), "c" (buf), "d" (count)
		: "cc", "edi", "esi", "memory"
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
	__asm__ volatile(
		"int $0x80"
		: "=a" (result)
		: "a" (0x5a), "b" (&arg)
		: "cc", "ecx", "edx", "edi", "esi", "memory"
	);
	return result;
}

int
munmap(void *addr, size_t length)
{
	int result;
	__asm__ volatile(
		"int $0x80"
		: "=a" (result)
		: "a" (0x5b), "b" (addr), "c" (length)
		: "cc", "edx", "edi", "esi", "memory"
	);
	return result;
}

void
__attribute__ ((noreturn))
_exit(int status)
{
	__asm__ volatile(
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
	__asm__ volatile(
		"int $0x80"
		: "=a" (result)
		: "a" (5), "b" (pathname), "c" (flags), "d" (mode)
		: "cc", "edi", "esi", "memory"
	);
	return result;
}

int
close(int fd)
{
	int result;
	__asm__ volatile(
		"int $0x80"
		: "=a" (result)
		: "a" (6), "b" (fd)
		: "cc", "ecx", "edx", "edi", "esi"
	);
	return result;
}

int
ioctl(int fd, unsigned long request, unsigned long arg)
{
	int result;
	__asm__ volatile(
		"int $0x80"
		: "=a" (result)
		: "a" (0x36), "b" (fd), "c" (request), "d" (arg)
		: "cc", "edi", "esi", "memory"
	);
	return result;
}

int
socketcall(int call, unsigned long* args)
{
	int result;
	__asm__ volatile(
		"int $0x80"
		: "=a" (result)
		: "a" (0x66), "b" (call), "c" (args)
		: "cc", "edx", "edi", "esi", "memory"
	);
	return result;
}

int
socket(int domain, int type, int protocol)
{
	unsigned long args[] = { domain, type, protocol };
	return socketcall(SYS_SOCKET, args);
}

int
connect(int sockfd, const struct sockaddr *addr, size_t addrlen)
{
	unsigned long args[] = { sockfd, (unsigned long)addr, addrlen };
	return socketcall(SYS_CONNECT, args);
}

#endif // __i386__

void*
__memcpy_chk(void *dstpp, const void *srcpp, size_t len, size_t dstlen)
{
	if (dstlen < len) _exit(1);
	char* dp = dstpp;
	const char* sp = srcpp;
	for (; len; --len) *dp++ = *sp++;
	return dstpp;
}
