#include "utils.h"

#include <cstring>
#include <cstdlib>

ssize_t
writes(int fd, const char* s)
{
	return write(fd, s, std::strlen(s));
}

const char*
getenv_or(const char* name, const char* _default)
{
	const char *const value = std::getenv(name);
	return value ? value : _default;
}
