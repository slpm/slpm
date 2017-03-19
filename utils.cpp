#include "utils.h"

#include <cstring>

ssize_t
writes(int fd, const char* s)
{
	return write(fd, s, std::strlen(s));
}
