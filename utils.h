#ifndef SLPM_UTILS_HEADER
#define SLPM_UTILS_HEADER

#include <unistd.h>

ssize_t writes(int fd, const char* s);
const char* getenv_or(const char* name, const char* _default);

#endif // SLPM_UTILS_HEADER
