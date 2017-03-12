#ifndef SLPM_FD_HEADER
#define SLPM_FD_HEADER

#include <unistd.h>

struct Fd {
	~Fd() { if (valid()) close(fd_); }
	Fd(int fd) : fd_(fd) {}
	Fd(const Fd&) = delete;
	Fd& operator=(const Fd&) = delete;

	bool valid() const { return fd_ != -1; }
	int get() const { return fd_; }

private:
	int fd_;
};

#endif // SLPM_FD_HEADER
