#include "utils.h"
#include "fd.h"

#include <sodium/utils.h>

#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
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

static char*
mygetstring(const char* prompt, int infd = STDIN_FILENO, int outfd = STDOUT_FILENO)
{
	static char buffer[256];
	static int sord = 0;
	static int processed = 0;

	writes(outfd, prompt);

	if (processed) {
		sodium_memzero(buffer, processed);
		sord -= processed;
		memcpy(buffer, buffer + processed, sord);
		processed = 0;
	}

	while (!0) {
		if (char *const eoln = reinterpret_cast<char*>(memchr(buffer, '\n', sord))) {
			*eoln = '\0';
			processed = eoln + 1 - buffer;
			return buffer;
		}
		const ssize_t rd = read(infd, buffer + sord, sizeof(buffer) - sord);
		if (rd <= 0) return 0;
		sord += rd;
	}
}

char* getstring(const char* prompt) { return mygetstring(prompt); }

struct HiddenInput {
	~HiddenInput()
	{
		ioctl(fd_.get(), TCSETSF, &s_);
		writes(fd_.get(), "\n");
	}

	HiddenInput()
	: fd_(open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC))
	{
		struct termios t;
		ioctl(fd_.get(), TCGETS, &t);
		s_ = t;
		t.c_lflag &= ~(ECHO|ISIG);
		t.c_lflag |= ICANON;
		t.c_iflag &= ~(INLCR|IGNCR);
		t.c_iflag |= ICRNL;
		ioctl(fd_.get(), TCSETSF, &t);
		ioctl(fd_.get(), TCSBRK, !0);
	}

	HiddenInput(const HiddenInput&) = delete;
	HiddenInput& operator=(const HiddenInput&) = delete;

	char*
	getpass(const char* prompt)
	const
	{
		return mygetstring(prompt, fd_.get(), fd_.get());
	}

private:
	struct termios s_;
	Fd fd_;
};

char*
mygetpass(const char* prompt)
{
	return HiddenInput().getpass(prompt);
}
