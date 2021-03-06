#ifndef SLPM_BUFFER_HEADER
#define SLPM_BUFFER_HEADER

#include <sodium/utils.h>

#include <array>
#include <unistd.h>
#include <cstddef>
#include <cstring>
#include <arpa/inet.h>

template <typename T, ptrdiff_t S>
struct Buffer {
	Buffer() = default;
	~Buffer() { sodium_memzero(data(), capacity()); }
	Buffer(const Buffer&) = delete;
	Buffer& operator=(const Buffer&) = delete;

	T* data() { return buf_.data(); }
	const T* data() const { return buf_.data(); }
	ptrdiff_t size() const { return last_ - buf_.begin(); }
	ptrdiff_t capacity() const { return buf_.size(); }

	Buffer&
	operator+=(char c)
	{
		if (last_ != buf_.end()) *last_++ = c;
		return *this;
	}

	Buffer&
	append(const char* s, ptrdiff_t l)
	{
		last_ = std::copy(
			  s
			, s + std::min(static_cast<ptrdiff_t>(l), buf_.end() - last_)
			, last_
		);
		return *this;
	}

	Buffer& operator+=(const char* s) { return append(s, strlen(s)); }

	Buffer&
	append_network_long(uint32_t hl)
	{
		if (last_ + sizeof(hl) <= buf_.end()) {
			const auto nl = htonl(hl);
			memcpy(last_, &nl, sizeof(nl));
			last_ += sizeof(nl);
		}
		return *this;
	}

	Buffer&
	append_with_be32_length_prefix(const char* s)
	{
		return append_with_be32_length_prefix(s, strlen(s));
	}

	Buffer&
	append_with_be32_length_prefix(const char* s, ptrdiff_t l)
	{
		append_network_long(l);
		return append(s, l);
	}

	ssize_t write(int fd) const { return ::write(fd, data(), size()); }

	void clear() { last_ = buf_.begin(); }

private:
	using Buf = std::array<T, S>;

	Buf buf_;
	typename Buf::iterator last_ = buf_.begin();
};


#endif // SLPM_BUFFER_HEADER
