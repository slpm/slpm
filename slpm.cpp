#include "buffer.h"
#include "fd.h"

#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_pwhash_scryptsalsa208sha256.h>
#include <sodium/crypto_sign_ed25519.h>

#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <cstring>
#include <cassert>
#include <sys/un.h>
#include <experimental/optional>
#include <algorithm>

#define COUNT(x) (sizeof(x) / sizeof(x[0]))

static const char*
lookup_pass_chars(char templat)
{
	switch (templat) {
	case 'V': return "AEIOU";
	case 'C': return "BCDFGHJKLMNPQRSTVWXYZ";
	case 'v': return "aeiou";
	case 'c': return "bcdfghjklmnpqrstvwxyz";
	case 'A': return "AEIOUBCDFGHJKLMNPQRSTVWXYZ";
	case 'a': return "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz";
	case 'n': return "0123456789";
	case 'o': return "@&%?,=[]_:-+*$#!'^~;()/.";
	case 'x': return "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()";
	}
	assert(!"invalid template");
	return 0;
}

static const char* temp_max_sec[] = {
	  "anoxxxxxxxxxxxxxxxxx"
	, "axxxxxxxxxxxxxxxxxno"
};

static const char* temp_long[] = {
	  "CvcvnoCvcvCvcv"
	, "CvcvCvcvnoCvcv"
	, "CvcvCvcvCvcvno"
	, "CvccnoCvcvCvcv"
	, "CvccCvcvnoCvcv"
	, "CvccCvcvCvcvno"
	, "CvcvnoCvccCvcv"
	, "CvcvCvccnoCvcv"
	, "CvcvCvccCvcvno"
	, "CvcvnoCvcvCvcc"
	, "CvcvCvcvnoCvcc"
	, "CvcvCvcvCvccno"
	, "CvccnoCvccCvcv"
	, "CvccCvccnoCvcv"
	, "CvccCvccCvcvno"
	, "CvcvnoCvccCvcc"
	, "CvcvCvccnoCvcc"
	, "CvcvCvccCvccno"
	, "CvccnoCvcvCvcc"
	, "CvccCvcvnoCvcc"
	, "CvccCvcvCvccno"
};

static const char* temp_medium[] = {
	  "CvcnoCvc"
	, "CvcCvcno"
};

static const char* temp_short[] = {
	  "Cvcn"
};

static const char* temp_basic[] = {
	  "aaanaaan"
	, "aannaaan"
	, "aaannaaa"
};

static const char* temp_pin[] = {
	  "nnnn"
};

#define DEF_TEMP(name, t) { name, t, COUNT(t) }

static const struct {
	const char* name;
	const char** templat;
	unsigned count;
} templates[] = {
	  DEF_TEMP("Maximum Security Password", temp_max_sec)
	, DEF_TEMP("Long Password", temp_long)
	, DEF_TEMP("Medium Password", temp_medium)
	, DEF_TEMP("Short Password", temp_short)
	, DEF_TEMP("Basic Password", temp_basic)
	, DEF_TEMP("PIN", temp_pin)
};

static ssize_t
writes(int fd, const char* s)
{
	return write(fd, s, strlen(s));
}

static int
hmacsha256(
	  uint8_t *out
	, const uint8_t *in, size_t inlen
	, const uint8_t *k, size_t klen
)
{
	struct crypto_auth_hmacsha256_state state;
	if (crypto_auth_hmacsha256_init(&state, k, klen)) return -1;
	if (crypto_auth_hmacsha256_update(&state, in, inlen)) return -2;
	if (crypto_auth_hmacsha256_final(&state, out)) return -3;
	return 0;
}

using Seed = std::array<uint8_t, crypto_auth_hmacsha256_BYTES>;

static void
output_site_generic(const Seed& seed)
{
	Buffer<uint8_t, 4096> buf;
	for (unsigned i = 0; i != COUNT(templates); ++i) {
		buf += templates[i].name;
		buf += ": ";
		const char* templat = templates[i].templat[seed[0] % templates[i].count];
		for (unsigned j = 0; templat[j]; ++j) {
			const char* pass_chars = lookup_pass_chars(templat[j]);
			int len = strlen(pass_chars);
			assert(seed.size() > 1 + j);
			buf += pass_chars[seed[1 + j] % len];
		}
		buf += '\n';
	}

	buf.write(STDOUT_FILENO);
}

extern "C" size_t to_base64(char *dst, size_t dst_len, const void *src, size_t src_len);

using Ed25519PublicKey = std::array<uint8_t, crypto_sign_ed25519_PUBLICKEYBYTES>;
using Ed25519SecretKey = std::array<uint8_t, crypto_sign_ed25519_SECRETKEYBYTES>;

struct Ed25519KeyPair {
	Ed25519PublicKey pub;
	Ed25519SecretKey sec;
};

static void
append(Buffer<uint8_t, 4096>& result, const Ed25519PublicKey& pk)
{
	Buffer<char, 256> buf;
	buf.append_with_be32_length_prefix("ssh-ed25519");
	buf.append_with_be32_length_prefix(reinterpret_cast<const char*>(pk.data()), pk.size());

	std::array<char, 256> base64;
	to_base64(base64.data(), base64.size(), buf.data(), buf.size());

	result += base64.data();
}

struct SshAgent {
	SshAgent()
	: fd_(socket(AF_UNIX, SOCK_STREAM, 0))
	{
		if (!fd_.valid()) {
			writes(STDERR_FILENO, "Failed to create socket for ssh-agent\n");
			return;
		}
		const char* ssh_auth_sock = getenv("SSH_AUTH_SOCK");
		if (!ssh_auth_sock) {
			writes(STDERR_FILENO, "Failed to find address of ssh-agent (SSH_AUTH_SOCK)\n");
			return;
		}
		sockaddr_un sa;
		memset(&sa, 0, sizeof(sa));
		sa.sun_family = AF_UNIX;
		strncpy(sa.sun_path, ssh_auth_sock, sizeof(sa.sun_path) - 1);
		if (connect(fd_.get(), reinterpret_cast<sockaddr*>(&sa), sizeof(sa))) {
			writes(STDERR_FILENO, "Failed to connect to ssh-agent\n");
			return;
		}
		valid_ = true;
	}

	SshAgent(const SshAgent&) = delete;
	SshAgent& operator=(const SshAgent&) = delete;

	int
	add(const Ed25519KeyPair& k)
	{
		if (exists(k.pub)) {
			writes(STDERR_FILENO, "Key was already in agent\n");
			return 0;
		}
		Entry e(fd_, k);
		if (e.error()) return e.error();
		auto& item = entries_[n_];
		if (item) {
			writes(STDERR_FILENO, "Oldest key is evicted from agent\n");
		}
		item = std::move(e);
		n_ = (n_ + 1) % entries_.size();
		return 0;
	}

private:
	struct Entry {
		~Entry()
		{
			if (error()) return;
			Buffer<uint8_t, 4096> buf;
			buf.append_network_long(0);
			buf += '\x12'; // SSH2_AGENTC_REMOVE_IDENTITY
			buf.append_network_long(0x33);
			buf.append_with_be32_length_prefix("ssh-ed25519");
			buf.append_with_be32_length_prefix(reinterpret_cast<const char*>(pk_.data()), pk_.size());
			sodium_memzero(pk_.data(), pk_.size());
			*reinterpret_cast<uint32_t*>(buf.data()) = htonl(buf.size() - 4);
			buf.write(fd_->get()); // TODO: check return value
			std::array<uint8_t, 8> resp;
			const auto rd2 = read(fd_->get(), resp.data(), resp.size());
			if (rd2 != 5 || ntohl(*reinterpret_cast<uint32_t*>(resp.data())) != 1) {
				writes(STDERR_FILENO, "Unexpected result size from ssh-agent at removing key\n");
				return;
			}
			if (resp[4] != 6) {
				writes(STDERR_FILENO, "ssh-agent did not return success at removing key\n");
				return;
			}
		}

		Entry(Fd& fd, const Ed25519KeyPair& k)
		: fd_(&fd)
		, pk_(k.pub)
		{
			if (!fd_->valid()) return;
			Buffer<uint8_t, 4096> buf;
			buf.append_network_long(0);
			buf += '\x19'; // SSH2_AGENTC_ADD_ID_CONSTRAINED
			buf.append_with_be32_length_prefix("ssh-ed25519");
			buf.append_with_be32_length_prefix(reinterpret_cast<const char*>(k.pub.data()), k.pub.size());
			buf.append_with_be32_length_prefix(reinterpret_cast<const char*>(k.sec.data()), k.sec.size());
			buf.append_with_be32_length_prefix("comment");
			buf += '\x01'; // SSH_AGENT_CONSTRAIN_LIFETIME
			buf.append_network_long(86400);
			buf += '\x02'; // SSH_AGENT_CONSTRAIN_CONFIRM
			*reinterpret_cast<uint32_t*>(buf.data()) = htonl(buf.size() - 4);
			buf.write(fd_->get()); // TODO: check return value
			std::array<uint8_t, 8> resp;
			const auto rd = read(fd_->get(), resp.data(), resp.size());
			if (rd != 5 || ntohl(*reinterpret_cast<uint32_t*>(resp.data())) != 1) {
				writes(STDERR_FILENO, "Unexpected result size from ssh-agent\n");
				return;
			}
			if (resp[4] == 6) error_ = 0;
		}

		Entry(const Entry&) = delete;

		Entry(Entry&& e)
		: fd_(e.fd_)
		, pk_(e.pk_)
		, error_(e.error_)
		{
			e.fd_ = nullptr;
			sodium_memzero(e.pk_.data(), e.pk_.size());
			e.error_ = -1;
		}

		Entry&
		operator=(Entry e)
		{
			using std::swap;
			swap(fd_, e.fd_);
			swap(pk_, e.pk_);
			swap(error_, e.error_);
			return *this;
		}

		int error() const { return error_; }

		bool
		operator==(const Ed25519PublicKey& rhs)
		const
		{
			return !sodium_memcmp(pk_.data(), rhs.data(), pk_.size());
		}

	private:
		Fd* fd_;
		Ed25519PublicKey pk_;
		int error_ = -1;
	};

	using OptEntry = std::experimental::optional<Entry>;
	using Entries = std::array<OptEntry, 8>;

	bool
	exists(const Ed25519PublicKey& pk)
	const
	{
		return std::find_if(
			  entries_.begin()
			, entries_.end()
			, [&](const auto& e){ return e && *e == pk; }
		) != entries_.end();
	}

	Fd fd_;
	Entries entries_;
	bool valid_{};
	int n_{};
};

// TODO: fill in comment field properly
// TODO: fill in user@localhost properly

static void
output_site_ssh(SshAgent& sa, const Seed& seed)
{
	assert(seed.size() >= crypto_sign_ed25519_SEEDBYTES);
	Ed25519KeyPair k;
	crypto_sign_ed25519_seed_keypair(k.pub.data(), k.sec.data(), seed.data());
	const auto error = sa.add(k);
	sodium_memzero(k.sec.data(), k.sec.size());

	if (!error) {
		Buffer<uint8_t, 4096> buf;
		buf += "ssh-ed25519 ";
		append(buf, k.pub);
		buf += " user@localhost";
		buf += '\n';
		buf.write(STDOUT_FILENO);
	}
	sodium_memzero(k.pub.data(), k.pub.size());
}

static const char iv[] = "com.lyndir.masterpassword";

static void
write_passwords_for_site(SshAgent& sa, const uint8_t* key, size_t keysize, const char* site, int counter)
{
	Buffer<uint8_t, 4096> buf;

	buf += iv;
	buf.append_with_be32_length_prefix(site);
	buf.append_network_long(counter);
	Seed seed;
	if (hmacsha256(seed.data(), buf.data(), buf.size(), key, keysize)) {
		writes(2, "hmac fail\n");
		return;
	}

	if (!strncmp(site, "ssh ", 4)) {
		output_site_ssh(sa, seed);
	} else {
		output_site_generic(seed);
	}
	sodium_memzero(seed.data(), seed.size());
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

static char* getstring(const char* prompt) { return mygetstring(prompt); }

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

static char*
mygetpass(const char* prompt)
{
	return HiddenInput().getpass(prompt);
}

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

int
main(int, char* [], char* envp[])
{
	environ = envp;
	const char* salt = getenv("SLPM_FULLNAME");
	if (!salt) salt = "";
	{
		Buffer<uint8_t, 256> buf;
		buf += "SLPM_FULLNAME='";
		buf += salt;
		buf += "'\n";
		buf.write(1);
	}

	Buffer<uint8_t, 4096> buf;
	buf += iv;
	buf.append_with_be32_length_prefix(salt);

	char *const pw = (isatty(STDIN_FILENO) ? mygetpass : getstring)("Passphrase: ");
	if (!pw) {
		writes(STDOUT_FILENO, "\n");
		return -1;
	}
	writes(1, "Deriving key...");
	uint8_t key[64];
	if (crypto_pwhash_scryptsalsa208sha256_ll(
		  (const uint8_t*)pw
		, strlen(pw)
		, buf.data()
		, buf.size()
		, 32768
		, 8
		, 2
		, key
		, sizeof(key)
	)) {
		sodium_memzero(pw, strlen(pw));
		writes(2, "scrypt fail\n");
		return -1;
	}
	sodium_memzero(pw, strlen(pw));

	writes(1, "\rKey derivation complete.\n");
	SshAgent sa;
	while (!0) {
		char site[256];
		const char* s = getstring("Site: ");
		if (!s) break;
		strncpy(site, s, sizeof(site) - 1);
		const char* c = getstring("Counter: ");
		if (!c) break;
		write_passwords_for_site(sa, key, sizeof(key), site, atoi(c));
	}

	sodium_memzero(key, sizeof(key));
	writes(1, "\rBye!    \n");
	return 0;
}
