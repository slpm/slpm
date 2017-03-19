#ifndef SLPM_SSH_AGENT_HEADER
#define SLPM_SSH_AGENT_HEADER

#include "fd.h"

#include <sodium/crypto_sign_ed25519.h>

#include <cstddef>
#include <array>
#include <experimental/optional>

extern "C" std::size_t to_base64(char* dst, std::size_t dst_len, const void* src, std::size_t src_len);

using Ed25519PublicKey = std::array<uint8_t, crypto_sign_ed25519_PUBLICKEYBYTES>;
using Ed25519SecretKey = std::array<uint8_t, crypto_sign_ed25519_SECRETKEYBYTES>;

struct Ed25519KeyPair {
	Ed25519PublicKey pub;
	Ed25519SecretKey sec;
};

struct SshAgent {
	SshAgent();
	SshAgent(const SshAgent&) = delete;
	SshAgent& operator=(const SshAgent&) = delete;

	int add(const Ed25519KeyPair& k, const char* comment);

private:
	struct Entry {
		~Entry();
		Entry(Fd& fd, const Ed25519KeyPair& k, const char* comment);
		Entry(const Entry&) = delete;
		Entry(Entry&& e);

		Entry& operator=(Entry e);

		int error() const { return error_; }

		bool operator==(const Ed25519PublicKey& rhs) const;

	private:
		Fd* fd_;
		Ed25519PublicKey pk_;
		int error_ = -1;
	};

	using OptEntry = std::experimental::optional<Entry>;
	using Entries = std::array<OptEntry, 8>;

	bool exists(const Ed25519PublicKey& pk) const;

	Fd fd_;
	Entries entries_;
	bool valid_{};
	int n_{};
};

#endif // SLPM_SSH_AGENT_HEADER
