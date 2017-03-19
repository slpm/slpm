#ifndef SLPM_SSH_AGENT_HEADER
#define SLPM_SSH_AGENT_HEADER

extern "C" size_t to_base64(char *dst, size_t dst_len, const void *src, size_t src_len);

using Ed25519PublicKey = std::array<uint8_t, crypto_sign_ed25519_PUBLICKEYBYTES>;
using Ed25519SecretKey = std::array<uint8_t, crypto_sign_ed25519_SECRETKEYBYTES>;

struct Ed25519KeyPair {
	Ed25519PublicKey pub;
	Ed25519SecretKey sec;
};

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
	add(const Ed25519KeyPair& k, const char* comment)
	{
		if (exists(k.pub)) {
			writes(STDERR_FILENO, "Key was already in agent\n");
			return 0;
		}
		Entry e(fd_, k, comment);
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

		Entry(Fd& fd, const Ed25519KeyPair& k, const char* comment)
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
			buf.append_with_be32_length_prefix(comment);
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

#endif // SLPM_SSH_AGENT_HEADER
