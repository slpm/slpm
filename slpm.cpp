#include "ssh-agent.h"
#include "buffer.h"
#include "fd.h"
#include "utils.h"
#include "mpw.h"

#include <sodium/crypto_pwhash_scryptsalsa208sha256.h>

#include <cstring>
#include <cassert>

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

static void
output_site_ssh(SshAgent& sa, const Seed& seed, const char* site)
{
	assert(seed.size() >= crypto_sign_ed25519_SEEDBYTES);
	Ed25519KeyPair k;
	crypto_sign_ed25519_seed_keypair(k.pub.data(), k.sec.data(), seed.data());
	Buffer<char, 256> comment;
	comment += "slpm+";
	comment += site;
	comment += '\0';
	const auto error = sa.add(k, comment.data());
	sodium_memzero(k.sec.data(), k.sec.size());

	if (!error) {
		Buffer<uint8_t, 4096> buf;
		buf += "ssh-ed25519";
		buf += ' ';
		append(buf, k.pub);
		buf += ' ';
		buf += getenv_or("USER", "user");
		buf += '@';
		buf += "slpm+";
		buf += site;
		buf += '\n';
		buf.write(STDOUT_FILENO);
	}
	sodium_memzero(k.pub.data(), k.pub.size());
}

static const char iv[] = "com.lyndir.masterpassword";

static void
write_passwords_for_site(SshAgent& sa, const uint8_t* key, size_t keysize, const char* site, int counter)
{
	const auto is_ssh = !strncmp(site, "ssh ", 4);
	if (is_ssh) site += 4;
	Buffer<uint8_t, 4096> buf;

	buf += iv;
	buf.append_with_be32_length_prefix(site);
	buf.append_network_long(counter);
	Seed seed;
	if (hmacsha256(seed.data(), buf.data(), buf.size(), key, keysize)) {
		writes(2, "hmac fail\n");
		return;
	}

	if (is_ssh) {
		output_site_ssh(sa, seed, site);
	} else {
		output_site_generic(seed);
	}
	sodium_memzero(seed.data(), seed.size());
}

int
main(int, char* [], char* envp[])
{
	environ = envp;
	const char *const salt = getenv_or("SLPM_FULLNAME", "");
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
