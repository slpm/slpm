#define _BSD_SOURCE (1)

#include "buffer.h"

#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_pwhash_scryptsalsa208sha256.h>

#include <string.h>
#include <assert.h>

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

static const char iv[] = "com.lyndir.masterpassword";

static void
write_passwords_for_site(const uint8_t* key, size_t keysize, const char* site, int counter)
{
	Buffer<uint8_t, 4096> buf;

	buf += iv;
	buf.append_network_long(strlen(site));
	buf += site;
	buf.append_network_long(counter);
	uint8_t seed[crypto_auth_hmacsha256_BYTES];
	if (hmacsha256(seed, buf.data(), buf.size(), key, keysize)) {
		writes(2, "hmac fail\n");
		return;
	}

	Buffer<uint8_t, 4096> obuf;
	for (unsigned i = 0; i != COUNT(templates); ++i) {
		obuf += templates[i].name;
		obuf += ": ";
		const char* templat = templates[i].templat[seed[0] % templates[i].count];
		for (unsigned j = 0; templat[j]; ++j) {
			const char* pass_chars = lookup_pass_chars(templat[j]);
			int len = strlen(pass_chars);
			assert(sizeof(seed) > 1 + j);
			obuf += pass_chars[seed[1 + j] % len];
		}
		obuf += '\n';
	}

	obuf.write(1);
	sodium_memzero(seed, sizeof(seed));
}

static const char*
getstring(const char* prompt)
{
	static char buffer[256];
	static int sord = 0;
	
	writes(1, prompt);

	if (sord) {
		char* eoln = reinterpret_cast<char*>(memchr(buffer, '\0', sord));
		if (eoln) {
			sord -= eoln + 1 - buffer;
			memcpy(buffer, eoln + 1, sord);
		}
	}

	while (!0) {
		if (char *const eoln = reinterpret_cast<char*>(memchr(buffer, '\n', sord))) {
			*eoln = '\0';
			return buffer;
		}
		const ssize_t rd = read(0, buffer + sord, sizeof(buffer) - sord);
		if (rd <= 0) return 0;
		sord += rd;
	}
}

// TODO: get rid of getpass, and use -nostdlib
int
main()
{
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
	buf.append_network_long(strlen(salt));
	buf += salt;

	char *const env_pw = getenv("SLPM_PASSPHRASE");
	char *const pw = env_pw ? env_pw : getpass("Passphrase: ");
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
	while (!0) {
		char site[256];
		const char* s = getstring("Site: ");
		if (!s) break;
		strncpy(site, s, sizeof(site) - 1);
		const char* c = getstring("Counter: ");
		if (!c) break;
		write_passwords_for_site(key, sizeof(key), site, atoi(c));
	}

	sodium_memzero(key, sizeof(key));
	writes(1, "\rBye!    \n");
	return 0;
}
