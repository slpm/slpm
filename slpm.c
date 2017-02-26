#define _BSD_SOURCE (1)
#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_pwhash_scryptsalsa208sha256.h>
#include <sodium/utils.h>

#include <arpa/inet.h>

#include <string.h>
#include <assert.h>
#include <unistd.h>

#define COUNT(x) (sizeof(x) / sizeof(x[0]))

static const char*
lookup_pass_chars(char template)
{
	switch (template) {
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
	const char** template;
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
writes(int fd, const void* s)
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

struct Buffer {
	uint8_t first[8192];
	uint8_t* last;
};

static void
buffer_reset(struct Buffer* b)
{
	b->last = b->first;
	sodium_memzero(b->first, sizeof(b->first));
}

static uint8_t*
buffer_data(struct Buffer* b)
{
	return b->first;
}

static size_t
buffer_size(const struct Buffer* b)
{
	return b->last - b->first;
}

static int
buffer_append_str(struct Buffer* b, const char* s)
{
	size_t len = strlen(s);
	if (b->first + len > b->first + sizeof(b->first)) return -1;
	memcpy(b->last, s, len);
	b->last += len;
	return 0;
}

static int
buffer_append_int(struct Buffer* b, int i)
{
	if (b->first + 4 > b->first + sizeof(b->first)) return -1;
	*((uint32_t*)b->last) = htonl(i);
	b->last += 4;
	return 0;
}

static int
buffer_append_char(struct Buffer* b, int c)
{
	if (b->first + 1 > b->first + sizeof(b->first)) return -1;
	*b->last++ = c;
	return 0;
}

static ssize_t
buffer_write(struct Buffer* b, int fd)
{
	return write(fd, b->first, b->last - b->first);
}

static const char iv[] = "com.lyndir.masterpassword";

static void
write_passwords_for_site(const uint8_t* key, size_t keysize, const char* site, int counter)
{
	struct Buffer buf;

	buffer_reset(&buf);
	buffer_append_str(&buf, iv);
	buffer_append_int(&buf, strlen(site));
	buffer_append_str(&buf, site);
	buffer_append_int(&buf, counter);
	uint8_t seed[crypto_auth_hmacsha256_BYTES];
	if (hmacsha256(seed, buffer_data(&buf), buffer_size(&buf), key, keysize)) {
		writes(2, "hmac fail\n");
		return;
	}

	buffer_reset(&buf);
	for (unsigned i = 0; i != COUNT(templates); ++i) {
		buffer_append_str(&buf, templates[i].name);
		buffer_append_str(&buf, ": ");
		const char* template = templates[i].template[seed[0] % templates[i].count];
		for (unsigned j = 0; template[j]; ++j) {
			const char* pass_chars = lookup_pass_chars(template[j]);
			int len = strlen(pass_chars);
			assert(sizeof(seed) > 1 + j);
			buffer_append_char(&buf, pass_chars[seed[1 + j] % len]);
		}
		buffer_append_char(&buf, '\n');
	}

	buffer_write(&buf, 1);
	buffer_reset(&buf);
	sodium_memzero(seed, sizeof(seed));
}

static const char*
getstring(const char* prompt)
{
	static char buffer[256];
	static int sord = 0;
	
	writes(1, prompt);

	if (sord) {
		char* eoln = memchr(buffer, '\0', sord);
		if (eoln) {
			sord -= eoln + 1 - buffer;
			memcpy(buffer, eoln + 1, sord);
		}
	}

	while (!0) {
		const ssize_t rd = read(0, buffer + sord, sizeof(buffer) - sord);
		if (rd <= 0) return 0;
		sord += rd;
		char* eoln = strchr(buffer, '\n');
		if (eoln) {
			*eoln = '\0';
			return buffer;
		}
	}
}

int
main()
{
	const char* salt = getenv("SLPM_FULLNAME");
	if (!salt) salt = "";
	writes(1, "SLPM_FULLNAME='");
	writes(1, salt);
	writes(1, "'\n");
	struct Buffer buf;

	buffer_reset(&buf);
	buffer_append_str(&buf, iv);
	buffer_append_int(&buf, strlen(salt));
	buffer_append_str(&buf, salt);

	char *const pw = getpass("Passphrase: ");
	writes(1, "Deriving key...");
	uint8_t key[64];
	if (crypto_pwhash_scryptsalsa208sha256_ll(
		  (const uint8_t*)pw
		, strlen(pw)
		, buffer_data(&buf)
		, buffer_size(&buf)
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
