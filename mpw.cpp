#include "mpw.h"

#include "buffer.h"

#include <cassert>

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

void
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
