#ifndef SLPM_MPW_HEADER
#define SLPM_MPW_HEADER

#include <sodium/crypto_auth_hmacsha256.h>

#include <array>

using Seed = std::array<uint8_t, crypto_auth_hmacsha256_BYTES>;

void output_site_generic(const Seed&);

#endif // SLPM_MPW_HEADER
