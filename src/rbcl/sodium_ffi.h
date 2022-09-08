/*
 * Declarations for the libsodium constants and functions invoked in
 * the main Python module for this library via a cffi wrapper module.
 */

int sodium_memcmp(const void * const b1_, const void * const b2_, size_t len);
int sodium_init();

// crypto_scalarmult_ristretto255
size_t crypto_scalarmult_ristretto255_bytes();
size_t crypto_scalarmult_ristretto255_scalarbytes();

int crypto_scalarmult_ristretto255_base(unsigned char *q, const unsigned char *n);
int crypto_scalarmult_ristretto255(unsigned char *q, const unsigned char *n, const unsigned char *p);

// csrypto_core_ristretto255
size_t crypto_core_ristretto255_bytes();
size_t crypto_core_ristretto255_hashbytes();
size_t crypto_core_ristretto255_scalarbytes();
size_t crypto_core_ristretto255_nonreducedscalarbytes();

int crypto_core_ristretto255_is_valid_point(const unsigned char *p);
int crypto_core_ristretto255_add(unsigned char *r, const unsigned char *p, const unsigned char *q);
int crypto_core_ristretto255_sub(unsigned char *r, const unsigned char *p, const unsigned char *q);
int crypto_core_ristretto255_from_hash(unsigned char *p, const unsigned char *r);
void crypto_core_ristretto255_random(unsigned char *p);
void crypto_core_ristretto255_scalar_random(unsigned char *r);
int crypto_core_ristretto255_scalar_invert(unsigned char *recip, const unsigned char *s);
void crypto_core_ristretto255_scalar_negate(unsigned char *neg, const unsigned char *s);
void crypto_core_ristretto255_scalar_complement(unsigned char *comp, const unsigned char *s);
void crypto_core_ristretto255_scalar_add(unsigned char *z, const unsigned char *x, const unsigned char *y);
void crypto_core_ristretto255_scalar_sub(unsigned char *z, const unsigned char *x, const unsigned char *y);
void crypto_core_ristretto255_scalar_mul(unsigned char *z, const unsigned char *x, const unsigned char *y);
void crypto_core_ristretto255_scalar_reduce(unsigned char *r, const unsigned char *s);

// randombytes
size_t randombytes_seedbytes();

void randombytes(unsigned char * const buf, const unsigned long long buf_len);
void randombytes_buf_deterministic(void * const buf, const size_t size, const unsigned char seed[32]);
