/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "base64.h"
#include "randgen.h"
#include "password-scheme.h"
#include "dcrypt.h"

#define AES128CBC_SCHEME_NAME		"AES-128-CBC"
#define AES128CBC_SALT_IV_BYTES	16
#define AES128CBC_KEY_BYTES		16
#define AES128CBC_PBKDF2_ROUNDS		1000
#define AES128CBC_CIPHER		"AES-128-CBC"

static void aes128cbc_trim_trailing(buffer_t *buf)
{
	while (buf->used > 0 &&
	       ((const unsigned char *)buf->data)[buf->used - 1] <= ' ')
		buffer_set_used_size(buf, buf->used - 1);
}

static const char *
aes128cbc_resolve_passphrase(const struct password_generate_params *params,
			     const char **error_r)
{
	const char *stored;
	buffer_t *decoded;

	if (params == NULL || params->scheme_passphrase == NULL ||
	    params->scheme_passphrase[0] == '\0') {
		*error_r = "AES-128-CBC passphrase missing";
		return NULL;
	}

	stored = params->scheme_passphrase;
	decoded = t_buffer_create(64);
	if (base64_decode(stored, strlen(stored), decoded) < 0 ||
	    decoded->used == 0)
		return stored;

	return t_strndup(decoded->data, decoded->used);
}

static int aes128cbc_decrypt(const char *passphrase,
			     const unsigned char *blob, size_t blob_len,
			     buffer_t *plain, const char **error_r)
{
	const unsigned char *salt, *iv, *cipher;
	size_t cipher_len;
	buffer_t *key = t_buffer_create(AES128CBC_KEY_BYTES);
	struct dcrypt_context_symmetric *ctx;

	if (passphrase == NULL || *passphrase == '\0') {
		*error_r = "AES-128-CBC passphrase missing";
		return -1;
	}
	if (blob_len < AES128CBC_SALT_IV_BYTES * 2 + 1) {
		*error_r = "AES-128-CBC payload too short";
		return -1;
	}

	salt = blob;
	iv = blob + AES128CBC_SALT_IV_BYTES;
	cipher = blob + AES128CBC_SALT_IV_BYTES * 2;
	cipher_len = blob_len - AES128CBC_SALT_IV_BYTES * 2;

	if (!dcrypt_pbkdf2((const unsigned char *)passphrase,
			   strlen(passphrase), salt, AES128CBC_SALT_IV_BYTES,
			   "sha1", AES128CBC_PBKDF2_ROUNDS, key,
			   AES128CBC_KEY_BYTES, error_r))
		return -1;

	if (!dcrypt_ctx_sym_create(AES128CBC_CIPHER, DCRYPT_MODE_DECRYPT,
				   &ctx, error_r))
		return -1;
	dcrypt_ctx_sym_set_key(ctx, key->data, key->used);
	dcrypt_ctx_sym_set_iv(ctx, iv, AES128CBC_SALT_IV_BYTES);
	if (!dcrypt_ctx_sym_init(ctx, error_r) ||
	    !dcrypt_ctx_sym_update(ctx, cipher, cipher_len, plain, error_r) ||
	    !dcrypt_ctx_sym_final(ctx, plain, error_r)) {
		dcrypt_ctx_sym_destroy(&ctx);
		return -1;
	}
	dcrypt_ctx_sym_destroy(&ctx);
	return 0;
}

static int aes128cbc_verify(const char *plaintext,
			    const struct password_generate_params *params,
			    const unsigned char *raw_password, size_t size,
			    const char **error_r)
{
	const char *passphrase;
	buffer_t *plain = t_buffer_create(128);

	if (size == 0) {
		*error_r = "Invalid AES-128-CBC passdb entry format";
		return -1;
	}

	passphrase = aes128cbc_resolve_passphrase(params, error_r);
	if (passphrase == NULL)
		return -1;

	if (aes128cbc_decrypt(passphrase, raw_password, size, plain, error_r) < 0)
		return -1;

	aes128cbc_trim_trailing(plain);
	return str_equals_timing_almost_safe(plaintext,
					     t_strndup(plain->data, plain->used)) ? 1 : 0;
}

static void aes128cbc_generate(const char *plaintext,
			       const struct password_generate_params *params,
			       const unsigned char **raw_password_r, size_t *size_r)
{
	const char *passphrase = params->scheme_passphrase;
	unsigned char salt[AES128CBC_SALT_IV_BYTES];
	unsigned char iv[AES128CBC_SALT_IV_BYTES];
	buffer_t *key = t_buffer_create(AES128CBC_KEY_BYTES);
	buffer_t *plain = t_buffer_create(strlen(plaintext) + 1);
	buffer_t *ciphertext = t_buffer_create(strlen(plaintext) + 32);
	buffer_t *blob;
	struct dcrypt_context_symmetric *ctx;
	const char *error;

	if (passphrase == NULL || *passphrase == '\0')
		i_fatal("AES-128-CBC scheme_passphrase missing");

	random_fill(salt, sizeof(salt));
	random_fill(iv, sizeof(iv));

	if (!dcrypt_pbkdf2((const unsigned char *)passphrase,
			   strlen(passphrase), salt, sizeof(salt),
			   "sha1", AES128CBC_PBKDF2_ROUNDS, key,
			   AES128CBC_KEY_BYTES, &error))
		i_fatal("AES-128-CBC PBKDF2 failed: %s", error);

	buffer_append(plain, plaintext, strlen(plaintext));

	if (!dcrypt_ctx_sym_create(AES128CBC_CIPHER, DCRYPT_MODE_ENCRYPT,
				   &ctx, &error))
		i_fatal("AES-128-CBC encrypt init failed: %s", error);
	dcrypt_ctx_sym_set_key(ctx, key->data, key->used);
	dcrypt_ctx_sym_set_iv(ctx, iv, sizeof(iv));
	if (!dcrypt_ctx_sym_init(ctx, &error) ||
	    !dcrypt_ctx_sym_update(ctx, plain->data, plain->used,
				   ciphertext, &error) ||
	    !dcrypt_ctx_sym_final(ctx, ciphertext, &error))
		i_fatal("AES-128-CBC encrypt failed: %s", error);
	dcrypt_ctx_sym_destroy(&ctx);

	blob = t_buffer_create(sizeof(salt) + sizeof(iv) + ciphertext->used);
	buffer_append(blob, salt, sizeof(salt));
	buffer_append(blob, iv, sizeof(iv));
	buffer_append(blob, ciphertext->data, ciphertext->used);

	*raw_password_r = blob->data;
	*size_r = blob->used;
}

static const struct password_scheme aes128cbc_scheme = {
	.name = AES128CBC_SCHEME_NAME,
	.default_encoding = PW_ENCODING_NONE,
	.raw_password_len = 0,
	.password_verify = aes128cbc_verify,
	.password_generate = aes128cbc_generate,
};

void password_scheme_register_aes128cbc(void)
{
	static bool registered = FALSE;
	const char *error;

	if (registered)
		return;
	if (!dcrypt_initialize(NULL, NULL, &error)) {
		i_warning("AES-128-CBC password scheme disabled: %s", error);
		return;
	}
	password_scheme_register(&aes128cbc_scheme);
	registered = TRUE;
}
