/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "hex-binary.h"
#include "randgen.h"
#include "password-scheme.h"
#include "dcrypt.h"

#define AES256CBC_SCHEME_NAME		"AES-256-CBC"
#define AES256CBC_SALT_IV_BYTES	16
#define AES256CBC_KEY_BYTES		16
#define AES256CBC_PBKDF2_ROUNDS		1000
#define AES256CBC_CIPHER		"AES-128-CBC"

static void aes256cbc_trim_trailing(buffer_t *buf)
{
	while (buf->used > 0 &&
	       ((const unsigned char *)buf->data)[buf->used - 1] <= ' ')
		buffer_set_used_size(buf, buf->used - 1);
}

static int aes256cbc_decode_payload(const char *cipher_text, size_t cipher_text_len,
				    const unsigned char **blob_r, size_t *blob_len_r,
				    const char **error_r)
{
	buffer_t *buf = t_buffer_create(MAX_BASE64_DECODED_SIZE(cipher_text_len));

	buffer_set_used_size(buf, 0);
	if (base64_decode(cipher_text, cipher_text_len, buf) >= 0 && buf->used > 0) {
		*blob_r = buf->data;
		*blob_len_r = buf->used;
		return 0;
	}
	buffer_set_used_size(buf, 0);
	if (hex_to_binary(cipher_text, buf) >= 0 && buf->used > 0) {
		*blob_r = buf->data;
		*blob_len_r = buf->used;
		return 0;
	}
	*error_r = "Invalid AES-256-CBC payload encoding";
	return -1;
}

static int aes256cbc_decrypt(const char *passphrase,
			     const unsigned char *blob, size_t blob_len,
			     buffer_t *plain, const char **error_r)
{
	const unsigned char *salt, *iv, *cipher;
	size_t cipher_len;
	buffer_t *key = t_buffer_create(AES256CBC_KEY_BYTES);
	struct dcrypt_context_symmetric *ctx;

	if (passphrase == NULL || *passphrase == '\0') {
		*error_r = "AES-256-CBC passphrase missing";
		return -1;
	}
	if (blob_len < AES256CBC_SALT_IV_BYTES * 2 + 1) {
		*error_r = "AES-256-CBC payload too short";
		return -1;
	}

	salt = blob;
	iv = blob + AES256CBC_SALT_IV_BYTES;
	cipher = blob + AES256CBC_SALT_IV_BYTES * 2;
	cipher_len = blob_len - AES256CBC_SALT_IV_BYTES * 2;

	if (!dcrypt_pbkdf2((const unsigned char *)passphrase,
			   strlen(passphrase), salt, AES256CBC_SALT_IV_BYTES,
			   "sha1", AES256CBC_PBKDF2_ROUNDS, key,
			   AES256CBC_KEY_BYTES, error_r))
		return -1;

	if (!dcrypt_ctx_sym_create(AES256CBC_CIPHER, DCRYPT_MODE_DECRYPT,
				   &ctx, error_r))
		return -1;
	dcrypt_ctx_sym_set_key(ctx, key->data, key->used);
	dcrypt_ctx_sym_set_iv(ctx, iv, AES256CBC_SALT_IV_BYTES);
	if (!dcrypt_ctx_sym_init(ctx, error_r) ||
	    !dcrypt_ctx_sym_update(ctx, cipher, cipher_len, plain, error_r) ||
	    !dcrypt_ctx_sym_final(ctx, plain, error_r)) {
		dcrypt_ctx_sym_destroy(&ctx);
		return -1;
	}
	dcrypt_ctx_sym_destroy(&ctx);
	return 0;
}

static int aes256cbc_verify(const char *plaintext,
			    const struct password_generate_params *params ATTR_UNUSED,
			    const unsigned char *raw_password, size_t size,
			    const char **error_r)
{
	const char *credential, *passphrase, *p;
	size_t payload_len;
	const unsigned char *blob;
	size_t blob_len;
	buffer_t *plain = t_buffer_create(128);

	if (size == 0) {
		*error_r = "Invalid AES-256-CBC passdb entry format";
		return -1;
	}

	credential = t_strndup(raw_password, size);
	p = strchr(credential, '$');
	if (p == NULL || p[1] == '\0') {
		*error_r = "Invalid AES-256-CBC passdb entry format";
		return -1;
	}
	payload_len = (size_t)(p - credential);
	passphrase = p + 1;

	if (aes256cbc_decode_payload(credential, payload_len,
				     &blob, &blob_len, error_r) < 0)
		return -1;
	if (aes256cbc_decrypt(passphrase, blob, blob_len, plain, error_r) < 0)
		return -1;

	aes256cbc_trim_trailing(plain);
	return str_equals_timing_almost_safe(plaintext,
					     t_strndup(plain->data, plain->used)) ? 1 : 0;
}

static void aes256cbc_generate(const char *plaintext,
			       const struct password_generate_params *params,
			       const unsigned char **raw_password_r, size_t *size_r)
{
	const char *passphrase = params->scheme_passphrase;
	unsigned char salt[AES256CBC_SALT_IV_BYTES];
	unsigned char iv[AES256CBC_SALT_IV_BYTES];
	buffer_t *key = t_buffer_create(AES256CBC_KEY_BYTES);
	buffer_t *plain = t_buffer_create(strlen(plaintext) + 1);
	buffer_t *ciphertext = t_buffer_create(strlen(plaintext) + 32);
	buffer_t *blob;
	struct dcrypt_context_symmetric *ctx;
	string_t *str;
	const char *error;

	if (passphrase == NULL || *passphrase == '\0')
		i_fatal("AES-256-CBC scheme_passphrase missing");

	random_fill(salt, sizeof(salt));
	random_fill(iv, sizeof(iv));

	if (!dcrypt_pbkdf2((const unsigned char *)passphrase,
			   strlen(passphrase), salt, sizeof(salt),
			   "sha1", AES256CBC_PBKDF2_ROUNDS, key,
			   AES256CBC_KEY_BYTES, &error))
		i_fatal("AES-256-CBC PBKDF2 failed: %s", error);

	buffer_append(plain, plaintext, strlen(plaintext));

	if (!dcrypt_ctx_sym_create(AES256CBC_CIPHER, DCRYPT_MODE_ENCRYPT,
				   &ctx, &error))
		i_fatal("AES-256-CBC encrypt init failed: %s", error);
	dcrypt_ctx_sym_set_key(ctx, key->data, key->used);
	dcrypt_ctx_sym_set_iv(ctx, iv, sizeof(iv));
	if (!dcrypt_ctx_sym_init(ctx, &error) ||
	    !dcrypt_ctx_sym_update(ctx, plain->data, plain->used,
				   ciphertext, &error) ||
	    !dcrypt_ctx_sym_final(ctx, ciphertext, &error))
		i_fatal("AES-256-CBC encrypt failed: %s", error);
	dcrypt_ctx_sym_destroy(&ctx);

	blob = t_buffer_create(sizeof(salt) + sizeof(iv) + ciphertext->used);
	buffer_append(blob, salt, sizeof(salt));
	buffer_append(blob, iv, sizeof(iv));
	buffer_append(blob, ciphertext->data, ciphertext->used);

	str = t_str_new(MAX_BASE64_ENCODED_SIZE(blob->used) + strlen(passphrase) + 2);
	base64_encode(blob->data, blob->used, str);
	str_printfa(str, "$%s", passphrase);

	*raw_password_r = str_data(str);
	*size_r = str_len(str);
}

static const struct password_scheme aes256cbc_scheme = {
	.name = AES256CBC_SCHEME_NAME,
	.default_encoding = PW_ENCODING_NONE,
	.raw_password_len = 0,
	.password_verify = aes256cbc_verify,
	.password_generate = aes256cbc_generate,
};

void password_scheme_register_aes256cbc(void)
{
	static bool registered = FALSE;
	const char *error;

	if (registered)
		return;
	if (!dcrypt_initialize(NULL, NULL, &error)) {
		i_warning("AES-256-CBC password scheme disabled: %s", error);
		return;
	}
	password_scheme_register(&aes256cbc_scheme);
	registered = TRUE;
}
