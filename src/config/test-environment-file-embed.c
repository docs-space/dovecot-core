/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"
#include "ostream.h"
#include "service-settings.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "iostream-ssl.h"
#include "config-parser.h"
#include "config-parser-private.h"
#include "dovecot-version.h"
#include "test-common.h"
#include "test-dir.h"

#define TEST_CONFIG_FILE "environment-file-embed.conf"
#define TEST_CERT_FILE "test-ssl-cert.pem"

static const struct config_service test_config_all_services[] = { { NULL, NULL } };
const struct config_service *config_all_services = test_config_all_services;

static const struct setting_parser_info *const infos[] = {
	&master_service_setting_parser_info,
	&ssl_setting_parser_info,
	&ssl_server_setting_parser_info,
	NULL
};

const struct setting_parser_info *const *all_infos = infos;

static const char *
find_embedded_ssl_server_cert(struct config_parsed *config)
{
	struct config_filter_parser *const *parsers =
		config_parsed_get_filter_parsers(config);

	for (; *parsers != NULL; parsers++) {
		const struct config_module_parser *l =
			(*parsers)->module_parsers;
		unsigned int info_idx, key_idx;

		if (l == NULL)
			continue;
		for (info_idx = 0; l[info_idx].info != NULL; info_idx++) {
			if (strcmp(l[info_idx].info->name, "ssl_server") != 0)
				continue;
			if (!setting_parser_info_find_key(l[info_idx].info,
					"ssl_server_cert_file", &key_idx))
				continue;
			if (l[info_idx].change_counters == NULL ||
			    l[info_idx].change_counters[key_idx] == 0)
				continue;
			return set_str_expanded(&l[info_idx].settings[key_idx]);
		}
	}
	return NULL;
}

static void write_config_file(const char *contents)
{
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);
	struct ostream *os = o_stream_create_file(config_file, 0, 0600, 0);

	o_stream_nsend_str(os, contents);
	test_assert(o_stream_finish(os) == 1);
	o_stream_unref(&os);
}

static void write_cert_file(const char *path)
{
	struct ostream *os = o_stream_create_file(path, 0, 0644, 0);

	o_stream_nsend_str(os,
		"-----BEGIN CERTIFICATE-----\n"
		"TESTCERT\n"
		"-----END CERTIFICATE-----\n");
	test_assert(o_stream_finish(os) == 1);
	o_stream_unref(&os);
}

static void test_environment_file_embed(void)
{
	struct config_parsed *config;
	const char *error = NULL;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);
	const char *cert_file = test_dir_prepend(TEST_CERT_FILE);
	const char *cert_setting;
	string_t *conf;

	test_begin("environment file embed");

	env_remove("TEST_SSL_CERT");
	i_unlink_if_exists(cert_file);
	write_cert_file(cert_file);

	conf = t_str_new(256);
	str_printfa(conf,
		"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
		"environment {\n"
		"  TEST_SSL_CERT = %s\n"
		"}\n"
		"ssl = yes\n"
		"ssl_server {\n"
		"  cert_file = %%{env:TEST_SSL_CERT}\n"
		"}\n", cert_file);
	write_config_file(str_c(conf));

	test_assert(config_parse_file(config_file,
				      CONFIG_PARSE_FLAG_NO_DEFAULTS,
				      NULL, &config, &error) == 1);
	if (error != NULL)
		i_error("config_parse_file(): %s", error);

	cert_setting = find_embedded_ssl_server_cert(config);
	test_assert(cert_setting != NULL);
	test_assert(strchr(cert_setting, '\n') != NULL);
	test_assert(strstr(cert_setting, "BEGIN CERTIFICATE") != NULL);
	test_assert(strstr(cert_setting, cert_file) != NULL);

	config_parsed_free(&config);
	config_parser_deinit();
	i_unlink_if_exists(config_file);
	i_unlink_if_exists(cert_file);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_environment_file_embed,
		NULL
	};

	test_dir_init("environment-file-embed");
	return test_run(test_functions);
}
