/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"
#include "ostream.h"
#include "master-service.h"
#include "all-settings.h"
#include "config-parser.h"
#include "dovecot-version.h"
#include "test-common.h"
#include "test-dir.h"

#define TEST_CONFIG_FILE "environment.conf"

static void write_config_file(const char *contents)
{
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);
	struct ostream *os = o_stream_create_file(config_file, 0, 0600, 0);
	o_stream_nsend_str(os, contents);
	test_assert(o_stream_finish(os) == 1);
	o_stream_unref(&os);
}

static void test_environment_early_apply(void)
{
	struct config_parsed *config;
	const char *error = NULL;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);
	const char *environment;

	test_begin("environment early apply");

	env_remove("TEST_MDA_PORT");

	write_config_file(
		"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
		"environment {\n"
		"  TEST_MDA_PORT = 4242\n"
		"}\n");

	test_assert(config_parse_file(config_file,
				      CONFIG_PARSE_FLAG_NO_DEFAULTS,
				      NULL, &config, &error) == 1);
	if (error != NULL)
		i_error("config_parse_file(): %s", error);

	environment = config_parsed_get_setting(config, "master_service",
					      "environment");
	test_assert(environment != NULL);
	test_assert(strstr(environment, "TEST_MDA_PORT=4242") != NULL);

	master_service_import_environment(environment);
	test_assert_strcmp(getenv("TEST_MDA_PORT"), "4242");

	config_parsed_free(&config);
	config_parser_deinit();
	i_unlink_if_exists(config_file);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_environment_early_apply,
		NULL
	};

	test_dir_init("environment-early");
	return test_run(test_functions);
}
