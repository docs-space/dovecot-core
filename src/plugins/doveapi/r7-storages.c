/* Copyright (c) 2025 R7-Office owners, author Talipov Ilja
 * [https://github.com/GromySkynet] */

#include "lib.h"
#include "strfuncs.h"
#include "mountpoint.h"
#include "module-dir.h"
#include "event-log.h"
#include "doveadm-print.h"
#include "doveadm-cmd.h"
#include "config.h"

#include <getopt.h>
#include <unistd.h>

void cmd_storages(struct doveadm_cmd_context *cctx);

/*
 * List mounted block devices (device path, mount point, filesystem type).
 * Uses mountpoint_iter to read system mount table and filters entries
 * whose device path starts with "/dev/" (block devices).
 */
void cmd_storages(struct doveadm_cmd_context *cctx)
{
	struct mountpoint_iter *iter;
	const struct mountpoint *mnt;

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header_simple("device");
	doveadm_print_header_simple("mountpoint");
	doveadm_print_header_simple("fstype");

	iter = mountpoint_iter_init();
	while ((mnt = mountpoint_iter_next(iter)) != NULL) {
		/* Only block devices: /dev/sda1, /dev/nvme0n1p1, etc. */
		if (!str_begins_with(mnt->device_path, "/dev/"))
			continue;
		doveadm_print(mnt->device_path);
		doveadm_print(mnt->mount_path);
		doveadm_print(mnt->type != NULL ? mnt->type : "");
	}
	if (mountpoint_iter_deinit(&iter) < 0) {
		e_error(cctx->event, "Failed to read mount table: %m");
		doveadm_exit_code = EX_TEMPFAIL;
	}
}

struct doveadm_cmd_ver2 r7_storages = {
	.name = "r7_storages",
	.cmd = cmd_storages,
	.usage = "List mounted block devices (device, mountpoint, fstype)",
	DOVEADM_CMD_PARAMS_START DOVEADM_CMD_PARAMS_END
};