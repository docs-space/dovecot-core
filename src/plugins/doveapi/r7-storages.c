/* Copyright (c) 2025 R7-Office owners, author Talipov Ilja
 * [https://github.com/GromySkynet] */

#include "lib.h"
#include "strfuncs.h"
#include "mountlist.h"
#include "doveadm-print.h"
#include "doveadm-cmd.h"
#include "config.h"

#include <getopt.h>
#include <unistd.h>

void cmd_storages(struct doveadm_cmd_context *cctx);

/*
 * List mounted block devices using mountlist (full API: device, mountpoint,
 * fstype, dummy, remote, mntroot). Filters entries whose device path
 * starts with "/dev/" (block devices).
 */
void cmd_storages(struct doveadm_cmd_context *cctx)
{
	struct mount_entry *list;
	struct mount_entry *me;

	list = read_file_system_list(TRUE);
	if (list == NULL) {
		e_error(cctx->event, "Failed to read mount table: %m");
		doveadm_exit_code = EX_TEMPFAIL;
		return;
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header_simple("device");
	doveadm_print_header_simple("mountpoint");
	doveadm_print_header_simple("fstype");
	doveadm_print_header_simple("dummy");
	doveadm_print_header_simple("remote");
	doveadm_print_header_simple("mntroot");

	for (me = list; me != NULL; me = me->me_next) {
		/* Only block devices: /dev/sda1, /dev/nvme0n1p1, etc. */
		if (!str_begins_with(me->me_devname, "/dev/"))
			continue;
		doveadm_print(me->me_devname);
		doveadm_print(me->me_mountdir);
		doveadm_print(me->me_type != NULL ? me->me_type : "");
		doveadm_print(me->me_dummy ? "1" : "0");
		doveadm_print(me->me_remote ? "1" : "0");
		doveadm_print(me->me_mntroot != NULL ? me->me_mntroot : "");
	}

	free_mount_list(list);
}

struct doveadm_cmd_ver2 r7_storages = {
	.name = "r7_storages",
	.cmd = cmd_storages,
	.usage = "List mounted block devices (device, mountpoint, fstype, dummy, remote, mntroot)",
	DOVEADM_CMD_PARAMS_START DOVEADM_CMD_PARAMS_END
};
