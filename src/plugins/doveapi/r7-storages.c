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
#include <sys/statvfs.h>

void cmd_storages(struct doveadm_cmd_context *cctx);
void cmd_storage_stat(struct doveadm_cmd_context *cctx);

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

/*
 * Return statistics for a mounted block device (by device path, e.g. /dev/sda1).
 * Uses mountlist to find the mount point, then statvfs() for capacity/inode stats.
 */
void cmd_storage_stat(struct doveadm_cmd_context *cctx)
{
	const char *device;
	struct mount_entry *list;
	struct mount_entry *me;
	struct statvfs buf;

	if (!doveadm_cmd_param_str(cctx, "device", &device) || device == NULL || *device == '\0') {
		e_error(cctx->event, "Usage: r7_storage_stat <device>");
		doveadm_exit_code = EX_USAGE;
		return;
	}

	list = read_file_system_list(TRUE);
	if (list == NULL) {
		e_error(cctx->event, "Failed to read mount table: %m");
		doveadm_exit_code = EX_TEMPFAIL;
		return;
	}

	for (me = list; me != NULL; me = me->me_next) {
		if (!str_begins_with(me->me_devname, "/dev/"))
			continue;
		if (strcmp(me->me_devname, device) == 0)
			break;
	}

	if (me == NULL) {
		e_error(cctx->event, "Device '%s' not found or not mounted", device);
		free_mount_list(list);
		doveadm_exit_code = EX_NOINPUT;
		return;
	}

	if (statvfs(me->me_mountdir, &buf) != 0) {
		e_error(cctx->event, "statvfs(%s) failed: %m", me->me_mountdir);
		free_mount_list(list);
		doveadm_exit_code = EX_TEMPFAIL;
		return;
	}

	{
		uintmax_t total_bytes = (uintmax_t)buf.f_blocks * buf.f_frsize;
		uintmax_t free_bytes = (uintmax_t)buf.f_bfree * buf.f_frsize;
		uintmax_t available_bytes = (uintmax_t)buf.f_bavail * buf.f_frsize;

		doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
		doveadm_print_header_simple("device");
		doveadm_print_header_simple("mountpoint");
		doveadm_print_header_simple("fstype");
		doveadm_print_header("total_bytes", "total_bytes", DOVEADM_PRINT_HEADER_FLAG_NUMBER);
		doveadm_print_header("free_bytes", "free_bytes", DOVEADM_PRINT_HEADER_FLAG_NUMBER);
		doveadm_print_header("available_bytes", "available_bytes", DOVEADM_PRINT_HEADER_FLAG_NUMBER);
		doveadm_print_header_simple("block_size");
		doveadm_print_header("total_inodes", "total_inodes", DOVEADM_PRINT_HEADER_FLAG_NUMBER);
		doveadm_print_header("free_inodes", "free_inodes", DOVEADM_PRINT_HEADER_FLAG_NUMBER);

		doveadm_print(me->me_devname);
		doveadm_print(me->me_mountdir);
		doveadm_print(me->me_type != NULL ? me->me_type : "");
		doveadm_print_num(total_bytes);
		doveadm_print_num(free_bytes);
		doveadm_print_num(available_bytes);
		doveadm_print_num((uintmax_t)buf.f_frsize);
		doveadm_print_num((uintmax_t)buf.f_files);
		doveadm_print_num((uintmax_t)buf.f_ffree);
	}

	free_mount_list(list);
}

struct doveadm_cmd_ver2 r7_storages = {
	.name = "r7_storages",
	.cmd = cmd_storages,
	.usage = "List mounted block devices (device, mountpoint, fstype, dummy, remote, mntroot)",
	DOVEADM_CMD_PARAMS_START DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 r7_storage_stat = {
	.name = "r7_storage_stat",
	.cmd = cmd_storage_stat,
	.usage = "<device>  - Statistics for a mounted block device (e.g. /dev/sda1)",
	DOVEADM_CMD_PARAMS_START
		DOVEADM_CMD_PARAM('\0', "device", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
	DOVEADM_CMD_PARAMS_END
};
