/* Copyright (c) 2006-2025 Dovecot authors, see the included COPYING file */

#ifndef MOUNTLIST_H
#define MOUNTLIST_H

/* Mount table entry (API compatible with Gnulib mountlist.h). */
struct mount_entry {
	char *me_devname;      /* Device node name, e.g. "/dev/sda1". */
	char *me_mountdir;     /* Mount point path. */
	char *me_mntroot;      /* Root of (bind) mount on the device, or NULL. */
	char *me_type;         /* Filesystem type: "ext4", "nfs", etc. */
	dev_t me_dev;          /* Device number of me_mountdir. */
	unsigned int me_dummy : 1;  /* Nonzero for dummy/virtual filesystems. */
	unsigned int me_remote : 1;  /* Nonzero for remote filesystems. */
	unsigned int me_type_malloced : 1;
	struct mount_entry *me_next;
};

/* Return a list of currently mounted filesystems, or NULL on error.
   Entries are appended so order is preserved.
   If need_fs_type is true, me_type is always filled (on some platforms
   it might otherwise be empty). */
struct mount_entry *read_file_system_list(bool need_fs_type);

/* Free a single mount entry (and its me_next chain if non-NULL). */
void free_mount_entry(struct mount_entry *me);

/* Free entire list. */
void free_mount_list(struct mount_entry *list);

#endif
