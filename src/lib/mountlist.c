/* Copyright (c) 2006-2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mountlist.h"

#include <sys/stat.h>

#ifdef HAVE_SYS_VMOUNT_H
#  include <stdio.h>
#  include <sys/vmount.h>
#  define MOUNTLIST_AIX
#elif defined(HAVE_STATVFS_MNTFROMNAME)
#  include <sys/statvfs.h>
#  define MOUNTLIST_STATVFS
#elif defined(HAVE_STATFS_MNTFROMNAME)
#  include <sys/param.h>
#  include <sys/mount.h>
#  define statvfs statfs
#  define MOUNTLIST_STATVFS
#elif defined(HAVE_MNTENT_H)
#  include <stdio.h>
#  include <mntent.h>
#  define MOUNTLIST_LINUX
#elif defined(HAVE_SYS_MNTTAB_H)
#  include <stdio.h>
#  include <sys/mnttab.h>
#  include <sys/mntent.h>
#  define MOUNTLIST_SOLARIS
#else
#  define MOUNTLIST_UNKNOWN
#endif

#ifdef MOUNTLIST_SOLARIS
#  define MTAB_PATH MNTTAB
#else
#  define MTAB_PATH "/etc/mtab"
#endif

#ifndef MNTTYPE_SWAP
#  define MNTTYPE_SWAP "swap"
#endif
#ifndef MNTTYPE_IGNORE
#  define MNTTYPE_IGNORE "ignore"
#endif
#ifndef MNTTYPE_ROOTFS
#  define MNTTYPE_ROOTFS "rootfs"
#endif

/* ME_DUMMY: virtual/dummy filesystems (no real block device). */
#define ME_DUMMY_0(fs_type) \
	(strcmp((fs_type), "autofs") == 0 || \
	 strcmp((fs_type), "proc") == 0 || \
	 strcmp((fs_type), "subfs") == 0 || \
	 strcmp((fs_type), "debugfs") == 0 || \
	 strcmp((fs_type), "devpts") == 0 || \
	 strcmp((fs_type), "fusectl") == 0 || \
	 strcmp((fs_type), "fuse.portal") == 0 || \
	 strcmp((fs_type), "mqueue") == 0 || \
	 strcmp((fs_type), "rpc_pipefs") == 0 || \
	 strcmp((fs_type), "sysfs") == 0 || \
	 strcmp((fs_type), "devfs") == 0 || \
	 strcmp((fs_type), "kernfs") == 0)

#define ME_DUMMY(fs_name, fs_type, bind) \
	(ME_DUMMY_0(fs_type) || \
	 (strcmp((fs_type), "none") == 0 && !(bind)))

/* ME_REMOTE: network or cluster filesystems. */
#define ME_REMOTE(fs_name, fs_type) \
	(strchr((fs_name), ':') != NULL || \
	 ((fs_name)[0] == '/' && (fs_name)[1] == '/' && \
	  (strcmp((fs_type), "smbfs") == 0 || strcmp((fs_type), "smb3") == 0 || \
	   strcmp((fs_type), "cifs") == 0)) || \
	 strcmp((fs_type), "nfs") == 0 || strcmp((fs_type), "nfs4") == 0 || \
	 strcmp((fs_type), "cifs") == 0 || strcmp((fs_type), "afs") == 0 || \
	 strcmp((fs_type), "coda") == 0 || strcmp((fs_type), "ocfs2") == 0 || \
	 strcmp((fs_name), "-hosts") == 0)

#if defined(MOUNTLIST_LINUX) && (defined(__linux__) || defined(__ANDROID__))
/* Advance *p past spaces, then read next path (unescaped) into buf, max len.
   Returns buf or NULL if no more token. *p is advanced. */
static char *mountinfo_next_path(char **p, char *buf, size_t bufsize)
{
	char *s = *p;
	while (*s == ' ' || *s == '\t') s++;
	if (!*s || *s == '\n') return NULL;
	char *out = buf;
	size_t remain = bufsize - 1;
	while (remain > 0 && *s && *s != ' ' && *s != '\t' && *s != '\n') {
		if (s[0] == '\\' && s[1] >= '0' && s[1] <= '7' &&
		    s[2] >= '0' && s[2] <= '7' && s[3] >= '0' && s[3] <= '7') {
			*out++ = (char)((s[1]-'0')*64 + (s[2]-'0')*8 + (s[3]-'0'));
			s += 4;
			remain--;
		} else {
			*out++ = *s++;
			remain--;
		}
	}
	*out = '\0';
	*p = s;
	return buf;
}

static struct mount_entry *read_mountinfo(void)
{
	FILE *fp;
	char *line = NULL;
	size_t line_size = 0;
	struct mount_entry *list = NULL;
	struct mount_entry **tail = &list;
	const char *path = "/proc/self/mountinfo";

	fp = fopen(path, "re");
	if (fp == NULL)
		return NULL;

	while (getline(&line, &line_size, fp) != -1) {
		char *dash = strstr(line, " - ");
		if (dash == NULL) continue;
		*dash = '\0';
		char *left = line;
		char *right = dash + 3;

		unsigned int maj = 0, min = 0;
		int n = 0;
		if (sscanf(left, "%*u %*u %u:%u %n", &maj, &min, &n) < 2)
			continue;
		char *fields = left + n;

		char root_buf[4096], mountdir_buf[4096];
		char *root = mountinfo_next_path(&fields, root_buf, sizeof(root_buf));
		char *mountdir = mountinfo_next_path(&fields, mountdir_buf, sizeof(mountdir_buf));
		if (root == NULL || mountdir == NULL) continue;

		char fstype_buf[256], source_buf[4096];
		char *fstype = mountinfo_next_path(&right, fstype_buf, sizeof(fstype_buf));
		char *source = mountinfo_next_path(&right, source_buf, sizeof(source_buf));
		if (fstype == NULL || source == NULL) continue;

		struct mount_entry *me = i_malloc(sizeof(*me));
		me->me_devname = i_strdup(source);
		me->me_mountdir = i_strdup(mountdir);
		me->me_mntroot = i_strdup(root);
		me->me_type = i_strdup(fstype);
		me->me_type_malloced = 1;
		me->me_dev = makedev(maj, min);
		me->me_dummy = ME_DUMMY(me->me_devname, me->me_type, false);
		me->me_remote = ME_REMOTE(me->me_devname, me->me_type);
		me->me_next = NULL;

		*tail = me;
		tail = &me->me_next;
	}
	i_free(line);
	fclose(fp);
	return list;
}
#endif

struct mount_entry *read_file_system_list(bool need_fs_type ATTR_UNUSED)
{
	struct mount_entry *list = NULL;
	struct mount_entry **tail = &list;

#if defined(MOUNTLIST_LINUX) && (defined(__linux__) || defined(__ANDROID__))
	{
		list = read_mountinfo();
		if (list != NULL)
			return list;
		/* Fallback to getmntent. */
	}
#endif

#ifdef MOUNTLIST_LINUX
	{
		FILE *mfp = setmntent(MTAB_PATH, "r");
		if (mfp == NULL)
			return NULL;

		const struct mntent *mnt;
		struct stat st;
		while ((mnt = getmntent(mfp)) != NULL) {
			if (strcmp(mnt->mnt_type, MNTTYPE_SWAP) == 0 ||
			    strcmp(mnt->mnt_type, MNTTYPE_IGNORE) == 0 ||
			    strcmp(mnt->mnt_type, MNTTYPE_ROOTFS) == 0)
				continue;

			bool bind = (hasmntopt(mnt, "bind") != NULL);
			struct mount_entry *me = i_malloc(sizeof(*me));
			me->me_devname = i_strdup(mnt->mnt_fsname);
			me->me_mountdir = i_strdup(mnt->mnt_dir);
			me->me_mntroot = NULL;
			me->me_type = i_strdup(mnt->mnt_type);
			me->me_type_malloced = 1;
			me->me_dummy = ME_DUMMY(me->me_devname, me->me_type, bind);
			me->me_remote = ME_REMOTE(me->me_devname, me->me_type);
			me->me_dev = (dev_t)-1;
			if (stat(mnt->mnt_dir, &st) == 0)
				me->me_dev = st.st_dev;
			me->me_next = NULL;

			*tail = me;
			tail = &me->me_next;
		}
		if (endmntent(mfp) != 1) {
			free_mount_list(list);
			return NULL;
		}
	}
#endif

#ifdef MOUNTLIST_SOLARIS
	{
		FILE *fp = fopen(MTAB_PATH, "re");
		if (fp == NULL)
			return NULL;

		union {
			struct mnttab ent;
			struct extmnttab ext;
		} ent;

		while (getextmntent(fp, &ent.ext, sizeof(ent.ext)) == 0) {
			if (hasmntopt(&ent.ent, MNTOPT_IGNORE) != NULL)
				continue;
			if (strcmp(ent.ent.mnt_special, MNTTYPE_SWAP) == 0)
				continue;

			struct mount_entry *me = i_malloc(sizeof(*me));
			me->me_devname = i_strdup(ent.ent.mnt_special);
			me->me_mountdir = i_strdup(ent.ent.mnt_mountp);
			me->me_mntroot = NULL;
			me->me_type = i_strdup(ent.ent.mnt_fstype);
			me->me_type_malloced = 1;
			me->me_dev = makedev(ent.ext.mnt_major, ent.ext.mnt_minor);
			me->me_dummy = ME_DUMMY(me->me_devname, me->me_type, false);
			me->me_remote = ME_REMOTE(me->me_devname, me->me_type);
			me->me_next = NULL;

			*tail = me;
			tail = &me->me_next;
		}
		if (fclose(fp) != 0 && list != NULL) {
			free_mount_list(list);
			return NULL;
		}
	}
#endif

#ifdef MOUNTLIST_AIX
	{
		unsigned int size = STATIC_MTAB_SIZE;
		char *mtab = t_buffer_get(size);
		int count;
		while ((count = mntctl(MCTL_QUERY, size, mtab)) == 0) {
			size = *(unsigned int *)mtab;
			mtab = t_buffer_get(size);
		}
		if (count < 0) {
			errno = EIO;
			return NULL;
		}
		char *thisent = mtab;
		for (int i = 0; i < count; i++) {
			struct vmount *vmp = (struct vmount *)thisent;
			char *obj = thisent + vmp->vmt_data[VMT_OBJECT].vmt_off;
			char *stub = thisent + vmp->vmt_data[VMT_STUB].vmt_off;
			/* Only NFS and JFS like mountpoint.c */
			if (vmp->vmt_gfstype != MNT_NFS && vmp->vmt_gfstype != MNT_NFS3 &&
			    vmp->vmt_gfstype != MNT_NFS4 && vmp->vmt_gfstype != MNT_RFS4 &&
			    vmp->vmt_gfstype != MNT_J2 && vmp->vmt_gfstype != MNT_JFS) {
				thisent += vmp->vmt_length;
				continue;
			}
			struct mount_entry *me = i_malloc(sizeof(*me));
			if (vmp->vmt_gfstype == MNT_NFS || vmp->vmt_gfstype == MNT_NFS3 ||
			    vmp->vmt_gfstype == MNT_NFS4 || vmp->vmt_gfstype == MNT_RFS4) {
				char *host = thisent + vmp->vmt_data[VMT_HOSTNAME].vmt_off;
				me->me_devname = i_strconcat(host, ":", obj, NULL);
				me->me_type = i_strdup("nfs");
			} else {
				me->me_devname = i_strdup(obj);
				me->me_type = i_strdup("jfs");
			}
			me->me_mountdir = i_strdup(stub);
			me->me_mntroot = NULL;
			me->me_type_malloced = 1;
			me->me_dev = (dev_t)-1;
			me->me_dummy = 0;
			me->me_remote = (vmp->vmt_gfstype == MNT_NFS || vmp->vmt_gfstype == MNT_NFS3 ||
			                 vmp->vmt_gfstype == MNT_NFS4 || vmp->vmt_gfstype == MNT_RFS4);
			me->me_next = NULL;
			*tail = me;
			tail = &me->me_next;
			thisent += vmp->vmt_length;
		}
	}
#endif

#if defined(HAVE_GETMNTINFO) && (defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__))
	{
#ifndef __NetBSD__
		struct statfs *fsp;
#else
		struct statvfs *fsp;
#endif
		int entries = getmntinfo(&fsp, MNT_NOWAIT);
		if (entries < 0)
			return NULL;
		for (; entries-- > 0; fsp++) {
			struct mount_entry *me = i_malloc(sizeof(*me));
			me->me_devname = i_strdup(fsp->f_mntfromname);
			me->me_mountdir = i_strdup(fsp->f_mntonname);
			me->me_mntroot = NULL;
#ifdef __osf__
			me->me_type = i_strdup(getvfsbynumber(fsp->f_type));
#else
			me->me_type = i_strdup(fsp->f_fstypename);
#endif
			me->me_type_malloced = 1;
			me->me_dev = (dev_t)-1;
			me->me_dummy = ME_DUMMY(me->me_devname, me->me_type, false);
			me->me_remote = ME_REMOTE(me->me_devname, me->me_type);
			me->me_next = NULL;
			*tail = me;
			tail = &me->me_next;
		}
	}
#endif

#ifdef MOUNTLIST_UNKNOWN
	errno = ENOSYS;
	return NULL;
#endif

	return list;
}

void free_mount_entry(struct mount_entry *me)
{
	if (me == NULL) return;
	i_free(me->me_devname);
	i_free(me->me_mountdir);
	i_free(me->me_mntroot);
	if (me->me_type_malloced)
		i_free(me->me_type);
	i_free(me);
}

void free_mount_list(struct mount_entry *list)
{
	while (list != NULL) {
		struct mount_entry *next = list->me_next;
		free_mount_entry(list);
		list = next;
	}
}
