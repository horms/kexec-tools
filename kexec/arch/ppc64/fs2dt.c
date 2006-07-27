/*
 * fs2dt: creates a flattened device-tree
 *
 * Copyright (C) 2004,2005  Milton D Miller II, IBM Corporation
 * Copyright (C) 2005  R Sharada (sharada@in.ibm.com), IBM Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation (version 2 of the License).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "kexec-ppc64.h"

#define MAXPATH 1024		/* max path name length */
#define NAMESPACE 16384		/* max bytes for property names */
#define TREEWORDS 65536		/* max 32 bit words for property values */
#define MEMRESERVE 256		/* max number of reserved memory blocks */

enum {
	ERR_NONE,
	ERR_USAGE,
	ERR_OPENDIR,
	ERR_READDIR,
	ERR_STAT,
	ERR_OPEN,
	ERR_READ,
	ERR_RESERVE,
};

void err(const char *str, int rc)
{
	if (errno)
		perror(str);
	else
		fprintf(stderr, "%s: unrecoverable error\n", str);
	exit(rc);
}

typedef unsigned dvt;
struct stat statbuf[1];
char pathname[MAXPATH], *pathstart;
char propnames[NAMESPACE];
dvt dtstruct[TREEWORDS], *dt;
unsigned long long mem_rsrv[2*MEMRESERVE];

extern unsigned long initrd_base;
extern unsigned long initrd_size;
static int initrd_found = 0;

void reserve(unsigned long long where, unsigned long long length)
{
	unsigned long long *mr;

	mr = mem_rsrv;

	while(mr[1])
		mr += 2;

	mr[0] = where;
	mr[1] = length;
}

/* look for properties we need to reserve memory space for */
void checkprop(char *name, dvt *data)
{
	static unsigned long long base, size, end;

	if ((data == NULL) && (base || size || end))
			err((void *)data, ERR_RESERVE);
	else if (!strcmp(name, "linux,rtas-base"))
		base = *data;
	else if (!strcmp(name, "linux,initrd-start")) {
		if (initrd_base)
			*(unsigned long long *) data = initrd_base;
		base = *(unsigned long long *)data;
		initrd_found = 1;
	}
	else if (!strcmp(name, "linux,tce-base"))
		base = *(unsigned long long *) data;
	else if (!strcmp(name, "rtas-size") ||
			!strcmp(name, "linux,tce-size"))
		size = *data;
	else if (!strcmp(name, "linux,initrd-end")) {
		if (initrd_size) {
			*(unsigned long long *) data = initrd_base +
							initrd_size;
			size = initrd_size;
		} else
			end = *(unsigned long long *)data;
		initrd_found = 1;
	}
	if (size && end)
		err(name, ERR_RESERVE);
	if (base && size) {
		reserve(base, size);
		base = size = 0;
	}
	if (base && end) {
		reserve(base, end-base);
		base = end = 0;
	}
}

/*
 * return the property index for a property name, creating a new one
 * if needed.
 */
dvt propnum(const char *name)
{
	dvt offset = 0;

	while(propnames[offset])
		if (strcmp(name, propnames+offset))
			offset += strlen(propnames+offset)+1;
		else
			return offset;

	strcpy(propnames+offset, name);

	return offset;
}

/* put all properties (files) in the property structure */
void putprops(char *fn, DIR *dir)
{
	struct dirent *dp;

	while ((dp = readdir(dir)) != NULL) {
		strcpy(fn, dp->d_name);

		if (lstat(pathname, statbuf))
			err(pathname, ERR_STAT);

		/* skip initrd entries if 2nd kernel does not need them */
		if (!initrd_base && !strcmp(fn,"linux,initrd-end"))
			continue;

		if (!initrd_base && !strcmp(fn,"linux,initrd-start"))
			continue;

		/*
		 * This property will be created for each node during kexec
		 * boot. So, ignore it.
		 */
		if (!strcmp(dp->d_name, "linux,pci-domain") ||
			!strcmp(dp->d_name, "linux,htab-base") ||
			!strcmp(dp->d_name, "linux,htab-size") ||
			!strcmp(dp->d_name, "linux,kernel-end"))
			continue;

		if (S_ISREG(statbuf[0].st_mode)) {
			int fd, len = statbuf[0].st_size;

			*dt++ = 3;
			*dt++ = len;
			*dt++ = propnum(fn);

			if ((len >= 8) && ((unsigned long)dt & 0x4))
				dt++;

			fd = open(pathname, O_RDONLY);
			if (fd == -1)
				err(pathname, ERR_OPEN);
			if (read(fd, dt, len) != len)
				err(pathname, ERR_READ);
			close(fd);

			checkprop(fn, dt);

			dt += (len + 3)/4;
		}
	}
	fn[0] = '\0';
	if(errno == ENOSYS)
		errno = 0;
	if (errno)
		err(pathname, ERR_READDIR);
	checkprop(pathname, NULL);
}

/*
 * put a node (directory) in the property structure.  first properties
 * then children.
 */
void putnode(void)
{
	DIR *dir;
	char *dn;
	struct dirent *dp;
	char *basename;

	*dt++ = 1;
	strcpy((void *)dt, *pathstart ? pathstart : "/");
	while(*dt)
		dt++;
	if (dt[-1] & 0xff)
		dt++;

	dir = opendir(pathname);

	if (!dir)
		err(pathname, ERR_OPENDIR);

	basename = strrchr(pathname,'/');

	strcat(pathname, "/");
	dn = pathname + strlen(pathname);

	putprops(dn, dir);

	/* Add initrd entries to the second kernel if first kernel does not
	 * have and second kernel needs.
	 */
	if (initrd_base && !initrd_found && !strcmp(basename,"/chosen/")) {
		int len = 8;
		unsigned long long initrd_end;
		*dt++ = 3;
		*dt++ = len;
		*dt++ = propnum("linux,initrd-start");

		if ((len >= 8) && ((unsigned long)dt & 0x4))
			dt++;

		memcpy(dt,&initrd_base,len);
		dt += (len + 3)/4;

		len = 8;
		*dt++ = 3;
		*dt++ = len;
		*dt++ = propnum("linux,initrd-end");

		initrd_end = initrd_base + initrd_size;
		if ((len >= 8) && ((unsigned long)dt & 0x4))
			dt++;

		memcpy(dt,&initrd_end,8);
		dt += (len + 3)/4;

		reserve(initrd_base, initrd_size);
	}

	rewinddir(dir);

	while ((dp = readdir(dir)) != NULL) {
		strcpy(dn, dp->d_name);

		if (!strcmp(dn, ".") || !strcmp(dn, ".."))
			continue;

		if (lstat(pathname, statbuf))
			err(pathname, ERR_STAT);

		if (S_ISDIR(statbuf[0].st_mode))
			putnode();
	}
	if (errno)
		err(pathname, ERR_READDIR);

	*dt++ = 2;
	closedir(dir);
	dn[-1] = '\0';
}

struct bootblock bb[1];

int create_flatten_tree(struct kexec_info *info, unsigned char **bufp, unsigned long *sizep)
{
	unsigned long len;
	unsigned long tlen;
	unsigned char *buf;
	unsigned long me;

	me = 0;

	strcpy(pathname, "/proc/device-tree/");

	pathstart = pathname + strlen(pathname);
	dt = dtstruct;

	putnode();
	*dt++ = 9;

	len = sizeof(bb[0]);
	len += 7; len &= ~7;

	bb->off_mem_rsvmap = len;

	for (len = 1; mem_rsrv[len]; len += 2)
		;
	len+= 3;
	len *= sizeof(mem_rsrv[0]);

	bb->off_dt_struct = bb->off_mem_rsvmap + len;

	len = dt - dtstruct;
	len *= sizeof(dvt);
	bb->off_dt_strings = bb->off_dt_struct + len;

	len = propnum("");
	len +=  3; len &= ~3;
	bb->totalsize = bb->off_dt_strings + len;

	bb->magic = 0xd00dfeed;
	bb->version = 2;
	bb->last_comp_version = 2;

	reserve(me, bb->totalsize); /* patched later in kexec_load */

	buf = (unsigned char *) realloc(*bufp, *sizep + bb->totalsize);
	*bufp = buf;
	memcpy(buf+(*sizep), bb, bb->off_mem_rsvmap);
	tlen = *sizep + bb->off_mem_rsvmap;
	memcpy(buf+tlen, mem_rsrv, bb->off_dt_struct - bb->off_mem_rsvmap);
	tlen = tlen + (bb->off_dt_struct - bb->off_mem_rsvmap);
	memcpy(buf+tlen, dtstruct,  bb->off_dt_strings - bb->off_dt_struct);
	tlen = tlen +  (bb->off_dt_strings - bb->off_dt_struct);
	memcpy(buf+tlen, propnames,  bb->totalsize - bb->off_dt_strings);
	tlen = tlen + bb->totalsize - bb->off_dt_strings;
	*sizep = tlen;
	return 0;
}
