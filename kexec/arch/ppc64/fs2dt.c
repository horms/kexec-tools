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

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "../../kexec.h"
#include "kexec-ppc64.h"
#include "crashdump-ppc64.h"

#define MAXPATH 1024		/* max path name length */
#define NAMESPACE 16384		/* max bytes for property names */
#define INIT_TREE_WORDS 65536	/* Initial num words for prop values */
#define MEMRESERVE 256		/* max number of reserved memory blocks */
#define MEM_RANGE_CHUNK_SZ 2048 /* Initial num dwords for mem ranges */

static char pathname[MAXPATH], *pathstart;
static char propnames[NAMESPACE] = { 0 };
static unsigned *dt_base, *dt;
static unsigned int dt_cur_size;
static unsigned long long mem_rsrv[2*MEMRESERVE] = { 0, 0 };

static int crash_param = 0;
static char local_cmdline[COMMAND_LINE_SIZE] = { "" };
extern mem_rgns_t usablemem_rgns;
static struct bootblock bb[1];
extern int my_debug;

/* Before we add something to the dt, reserve N words using this.
 * If there isn't enough room, it's realloced -- and you don't overflow and
 * splat bits of your heap. 
 */
void dt_reserve(unsigned **dt_ptr, unsigned words)
{
	if (((*dt_ptr - dt_base) + words) >= dt_cur_size) {
		int offset;
		unsigned int new_size = dt_cur_size + INIT_TREE_WORDS;
		unsigned *new_dt = realloc(dt_base, new_size*4);

		if (!new_dt)
			die("unrecoverable error: Can't realloc %d bytes for "
			    "device tree\n", new_size*4);
		offset = *dt_ptr - dt_base;
		dt_base = new_dt;
		dt_cur_size = new_size;
		*dt_ptr = dt_base + offset;
		memset(*dt_ptr, 0, (new_size - offset)*4);
	}
}

void reserve(unsigned long long where, unsigned long long length)
{
	size_t offset;

	for (offset = 0; mem_rsrv[offset + 1]; offset += 2)
		;

	if (offset + 4 >= 2 * MEMRESERVE)
		die("unrecoverable error: exhasuted reservation meta data\n");

	mem_rsrv[offset] = where;
	mem_rsrv[offset + 1] = length;
	mem_rsrv[offset + 3] = 0;  /* N.B: don't care about offset + 2 */
}

/* look for properties we need to reserve memory space for */
static void checkprop(char *name, unsigned *data, int len)
{
	static unsigned long long base, size, end;

	if ((data == NULL) && (base || size || end))
		die("unrecoverable error: no property data");
	else if (!strcmp(name, "linux,rtas-base"))
		base = *data;
	else if (!strcmp(name, "linux,tce-base"))
		base = *(unsigned long long *) data;
	else if (!strcmp(name, "rtas-size") ||
			!strcmp(name, "linux,tce-size"))
		size = *data;
	else if (reuse_initrd && !strcmp(name, "linux,initrd-start"))
		if (len == 8)
			base = *(unsigned long long *) data;
		else
			base = *data;
	else if (reuse_initrd && !strcmp(name, "linux,initrd-end"))
		end = *(unsigned long long *) data;

	if (size && end)
		die("unrecoverable error: size and end set at same time\n");
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
static unsigned propnum(const char *name)
{
	unsigned offset = 0;

	while(propnames[offset])
		if (strcmp(name, propnames+offset))
			offset += strlen(propnames+offset)+1;
		else
			return offset;

	if (NAMESPACE - offset < strlen(name) + 1)
		die("unrecoverable error: propnames overrun\n");

	strcpy(propnames+offset, name);

	return offset;
}

static void add_dyn_reconf_usable_mem_property(int fd)
{
	char fname[MAXPATH], *bname;
	uint64_t buf[32];
	uint64_t *ranges;
	int ranges_size = MEM_RANGE_CHUNK_SZ;
	uint64_t base, end, loc_base, loc_end;
	size_t i, rngs_cnt, range;
	int rlen = 0;
	int tmp_indx;

	strcpy(fname, pathname);
	bname = strrchr(fname, '/');
	bname[0] = '\0';
	bname = strrchr(fname, '/');
	if (strncmp(bname, "/ibm,dynamic-reconfiguration-memory", 36))
		return;

	if (lseek(fd, 4, SEEK_SET) < 0)
		die("unrecoverable error: error seeking in \"%s\": %s\n",
			pathname, strerror(errno));

	ranges = malloc(ranges_size*8);
	if (!ranges)
		die("unrecoverable error: can't alloc %d bytes for ranges.\n",
		    ranges_size*8);

	rlen = 0;
	for (i = 0; i < num_of_lmbs; i++) {
		if (read(fd, buf, 24) < 0)
			die("unrecoverable error: error reading \"%s\": %s\n",
				pathname, strerror(errno));

		base = (uint64_t) buf[0];
		end = base + lmb_size;
		if (~0ULL - base < end)
			die("unrecoverable error: mem property overflow\n");

		tmp_indx = rlen++;

		rngs_cnt = 0;
		for (range = 0; range < usablemem_rgns.size; range++) {
			int add = 0;
			loc_base = usablemem_rgns.ranges[range].start;
			loc_end = usablemem_rgns.ranges[range].end;
			if (loc_base >= base && loc_end <= end) {
				add = 1;
			} else if (base < loc_end && end > loc_base) {
				if (loc_base < base)
					loc_base = base;
				if (loc_end > end)
					loc_end = end;
				add = 1;
			}

			if (add) {
				if (rlen >= (ranges_size-2)) {
					ranges_size += MEM_RANGE_CHUNK_SZ;
					ranges = realloc(ranges, ranges_size*8);
					if (!ranges)
						die("unrecoverable error: can't"
						    " realloc %d bytes for"
						    " ranges.\n",
						    ranges_size*8);
				}
				ranges[rlen++] = loc_base;
				ranges[rlen++] = loc_end - loc_base;
				rngs_cnt++;
			}
		}
		if (rngs_cnt == 0) {
			/* We still need to add a counter for every LMB because
			 * the kernel parsing code is dumb.  We just have
			 * a zero in this case, with no following base/len.
			 */
			ranges[tmp_indx] = 0;
			/* rlen is already just tmp_indx+1 as we didn't write
			 * anything.  Check array size here, as we'll probably
			 * go on for a while writing zeros now.
			 */
			if (rlen >= (ranges_size-1)) {
				ranges_size += MEM_RANGE_CHUNK_SZ;
				ranges = realloc(ranges, ranges_size*8);
				if (!ranges)
					die("unrecoverable error: can't"
					    " realloc %d bytes for"
					    " ranges.\n",
					    ranges_size*8);
			}
		} else {
			/* Store the count of (base, size) duple */
			ranges[tmp_indx] = rngs_cnt;
		}
	}
		
	rlen = rlen * sizeof(uint64_t);
	/*
	 * Add linux,drconf-usable-memory property.
	 */
	dt_reserve(&dt, 4+((rlen + 3)/4));
	*dt++ = 3;
	*dt++ = rlen;
	*dt++ = propnum("linux,drconf-usable-memory");
	if ((rlen >= 8) && ((unsigned long)dt & 0x4))
		dt++;
	memcpy(dt, ranges, rlen);
	free(ranges);
	dt += (rlen + 3)/4;
}

static void add_usable_mem_property(int fd, size_t len)
{
	char fname[MAXPATH], *bname;
	uint64_t buf[2];
	uint64_t *ranges;
	int ranges_size = MEM_RANGE_CHUNK_SZ;
	uint64_t base, end, loc_base, loc_end;
	size_t range;
	int rlen = 0;
	ssize_t slen;

	strcpy(fname, pathname);
	bname = strrchr(fname,'/');
	bname[0] = '\0';
	bname = strrchr(fname,'/');
	if (strncmp(bname, "/memory@", 8))
		return;

	if (len < 2 * sizeof(uint64_t))
		die("unrecoverable error: not enough data for mem property\n");
	slen = 2 * sizeof(uint64_t);

	if (lseek(fd, 0, SEEK_SET) < 0)
		die("unrecoverable error: error seeking in \"%s\": %s\n",
		    pathname, strerror(errno));
	if (read(fd, buf, slen) != slen)
		die("unrecoverable error: error reading \"%s\": %s\n",
		    pathname, strerror(errno));

	if (~0ULL - buf[0] < buf[1])
		die("unrecoverable error: mem property overflow\n");
	base = buf[0];
	end = base + buf[1];

	ranges = malloc(ranges_size*8);
	if (!ranges)
		die("unrecoverable error: can't alloc %d bytes for ranges.\n",
		    ranges_size*8);

	for (range = 0; range < usablemem_rgns.size; range++) {
		int add = 0;
		loc_base = usablemem_rgns.ranges[range].start;
		loc_end = usablemem_rgns.ranges[range].end;
		if (loc_base >= base && loc_end <= end) {
			add = 1;
		} else if (base < loc_end && end > loc_base) {
			if (loc_base < base)
				loc_base = base;
			if (loc_end > end)
				loc_end = end;
			add = 1;
		}
		if (add) {
			if (rlen >= (ranges_size-2)) {
				ranges_size += MEM_RANGE_CHUNK_SZ;
				ranges = realloc(ranges, ranges_size*8);
				if (!ranges)
					die("unrecoverable error: can't realloc"
					    "%d bytes for ranges.\n",
					    ranges_size*8);
			}
			ranges[rlen++] = loc_base;
			ranges[rlen++] = loc_end - loc_base;
		}
	}

	if (!rlen) {
		/*
		 * User did not pass any ranges for thsi region. Hence, write
		 * (0,0) duple in linux,usable-memory property such that
		 * this region will be ignored.
		 */
		ranges[rlen++] = 0;
		ranges[rlen++] = 0;
	}

	rlen = rlen * sizeof(uint64_t);
	/*
	 * No add linux,usable-memory property.
	 */
	dt_reserve(&dt, 4+((rlen + 3)/4));
	*dt++ = 3;
	*dt++ = rlen;
	*dt++ = propnum("linux,usable-memory");
	if ((rlen >= 8) && ((unsigned long)dt & 0x4))
		dt++;
	memcpy(dt, ranges, rlen);
	free(ranges);
	dt += (rlen + 3)/4;
}

/* put all properties (files) in the property structure */
static void putprops(char *fn, struct dirent **nlist, int numlist)
{
	struct dirent *dp;
	int i = 0, fd;
	size_t len;
	ssize_t slen;
	struct stat statbuf;

	for (i = 0; i < numlist; i++) {
		dp = nlist[i];
		strcpy(fn, dp->d_name);

		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
                        continue;

		if (lstat(pathname, &statbuf))
			die("unrecoverable error: could not stat \"%s\": %s\n",
			    pathname, strerror(errno));

		if (!crash_param && !strcmp(fn,"linux,crashkernel-base"))
			continue;

		if (!crash_param && !strcmp(fn,"linux,crashkernel-size"))
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

		/* This property will be created/modified later in putnode()
		 * So ignore it, unless we are reusing the initrd.
		 */
		if ((!strcmp(dp->d_name, "linux,initrd-start") ||
		     !strcmp(dp->d_name, "linux,initrd-end")) &&
		    !reuse_initrd)
				continue;

		/* This property will be created later in putnode() So
		 * ignore it now.
		 */
		if (!strcmp(dp->d_name, "bootargs"))
			continue;

		if (! S_ISREG(statbuf.st_mode))
			continue;

		len = statbuf.st_size;

		dt_reserve(&dt, 4+((len + 3)/4));
		*dt++ = 3;
		*dt++ = len;
		*dt++ = propnum(fn);

		if ((len >= 8) && ((unsigned long)dt & 0x4))
			dt++;

		fd = open(pathname, O_RDONLY);
		if (fd == -1)
			die("unrecoverable error: could not open \"%s\": %s\n",
			    pathname, strerror(errno));

		slen = read(fd, dt, len);
		if (slen < 0)
			die("unrecoverable error: could not read \"%s\": %s\n",
			    pathname, strerror(errno));
		if ((size_t)slen != len)
			die("unrecoverable error: short read from\"%s\"\n",
			    pathname);

		checkprop(fn, dt, len);

		dt += (len + 3)/4;
		if (!strcmp(dp->d_name, "reg") && usablemem_rgns.size)
			add_usable_mem_property(fd, len);
		if (!strcmp(dp->d_name, "ibm,dynamic-memory") &&
					usablemem_rgns.size)
			add_dyn_reconf_usable_mem_property(fd);

		close(fd);
	}

	fn[0] = '\0';
	checkprop(pathname, NULL, 0);
}

/*
 * Compare function used to sort the device-tree directories
 * This function will be passed to scandir.
 */
static int comparefunc(const struct dirent **dentry1,
		       const struct dirent **dentry2)
{
	char *str1 = (*(struct dirent **)dentry1)->d_name;
	char *str2 = (*(struct dirent **)dentry2)->d_name;

	/*
	 * strcmp scans from left to right and fails to idetify for some
	 * strings such as memory@10000000 and memory@f000000.
	 * Therefore, we get the wrong sorted order like memory@10000000 and
	 * memory@f000000.
	 */
	if (strchr(str1, '@') && strchr(str2, '@') &&
		(strlen(str1) > strlen(str2)))
		return 1;

	return strcmp(str1, str2);
}

/*
 * put a node (directory) in the property structure.  first properties
 * then children.
 */
static void putnode(void)
{
	char *dn;
	struct dirent *dp;
	char *basename;
	struct dirent **namelist;
	int numlist, i;
	struct stat statbuf;
	int plen;

	plen = *pathstart ? strlen(pathstart) : 1;
	/* Reserve space for string packed to words; e.g. string length 10 
	 * occupies 3 words, length 12 occupies 4 (for terminating \0s).  
	 * So round up & include the \0:
	 */
	dt_reserve(&dt, 1+((plen + 4)/4));
	*dt++ = 1;
	strcpy((void *)dt, *pathstart ? pathstart : "/");
	dt += ((plen + 4)/4);

	numlist = scandir(pathname, &namelist, 0, comparefunc);
	if (numlist < 0)
		die("unrecoverable error: could not scan \"%s\": %s\n",
		    pathname, strerror(errno));
	if (numlist == 0)
		die("unrecoverable error: no directory entries in \"%s\"",
		    pathname);

	basename = strrchr(pathname,'/');

	strcat(pathname, "/");
	dn = pathname + strlen(pathname);

	putprops(dn, namelist, numlist);

	/* Add initrd entries to the second kernel */
	if (initrd_base && !strcmp(basename,"/chosen/")) {
		int len = 8;
		unsigned long long initrd_end;

		dt_reserve(&dt, 12); /* both props, of 6 words ea. */
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

		memcpy(dt,&initrd_end,len);
		dt += (len + 3)/4;

		reserve(initrd_base, initrd_size);
	}

	/* Add cmdline to the second kernel.  Check to see if the new
	 * cmdline has a root=.  If not, use the old root= cmdline.  */
	if (!strcmp(basename,"/chosen/")) {
		size_t cmd_len = 0;
		char *param = NULL;
		char filename[MAXPATH];
		char *buff;
		int fd;

		cmd_len = strlen(local_cmdline);
		if (cmd_len != 0) {
			param = strstr(local_cmdline, "crashkernel=");
			if (param)
				crash_param = 1;
			/* does the new cmdline have a root= ? ... */
			param = strstr(local_cmdline, "root=");
		}

		/* ... if not, grab root= from the old command line */
		if (!param) {
			FILE *fp;
			char *last_cmdline = NULL;
			char *old_param;

			strcpy(filename, pathname);
			strcat(filename, "bootargs");
			fp = fopen(filename, "r");
			if (fp) {
				if (getline(&last_cmdline, &cmd_len, fp) == -1)
					die("unable to read %s\n", filename);

				param = strstr(last_cmdline, "root=");
				if (param) {
					old_param = strtok(param, " ");
					if (cmd_len != 0)
						strcat(local_cmdline, " ");
					strcat(local_cmdline, old_param);
				}
			}
			if (last_cmdline)
				free(last_cmdline);
		}
		strcat(local_cmdline, " ");
		cmd_len = strlen(local_cmdline);
		cmd_len = cmd_len + 1;

		/* add new bootargs */
		dt_reserve(&dt, 4+((cmd_len+3)/4));
		*dt++ = 3;
		*dt++ = cmd_len;
		*dt++ = propnum("bootargs");
		if ((cmd_len >= 8) && ((unsigned long)dt & 0x4))
			dt++;
		memcpy(dt, local_cmdline,cmd_len);
		dt += (cmd_len + 3)/4;

		fprintf(stderr, "Modified cmdline:%s\n", local_cmdline);

		/*
		 * Determine the platform type/stdout type, so that purgatory
		 * code can print 'I'm in purgatory' message. Currently only
		 * pseries/hvcterminal is supported.
		 */
		strcpy(filename, pathname);
		strncat(filename, "linux,stdout-path", MAXPATH);
		fd = open(filename, O_RDONLY);
		if (fd == -1) {
			printf("Unable to find %s, printing from purgatory is diabled\n",
														filename);
			goto no_debug;
		}
		if (fstat(fd, &statbuf)) {
			printf("Unable to stat %s, printing from purgatory is diabled\n",
														filename);
			close(fd);
			goto no_debug;

		}

		buff = malloc(statbuf.st_size);
		if (!buff) {
			printf("Can not allocate memory for buff\n");
			close(fd);
			goto no_debug;
		}
		read(fd, buff, statbuf.st_size);
		close(fd);
		strncpy(filename, "/proc/device-tree/", MAXPATH);
		strncat(filename, buff, MAXPATH);
		strncat(filename, "/compatible", MAXPATH);
		fd = open(filename, O_RDONLY);
		if (fd == -1) {
			printf("Unable to find %s printing from purgatory is diabled\n",
														filename);
			goto no_debug;
		}
		if (fstat(fd, &statbuf)) {
			printf("Unable to stat %s printing from purgatory is diabled\n",
														filename);
			close(fd);
			goto no_debug;
		}
		buff = realloc(buff, statbuf.st_size);
		if (!buff) {
			printf("Can not allocate memory for buff\n");
			close(fd);
			goto no_debug;
		}
		read(fd, buff, statbuf.st_size);
		if (!strcmp(buff, "hvterm1") || !strcmp(buff, "hvterm-protocol"))
			my_debug = 1;
		close(fd);
		free(buff);
	}

no_debug:
	for (i=0; i < numlist; i++) {
		dp = namelist[i];
		strcpy(dn, dp->d_name);
		free(namelist[i]);

		if (!strcmp(dn, ".") || !strcmp(dn, ".."))
			continue;

		if (lstat(pathname, &statbuf))
			die("unrecoverable error: could not stat \"%s\": %s\n",
			    pathname, strerror(errno));

		if (S_ISDIR(statbuf.st_mode))
			putnode();
	}

	dt_reserve(&dt, 1);
	*dt++ = 2;
	dn[-1] = '\0';
	free(namelist);
}

int create_flatten_tree(char **bufp, off_t *sizep, char *cmdline)
{
	unsigned long len;
	unsigned long tlen;
	char *buf;
	unsigned long me;

	me = 0;

	strcpy(pathname, "/proc/device-tree/");

	pathstart = pathname + strlen(pathname);

	dt_cur_size = INIT_TREE_WORDS;
	dt_base = malloc(dt_cur_size*4);
	if (!dt_base) {
		die("Can't malloc %d bytes for dt struct!\n", dt_cur_size*4);
	}
	memset(dt_base, 0, dt_cur_size*4);

	dt = dt_base;

	if (cmdline)
		strcpy(local_cmdline, cmdline);

	putnode();
	dt_reserve(&dt, 1);
	*dt++ = 9;

	len = sizeof(bb[0]);
	len += 7; len &= ~7;

	bb->off_mem_rsvmap = len;

	for (len = 1; mem_rsrv[len]; len += 2)
		;
	len+= 3;
	len *= sizeof(mem_rsrv[0]);

	bb->off_dt_struct = bb->off_mem_rsvmap + len;

	len = dt - dt_base;
	len *= sizeof(unsigned);
	bb->off_dt_strings = bb->off_dt_struct + len;

	len = propnum("");
	len +=  3; len &= ~3;
	bb->totalsize = bb->off_dt_strings + len;

	bb->magic = 0xd00dfeed;
	bb->version = 2;
	bb->last_comp_version = 2;

	reserve(me, bb->totalsize); /* patched later in kexec_load */

	buf = malloc(bb->totalsize);
	*bufp = buf;
	memcpy(buf, bb, bb->off_mem_rsvmap);
	tlen = bb->off_mem_rsvmap;
	memcpy(buf+tlen, mem_rsrv, bb->off_dt_struct - bb->off_mem_rsvmap);
	tlen = tlen + (bb->off_dt_struct - bb->off_mem_rsvmap);
	memcpy(buf+tlen, dt_base,  bb->off_dt_strings - bb->off_dt_struct);
	tlen = tlen +  (bb->off_dt_strings - bb->off_dt_struct);
	memcpy(buf+tlen, propnames,  bb->totalsize - bb->off_dt_strings);
	tlen = tlen + bb->totalsize - bb->off_dt_strings;
	*sizep = tlen;
	free(dt_base);
	return 0;
}
