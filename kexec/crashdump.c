/*
 * crashdump.c: Architecture independent code for crashdump support.
 *
 * Created by: Vivek Goyal (vgoyal@in.ibm.com)
 * Copyright (C) IBM Corporation, 2005. All rights reserved
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "kexec.h"

/* Returns the physical address of start of crash notes buffer for a cpu. */
int get_crash_notes_per_cpu(int cpu, uint64_t *addr)
{
	char crash_notes[PATH_MAX];
	char line[MAX_LINE];
	FILE *fp;
	struct stat cpu_stat;
	int count;
	unsigned long long temp;
	int fopen_errno;
	int stat_errno;

	*addr = 0;

	sprintf(crash_notes, "/sys/devices/system/cpu/cpu%d/crash_notes", cpu);
	fp = fopen(crash_notes, "r");
	if (!fp) {
		fopen_errno = errno;
		if (fopen_errno != ENOENT)
			die(stderr, "Could not open \"%s\": %s\n",
				crash_notes, strerror(fopen_errno));
		if (!stat("/sys/devices", &cpu_stat)) {
			stat_errno = errno;
			fprintf(stderr, "Could not open \"%s\": %s\n",
				crash_notes, strerror(fopen_errno));
			if (stat_errno == ENOENT)
				die("\"/sys/devices\" does not exist. "
				    "Sysfs does not seem to be mounted. "
				    "Try mounting sysfs.\n");
			die("Could not open \"/sys/devices\": %s\n",
			    crash_notes, strerror(stat_errno));
		}
		/* CPU is not physically present.*/
		return -1;
	}
	if (!fgets(line, sizeof(line), fp))
		die("Cannot parse %s: %s\n", crash_notes, strerror(errno));
	count = sscanf(line, "%Lx", &temp);
	if (count != 1)
		die("Cannot parse %s: %s\n", crash_notes, strerror(errno));
	*addr = (uint64_t) temp;
#if 0
	printf("crash_notes addr = %Lx\n", *addr);
#endif

	return 0;
}
