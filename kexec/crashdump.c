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
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "kexec.h"
#include "crashdump.h"

/* Returns the physical address of start of crash notes buffer for a cpu. */
int get_crash_notes_per_cpu(int cpu, uint64_t *addr)
{
	char crash_notes[PATH_MAX];
	char line[MAX_LINE];
	FILE *fp;
	struct stat cpu_stat;
	int count;
	unsigned long long temp;

	sprintf(crash_notes, "/sys/devices/system/cpu/cpu%d/crash_notes", cpu);
	fp = fopen(crash_notes, "r");
	if (!fp) {
		/* Either sysfs is not mounted or CPU is not present*/
		if (stat("/sys/devices", &cpu_stat))
			die("Sysfs is not mounted. Try mounting sysfs\n");

		/* CPU is not physically present.*/
		*addr = 0;
		return errno;
	}
	if (fgets(line, sizeof(line), fp) != 0) {
		count = sscanf(line, "%Lx", &temp);
		if (count != 1)
			die("Cannot parse %s: %s\n", crash_notes,
						strerror(errno));
		*addr = (uint64_t) temp;
	}
#if 0
	printf("crash_notes addr = %Lx\n", *addr);
#endif
	return 0;
}
