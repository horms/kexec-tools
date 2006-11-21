#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "kexec.h"
#include "crashdump.h"

struct crash_note_info {
	unsigned long base;
	unsigned long length;
};

int xen_phys_cpus = 0;
struct crash_note_info *xen_phys_notes;

int xen_present(void)
{
	struct stat buf;

	return stat("/proc/xen", &buf) == 0;
}

static int xen_crash_note_callback(void *data, int nr,
				   char *str,
				   unsigned long base,
				   unsigned long length)
{
	struct crash_note_info *note = xen_phys_notes + nr;

	note->base = base;
	note->length = length;

	return 0;
}

int xen_get_nr_phys_cpus(void)
{
	char *match = "Crash note\n";
	int cpus, n;

	if (xen_phys_cpus)
		return xen_phys_cpus;

	if ((cpus = kexec_iomem_for_each_line(match, NULL, NULL))) {
		n = sizeof(struct crash_note_info) * cpus;
		xen_phys_notes = malloc(n);
		if (xen_phys_notes) {
			memset(xen_phys_notes, 0, n);
			kexec_iomem_for_each_line(match,
						  xen_crash_note_callback,
						  NULL);
		}

		xen_phys_cpus = cpus;
	}

	return cpus;
}

int xen_get_note(int cpu, uint64_t *addr, uint64_t *len)
{
	struct crash_note_info *note;

	if (xen_phys_cpus <= 0)
		return -1;

	note = xen_phys_notes + cpu;

	*addr = note->base;
	*len = note->length;

	return 0;
}
