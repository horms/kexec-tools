#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "kexec.h"
#include "crashdump.h"
#include "kexec-syscall.h"

#ifdef HAVE_XENCTRL_H
#include <xenctrl.h>
#endif

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

unsigned long xen_architecture(struct crash_elf_info *elf_info)
{
	unsigned long machine = elf_info->machine;
#ifdef HAVE_XENCTRL_H
	int xc, rc;
	xen_capabilities_info_t capabilities;

	if (!xen_present())
		goto out;

	memset(capabilities, '0', XEN_CAPABILITIES_INFO_LEN);

	xc = xc_interface_open();
	if ( xc == -1 ) {
		fprintf(stderr, "failed to open xen control interface.\n");
		goto out;
	}

	rc = xc_version(xc, XENVER_capabilities, &capabilities[0]);
	if ( rc == -1 ) {
		fprintf(stderr, "failed to make Xen version hypercall.\n");
		goto out_close;
	}

	if (strstr(capabilities, "xen-3.0-x86_64"))
		machine = EM_X86_64;
        else if (strstr(capabilities, "xen-3.0-x86_32"))
		machine = EM_386;

 out_close:
	xc_interface_close(xc);

 out:
#endif
	return machine;
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

	if ((cpus = kexec_iomem_for_each_line(match, 1, NULL, NULL))) {
		n = sizeof(struct crash_note_info) * cpus;
		xen_phys_notes = malloc(n);
		if (!xen_phys_notes) {
			fprintf(stderr, "failed to allocate xen_phys_notes.\n");
			return -1;
		}
		memset(xen_phys_notes, 0, n);
		kexec_iomem_for_each_line(match, 1,
					  xen_crash_note_callback, NULL);
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
