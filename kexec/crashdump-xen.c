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
#include <setjmp.h>
#include <signal.h>
#include "kexec.h"
#include "crashdump.h"
#include "kexec-syscall.h"

#include "config.h"

#ifdef HAVE_LIBXENCTRL
#include <xenctrl.h>
#endif

struct crash_note_info {
	unsigned long base;
	unsigned long length;
};

static int xen_phys_cpus;
static struct crash_note_info *xen_phys_notes;

/* based on code from xen-detect.c */
static int is_dom0;
#if defined(__i386__) || defined(__x86_64__)
static jmp_buf xen_sigill_jmp;
void xen_sigill_handler(int sig)
{
	longjmp(xen_sigill_jmp, 1);
}

static void xen_cpuid(uint32_t idx, uint32_t *regs, int pv_context)
{
	asm volatile (
#ifdef __i386__
#define R(x) "%%e"#x"x"
#else
#define R(x) "%%r"#x"x"
#endif
	"push "R(a)"; push "R(b)"; push "R(c)"; push "R(d)"\n\t"
	"test %1,%1 ; jz 1f ; ud2a ; .ascii \"xen\" ; 1: cpuid\n\t"
	"mov %%eax,(%2); mov %%ebx,4(%2)\n\t"
	"mov %%ecx,8(%2); mov %%edx,12(%2)\n\t"
	"pop "R(d)"; pop "R(c)"; pop "R(b)"; pop "R(a)"\n\t"
	: : "a" (idx), "c" (pv_context), "S" (regs) : "memory" );
}

static int check_for_xen(int pv_context)
{
	uint32_t regs[4];
	char signature[13];
	uint32_t base;

	for (base = 0x40000000; base < 0x40010000; base += 0x100)
	{
		xen_cpuid(base, regs, pv_context);

		*(uint32_t *)(signature + 0) = regs[1];
		*(uint32_t *)(signature + 4) = regs[2];
		*(uint32_t *)(signature + 8) = regs[3];
		signature[12] = '\0';

		if (strcmp("XenVMMXenVMM", signature) == 0 && regs[0] >= (base + 2))
			goto found;
	}

	return 0;

found:
	xen_cpuid(base + 1, regs, pv_context);
	return regs[0];
}

static int xen_detect_pv_guest(void)
{
	struct sigaction act, oldact;
	int is_pv = -1;

	if (setjmp(xen_sigill_jmp))
		return is_pv;

	memset(&act, 0, sizeof(act));
	act.sa_handler = xen_sigill_handler;
	sigemptyset (&act.sa_mask);
	if (sigaction(SIGILL, &act, &oldact))
		return is_pv;
	if (check_for_xen(1))
		is_pv = 1;
	sigaction(SIGILL, &oldact, NULL);
	return is_pv;
}
#else
static int xen_detect_pv_guest(void)
{
	return 1;
}
#endif

/*
 * Return 1 if its a PV guest.
 * This includes dom0, which is the only PV guest where kexec/kdump works.
 * HVM guests have to be handled as native hardware.
 */
int xen_present(void)
{
	if (!is_dom0) {
		if (access("/proc/xen", F_OK) == 0)
			is_dom0 = xen_detect_pv_guest();
		else
			is_dom0 = -1;
	}
	return is_dom0 > 0;
}

unsigned long xen_architecture(struct crash_elf_info *elf_info)
{
	unsigned long machine = elf_info->machine;
#ifdef HAVE_LIBXENCTRL
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

static int xen_crash_note_callback(void *UNUSED(data), int nr,
				   char *UNUSED(str),
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
		if (!xen_phys_notes) {
			fprintf(stderr, "failed to allocate xen_phys_notes.\n");
			return -1;
		}
		memset(xen_phys_notes, 0, n);
		kexec_iomem_for_each_line(match,
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
