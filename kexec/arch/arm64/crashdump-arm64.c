/*
 * ARM64 crashdump.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <linux/elf.h>

#include "kexec.h"
#include "crashdump.h"
#include "crashdump-arm64.h"
#include "kexec-arm64.h"
#include "kexec-elf.h"

struct memory_ranges usablemem_rgns = {};

int is_crashkernel_mem_reserved(void)
{
	return 0;
}

int get_crash_kernel_load_range(uint64_t *start, uint64_t *end)
{
	/* Crash kernel region size is not exposed by the system */
	return -1;
}
