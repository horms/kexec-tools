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
