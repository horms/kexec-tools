#include "../../kexec.h"
#include <errno.h>
#include <string.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>

#include "crashdump-x86_64.h"

#define PAGE_OFFSET_PRE_2_6_27	0xffff810000000000UL
#define PAGE_OFFSET		0xffff880000000000UL

unsigned long page_offset;

int arch_init(void)
{
	int kv;

	kv = kernel_version();
	if (kv < 0)
		return -1;

	if (kv < KERNEL_VERSION(2, 6, 27))
		page_offset = PAGE_OFFSET_PRE_2_6_27;
	else
		page_offset = PAGE_OFFSET;

	return 0;
}
