#include <errno.h>
#include <string.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>

#include "crashdump-x86_64.h"

#define KERNEL_VERSION(major, minor, patch) \
	(((major) << 16) | ((minor) << 8) | patch)

long kernel_version(void)
{
	struct utsname utsname;
	unsigned long major, minor, patch;
	char *p;

	if (uname(&utsname) < 0) {
		fprintf(stderr, "uname failed: %s\n", strerror(errno));
		return -1;
	}

	p = utsname.release;
	major = strtoul(p, &p, 10);
	if (major == ULONG_MAX) {
		fprintf(stderr, "strtoul failed: %s\n", strerror(errno));
		return -1;
	}

	if (*p++ != '.') {
		fprintf(stderr, "Unsupported utsname.release: %s\n",
			utsname.release);
		return -1;
	}

	minor = strtoul(p, &p, 10);
	if (major == ULONG_MAX) {
		fprintf(stderr, "strtoul failed: %s\n", strerror(errno));
		return -1;
	}

	if (*p++ != '.') {
		fprintf(stderr, "Unsupported utsname.release: %s\n",
			utsname.release);
		return -1;
	}

	patch = strtoul(p, &p, 10);
	if (major == ULONG_MAX) {
		fprintf(stderr, "strtoul failed: %s\n", strerror(errno));
		return -1;
	}

	if (major >= 256 || minor >= 256 || patch >= 256) {
		fprintf(stderr, "Unsupported utsname.release: %s\n",
			utsname.release);
		return -1;
	}

	return KERNEL_VERSION(major, minor, patch);
}

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
