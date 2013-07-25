#include "kexec.h"
#include <errno.h>
#include <string.h>
#include <sys/utsname.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

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
	if (minor == ULONG_MAX) {
		fprintf(stderr, "strtoul failed: %s\n", strerror(errno));
		return -1;
	}

	/* There may or may not be a patch level for this kernel */
	if (*p++ == '.') {
		patch = strtoul(p, &p, 10);
		if (patch == ULONG_MAX) {
			fprintf(stderr, "strtoul failed: %s\n",strerror(errno));
			return -1;
		}
	} else {
		patch = 0;
	}

	if (major >= 256 || minor >= 256 || patch >= 256) {
		fprintf(stderr, "Unsupported utsname.release: %s\n",
			utsname.release);
		return -1;
	}

	return KERNEL_VERSION(major, minor, patch);
}
