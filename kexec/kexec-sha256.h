#ifndef KEXEC_SHA256_H
#define KEXEC_SHA256_H

struct sha256_region {
	const void *start;
	unsigned long len;
};

#define SHA256_REGIONS 16

#endif /* KEXEC_SHA256_H */
