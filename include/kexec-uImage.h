#ifndef __KEXEC_UIMAGE_H__
#define __KEXEC_UIMAGE_H__

struct Image_info {
	const char *buf;
	off_t len;
	unsigned int base;
	unsigned int ep;
};

int uImage_probe(const char *buf, off_t len, unsigned int arch);
int uImage_load(const char *buf, off_t len, struct Image_info *info);
#endif
