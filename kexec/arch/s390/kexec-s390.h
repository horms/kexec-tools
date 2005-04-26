/*
 * kexec/arch/s390/kexec-s390.h
 *
 * (C) Copyright IBM Corp. 2005
 *
 * Author(s): Rolf Adelsberger <adelsberger@de.ibm.com>
 *
 */

#ifndef KEXEC_S390_H
#define KEXEC_S390_H

#define IMAGE_READ_OFFSET     0x10000

#define RAMDISK_ORIGIN_ADDR   0x800000
#define INITRD_START_OFFS     0x408
#define INITRD_SIZE_OFFS      0x410
#define COMMAND_LINE_OFFS     0x480
#define COMMAND_LINESIZE      896

extern int image_s390_load(int, char **, const char *, off_t, struct kexec_info *);
extern int image_s390_probe(const char *, off_t);
extern void image_s390_usage(void);

#endif /* KEXEC_IA64_H */
