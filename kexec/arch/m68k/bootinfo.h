#include <asm/bootinfo.h>

#define DEFAULT_BOOTINFO_FILE	"/proc/bootinfo"
#define MAX_BOOTINFO_SIZE	1536


    /*
     *  Convenience overlay of several struct bi_record variants
     */

struct bi_rec {
	__be16 tag;
	__be16 size;
	union {
		__be32 data[0];
		/* shorthands for the types we use */
		__be32 machtype;
		struct {
			__be32 addr;
			__be32 size;
		} mem_info;
		char string[0];
	};
};


    /*
     *  We only support the "new" tagged bootinfo (v2)
     */

#define SUPPORTED_BOOTINFO_VERSION	2


extern const char *bootinfo_file;

extern void bootinfo_load(void);
extern void bootinfo_print(void);
extern int bootinfo_get_memory_ranges(struct memory_range **range);
extern void bootinfo_set_cmdline(const char *cmdline);
extern void bootinfo_set_ramdisk(unsigned long ramdisk_addr,
				 unsigned long ramdisk_size);
extern void bootinfo_check_bootversion(const struct kexec_info *info);
extern void add_bootinfo(struct kexec_info *info, unsigned long addr);
