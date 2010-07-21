#ifndef KEXEC_PPC_H
#define KEXEC_PPC_H

#define MAXBYTES	128
#define MAX_LINE	160
#define CORE_TYPE_ELF32	1
#define CORE_TYPE_ELF64	2

extern unsigned char setup_simple_start[];
extern uint32_t setup_simple_size;

extern struct {
	uint32_t spr8;
} setup_simple_regs;

extern unsigned char setup_dol_start[];
extern uint32_t setup_dol_size;
extern uint64_t rmo_top;

extern struct {
	uint32_t spr8;
} setup_dol_regs;

#define SIZE_16M	(16*1024*1024UL)

int elf_ppc_probe(const char *buf, off_t len);
int elf_ppc_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void elf_ppc_usage(void);

int uImage_ppc_probe(const char *buf, off_t len);
int uImage_ppc_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void uImage_ppc_usage(void);

int dol_ppc_probe(const char *buf, off_t len);
int dol_ppc_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void dol_ppc_usage(void);

/*
 * During inital setup the kernel does not map the whole memory but a part of
 * it. On Book-E that is 64MiB, 601 24MiB or 256MiB (if possible).
 */
#define KERNEL_ACCESS_TOP (24 * 1024 * 1024)

/* boot block version 17 as defined by the linux kernel */
struct bootblock {
	unsigned magic,
		totalsize,
		off_dt_struct,
		off_dt_strings,
		off_mem_rsvmap,
		version,
		last_comp_version,
		boot_physid,
		dt_strings_size,
		dt_struct_size;
};

typedef struct mem_rgns {
	unsigned int size;
	struct memory_range *ranges;
} mem_rgns_t;
extern mem_rgns_t usablemem_rgns;
extern int max_memory_ranges;
extern unsigned long long initrd_base, initrd_size;
extern unsigned long long ramdisk_base, ramdisk_size;
extern unsigned char reuse_initrd;
extern const char *ramdisk;
#define COMMAND_LINE_SIZE	512 /* from kernel */
/*fs2dt*/
void reserve(unsigned long long where, unsigned long long length);
#endif /* KEXEC_PPC_H */
