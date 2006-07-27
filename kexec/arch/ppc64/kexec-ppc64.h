#ifndef KEXEC_PPC64_H
#define KEXEC_PPC64_H

int elf_ppc64_probe(const char *buf, off_t len);
int elf_ppc64_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void elf_ppc64_usage(void);
void reserve(unsigned long long where, unsigned long long length);

extern unsigned long initrd_base, initrd_size;
/* boot block version 2 as defined by the linux kernel */
struct bootblock {
	unsigned magic,
		totalsize,
		off_dt_struct,
		off_dt_strings,
		off_mem_rsvmap,
		version,
		last_comp_version,
		boot_physid;
};

typedef struct mem_rgns {
        unsigned int size;
        struct exclude_range ranges[MAX_MEMORY_RANGES];
} mem_rgns_t;

#endif /* KEXEC_PPC64_H */
