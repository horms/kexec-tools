#ifndef KEXEC_PPC64_H
#define KEXEC_PPC64_H

#define MAXBYTES 128
#define MAX_LINE 160
#define CORE_TYPE_ELF32 1
#define CORE_TYPE_ELF64 2

int setup_memory_ranges(unsigned long kexec_flags);

int elf_ppc64_probe(const char *buf, off_t len);
int elf_ppc64_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void elf_ppc64_usage(void);
void reserve(unsigned long long where, unsigned long long length);

extern unsigned long initrd_base, initrd_size;
extern int max_memory_ranges;

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

struct arch_options_t {
	int core_header_type;
};

typedef struct mem_rgns {
        unsigned int size;
        struct memory_range *ranges;
} mem_rgns_t;

extern mem_rgns_t usablemem_rgns;

#endif /* KEXEC_PPC64_H */
