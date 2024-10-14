/*
 * Extract from linux kernel include/linux/pe.h
 */

#ifndef __PE_H__
#define __PE_H__

struct pe_hdr {
	uint32_t magic;		/* PE magic */
	uint16_t machine;	/* machine type */
	uint16_t sections;	/* number of sections */
	uint32_t timestamp;	/* time_t */
	uint32_t symbol_table;	/* symbol table offset */
	uint32_t symbols;	/* number of symbols */
	uint16_t opt_hdr_size;	/* size of optional header */
	uint16_t flags;		/* flags */
};

/* the fact that pe32 isn't padded where pe32+ is 64-bit means union won't
 * work right.  vomit. */
struct pe32_opt_hdr {
	/* "standard" header */
	uint16_t magic;		/* file type */
	uint8_t  ld_major;	/* linker major version */
	uint8_t  ld_minor;	/* linker minor version */
	uint32_t text_size;	/* size of text section(s) */
	uint32_t data_size;	/* size of data section(s) */
	uint32_t bss_size;	/* size of bss section(s) */
	uint32_t entry_point;	/* file offset of entry point */
	uint32_t code_base;	/* relative code addr in ram */
	uint32_t data_base;	/* relative data addr in ram */
	/* "windows" header */
	uint32_t image_base;	/* preferred load address */
	uint32_t section_align;	/* alignment in bytes */
	uint32_t file_align;	/* file alignment in bytes */
	uint16_t os_major;	/* major OS version */
	uint16_t os_minor;	/* minor OS version */
	uint16_t image_major;	/* major image version */
	uint16_t image_minor;	/* minor image version */
	uint16_t subsys_major;	/* major subsystem version */
	uint16_t subsys_minor;	/* minor subsystem version */
	uint32_t win32_version;	/* reserved, must be 0 */
	uint32_t image_size;	/* image size */
	uint32_t header_size;	/* header size rounded up to
				   file_align */
	uint32_t csum;		/* checksum */
	uint16_t subsys;	/* subsystem */
	uint16_t dll_flags;	/* more flags! */
	uint32_t stack_size_req;/* amt of stack requested */
	uint32_t stack_size;	/* amt of stack required */
	uint32_t heap_size_req;	/* amt of heap requested */
	uint32_t heap_size;	/* amt of heap required */
	uint32_t loader_flags;	/* reserved, must be 0 */
	uint32_t data_dirs;	/* number of data dir entries */
};

struct pe32plus_opt_hdr {
	uint16_t magic;		/* file type */
	uint8_t  ld_major;	/* linker major version */
	uint8_t  ld_minor;	/* linker minor version */
	uint32_t text_size;	/* size of text section(s) */
	uint32_t data_size;	/* size of data section(s) */
	uint32_t bss_size;	/* size of bss section(s) */
	uint32_t entry_point;	/* file offset of entry point */
	uint32_t code_base;	/* relative code addr in ram */
	/* "windows" header */
	uint64_t image_base;	/* preferred load address */
	uint32_t section_align;	/* alignment in bytes */
	uint32_t file_align;	/* file alignment in bytes */
	uint16_t os_major;	/* major OS version */
	uint16_t os_minor;	/* minor OS version */
	uint16_t image_major;	/* major image version */
	uint16_t image_minor;	/* minor image version */
	uint16_t subsys_major;	/* major subsystem version */
	uint16_t subsys_minor;	/* minor subsystem version */
	uint32_t win32_version;	/* reserved, must be 0 */
	uint32_t image_size;	/* image size */
	uint32_t header_size;	/* header size rounded up to
				   file_align */
	uint32_t csum;		/* checksum */
	uint16_t subsys;	/* subsystem */
	uint16_t dll_flags;	/* more flags! */
	uint64_t stack_size_req;/* amt of stack requested */
	uint64_t stack_size;	/* amt of stack required */
	uint64_t heap_size_req;	/* amt of heap requested */
	uint64_t heap_size;	/* amt of heap required */
	uint32_t loader_flags;	/* reserved, must be 0 */
	uint32_t data_dirs;	/* number of data dir entries */
};

struct section_header {
	char name[8];			/* name or "/12\0" string tbl offset */
	uint32_t virtual_size;		/* size of loaded section in ram */
	uint32_t virtual_address;	/* relative virtual address */
	uint32_t raw_data_size;		/* size of the section */
	uint32_t data_addr;		/* file pointer to first page of sec */
	uint32_t relocs;		/* file pointer to relocation entries */
	uint32_t line_numbers;		/* line numbers! */
	uint16_t num_relocs;		/* number of relocations */
	uint16_t num_lin_numbers;	/* srsly. */
	uint32_t flags;
};

#endif
