/*
 * purgatory:  setup code
 *
 * Copyright (C) 2005-2006  Zou Nan hai (nanhai.zou@intel.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation (version 2 of the License).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <purgatory.h>
#include <stdint.h>
#include <string.h>
#include "purgatory-ia64.h"

#define PAGE_OFFSET             0xe000000000000000UL

#define EFI_PAGE_SHIFT          12
#define EFI_PAGE_SIZE		(1UL<<EFI_PAGE_SHIFT)
#define EFI_PAGE_ALIGN(x)	((x + EFI_PAGE_SIZE - 1)&~(EFI_PAGE_SIZE-1))
/* Memory types: */
#define EFI_RESERVED_TYPE                0
#define EFI_LOADER_CODE                  1
#define EFI_LOADER_DATA                  2
#define EFI_BOOT_SERVICES_CODE           3
#define EFI_BOOT_SERVICES_DATA           4
#define EFI_RUNTIME_SERVICES_CODE        5
#define EFI_RUNTIME_SERVICES_DATA        6
#define EFI_CONVENTIONAL_MEMORY          7
#define EFI_UNUSABLE_MEMORY              8
#define EFI_ACPI_RECLAIM_MEMORY          9
#define EFI_ACPI_MEMORY_NVS             10
#define EFI_MEMORY_MAPPED_IO            11
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE 12
#define EFI_PAL_CODE                    13
#define EFI_MAX_MEMORY_TYPE             14

typedef struct {
        uint64_t signature;
        uint32_t revision;
        uint32_t headersize;
        uint32_t crc32;
        uint32_t reserved;
} efi_table_hdr_t;

typedef struct {
        efi_table_hdr_t hdr;
        unsigned long get_time;
        unsigned long set_time;
        unsigned long get_wakeup_time;
        unsigned long set_wakeup_time;
        unsigned long set_virtual_address_map;
        unsigned long convert_pointer;
        unsigned long get_variable;
        unsigned long get_next_variable;
        unsigned long set_variable;
        unsigned long get_next_high_mono_count;
        unsigned long reset_system;
} efi_runtime_services_t;

typedef struct {
        efi_table_hdr_t hdr;
        unsigned long fw_vendor;        /* physical addr of CHAR16 vendor string
 */
        uint32_t fw_revision;
        unsigned long con_in_handle;
        unsigned long con_in;
        unsigned long con_out_handle;
        unsigned long con_out;
        unsigned long stderr_handle;
        unsigned long stderr;
        unsigned long runtime;
        unsigned long boottime;
        unsigned long nr_tables;
        unsigned long tables;
} efi_system_table_t;

struct ia64_boot_param {
        uint64_t command_line;             /* physical address of command line arguments */
        uint64_t efi_systab;               /* physical address of EFI system table */
        uint64_t efi_memmap;               /* physical address of EFI memory map */
        uint64_t efi_memmap_size;          /* size of EFI memory map */
        uint64_t efi_memdesc_size;         /* size of an EFI memory map descriptor */
        uint32_t efi_memdesc_version;      /* memory descriptor version */
        struct {
                uint16_t num_cols; /* number of columns on console output device */
                uint16_t num_rows; /* number of rows on console output device */
                uint16_t orig_x;   /* cursor's x position */
                uint16_t orig_y;   /* cursor's y position */
        } console_info;
        uint64_t fpswa;            /* physical address of the fpswa interface */
        uint64_t initrd_start;
        uint64_t initrd_size;
};

typedef struct {
        uint32_t type;
        uint32_t pad;
        uint64_t phys_addr;
        uint64_t virt_addr;
        uint64_t num_pages;
        uint64_t attribute;
} efi_memory_desc_t;

struct loaded_segment {
        unsigned long start;
        unsigned long end;
        unsigned long reserved;
};

struct kexec_boot_params {
	uint64_t ramdisk_base;
	uint64_t ramdisk_size;
	uint64_t command_line;
	uint64_t command_line_len;
	uint64_t efi_memmap_base;
	uint64_t efi_memmap_size;
	struct loaded_segment *loaded_segments;
	unsigned long loaded_segments_num;
};

void
setup_arch(void)
{
	reset_vga();
}

inline unsigned long PA(unsigned long addr)
{
	return addr - PAGE_OFFSET;
}

void
patch_efi_memmap(struct kexec_boot_params *params,
		struct ia64_boot_param *boot_param)
{
	void *dest = (void *)params->efi_memmap_base;
	void *src  = (void *)boot_param->efi_memmap;
	unsigned long len = boot_param->efi_memmap_size;
	unsigned long memdesc_size = boot_param->efi_memdesc_size;
	uint64_t orig_type;
	efi_memory_desc_t *md1, *md2;
	void *p1, *p2, *src_end = src + len;
	int i;
	for (p1 = src, p2 = dest; p1 < src_end;
			p1 += memdesc_size, p2 += memdesc_size) {
		unsigned long mstart, mend;
		md1 = p1;
		md2 = p2;
		if (md1->num_pages == 0)
			continue;
		mstart = md1->phys_addr;
		mend = md1->phys_addr + (md1->num_pages
				<< EFI_PAGE_SHIFT);
		switch (md1->type) {
			case EFI_LOADER_DATA:
				*md2 = *md1;
				md2->type = EFI_CONVENTIONAL_MEMORY;
				break;
			default:
				*md2 = *md1;
		}
		// segments are already sorted and aligned to 4K
		orig_type = md2->type;
		for (i = 0; i < params->loaded_segments_num; i++) {
			struct loaded_segment *seg;
			seg = &params->loaded_segments[i];
			if (seg->start >= mstart && seg->start < mend) {
				unsigned long start_pages, mid_pages, end_pages;
				if (seg->end > mend) {
					p1 += memdesc_size;
					for(; p1 < src_end;
							p1 += memdesc_size) {
						md1 = p1;
						/* TODO check contig and attribute here */
						mend = md1->phys_addr
							+ (md1->num_pages << EFI_PAGE_SHIFT);
						if (seg->end < mend)
							break;
					}
				}
				start_pages = (seg->start - mstart)
					>> EFI_PAGE_SHIFT;
				mid_pages = (seg->end - seg->start)
					>> EFI_PAGE_SHIFT;
				end_pages  = (mend - seg->end)
					>> EFI_PAGE_SHIFT;
				if (start_pages) {
					md2->num_pages = start_pages;
					p2 += memdesc_size;
					md2 = p2;
					*md2 = *md1;
				}
				md2->phys_addr = seg->start;
				md2->num_pages = mid_pages;
				md2->type = seg->reserved ?
					EFI_UNUSABLE_MEMORY:EFI_LOADER_DATA;
				if (end_pages) {
					p2 += memdesc_size;
					md2 = p2;
					*md2 = *md1;
					md2->phys_addr = seg->end;
					md2->num_pages = end_pages;
					md2->type = orig_type;
					mstart = seg->end;
				} else
					break;
			}
		}
	}

	boot_param->efi_memmap_size = p2 - dest;
}

void
flush_icache_range(char *start, unsigned long len)
{
	unsigned long i;
	for (i = 0;i < len; i += 32)
	  asm volatile("fc.i %0"::"r"(start + i):"memory");
	asm volatile (";;sync.i;;":::"memory");
	asm volatile ("srlz.i":::"memory");
}

extern char __dummy_efi_function[], __dummy_efi_function_end[];


void
ia64_env_setup(struct ia64_boot_param *boot_param,
	struct kexec_boot_params *params)
{
	unsigned long len;
        efi_system_table_t *systab;
        efi_runtime_services_t *runtime;
	unsigned long *set_virtual_address_map;
	char *command_line = (char *)params->command_line;
	uint64_t command_line_len = params->command_line_len;

	// patch efi_runtime->set_virtual_address_map to a
	// dummy function
	len = __dummy_efi_function_end - __dummy_efi_function;
	memcpy(command_line + command_line_len,
		__dummy_efi_function, len);
	systab = (efi_system_table_t *)boot_param->efi_systab;
	runtime = (efi_runtime_services_t *)PA(systab->runtime);
	set_virtual_address_map =
		(unsigned long *)PA(runtime->set_virtual_address_map);
	*(set_virtual_address_map) =
		(unsigned long)(command_line + command_line_len);
	flush_icache_range(command_line + command_line_len, len);

	patch_efi_memmap(params, boot_param);

	boot_param->efi_memmap = params->efi_memmap_base;

	boot_param->command_line = params->command_line;
	boot_param->console_info.orig_x = 0;
	boot_param->console_info.orig_y = 0;
	boot_param->initrd_start = params->ramdisk_base;
	boot_param->initrd_size =  params->ramdisk_size;
}

/* This function can be used to execute after the SHA256 verification. */
void post_verification_setup_arch(void)
{
	/* Nothing for now */
}
