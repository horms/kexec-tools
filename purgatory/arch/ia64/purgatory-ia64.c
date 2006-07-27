#include <purgatory.h>
#include <stdint.h>
#include <string.h>
#include "purgatory-ia64.h"

#define PAGE_OFFSET             0xe000000000000000

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

void setup_arch(void)
{
	/* Nothing for now */
}
inline unsigned long PA(unsigned long addr)
{
	return addr - PAGE_OFFSET;
}

void flush_icache_range(char *start, unsigned long len)
{
	unsigned long i;
	for (i = 0;i < len; i += 32)
	  asm volatile("fc.i %0"::"r"(start+i):"memory");
	asm volatile (";;sync.i;;":::"memory");
	asm volatile ("srlz.i":::"memory");
}

extern char __dummy_efi_function[], __dummy_efi_function_end[];

void ia64_env_setup(struct ia64_boot_param *boot_param,
	uint64_t command_line, uint64_t command_line_len,
	uint64_t ramdisk_base, uint64_t ramdisk_size)
{
	unsigned long len;
        efi_system_table_t *systab;
        efi_runtime_services_t *runtime;
	unsigned long *set_virtual_address_map;

	// patch efi_runtime->set_virtual_address_map to a
	// dummy function
	len = __dummy_efi_function_end - __dummy_efi_function;
	memcpy((char *)command_line + command_line_len, __dummy_efi_function,
	len);
	systab = (efi_system_table_t *)boot_param->efi_systab;
	runtime = (efi_runtime_services_t *)PA(systab->runtime);
	set_virtual_address_map =
		(unsigned long *)PA(runtime->set_virtual_address_map);
	*(set_virtual_address_map)=
		(unsigned long)((char *)command_line + command_line_len);
	flush_icache_range((char *)command_line+command_line_len, len);

	boot_param->command_line = command_line;
	boot_param->console_info.orig_x = 0;
	boot_param->console_info.orig_y = 0;
	boot_param->initrd_start = ramdisk_base;
	boot_param->initrd_size =  ramdisk_size;
}

/* This function can be used to execute after the SHA256 verification. */
void post_verification_setup_arch(void)
{
	/* Nothing for now */
}
