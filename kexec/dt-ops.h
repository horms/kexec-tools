#if !defined(KEXEC_DT_OPS_H)
#define KEXEC_DT_OPS_H

#include <sys/types.h>

int dtb_set_initrd(char **dtb, off_t *dtb_size, off_t start, off_t end);
void dtb_clear_initrd(char **dtb, off_t *dtb_size);
int dtb_set_bootargs(char **dtb, off_t *dtb_size, const char *command_line);
int dtb_set_property(char **dtb, off_t *dtb_size, const char *node,
	const char *prop, const void *value, int value_len);

int dtb_delete_property(char *dtb, const char *node, const char *prop);

void dtb_extract_int_property(uint64_t *val, const void *buf, uint32_t cells);
void dtb_fill_int_property(void *buf, uint64_t val, uint32_t cells);
int dtb_add_range_property(char **dtb, off_t *dtb_size, uint64_t start, uint64_t end,
                           const char *node, const char* parent);
int dtb_get_memory_ranges(char *dtb, struct memory_ranges *mem_ranges,
			  struct memory_ranges *extra_ranges);

#endif
