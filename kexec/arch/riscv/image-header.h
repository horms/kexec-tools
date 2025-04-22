/*
 * RISCV64 binary image header.
 * token from arm64/image-header.h
 */

#if !defined(__RISCV_IMAGE_HEADER_H)
#define __RISCV_IMAGE_HEADER_H

#include <endian.h>
#include <stdint.h>

/**
 * struct riscv_image_header - riscv kernel image header.
 *
 **/
struct riscv_image_header {
        uint32_t code0;
        uint32_t code1;
        uint64_t text_offset;
        uint64_t image_size;
        uint64_t flags;
        uint32_t version;
        uint32_t res1;
        uint64_t res2;
        uint64_t magic;
        uint32_t magic2;
        uint32_t res3;
};

#define RISCV_IMAGE_MAGIC       0x5643534952
#define RISCV_IMAGE_MAGIC2      0x05435352

#define RISCV_HEADER_VERSION_MAJOR 0
#define RISCV_HEADER_VERSION_MINOR 2

#define RISCV_HEADER_VERSION (RISCV_HEADER_VERSION_MAJOR << 16 | \
		                              RISCV_HEADER_VERSION_MINOR)


static const uint64_t riscv_image_flag_be = (1UL << 0);

/**
 * riscv_header_check_magic - Helper to check the riscv image header.
 *
 * Returns non-zero if header is OK.
 */

static inline int riscv_header_check_magic(const struct riscv_image_header *h)
{
	if (!h)
		return 0;

	return (h->version >= RISCV_HEADER_VERSION && h->magic2 == RISCV_IMAGE_MAGIC2);
}

/**
 * riscv_header_check_endiannes - Helper to check the riscv image header.
 *
 * Returns non-zero if the image was built as big endian.
 */

static inline int riscv_header_check_endiannes(const struct riscv_image_header *h)
{
	if (!h)
		return 0;

	return (le64toh(h->flags) & riscv_image_flag_be) >> 0;
}



static inline uint64_t riscv_header_text_offset(const struct riscv_image_header *h)
{
	if (!h)
		return 0;

	return le64toh(h->text_offset);
}

static inline uint64_t riscv_header_image_size(const struct riscv_image_header *h)
{
	if (!h)
		return 0;

	return le64toh(h->image_size);
}

#endif
