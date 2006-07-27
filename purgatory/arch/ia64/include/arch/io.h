#ifndef ARCH_IO_H
#define ARCH_IO_H

#include <stdint.h>
/* Helper functions for directly doing I/O */

extern inline uint8_t inb(void *port)
{
	volatile unsigned char *addr = (unsigned char *)port;
	uint8_t result;

	result = *addr;
	asm volatile ("mf.a"::: "memory");
	return result;
}

extern inline void outb (uint8_t value, void *port)
{
	volatile unsigned char *addr = (unsigned char *)port;

	*addr = value;
	asm volatile ("mf.a"::: "memory");
}

#endif /* ARCH_IO_H */
