#ifndef ARCH_IO_H
#define ARCH_IO_H

#include <stdint.h>

/*
 * readX/writeX() are used to access memory mapped devices. On some
 * architectures the memory mapped IO stuff needs to be accessed
 * differently. On the x86 architecture, we just read/write the
 * memory location directly.
 */

static inline unsigned char readb(const volatile void  *addr)
{
	return *(volatile unsigned char *) addr;
}
static inline unsigned short readw(const volatile void  *addr)
{
	return *(volatile unsigned short *) addr;
}
static inline unsigned int readl(const volatile void  *addr)
{
	return *(volatile unsigned int *) addr;
}

static inline void writeb(unsigned char b, volatile void  *addr)
{
	*(volatile unsigned char *) addr = b;
}
static inline void writew(unsigned short b, volatile void  *addr)
{
	*(volatile unsigned short *) addr = b;
}
static inline void writel(unsigned int b, volatile void  *addr)
{
	*(volatile unsigned int *) addr = b;
}

#endif /* ARCH_IO_H */
