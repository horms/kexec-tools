#include <arch/io.h>
#include <purgatory.h>
#include "purgatory-x86_64.h"

uint8_t reset_vga = 0;
uint8_t legacy_pic = 0;

void setup_arch(void)
{
	if (reset_vga)    x86_reset_vga();
	if (legacy_pic)   x86_setup_legacy_pic();
}
