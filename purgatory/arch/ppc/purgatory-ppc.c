#include <purgatory.h>
#include "purgatory-ppc.h"

unsigned int pul_stack = 0;
unsigned int dt_offset = 0;
unsigned int kernel = 0;
unsigned int epapr_magic = 0;
unsigned int mem_size = 0;

void setup_arch(void)
{
	/* Nothing for now */
}

/* This function can be used to execute after the SHA256 verification. */
void post_verification_setup_arch(void)
{
	/* Nothing for now */
}
