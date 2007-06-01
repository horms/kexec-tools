/*
 * mipsel-setup-simple.S - code to execute before kernel to handle command line
 * Copyright (C) 2007 Francesco Chiechi, Alessandro Rubini
 * Copyright (C) 2007 Tvblob s.r.l.
 *
 * derived from Albert Herranz idea (ppc) adding command line support
 * (boot_notes structure)
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

/*
 * Only suitable for platforms booting with MMU turned off.
 * -- Albert Herranz
 */
#include "regdef.h"

/* returns  t0 = relocated address of sym */
/* modifies t1 t2 */
/* sym must not be global or this will not work (at least AFAIK up to now) */
#define RELOC_SYM(sym)                                                 \
	move    t0,ra;          /* save ra */                           \
	bal 1f;                                                         \
1:                                                                     \
	move    t1,ra;          /* now t1 is 1b (where we are now) */   \
	move    ra,t0;          /* restore ra */                        \
	lui     t2,%hi(1b);                                             \
	ori     t2,t2,%lo(1b);                                          \
	lui     t0,%hi(sym);                                            \
	ori     t0,t0,%lo(sym);                                         \
	sub     t0,t0,t2;       /* t0 = offset between sym and 1b */    \
	add     t0,t1,t0;       /* t0 = actual address in memory */

	.data
	.globl setup_simple_start
setup_simple_start:

	/* should perform here any required setup */

	/* Initialize GOT pointer (verify if needed) */
	bal     1f
	nop
	.word   _GLOBAL_OFFSET_TABLE_
	1:
	move    gp, ra
	lw      t1, 0(ra)
	move    gp, t1

	/* spr8 relocation */
	RELOC_SYM(spr8)

	move    t4,t0           // save pointer to kernel start addr
	lw      t3,0(t0)        // save kernel start address

	/* spr9 relocation */
	RELOC_SYM(spr9)
	lw      a0,0(t0)        // load argc

	// this code is to be changed if boot_notes struct changes
	lw      t2,12(t4)       // t2 is size of boot_notes struct
	addi    t2,t2,3
	srl     t2,t2,2
	sll     v1,t2,2         // v1 = size of boot_notes struct
				// aligned to word boundary

	addi    t0,t4,0x20      // t0 contains the address of "kexec" string
	add     v0,t4,v1        // v0 points to last word of boot_notes
	addi    v0,v0,8         // v0 points to address after boot_notes
	sw      t0,0(v0)        // store pointer to "kexec" string there

	lw      t2,-8(t0)       // t2 is size of "kexec" string in bytes
	addi    t2,t2,3
	srl     t2,t2,2
	sll     v1,t2,2         // v1 = size of "kexec" string
				// aligned to word boundary
	add     t2,t0,v1
	addi    t0,t2,4         // t0 points to size of version string

	lw      t2,0(t0)        // t2 is size of version string in bytes
	addi    t2,t2,3
	srl     t2,t2,2
	sll     v1,t2,2         // v1 = size of version string
				// aligned to word boundary

	addi    t0,t0,8         // t0 points to version string
	add     t0,t0,v1        // t0 points to start of command_line record
	addi    t0,t0,12        // t0 points command line

	sw      t0,4(v0)        // store pointer to command line

	move    a1,v0           // load argv
	li      a2,0
	li      a3,0

	jr      t3
	nop

	.balign 4
	.globl setup_simple_regs
setup_simple_regs:
spr8:	.long 0x00000000
spr9:	.long 0x00000000

setup_simple_end:

	.globl setup_simple_size
setup_simple_size:
	.long setup_simple_end - setup_simple_start

