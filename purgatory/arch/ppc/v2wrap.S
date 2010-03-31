#
#  kexec: Linux boots Linux
#
#  Copyright (C) 2004 - 2005, Milton D Miller II, IBM Corporation
#  Copyright (C) 2006, Mohan Kumar M (mohan@in.ibm.com), IBM Corporation
#  Copyright (C) 2008, Sebastian Andrzej Siewior (bigeasy@linutronix.de), linutronix
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation (version 2 of the License).
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

#include "ppc_asm.h"

# v2wrap.S
# a wrapper to call purgatory code
# Invokes ppc kernel with the arguments according to ePAPR v1.0
# It assumes that the MSR is allready correct.

# calling convention:
#  no register are considred
#

#define LOADADDR(rn,name)	\
	lis     rn,name##@h;	\
	ori     rn,rn,name##@l;	\

	.globl purgatory_start
purgatory_start:

	LOADADDR(r6,pul_stack)
	lwz	r1,0(r6)		#setup stack

	subi	r1, r1, 112
	bl	purgatory
	nop

	LOADADDR(r6,kernel)
	lwz	r4,0(r6)		# load the kernel address
	mtlr	r4			# prepare branch too

	LOADADDR(r6, dt_offset)
	lwz	r3, 0(r6)		# load device-tree address

	li	r4, 0
	li	r5, 0

	LOADADDR(r6, epapr_magic)	# ePAPR magic value
	lwz	r6, 0(r6)

	LOADADDR(r7, mem_size)		# the Initial Mapped Area
	lwz	r7, 0(r6)

	li	r8, 0
	li	r9, 0

	blr				# start kernel
