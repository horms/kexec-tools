#
#  kexec: Linux boots Linux
#
#  Copyright (C) 2004 - 2005, Milton D Miller II, IBM Corporation
#  Copyright (C) 2006, Mohan Kumar M (mohan@in.ibm.com), IBM Corporation
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

# v2wrap.S
# a wrapper to call purgatory code to backup first
# 32kB of first kernel into the backup region
# reserved by kexec-tools.
# Invokes ppc64 kernel with the expected arguments
# of kernel(device-tree, phys-offset, 0)

#
# calling convention:
#   r3 = physical number of this cpu (all cpus)
#   r4 = address of this chunk (master only)
# master enters at purgatory_start (aka first byte of this chunk)
# slaves (additional cpus), if any, enter a copy of the
# first 0x100 bytes of this code relocated to 0x0
#
# in other words,
#   a copy of the first 0x100 bytes of this code is copied to 0
#   and the slaves are sent to address 0x60
#   with r3 = their physical cpu number.

#define LOADADDR(rn,name) \
	lis     rn,name##@highest;      \
	ori     rn,rn,name##@higher;    \
	rldicr  rn,rn,32,31;            \
	oris    rn,rn,name##@h;         \
	ori     rn,rn,name##@l


	.machine ppc64
	.globl purgatory_start
purgatory_start:	b	master
	.org purgatory_start + 0x60     # ABI: slaves start at 60 with r3=phys
slave:	b $
	.org purgatory_start + 0x100    # ABI: end of copied region
	.size purgatory_start, . - purgatory_start

#
# The above 0x100 bytes at purgatory_start are replaced with the
# code from the kernel (or next stage) by kexec/arch/ppc64/kexec-ppc64.c
#

master:
	or	1,1,1		# low priority to let other threads catchup
	isync
	mr      17,3            # save cpu id to r17
	mr      15,4            # save physical address in reg15

	LOADADDR(6,my_toc)
	ld      2,0(6)          #setup toc

	LOADADDR(6,stack)
	ld      1,0(6)          #setup stack

	subi    1,1,112
	bl      .purgatory
	nop

	or	3,3,3		# ok now to high priority, lets boot
	lis	6,0x1
	mtctr	6		# delay a bit for slaves to catch up
83:	bdnz	83b		# before we overwrite 0-100 again

	LOADADDR(16, dt_offset)
	ld      3,0(16)         # load device-tree address
	mr      16,3            # save dt address in reg16
	lwz     6,20(3)         # fetch version number
	cmpwi   0,6,2           # v2 ?
	blt     80f
	stw     17,28(3)        # save my cpu number as boot_cpu_phys
80:
	LOADADDR(6,kernel)
	ld      4,0(6)          # load the kernel address
	li	5,0		# r5 will be 0 for kernel
	mtctr	4		# prepare branch too
	mr      3,16            # restore dt address

	lwz	7,0(4)		# get the first instruction that we stole
	stw	7,0(0)		# and put it in the slave loop at 0
				# skip cache flush, do we care?

	bctr			# start kernel
