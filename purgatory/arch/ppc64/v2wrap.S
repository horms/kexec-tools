#
#  kexec: Linux boots Linux
#
#  Copyright (C) 2004 - 2005, Milton D Miller II, IBM Corporation
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
# a wrapper to place in front of a v2 device tree
# to call a ppc64 kernel with the expected arguments
# of kernel(device-tree, phys-offset, 0)
#
# calling convention:
#   r3 = physical number of this cpu (all cpus)
#   r4 = address of this chunk (master only)
# master enters at start (aka first byte of this chunk)
# slaves (additional cpus), if any, enter a copy of the
# first 0x100 bytes of this code relocated to 0x0
#
# in other words,
#   a copy of the first 0x100 bytes of this code is copied to 0
#   and the slaves are sent to address 0x60
#   with r3 = their physical cpu number.


# look a bit like a Linux kernel here ...
	.machine ppc64
	.org 0
start:	b	master
	tweq	0,0
secondary_hold:
	.llong	0

	.org 0x20	# need a bit more space than after slave,
master:
	std	4,secondary_hold@l(0)	# bring slaves up here to this copy
	sync			# try to get the slaves to see this
	or	1,1,1		# low priority to let other thread catchup
	isync
	mr	5,3		# save cpu id to r5
	addi	3,4,0x100	# r3 = boot param block
	lwz	6,20(3)		# fetch version number
	cmpwi	0,6,2		# v2 ?
	blt	80f
	stw	5,28(3)		# save my cpu number as boot_cpu_phys
80:	b	81f

	.org 0x60		# ABI: slaves start at 60 with r3=phys
slave:	ld	4,secondary_hold@l(0);
	cmpdi	0,4,0
	beq	slave

	# ahh, master told us where he is running from
	# jump into our copy of the code up there so this code can change
	addi	5,4,1f-start
	mtctr	5
	bctr

	# ok, now wait for the master to tell is to go back to the new block
1:	ld	5,copied@l(4)
	cmpdi	0,5,0
	beq	1b
	ba	0x60



	.long	0		# just an eye-catcher, delete if space needed
	.long	0		# just an eye-catcher, delete if space needed

81:				# master continues here
	or	3,3,3		# ok back to high, lets boot
	lis	6,0x1
	mtctr	6		# delay a bit for slaves to catch up
83:	bdnz	83b		# before we overwrite 0-100 again

	ld	4,-8(3)		# kernel pointer is at -8(bb) by loader
	addi	5,4,-8		# prepare copy with update form instructions
	li	6,0x100/8
	mtctr	6
	li	6,-8
85:	ldu	7,8(5)
	stdu	7,8(6)
	bdnz	85b

	li	5,0		# r5 will be 0 for kernel
	dcbst	0,5		# store dcache, flush icache
	dcbst	0,6		# 0 and 0xf8 covers us with 128 byte lines
	mtctr	4		# prepare branch too
	sync
	icbi	0,5
	icbi	0,6
	sync
	isync
	std	6,-16(3)	# send slaves back down
	bctr			# start kernel

	.org 0xf0
copied:	.llong 0
kernel:	.llong 0
	.org 0x100
__end_stub:
	.equ	boot_block,	. - start
