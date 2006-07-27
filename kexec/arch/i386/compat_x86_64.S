/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) 2003,2004,2005  Eric Biederman (ebiederm@xmission.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation (version 2 of the License).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define USE_LRET 0
	
.data
	.equ	MSR_K6_EFER,   0xC0000080
	.equ	EFER_LME,      0x00000100
	.equ	X86_CR4_PAE,   0x00000020
	.equ	CR0_PG,        0x80000000

	.globl compat_x86_64, compat_x86_64_size, compat_x86_64_entry32
	.code64
	.balign 16	
compat_x86_64:
	/* Compute where I am running at */
	leaq	compat_x86_64(%rip), %rbx

	/* Relocate the code */
	addq	%rbx, gdt_addr(%rip)
#if !USE_LRET
	addl	%ebx, lm_exit_addr(%rip)
#endif	

	/* Lookup the 32bit start address */
	movl	compat_x86_64_entry32(%rip), %ebx
	pushq	%rbx

#if USE_LRET	
	/* Push the 64bit start address */
	pushq	$0x10
	pushq	lm_exit(%rip)
#endif	
	
	/* This also acts as a serializing instruction ensuring
	 * my self modifying code works.
	 */
	lgdt	gdt(%rip)

#if USE_LRET
	lret
#else				
	/* Switch to 32bit compatiblity mode */
	ljmp	*lm_exit_addr(%rip)
#endif	
lm_exit:
	.code32

	/* Disable paging */
	movl	%cr0, %eax
	andl	$~CR0_PG, %eax
	movl	%eax, %cr0

	/* Disable long mode */
	movl	$MSR_K6_EFER, %ecx
	rdmsr
	andl	$~EFER_LME, %eax
	wrmsr

	/* Disable PAE */
	xorl	%eax, %eax
	movl	%eax, %cr4

	/* load the data segments */
	movl	$0x18, %eax	/* data segment */
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %fs
	movl	%eax, %gs

	/* Remove the 32 bits of the 64 bit start address */
	popl	%eax

	/* set all of the registers to known values */
	/* leave %esp alone */

	xorl	%eax, %eax
	xorl	%ebx, %ebx
	xorl    %ecx, %ecx
	xorl    %edx, %edx
	xorl    %esi, %esi
	xorl    %edi, %edi
	xorl    %ebp, %ebp

	ret

	.balign 16
gdt:	/* 0x00 unusable segment 
	 * 0x08 unused
	 * so use them as the gdt ptr
	 */
	.word	gdt_end - gdt - 1
gdt_addr:	
	.quad	gdt - compat_x86_64
	.word	0, 0, 0

	/* 0x10 4GB flat code segment */
	.word	0xFFFF, 0x0000, 0x9A00, 0x00CF
	/* 0x18 4GB flat data segment */
	.word	0xFFFF, 0x0000, 0x9200, 0x00CF
gdt_end:	

#if !USE_LRET	
lm_exit_addr:
	.long lm_exit - compat_x86_64
	.long 0x10
#endif	

compat_x86_64_entry32:
	.long 0  
	     	
compat_x86_64_end:
compat_x86_64_size:
	.long compat_x86_64_end - compat_x86_64
