/*
 * purgatory:  setup code
 *
 * Copyright (C) 2005  Zou Nan hai (nanhai.zou@intel.com)
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

.global __dummy_efi_function
.align  32
.proc  __dummy_efi_function
__dummy_efi_function:
	mov r8=r0;;
	br.ret.sptk.many rp;;
.global __dummy_efi_function_end
__dummy_efi_function_end:
.endp 	__dummy_efi_function

.global purgatory_start
.align  32
.proc   purgatory_start
purgatory_start:
	movl r2=__gp_value;;
	ld8 gp=[r2];;
	br.call.sptk.many b0=purgatory
	;;
	alloc r2 = ar.pfs, 0, 0, 5, 0
	;;
	mov out0=r28

	movl r2=__command_line;;
	ld8 out1=[r2];;
	movl r2=__command_line_len;;
	ld8 out2=[r2];;
	movl r2=__ramdisk_base;;
	ld8 out3=[r2];;
	movl r2=__ramdisk_size;;
	ld8 out4=[r2];;
	br.call.sptk.many b0=ia64_env_setup
	movl r10=__kernel_entry;;
	ld8 r14=[r10];;
	mov b6=r14;;
	mov ar.lc=r0
	mov ar.ec=r0
	cover;;
	invala;;
	br.call.sptk.many  b0=b6
.endp   purgatory_start

.align  32
.global __kernel_entry
.size	__kernel_entry, 8
__kernel_entry:
        data8 0x0
.global __command_line
.size	__command_line, 8
__command_line:
        data8 0x0
.global __command_line_len
.size	__command_line_len, 8
__command_line_len:
        data8 0x0
.global __ramdisk_base
.size	__ramdisk_base, 8
__ramdisk_base:
        data8 0x0
.global __ramdisk_size
.size	__ramdisk_size, 8
__ramdisk_size:
        data8 0x0
.global __gp_value
.size	__gp_value, 8
__gp_value:
        data8 0x0
