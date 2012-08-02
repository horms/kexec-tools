#
# kexec arm (linux booting linux)
#
arm_KEXEC_SRCS=  kexec/arch/arm/kexec-elf-rel-arm.c
arm_KEXEC_SRCS+= kexec/arch/arm/kexec-zImage-arm.c
arm_KEXEC_SRCS+= kexec/arch/arm/kexec-uImage-arm.c
arm_KEXEC_SRCS+= kexec/arch/arm/kexec-arm.c
arm_KEXEC_SRCS+= kexec/arch/arm/crashdump-arm.c

arm_UIMAGE = kexec/kexec-uImage.c
arm_PHYS_TO_VIRT = kexec/arch/arm/phys_to_virt.c

dist += kexec/arch/arm/Makefile $(arm_KEXEC_SRCS) $(arm_PHYS_TO_VIRT)	\
	kexec/arch/arm/crashdump-arm.h kexec/arch/arm/kexec-arm.h	\
	kexec/arch/arm/include/arch/options.h
