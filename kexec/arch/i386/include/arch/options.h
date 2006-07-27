#ifndef KEXEC_ARCH_I386_OPTIONS_H
#define KEXEC_ARCH_I386_OPTIONS_H

#define OPT_RESET_VGA      (OPT_MAX+0)
#define OPT_SERIAL         (OPT_MAX+1)
#define OPT_SERIAL_BAUD    (OPT_MAX+2)
#define OPT_CONSOLE_VGA    (OPT_MAX+3)
#define OPT_CONSOLE_SERIAL (OPT_MAX+4)
#define OPT_ARCH_MAX       (OPT_MAX+5)

#define KEXEC_ARCH_OPTIONS \
	KEXEC_OPTIONS \
	{ "reset-vga",	    0, 0, OPT_RESET_VGA }, \
	{ "serial",	    1, 0, OPT_SERIAL }, \
	{ "serial-baud",    1, 0, OPT_SERIAL_BAUD }, \
	{ "console-vga",    0, 0, OPT_CONSOLE_VGA }, \
	{ "console-serial", 0, 0, OPT_CONSOLE_SERIAL }, \

#define KEXEC_ARCH_OPT_STR KEXEC_OPT_STR ""

#endif /* KEXEC_ARCH_I386_OPTIONS_H */

