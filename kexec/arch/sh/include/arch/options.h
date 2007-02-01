#ifndef KEXEC_ARCH_SH_OPTIONS_H
#define KEXEC_ARCH_SH_OPTIONS_H

#define OPT_ARCH_MAX     (OPT_MAX+0)
#define OPT_APPEND       (OPT_ARCH_MAX+1)
#define OPT_EMPTYZERO    (OPT_ARCH_MAX+2)
#define OPT_NBSD_HOWTO   (OPT_ARCH_MAX+3)
#define OPT_NBSD_MROOT   (OPT_ARCH_MAX+4)


#define KEXEC_ARCH_OPTIONS \
	KEXEC_OPTIONS \
        {"command-line",   1, 0, OPT_APPEND}, \
        {"append",         1, 0, OPT_APPEND}, \
        {"empty-zero",     1, 0, OPT_APPEND}, \
        {"howto",          1, 0, OPT_NBSD_HOWTO}, \
        {"miniroot",       1, 0, OPT_NBSD_MROOT}, \


#define KEXEC_ARCH_OPT_STR KEXEC_OPT_STR ""

#endif /* KEXEC_ARCH_SH_OPTIONS_H */
