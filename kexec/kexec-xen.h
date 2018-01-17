#ifndef KEXEC_XEN_H
#define KEXEC_XEN_H

#ifdef HAVE_LIBXENCTRL
#include <xenctrl.h>

#ifdef CONFIG_LIBXENCTRL_DL
#include <dlfcn.h>

/* The handle from dlopen(), needed by dlsym(), dlclose() */
extern void *xc_dlhandle;

/* Wrappers around xc_interface_open/close() to insert dlopen/dlclose() */
xc_interface *__xc_interface_open(xentoollog_logger *logger,
				  xentoollog_logger *dombuild_logger,
				  unsigned open_flags);
int __xc_interface_close(xc_interface *xch);

/* GCC expression statements for evaluating dlsym() */
#define __xc_call(dtype, name, args...) \
( \
	{ dtype value; \
	typedef dtype (*func_t)(xc_interface *, ...); \
	func_t func = dlsym(xc_dlhandle, #name); \
	value = func(args); \
	value; } \
)
#define __xc_data(dtype, name) \
( \
	{ dtype *value = (dtype *)dlsym(xc_dlhandle, #name); value; } \
)

/* The wrappers around utilized xenctrl.h functions */
#define xc_interface_open(a, b, c)  \
	__xc_interface_open(a, b, c)
#define xc_interface_close(a) \
	__xc_interface_close(a)
#define xc_version(args...) \
	__xc_call(int, xc_version, args)
#define xc_get_max_cpus(args...) \
	__xc_call(int, xc_get_max_cpus, args)
#define xc_get_machine_memory_map(args...) \
	__xc_call(int, xc_get_machine_memory_map, args)
#define xc_kexec_get_range(args...) \
	__xc_call(int, xc_kexec_get_range, args)
#define xc_kexec_load(args...) \
	__xc_call(int, xc_kexec_load, args)
#define xc_kexec_unload(args...) \
	__xc_call(int, xc_kexec_unload, args)
#define xc_kexec_status(args...) \
	__xc_call(int, xc_kexec_status, args)
#define xc_kexec_exec(args...) \
	__xc_call(int, xc_kexec_exec, args)
#define xc_hypercall_buffer_array_create(args...) \
	__xc_call(xc_hypercall_buffer_array_t *, xc_hypercall_buffer_array_create, args)
#define xc__hypercall_buffer_alloc_pages(args...) \
	__xc_call(void *, xc__hypercall_buffer_alloc_pages, args)
#define xc__hypercall_buffer_free_pages(args...) \
	__xc_call(void  , xc__hypercall_buffer_free_pages, args)
#define xc__hypercall_buffer_array_alloc(args...) \
	__xc_call(void *, xc__hypercall_buffer_array_alloc, args)
#define xc__hypercall_buffer_array_get(args...) \
	__xc_call(void *, xc__hypercall_buffer_array_get, args)
#define xc_hypercall_buffer_array_destroy(args...) \
	__xc_call(void *, xc_hypercall_buffer_array_destroy, args)

#endif /* CONFIG_LIBXENCTRL_DL */
#endif /* HAVE_LIBXENCTRL */

#endif /* KEXEC_XEN_H */
