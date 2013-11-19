#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdlib.h>
#include <elf.h>
#include "kexec.h"
#include "kexec-syscall.h"
#include "crashdump.h"

#include "config.h"

#ifdef HAVE_LIBXENCTRL
#include <xenctrl.h>

#include "crashdump.h"

int xen_kexec_load(struct kexec_info *info)
{
	uint32_t nr_segments = info->nr_segments;
	struct kexec_segment *segments = info->segment;
	xc_interface *xch;
	xc_hypercall_buffer_array_t *array = NULL;
	uint8_t type;
	uint8_t arch;
	xen_kexec_segment_t *xen_segs;
	int s;
	int ret = -1;

	xch = xc_interface_open(NULL, NULL, 0);
	if (!xch)
		return -1;

	xen_segs = calloc(nr_segments + 1, sizeof(*xen_segs));
	if (!xen_segs)
		goto out;

	array = xc_hypercall_buffer_array_create(xch, nr_segments);
	if (array == NULL)
		goto out;

	for (s = 0; s < nr_segments; s++) {
		DECLARE_HYPERCALL_BUFFER(void, seg_buf);

		seg_buf = xc_hypercall_buffer_array_alloc(xch, array, s,
							  seg_buf, segments[s].bufsz);
		if (seg_buf == NULL)
			goto out;
		memcpy(seg_buf, segments[s].buf, segments[s].bufsz);

		set_xen_guest_handle(xen_segs[s].buf.h, seg_buf);
		xen_segs[s].buf_size = segments[s].bufsz;
		xen_segs[s].dest_maddr = (uint64_t)segments[s].mem;
		xen_segs[s].dest_size = segments[s].memsz;
	}

	/*
	 * Ensure 0 - 1 MiB is mapped and accessible by the image.
	 *
	 * This allows access to the VGA memory and the region
	 * purgatory copies in the crash case.
	 */
	set_xen_guest_handle(xen_segs[s].buf.h, HYPERCALL_BUFFER_NULL);
	xen_segs[s].buf_size = 0;
	xen_segs[s].dest_maddr = 0;
	xen_segs[s].dest_size = 1 * 1024 * 1024;
	nr_segments++;

	type = (info->kexec_flags & KEXEC_ON_CRASH) ? KEXEC_TYPE_CRASH
		: KEXEC_TYPE_DEFAULT;

	arch = (info->kexec_flags & KEXEC_ARCH_MASK) >> 16;
#if defined(_i386__) || defined(__x86_64__)
	if (!arch)
		arch = EM_386;
#endif

	ret = xc_kexec_load(xch, type, arch, (uint64_t)info->entry,
			    nr_segments, xen_segs);

out:
	xc_hypercall_buffer_array_destroy(xch, array);
	free(xen_segs);
	xc_interface_close(xch);

	return ret;
}

int xen_kexec_unload(uint64_t kexec_flags)
{
	xc_interface *xch;
	uint8_t type;
	int ret;

	xch = xc_interface_open(NULL, NULL, 0);
	if (!xch)
		return -1;

	type = (kexec_flags & KEXEC_ON_CRASH) ? KEXEC_TYPE_CRASH
		: KEXEC_TYPE_DEFAULT;

	ret = xc_kexec_unload(xch, type);

	xc_interface_close(xch);

	return ret;
}

void xen_kexec_exec(void)
{
	xc_interface *xch;
	
	xch = xc_interface_open(NULL, NULL, 0);
	if (!xch)
		return;

	xc_kexec_exec(xch, KEXEC_TYPE_DEFAULT);

	xc_interface_close(xch);
}

#else /* ! HAVE_LIBXENCTRL */

int xen_kexec_load(struct kexec_info *UNUSED(info))
{
	return -1;
}

int xen_kexec_unload(uint64_t kexec_flags)
{
	return -1;
}

void xen_kexec_exec(void)
{
}

#endif
