/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) 2003-2005  Eric Biederman (ebiederm@xmission.com)
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#include <sha256.h>
#include "kexec.h"
#include "kexec-syscall.h"
#include "kexec-elf.h"
#include "kexec-sha256.h"
#include <arch/options.h>

unsigned long long mem_min = 0;
unsigned long long mem_max = ULONG_MAX;

void die(char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fflush(stdout);
	fflush(stderr);
	exit(1);
}


void *xmalloc(size_t size)
{
	void *buf;
	buf = malloc(size);
	if (!size)
		return NULL;
	if (!buf) {
		die("Cannot malloc %ld bytes: %s\n",
			size + 0UL, strerror(errno));
	}
	return buf;
}

void *xrealloc(void *ptr, size_t size)
{
	void *buf;
	buf = realloc(ptr, size);
	if (!buf) {
		die("Cannot realloc %ld bytes: %s\n",
			size + 0UL, strerror(errno));
	}
	return buf;
}

int valid_memory_range(struct kexec_info *info,
		       unsigned long sstart, unsigned long send)
{
	int i;
	if (sstart > send) {
		return 0;
	}
	if ((send > mem_max) || (sstart < mem_min)) {
		return 0;
	}
	for (i = 0; i < info->memory_ranges; i++) {
		unsigned long mstart, mend;
		/* Only consider memory ranges */
		if (info->memory_range[i].type != RANGE_RAM)
			continue;
		mstart = info->memory_range[i].start;
		mend = info->memory_range[i].end;
		if (i < info->memory_ranges - 1
		    && mend == info->memory_range[i+1].start)
			mend = info->memory_range[i+1].end;

		/* Check to see if we are fully contained */
		if ((mstart <= sstart) && (mend >= send)) {
			return 1;
		}
	}
	return 0;
}

static int valid_memory_segment(struct kexec_info *info,
				struct kexec_segment *segment)
{
	unsigned long sstart, send;
	sstart = (unsigned long)segment->mem;
	send   = sstart + segment->memsz - 1;

	return valid_memory_range(info, sstart, send);
}

void print_segments(FILE *f, struct kexec_info *info)
{
	int i;

	fprintf(f, "nr_segments = %d\n", info->nr_segments);
	for (i = 0; i < info->nr_segments; i++) {
		fprintf(f, "segment[%d].buf   = %p\n",	i,
			info->segment[i].buf);
		fprintf(f, "segment[%d].bufsz = %zx\n", i,
			info->segment[i].bufsz);
		fprintf(f, "segment[%d].mem   = %p\n",	i,
			info->segment[i].mem);
		fprintf(f, "segment[%d].memsz = %zx\n", i,
			info->segment[i].memsz);
	}
}

int sort_segments(struct kexec_info *info)
{
	int i, j;
	void *end;

	/* Do a stupid insertion sort... */
	for (i = 0; i < info->nr_segments; i++) {
		int tidx;
		struct kexec_segment temp;
		tidx = i;
		for (j = i +1; j < info->nr_segments; j++) {
			if (info->segment[j].mem < info->segment[tidx].mem) {
				tidx = j;
			}
		}
		if (tidx != i) {
			temp = info->segment[tidx];
			info->segment[tidx] = info->segment[i];
			info->segment[i] = temp;
		}
	}
	/* Now see if any of the segments overlap */
	end = 0;
	for (i = 0; i < info->nr_segments; i++) {
		if (end > info->segment[i].mem) {
			fprintf(stderr, "Overlapping memory segments at %p\n",
				end);
			return -1;
		}
		end = ((char *)info->segment[i].mem) + info->segment[i].memsz;
	}
	return 0;
}

unsigned long locate_hole(struct kexec_info *info,
	unsigned long hole_size, unsigned long hole_align, 
	unsigned long hole_min, unsigned long hole_max, 
	int hole_end)
{
	int i, j;
	struct memory_range *mem_range;
	int max_mem_ranges, mem_ranges;
	unsigned long hole_base;

	if (hole_end == 0) {
		die("Invalid hole end argument of 0 specified to locate_hole");
	}

	/* Set an intial invalid value for the hole base */
	hole_base = ULONG_MAX;

	/* Ensure I have a sane alignment value */
	if (hole_align == 0) {
		hole_align = 1;
	}
	/* Align everything to at least a page size boundary */
	if (hole_align < getpagesize()) {
		hole_align = getpagesize();
	}

	/* Compute the free memory ranges */
	max_mem_ranges = info->memory_ranges + info->nr_segments;
	mem_range = xmalloc(max_mem_ranges *sizeof(struct memory_range));
	mem_ranges = 0;
		
	/* Perform a merge on the 2 sorted lists of memory ranges  */
	for (j = 0, i = 0; i < info->memory_ranges; i++) {
		unsigned long long sstart, send;
		unsigned long long mstart, mend;
		mstart = info->memory_range[i].start;
		mend = info->memory_range[i].end;
		if (info->memory_range[i].type != RANGE_RAM)
			continue;
		while ((j < info->nr_segments) &&
		       (((unsigned long)info->segment[j].mem) <= mend)) {
			sstart = (unsigned long)info->segment[j].mem;
			send = sstart + info->segment[j].memsz -1;
			if (mstart < sstart) {
				mem_range[mem_ranges].start = mstart;
				mem_range[mem_ranges].end = sstart -1;
				mem_range[mem_ranges].type = RANGE_RAM;
				mem_ranges++;
			}
			mstart = send +1;
			j++;
		}
		if (mstart < mend) {
			mem_range[mem_ranges].start = mstart;
			mem_range[mem_ranges].end = mend;
			mem_range[mem_ranges].type = RANGE_RAM;
			mem_ranges++;
		}
	}
	/* Now find the end of the last memory_range I can use */
	for (i = 0; i < mem_ranges; i++) {
		unsigned long long start, end, size;
		start = mem_range[i].start;
		end   = mem_range[i].end;
		/* First filter the range start and end values
		 * through the lens of mem_min, mem_max and hole_align.
		 */
		if (start < mem_min) {
			start = mem_min;
		}
		if (start < hole_min) {
			start = hole_min;
		}
		start = (start + hole_align - 1) &
			~((unsigned long long)hole_align - 1);
		if (end > mem_max) {
			end = mem_max;
		}
		if (end > hole_max) {
			end = hole_max;
		}
		/* Is this still a valid memory range? */
		if ((start >= end) || (start >= mem_max) || (end <= mem_min)) {
			continue;
		}
		/* Is there enough space left so we can use it? */
		size = end - start;
		if (size >= hole_size) {
			if (hole_end > 0) {
				hole_base = start;
				break;
			} else {
				hole_base = (end - hole_size) &
					~((unsigned long long)hole_align - 1);
			}
		}
	}
	free(mem_range);
	if (hole_base == ULONG_MAX) {
		fprintf(stderr, "Could not find a free area of memory of "
			"%lx bytes...\n", hole_size);
		return ULONG_MAX;
	}
	if ((hole_base + hole_size)  > hole_max) {
		fprintf(stderr, "Could not find a free area of memory below: "
			"%lx...\n", hole_max);
		return ULONG_MAX;
	}
	return hole_base;
}

void add_segment(struct kexec_info *info,
	const void *buf, size_t bufsz,
	unsigned long base, size_t memsz)
{
	unsigned long last;
	size_t size;
	int pagesize;

	if (bufsz > memsz) {
		bufsz = memsz;
	}
	/* Forget empty segments */
	if (memsz == 0) {
		return;
	}

	/* Round memsz up to a multiple of pagesize */
	pagesize = getpagesize();
	memsz = (memsz + (pagesize - 1)) & ~(pagesize - 1);

	/* Verify base is pagesize aligned.
	 * Finding a way to cope with this problem
	 * is important but for now error so at least
	 * we are not surprised by the code doing the wrong
	 * thing.
	 */
	if (base & (pagesize -1)) {
		die("Base address: %x is not page aligned\n", base);
	}
	
	last = base + memsz -1;
	if (!valid_memory_range(info, base, last)) {
		die("Invalid memory segment %p - %p\n",
			(void *)base, (void *)last);
	}
	
	size = (info->nr_segments + 1) * sizeof(info->segment[0]);
	info->segment = xrealloc(info->segment, size);
	info->segment[info->nr_segments].buf   = buf;
	info->segment[info->nr_segments].bufsz = bufsz;
	info->segment[info->nr_segments].mem   = (void *)base;
	info->segment[info->nr_segments].memsz = memsz;
	info->nr_segments++;
	if (info->nr_segments > KEXEC_MAX_SEGMENTS) {
		fprintf(stderr, "Warning: kernel segment limit reached. "
			"This will likely fail\n");
	}
}

unsigned long add_buffer(struct kexec_info *info,
	const void *buf, unsigned long bufsz, unsigned long memsz,
	unsigned long buf_align, unsigned long buf_min, unsigned long buf_max,
	int buf_end)
{
	unsigned long base;
	int result;
	int pagesize;

	result = sort_segments(info);
	if (result < 0) {
		die("sort_segments failed\n");
	}

	/* Round memsz up to a multiple of pagesize */
	pagesize = getpagesize();
	memsz = (memsz + (pagesize - 1)) & ~(pagesize - 1);

	base = locate_hole(info, memsz, buf_align, buf_min, buf_max, buf_end);
	if (base == ULONG_MAX) {
		die("locate_hole failed\n");
	}
	
	add_segment(info, buf, bufsz, base, memsz);
	return base;
}

char *slurp_file(const char *filename, off_t *r_size)
{
	int fd;
	char *buf;
	off_t size, progress;
	ssize_t result;
	struct stat stats;
	

	if (!filename) {
		*r_size = 0;
		return 0;
	}
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		die("Cannot open `%s': %s\n",
			filename, strerror(errno));
	}
	result = fstat(fd, &stats);
	if (result < 0) {
		die("Cannot stat: %s: %s\n",
			filename, strerror(errno));
	}
	size = stats.st_size;
	*r_size = size;
	buf = xmalloc(size);
	progress = 0;
	while(progress < size) {
		result = read(fd, buf + progress, size - progress);
		if (result < 0) {
			if ((errno == EINTR) ||	(errno == EAGAIN))
				continue;
			die("read on %s of %ld bytes failed: %s\n", filename,
			    (size - progress)+ 0UL, strerror(errno));
		}
		progress += result;
	}
	result = close(fd);
	if (result < 0) {
		die("Close of %s failed: %s\n", filename, strerror(errno));
	}
	return buf;
}

/* This functions reads either specified number of bytes from the file or
   lesser if EOF is met. */

char *slurp_file_len(const char *filename, off_t size)
{
	int fd;
	char *buf;
	off_t progress;
	ssize_t result;

	if (!filename)
		return 0;
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", filename,
				strerror(errno));
		return 0;
	}
	buf = xmalloc(size);
	progress = 0;
	while(progress < size) {
		result = read(fd, buf + progress, size - progress);
		if (result < 0) {
			if ((errno == EINTR) ||	(errno == EAGAIN))
				continue;
			fprintf(stderr, "read on %s of %ld bytes failed: %s\n",
					filename, (size - progress)+ 0UL,
					strerror(errno));
			free(buf);
			return 0;
		}
		if (result == 0)
			/* EOF */
			break;
		progress += result;
	}
	result = close(fd);
	if (result < 0) {
		die("Close of %s failed: %s\n",
			filename, strerror(errno));
	}
	return buf;
}

#if HAVE_ZLIB_H
char *slurp_decompress_file(const char *filename, off_t *r_size)
{
	gzFile fp;
	int errnum;
	const char *msg;
	char *buf;
	off_t size, allocated;
	ssize_t result;

	if (!filename) {
		*r_size = 0;
		return 0;
	}
	fp = gzopen(filename, "rb");
	if (fp == 0) {
		msg = gzerror(fp, &errnum);
		if (errnum == Z_ERRNO) {
			msg = strerror(errno);
		}
		die("Cannot open `%s': %s\n", filename, msg);
	}
	size = 0;
	allocated = 65536;
	buf = xmalloc(allocated);
	do {
		if (size == allocated) {
			allocated <<= 1;
			buf = xrealloc(buf, allocated);
		}
		result = gzread(fp, buf + size, allocated - size);
		if (result < 0) {
			if ((errno == EINTR) || (errno == EAGAIN))
				continue;

			msg = gzerror(fp, &errnum);
			if (errnum == Z_ERRNO) {
				msg = strerror(errno);
			}
			die ("read on %s of %ld bytes failed: %s\n",
				filename, (allocated - size) + 0UL, msg);
		}
		size += result;
	} while(result > 0);
	result = gzclose(fp);
	if (result != Z_OK) {
		msg = gzerror(fp, &errnum);
		if (errnum == Z_ERRNO) {
			msg = strerror(errno);
		}
		die ("Close of %s failed: %s\n", filename, msg);
	}
	*r_size =  size;
	return buf;
}
#else
char *slurp_decompress_file(const char *filename, off_t *r_size)
{
	return slurp_file(filename, r_size);
}
#endif

static void update_purgatory(struct kexec_info *info)
{
	static const uint8_t null_buf[256];
	sha256_context ctx;
	sha256_digest_t digest;
	struct sha256_region region[SHA256_REGIONS];
	int i, j;
	/* Don't do anything if we are not using purgatory */
	if (!info->rhdr.e_shdr) {
		return;
	}
	arch_update_purgatory(info);
	memset(region, 0, sizeof(region));
	sha256_starts(&ctx);
	/* Compute a hash of the loaded kernel */
	for(j = i = 0; i < info->nr_segments; i++) {
		unsigned long nullsz;
		/* Don't include purgatory in the checksum.  The stack
		 * in the bss will definitely change, and the .data section
		 * will also change when we poke the sha256_digest in there.
		 * A very clever/careful person could probably improve this.
		 */
		if (info->segment[i].mem == (void *)info->rhdr.rel_addr) {
			continue;
		}
		sha256_update(&ctx, info->segment[i].buf,
			      info->segment[i].bufsz);
		nullsz = info->segment[i].memsz - info->segment[i].bufsz;
		while(nullsz) {
			unsigned long bytes = nullsz;
			if (bytes > sizeof(null_buf)) {
				bytes = sizeof(null_buf);
			}
			sha256_update(&ctx, null_buf, bytes);
			nullsz -= bytes;
		}
		region[j].start = info->segment[i].mem;
		region[j].len   = info->segment[i].memsz;
		j++;
	}
	sha256_finish(&ctx, digest);
	elf_rel_set_symbol(&info->rhdr, "sha256_regions", &region,
			   sizeof(region));
	elf_rel_set_symbol(&info->rhdr, "sha256_digest", &digest,
			   sizeof(digest));
}

/*
 *	Load the new kernel
 */
static int my_load(const char *type, int fileind, int argc, char **argv,
	unsigned long kexec_flags)
{
	char *kernel;
	char *kernel_buf;
	off_t kernel_size;
	int i = 0;
	int result;
	struct kexec_info info;
	int guess_only = 0;

	memset(&info, 0, sizeof(info));
	info.segment = NULL;
	info.nr_segments = 0;
	info.entry = NULL;
	info.backup_start = 0;
	info.kexec_flags = kexec_flags;

	result = 0;
	if (argc - fileind <= 0) {
		fprintf(stderr, "No kernel specified\n");
		usage();
		return -1;
	}
	kernel = argv[fileind];
	/* slurp in the input kernel */
	kernel_buf = slurp_decompress_file(kernel, &kernel_size);
#if 0
	fprintf(stderr, "kernel: %p kernel_size: %lx\n", 
		kernel_buf, kernel_size);
#endif

	if (get_memory_ranges(&info.memory_range, &info.memory_ranges,
		info.kexec_flags) < 0) {
		fprintf(stderr, "Could not get memory layout\n");
		return -1;
	}
	/* if a kernel type was specified, try to honor it */
	if (type) {
		for (i = 0; i < file_types; i++) {
			if (strcmp(type, file_type[i].name) == 0)
				break;
		}
		if (i == file_types) {
			fprintf(stderr, "Unsupported kernel type %s\n", type);
			return -1;
		} else {
			/* make sure our file is really of that type */
			if (file_type[i].probe(kernel_buf, kernel_size) < 0)
				guess_only = 1;
		}
	}
	if (!type || guess_only) {
		for (i = 0; i < file_types; i++) {
			if (file_type[i].probe(kernel_buf, kernel_size) >= 0)
				break;
		}
		if (i == file_types) {
			fprintf(stderr, "Cannot determine the file type "
					"of %s\n", kernel);
			return -1;
		} else {
			if (guess_only) {
				fprintf(stderr, "Wrong file type %s, "
					"file matches type %s\n",
					type, file_type[i].name);
				return -1;
			}
		}
	}
	if (file_type[i].load(argc, argv, kernel_buf,
			      kernel_size, &info) < 0) {
		fprintf(stderr, "Cannot load %s\n", kernel);
		return -1;
	}
	/* If we are not in native mode setup an appropriate trampoline */
	if (arch_compat_trampoline(&info) < 0) {
		return -1;
	}
	/* Verify all of the segments load to a valid location in memory */
	for (i = 0; i < info.nr_segments; i++) {
		if (!valid_memory_segment(&info, info.segment +i)) {
			fprintf(stderr, "Invalid memory segment %p - %p\n",
				info.segment[i].mem,
				((char *)info.segment[i].mem) + 
				info.segment[i].memsz);
			return -1;
		}
	}
	/* Sort the segments and verify we don't have overlaps */
	if (sort_segments(&info) < 0) {
		return -1;
	}
	/* if purgatory is loaded update it */
	update_purgatory(&info);
#if 0
	fprintf(stderr, "kexec_load: entry = %p flags = %lx\n", 
		info.entry, info.kexec_flags);
	print_segments(stderr, &info);
#endif
	result = kexec_load(
		info.entry, info.nr_segments, info.segment, info.kexec_flags);
	if (result != 0) {
		/* The load failed, print some debugging information */
		fprintf(stderr, "kexec_load failed: %s\n", 
			strerror(errno));
		fprintf(stderr, "entry       = %p flags = %lx\n", 
			info.entry, info.kexec_flags);
		print_segments(stderr, &info);
	}
	return result;
}

int k_unload (unsigned long kexec_flags)
{
	int result;

	result = kexec_load(NULL, 0, NULL, kexec_flags);
	if (result != 0) {
		/* The unload failed, print some debugging information */
		fprintf(stderr, "kexec_load (0 segments) failed: %s\n",
			strerror(errno));
	}
	return result;
}

/*
 *	Start a reboot.
 */
static int my_shutdown(void)
{
	char *args[8];
	int i = 0;

	args[i++] = "shutdown";
	args[i++] = "-r";
	args[i++] = "now";
	args[i++] = NULL;

	execv("/sbin/shutdown", args);
	execv("/etc/shutdown", args);
	execv("/bin/shutdown", args);

	perror("shutdown");
	return -1;
}

/*
 *	Exec the new kernel (reboot)
 */
static int my_exec(void)
{
	int result;

	result = kexec_reboot();
	/* I have failed if I make it here */
	fprintf(stderr, "kexec failed: %s\n", 
		strerror(errno));
	return -1;
}

static void version(void)
{
	printf(PACKAGE " " VERSION " released " RELEASE_DATE "\n");
}

void usage(void)
{
	int i;

	version();
	printf("Usage: kexec [OPTION]... [kernel]\n"
	       "Directly reboot into a new kernel\n"
	       "\n"
	       " -h, --help           Print this help.\n"
	       " -v, --version        Print the version of kexec.\n"
	       " -f, --force          Force an immediate kexec,\n"
	       "                      don't call shutdown.\n"
	       " -x, --no-ifdown      Don't bring down network interfaces.\n"
	       "                      (if used, must be last option\n"
	       "                       specified)\n"
	       " -l, --load           Load the new kernel into the\n"
	       "                      current kernel.\n"
	       " -p, --load-panic     Load the new kernel for use on panic.\n"
	       " -u, --unload         Unload the current kexec target kernel.\n"
	       "                      If capture kernel is being unloaded\n"
	       "                      specify -p with -u.\n"
	       " -e, --exec           Execute a currently loaded kernel.\n"
	       " -t, --type=TYPE      Specify the new kernel is of this type.\n"
	       "     --mem-min=<addr> Specify the lowest memory address to\n"
	       "                      load code into.\n"
	       "     --mem-max=<addr> Specify the highest memory address to\n"
	       "                      load code into.\n"
	       "     --reuseinird     Reuse initrd from first boot.\n"
	       "\n"
	       "Supported kernel file types and options: \n");
	for (i = 0; i < file_types; i++) {
		printf("%s\n", file_type[i].name);
		file_type[i].usage();
	}
	printf(	"Architecture options: \n");
	arch_usage();
	printf("\n");
}

static int kexec_loaded(void)
{
	int ret;
	FILE *fp;

	fp = fopen("/sys/kernel/kexec_loaded", "r");
	if (fp == NULL)
		return -1;
	fscanf(fp, "%d", &ret);
	fclose(fp);
	return ret;
}

/* check we retained the initrd */
void check_reuse_initrd(void)
{
	FILE * fp;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	fp = fopen("/proc/cmdline", "r");
	if (fp == NULL)
		die("unable to open /proc/cmdline\n");
	read = getline(&line, &len, fp);
	if (strstr(line, "retain_initrd") == NULL)
		die("unrecoverable error: current boot didn't "
		    "retain the initrd for reuse.\n");
	if (line)
		free(line);
	close(fp);
}

/* Arch hook for reuse_initrd */
void __attribute__((weak)) arch_reuse_initrd(void)
{
	die("--reuseinitrd not implemented on this architecture\n");
}

int main(int argc, char *argv[])
{
	int do_load = 1;
	int do_exec = 0;
	int do_shutdown = 1;
	int do_sync = 1;
	int do_ifdown = 0;
	int do_unload = 0;
	int do_reuse_initrd = 0;
	unsigned long kexec_flags = 0;
	char *type = 0;
	char *endptr;
	int opt;
	int result = 0;
	int fileind;
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ 0, 0, 0, 0},
	};
	static const char short_options[] = KEXEC_OPT_STR;

	opterr = 0; /* Don't complain about unrecognized options here */
	while ((opt = getopt_long(argc, argv, short_options,
				  options, 0)) != -1) {
		switch(opt) {
		case OPT_HELP:
			usage();
			return 0;
		case OPT_VERSION:
			version();
			return 0;
		case OPT_NOIFDOWN:
			do_ifdown = 0;
			break;
		case OPT_FORCE:
			do_load = 1;
			do_shutdown = 0;
			do_sync = 1;
			do_ifdown = 1;
			do_exec = 1;
			break;
		case OPT_LOAD:
			do_load = 1;
			do_exec = 0;
			do_shutdown = 0;
			break;
		case OPT_UNLOAD:
			do_load = 0;
			do_shutdown = 0;
			do_sync = 0;
			do_unload = 1;
			break;
		case OPT_EXEC:
			do_load = 0;
			do_shutdown = 0;
			do_sync = 1;
			do_ifdown = 1;
			do_exec = 1;
			break;
		case OPT_TYPE:
			type = optarg;
			break;
		case OPT_PANIC:
			do_load = 1;
			do_exec = 0;
			do_shutdown = 0;
			do_sync = 0;
			kexec_flags = KEXEC_ON_CRASH;
			break;
		case OPT_MEM_MIN:
			mem_min = strtoul(optarg, &endptr, 0);
			if (*endptr) {
				fprintf(stderr,
					"Bad option value in --mem-min=%s\n",
					optarg);
				usage();
				return 1;
			}
			break;
		case OPT_MEM_MAX:
			mem_max = strtoul(optarg, &endptr, 0);
			if (*endptr) {
				fprintf(stderr,
					"Bad option value in --mem-max=%s\n",
					optarg);
				usage();
				return 1;
			}
			break;
		case OPT_REUSE_INITRD:
			do_reuse_initrd = 1;
			break;
		default:
			break;
		}
	}

	if ((kexec_flags & KEXEC_ON_CRASH) && !is_crashkernel_mem_reserved()) {
		printf("Memory for crashkernel is not reserved\n");
		printf("Please reserve memory by passing ");
		printf("\"crashkernel=X@Y\" parameter to the kernel\n");
		die("Then try loading kdump kernel\n");
	}

	fileind = optind;
	/* Reset getopt for the next pass; called in other source modules */
	opterr = 1;
	optind = 1;

	result = arch_process_options(argc, argv);

	/* Check for bogus options */
	if (!do_load) {
		while((opt = getopt_long(argc, argv, short_options,
					 options, 0)) != -1) {
			if ((opt == '?') || (opt >= OPT_ARCH_MAX)) {
				usage();
				return 1;
			}
		}
	}

	if (do_reuse_initrd){
		check_reuse_initrd();
		arch_reuse_initrd();
	}

	if (do_unload) {
		result = k_unload(kexec_flags);
	}
	if (do_load && (result == 0)) {
		result = my_load(type, fileind, argc, argv, kexec_flags);
	}
	/* Don't shutdown unless there is something to reboot to! */
	if ((result == 0) && (do_shutdown || do_exec) && !kexec_loaded()) {
		die("Nothing has been loaded!\n");
	}
	if ((result == 0) && do_shutdown) {
		result = my_shutdown();
	}
	if ((result == 0) && do_sync) {
		sync();
	}
	if ((result == 0) && do_ifdown) {
		extern int ifdown(void);
		(void)ifdown();
	}
	if ((result == 0) && do_exec) {
		result = my_exec();
	}

	fflush(stdout);
	fflush(stderr);
	return result;
} 
