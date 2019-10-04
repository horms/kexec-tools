/*
 * elf_info.c: Architecture independent code for parsing elf files.
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

#include <elf_info.h>

/* The 32bit and 64bit note headers make it clear we don't care */
typedef Elf32_Nhdr Elf_Nhdr;

const char *fname;
static Elf64_Ehdr ehdr;
static Elf64_Phdr *phdr;
static int num_pt_loads;

static char osrelease[4096];

static loff_t log_buf_vaddr;
static loff_t log_end_vaddr;
static loff_t log_buf_len_vaddr;
static loff_t logged_chars_vaddr;

/* record format logs */
static loff_t log_first_idx_vaddr;
static loff_t log_next_idx_vaddr;

/* struct printk_log (or older log) size */
static uint64_t log_sz;

/* struct printk_log (or older log) field offsets */
static uint64_t log_offset_ts_nsec = UINT64_MAX;
static uint16_t log_offset_len = UINT16_MAX;
static uint16_t log_offset_text_len = UINT16_MAX;

static uint64_t phys_offset = UINT64_MAX;

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ELFDATANATIVE ELFDATA2LSB
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ELFDATANATIVE ELFDATA2MSB
#else
#error "Unknown machine endian"
#endif

static uint16_t file16_to_cpu(uint16_t val)
{
	if (ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
		val = bswap_16(val);
	return val;
}

static uint32_t file32_to_cpu(uint32_t val)
{
	if (ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
		val = bswap_32(val);
	return val;
}

static uint64_t file64_to_cpu(uint64_t val)
{
	if (ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
		val = bswap_64(val);
	return val;
}

static uint64_t vaddr_to_offset(uint64_t vaddr)
{
	/* Just hand the simple case where kexec gets
	 * the virtual address on the program headers right.
	 */
	ssize_t i;
	for (i = 0; i < ehdr.e_phnum; i++) {
		if (phdr[i].p_vaddr > vaddr)
			continue;
		if ((phdr[i].p_vaddr + phdr[i].p_memsz) <= vaddr)
			continue;
		return (vaddr - phdr[i].p_vaddr) + phdr[i].p_offset;
	}
	fprintf(stderr, "No program header covering vaddr 0x%llxfound kexec bug?\n",
		(unsigned long long)vaddr);
	exit(30);
}

static unsigned machine_pointer_bits(void)
{
	uint8_t bits = 0;

	/* Default to the size of the elf class */
	switch(ehdr.e_ident[EI_CLASS]) {
	case ELFCLASS32:        bits = 32; break;
	case ELFCLASS64:        bits = 64; break;
	}

	/* Report the architectures pointer size */
	switch(ehdr.e_machine) {
	case EM_386:            bits = 32; break;
	}

	return bits;
}

void read_elf32(int fd)
{
	Elf32_Ehdr ehdr32;
	Elf32_Phdr *phdr32;
	size_t phdrs32_size;
	ssize_t ret, i;

	ret = pread(fd, &ehdr32, sizeof(ehdr32), 0);
	if (ret != sizeof(ehdr32)) {
		fprintf(stderr, "Read of Elf header from %s failed: %s\n",
			fname, strerror(errno));
		exit(10);
	}

	ehdr.e_type		= file16_to_cpu(ehdr32.e_type);
	ehdr.e_machine		= file16_to_cpu(ehdr32.e_machine);
	ehdr.e_version		= file32_to_cpu(ehdr32.e_version);
	ehdr.e_entry		= file32_to_cpu(ehdr32.e_entry);
	ehdr.e_phoff		= file32_to_cpu(ehdr32.e_phoff);
	ehdr.e_shoff		= file32_to_cpu(ehdr32.e_shoff);
	ehdr.e_flags		= file32_to_cpu(ehdr32.e_flags);
	ehdr.e_ehsize		= file16_to_cpu(ehdr32.e_ehsize);
	ehdr.e_phentsize	= file16_to_cpu(ehdr32.e_phentsize);
	ehdr.e_phnum		= file16_to_cpu(ehdr32.e_phnum);
	ehdr.e_shentsize	= file16_to_cpu(ehdr32.e_shentsize);
	ehdr.e_shnum		= file16_to_cpu(ehdr32.e_shnum);
	ehdr.e_shstrndx		= file16_to_cpu(ehdr32.e_shstrndx);

	if (ehdr.e_version != EV_CURRENT) {
		fprintf(stderr, "Bad Elf header version %u\n",
			ehdr.e_version);
		exit(11);
	}
	if (ehdr.e_phentsize != sizeof(Elf32_Phdr)) {
		fprintf(stderr, "Bad Elf progra header size %u expected %zu\n",
			ehdr.e_phentsize, sizeof(Elf32_Phdr));
		exit(12);
	}
	phdrs32_size = ehdr.e_phnum * sizeof(Elf32_Phdr);
	phdr32 = calloc(ehdr.e_phnum, sizeof(Elf32_Phdr));
	if (!phdr32) {
		fprintf(stderr, "Calloc of %u phdrs32 failed: %s\n",
			ehdr.e_phnum, strerror(errno));
		exit(14);
	}
	phdr = calloc(ehdr.e_phnum, sizeof(Elf64_Phdr));
	if (!phdr) {
		fprintf(stderr, "Calloc of %u phdrs failed: %s\n",
			ehdr.e_phnum, strerror(errno));
		exit(15);
	}
	ret = pread(fd, phdr32, phdrs32_size, ehdr.e_phoff);
	if (ret < 0 || (size_t)ret != phdrs32_size) {
		fprintf(stderr, "Read of program header @ 0x%llu for %zu bytes failed: %s\n",
			(unsigned long long)ehdr.e_phoff, phdrs32_size, strerror(errno));
		exit(16);
	}
	for (i = 0; i < ehdr.e_phnum; i++) {
		phdr[i].p_type		= file32_to_cpu(phdr32[i].p_type);
		phdr[i].p_offset	= file32_to_cpu(phdr32[i].p_offset);
		phdr[i].p_vaddr		= file32_to_cpu(phdr32[i].p_vaddr);
		phdr[i].p_paddr		= file32_to_cpu(phdr32[i].p_paddr);
		phdr[i].p_filesz	= file32_to_cpu(phdr32[i].p_filesz);
		phdr[i].p_memsz		= file32_to_cpu(phdr32[i].p_memsz);
		phdr[i].p_flags		= file32_to_cpu(phdr32[i].p_flags);
		phdr[i].p_align		= file32_to_cpu(phdr32[i].p_align);

		if (phdr[i].p_type == PT_LOAD)
			num_pt_loads++;
	}
	free(phdr32);
}

void read_elf64(int fd)
{
	Elf64_Ehdr ehdr64;
	Elf64_Phdr *phdr64;
	size_t phdrs_size;
	ssize_t ret, i;

	ret = pread(fd, &ehdr64, sizeof(ehdr64), 0);
	if (ret < 0 || (size_t)ret != sizeof(ehdr)) {
		fprintf(stderr, "Read of Elf header from %s failed: %s\n",
			fname, strerror(errno));
		exit(10);
	}

	ehdr.e_type		= file16_to_cpu(ehdr64.e_type);
	ehdr.e_machine		= file16_to_cpu(ehdr64.e_machine);
	ehdr.e_version		= file32_to_cpu(ehdr64.e_version);
	ehdr.e_entry		= file64_to_cpu(ehdr64.e_entry);
	ehdr.e_phoff		= file64_to_cpu(ehdr64.e_phoff);
	ehdr.e_shoff		= file64_to_cpu(ehdr64.e_shoff);
	ehdr.e_flags		= file32_to_cpu(ehdr64.e_flags);
	ehdr.e_ehsize		= file16_to_cpu(ehdr64.e_ehsize);
	ehdr.e_phentsize	= file16_to_cpu(ehdr64.e_phentsize);
	ehdr.e_phnum		= file16_to_cpu(ehdr64.e_phnum);
	ehdr.e_shentsize	= file16_to_cpu(ehdr64.e_shentsize);
	ehdr.e_shnum		= file16_to_cpu(ehdr64.e_shnum);
	ehdr.e_shstrndx		= file16_to_cpu(ehdr64.e_shstrndx);

	if (ehdr.e_version != EV_CURRENT) {
		fprintf(stderr, "Bad Elf header version %u\n",
			ehdr.e_version);
		exit(11);
	}
	if (ehdr.e_phentsize != sizeof(Elf64_Phdr)) {
		fprintf(stderr, "Bad Elf progra header size %u expected %zu\n",
			ehdr.e_phentsize, sizeof(Elf64_Phdr));
		exit(12);
	}
	phdrs_size = ehdr.e_phnum * sizeof(Elf64_Phdr);
	phdr64 = calloc(ehdr.e_phnum, sizeof(Elf64_Phdr));
	if (!phdr64) {
		fprintf(stderr, "Calloc of %u phdrs64 failed: %s\n",
			ehdr.e_phnum, strerror(errno));
		exit(14);
	}
	phdr = calloc(ehdr.e_phnum, sizeof(Elf64_Phdr));
	if (!phdr) {
		fprintf(stderr, "Calloc of %u phdrs failed: %s\n",
			ehdr.e_phnum, strerror(errno));
		exit(15);
	}
	ret = pread(fd, phdr64, phdrs_size, ehdr.e_phoff);
	if (ret < 0 || (size_t)ret != phdrs_size) {
		fprintf(stderr, "Read of program header @ %llu for %zu bytes failed: %s\n",
			(unsigned long long)(ehdr.e_phoff), phdrs_size, strerror(errno));
		exit(16);
	}
	for (i = 0; i < ehdr.e_phnum; i++) {
		phdr[i].p_type		= file32_to_cpu(phdr64[i].p_type);
		phdr[i].p_flags		= file32_to_cpu(phdr64[i].p_flags);
		phdr[i].p_offset	= file64_to_cpu(phdr64[i].p_offset);
		phdr[i].p_vaddr		= file64_to_cpu(phdr64[i].p_vaddr);
		phdr[i].p_paddr		= file64_to_cpu(phdr64[i].p_paddr);
		phdr[i].p_filesz	= file64_to_cpu(phdr64[i].p_filesz);
		phdr[i].p_memsz		= file64_to_cpu(phdr64[i].p_memsz);
		phdr[i].p_align		= file64_to_cpu(phdr64[i].p_align);

		if (phdr[i].p_type == PT_LOAD)
			num_pt_loads++;
	}
	free(phdr64);
}

int get_pt_load(int idx,
	unsigned long long *phys_start,
	unsigned long long *phys_end,
	unsigned long long *virt_start,
	unsigned long long *virt_end)
{
	Elf64_Phdr *pls;

	if (num_pt_loads <= idx)
		return 0;

	pls = &phdr[idx];

	if (phys_start)
		*phys_start = pls->p_paddr;
	if (phys_end)
		*phys_end   = pls->p_paddr + pls->p_memsz;
	if (virt_start)
		*virt_start = pls->p_vaddr;
	if (virt_end)
		*virt_end   = pls->p_vaddr + pls->p_memsz;

	return 1;
}

#define NOT_FOUND_LONG_VALUE		(-1)

void scan_vmcoreinfo(char *start, size_t size)
{
	char *last = start + size - 1;
	char *pos, *eol;
	char temp_buf[1024];
	bool last_line = false;
	char *str, *endp;

#define SYMBOL(sym) {					\
	.str = "SYMBOL(" #sym  ")=",			\
	.name = #sym,					\
	.len = sizeof("SYMBOL(" #sym  ")=") - 1,	\
	.vaddr = & sym ## _vaddr,			\
 }
	static struct symbol {
		const char *str;
		const char *name;
		size_t len;
		loff_t *vaddr;
	} symbol[] = {
		SYMBOL(log_buf),
		SYMBOL(log_end),
		SYMBOL(log_buf_len),
		SYMBOL(logged_chars),
		SYMBOL(log_first_idx),
		SYMBOL(log_next_idx),
	};

	for (pos = start; pos <= last; pos = eol + 1) {
		size_t len, i;
		/* Find the end of the current line */
		for (eol = pos; (eol <= last) && (*eol != '\n') ; eol++)
			;
		if (eol > last) {
			/*
			 * We did not find \n and note ended. Currently kernel
			 * is appending last field CRASH_TIME without \n. It
			 * is ugly but handle it.
			 */
			eol = last;
			len = eol - pos + 1;
			if (len >= sizeof(temp_buf))
				len = sizeof(temp_buf) - 1;
			strncpy(temp_buf, pos, len);
			temp_buf[len + 1] = '\0';

			pos = temp_buf;
			len = len + 1;
			eol = pos + len -1;
			last_line = true;
		} else  {
			len = eol - pos + 1;
		}

		/* Stomp the last character so I am guaranteed a terminating null */
		*eol = '\0';
		/* Copy OSRELEASE if I see it */
		if ((len >= 10) && (memcmp("OSRELEASE=", pos, 10) == 0)) {
			size_t to_copy = len - 10;
			if (to_copy >= sizeof(osrelease))
				to_copy = sizeof(osrelease) - 1;
			memcpy(osrelease, pos + 10, to_copy);
			osrelease[to_copy] = '\0';
		}
		/* See if the line is mentions a symbol I am looking for */
		for (i = 0; i < sizeof(symbol)/sizeof(symbol[0]); i++ ) {
			unsigned long long vaddr;
			if (symbol[i].len >= len)
				continue;
			if (memcmp(symbol[i].str, pos, symbol[i].len) != 0)
				continue;
			/* Found a symbol now decode it */
			vaddr = strtoull(pos + symbol[i].len, NULL, 16);
			/* Remember the virtual address */
			*symbol[i].vaddr = vaddr;
		}

		/* Check for "SIZE(printk_log)" or older "SIZE(log)=" */
		str = "SIZE(log)=";
		if (memcmp(str, pos, strlen(str)) == 0)
			log_sz = strtoull(pos + strlen(str), NULL, 10);

		str = "SIZE(printk_log)=";
		if (memcmp(str, pos, strlen(str)) == 0)
			log_sz = strtoull(pos + strlen(str), NULL, 10);

		/* Check for struct printk_log (or older log) field offsets */
		str = "OFFSET(log.ts_nsec)=";
		if (memcmp(str, pos, strlen(str)) == 0)
			log_offset_ts_nsec = strtoull(pos + strlen(str), NULL,
							10);
		str = "OFFSET(printk_log.ts_nsec)=";
		if (memcmp(str, pos, strlen(str)) == 0)
			log_offset_ts_nsec = strtoull(pos + strlen(str), NULL,
							10);

		str = "OFFSET(log.len)=";
		if (memcmp(str, pos, strlen(str)) == 0)
			log_offset_len = strtoul(pos + strlen(str), NULL, 10);

		str = "OFFSET(printk_log.len)=";
		if (memcmp(str, pos, strlen(str)) == 0)
			log_offset_len = strtoul(pos + strlen(str), NULL, 10);

		str = "OFFSET(log.text_len)=";
		if (memcmp(str, pos, strlen(str)) == 0)
			log_offset_text_len = strtoul(pos + strlen(str), NULL,
							10);
		str = "OFFSET(printk_log.text_len)=";
		if (memcmp(str, pos, strlen(str)) == 0)
			log_offset_text_len = strtoul(pos + strlen(str), NULL,
							10);

		/* Check for PHYS_OFFSET number */
		str = "NUMBER(PHYS_OFFSET)=";
		if (memcmp(str, pos, strlen(str)) == 0) {
			phys_offset = strtoul(pos + strlen(str), &endp,
							10);
			if (strlen(endp) != 0)
				phys_offset = strtoul(pos + strlen(str), &endp, 16);
			if ((phys_offset == LONG_MAX) || strlen(endp) != 0) {
				fprintf(stderr, "Invalid data %s\n",
					pos);
				break;
			}
		}

		if (last_line)
			break;
	}
}

static int scan_notes(int fd, loff_t start, loff_t lsize)
{
	char *buf, *last, *note, *next;
	size_t size;
	ssize_t ret;

	if (lsize > SSIZE_MAX) {
		fprintf(stderr, "Unable to handle note section of %llu bytes\n",
			(unsigned long long)lsize);
		exit(20);
	}

	size = lsize;
	buf = malloc(size);
	if (!buf) {
		fprintf(stderr, "Cannot malloc %zu bytes\n", size);
		exit(21);
	}
	last = buf + size - 1;
	ret = pread(fd, buf, size, start);
	if (ret != (ssize_t)size) {
		fprintf(stderr, "Cannot read note section @ 0x%llx of %zu bytes: %s\n",
			(unsigned long long)start, size, strerror(errno));
		exit(22);
	}

	for (note = buf; (note + sizeof(Elf_Nhdr)) < last; note = next)
	{
		Elf_Nhdr *hdr;
		char *n_name, *n_desc;
		size_t n_namesz, n_descsz, n_type;

		hdr = (Elf_Nhdr *)note;
		n_namesz = file32_to_cpu(hdr->n_namesz);
		n_descsz = file32_to_cpu(hdr->n_descsz);
		n_type   = file32_to_cpu(hdr->n_type);

		n_name = note + sizeof(*hdr);
		n_desc = n_name + ((n_namesz + 3) & ~3);
		next = n_desc + ((n_descsz + 3) & ~3);

		if (next > (last + 1))
			break;

		if ((memcmp(n_name, "VMCOREINFO", 11) != 0) || (n_type != 0))
			continue;
		scan_vmcoreinfo(n_desc, n_descsz);
	}

	if ((note + sizeof(Elf_Nhdr)) == last)
		return -1;

	free(buf);

	return 0;
}

static int scan_note_headers(int fd)
{
	int i, ret = 0;

	for (i = 0; i < ehdr.e_phnum; i++) {
		if (phdr[i].p_type != PT_NOTE)
			continue;
		ret = scan_notes(fd, phdr[i].p_offset, phdr[i].p_filesz);
	}

	return ret;
}

static uint64_t read_file_pointer(int fd, uint64_t addr)
{
	uint64_t result;
	ssize_t ret;

	if (machine_pointer_bits() == 64) {
		uint64_t scratch;
		ret = pread(fd, &scratch, sizeof(scratch), addr);
		if (ret != sizeof(scratch)) {
			fprintf(stderr, "Failed to read pointer @ 0x%llx: %s\n",
				(unsigned long long)addr, strerror(errno));
			exit(40);
		}
		result = file64_to_cpu(scratch);
	} else {
		uint32_t scratch;
		ret = pread(fd, &scratch, sizeof(scratch), addr);
		if (ret != sizeof(scratch)) {
			fprintf(stderr, "Failed to read pointer @ 0x%llx: %s\n",
				(unsigned long long)addr, strerror(errno));
			exit(40);
		}
		result = file32_to_cpu(scratch);
	}
	return result;
}

static uint32_t read_file_u32(int fd, uint64_t addr)
{
	uint32_t scratch;
	ssize_t ret;
	ret = pread(fd, &scratch, sizeof(scratch), addr);
	if (ret != sizeof(scratch)) {
		fprintf(stderr, "Failed to read value @ 0x%llx: %s\n",
			(unsigned long long)addr, strerror(errno));
		exit(41);
	}
	return file32_to_cpu(scratch);
}

static int32_t read_file_s32(int fd, uint64_t addr)
{
	return read_file_u32(fd, addr);
}

static void dump_dmesg_legacy(int fd, void (*handler)(char*, unsigned int))
{
	uint64_t log_buf, log_buf_offset;
	unsigned log_end, logged_chars, log_end_wrapped;
	int log_buf_len, to_wrap;
	char *buf;
	ssize_t ret;

	if (!log_buf_vaddr) {
		fprintf(stderr, "Missing the log_buf symbol\n");
		exit(50);
	}
	if (!log_end_vaddr) {
		fprintf(stderr, "Missing the log_end symbol\n");
		exit(51);
	}
	if (!log_buf_len_vaddr) {
		fprintf(stderr, "Missing the log_bug_len symbol\n");
		exit(52);
	}
	if (!logged_chars_vaddr) {
		fprintf(stderr, "Missing the logged_chars symbol\n");
		exit(53);
	}

	log_buf = read_file_pointer(fd, vaddr_to_offset(log_buf_vaddr));
	log_end = read_file_u32(fd, vaddr_to_offset(log_end_vaddr));
	log_buf_len = read_file_s32(fd, vaddr_to_offset(log_buf_len_vaddr));
	logged_chars = read_file_u32(fd, vaddr_to_offset(logged_chars_vaddr));

	log_buf_offset = vaddr_to_offset(log_buf);

	buf = calloc(1, log_buf_len);
	if (!buf) {
		fprintf(stderr, "Failed to malloc %d bytes for the logbuf: %s\n",
			log_buf_len, strerror(errno));
		exit(51);
	}

	log_end_wrapped = log_end % log_buf_len;
	to_wrap = log_buf_len - log_end_wrapped;

	ret = pread(fd, buf, to_wrap, log_buf_offset + log_end_wrapped);
	if (ret != to_wrap) {
		fprintf(stderr, "Failed to read the first half of the log buffer: %s\n",
			strerror(errno));
		exit(52);
	}
	ret = pread(fd, buf + to_wrap, log_end_wrapped, log_buf_offset);
	if (ret != log_end_wrapped) {
		fprintf(stderr, "Faield to read the second half of the log buffer: %s\n",
			strerror(errno));
		exit(53);
	}

	/*
	 * To collect full dmesg including the part before `dmesg -c` is useful
	 * for later debugging. Use same logic as what crash utility is using.
	 */
	logged_chars = log_end < log_buf_len ? log_end : log_buf_len;

	if (handler)
		handler(buf + (log_buf_len - logged_chars), logged_chars);
}

static inline uint16_t struct_val_u16(char *ptr, unsigned int offset)
{
	return(file16_to_cpu(*(uint16_t *)(ptr + offset)));
}

static inline uint32_t struct_val_u32(char *ptr, unsigned int offset)
{
	return(file32_to_cpu(*(uint32_t *)(ptr + offset)));
}

static inline uint64_t struct_val_u64(char *ptr, unsigned int offset)
{
	return(file64_to_cpu(*(uint64_t *)(ptr + offset)));
}

/* Read headers of log records and dump accordingly */
static void dump_dmesg_structured(int fd, void (*handler)(char*, unsigned int))
{
#define OUT_BUF_SIZE	4096
	uint64_t log_buf, log_buf_offset, ts_nsec;
	uint32_t log_first_idx, log_next_idx, current_idx, len = 0, i;
	char *buf, out_buf[OUT_BUF_SIZE];
	ssize_t ret;
	char *msg;
	uint16_t text_len;
	imaxdiv_t imaxdiv_sec, imaxdiv_usec;

	if (!log_buf_vaddr) {
		fprintf(stderr, "Missing the log_buf symbol\n");
		exit(60);
	}

	if (!log_buf_len_vaddr) {
		fprintf(stderr, "Missing the log_bug_len symbol\n");
		exit(61);
	}

	if (!log_first_idx_vaddr) {
		fprintf(stderr, "Missing the log_first_idx symbol\n");
		exit(62);
	}

	if (!log_next_idx_vaddr) {
		fprintf(stderr, "Missing the log_next_idx symbol\n");
		exit(63);
	}

	if (!log_sz) {
		fprintf(stderr, "Missing the struct log size export\n");
		exit(64);
	}

	if (log_offset_ts_nsec == UINT64_MAX) {
		fprintf(stderr, "Missing the log.ts_nsec offset export\n");
		exit(65);
	}

	if (log_offset_len == UINT16_MAX) {
		fprintf(stderr, "Missing the log.len offset export\n");
		exit(66);
	}

	if (log_offset_text_len == UINT16_MAX) {
		fprintf(stderr, "Missing the log.text_len offset export\n");
		exit(67);
	}

	log_buf = read_file_pointer(fd, vaddr_to_offset(log_buf_vaddr));

	log_first_idx = read_file_u32(fd, vaddr_to_offset(log_first_idx_vaddr));
	log_next_idx = read_file_u32(fd, vaddr_to_offset(log_next_idx_vaddr));

	log_buf_offset = vaddr_to_offset(log_buf);

	buf = calloc(1, log_sz);
	if (!buf) {
		fprintf(stderr, "Failed to malloc %" PRId64 " bytes for the log:"
				" %s\n", log_sz, strerror(errno));
		exit(64);
	}

	/* Parse records and write out data at standard output */

	current_idx = log_first_idx;
	len = 0;
	while (current_idx != log_next_idx) {
		uint16_t loglen;

		ret = pread(fd, buf, log_sz, log_buf_offset + current_idx);
		if (ret != log_sz) {
			fprintf(stderr, "Failed to read log of size %" PRId64 " bytes:"
				" %s\n", log_sz, strerror(errno));
			exit(65);
		}
		ts_nsec = struct_val_u64(buf, log_offset_ts_nsec);
		imaxdiv_sec = imaxdiv(ts_nsec, 1000000000);
		imaxdiv_usec = imaxdiv(imaxdiv_sec.rem, 1000);

		len += sprintf(out_buf + len, "[%5llu.%06llu] ",
			(long long unsigned int)imaxdiv_sec.quot,
			(long long unsigned int)imaxdiv_usec.quot);

		/* escape non-printable characters */
		text_len = struct_val_u16(buf, log_offset_text_len);
		msg = calloc(1, text_len);
		if (!msg) {
			fprintf(stderr, "Failed to malloc %u bytes for log text:"
				" %s\n", text_len, strerror(errno));
			exit(64);
		}

		ret = pread(fd, msg, text_len, log_buf_offset + current_idx + log_sz);
		if (ret != text_len) {
			fprintf(stderr, "Failed to read log text of size %u bytes:"
				" %s\n", text_len, strerror(errno));
			exit(65);
		}
		for (i = 0; i < text_len; i++) {
			unsigned char c = msg[i];

			if (!isprint(c) && !isspace(c))
				len += sprintf(out_buf + len, "\\x%02x", c);
			else
				out_buf[len++] = c;

			if (len >= OUT_BUF_SIZE - 64) {
				if (handler)
					handler(out_buf, len);
				len = 0;
			}
		}

		out_buf[len++] = '\n';
		free(msg);
		/*
		 * A length == 0 record is the end of buffer marker. Wrap around
		 * and read the message at the start of the buffer.
		 */
		loglen = struct_val_u16(buf, log_offset_len);
		if (!loglen)
			current_idx = 0;
		else
			/* Move to next record */
			current_idx += loglen;
	}
	free(buf);
	if (len && handler)
		handler(out_buf, len);
}

void dump_dmesg(int fd, void (*handler)(char*, unsigned int))
{
	if (log_first_idx_vaddr)
		dump_dmesg_structured(fd, handler);
	else
		dump_dmesg_legacy(fd, handler);
}

int read_elf(int fd)
{
	int ret;

	ret = pread(fd, ehdr.e_ident, EI_NIDENT, 0);
	if (ret != EI_NIDENT) {
		fprintf(stderr, "Read of e_ident from %s failed: %s\n",
			fname, strerror(errno));
		return 3;
	}
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "Missing elf signature\n");
		return 4;
	}
	if (ehdr.e_ident[EI_VERSION] != EV_CURRENT) {
		fprintf(stderr, "Bad elf version\n");
		return 5;
	}
	if ((ehdr.e_ident[EI_CLASS] != ELFCLASS32) &&
	    (ehdr.e_ident[EI_CLASS] != ELFCLASS64))
	{
		fprintf(stderr, "Unknown elf class %u\n",
			ehdr.e_ident[EI_CLASS]);
		return 6;
	}
	if ((ehdr.e_ident[EI_DATA] != ELFDATA2LSB) &&
	    (ehdr.e_ident[EI_DATA] != ELFDATA2MSB))
	{
		fprintf(stderr, "Unkown elf data order %u\n",
			ehdr.e_ident[EI_DATA]);
		return 7;
	}
	if (ehdr.e_ident[EI_CLASS] == ELFCLASS32)
		read_elf32(fd);
	else
		read_elf64(fd);

	ret = scan_note_headers(fd);
	if (ret < 0)
		return ret;

	return 0;
}

int read_phys_offset_elf_kcore(int fd, unsigned long *phys_off)
{
	int ret;

	*phys_off = ULONG_MAX;

	ret = read_elf(fd);
	if (!ret) {
		/* If we have a valid 'PHYS_OFFSET' by now,
		 * return it to the caller now.
		 */
		if (phys_offset != UINT64_MAX) {
			*phys_off = phys_offset;
			return ret;
		}
	}

	return 2;
}
