#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <endian.h>
#include <elf.h>

#if !defined(__BYTE_ORDER) || !defined(__LITTLE_ENDIAN) || !defined(__BIG_ENDIAN)
#error Endian defines missing
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define ELFDATALOCAL ELFDATA2LSB
#elif __BYTE_ORDER == __BIG_ENDIAN
# define ELFDATALOCAL ELFDATA2MSB
#else
# error Unknown byte order
#endif

#define MAP_WINDOW_SIZE (64*1024*1024)
#define DEV_MEM "/dev/mem"

static void *map_addr(int fd, unsigned long size, off_t offset)
{
	void *result;
	result = mmap(0, size, PROT_READ, MAP_SHARED, fd, offset);
	if (result == MAP_FAILED) {
		fprintf(stderr, "Cannot mmap " DEV_MEM " offset: %llu size: %lu: %s\n",
			(unsigned long long)offset, size, strerror(errno));
		exit(5);
	}
	return result;
}

static void unmap_addr(void *addr, unsigned long size)
{
	int ret;
	ret = munmap(addr, size);
	if (ret < 0) {
		fprintf(stderr, "munmap failed: %s\n",
			strerror(errno));
		exit(6);
	}
}

static void *xmalloc(size_t size)
{
	void *result;
	result = malloc(size);
	if (result == NULL) {
		fprintf(stderr, "malloc of %u bytes failed: %s\n",
			size, strerror(errno));
		exit(7);
	}
	return result;
}

static void *collect_notes(
	int fd, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr, size_t *note_bytes)
{
	int i;
	size_t bytes, result_bytes;
	char *notes;

	result_bytes = 0;
	/* Find the worst case note memory usage */
	bytes = 0;
	for(i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_NOTE) {
			bytes += phdr[i].p_filesz;
		}
	}

	/* Allocate the worst case note array */
	notes = xmalloc(bytes);

	/* Walk through and capture the notes */
	for(i = 0; i < ehdr->e_phnum; i++) {
		Elf64_Nhdr *hdr, *lhdr, *nhdr;
		void *pnotes;
		if (phdr[i].p_type != PT_NOTE) {
			continue;
		}
		/* First snapshot the notes */
		pnotes = map_addr(fd, phdr[i].p_filesz, phdr[i].p_offset);
		memcpy(notes + result_bytes, pnotes, phdr[i].p_filesz);
		unmap_addr(pnotes, phdr[i].p_filesz);

		/* Walk through the new notes and find the real length */
		hdr = (Elf64_Nhdr *)(notes + result_bytes);
		lhdr = (Elf64_Nhdr *)(notes + result_bytes + phdr[i].p_filesz);
		for(; hdr < lhdr; hdr = nhdr) {
			size_t hdr_size;
			/* If there is not a name this is a invalid/reserved note
			 * stop here.
			 */
			if (hdr->n_namesz == 0) {
				break;
			}
			hdr_size = 
				sizeof(*hdr) + 
				((hdr->n_namesz + 3) & ~3) +
				((hdr->n_descsz + 3) & ~3);

			nhdr = (Elf64_Nhdr *)(((char *)hdr) + hdr_size); 
			/* if the note does not fit in the segment stop here */
			if (nhdr > lhdr) {
				break;
			}
			/* Update result_bytes for after each good header */
			result_bytes = ((char *)hdr) - notes;
		}
	}
	*note_bytes = result_bytes;
	return notes;
}

static void *generate_new_headers(
	Elf64_Ehdr *ehdr, Elf64_Phdr *phdr, size_t note_bytes, size_t *header_bytes)
{
	unsigned phnum;
	size_t bytes;
	char *headers;
	Elf64_Ehdr *nehdr;
	Elf64_Phdr *nphdr;
	unsigned long long offset;
	int i;
	/* Count the number of program headers.
	 * When we are done there will be only one note header.
	 */
	phnum = 1;
	for(i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_NOTE) {
			continue;
		}
		phnum++;
	}

	/* Compute how many bytes we will need for headers */
	bytes = sizeof(*ehdr) + sizeof(*phdr)*phnum;

	/* Allocate memory for the headers */
	headers = xmalloc(bytes);

	/* Setup pointers to the new headers */
	nehdr = (Elf64_Ehdr *)headers;
	nphdr = (Elf64_Phdr *)(headers + sizeof(*nehdr));
	
	/* Copy and adjust the Elf header */
	memcpy(nehdr, ehdr, sizeof(*nehdr));
	nehdr->e_phoff = sizeof(*nehdr);
	nehdr->e_phnum = phnum;
	nehdr->e_shoff = 0;
	nehdr->e_shentsize = 0;
	nehdr->e_shnum = 0;
	nehdr->e_shstrndx = 0;

	/* Write the note program header */
	nphdr->p_type = PT_NOTE;
	nphdr->p_offset = bytes;
	nphdr->p_vaddr  = 0;
	nphdr->p_paddr  = 0;
	nphdr->p_filesz = note_bytes;
	nphdr->p_memsz  = note_bytes;
	nphdr->p_flags  = 0;
	nphdr->p_align  = 0;
	nphdr++;

	/* Write the rest of the program headers */
	offset = bytes + note_bytes;
	for(i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_NOTE) {
			continue;
		}
		memcpy(nphdr, &phdr[i], sizeof(*nphdr));
		nphdr->p_offset = offset;
		offset += phdr[i].p_filesz;
	}
	
	*header_bytes = bytes;
	return headers;
}

static void write_all(int fd, const void *buf, size_t count)
{
	ssize_t result, written;
	const char *ptr;
	size_t left;
	ptr = buf;
	left = count;
	do {
		result = write(fd, ptr, left);
		if (result >= 0) {
			written += result;
			ptr += result;
			left -= result;
		}
		else if ((errno != EAGAIN) && (errno != EINTR)) {
			fprintf(stderr, "write failed: %s\n",
				strerror(errno));
			exit(8);
		}
	} while(written < count);
}

int main(int argc, char **argv)
{
	char *start_addr_str, *end;
	unsigned long long start_addr;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	void *notes, *headers;
	size_t note_bytes, header_bytes;
	int fd;
	int i;
	start_addr_str = 0;
	if (argc > 2) {
		fprintf(stderr, "Invalid argument count\n");
		exit(9);
	}
	if (argc == 2) {
		start_addr_str = argv[1];
	}
	if (!start_addr_str) {
		start_addr_str = getenv("elfcorehdr");
	}
	if (!start_addr_str) {
		fprintf(stderr, "Cannot find the start of the core dump\n");
		exit(1);
	}
	start_addr = strtoull(start_addr_str, &end, 0);
	if ((start_addr_str == end) || (*end != '\0')) {
		fprintf(stderr, "Bad core dump start addres: %s\n",
			start_addr_str);
		exit(2);
	}
	
	fd = open(DEV_MEM, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open " DEV_MEM ": %s\n",
			strerror(errno));
		exit(3);
	}

	/* Get the elf header */
	ehdr = map_addr(fd, sizeof(*ehdr), start_addr);

	/* Verify the ELF header */
	if (	(ehdr->e_ident[EI_MAG0] != ELFMAG0) ||
		(ehdr->e_ident[EI_MAG1] != ELFMAG1) ||
		(ehdr->e_ident[EI_MAG2] != ELFMAG2) ||
		(ehdr->e_ident[EI_MAG3] != ELFMAG3) ||
		(ehdr->e_ident[EI_CLASS] != ELFCLASS64) ||
		(ehdr->e_ident[EI_DATA] != ELFDATALOCAL) ||
		(ehdr->e_ident[EI_VERSION] != EV_CURRENT) ||
		(ehdr->e_type != ET_CORE) ||
		(ehdr->e_version != EV_CURRENT) ||
		(ehdr->e_ehsize != sizeof(Elf64_Ehdr)) ||
		(ehdr->e_phentsize != sizeof(Elf64_Phdr)) ||
		(ehdr->e_phnum == 0))
	{
		fprintf(stderr, "Invalid Elf header\n");
		exit(4);
	}
	
	/* Get the program header */
	phdr = map_addr(fd, sizeof(*phdr)*(ehdr->e_phnum), ehdr->e_phoff);

	/* Collect up the notes */
	note_bytes = 0;
	notes = collect_notes(fd, ehdr, phdr, &note_bytes);
	
	/* Generate new headers */
	header_bytes = 0;
	headers = generate_new_headers(ehdr, phdr, note_bytes, &header_bytes);

	/* Write out everything */
	write_all(STDOUT_FILENO, headers, header_bytes);
	write_all(STDOUT_FILENO, notes, note_bytes);
	for(i = 0; i < ehdr->e_phnum; i++) {
		unsigned long long offset, size;
		size_t wsize;
		if (phdr[i].p_type != PT_NOTE) {
			continue;
		}
		offset = phdr[i].p_offset;
		size   = phdr[i].p_filesz;
		wsize  = MAP_WINDOW_SIZE;
		if (wsize > size) {
			wsize = size;
		}
		for(;size > 0; size -= wsize, offset += wsize) {
			void *buf;
			wsize = MAP_WINDOW_SIZE;
			if (wsize > size) {
				wsize = size;
			}
			buf = map_addr(fd, wsize, offset);
			write_all(STDOUT_FILENO, buf, wsize);
			unmap_addr(buf, wsize);
		}
	}
	free(notes);
	close(fd);
	return 0;
}
