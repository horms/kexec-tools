#include <elf_info.h>

/* The 32bit and 64bit note headers make it clear we don't care */
typedef Elf32_Nhdr Elf_Nhdr;

static const char *fname;

int main(int argc, char **argv)
{
	ssize_t ret;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <kernel core file>\n", argv[0]);
		return 1;
	}
	fname = argv[1];

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n",
			fname, strerror(errno));
		return 2;
	}

	ret = read_elf_vmcore(fd);
	
	close(fd);

	return ret;
}
