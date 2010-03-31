#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../../kexec.h"
#include <libfdt.h>
#include "ops.h"
#include "page.h"
#include "fixup_dtb.h"

const char proc_dts[] = "/proc/device-tree";

static void fixup_nodes(char *nodes[])
{
	int index = 0;
	char *fname;
	char *prop_name;
	char *node_name;
	void *node;
	int len;
	char *content;
	off_t content_size;
	int ret;

	while (nodes[index]) {

		len = asprintf(&fname, "%s%s", proc_dts, nodes[index]);
		if (len < 0)
			fatal("asprintf() failed\n");

		content = slurp_file(fname, &content_size);
		if (!content) {
			fprintf(stderr, "Can't open %s: %s\n",
					fname, strerror(errno));
			exit(1);
		}

		prop_name = fname + len;
		while (*prop_name != '/')
			prop_name--;

		*prop_name = '\0';
		prop_name++;

		node_name = fname + sizeof(proc_dts) - 1;

		node = finddevice(node_name);
		if (!node)
			node = create_node(NULL, node_name + 1);

		ret = setprop(node, prop_name, content, content_size);
		if (ret < 0)
			fatal("setprop of %s/%s size: %ld failed: %s\n",
					node_name, prop_name, content_size,
					fdt_strerror(ret));

		free(content);
		free(fname);
		index++;
	};
}

/*
 * command line priority:
 * - use the supplied command line
 * - if none available use the command line from .dtb
 * - if not available use the current command line
 */
static void fixup_cmdline(const char *cmdline)
{
	void *chosen;
	char *fixup_cmd_node[] = {
		"/chosen/bootargs",
		NULL,
	};

	chosen = finddevice("/chosen");

	if (!cmdline) {
		if (!chosen)
			fixup_nodes(fixup_cmd_node);
	} else {
		if (!chosen)
			chosen = create_node(NULL, "chosen");
		setprop_str(chosen, "bootargs", cmdline);
	}
	return;
}

char *fixup_dtb_nodes(char *blob_buf, off_t *blob_size, char *nodes[], char *cmdline)
{
	fdt_init(blob_buf);

	fixup_nodes(nodes);
	fixup_cmdline(cmdline);

	blob_buf = (char *)dt_ops.finalize();
	*blob_size = fdt_totalsize(blob_buf);
	return blob_buf;
}
