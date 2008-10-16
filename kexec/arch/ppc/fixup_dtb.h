#ifndef __FIXUP_DTB_H
#define __FIXUP_DTB_H

char *fixup_dtb_nodes(char *blob_buf, off_t *blob_size, char *nodes[], char *cmdline);

#endif
