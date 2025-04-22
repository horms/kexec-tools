#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <libfdt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "kexec.h"
#include "dt-ops.h"
#include "mem_regions.h"

static const char n_chosen[] = "chosen";

static const char p_bootargs[] = "bootargs";
static const char p_initrd_start[] = "linux,initrd-start";
static const char p_initrd_end[] = "linux,initrd-end";

int dtb_set_initrd(char **dtb, off_t *dtb_size, off_t start, off_t end)
{
	int result;
	uint64_t value;

	dbgprintf("%s: start %jd, end %jd, size %jd (%jd KiB)\n",
		__func__, (intmax_t)start, (intmax_t)end,
		(intmax_t)(end - start),
		(intmax_t)(end - start) / 1024);

	value = cpu_to_fdt64(start);

	result = dtb_set_property(dtb, dtb_size, n_chosen, p_initrd_start,
		&value, sizeof(value));

	if (result)
		return result;

	value = cpu_to_fdt64(end);

	result = dtb_set_property(dtb, dtb_size, n_chosen, p_initrd_end,
		&value, sizeof(value));

	if (result) {
		dtb_delete_property(*dtb, n_chosen, p_initrd_start);
		return result;
	}

	return 0;
}

void dtb_clear_initrd(char **dtb, off_t *dtb_size)
{
	dtb_delete_property(*dtb, n_chosen, p_initrd_start);
	dtb_delete_property(*dtb, n_chosen, p_initrd_end);
}

int dtb_set_bootargs(char **dtb, off_t *dtb_size, const char *command_line)
{
	return dtb_set_property(dtb, dtb_size, n_chosen, p_bootargs,
		command_line, strlen(command_line) + 1);
}

int dtb_set_property(char **dtb, off_t *dtb_size, const char *node,
	const char *prop, const void *value, int value_len)
{
	int result;
	int nodeoffset;
	void *new_dtb;
	int new_size;
	char *new_node = NULL;

	value_len = FDT_TAGALIGN(value_len);

	new_size = FDT_TAGALIGN(*dtb_size + fdt_node_len(node)
		+ fdt_prop_len(prop, value_len));

	new_dtb = malloc(new_size);

	if (!new_dtb) {
		dbgprintf("%s: malloc failed\n", __func__);
		return -ENOMEM;
	}

	result = fdt_open_into(*dtb, new_dtb, new_size);

	if (result) {
		dbgprintf("%s: fdt_open_into failed: %s\n", __func__,
			fdt_strerror(result));
		goto on_error;
	}

	new_node = malloc(strlen("/") + strlen(node) + 1);
	if (!new_node) {
		dbgprintf("%s: malloc failed\n", __func__);
		result = -ENOMEM;
		goto on_error;
	}

	strcpy(new_node, "/");
	strcat(new_node, node);

	nodeoffset = fdt_path_offset(new_dtb, new_node);

	if (nodeoffset == -FDT_ERR_NOTFOUND) {
		result = fdt_add_subnode(new_dtb, 0, node);

		if (result < 0) {
			dbgprintf("%s: fdt_add_subnode failed: %s\n", __func__,
				fdt_strerror(result));
			goto on_error;
		}
		nodeoffset = result;
	} else if (nodeoffset < 0) {
		dbgprintf("%s: fdt_path_offset failed: %s\n", __func__,
			fdt_strerror(nodeoffset));
		goto on_error;
	}

	result = fdt_setprop(new_dtb, nodeoffset, prop, value, value_len);

	if (result) {
		dbgprintf("%s: fdt_setprop failed: %s\n", __func__,
			fdt_strerror(result));
		goto on_error;
	}

	/*
	 * Can't call free on dtb since dtb may have been mmaped by
	 * slurp_file().
	 */

	result = fdt_pack(new_dtb);

	if (result)
		dbgprintf("%s: Unable to pack device tree: %s\n", __func__,
			fdt_strerror(result));

	*dtb = new_dtb;
	*dtb_size = fdt_totalsize(*dtb);

	return 0;

on_error:
	free(new_dtb);
	free(new_node);
	return result;
}

int dtb_delete_property(char *dtb, const char *node, const char *prop)
{
	int result, nodeoffset;
	char *new_node = NULL;

	new_node = malloc(strlen("/") + strlen(node) + 1);
	if (!new_node) {
		dbgprintf("%s: malloc failed\n", __func__);
		return -ENOMEM;
	}

	strcpy(new_node, "/");
	strcat(new_node, node);

	nodeoffset = fdt_path_offset(dtb, new_node);
	if (nodeoffset < 0) {
		dbgprintf("%s: fdt_path_offset failed: %s\n", __func__,
			fdt_strerror(nodeoffset));
		free(new_node);
		return nodeoffset;
	}

	result = fdt_delprop(dtb, nodeoffset, prop);

	if (result)
		dbgprintf("%s: fdt_delprop failed: %s\n", __func__,
			fdt_strerror(nodeoffset));

	free(new_node);
	return result;
}

static int dtb_get_num_cells(char *dtb, int nodeoffset, uint32_t *addr_cells,
			     uint32_t *size_cells, bool recursive)
{
	const uint32_t *prop32 = NULL;
	int curr_offset = nodeoffset;
	int prop_len = 0;
	*addr_cells = 0;
	*size_cells = 0;

	do {
		prop32 = fdt_getprop(dtb, curr_offset, "#address-cells", &prop_len);
		curr_offset = fdt_parent_offset(dtb, curr_offset);
	} while (!prop32 && prop_len == -FDT_ERR_NOTFOUND && recursive);

	if (!prop32) {
		dbgprintf("Could not get #address-cells property for %s (%s)\n",
			  fdt_get_name(dtb, nodeoffset, NULL), fdt_strerror(nodeoffset));
		return -EINVAL;
	}
	*addr_cells = fdt32_to_cpu(*prop32);

	curr_offset = nodeoffset;
	do {
		prop32 = fdt_getprop(dtb, curr_offset, "#size-cells", &prop_len);
		curr_offset = fdt_parent_offset(dtb, curr_offset);
	} while (!prop32 && prop_len == -FDT_ERR_NOTFOUND && recursive);

	if (!prop32) {
		dbgprintf("Could not get #size-cells property for %s (%s)\n",
			  fdt_get_name(dtb, nodeoffset, NULL), fdt_strerror(nodeoffset));
		return -EINVAL;
	}
	*size_cells = fdt32_to_cpu(*prop32);

	dbgprintf("%s: #address-cells:%d #size-cells:%d\n",
		 fdt_get_name(dtb, nodeoffset, NULL), *addr_cells, *size_cells);

	return 0;
}

void dtb_extract_int_property(uint64_t *val, const void *buf, uint32_t cells)
{
	const uint32_t *prop32 = NULL;
	const uint64_t *prop64 = NULL;

	if (cells == 1) {
		prop32 = (const uint32_t *) buf;
		*val = (uint64_t) be32_to_cpu(*prop32);
	} else {
		/* Skip any leading cells */
		prop64 = (const uint64_t *) (uint32_t *)buf + cells - 2;
		*val = (uint64_t) be64_to_cpu(*prop64);
	}
}

void dtb_fill_int_property(void *buf, uint64_t val, uint32_t cells)
{
	uint32_t prop32 = 0;
	uint64_t prop64 = 0;

	if (cells == 1) {
		prop32 = cpu_to_fdt32((uint32_t) val);
		memcpy(buf, &prop32, sizeof(uint32_t));
	} else {
		prop64 = cpu_to_fdt64(val);
		/* Skip any leading cells */
		memcpy((uint64_t *)(uint32_t *)buf + cells - 2,
		       &prop64, sizeof(uint64_t));
	}
}

int dtb_add_range_property(char **dtb, off_t *dtb_size, uint64_t start, uint64_t end,
			   const char *parent, const char *name)
{
	uint32_t addr_cells = 0;
	uint32_t size_cells = 0;
	char *nodepath = NULL;
	void *prop = NULL;
	int nodeoffset = 0;
	int prop_size = 0;
	int ret = 0;

	nodepath = malloc(strlen("/") + strlen(parent) + 1);
	if (!nodepath) {
		dbgprintf("%s: malloc failed\n", __func__);
		return -ENOMEM;
	}

	strcpy(nodepath, "/");
	strcat(nodepath, parent);

	nodeoffset = fdt_path_offset(*dtb, nodepath);
	if (nodeoffset < 0) {
		dbgprintf("%s: fdt_path_offset(%s) failed: %s\n", __func__,
			  nodepath, fdt_strerror(nodeoffset));
		free(nodepath);
		return nodeoffset;
	}
	free(nodepath);

	ret = dtb_get_num_cells(*dtb, nodeoffset, &addr_cells, &size_cells, true);
	if (ret < 0)
		return ret;

	/* Can the range fit with the given address/size cells ? */
	if ((addr_cells == 1) && (start >= (1ULL << 32)))
		return -EINVAL;

	if ((size_cells == 1) && ((end - start + 1) >= (1ULL << 32)))
		return -EINVAL;

	prop_size = sizeof(uint32_t) * (addr_cells + size_cells);
	prop = malloc(prop_size);

	dtb_fill_int_property(prop, start, addr_cells);
	dtb_fill_int_property((void *)((uint32_t *)prop + addr_cells),
			      end - start + 1, size_cells);

	/* Add by node path name */
	return dtb_set_property(dtb, dtb_size, parent, name, prop, prop_size);
}

/************************\
* MEMORY RANGES HANDLING *
\************************/

static int dtb_add_memory_range(struct memory_ranges *mem_ranges, uint64_t start,
				uint64_t end, unsigned type)
{
	struct memory_range this_region = {0};
	struct memory_range *ranges = mem_ranges->ranges;
	int i = 0;
	int ret = 0;

	if (start == end) {
		dbgprintf("Ignoring empty region\n");
		return -EINVAL;
	}

	/* Check if we are adding an existing region */
	for (i = 0; i < mem_ranges->size; i++) {
		if (start == ranges[i].start && end == ranges[i].end) {
			dbgprintf("Duplicate: 0x%lx - 0x%lx\n", start, end);

			if (type == ranges[i].type)
				return 0;
			else if (type == RANGE_RESERVED) {
				ranges[i].type = RANGE_RESERVED;
				return 0;
			}

			dbgprintf("Conflicting types for region: 0x%lx - 0x%lx\n",
				  start, end);
			return -EINVAL;
		}
	}

	/*
	 * Reserved regions may be part of an existing /memory
	 * region and shouldn't overlap according to spec, so
	 * since we add /memory regions first, we can exclude
	 * reserved regions here from the existing /memory regions
	 * included in ranges[], so that we don't have the same
	 * region twice.
	 */
	if (type == RANGE_RESERVED) {
		this_region.start = start;
		this_region.end = end - 1;
		this_region.type = type;
		ret = mem_regions_exclude(mem_ranges, &this_region);
		if (ret)
			return ret;
	}

	ret = mem_regions_alloc_and_add(mem_ranges, start,
					end - start, type);

	return ret;
}

static int dtb_add_memory_region(char *dtb, int nodeoffset,
				 struct memory_ranges *mem_ranges, int type)
{
	uint32_t root_addr_cells = 0;
	uint32_t root_size_cells = 0;
	uint64_t addr = 0;
	uint64_t size = 0;
	const char *reg = NULL;
	int prop_size = 0;
	int offset = 0;
	int entry_size = 0;
	int num_entries = 0;
	int ret = 0;

	/*
	 * Get address-cells and size-cells properties (according to
	 * binding spec these are the same as in the root node)
	 */
	ret = dtb_get_num_cells(dtb, 0, &root_addr_cells, &root_size_cells, false);
	if (ret < 0) {
		dbgprintf("No address/size cells on root node !\n");
		return ret;
	}

	/*
	 * Parse the reg array, acording to device tree spec it includes
	 * an arbitary number of <address><size> pairs
	 */
	entry_size = (root_addr_cells + root_size_cells) * sizeof(uint32_t);
	reg = fdt_getprop(dtb, nodeoffset, "reg", &prop_size);
	if (!reg) {
		dbgprintf("Warning: Malformed memory region with no reg property (%s) !\n",
			  fdt_get_name(dtb, nodeoffset, NULL));
		return -EINVAL;
	}

	num_entries = prop_size / entry_size;
	dbgprintf("Got region with %i entries: %s\n", num_entries,
		  fdt_get_name(dtb, nodeoffset, NULL));

	for (num_entries--; num_entries >= 0; num_entries--) {
		offset = num_entries * entry_size;

		dtb_extract_int_property(&addr, reg + offset,
					 root_addr_cells);
		offset += root_addr_cells * sizeof(uint32_t);

		dtb_extract_int_property(&size, reg + offset,
					 root_size_cells);

		ret = dtb_add_memory_range(mem_ranges, addr,
					   addr + size, type);
		if (ret)
			return ret;
	}

	return 0;
}

static int dtb_parse_memory_reservations_table(char *dtb, struct memory_ranges *mem_ranges)
{
	int total_memrsrv = 0;
	uint64_t addr = 0;
	uint64_t size = 0;
	int ret = 0;
	int i = 0;

	total_memrsrv = fdt_num_mem_rsv(dtb);
	for (i = 0; i < total_memrsrv; i++) {
		ret = fdt_get_mem_rsv(dtb, i, &addr, &size);
		if (ret)
			continue;
		ret = dtb_add_memory_range(mem_ranges, addr, addr + size - 1,
					   RANGE_RESERVED);
		if (ret)
			return ret;
	}

	return 0;
}

static int dtb_get_reserved_memory_node(char *dtb)
{
	uint32_t root_addr_cells = 0;
	uint32_t root_size_cells = 0;
	uint32_t addr_cells = 0;
	uint32_t size_cells = 0;
	int prop_size = 0;
	int nodeoffset = 0;
	int ret = 0;

	/* Get address / size cells from root node */
	ret = dtb_get_num_cells(dtb, 0, &root_addr_cells, &root_size_cells, false);
	if (ret < 0) {
		dbgprintf("No address/size cells on root node !\n");
		return ret;
	}

	/* This calls fdt_next_node internaly */
	nodeoffset = fdt_subnode_offset(dtb, 0, "reserved-memory");
	if (nodeoffset == -FDT_ERR_NOTFOUND) {
		return nodeoffset;
	} else if (nodeoffset < 0) {
		dbgprintf("Error while looking for reserved-memory: %s\n",
			fdt_strerror(nodeoffset));
		return nodeoffset;
	}

	/* Look for the ranges property */
	fdt_getprop(dtb, nodeoffset, "ranges", &prop_size);
	if (prop_size < 0) {
		fprintf(stderr, "Malformed reserved-memory node (no ranges property) !\n");
		return -EINVAL;
	}

	/* Verify address-cells / size-cells */
	ret = dtb_get_num_cells(dtb, nodeoffset, &addr_cells, &size_cells, false);
	if (ret < 0) {
		dbgprintf("No address/size cells property on reserved-memory node\n");
		return ret;
	}

	if (addr_cells != root_addr_cells) {
		fprintf(stderr, "Invalid #address-cells property on reserved-memory node\n");
		return -EINVAL;
	}

	if (size_cells != root_size_cells) {
		fprintf(stderr, "Invalid #size-cells property on reserved-memory node\n");
		return -EINVAL;

	}

	return nodeoffset;
}

static int dtb_parse_reserved_memory_node(char *dtb, struct memory_ranges *mem_ranges)
{
	int nodeoffset = 0;
	int node_depth = 0;
	int parent_depth = 0;
	int ret = 0;

	nodeoffset = dtb_get_reserved_memory_node(dtb);
	if (nodeoffset == -FDT_ERR_NOTFOUND)
		return 0;
	else if (nodeoffset < 0)
		return nodeoffset;

	/* Got the parent node, check for sub-nodes */

	/* fdt_next_node() increases or decreases depth */
	node_depth = parent_depth;
	nodeoffset = fdt_next_node(dtb, nodeoffset, &node_depth);
	if (ret < 0) {
		dbgprintf("Unable to get next node: %s\n",
			  fdt_strerror(ret));
		return -EINVAL;
	}

	while (node_depth != parent_depth) {

		ret = dtb_add_memory_region(dtb, nodeoffset,
					    mem_ranges, RANGE_RESERVED);
		if (ret)
			return ret;

		nodeoffset = fdt_next_node(dtb, nodeoffset, &node_depth);
		if (ret < 0) {
			dbgprintf("Unable to get next node: %s\n",
				  fdt_strerror(ret));
			return -EINVAL;
		}
	}

	return 0;
}

static int dtb_parse_memory_nodes(char *dtb, struct memory_ranges *mem_ranges)
{
	int nodeoffset = 0;
	int num_regions = 0;
	const char* dev_type = 0;
	int prop_size = 0;
	int ret = 0;

	for (; ; num_regions++) {
		nodeoffset = fdt_subnode_offset(dtb, nodeoffset,
						 "memory");
		if (nodeoffset < 0)
			break;

		dbgprintf("Got memory node at depth: %i\n", fdt_node_depth(dtb, nodeoffset));

		/* Look for the device_type  property */
		dev_type = fdt_getprop(dtb, nodeoffset, "device_type", &prop_size);
		if (prop_size < 0) {
			fprintf(stderr, "Malformed /memory node (no device-type property) !\n");
			return -EINVAL;
		}

		if (strncmp(dev_type, "memory", prop_size)) {
			dbgprintf("Got unknown dev_type property: %s\n", dev_type);
			continue;
		}

		ret = dtb_add_memory_region(dtb, nodeoffset, mem_ranges, RANGE_RAM);
		if (ret)
			return ret;
	}

	if (!num_regions) {
		dbgprintf("Malformed dtb, no /memory nodes present !\n");
		return -EINVAL;
	}

	dbgprintf("Got %i /memory nodes\n", num_regions);

	return 0;
}

int dtb_get_memory_ranges(char *dtb, struct memory_ranges *mem_ranges, struct memory_ranges *extra_ranges)
{
	int i = 0;
	int ret = 0;

	/* Fill mem_ranges[] by parsing the device tree */
	ret = dtb_parse_memory_nodes(dtb, mem_ranges);
	if (ret)
		return ret;

	ret = dtb_parse_memory_reservations_table(dtb, mem_ranges);
	if (ret)
		return ret;

	ret = dtb_parse_reserved_memory_node(dtb, mem_ranges);
	if (ret)
		return ret;

	/* Append any extra ranges provided by the caller (e.g. initrd) */
	for (i = 0; extra_ranges != NULL && i < extra_ranges->size; i++) {
		dbgprintf("Adding extra range: 0x%llx - 0x%llx (%s)\n",
			  extra_ranges->ranges[i].start,
			  extra_ranges->ranges[i].end,
			  extra_ranges->ranges[i].type == RANGE_RESERVED ?
                          "RANGE_RESERVED" : "RANGE_RAM");

		ret = dtb_add_memory_range(mem_ranges, extra_ranges->ranges[i].start,
                                extra_ranges->ranges[i].end, extra_ranges->ranges[i].type);
		if (ret)
			return ret;
	}

	mem_regions_sort(mem_ranges);

	return 0;
}
