#include "kexec.h"
#include "mem_regions.h"

/**
 * mem_regions_add() - add a memory region to a set of ranges
 * @ranges: ranges to add the memory region to
 * @max: maximum number of entries in memory region
 * @base: base address of memory region
 * @length: length of memory region in bytes
 * @type: type of memory region
 *
 * Add the memory region to the set of ranges, and return %0 if successful,
 * or %-1 if we ran out of space.
 */
int mem_regions_add(struct memory_ranges *ranges, unsigned long long base,
                    unsigned long long length, int type)
{
	struct memory_range *range;

	if (ranges->size >= ranges->max_size)
		return -1;

	range = ranges->ranges + ranges->size++;
	range->start = base;
	range->end = base + length - 1;
	range->type = type;

	return 0;
}
