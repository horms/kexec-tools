#include <stdlib.h>

#include "kexec.h"
#include "mem_regions.h"

static int mem_range_cmp(const void *a1, const void *a2)
{
	const struct memory_range *r1 = a1;
	const struct memory_range *r2 = a2;

	if (r1->start > r2->start)
		return 1;
	if (r1->start < r2->start)
		return -1;

	return 0;
}

/**
 * mem_regions_sort() - sort ranges into ascending address order
 * @ranges: ranges to sort
 *
 * Sort the memory regions into ascending address order.
 */
void mem_regions_sort(struct memory_ranges *ranges)
{
	qsort(ranges->ranges, ranges->size, sizeof(ranges->ranges),
	      mem_range_cmp);
}

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
