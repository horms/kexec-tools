#ifndef MEM_REGIONS_H
#define MEM_REGIONS_H

struct memory_ranges;

void mem_regions_sort(struct memory_ranges *ranges);

int mem_regions_add(struct memory_ranges *ranges, unsigned long long base,
                    unsigned long long length, int type);

#endif
