#ifndef CRASHDUMP_H
#define CRASHDUMP_H

extern int get_crash_notes_per_cpu(int cpu, uint64_t *addr);

/* Need to find a better way to determine per cpu notes section size. */
#define MAX_NOTE_BYTES		1024

#endif /* CRASHDUMP_H */
