#ifndef CRASHDUMP_X86_H
#define CRASHDUMP_X86_H

/* Backup Region, First 640K of System RAM. */
#define BACKUP_START	0x00000000
#define BACKUP_END	0x0009ffff
#define BACKUP_SIZE	(BACKUP_END - BACKUP_START + 1)

#endif /* CRASHDUMP_X86_H */
