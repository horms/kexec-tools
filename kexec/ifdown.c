/*
 * ifdown.c	Find all network interfaces on the system and
 *		shut them down.
 *
 */
char *v_ifdown = "@(#)ifdown.c  1.11  02-Jun-1998  miquels@cistron.nl";

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/errno.h>

#include <net/if.h>
#include <netinet/in.h>

#define MAX_IFS	64

/*
 *	First, we find all shaper devices and down them. Then we
 *	down all real interfaces. This is because the comment in the
 *	shaper driver says "if you down the shaper device before the
 *	attached inerface your computer will follow".
 */
int ifdown(void)
{
	struct ifreq ifr[MAX_IFS];
	struct ifconf ifc;
	int i, fd;
	int numif;
	int shaper;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "ifdown: ");
		perror("socket");
		return -1;
	}
	ifc.ifc_len = sizeof(ifr);
	ifc.ifc_req = ifr;

	if (ioctl(fd, SIOCGIFCONF, &ifc) < 0) {
		fprintf(stderr, "ifdown: ");
		perror("SIOCGIFCONF");
		close(fd);
		return -1;
	}
	numif = ifc.ifc_len / sizeof(struct ifreq);

	for (shaper = 1; shaper >= 0; shaper--) {
		for (i = 0; i < numif; i++) {

			if ((strncmp(ifr[i].ifr_name, "shaper", 6) == 0)
			    != shaper) continue;

			if (strcmp(ifr[i].ifr_name, "lo") == 0)
				continue;
			if (strchr(ifr[i].ifr_name, ':') != NULL)
				continue;
			ifr[i].ifr_flags &= ~(IFF_UP);
			if (ioctl(fd, SIOCSIFFLAGS, &ifr[i]) < 0) {
				fprintf(stderr, "ifdown: shutdown ");
				perror(ifr[i].ifr_name);
			}
		}
	}
	close(fd);

	return 0;
}
