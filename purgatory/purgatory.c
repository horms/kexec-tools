#include <stdarg.h>
#include <limits.h>
#include <stdint.h>
#include <purgatory.h>
#include <sha256.h>
#include <string.h>
#include "../kexec/kexec-sha256.h"

struct sha256_region sha256_regions[SHA256_REGIONS] = {};
sha256_digest_t sha256_digest = { };

void verify_sha256_digest(void)
{
	struct sha256_region *ptr, *end;
	sha256_digest_t digest;
	int i;
	sha256_context ctx;
	sha256_starts(&ctx);
	end = &sha256_regions[sizeof(sha256_regions)/sizeof(sha256_regions[0])];
	for(ptr = sha256_regions; ptr < end; ptr++) {
		sha256_update(&ctx, ptr->start, ptr->len);
	}
	sha256_finish(&ctx, digest);
	if (memcmp(digest, sha256_digest, sizeof(digest)) != 0) {
		printf("sha256 digests do not match :(\n");
		printf("       digest: ");
		for(i = 0; i < sizeof(digest); i++) {
			printf("%hhx ", digest[i]);
		}
		printf("\n");
		printf("sha256_digest: ");
		for(i = 0; i < sizeof(sha256_digest); i++) {
			printf("%hhx ", sha256_digest[i]);
		}
		printf("\n");
		for(;;) {
			/* loop forever */
		}
	}
}

void purgatory(void)
{
	printf("I'm in purgatory\n");
	setup_arch();
	verify_sha256_digest();
}
