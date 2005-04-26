#ifndef _STDINT_H
#define _STDINT_H

typedef unsigned long		size_t;

typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;
#ifdef __s390x__
typedef unsigned long		uint64_t;
#else
typedef unsigned long long	uint64_t;
#endif

typedef signed char 		int8_t;
typedef short 			int16_t;
typedef int 			int32_t;
#ifdef __s390x__
typedef long			int64_t;
#else
typedef long long		int64_t;
#endif

#endif
