#pragma once
#include <ntddk.h>
#include <wsk.h>

#define MIN(_a, _b) ((_a) < (_b)? (_a): (_b))

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos)   \
	 (((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
	 (((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli)  \
	 (((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds)	 \
	 (((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define HTONS(n) (((((unsigned short)(n) & 0xFFu  )) << 8) | \
                   (((unsigned short)(n) & 0xFF00u) >> 8))

#define	IP4_ADDR(a,b,c,d)	((d<<24) | (c<<16) | (b<<8) | a)
