// from scetool
#pragma once

//Align.
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

//Endian swap for uint16_t.
#define _ES16(val) \
	((uint16_t)(((((uint16_t)val) & 0xff00) >> 8) | \
	       ((((uint16_t)val) & 0x00ff) << 8)))

//Endian swap for uint32_t.
#define _ES32(val) \
	((uint32_t)(((((uint32_t)val) & 0xff000000) >> 24) | \
	       ((((uint32_t)val) & 0x00ff0000) >> 8 ) | \
	       ((((uint32_t)val) & 0x0000ff00) << 8 ) | \
	       ((((uint32_t)val) & 0x000000ff) << 24)))

//Endian swap for uint64_t.
#define _ES64(val) \
	((uint64_t)(((((uint64_t)val) & 0xff00000000000000ull) >> 56) | \
	       ((((uint64_t)val) & 0x00ff000000000000ull) >> 40) | \
	       ((((uint64_t)val) & 0x0000ff0000000000ull) >> 24) | \
	       ((((uint64_t)val) & 0x000000ff00000000ull) >> 8 ) | \
	       ((((uint64_t)val) & 0x00000000ff000000ull) << 8 ) | \
	       ((((uint64_t)val) & 0x0000000000ff0000ull) << 24) | \
	       ((((uint64_t)val) & 0x000000000000ff00ull) << 40) | \
	       ((((uint64_t)val) & 0x00000000000000ffull) << 56)))
