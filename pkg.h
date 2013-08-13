#pragma once

#include <stdint.h>

#define PKG_FILE_OVERWRITE	0x80000000
#define PKG_FILE_SELFNPDRM	0x1
#define PKG_FILE_DIRECTORY	0x4
#define PKG_FILE_RAW		0x3

typedef struct {
	uint32_t magic;				// 0x7f504b47
	uint32_t pkg_type;			// 0x1 (ps3), 0x2 (psp), 0x80000000 (retail)
	uint32_t pkg_info_offset;	// 0xc0
	uint32_t pkg_info_size;		// (sizeof gpkg_info / 8) = 8

	uint32_t header_size;		// 0xc0
	uint32_t item_count;
	uint64_t total_size;		// data_size + 0x1E0

	uint64_t data_offset;		// 0x180
	uint64_t data_size;
	
	char contentid[0x30];
	uint8_t qa_digest[0x10];
	uint8_t k_licensee[0x10];
} gpkg_header; // 128 bytes

typedef struct {
	uint8_t shash[0x10];
	uint8_t crypt[0x30];
} gpkg_crypt; // 64 bytes

typedef struct {
	uint32_t unknown11;			// 0x1
	uint32_t unknown12;			// 0x4
	uint32_t drm_type;			// 0x1 (network), 0x2 (local), 0x3 (free)
	uint32_t unknown14;			// 0x2

	uint32_t unknown21;			// 0x4
	uint32_t unknown22;			// 0x5 (gameexec)
	uint32_t unknown23;			// 0x3
	uint32_t unknown24;			// 0x4

	uint32_t unknown31;			// 0x4e (gameexec)
	uint32_t unknown32;			// 0x4
	uint32_t unknown33;			// 0x8
	uint16_t secondary_version;	// 0x0
	uint16_t unknown34;			// 0x0

	uint32_t data_size;
	uint32_t unknown42;			// 0x5
	uint32_t unknown43;			// 0x4
	uint16_t pkg_author;		// make_package_npdrm revision
	uint16_t pkg_version;		// package version
} gpkg_info; // 64 bytes

typedef struct {
	uint32_t unknown11;			// 0x7
	uint32_t unknown12;			// 0x18
	uint32_t unknown13;			// 0x0
	uint32_t unknown14;			// 0x0

	uint8_t qa_digest[0x10];

	uint32_t unknown31;			// 0x8
	uint32_t unknown32;			// 0x8
	uint8_t pkg_flags;			// 0x85? 0x81?
	uint8_t fw_major;
	uint16_t fw_minor;
	uint16_t pkg_version;
	uint16_t app_version;

	uint32_t unknown41;			// 0x9
	uint32_t unknown42;			// 0x8
	uint32_t unknown43;			// 0x0
	uint32_t unknown44;			// 0x0
} gpkg_einfo; // 64 bytes

typedef struct {
	uint32_t filename_offset;
	uint32_t filename_size;
	uint64_t data_offset;
	uint64_t data_size;
	uint32_t flags;				// 0x80000000 (overwrite), 0x3 (file), 0x4 (dir)
	uint32_t padding;
} gpkg_file; // 32 bytes

typedef struct {
	uint8_t data_sha1[0x20];	// sha1_digest of everything above
} gpkg_footer; // 32 bytes
