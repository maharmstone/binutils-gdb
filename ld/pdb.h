/* Copyright (C) 2021 Mark Harmstone

   This file is part of the GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#ifndef _PDB_H
#define _PDB_H

#include "sysdep.h"
#include "bfd.h"
#include <assert.h>

#define PDB_MAGIC "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\0\0"
#define PDB_BLOCK_SIZE 0x1000
#define FIRST_TYPE_INDEX 0x1000

#define GSI_HASH_VERSION_V70 (0xeffe0000 + 19990810)

#define PDB_OPTIONAL_SECTION_STREAM 5

#define BYTES_TO_PAGES(b) (((b) + PDB_BLOCK_SIZE - 1) / PDB_BLOCK_SIZE)

#define CV_SIGNATURE_C13	4

#define CV_DEBUG_S_SYMBOLS		0xf1

#define S_LDATA32			0x110c
#define S_GDATA32			0x110d
#define S_PUB32				0x110e
#define S_LPROC32			0x110f
#define S_GPROC32			0x1110
#define S_PROCREF			0x1125
#define S_LPROCREF			0x1127
#define S_LPROC32_ID			0x1146
#define S_GPROC32_ID			0x1147
#define S_LPROC32_DPC			0x1155
#define S_LPROC32_DPC_ID		0x1156
#define LF_CLASS			0x1504
#define LF_STRUCTURE			0x1505
#define LF_UNION			0x1506
#define LF_ENUM				0x1507

struct pdb_superblock {
  char magic[sizeof(PDB_MAGIC)];
  uint32_t block_size;
  uint32_t free_block_map;
  uint32_t num_blocks;
  uint32_t num_directory_bytes;
  uint32_t unknown;
  uint32_t block_map_addr;
};

struct pdb_stream {
  struct pdb_stream *next;
  unsigned int index;
  char *name;
  uint32_t length;
  void *data;
};

struct pdb_context {
  bfd *abfd;
  int fd;
  uint32_t free_block_map;
  uint32_t num_blocks;
  uint32_t num_directory_bytes;
  uint32_t block_map_addr;
  struct pdb_stream *first_stream;
  struct pdb_stream *last_stream;
  unsigned int num_streams;
  char *directory;
};

enum pdb_stream_version {
  pdb_stream_version_vc2 = 19941610,
  pdb_stream_version_vc4 = 19950623,
  pdb_stream_version_vc41 = 19950814,
  pdb_stream_version_vc50 = 19960307,
  pdb_stream_version_vc98 = 19970604,
  pdb_stream_version_vc70dep = 19990604,
  pdb_stream_version_vc70 = 20000404,
  pdb_stream_version_vc80 = 20030901,
  pdb_stream_version_vc110 = 20091201,
  pdb_stream_version_vc140 = 20140508,
};

enum pdb_feature_code {
  pdb_feature_code_vc110 = 20091201,
  pdb_feature_code_vc140 = 20140508,
  pdb_feature_code_notypemerge = 0x4d544f4e,
  pdb_feature_code_minimaldebuginfo = 0x494e494d,
};

enum tpi_stream_version {
  tpi_stream_version_v40 = 19950410,
  tpi_stream_version_v41 = 19951122,
  tpi_stream_version_v50 = 19961031,
  tpi_stream_version_v70 = 19990903,
  tpi_stream_version_v80 = 20040203,
};

struct tpi_stream_header {
  uint32_t version;
  uint32_t header_size;
  uint32_t type_index_begin;
  uint32_t type_index_end;
  uint32_t type_record_bytes;
  uint16_t hash_stream_index;
  uint16_t hash_aux_stream_index;
  uint32_t hash_key_size;
  uint32_t num_hash_buckets;
  int32_t hash_value_buffer_offset;
  uint32_t hash_value_buffer_length;
  int32_t index_offset_buffer_offset;
  uint32_t index_offset_buffer_length;
  int32_t hash_adj_buffer_offset;
  uint32_t hash_adj_buffer_length;
};

static_assert(sizeof(struct tpi_stream_header) == 0x38, "tpi_stream_header has incorrect size");

enum dbi_stream_version {
  dbi_stream_version_vc41 = 930803,
  dbi_stream_version_v50 = 19960307,
  dbi_stream_version_v60 = 19970606,
  dbi_stream_version_v70 = 19990903,
  dbi_stream_version_v110 = 20091201
};

struct dbi_stream_header {
  int32_t version_signature;
  uint32_t version_header;
  uint32_t age;
  uint16_t global_stream_index;
  uint16_t build_number;
  uint16_t public_stream_index;
  uint16_t pdb_dll_version;
  uint16_t sym_record_stream;
  uint16_t pdb_dll_rbld;
  int32_t mod_info_size;
  int32_t section_contribution_size;
  int32_t section_map_size;
  int32_t source_info_size;
  int32_t type_server_map_size;
  uint32_t mfc_type_server_index;
  int32_t optional_dbg_header_size;
  int32_t ec_substream_size;
  uint16_t flags;
  uint16_t machine;
  uint32_t padding;
};

static_assert(sizeof(struct dbi_stream_header) == 0x40, "dbi_stream_header has incorrect size");

struct pdb_hash_entry {
  uint32_t hash;
  struct pdb_hash_entry *prev;
  struct pdb_hash_entry *next;
  uint32_t offset;
  uint32_t index;
  size_t length;
  uint8_t data[0];
};

struct pdb_hash_list {
  unsigned int num_buckets;
  struct pdb_hash_entry **buckets;
  struct pdb_hash_entry *first;
};

struct pdb_rollover_hash_entry {
  uint32_t hash;
  uint32_t offset;
  uint32_t index;
  size_t length;
  uint8_t data[0];
};

struct pdb_rollover_hash_list {
  unsigned int num_buckets;
  struct pdb_rollover_hash_entry **buckets;
};

struct gsi_header { // PSGSIHDR in cvdump
  uint32_t sym_hash_length;
  uint32_t addr_map_length;
  uint32_t num_thunks;
  uint32_t size_of_thunk;
  uint32_t section_thunk_table;
  uint32_t offset_thunk_table;
  uint32_t num_sections;
};

struct gsi_hash_header { // GSIHashHdr in cvdump
  uint32_t signature;
  uint32_t version;
  uint32_t data_length;
  uint32_t buckets_length;
};

struct hash_record_file { // HRFile in cvdump
  uint32_t offset;
  uint32_t ref;
};

struct section_contribution { // SC in cvdump
  uint16_t section;
  uint16_t padding1;
  uint32_t offset;
  uint32_t size;
  uint32_t characteristics;
  uint16_t module_index;
  uint16_t padding2;
  uint32_t data_crc;
  uint32_t reloc_crc;
};

struct module_info { // MODI_60_Persist in cvdump
  uint32_t unused1;
  struct section_contribution sc;
  uint16_t written : 1;
  uint16_t ec_enabled : 1;
  uint16_t unused2 : 6;
  uint16_t tsm : 8;
  uint16_t module_stream;
  uint32_t symbols_size;
  uint32_t lines_size;
  uint32_t c13_lines_size;
  uint16_t source_file_count;
  uint16_t padding;
  uint32_t unused3;
  uint32_t source_file_name_index;
  uint32_t pdb_file_name_index;
};

struct file_info_substream {
  uint16_t num_modules;
  uint16_t num_source_files;
};

enum section_contributions_version {
  section_contributions_version_ver60 = 0xeffe0000 + 19970605,
  section_contributions_version_v2 = 0xeffe0000 + 20140516
};

struct section_map_header {
  uint16_t count;
  uint16_t log_count;
};

struct section_map_entry {
  uint16_t flags;
  uint16_t ovl;
  uint16_t group;
  uint16_t frame;
  uint16_t section_name;
  uint16_t class_name;
  uint32_t offset;
  uint32_t section_length;
};

#define SECTION_MAP_ENTRY_FLAGS_READ		0x0001
#define SECTION_MAP_ENTRY_FLAGS_WRITE		0x0002
#define SECTION_MAP_ENTRY_FLAGS_EXECUTE		0x0004
#define SECTION_MAP_ENTRY_FLAGS_32BIT		0x0008
#define SECTION_MAP_ENTRY_FLAGS_SELECTOR	0x0100
#define SECTION_MAP_ENTRY_FLAGS_ABSOLUTE	0x0200
#define SECTION_MAP_ENTRY_FLAGS_GROUP		0x0400

struct pdb_type {
  struct pdb_type *next;
  uint16_t index;
  uint8_t data[1];
};

struct codeview_property { // CV_prop_t in cvdump
  union {
    uint16_t value;
    struct {
      uint16_t packed : 1;
      uint16_t ctor : 1;
      uint16_t ovlops : 1;
      uint16_t isnested : 1;
      uint16_t cnested : 1;
      uint16_t opassign : 1;
      uint16_t opcast : 1;
      uint16_t fwdref : 1;
      uint16_t scoped : 1;
      uint16_t hasuniquename : 1;
      uint16_t sealed : 1;
      uint16_t hfa : 2;
      uint16_t intrinsic : 1;
      uint16_t mocom : 2;
    };
  };
};

struct pdb_mod_type_info {
  uint16_t offset;
  unsigned int num_entries;
};

struct pdb_subsection {
  uint32_t type;
  uint32_t length;
};

struct pdb_named_stream_entry {
  uint32_t offset;
  uint32_t stream;
};

// pdb.c
void create_pdb_file(bfd *abfd, const char *pdb_path, const unsigned char *guid);
struct pdb_stream *add_stream (struct pdb_context *ctx, const char *name);
uint32_t calc_hash(const uint8_t* data, size_t len);
void add_hash_entry (struct pdb_hash_list *list, struct pdb_hash_entry *ent);
void init_hash_list (struct pdb_hash_list *list, unsigned int num_buckets);
void free_hash_list (struct pdb_hash_list *list);

// pdb-dbi.c
void create_dbi_stream (struct pdb_context *ctx, struct pdb_stream *stream);

// pdb-tpi.c
void create_tpi_stream (struct pdb_context *ctx, struct pdb_stream *stream,
			struct pdb_stream *ipi_stream, struct pdb_mod_type_info *type_info);

#endif /* _PDB_H */
