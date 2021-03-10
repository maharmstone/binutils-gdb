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

#define PDB_OPTIONAL_SECTION_STREAM 5

#define BYTES_TO_PAGES(b) (((b) + PDB_BLOCK_SIZE - 1) / PDB_BLOCK_SIZE)

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
void create_tpi_stream (struct pdb_context *ctx, struct pdb_stream *stream);

#endif /* _PDB_H */
