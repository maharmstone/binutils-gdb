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

#define PDB_MAGIC "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\0\0"
#define PDB_BLOCK_SIZE 0x1000

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
  uint32_t length;
  void *data;
};

struct pdb_context {
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

// pdb.c
void create_pdb_file(bfd *abfd, const char *pdb_path, const unsigned char *guid);

#endif /* _PDB_H */
