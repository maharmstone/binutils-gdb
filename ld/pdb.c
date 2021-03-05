/* Support for generating PDB CodeView debugging files.
   Copyright (C) 2021 Mark Harmstone

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

#include "pdb.h"
#include "ld.h"
#include "ldmisc.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "libiberty.h"

static void
write_stream_directory (struct pdb_context *ctx, void *directory)
{
  uint32_t num_directory_pages = BYTES_TO_PAGES(ctx->num_directory_bytes);
  uint32_t *block_map = xmalloc(sizeof(uint32_t) * num_directory_pages);
  uint32_t left = ctx->num_directory_bytes;

  /* Write stream directory */

  for (unsigned int i = 0; i < num_directory_pages; i++) {
    ssize_t to_write = left < PDB_BLOCK_SIZE ? left : PDB_BLOCK_SIZE;
    uint32_t block = ctx->num_blocks;

    bfd_putl32(block, &block_map[i]);

    ctx->num_blocks++;

    if (ftruncate(ctx->fd, PDB_BLOCK_SIZE * ctx->num_blocks))
      einfo (_("%F%P: error extending PDB file: %E\n"));

    lseek(ctx->fd, block * PDB_BLOCK_SIZE, SEEK_SET);
    if (write (ctx->fd, directory, to_write) != to_write)
      einfo (_("%F%P: error writing to PDB file: %E\n"));

    directory = (uint8_t*)directory + PDB_BLOCK_SIZE;
    left -= PDB_BLOCK_SIZE;
  }

  /* Allocate and write stream directory block map */

  ctx->block_map_addr = ctx->num_blocks;
  ctx->num_blocks++;

  if (ftruncate(ctx->fd, PDB_BLOCK_SIZE * ctx->num_blocks))
    einfo (_("%F%P: error extending PDB file: %E\n"));

  lseek(ctx->fd, ctx->block_map_addr * PDB_BLOCK_SIZE, SEEK_SET);

  if (write (ctx->fd, block_map, sizeof(uint32_t) * num_directory_pages) !=
      (ssize_t)(sizeof(uint32_t) * num_directory_pages)) {
    einfo (_("%F%P: error writing to PDB file: %E\n"));
  }

  free(block_map);
}

void
create_pdb_file(bfd *abfd, const char *pdb_path, const unsigned char *guid)
{
  struct pdb_context ctx;
  char *directory;
  struct pdb_superblock super;

  memset(&ctx, 0, sizeof(struct pdb_context));

  ctx.fd = open (pdb_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);

  if (ctx.fd == -1)
      einfo (_("%F%P: cannot open output file %s: %E\n"), pdb_path);

  ctx.num_blocks = 3; // for superblock and two free block maps

  // FIXME - write streams etc.

  // FIXME - prepare stream directory
  directory = strdup("test");
  ctx.num_directory_bytes = 4;

  // FIXME - return error if directory would contain too many blocks for one page

  write_stream_directory(&ctx, directory);

  /* Write superblock */
  memcpy(super.magic, PDB_MAGIC, sizeof(PDB_MAGIC));
  bfd_putl32(PDB_BLOCK_SIZE, &super.block_size);
  bfd_putl32(ctx.free_block_map, &super.free_block_map);
  bfd_putl32(ctx.num_blocks, &super.num_blocks);
  bfd_putl32(ctx.num_directory_bytes, &super.num_directory_bytes);
  bfd_putl32(0, &super.unknown);
  bfd_putl32(ctx.block_map_addr, &super.block_map_addr);
  // FIXME - free_block_map

  lseek(ctx.fd, 0, SEEK_SET);

  if (write (ctx.fd, &super, sizeof(super)) != sizeof(super))
    einfo (_("%F%P: error writing to PDB file: %E\n"));

  close(ctx.fd);
}
