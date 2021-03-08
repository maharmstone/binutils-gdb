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
#include <time.h>
#include "libiberty.h"

static uint32_t
allocate_block (struct pdb_context *ctx)
{
  uint32_t block = ctx->num_blocks;

  // FIXME - avoid free page map

  ctx->num_blocks++;

  if (ftruncate(ctx->fd, PDB_BLOCK_SIZE * ctx->num_blocks))
    einfo (_("%F%P: error extending PDB file: %E\n"));

  return block;
}

static void
write_stream_directory (struct pdb_context *ctx)
{
  uint32_t num_directory_pages = BYTES_TO_PAGES(ctx->num_directory_bytes);
  uint32_t *block_map = xmalloc(sizeof(uint32_t) * num_directory_pages);
  uint32_t left = ctx->num_directory_bytes;
  void *directory = ctx->directory;

  /* Write stream directory */

  for (unsigned int i = 0; i < num_directory_pages; i++) {
    ssize_t to_write = left < PDB_BLOCK_SIZE ? left : PDB_BLOCK_SIZE;
    uint32_t block = allocate_block(ctx);

    bfd_putl32(block, &block_map[i]);

    lseek(ctx->fd, block * PDB_BLOCK_SIZE, SEEK_SET);
    if (write (ctx->fd, directory, to_write) != to_write)
      einfo (_("%F%P: error writing to PDB file: %E\n"));

    directory = (uint8_t*)directory + PDB_BLOCK_SIZE;
    left -= PDB_BLOCK_SIZE;
  }

  /* Allocate and write stream directory block map */

  ctx->block_map_addr = allocate_block(ctx);

  lseek(ctx->fd, ctx->block_map_addr * PDB_BLOCK_SIZE, SEEK_SET);

  if (write (ctx->fd, block_map, sizeof(uint32_t) * num_directory_pages) !=
      (ssize_t)(sizeof(uint32_t) * num_directory_pages)) {
    einfo (_("%F%P: error writing to PDB file: %E\n"));
  }

  free(block_map);
}

static void
write_free_page_map (struct pdb_context *ctx)
{
  uint32_t map[PDB_BLOCK_SIZE / sizeof(uint32_t)], *ptr;
  uint32_t blocks = ctx->num_blocks;

  // FIXME - handle large free page maps

  memset(map, 0xff, PDB_BLOCK_SIZE);

  ptr = map;
  while (blocks > 0) {
    if (blocks >= 32) {
      bfd_putl32(0, ptr);
      ptr++;
      blocks -= 32;
    } else {
      uint32_t bit = 1;
      uint32_t val = bfd_getl32(ptr);

      do {
	val &= ~bit;
	bit <<= 1;
	blocks--;
      } while (blocks > 0);

      bfd_putl32(val, ptr);

      break;
    }
  }

  lseek(ctx->fd, ctx->free_block_map * PDB_BLOCK_SIZE, SEEK_SET);

  if (write (ctx->fd, map, PDB_BLOCK_SIZE) != PDB_BLOCK_SIZE)
    einfo (_("%F%P: error writing to PDB file: %E\n"));
}

struct pdb_stream *
add_stream (struct pdb_context *ctx)
{
  struct pdb_stream *stream = xmalloc(sizeof(struct pdb_stream));

  memset(stream, 0, sizeof(struct pdb_stream));

  if (ctx->last_stream)
    ctx->last_stream->next = stream;

  ctx->last_stream = stream;

  if (!ctx->first_stream)
    ctx->first_stream = stream;

  ctx->num_streams++;

  return stream;
}

static void
prepare_stream_directory (struct pdb_context *ctx)
{
  struct pdb_stream *stream;
  uint32_t *sizes, *blocks;

  ctx->num_directory_bytes = sizeof(uint32_t) * (ctx->num_streams + 1);

  stream = ctx->first_stream;
  while (stream) {
    uint32_t pages = BYTES_TO_PAGES(stream->length);

    ctx->num_directory_bytes += pages * sizeof(uint32_t);

    stream = stream->next;
  }

  ctx->directory = xmalloc(ctx->num_directory_bytes);
  bfd_putl32(ctx->num_streams, ctx->directory);

  sizes = ((uint32_t*)ctx->directory) + 1;
  blocks = &sizes[ctx->num_streams];

  stream = ctx->first_stream;
  while (stream) {
    bfd_putl32(stream->length, sizes);
    sizes++;

    if (stream->length > 0) {
      uint32_t length = stream->length;
      uint8_t *buf = stream->data;

      while (length > 0) {
	uint32_t block = allocate_block(ctx);
	ssize_t to_write = length < PDB_BLOCK_SIZE ? length : PDB_BLOCK_SIZE;

	lseek(ctx->fd, block * PDB_BLOCK_SIZE, SEEK_SET);
	if (write (ctx->fd, buf, to_write) != to_write)
	  einfo (_("%F%P: error writing to PDB file: %E\n"));

	bfd_putl32(block, blocks);
	blocks++;

	if (length <= PDB_BLOCK_SIZE)
	  break;

	length -= PDB_BLOCK_SIZE;
	buf += PDB_BLOCK_SIZE;
      }
    }

    stream = stream->next;
  }

  // FIXME - return error if directory would contain too many blocks for one page

  while (ctx->first_stream) {
    stream = ctx->first_stream->next;

    if (ctx->first_stream->data)
      free(ctx->first_stream->data);

    free(ctx->first_stream);
    ctx->first_stream = stream;
  }
}

static void
create_pdb_info_stream (struct pdb_stream *stream, const unsigned char *guid)
{
  uint32_t *feature_code;
  uint8_t *ptr;

  stream->length = 28; // header
  stream->length += sizeof(uint32_t); // named stream map length
  stream->length += sizeof(uint32_t) * 5; // empty hash map
  stream->length += sizeof(uint32_t); // feature code

  stream->data = xmalloc(stream->length);
  memset(stream->data, 0, stream->length);

  ptr = (uint8_t*)stream->data;

  bfd_putl32 (pdb_stream_version_vc70, ptr); ptr += sizeof(uint32_t); // version
  bfd_putl32 (time(NULL), ptr); ptr += sizeof(uint32_t); // signature
  bfd_putl32 (1, ptr); ptr += sizeof(uint32_t); // age

  // guid
  bfd_putl32 (bfd_getb32 (guid), ptr); ptr += sizeof(uint32_t);
  bfd_putl16 (bfd_getb16 (&guid[4]), ptr); ptr += sizeof(uint16_t);
  bfd_putl16 (bfd_getb16 (&guid[6]), ptr); ptr += sizeof(uint16_t);
  memcpy (ptr, &guid[8], 8); ptr += 8;

  // FIXME - named stream map

  feature_code = (uint32_t*)((uint8_t*)stream->data + stream->length - sizeof(uint32_t));
  bfd_putl32 (pdb_feature_code_vc110, feature_code);
}

void
create_pdb_file(bfd *abfd, const char *pdb_path, const unsigned char *guid)
{
  struct pdb_context ctx;
  struct pdb_stream *pdb_info_stream, *tpi_stream, *dbi_stream, *ipi_stream;
  struct pdb_superblock super;

  memset(&ctx, 0, sizeof(struct pdb_context));

  ctx.fd = open (pdb_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);

  if (ctx.fd == -1)
      einfo (_("%F%P: cannot open output file %s: %E\n"), pdb_path);

  ctx.num_blocks = 3; // for superblock and two free block maps

  // FIXME - write streams etc.

  add_stream(&ctx); // old directory (FIXME?)

  add_stream(&ctx);
  pdb_info_stream = ctx.last_stream;

  add_stream(&ctx);
  tpi_stream = ctx.last_stream;

  add_stream(&ctx);
  dbi_stream = ctx.last_stream;

  add_stream(&ctx);
  ipi_stream = ctx.last_stream;

  // FIXME - named streams?

  create_pdb_info_stream(pdb_info_stream, guid);

  create_tpi_stream(&ctx, tpi_stream);

  prepare_stream_directory(&ctx);

  write_stream_directory(&ctx);

  free(ctx.directory);

  ctx.free_block_map = 1;
  write_free_page_map(&ctx);

  /* Write superblock */
  memcpy(super.magic, PDB_MAGIC, sizeof(PDB_MAGIC));
  bfd_putl32(PDB_BLOCK_SIZE, &super.block_size);
  bfd_putl32(ctx.free_block_map, &super.free_block_map);
  bfd_putl32(ctx.num_blocks, &super.num_blocks);
  bfd_putl32(ctx.num_directory_bytes, &super.num_directory_bytes);
  bfd_putl32(0, &super.unknown);
  bfd_putl32(ctx.block_map_addr, &super.block_map_addr);

  lseek(ctx.fd, 0, SEEK_SET);

  if (write (ctx.fd, &super, sizeof(super)) != sizeof(super))
    einfo (_("%F%P: error writing to PDB file: %E\n"));

  close(ctx.fd);
}
