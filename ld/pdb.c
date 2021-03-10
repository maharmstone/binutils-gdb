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
#include "coff/i386.h"
#include "coff/external.h"
#include "coff/internal.h"
#include "libcoff.h"
#include "ld.h"
#include "ldmisc.h"

struct pdb_string *strings = NULL;
unsigned int strings_buf_len = 0;

uint32_t
calc_hash(const uint8_t* data, size_t len) {
  uint32_t hash = 0;

  while (len >= 4) {
    hash ^= bfd_getl32(data);
    data += 4;
    len -= 4;
  }

  if (len >= 2) {
    hash ^= bfd_getl16(data);
    data += 2;
    len -= 2;
  }

  if (len != 0)
    hash ^= *data;

  hash |= 0x20202020;
  hash ^= (hash >> 11);

  return hash ^ (hash >> 16);
}

void
init_hash_list (struct pdb_hash_list *list, unsigned int num_buckets)
{
  list->num_buckets = num_buckets;

  list->buckets = xmalloc (sizeof (struct pdb_hash_entry*) * num_buckets);
  memset(list->buckets, 0, sizeof (struct pdb_hash_entry*) * num_buckets);

  list->first = NULL;
}

static void
init_rollover_hash_list (struct pdb_rollover_hash_list *list, unsigned int num_buckets)
{
  list->num_buckets = num_buckets;

  list->buckets = xmalloc (sizeof (struct pdb_hash_entry*) * num_buckets);
  memset(list->buckets, 0, sizeof (struct pdb_hash_entry*) * num_buckets);
}

void
free_hash_list (struct pdb_hash_list *list)
{
  while (list->first) {
    struct pdb_hash_entry *ent = list->first;

    list->first = ent->next;

    free(ent);
  }

  free(list->buckets);
}

static void
free_rollover_hash_list (struct pdb_rollover_hash_list *list)
{
  for (unsigned int i = 0; i < list->num_buckets; i++) {
    if (list->buckets[i])
      free (list->buckets[i]);
  }

  free(list->buckets);
}

void
add_hash_entry (struct pdb_hash_list *list, struct pdb_hash_entry *ent)
{
  ent->hash %= list->num_buckets;

  // bucket already filled - place entry after existing one

  if (list->buckets[ent->hash]) {
    struct pdb_hash_entry *ent2 = list->buckets[ent->hash];

    // check for dupes
    while (ent2 && ent2->hash == ent->hash) {
      if (ent->length == ent2->length && !memcmp(ent->data, ent2->data, ent->length)) {
	free(ent);
	return;
      }

      ent2 = ent2->next;
    }

    ent->prev = list->buckets[ent->hash];
    ent->next = list->buckets[ent->hash]->next;
    list->buckets[ent->hash]->next = ent;

    if (ent->next)
      ent->next->prev = ent;

    return;
  }

  // bucket not filled - find preceding entry

  if (ent->hash > 0) {
    uint32_t hash = ent->hash - 1;

    while (1) {
      if (list->buckets[hash]) {
	ent->prev = list->buckets[hash];

	while (ent->prev->next && ent->prev->next->hash == ent->prev->hash) {
	  ent->prev = ent->prev->next;
	}

	ent->next = ent->prev->next;
	ent->prev->next = ent;

	if (ent->next)
	  ent->next->prev = ent;

	list->buckets[ent->hash] = ent;

	return;
      }

      if (hash == 0)
	break;

      hash--;
    }
  }

  // place entry at head of list

  ent->next = list->first;

  if (ent->next)
    ent->next->prev = ent;

  list->first = ent;
  list->buckets[ent->hash] = ent;
}

static void
add_rollover_hash_entry (struct pdb_rollover_hash_list *list, struct pdb_rollover_hash_entry *ent)
{
  ent->hash %= list->num_buckets;

  if (list->buckets[ent->hash]) {
    uint32_t hash = ent->hash;

    while (list->buckets[hash]) {
      // check for dupe
      if (ent->length == list->buckets[hash]->length && !memcmp(ent->data, list->buckets[hash]->data, ent->length)) {
	free(ent);
	return;
      }

      hash = (hash + 1) % list->num_buckets;
    }

    list->buckets[hash] = ent;
  } else
    list->buckets[ent->hash] = ent;
}

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
add_stream (struct pdb_context *ctx, const char *name)
{
  struct pdb_stream *stream = xmalloc(sizeof(struct pdb_stream));

  memset(stream, 0, sizeof(struct pdb_stream));

  stream->index = ctx->num_streams;

  if (name)
    stream->name = xstrdup(name);

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

    if (ctx->first_stream->name)
      free(ctx->first_stream->name);

    free(ctx->first_stream);
    ctx->first_stream = stream;
  }
}

static void
create_pdb_info_stream (struct pdb_context *ctx, struct pdb_stream *stream, const unsigned char *guid)
{
  struct pdb_stream *s;
  uint32_t named_stream_buf_len = 0, hash_size = 0, num_buckets, buf_pos;
  uint8_t *ptr;
  struct pdb_rollover_hash_list named_stream_hash_list;

  stream->length = 28; // header
  stream->length += sizeof(uint32_t); // named stream map length
  stream->length += sizeof(uint32_t) * 4; // for hash map
  stream->length += sizeof(uint32_t); // after hash map
  stream->length += sizeof(uint32_t); // feature code

  s = ctx->first_stream;
  while (s) {
    if (s->name)
      hash_size++;

    s = s->next;
  }

  num_buckets = hash_size * 2;

  init_rollover_hash_list(&named_stream_hash_list, num_buckets);

  s = ctx->first_stream;
  buf_pos = 0;
  while (s) {
    if (s->name) {
      size_t name_len = strlen(s->name);
      struct pdb_rollover_hash_entry *ent;
      struct pdb_named_stream_entry *pnse;

      ent = xmalloc(offsetof(struct pdb_rollover_hash_entry, data) + sizeof(struct pdb_named_stream_entry));

      ent->hash = calc_hash((const uint8_t*)s->name, name_len);
      ent->length = sizeof(struct pdb_named_stream_entry);

      pnse = (struct pdb_named_stream_entry*)ent->data;
      bfd_putl32(buf_pos, &pnse->offset);
      bfd_putl32(s->index, &pnse->stream);

      add_rollover_hash_entry (&named_stream_hash_list, ent);

      named_stream_buf_len += name_len + 1;
      buf_pos += name_len + 1;
     }

     s = s->next;
  }

  stream->length += named_stream_buf_len;
  stream->length += ((hash_size + 31) / 32) * sizeof(uint32_t); // present bitmap
  stream->length += hash_size * sizeof(struct pdb_named_stream_entry);

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

  bfd_putl32 (named_stream_buf_len, ptr);
  ptr += sizeof(uint32_t);

  s = ctx->first_stream;
  while (s) {
    if (s->name) {
      size_t len = strlen(s->name);

      memcpy(ptr, s->name, len);
      ptr += len + 1;
    }

    s = s->next;
  }

  // hash map

  bfd_putl32 (hash_size, ptr);
  ptr += sizeof(uint32_t);

  bfd_putl32 (num_buckets, ptr);
  ptr += sizeof(uint32_t);

  bfd_putl32 ((num_buckets + 31) / 32, ptr); // present bitmap length
  ptr += sizeof(uint32_t);

  for (unsigned int i = 0; i < num_buckets; i += 32) {
    uint32_t v = 0;

    for (unsigned int j = 0; j < 8; j++) {
      if (i + j >= num_buckets)
	break;

      v <<= 1;

      if (named_stream_hash_list.buckets[i + j])
	v |= 1;
    }

    bfd_putl32 (v, ptr);
    ptr += sizeof(uint32_t);
  }

  bfd_putl32 (0, ptr); // deleted bitmap length
  ptr += sizeof(uint32_t);

  for (unsigned int i = 0; i < named_stream_hash_list.num_buckets; i++) {
    if (named_stream_hash_list.buckets[i]) {
      memcpy(ptr, named_stream_hash_list.buckets[i]->data, named_stream_hash_list.buckets[i]->length);
      ptr += named_stream_hash_list.buckets[i]->length;
    }
  }

  ptr += sizeof(uint32_t);

  bfd_putl32 (pdb_feature_code_vc110, ptr);

  free_rollover_hash_list(&named_stream_hash_list);
}

unsigned int
add_pdb_string (const char *str)
{
  size_t len = strlen(str);
  uint32_t hash = calc_hash((const uint8_t*)str, len);
  struct pdb_string *s = strings, *prev = NULL;

  while (s) {
    if (s->hash == hash && !strcmp(s->string, str))
      return s->offset;

    if (s->hash > hash)
      break;

    prev = s;
    s = s->next;
  }

  s = (struct pdb_string*)xmalloc(offsetof(struct pdb_string, string) + len + 1);

  s->offset = strings_buf_len;
  s->hash = hash;
  memcpy(s->string, str, len + 1);

  if (!prev) {
    s->next = strings;
    strings = s;
  } else {
    s->next = prev->next;
    prev->next = s;
  }

  strings_buf_len += len + 1;

  return s->offset;
}

static void
populate_names_stream (struct pdb_stream *stream)
{
  struct pdb_string *s;
  struct pdb_names_stream_header *h;
  unsigned int num_strings = 0, num_buckets;
  uint8_t *buf;
  uint32_t *num_buckets_ptr, *buckets;
  struct pdb_rollover_hash_list hash_list;

  s = strings;
  while (s) {
    num_strings++;
    s = s->next;
  }

  num_buckets = num_strings * 2;

  stream->length = sizeof(struct pdb_names_stream_header) + strings_buf_len + sizeof(uint32_t) +
		   (num_buckets * sizeof(uint32_t)) + sizeof(uint32_t);
  stream->data = xmalloc(stream->length);

  h = (struct pdb_names_stream_header*)stream->data;

  bfd_putl32(NAMES_STREAM_SIGNATURE, &h->signature);
  bfd_putl32(NAMES_STREAM_VERSION, &h->version);
  bfd_putl32(strings_buf_len, &h->buf_len);

  buf = (uint8_t*)&h[1];

  init_rollover_hash_list (&hash_list, num_buckets);

  s = strings;
  while (s) {
    struct pdb_rollover_hash_entry *ent;

    memcpy(buf + s->offset, s->string, strlen(s->string) + 1);

    ent = xmalloc(offsetof(struct pdb_rollover_hash_entry, data) + sizeof(uint32_t));

    ent->hash = s->hash;
    ent->length = sizeof(uint32_t);
    *(uint32_t*)ent->data = s->offset;

    add_rollover_hash_entry(&hash_list, ent);

    s = s->next;
  }

  num_buckets_ptr = (uint32_t*)((uint8_t*)h + sizeof(struct pdb_names_stream_header) + strings_buf_len);
  bfd_putl32(num_buckets, num_buckets_ptr);

  buckets = num_buckets_ptr + 1;

  memset(buckets, 0, sizeof(uint32_t) * num_buckets);

  for (unsigned int i = 0; i < hash_list.num_buckets; i++) {
    if (hash_list.buckets[i])
      bfd_putl32(*(uint32_t*)hash_list.buckets[i]->data, &buckets[i]);
  }

  while (strings) {
    s = strings->next;
    free(strings);
    strings = s;
  }

  bfd_putl32(num_strings, &buckets[num_buckets]);

  free_rollover_hash_list (&hash_list);
}

void
create_pdb_file(bfd *abfd, const char *pdb_path, const unsigned char *guid)
{
  struct pdb_context ctx;
  struct pdb_stream *pdb_info_stream, *tpi_stream, *dbi_stream, *ipi_stream,
		    *names_stream;
  unsigned int num_modules = 0;
  bfd *in_bfd;
  struct pdb_mod_type_info *type_info;
  struct pdb_superblock super;

  in_bfd = abfd->tdata.coff_obj_data->link_info->input_bfds;

  while (in_bfd) {
    num_modules++;
    in_bfd = in_bfd->link.next;
  }

  if (num_modules == 0)
    return;

  memset(&ctx, 0, sizeof(struct pdb_context));

  ctx.abfd = abfd;
  ctx.fd = open (pdb_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);

  if (ctx.fd == -1)
      einfo (_("%F%P: cannot open output file %s: %E\n"), pdb_path);

  ctx.num_blocks = 3; // for superblock and two free block maps

  add_stream(&ctx, NULL); // old directory (FIXME?)

  add_stream(&ctx, NULL);
  pdb_info_stream = ctx.last_stream;

  add_stream(&ctx, NULL);
  tpi_stream = ctx.last_stream;

  add_stream(&ctx, NULL);
  dbi_stream = ctx.last_stream;

  add_stream(&ctx, NULL);
  ipi_stream = ctx.last_stream;

  add_stream(&ctx, "/LinkInfo");

  add_stream(&ctx, "/names");
  names_stream = ctx.last_stream;
  add_pdb_string("");

  create_pdb_info_stream(&ctx, pdb_info_stream, guid);

  type_info = xmalloc(num_modules * sizeof(struct pdb_mod_type_info));

  create_tpi_stream(&ctx, tpi_stream, ipi_stream, type_info);

  create_dbi_stream(&ctx, dbi_stream);

  free(type_info);

  populate_names_stream(names_stream);

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
