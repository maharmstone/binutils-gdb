/* Support for generating type database in PDB files.
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
#include "libiberty.h"
#include "coff/i386.h"
#include "coff/external.h"
#include "coff/internal.h"
#include "coff/pe.h"
#include "libcoff.h"

struct pdb_type *types = NULL, *last_type = NULL;
uint16_t type_index = FIRST_TYPE_INDEX;

static void
load_module_types (bfd *in_bfd)
{
  struct bfd_section *sect, *pdb_sect = NULL;
  bfd_byte *contents = NULL;
  uint8_t *ptr;
  uint32_t len;

  sect = in_bfd->sections;
  while (sect) {
    if (!strcmp(sect->name, ".debug$T")) {
      pdb_sect = sect;
      break;
    }

    sect = sect->next;
  }

  if (!pdb_sect)
    return;

  if (!bfd_get_full_section_contents (in_bfd, pdb_sect, &contents))
    return;

  if (!contents)
    return;

  if (bfd_getl32((uint32_t*)contents) != CV_SIGNATURE_C13) {
    free(contents);
    return;
  }

  len = pdb_sect->size - sizeof(uint32_t);
  ptr = (uint8_t*)contents + sizeof(uint32_t);

  while (len >= 4) {
    uint16_t cv_length = bfd_getl16(ptr);
    struct pdb_type *t;

    if (len < sizeof(uint16_t) + cv_length)
      break;

    t = (struct pdb_type*)xmalloc(offsetof(struct pdb_type, data) + sizeof(uint16_t) + cv_length);

    t->next = NULL;
    t->index = type_index;
    memcpy(t->data, ptr, sizeof(uint16_t) + cv_length);

    if (last_type)
      last_type->next = t;

    last_type = t;

    if (!types)
      types = t;

    ptr += sizeof(uint16_t) + cv_length;
    len -= sizeof(uint16_t) + cv_length;
    type_index++;
  }

  free(contents);
}

static void
create_type_hash_stream (struct pdb_stream *stream, struct pdb_type *type_list,
			 uint32_t *hash_value_buffer_length, uint32_t *index_offset_buffer_length)
{
  struct pdb_type *t;
  unsigned int num_types = 0, index_entries;
  uint32_t *ptr;

  index_entries = 1; // FIXME - calculate

  t = type_list;
  while (t) {
    num_types++;

    t = t->next;
  }

  *hash_value_buffer_length = sizeof(uint32_t) * num_types;
  *index_offset_buffer_length = (sizeof(uint32_t) + sizeof(uint32_t)) * index_entries;

  stream->length = *hash_value_buffer_length + *index_offset_buffer_length;
  stream->data = xmalloc(stream->length);

  ptr = stream->data;

  t = type_list;
  while (t) {
    *ptr = 0; // FIXME - calculate hash

    t = t->next;
    ptr++;
  }

  // FIXME - index offset list
  bfd_putl32(FIRST_TYPE_INDEX, ptr); ptr++;
  bfd_putl32(0, ptr); ptr++;
}

void
create_tpi_stream (struct pdb_context *ctx, struct pdb_stream *stream)
{
  struct tpi_stream_header *h;
  bfd *in_bfd;
  uint32_t len;
  struct pdb_type *t;
  uint8_t *ptr;
  uint32_t hash_value_buffer_length, index_offset_buffer_length;

  in_bfd = ctx->abfd->tdata.coff_obj_data->link_info->input_bfds;

  while (in_bfd) {
    load_module_types(in_bfd);

    in_bfd = in_bfd->link.next;
  }

  len = 0;

  t = types;
  while (t) {
    uint16_t cv_length = bfd_getl16(t->data);

    len += cv_length + sizeof(uint16_t);

    t = t->next;
  }

  stream->length = sizeof(struct tpi_stream_header) + len;
  stream->data = xmalloc(stream->length);

  h = (struct tpi_stream_header*)stream->data;

  // FIXME - populate with real type data from gcc files - will need to merge dupes

  bfd_putl32(tpi_stream_version_v80, &h->version);
  bfd_putl32(sizeof(struct tpi_stream_header), &h->header_size);
  bfd_putl32(FIRST_TYPE_INDEX, &h->type_index_begin);
  bfd_putl32(type_index, &h->type_index_end);
  bfd_putl32(len, &h->type_record_bytes);

  bfd_putl16(ctx->num_streams, &h->hash_stream_index);
  add_stream(ctx, NULL);
  create_type_hash_stream(ctx->last_stream, types, &hash_value_buffer_length,
			  &index_offset_buffer_length);

  bfd_putl16(0xfffff, &h->hash_aux_stream_index);
  bfd_putl32(sizeof(uint32_t), &h->hash_key_size);
  bfd_putl32(0x3ffff, &h->num_hash_buckets);
  bfd_putl32(0, &h->hash_value_buffer_offset);
  bfd_putl32(hash_value_buffer_length, &h->hash_value_buffer_length);
  bfd_putl32(hash_value_buffer_length, &h->index_offset_buffer_offset);
  bfd_putl32(index_offset_buffer_length, &h->index_offset_buffer_length);
  bfd_putl32(hash_value_buffer_length + index_offset_buffer_length, &h->hash_adj_buffer_offset);
  bfd_putl32(0, &h->hash_adj_buffer_length);

  ptr = (uint8_t*)&h[1];

  while (types) {
    uint16_t cv_length = bfd_getl16(types->data);
    struct pdb_type *n = types->next;

    memcpy(ptr, types->data, cv_length + sizeof(uint16_t));

    ptr += cv_length + sizeof(uint16_t);

    free(types);

    types = n;
  }
}
