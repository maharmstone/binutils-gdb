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

void
create_tpi_stream (struct pdb_context *ctx, struct pdb_stream *stream)
{
  struct tpi_stream_header *h;

  stream->length = sizeof(struct tpi_stream_header);
  stream->data = xmalloc(stream->length);

  h = (struct tpi_stream_header*)stream->data;

  // FIXME - populate with real type data from gcc files - will need to merge dupes

  bfd_putl32(tpi_stream_version_v80, &h->version);
  bfd_putl32(sizeof(struct tpi_stream_header), &h->header_size);
  bfd_putl32(FIRST_TYPE_INDEX, &h->type_index_begin);
  bfd_putl32(FIRST_TYPE_INDEX, &h->type_index_end); // FIXME
  bfd_putl32(0, &h->type_record_bytes);

  bfd_putl16(ctx->num_streams, &h->hash_stream_index);
  add_stream(ctx, NULL);

  bfd_putl16(0xfffff, &h->hash_aux_stream_index);
  bfd_putl32(sizeof(uint32_t), &h->hash_key_size);
  bfd_putl32(0, &h->num_hash_buckets);
  bfd_putl32(0, &h->hash_value_buffer_offset);
  bfd_putl32(0, &h->hash_value_buffer_length);
  bfd_putl32(0, &h->index_offset_buffer_offset);
  bfd_putl32(0, &h->index_offset_buffer_length);
  bfd_putl32(0, &h->hash_adj_buffer_offset);
  bfd_putl32(0, &h->hash_adj_buffer_length);
}
