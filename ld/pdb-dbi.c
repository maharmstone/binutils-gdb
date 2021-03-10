/* Support for generating module information in PDB files.
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

static void
create_section_stream(struct pdb_context *ctx, struct pdb_stream *stream)
{
  file_ptr scn_base;

  stream->length = ctx->abfd->section_count * sizeof(struct external_scnhdr);
  stream->data = xmalloc(stream->length);

  // copy section table from output - it's already been written at this point

  scn_base = bfd_coff_filhsz(ctx->abfd) + bfd_coff_aoutsz(ctx->abfd);

  bfd_seek(ctx->abfd, scn_base, SEEK_SET);
  bfd_bread(stream->data, stream->length, ctx->abfd);
}

static void
create_optional_dbg_header(struct pdb_context *ctx, void **data, uint32_t *size)
{
  uint16_t *arr;

  *size = sizeof(uint16_t) * 11;
  *data = xmalloc(*size);
  arr = (uint16_t*)*data;

  memset(arr, 0xff, *size);

  bfd_putl16(ctx->num_streams, &arr[PDB_OPTIONAL_SECTION_STREAM]);
  add_stream(ctx, NULL);

  create_section_stream(ctx, ctx->last_stream);
}

static void
create_file_info_substream(void **data, uint32_t *length)
{
  // FIXME - do this properly

  *length = sizeof(uint32_t);
  *data = xmalloc(*length);

  memset(*data, 0, *length);
}

void
create_dbi_stream (struct pdb_context *ctx, struct pdb_stream *stream)
{
  struct dbi_stream_header *h;
  void *optional_dbg_header = NULL, *file_info = NULL;
  uint32_t optional_dbg_header_size = 0, file_info_size = 0;
  uint8_t *ptr;

  create_optional_dbg_header(ctx, &optional_dbg_header, &optional_dbg_header_size);

  create_file_info_substream(&file_info, &file_info_size);

  stream->length = sizeof(struct dbi_stream_header) + optional_dbg_header_size +
		   file_info_size;
  stream->data = xmalloc(stream->length);

  h = (struct dbi_stream_header*)stream->data;

  bfd_putl32(0xffffffff, &h->version_signature);
  bfd_putl32(dbi_stream_version_v70, &h->version_header);
  bfd_putl32(1, &h->age);
  bfd_putl16(0xffff, &h->global_stream_index); // FIXME
  bfd_putl16(0x8a0a, &h->build_number); // claim to be MSVC 10.10
  bfd_putl16(0xffff, &h->public_stream_index); // FIXME
  bfd_putl16(0, &h->pdb_dll_version);
  bfd_putl16(0xffff, &h->sym_record_stream); // FIXME
  bfd_putl16(0, &h->pdb_dll_rbld);
  bfd_putl32(0, &h->mod_info_size); // FIXME
  bfd_putl32(0, &h->section_contribution_size); // FIXME
  bfd_putl32(0, &h->section_map_size); // FIXME
  bfd_putl32(file_info_size, &h->source_info_size);
  bfd_putl32(0, &h->type_server_map_size);
  bfd_putl32(0, &h->mfc_type_server_index);
  bfd_putl32(optional_dbg_header_size, &h->optional_dbg_header_size);
  bfd_putl32(0, &h->ec_substream_size);
  bfd_putl16(0, &h->flags);

  if (ctx->abfd->arch_info->arch == bfd_arch_i386) {
    if (ctx->abfd->arch_info->bits_per_address == 64)
      bfd_putl16(IMAGE_FILE_MACHINE_AMD64, &h->machine);
    else
      bfd_putl16(IMAGE_FILE_MACHINE_I386, &h->machine);
  } else
    bfd_putl16(0, &h->machine);

  bfd_putl32(0, &h->padding);

  ptr = (uint8_t*)stream->data + sizeof(struct dbi_stream_header);

  // FIXME - global stream
  // FIXME - public stream
  // FIXME - sym record stream

  // FIXME - module info
  // FIXME - section contribution
  // FIXME - section map

  if (file_info) {
    memcpy(ptr, file_info, file_info_size);
    ptr += file_info_size;
    free(file_info);
  }

  if (optional_dbg_header) {
    memcpy(ptr, optional_dbg_header, optional_dbg_header_size);
    free(optional_dbg_header);
  }
}
