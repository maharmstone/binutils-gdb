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
#include "coff/pe.h"

void
create_dbi_stream (struct pdb_context *ctx, struct pdb_stream *stream)
{
  struct dbi_stream_header *h;

  stream->length = sizeof(struct dbi_stream_header);
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
  bfd_putl32(0, &h->source_info_size); // FIXME
  bfd_putl32(0, &h->type_server_map_size);
  bfd_putl32(0, &h->mfc_type_server_index);
  bfd_putl32(0, &h->optional_dbg_header_size); // FIXME
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

  // FIXME - global stream
  // FIXME - public stream
  // FIXME - sym record stream

  // FIXME - module info
  // FIXME - section contribution
  // FIXME - section map
  // FIXME - source info
  // FIXME - optional debug header and streams
}
