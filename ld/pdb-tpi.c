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
#include <stdbool.h>

#define NUM_TPI_HASH_BUCKETS 0x3ffff

struct pdb_type *types = NULL, *last_type = NULL;
uint16_t type_index = FIRST_TYPE_INDEX;

static const uint32_t crc_table[] = {
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
  0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
  0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
  0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
  0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
  0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
  0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
  0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
  0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
  0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
  0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
  0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
  0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
  0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
  0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
  0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
  0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
  0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
  0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
  0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
  0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
  0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
  0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
  0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
  0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
  0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
  0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
  0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
  0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

static uint32_t
crc32 (uint8_t *data, size_t len)
{
  uint32_t crc = 0;

  while (len > 0) {
    crc = (crc >> 8) ^ crc_table[(crc & 0xff) ^ *data];

    data++;
    len--;
  }

  return crc;
}

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

static bool
is_name_anonymous (const char *name)
{
  size_t len;

  // see fUDTAnon in cvdump

  static const char un1[] = "::<unnamed-tag>";
  static const char un2[] = "::__unnamed";

  if (!strcmp(name, "<unnamed-tag>") || !strcmp(name, "__unnamed"))
    return true;

  len = strlen(name);

  if (len >= sizeof(un1) - 1 && !memcmp(name + len - sizeof(un1) + 1, un1, sizeof(un1) - 1))
    return true;

  if (len >= sizeof(un2) - 1 && !memcmp(name + len - sizeof(un2) + 1, un1, sizeof(un2) - 1))
    return true;

  return false;
}

static void
create_type_hash_stream (struct pdb_stream *stream, unsigned int num_types,
			 uint32_t *hash_value_buffer_length, uint32_t *index_offset_buffer_length,
			 uint8_t *data, size_t len)
{
  unsigned int index_entries;
  uint32_t *ptr;

  index_entries = 1; // FIXME - calculate

  *hash_value_buffer_length = sizeof(uint32_t) * num_types;
  *index_offset_buffer_length = (sizeof(uint32_t) + sizeof(uint32_t)) * index_entries;

  stream->length = *hash_value_buffer_length + *index_offset_buffer_length;
  stream->data = xmalloc(stream->length);

  ptr = stream->data;

  while (len >= 4) {
    bool other_hash = false;
    uint16_t record_length, record_type;
    uint32_t hash;

    record_length = bfd_getl16(data);
    record_type = bfd_getl16(data + sizeof(uint16_t));

    switch (record_type) {
      case LF_CLASS:
      case LF_STRUCTURE:
      {
	struct codeview_property prop;

	prop.value = bfd_getl16(data + 6);

	if (!prop.fwdref && !prop.scoped) {
	  const char *name = (const char*)(data + 22);

	  if (!is_name_anonymous(name)) {
	    hash = calc_hash((const uint8_t*)name, strlen(name));
	    other_hash = true;
	  }
	}

	break;
      }

      case LF_UNION:
      {
	struct codeview_property prop;

	prop.value = bfd_getl16(data + 6);

	if (!prop.fwdref && !prop.scoped) {
	  const char *name = (const char*)(data + 14);

	  if (!is_name_anonymous(name)) {
	    hash = calc_hash((const uint8_t*)name, strlen(name));
	    other_hash = true;
	  }
	}

	break;
      }

      case LF_ENUM:
      {
	struct codeview_property prop;

	prop.value = bfd_getl16(data + 6);

	if (!prop.fwdref && !prop.scoped) {
	  const char *name = (const char*)(data + 16);

	  if (!is_name_anonymous(name)) {
	    hash = calc_hash((const uint8_t*)name, strlen(name));
	    other_hash = true;
	  }
	}

	break;
      }
    }

    if (!other_hash)
      hash = crc32(data, record_length + sizeof(uint16_t));

    hash %= NUM_TPI_HASH_BUCKETS;

    bfd_putl32(hash, ptr);

    len -= record_length + sizeof(uint16_t);
    data += record_length + sizeof(uint16_t);
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
  struct pdb_stream *hash_stream;
  unsigned int num_types;

  in_bfd = ctx->abfd->tdata.coff_obj_data->link_info->input_bfds;

  while (in_bfd) {
    load_module_types(in_bfd);

    in_bfd = in_bfd->link.next;
  }

  len = 0;
  num_types = 0;

  t = types;
  while (t) {
    uint16_t cv_length = bfd_getl16(t->data);

    num_types++;
    len += cv_length + sizeof(uint16_t);

    t = t->next;
  }

  stream->length = sizeof(struct tpi_stream_header) + len;
  stream->data = xmalloc(stream->length);

  h = (struct tpi_stream_header*)stream->data;

  bfd_putl32(tpi_stream_version_v80, &h->version);
  bfd_putl32(sizeof(struct tpi_stream_header), &h->header_size);
  bfd_putl32(FIRST_TYPE_INDEX, &h->type_index_begin);
  bfd_putl32(FIRST_TYPE_INDEX + num_types, &h->type_index_end);
  bfd_putl32(len, &h->type_record_bytes);

  bfd_putl16(ctx->num_streams, &h->hash_stream_index);
  add_stream(ctx, NULL);
  hash_stream = ctx->last_stream;

  bfd_putl16(0xfffff, &h->hash_aux_stream_index);
  bfd_putl32(sizeof(uint32_t), &h->hash_key_size);
  bfd_putl32(0x3ffff, &h->num_hash_buckets);

  ptr = (uint8_t*)&h[1];

  while (types) {
    uint16_t cv_length = bfd_getl16(types->data);
    struct pdb_type *n = types->next;

    memcpy(ptr, types->data, cv_length + sizeof(uint16_t));

    ptr += cv_length + sizeof(uint16_t);

    free(types);

    types = n;
  }

  create_type_hash_stream(hash_stream, num_types, &hash_value_buffer_length,
			  &index_offset_buffer_length, (uint8_t*)&h[1], len);

  bfd_putl32(0, &h->hash_value_buffer_offset);
  bfd_putl32(hash_value_buffer_length, &h->hash_value_buffer_length);
  bfd_putl32(hash_value_buffer_length, &h->index_offset_buffer_offset);
  bfd_putl32(index_offset_buffer_length, &h->index_offset_buffer_length);
  bfd_putl32(hash_value_buffer_length + index_offset_buffer_length, &h->hash_adj_buffer_offset);
  bfd_putl32(0, &h->hash_adj_buffer_length);
}
