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

#define NUM_SYMBOL_BUCKETS 4096

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
add_public_symbol(struct pdb_hash_list *list, const char *name, uint16_t section, uint32_t address)
{
  size_t name_len = strlen(name);
  struct pdb_hash_entry *ent;
  uint8_t *pubsym32;

  // payload is PUBSYM32 in cvdump

  ent = xmalloc(offsetof(struct pdb_hash_entry, data[0]) + 15 + name_len);
  pubsym32 = ent->data;

  ent->hash = calc_hash((const uint8_t*)name, name_len);
  ent->length = 15 + name_len;

  bfd_putl16(ent->length, pubsym32); // length
  bfd_putl16(S_PUB32, pubsym32 + 2); // type
  bfd_putl32(0, pubsym32 + 4); // flags
  bfd_putl32(address, pubsym32 + 8); // address
  bfd_putl16(section, pubsym32 + 12); // section

  memcpy(pubsym32 + 14, name, name_len + 1);

  add_hash_entry(list, ent);
}

static void
create_file_info_substream(void **data, uint32_t *length)
{
  // FIXME - do this properly

  *length = sizeof(uint32_t);
  *data = xmalloc(*length);

  memset(*data, 0, *length);
}

static uint16_t
create_symbol_record_stream (struct pdb_context *ctx, struct pdb_hash_list *publics)
{
  uint16_t index;
  struct pdb_stream *stream;
  struct pdb_hash_entry *ent;
  uint8_t *ptr;

  index = ctx->num_streams;
  add_stream(ctx, NULL);
  stream = ctx->last_stream;

  ent = publics->first;
  while (ent) {
    if (stream->length % 4 != 0) // align to 32-bit boundary
      stream->length += 4 - (stream->length % 4);

    stream->length += ent->length;

    ent = ent->next;
  }

  stream->data = xmalloc(stream->length);

  memset(stream->data, 0, stream->length);

  ent = publics->first;
  ptr = stream->data;

  while (ent) {
    uint16_t next_entry = bfd_getl16(ent->data);

    memcpy(ptr, ent->data, ent->length);

    if (ent->length % 4 != 0) // align next entry to 32-bit boundary
      next_entry += 4 - (ent->length % 4);

    next_entry -= sizeof(uint16_t);

    bfd_putl16(next_entry, ptr);

    ent->offset = (uint8_t*)ptr - (uint8_t*)stream->data;

    ptr = ptr + sizeof(uint16_t) + next_entry;

    ent = ent->next;
  }

  return index;
}

static int
pub32_addr_compare(const void *s1, const void* s2)
{
  const struct pdb_hash_entry *ent1 = *(const struct pdb_hash_entry **)s1;
  const struct pdb_hash_entry *ent2 = *(const struct pdb_hash_entry **)s2;
  uint16_t sect1, sect2;
  uint32_t address1, address2;

  sect1 = bfd_getl16(ent1->data + 12);
  sect2 = bfd_getl16(ent2->data + 12);

  if (sect1 < sect2)
    return -1;
  if (sect1 > sect2)
    return 1;

  address1 = bfd_getl32(ent1->data + 8);
  address2 = bfd_getl32(ent2->data + 8);

  if (address1 < address2)
    return -1;
  if (address1 > address2)
    return 1;

  return 0;
}

static uint16_t
create_symbol_stream (struct pdb_context *ctx, struct pdb_hash_list *list)
{
  uint16_t stream_index;
  struct pdb_stream *stream;
  uint32_t num_entries, num_buckets;
  struct pdb_hash_entry *ent;
  struct gsi_header *header;
  struct gsi_hash_header *hash_header;
  struct hash_record_file *hrf;
  uint8_t *bmp;
  uint32_t *bucket_offs, *addr_map;
  struct pdb_hash_entry **ents_sorted;

  stream_index = ctx->num_streams;
  add_stream(ctx, NULL);
  stream = ctx->last_stream;

  num_entries = 0;
  ent = list->first;

  while (ent) {
    ent->index = num_entries;
    num_entries++;
    ent = ent->next;
  }

  num_buckets = 0;
  for (unsigned int i = 0; i < list->num_buckets; i++) {
    if (list->buckets[i])
      num_buckets++;
  }

  stream->length = sizeof(struct gsi_header) + sizeof(struct gsi_hash_header) +
		   (num_entries * sizeof(struct hash_record_file)) + (num_buckets * sizeof(uint32_t)) +
		   (list->num_buckets / 8) + sizeof(uint32_t) + (num_entries * sizeof(uint32_t));
  stream->data = xmalloc(stream->length);
  memset(stream->data, 0, stream->length);

  header = (struct gsi_header*)stream->data;
  bfd_putl32(stream->length - sizeof(struct gsi_header) - (num_entries * sizeof(uint32_t)),
	     &header->sym_hash_length);
  bfd_putl32(num_entries * sizeof(uint32_t), &header->addr_map_length);

  hash_header = (struct gsi_hash_header*)&header[1];
  bfd_putl32(0xffffffff, &hash_header->signature);
  bfd_putl32(GSI_HASH_VERSION_V70, &hash_header->version);
  bfd_putl32(num_entries * sizeof(struct hash_record_file), &hash_header->data_length);
  bfd_putl32((num_buckets * 4) + (list->num_buckets / 8) + sizeof(uint32_t),
	     &hash_header->buckets_length);

  hrf = (struct hash_record_file*)&hash_header[1];
  ent = list->first;

  while (ent) {
    bfd_putl32(ent->offset + 1, &hrf->offset);
    bfd_putl32(1, &hrf->ref);

    ent = ent->next;
    hrf++;
  }

  bmp = (uint8_t*)hrf;
  for (unsigned int i = 0; i < list->num_buckets; i += 8) {
    uint8_t bit = 1;

    for (unsigned int j = 0; j < 8; j++) {
      if (list->buckets[i+j])
	*bmp |= bit;

      bit <<= 1;
    }

    bmp++;
  }

  bucket_offs = (uint32_t*)(bmp + sizeof(uint32_t)); // 4-byte gap

  for (unsigned int i = 0; i < list->num_buckets; i++) {
    if (list->buckets[i]) {
      bfd_putl32(list->buckets[i]->index * 0xc, bucket_offs); // size of internal hash_record structure
      bucket_offs++;
    }
  }

  addr_map = bucket_offs;

  ents_sorted = xmalloc(sizeof(struct pdb_hash_entry*) * num_entries);

  ent = list->first;
  for (unsigned int i = 0; i < num_entries; i++) {
    ents_sorted[i] = ent;
    ent = ent->next;
  }

  qsort(ents_sorted, num_entries, sizeof(struct pdb_hash_entry*), pub32_addr_compare);

  for (unsigned int i = 0; i < num_entries; i++) {
    bfd_putl32(ents_sorted[i]->offset, addr_map);

    addr_map++;
  }

  free(ents_sorted);

  return stream_index;
}

void
create_dbi_stream (struct pdb_context *ctx, struct pdb_stream *stream)
{
  struct dbi_stream_header *h;
  void *optional_dbg_header = NULL, *file_info = NULL;
  uint32_t optional_dbg_header_size = 0, file_info_size = 0;
  uint16_t sym_record_stream, public_stream;
  uint8_t *ptr;
  struct pdb_hash_list publics;

  init_hash_list(&publics, NUM_SYMBOL_BUCKETS);

  create_optional_dbg_header(ctx, &optional_dbg_header, &optional_dbg_header_size);

  create_file_info_substream(&file_info, &file_info_size);

  sym_record_stream = create_symbol_record_stream(ctx, &publics);

  public_stream = create_symbol_stream(ctx, &publics);

  stream->length = sizeof(struct dbi_stream_header) + optional_dbg_header_size +
		   file_info_size;
  stream->data = xmalloc(stream->length);

  h = (struct dbi_stream_header*)stream->data;

  bfd_putl32(0xffffffff, &h->version_signature);
  bfd_putl32(dbi_stream_version_v70, &h->version_header);
  bfd_putl32(1, &h->age);
  bfd_putl16(0xffff, &h->global_stream_index); // FIXME
  bfd_putl16(0x8a0a, &h->build_number); // claim to be MSVC 10.10
  bfd_putl16(public_stream, &h->public_stream_index);
  bfd_putl16(0, &h->pdb_dll_version);
  bfd_putl16(sym_record_stream, &h->sym_record_stream);
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

  free_hash_list (&publics);
}
