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
#include <stdbool.h>

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

static uint16_t
find_section_number (struct bfd *abfd, struct bfd_section *section)
{
  struct bfd_section *s = abfd->sections;
  uint16_t i = 1;

  while (s) {
    if (s == section)
      return i;

    i++;
    s = s->next;
  }

  return 0;
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
add_public_symbols(struct pdb_hash_list *publics, bfd *abfd)
{
  bfd *in_bfd = abfd->tdata.coff_obj_data->link_info->input_bfds;

  while (in_bfd) {
    for (unsigned int i = 0; i < in_bfd->symcount; i++) {
      if (in_bfd->tdata.coff_obj_data->sym_hashes[i]) {
	struct coff_link_hash_entry *ent = in_bfd->tdata.coff_obj_data->sym_hashes[i];
	uint16_t section = find_section_number(abfd, ent->root.u.def.section->output_section);

	if (section > 0) {
	  add_public_symbol(publics, ent->root.root.string, section,
			    ent->root.u.def.section->output_offset + ent->root.u.def.value);
	}
      }
    }

    in_bfd = in_bfd->link.next;
  }
}

static void
create_file_info_substream(bfd *abfd, void **data, uint32_t *length)
{
  unsigned int num_modules = 0;
  struct file_info_substream *fis;
  bfd *in_bfd;

  in_bfd = abfd->tdata.coff_obj_data->link_info->input_bfds;

  while (in_bfd) {
    num_modules++;
    in_bfd = in_bfd->link.next;
  }

  *length = sizeof(struct file_info_substream) + (num_modules * sizeof(uint32_t)) + 1;
  *data = xmalloc(*length);

  memset(*data, 0, *length);

  fis = (struct file_info_substream *)*data;

  bfd_putl16(num_modules, &fis->num_modules);

  // FIXME - set file counts
}

static uint16_t
create_symbol_record_stream (struct pdb_context *ctx, struct pdb_hash_list *publics,
			     struct pdb_hash_list *globals)
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

  ent = globals->first;
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

  ent = globals->first;

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
create_symbol_stream (struct pdb_context *ctx, struct pdb_hash_list *list, bool include_header)
{
  uint16_t stream_index;
  struct pdb_stream *stream;
  uint32_t num_entries, num_buckets;
  struct pdb_hash_entry *ent;
  struct gsi_hash_header *hash_header;
  struct hash_record_file *hrf;
  uint8_t *bmp;
  uint32_t *bucket_offs;

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

  stream->length = sizeof(struct gsi_hash_header) + (num_entries * sizeof(struct hash_record_file)) +
		   (num_buckets * sizeof(uint32_t)) + (list->num_buckets / 8) + sizeof(uint32_t);

  if (include_header)
    stream->length += sizeof(struct gsi_header) + (num_entries * sizeof(uint32_t));

  stream->data = xmalloc(stream->length);
  memset(stream->data, 0, stream->length);

  if (include_header) {
    struct gsi_header *header = (struct gsi_header*)stream->data;

    bfd_putl32(stream->length - sizeof(struct gsi_header) - (num_entries * sizeof(uint32_t)),
	       &header->sym_hash_length);
    bfd_putl32(num_entries * sizeof(uint32_t), &header->addr_map_length);

    hash_header = (struct gsi_hash_header*)&header[1];
  } else
    hash_header = (struct gsi_hash_header*)stream->data;

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

  if (include_header) {
    uint32_t *addr_map;
    struct pdb_hash_entry **ents_sorted;

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
  }

  return stream_index;
}

// FIXME - use sec_to_styp_flags in coffcode.h instead? Or just copy from output?
static uint32_t
get_section_characteristics(uint32_t sec_flags)
{
  uint32_t styp_flags = 0;

  if ((sec_flags & SEC_CODE) != 0)
    styp_flags |= IMAGE_SCN_CNT_CODE;
  if ((sec_flags & (SEC_DATA | SEC_DEBUGGING)) != 0)
    styp_flags |= IMAGE_SCN_CNT_INITIALIZED_DATA;
  if ((sec_flags & SEC_ALLOC) != 0 && (sec_flags & SEC_LOAD) == 0)
    styp_flags |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;  /* ==STYP_BSS */
  /* skip ROM */
  /* skip constRUCTOR */
  /* skip CONTENTS */
  if ((sec_flags & SEC_IS_COMMON) != 0)
    styp_flags |= IMAGE_SCN_LNK_COMDAT;
  if ((sec_flags & SEC_DEBUGGING) != 0)
    styp_flags |= IMAGE_SCN_MEM_DISCARDABLE;
  if ((sec_flags & SEC_EXCLUDE) != 0)
    styp_flags |= IMAGE_SCN_LNK_REMOVE;
  if ((sec_flags & SEC_NEVER_LOAD) != 0)
    styp_flags |= IMAGE_SCN_LNK_REMOVE;
  /* skip IN_MEMORY */
  /* skip SORT */
  if (sec_flags & SEC_LINK_ONCE)
    styp_flags |= IMAGE_SCN_LNK_COMDAT;
  if ((sec_flags
       & (SEC_LINK_DUPLICATES_DISCARD | SEC_LINK_DUPLICATES_SAME_CONTENTS
	  | SEC_LINK_DUPLICATES_SAME_SIZE)) != 0)
    styp_flags |= IMAGE_SCN_LNK_COMDAT;

  /* skip LINKER_CREATED */

  if ((sec_flags & SEC_COFF_NOREAD) == 0)
    styp_flags |= IMAGE_SCN_MEM_READ;     /* Invert NOREAD for read.  */
  if ((sec_flags & SEC_READONLY) == 0)
    styp_flags |= IMAGE_SCN_MEM_WRITE;    /* Invert READONLY for write.  */
  if (sec_flags & SEC_CODE)
    styp_flags |= IMAGE_SCN_MEM_EXECUTE;  /* CODE->EXECUTE.  */
  if (sec_flags & SEC_COFF_SHARED)
    styp_flags |= IMAGE_SCN_MEM_SHARED;   /* Shared remains meaningful.  */

  return styp_flags;
}

static void
add_procref (struct pdb_hash_list *list, uint32_t offset, uint16_t module,
	     const char *name, bool global)
{
  size_t name_len = strlen(name);
  struct pdb_hash_entry *ent;
  uint8_t *refsym32;

  // payload type is REFSYM32 in cvdump

  ent = xmalloc(offsetof(struct pdb_hash_entry, data) + 15 + name_len);
  refsym32 = ent->data;

  ent->hash = calc_hash((const uint8_t*)name, name_len);
  ent->length = 15 + name_len;

  bfd_putl16(ent->length, refsym32); // length
  bfd_putl16(global ? S_PROCREF : S_LPROCREF, refsym32 + 2); // type
  bfd_putl32(0, refsym32 + 4); // unknown
  bfd_putl32(offset, refsym32 + 8); // offset
  bfd_putl32(module, refsym32 + 12); // module

  memcpy(refsym32 + 14, name, name_len + 1);

  add_hash_entry(list, ent);
}

static void
add_data32 (struct pdb_hash_list *list, uint32_t type, uint32_t off,
	    uint16_t seg, const char *name, bool global)
{
  size_t name_len = strlen(name);
  struct pdb_hash_entry *ent;
  uint8_t *datasym32;

  // payload type is DATASYM32 in cvdump

  ent = xmalloc(offsetof(struct pdb_hash_entry, data) + 15 + name_len);
  datasym32 = ent->data;

  ent->hash = calc_hash((const uint8_t*)name, name_len);
  ent->length = 15 + name_len;

  bfd_putl16(ent->length, datasym32); // length
  bfd_putl16(global ? S_GDATA32 : S_LDATA32, datasym32 + 2); // type
  bfd_putl32(type, datasym32 + 4); // type
  bfd_putl32(off, datasym32 + 8); // offset
  bfd_putl16(seg, datasym32 + 12); // segment

  memcpy(datasym32 + 14, name, name_len + 1);

  add_hash_entry(list, ent);
}

static void
handle_module_codeview_entries(uint8_t *data, size_t length, uint16_t module_num,
			       struct pdb_hash_list *globals, int32_t offset)
{
  uint32_t addr = sizeof(uint32_t);
  uint16_t cv_type, cv_length;

  cv_length = bfd_getl16(data);
  cv_type = bfd_getl16(data + 2);

  while (length > 0 && length >= sizeof(uint16_t) + cv_length) {
    switch (cv_type) {
      case S_LPROC32:
      case S_GPROC32:
      case S_LPROC32_ID:
      case S_GPROC32_ID:
      case S_LPROC32_DPC:
      case S_LPROC32_DPC_ID:
      {
	uint32_t end;
	const char *name;

	// PROCSYM32 in cvdump

	end = bfd_getl32(data + 8);

	if (end != 0) {
	  end += offset;
	  bfd_putl32(end, data + 8);
	}

	name = (const char*)(data + 39);

	add_procref (globals, addr, module_num, name,
		     cv_type == S_GPROC32 || cv_type == S_GPROC32_ID);

	break;
      }

      case S_LDATA32:
      case S_GDATA32:
      {
	uint32_t off, type;
	uint16_t seg;
	const char *name;

	// DATASYM32 in cvdump

	off = bfd_getl32(data + 8);
	seg = bfd_getl32(data + 12);

	type = bfd_getl32(data + 4);

	name = (const char*)(data + 14);

	add_data32 (globals, type, off, seg, name, cv_type == S_GDATA32);
	break;
      }
    }

    if (length <= cv_length + sizeof(uint16_t))
      return;

    addr += cv_length + sizeof(uint16_t);
    length -= cv_length + sizeof(uint16_t);

    if (length < 4)
      return;

    data += sizeof(uint16_t) + cv_length;

    cv_length = bfd_getl16(data);
    cv_type = bfd_getl16(data + 2);
  }
}

static void
handle_module_checksums(uint8_t *data, uint32_t length, uint16_t *num_source_files,
			struct pdb_string_mapping *string_map)
{
  struct pdb_checksum *checksum;

  checksum = (struct pdb_checksum*)data;

  while (length >= sizeof(struct pdb_checksum)) {
    struct pdb_string_mapping *map;
    bool string_found = false;
    uint32_t checksum_len = sizeof(struct pdb_checksum) + checksum->hash_length;
    uint32_t string_offset = bfd_getl32(&checksum->string_offset);

    if (checksum_len % 4 != 0)
      checksum_len += 4 - (checksum_len % 4);

    if (checksum_len > length)
      break;

    map = string_map;
    while (map) {
      if (string_offset == map->local) {
	string_offset = map->global;
	bfd_putl32(string_offset, &checksum->string_offset);
	string_found = true;
	break;
      }

      map = map->next;
    }

    if (!string_found)
      bfd_putl32(0, &checksum->string_offset);

    (*num_source_files)++;

    checksum = (struct pdb_checksum*)((uint8_t*)checksum + checksum_len);
    length -= checksum_len;
  }
}

static uint16_t
create_module_stream(struct pdb_context *ctx, bfd *in_bfd, uint32_t *symbols_size,
		     uint32_t *c13_lines_size, uint16_t *num_source_files,
		     uint16_t module_num, struct pdb_hash_list *globals)
{
  struct bfd_section *sect, *pdb_sect = NULL;
  struct pdb_stream *stream;
  uint16_t index;
  bfd_byte *contents = NULL;
  struct pdb_subsection *subsect;
  uint32_t left, checksums_length;
  uint8_t *symptr, *chksumptr;
  struct pdb_string_mapping* string_map = NULL;

  *symbols_size = 0;
  *c13_lines_size = 0;
  *num_source_files = 0;

  sect = in_bfd->sections;
  while (sect) {
    if (!strcmp(sect->name, ".debug$S")) {
      pdb_sect = sect;
      break;
    }

    sect = sect->next;
  }

  if (!pdb_sect || pdb_sect->size < sizeof(uint32_t))
    return 0xffff;

  if (!bfd_get_full_section_contents (in_bfd, pdb_sect, &contents))
    return 0xffff;

  if (bfd_getl32(contents) != CV_SIGNATURE_C13) {
    free(contents);
    return 0xffff;
  }

  if (pdb_sect->flags & SEC_RELOC) { // do relocations
    struct internal_reloc *ir = _bfd_coff_read_internal_relocs(in_bfd, pdb_sect, FALSE, NULL, TRUE, NULL);
    struct internal_syment *symbols;
    asection **sectlist;
    int sect_num;

    symbols = xmalloc(sizeof(struct internal_syment) * in_bfd->tdata.coff_obj_data->raw_syment_count);
    sectlist = xmalloc(sizeof(struct asection*) * in_bfd->tdata.coff_obj_data->raw_syment_count);

    memset(sectlist, 0, sizeof(struct asection*) * in_bfd->tdata.coff_obj_data->raw_syment_count);

    for (unsigned int i = 0; i < in_bfd->tdata.coff_obj_data->raw_syment_count; i++) {
      bfd_coff_swap_sym_in (in_bfd, &((struct external_syment *)(in_bfd->tdata.coff_obj_data->external_syms))[i], &symbols[i]);
    }

    sect = in_bfd->sections;
    sect_num = 1;

    while (sect) {
      for (unsigned int i = 0; i < in_bfd->tdata.coff_obj_data->raw_syment_count; i++) {
	if (symbols[i].n_scnum == sect_num)
	  sectlist[i] = sect;
      }

      sect = sect->next;
      sect_num++;
    }

    if (!bfd_coff_relocate_section (ctx->abfd, ctx->abfd->tdata.coff_obj_data->link_info, in_bfd, pdb_sect,
				    contents, ir, symbols, sectlist)) {
      free(contents);
      free(sectlist);
      free(symbols);
      return 0xffff;
    }

    free(sectlist);
    free(symbols);
  }

  index = ctx->num_streams;
  add_stream(ctx, NULL);
  stream = ctx->last_stream;

  subsect = (struct pdb_subsection*)((uint8_t*)contents + sizeof(uint32_t));
  left = pdb_sect->size - sizeof(uint32_t);
  *symbols_size = sizeof(uint32_t);
  checksums_length = 0;

  while (left > 0) {
    uint32_t type = bfd_getl32(&subsect->type);
    uint32_t length = bfd_getl32(&subsect->length);

    if (type == CV_DEBUG_S_SYMBOLS)
      *symbols_size += length;
    else if (type == CV_DEBUG_S_FILECHKSMS)
      checksums_length += length;

    if (left < sizeof(struct pdb_subsection) + length)
      break;

    left -= sizeof(struct pdb_subsection) + length;
    subsect = (struct pdb_subsection*)((uint8_t*)subsect + sizeof(struct pdb_subsection) + length);
  }

  stream->length = *symbols_size;

  if (checksums_length != 0)
    stream->length += sizeof(struct pdb_subsection) + checksums_length;

  stream->data = xmalloc(stream->length);

  // copy data into stream

  subsect = (struct pdb_subsection*)((uint8_t*)contents + sizeof(uint32_t));
  left = pdb_sect->size - sizeof(uint32_t);

  bfd_putl32(CV_SIGNATURE_C13, (uint32_t*)stream->data);
  symptr = (uint8_t*)stream->data + sizeof(uint32_t);
  chksumptr = (uint8_t*)stream->data + *symbols_size;

  if (checksums_length != 0) {
    struct pdb_subsection* csss = (struct pdb_subsection*)chksumptr;

    bfd_putl32(CV_DEBUG_S_FILECHKSMS, &csss->type);
    bfd_putl32(checksums_length, &csss->length);

    chksumptr += sizeof(struct pdb_subsection);
  }

  while (left > 0) {
    uint32_t type = bfd_getl32(&subsect->type);
    uint32_t length = bfd_getl32(&subsect->length);

    if (type == CV_DEBUG_S_SYMBOLS) {
      memcpy(symptr, (uint8_t*)subsect + sizeof(struct pdb_subsection), length);

      handle_module_codeview_entries(symptr, length, module_num, globals,
				     (symptr - (uint8_t*)stream->data) - ((uint8_t*)subsect - (uint8_t*)contents) - sizeof(struct pdb_subsection));

      symptr += length;
    } else if (type == CV_DEBUG_S_STRINGTABLE) {
      char *ptr = (char*)subsect + sizeof(struct pdb_subsection);
      uint32_t length2 = length;
      uint32_t string_len;

      while (length2 > 0) {
	struct pdb_string_mapping *map;

	string_len = strlen(ptr);

	map = (struct pdb_string_mapping*)xmalloc(sizeof(struct pdb_string_mapping));

	map->next = string_map;
	map->local = (ptr - (char*)subsect) - sizeof(struct pdb_subsection);
	map->global = add_pdb_string(ptr);

	string_map = map;

	if (length2 < string_len + 1)
	  break;

	ptr += string_len + 1;
	length2 -= string_len + 1;
      }
    } else if (type == CV_DEBUG_S_FILECHKSMS) {
      memcpy(chksumptr, (uint8_t*)subsect + sizeof(struct pdb_subsection), length);

      chksumptr += length;
    }

    if (left < sizeof(struct pdb_subsection) + length)
      break;

    left -= sizeof(struct pdb_subsection) + length;
    subsect = (struct pdb_subsection*)((uint8_t*)subsect + sizeof(struct pdb_subsection) + length);
  }

  free(contents);

  if (checksums_length != 0) {
    chksumptr = (uint8_t*)stream->data + *symbols_size + sizeof(struct pdb_subsection);
    handle_module_checksums(chksumptr, checksums_length, num_source_files, string_map);
  }

  // FIXME - line numbers

  while (string_map) {
    struct pdb_string_mapping *n;

    n = string_map->next;
    free(string_map);

    string_map = n;
  }

  return index;
}

static void
create_module_info_substream (struct pdb_context *ctx, bfd *abfd, void **data, uint32_t *length,
			      struct pdb_hash_list *globals)
{
  bfd *in_bfd = abfd->tdata.coff_obj_data->link_info->input_bfds;
  uint8_t *ptr;
  uint16_t index;

  *length = 0;

  while (in_bfd) {
    size_t name_len = strlen(in_bfd->filename);

    *length += sizeof(struct module_info) + name_len + 1;

    if (in_bfd->my_archive)
      *length += strlen(in_bfd->my_archive->filename) + 1;
    else
      *length += name_len + 1;

    if (*length % 4 != 0) // align to 32-bit boundary
      *length += 4 - (*length % 4);

    in_bfd = in_bfd->link.next;
  }

  *data = xmalloc(*length);
  memset(*data, 0, *length);

  ptr = *data;
  index = 0;
  in_bfd = abfd->tdata.coff_obj_data->link_info->input_bfds;

  while (in_bfd) {
    size_t name_len = strlen(in_bfd->filename);
    struct module_info *mod_info = (struct module_info *)ptr;
    struct bfd_section *sect = in_bfd->sections;
    uint16_t module_stream, source_file_count;
    uint32_t symbols_size, c13_lines_size;

    bfd_putl16(0xffff, &mod_info->sc.section);
    bfd_putl32(0xffffffff, &mod_info->sc.size);
    bfd_putl16(index, &mod_info->sc.module_index);

    while (sect) {
      if (sect->size > 0) {
	uint16_t sect_num = find_section_number(abfd, sect->output_section);

	if (sect_num != 0) {
	  bfd_putl16(sect_num, &mod_info->sc.section);
	  bfd_putl32(sect->output_offset, &mod_info->sc.offset);
	  bfd_putl32(sect->size, &mod_info->sc.size);
	  bfd_putl32(get_section_characteristics(sect->flags), &mod_info->sc.characteristics);
	  break;
	}
      }

      sect = sect->next;
    }

    module_stream = create_module_stream(ctx, in_bfd, &symbols_size, &c13_lines_size,
					 &source_file_count, index + 1, globals);

    bfd_putl16(module_stream, &mod_info->module_stream);
    bfd_putl32(symbols_size, &mod_info->symbols_size);
    bfd_putl32(c13_lines_size, &mod_info->c13_lines_size);
    bfd_putl16(source_file_count, &mod_info->source_file_count);

    ptr += sizeof(struct module_info);

    memcpy(ptr, in_bfd->filename, name_len + 1);
    ptr += name_len + 1;

    if (in_bfd->my_archive) {
      name_len = strlen(in_bfd->my_archive->filename);

      memcpy(ptr, in_bfd->my_archive->filename, name_len + 1);
      ptr += name_len + 1;
    } else {
      memcpy(ptr, in_bfd->filename, name_len + 1);
      ptr += name_len + 1;
    }

    if ((ptr - (uint8_t*)*data) % 4 != 0) // align to 32-bit boundary
      ptr += 4 - ((ptr - (uint8_t*)*data) % 4);

    in_bfd = in_bfd->link.next;
    index++;
  }
}

static int
sc_compare(const void *s1, const void* s2)
{
  const struct section_contribution *sc1 = s1;
  const struct section_contribution *sc2 = s2;

  if (bfd_getl16(&sc1->section) < bfd_getl16(&sc2->section))
    return -1;
  if (bfd_getl16(&sc1->section) > bfd_getl16(&sc2->section))
    return 1;

  if (bfd_getl32(&sc1->offset) < bfd_getl32(&sc2->offset))
    return -1;
  if (bfd_getl32(&sc1->offset) > bfd_getl32(&sc2->offset))
    return 1;

  return 0;
}

static void
create_sections_contribution_substream(bfd *abfd, void **data, uint32_t *length)
{
  struct section_contribution *sc;
  unsigned int num_sections = 0, module_index = 0;
  bfd *in_bfd;

  in_bfd = abfd->tdata.coff_obj_data->link_info->input_bfds;

  while (in_bfd) {
    struct bfd_section *sect = in_bfd->sections;

    while (sect) {
      if (sect->size > 0 && find_section_number(abfd, sect->output_section) != 0)
	num_sections++;

      sect = sect->next;
    }

    in_bfd = in_bfd->link.next;
  }

  *length = sizeof(uint32_t) + (num_sections * sizeof(struct section_contribution));
  *data = xmalloc(*length);
  memset(*data, 0, *length);

  bfd_putl32(section_contributions_version_ver60, (uint32_t*)*data);

  sc = (struct section_contribution *)((uint8_t*)*data + sizeof(uint32_t));

  in_bfd = abfd->tdata.coff_obj_data->link_info->input_bfds;
  while (in_bfd) {
    struct bfd_section *sect = in_bfd->sections;

    while (sect) {
      if (sect->size > 0) {
	uint16_t sect_num = find_section_number(abfd, sect->output_section);

	if (sect_num != 0) {
	  bfd_putl16(find_section_number(abfd, sect->output_section), &sc->section);

	  bfd_putl32(sect->output_offset, &sc->offset);

	  bfd_putl32(sect->size, &sc->size);
	  bfd_putl32(get_section_characteristics(sect->flags), &sc->characteristics);
	  bfd_putl16(module_index, &sc->module_index);

	  sc++;
	}
      }

      sect = sect->next;
    }

    in_bfd = in_bfd->link.next;
    module_index++;
  }

  qsort((uint8_t*)*data + sizeof(uint32_t), num_sections, sizeof(struct section_contribution), sc_compare);
}

static void
create_section_map_substream (bfd *abfd, void **data, uint32_t *length)
{
  struct section_map_header *header;
  struct section_map_entry *entries;
  struct bfd_section *sect;

  /* This substream, also known as the segment map, looks to be a remnant of
   * pre-32-bit Windows, and doesn't appear to do anything useful. */

  *length = sizeof(struct section_map_header) + ((abfd->section_count + 1) * sizeof(struct section_map_entry));
  *data = xmalloc(*length);

  header = (struct section_map_header*)*data;

  bfd_putl16(abfd->section_count + 1, &header->count);
  bfd_putl16(abfd->section_count + 1, &header->log_count);

  entries = (struct section_map_entry*)&header[1];
  sect = abfd->sections;

  for (unsigned int i = 0; i < abfd->section_count; i++) {
    uint16_t flags = SECTION_MAP_ENTRY_FLAGS_SELECTOR |
		     SECTION_MAP_ENTRY_FLAGS_32BIT |
		     SECTION_MAP_ENTRY_FLAGS_READ;

    if (!(sect->flags & SEC_READONLY))
      flags |= SECTION_MAP_ENTRY_FLAGS_WRITE;

    if (sect->flags & SEC_CODE)
      flags |= SECTION_MAP_ENTRY_FLAGS_EXECUTE;

    bfd_putl16(flags, &entries[i].flags);

    bfd_putl16(0, &entries[i].ovl);
    bfd_putl16(0, &entries[i].group);
    bfd_putl16(i + 1, &entries[i].frame);
    bfd_putl16(0xffff, &entries[i].section_name);
    bfd_putl16(0xffff, &entries[i].class_name);
    bfd_putl32(0, &entries[i].offset);
    bfd_putl32(sect->size, &entries[i].section_length);

    sect = sect->next;
  }

  bfd_putl16(SECTION_MAP_ENTRY_FLAGS_ABSOLUTE | SECTION_MAP_ENTRY_FLAGS_32BIT,
	     &entries[abfd->section_count].flags);
  bfd_putl16(0, &entries[abfd->section_count].ovl);
  bfd_putl16(0, &entries[abfd->section_count].group);
  bfd_putl16(0, &entries[abfd->section_count].frame);
  bfd_putl16(0xffff, &entries[abfd->section_count].section_name);
  bfd_putl16(0xffff, &entries[abfd->section_count].class_name);
  bfd_putl32(0, &entries[abfd->section_count].offset);
  bfd_putl32(0xffffffff, &entries[abfd->section_count].section_length);
}

void
create_dbi_stream (struct pdb_context *ctx, struct pdb_stream *stream)
{
  struct dbi_stream_header *h;
  void *optional_dbg_header = NULL, *file_info = NULL, *module_info = NULL;
  void *section_contributions = NULL, *section_map = NULL;
  uint32_t optional_dbg_header_size = 0, file_info_size = 0, module_info_size = 0;
  uint32_t section_contributions_size = 0, section_map_size = 0;
  uint16_t sym_record_stream, public_stream, global_stream;
  uint8_t *ptr;
  struct pdb_hash_list publics, globals;

  init_hash_list(&publics, NUM_SYMBOL_BUCKETS);
  init_hash_list(&globals, NUM_SYMBOL_BUCKETS);

  add_public_symbols(&publics, ctx->abfd);

  create_optional_dbg_header(ctx, &optional_dbg_header, &optional_dbg_header_size);

  create_module_info_substream(ctx, ctx->abfd, &module_info, &module_info_size,
			       &globals);

  create_file_info_substream(ctx->abfd, &file_info, &file_info_size);

  create_sections_contribution_substream(ctx->abfd, &section_contributions,
					 &section_contributions_size);

  create_section_map_substream(ctx->abfd, &section_map, &section_map_size);

  sym_record_stream = create_symbol_record_stream(ctx, &publics, &globals);

  public_stream = create_symbol_stream(ctx, &publics, true);
  global_stream = create_symbol_stream(ctx, &globals, false);

  stream->length = sizeof(struct dbi_stream_header) + optional_dbg_header_size +
		   file_info_size + module_info_size + section_contributions_size +
		   section_map_size;
  stream->data = xmalloc(stream->length);

  h = (struct dbi_stream_header*)stream->data;

  bfd_putl32(0xffffffff, &h->version_signature);
  bfd_putl32(dbi_stream_version_v70, &h->version_header);
  bfd_putl32(1, &h->age);
  bfd_putl16(global_stream, &h->global_stream_index);
  bfd_putl16(0x8a0a, &h->build_number); // claim to be MSVC 10.10
  bfd_putl16(public_stream, &h->public_stream_index);
  bfd_putl16(0, &h->pdb_dll_version);
  bfd_putl16(sym_record_stream, &h->sym_record_stream);
  bfd_putl16(0, &h->pdb_dll_rbld);
  bfd_putl32(module_info_size, &h->mod_info_size);
  bfd_putl32(section_contributions_size, &h->section_contribution_size);
  bfd_putl32(section_map_size, &h->section_map_size);
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

  if (module_info) {
    memcpy(ptr, module_info, module_info_size);
    ptr += module_info_size;
    free(module_info);
  }

  if (section_contributions) {
    memcpy(ptr, section_contributions, section_contributions_size);
    ptr += section_contributions_size;
    free(section_contributions);
  }

  if (section_map) {
    memcpy(ptr, section_map, section_map_size);
    ptr += section_map_size;
    free(section_map);
  }

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
  free_hash_list (&globals);
}
