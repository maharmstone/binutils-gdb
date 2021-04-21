#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "libiberty.h"
#include "pdb.h"

#define pdb_archive_slurp_armap _bfd_noarchive_slurp_armap
#define pdb_archive_slurp_extended_name_table _bfd_noarchive_slurp_extended_name_table
#define pdb_archive_construct_extended_name_table _bfd_noarchive_construct_extended_name_table
#define pdb_archive_truncate_arname _bfd_noarchive_truncate_arname
#define pdb_archive_write_armap _bfd_noarchive_write_armap
#define pdb_archive_read_ar_hdr _bfd_noarchive_read_ar_hdr
#define pdb_archive_write_ar_hdr _bfd_noarchive_write_ar_hdr
#define pdb_archive_update_armap_timestamp _bfd_noarchive_update_armap_timestamp

const bfd_target pdb_vec =
{
  "pdb",
  bfd_target_pdb_flavour,
  BFD_ENDIAN_LITTLE,		/* target byte order */
  BFD_ENDIAN_LITTLE,		/* target headers byte order */
  0,				/* object flags */
  0,				/* section flags */
  0,				/* leading underscore */
  ' ',				/* ar_pad_char */
  16,				/* ar_max_namelen */
  0,				/* match priority.  */
  TARGET_KEEP_UNUSED_SECTION_SYMBOLS, /* keep unused section symbols.  */
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
  bfd_getl32, bfd_getl_signed_32, bfd_putl32,
  bfd_getl16, bfd_getl_signed_16, bfd_putl16, /* Data.  */
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
  bfd_getl32, bfd_getl_signed_32, bfd_putl32,
  bfd_getl16, bfd_getl_signed_16, bfd_putl16, /* Hdrs.  */

  {				/* bfd_check_format */
    _bfd_dummy_target,
    _bfd_dummy_target,
    pdb_check_format,
    _bfd_dummy_target
  },
  {				/* bfd_create_object */
    _bfd_bool_bfd_false_error,
    _bfd_bool_bfd_false_error,
    _bfd_bool_bfd_false_error,
    _bfd_bool_bfd_false_error
  },
  {				/* bfd_write_contents */
    _bfd_bool_bfd_false_error,
    _bfd_bool_bfd_false_error,
    _bfd_bool_bfd_false_error,
    _bfd_bool_bfd_false_error
  },

  BFD_JUMP_TABLE_GENERIC (_bfd_generic),
  BFD_JUMP_TABLE_COPY (_bfd_generic),
  BFD_JUMP_TABLE_CORE (_bfd_nocore),
  BFD_JUMP_TABLE_ARCHIVE (pdb_archive),
  BFD_JUMP_TABLE_SYMBOLS (_bfd_nosymbols),
  BFD_JUMP_TABLE_RELOCS (_bfd_norelocs),
  BFD_JUMP_TABLE_WRITE (_bfd_generic),
  BFD_JUMP_TABLE_LINK (_bfd_nolink),
  BFD_JUMP_TABLE_DYNAMIC (_bfd_nodynamic),

  NULL,

  NULL
};

static const struct bfd_iovec pdb_iovec =
{
  &pdb_bread, &pdb_bwrite, &pdb_btell, &pdb_bseek,
  &pdb_bclose, &pdb_bflush, &pdb_bstat, &pdb_bmmap
};

static bfd_cleanup
pdb_check_format (bfd *abfd)
{
  int ret;
  struct pdb_superblock super;
  struct pdb_data_struct *data;
  size_t dir_map_len;
  uint32_t *dir_map;
  void *directory, *dir_ptr;
  size_t left;

  ret = bfd_bread (&super, sizeof(super), abfd);
  if (ret != sizeof(super))
  {
    bfd_set_error (bfd_error_wrong_format);
    return NULL;
  }

  if (memcmp(super.magic, PDB_MAGIC, sizeof(super.magic)))
  {
    bfd_set_error (bfd_error_wrong_format);
    return NULL;
  }

  data = (struct pdb_data_struct *) bfd_zalloc (abfd, sizeof (*data));
  if (!data)
    return NULL;

  data->block_size = bfd_getl32(&super.block_size);
  data->free_block_map = bfd_getl32(&super.free_block_map);
  data->num_blocks = bfd_getl32(&super.num_blocks);
  data->num_directory_bytes = bfd_getl32(&super.num_directory_bytes);
  data->block_map_addr = bfd_getl32(&super.block_map_addr);

  if (data->num_directory_bytes < sizeof(uint32_t))
  {
    bfd_release (abfd, data);
    bfd_set_error (bfd_error_malformed_archive);
    return NULL;
  }

  // read list of directory blocks

  if (bfd_seek (abfd, data->block_map_addr * data->block_size, SEEK_SET))
  {
    bfd_release (abfd, data);
    return NULL;
  }

  dir_map_len = (data->num_directory_bytes + data->block_size - 1) / data->block_size;
  dir_map = bfd_malloc (dir_map_len * sizeof(uint32_t));
  if (!dir_map)
  {
    bfd_release (abfd, data);
    return NULL;
  }

  if (bfd_bread (dir_map, dir_map_len * sizeof(uint32_t), abfd) != dir_map_len * sizeof(uint32_t))
  {
    free (dir_map);
    bfd_release (abfd, data);
    return NULL;
  }

  // read directory

  directory = bfd_malloc(data->num_directory_bytes);
  if (!directory)
  {
    free (dir_map);
    bfd_release (abfd, data);
    return NULL;
  }

  left = data->num_directory_bytes;
  dir_ptr = directory;

  for (unsigned int i = 0; i < dir_map_len; i++) {
    uint32_t block = bfd_getl32(&dir_map[i]);
    size_t to_read;

    if (bfd_seek (abfd, block * data->block_size, SEEK_SET))
    {
      free (directory);
      free (dir_map);
      bfd_release (abfd, data);
      return NULL;
    }

    to_read = left < data->block_size ? left : data->block_size;

    if (bfd_bread (dir_ptr, to_read, abfd) != to_read)
    {
      free (directory);
      free (dir_map);
      bfd_release (abfd, data);
      return NULL;
    }

    if (to_read <= data->block_size)
      break;

    dir_ptr = (uint8_t*)dir_ptr + data->block_size;
    left -= to_read;
  }

  free (dir_map);

  data->num_streams = bfd_getl32(directory);

  if (data->num_directory_bytes < sizeof(uint32_t) + (data->num_streams * sizeof(uint32_t)))
  {
    free (directory);
    bfd_release (abfd, data);
    bfd_set_error (bfd_error_malformed_archive);
    return NULL;
  }

  if (data->num_streams > 0)
  {
    uint32_t *ptr;

    data->streams = bfd_zalloc (abfd, sizeof (*data));
    if (!data->streams)
    {
      free (directory);
      bfd_release (abfd, data);
      return NULL;
    }

    ptr = (uint32_t*)directory + 1 + data->num_streams;

    for (unsigned int i = 0; i < data->num_streams; i++)
    {
      struct pdb_data_struct *el_data;
      char filename[5];
      uint32_t num_blocks;

      data->streams[i] = _bfd_new_bfd();
      if (!data->streams[i])
      {
	free (directory);

	for (unsigned int j = 0; j < i; j++)
	{
	  bfd_close_all_done (data->streams[j]);
	}

	bfd_release (abfd, data);
	return NULL;
      }

      sprintf(filename, "%u", i);

      data->streams[i]->xvec = &pdb_vec;
      data->streams[i]->direction = read_direction;
      data->streams[i]->target_defaulted = abfd->target_defaulted;
      data->streams[i]->lto_output = abfd->lto_output;
      data->streams[i]->no_export = abfd->no_export;
      data->streams[i]->filename = xstrdup(filename);
      data->streams[i]->iovec = &pdb_iovec;
      data->streams[i]->archive_head = abfd;

      el_data = (struct pdb_data_struct *) bfd_zalloc (data->streams[i], sizeof (*el_data));
      if (!el_data)
      {
	free (directory);

	for (unsigned int j = 0; j <= i; j++)
	{
	  bfd_close_all_done (data->streams[j]);
	}

	bfd_release (abfd, data);
	return NULL;
      }

      el_data->index = i;
      el_data->size = bfd_getl32((uint32_t*)directory + i + 1);

      num_blocks = (el_data->size + data->block_size - 1) / data->block_size;

      if (num_blocks > 0)
      {
	el_data->blocks = bfd_alloc (data->streams[i], num_blocks * sizeof(uint32_t));
	if (!el_data->blocks)
	{
	  free (directory);

	  for (unsigned int j = 0; j <= i; j++)
	  {
	    bfd_close_all_done (data->streams[j]);
	  }

	  bfd_release (abfd, data);
	  return NULL;
	}

	for (unsigned int j = 0; j < num_blocks; j++)
	{
	  el_data->blocks[j] = bfd_getl32(ptr);
	  ptr++;
	}
      }

      bfd_pdb_get_data(data->streams[i]) = el_data;
    }
  }

  free (directory);

  bfd_pdb_get_data(abfd) = data;

  return _bfd_no_cleanup;
}

static bfd *
pdb_archive_openr_next_archived_file (bfd *archive, bfd *last_file ATTRIBUTE_UNUSED)
{
  struct pdb_data_struct *data = bfd_pdb_get_data(archive);
  struct pdb_data_struct *el_data = last_file ? bfd_pdb_get_data(last_file) : NULL;

  if (!last_file)
    return data->streams[0];
  else
  {
    if (el_data->index >= data->num_streams - 1)
    {
      bfd_set_error (bfd_error_no_more_archived_files);
      return NULL;
    }

    return data->streams[el_data->index + 1];
  }
}

static bfd *
pdb_archive_get_elt_at_index (bfd *abfd, symindex sym_index)
{
  struct pdb_data_struct *data = bfd_pdb_get_data(abfd);

  if (sym_index >= data->num_streams)
  {
    bfd_set_error (bfd_error_invalid_operation);
    return NULL;
  }

  return data->streams[sym_index];
}

static int
pdb_archive_generic_stat_arch_elt (bfd *abfd, struct stat *buf)
{
  struct pdb_data_struct *el_data = bfd_pdb_get_data(abfd);

  memset(buf, 0, sizeof(struct stat));

  buf->st_mode = 0644;
  buf->st_size = el_data->size;

  return 0;
}

static file_ptr
pdb_bread (struct bfd *abfd, void *buf, file_ptr nbytes)
{
  struct pdb_data_struct *data = bfd_pdb_get_data(abfd->archive_head);
  struct pdb_data_struct *el_data = bfd_pdb_get_data(abfd);
  file_ptr left;
  uint32_t block;

  if (el_data->pos > el_data->size)
    return 0;

  if (el_data->pos + nbytes > el_data->size)
    nbytes = el_data->size - el_data->pos;

  if (nbytes == 0)
    return 0;

  left = nbytes;
  block = el_data->pos / data->block_size;

  while (left > 0)
  {
    file_ptr to_read, ret;

    if (el_data->pos % data->block_size)
      to_read = data->block_size - (el_data->pos % data->block_size);
    else
      to_read = data->block_size;

    if (to_read > left)
      to_read = left;

    if (bfd_seek (abfd->archive_head, el_data->blocks[block] * data->block_size, SEEK_SET))
      return -1;

    ret = bfd_bread (buf, to_read, abfd->archive_head);
    if (ret < 0)
      return ret;

    el_data->pos += to_read;
    left -= to_read;
    buf = (uint8_t*)buf + to_read;
    block++;
  }

  return nbytes;
}

static file_ptr pdb_bwrite (struct bfd *abfd ATTRIBUTE_UNUSED,
			    const void *where ATTRIBUTE_UNUSED,
			    file_ptr nbytes ATTRIBUTE_UNUSED)
{
  return -1;
}

static file_ptr pdb_btell (struct bfd *abfd ATTRIBUTE_UNUSED)
{
  struct pdb_data_struct *el_data = bfd_pdb_get_data(abfd);

  return el_data->pos;
}

static int pdb_bseek (struct bfd *abfd, file_ptr offset, int whence)
{
  struct pdb_data_struct *el_data = bfd_pdb_get_data(abfd);

  switch (whence)
  {
    case SEEK_SET:
      el_data->pos = offset;
    break;

    case SEEK_CUR:
      el_data->pos += offset;
    break;

    default:
      return -1;
  }

  return 0;
}

static int pdb_bclose (struct bfd *abfd ATTRIBUTE_UNUSED)
{
  return 0;
}

static int pdb_bflush (struct bfd *abfd ATTRIBUTE_UNUSED)
{
  return 0;
}

static int pdb_bstat (struct bfd *abfd, struct stat *sb)
{
  return pdb_archive_generic_stat_arch_elt (abfd, sb);
}

static void *pdb_bmmap (struct bfd *abfd ATTRIBUTE_UNUSED,
			void *addr ATTRIBUTE_UNUSED,
			bfd_size_type len ATTRIBUTE_UNUSED,
			int prot ATTRIBUTE_UNUSED,
			int flags ATTRIBUTE_UNUSED,
			file_ptr offset ATTRIBUTE_UNUSED,
			void **map_addr ATTRIBUTE_UNUSED,
			bfd_size_type *map_len ATTRIBUTE_UNUSED)
{
  return (void *) -1;
}
