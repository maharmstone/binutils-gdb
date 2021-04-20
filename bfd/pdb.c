#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "libiberty.h"
#include "pdb.h"

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

  fprintf(stderr, "block_size = %x\n", data->block_size);
  fprintf(stderr, "free_block_map = %x\n", data->free_block_map);
  fprintf(stderr, "num_blocks = %x\n", data->num_blocks);
  fprintf(stderr, "num_directory_bytes = %x\n", data->num_directory_bytes);
  fprintf(stderr, "block_map_addr = %x\n", data->block_map_addr);

  if (data->num_directory_bytes == 0)
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

  // FIXME - parse directory

  bfd_pdb_get_data(abfd) = data;

  return _bfd_no_cleanup; // FIXME - free?
}

static bfd_boolean
pdb_archive_slurp_armap (bfd *abfd ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_archive_slurp_armap\n");
  return FALSE;
}

static bfd_boolean
pdb_archive_slurp_extended_name_table (bfd *abfd ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_archive_slurp_extended_name_table\n");
  return FALSE;
}

static bfd_boolean
pdb_archive_construct_extended_name_table (bfd *abfd ATTRIBUTE_UNUSED, char **tabloc ATTRIBUTE_UNUSED,
					   bfd_size_type *tablen ATTRIBUTE_UNUSED,
					   const char **name ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_archive_construct_extended_name_table\n");
  return FALSE;
}

static void
pdb_archive_truncate_arname (bfd *abfd ATTRIBUTE_UNUSED,
			     const char *pathname ATTRIBUTE_UNUSED,
			     char *arhdr ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_archive_truncate_arname\n");
}

static bfd_boolean
pdb_archive_write_armap(bfd *arch ATTRIBUTE_UNUSED,
			unsigned int elength ATTRIBUTE_UNUSED,
			struct orl *map ATTRIBUTE_UNUSED,
			unsigned int orl_count ATTRIBUTE_UNUSED,
			int stridx ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_archive_write_armap\n");
  return TRUE;
}

static void *
pdb_archive_read_ar_hdr (bfd *abfd ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_archive_read_ar_hdr\n");
  return NULL;
}

static bfd_boolean
pdb_archive_write_ar_hdr (bfd *archive, bfd *abfd ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_archive_write_ar_hdr\n");
  return _bfd_bool_bfd_false_error (archive);
}

static bfd *
pdb_archive_openr_next_archived_file (bfd *archive, bfd *last_file ATTRIBUTE_UNUSED)
{
  bfd *out;

  fprintf(stderr, "pdb_archive_openr_next_archived_file(%p, %p)\n", archive, last_file);

  if (last_file) // FIXME
  {
    bfd_set_error (bfd_error_no_more_archived_files);
    return NULL;
  }

//   out = bfd_create(NULL, NULL); // FIXME?

//   return out;
  out = _bfd_create_empty_archive_element_shell (archive); // FIXME - version that doesn't set my_archive?
  out->filename = xstrdup("test");
  out->my_archive = NULL;
  out->iovec = &pdb_iovec;

  fprintf(stderr, "returning %p\n", out);

  return out;
}

static bfd *
pdb_archive_get_elt_at_index (bfd *abfd, symindex sym_index ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_archive_get_elt_at_index\n");
  return (bfd *) _bfd_ptr_bfd_null_error (abfd);
}

static int
pdb_archive_generic_stat_arch_elt (bfd *abfd, struct stat *buf)
{
  fprintf(stderr, "pdb_archive_generic_stat_arch_elt (%p, %p)\n", abfd, buf);

  memset(buf, 0, sizeof(struct stat));

  buf->st_mode = 0644;
  buf->st_size = 4;

  return 0;
}

static bfd_boolean
pdb_archive_update_armap_timestamp (bfd *arch ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_archive_update_armap_timestamp\n");
  return FALSE;
}

static file_ptr
pdb_bread (struct bfd *abfd, void *buf, file_ptr nbytes)
{
  fprintf(stderr, "pdb_bread(%p, %p, %lx)\n", abfd, buf, nbytes);

  // FIXME
  memset(buf, 0, nbytes);

  return nbytes;
}

static file_ptr pdb_bwrite (struct bfd *abfd ATTRIBUTE_UNUSED,
			    const void *where ATTRIBUTE_UNUSED,
			    file_ptr nbytes ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_bwrite\n");

  // FIXME

  return -1;
}

static file_ptr pdb_btell (struct bfd *abfd ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_btell\n");

  // FIXME

  return 0;
}

static int pdb_bseek (struct bfd *abfd ATTRIBUTE_UNUSED, file_ptr offset ATTRIBUTE_UNUSED,
		      int whence ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_bseek\n");

  // FIXME

  return -1;
}

static int pdb_bclose (struct bfd *abfd ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_bclose\n");

  return 0;
}

static int pdb_bflush (struct bfd *abfd ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_bflush\n");

  return 0;
}

static int pdb_bstat (struct bfd *abfd ATTRIBUTE_UNUSED, struct stat *sb ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "pdb_bstat\n");

  // FIXME

  return 0;
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
  fprintf(stderr, "pdb_bmmap\n");

  return (void *) -1;
}
