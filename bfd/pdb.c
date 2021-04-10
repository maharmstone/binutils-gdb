#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"

#define PDB_MAGIC "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\0\0"

static bfd_cleanup pdb_check_format (bfd *abfd);

const bfd_target pdb_vec =
{
  "pdb",
  bfd_target_unknown_flavour,
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
    pdb_check_format,
    _bfd_dummy_target,
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
  BFD_JUMP_TABLE_ARCHIVE (_bfd_noarchive),
  BFD_JUMP_TABLE_SYMBOLS (_bfd_nosymbols),
  BFD_JUMP_TABLE_RELOCS (_bfd_norelocs),
  BFD_JUMP_TABLE_WRITE (_bfd_generic),
  BFD_JUMP_TABLE_LINK (_bfd_nolink),
  BFD_JUMP_TABLE_DYNAMIC (_bfd_nodynamic),

  NULL,

  NULL
};

static bfd_cleanup
pdb_check_format (bfd *abfd)
{
  int ret;
  char magic[sizeof(PDB_MAGIC) - 1];

  ret = bfd_bread (magic, sizeof(magic), abfd);
  if (ret != sizeof(magic))
  {
    bfd_set_error (bfd_error_wrong_format);
    return NULL;
  }

  if (memcmp(magic, PDB_MAGIC, sizeof(magic)))
  {
    bfd_set_error (bfd_error_wrong_format);
    return NULL;
  }

  // FIXME - load data etc.

  return _bfd_no_cleanup;
}
