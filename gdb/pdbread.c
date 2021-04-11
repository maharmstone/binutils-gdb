#include "defs.h"
#include "symfile.h"
#include "psymtab.h"

static void
pdb_symfile_init (struct objfile *objfile)
{
  // FIXME
}

static void
pdb_symfile_offsets (struct objfile *objfile,
		     const section_addr_info &addrs)
{
  // FIXME?

  default_symfile_offsets (objfile, addrs);
}

static void
pdb_symfile_read (struct objfile *objfile, symfile_add_flags symfile_flags)
{
  // FIXME
}

static const struct sym_fns pdb_sym_fns =
{
  NULL,			/* sym_new_init */
  pdb_symfile_init,
  pdb_symfile_read,
  NULL,			/* sym_read_psymbols */
  NULL,			/* sym_finish */
  pdb_symfile_offsets,
  default_symfile_segments,
  NULL,			/* sym_read_linetable */
  NULL,			/* sym_relocate */
  NULL,			/* sym_probe_fns */
  &psym_functions
};

void _initialize_pdbread ();
void
_initialize_pdbread ()
{
  add_symtab_fns (bfd_target_pdb_flavour, &pdb_sym_fns);
}
