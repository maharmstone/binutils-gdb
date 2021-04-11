#include "defs.h"
#include "symfile.h"

static const struct sym_fns pdb_sym_fns =
{
  NULL,		/* sym_new_init */
  NULL,		/* sym_init */
  NULL,		/* sym_read */
  NULL,		/* sym_read_psymbols */
  NULL,		/* sym_finish */
  NULL,		/* sym_offsets */
  NULL,		/* sym_segments */
  NULL,		/* sym_read_linetable */
  NULL,		/* sym_relocate */
  NULL,		/* sym_probe_fns */
  NULL		/* qf */
};

void _initialize_pdbread ();
void
_initialize_pdbread ()
{
  add_symtab_fns (bfd_target_pdb_flavour, &pdb_sym_fns);
}
