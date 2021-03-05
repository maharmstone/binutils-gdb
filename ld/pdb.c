/* Support for generating PDB CodeView debugging files.
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
#include "ld.h"
#include "ldmisc.h"

void
create_pdb_file (bfd *abfd, const char *pdb_path, const unsigned char *guid)
{
  int fd;

  fd = open (pdb_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);

  if (fd == -1)
      einfo (_("%F%P: cannot open output file %s: %E\n"), pdb_path);

  close(fd);
}
