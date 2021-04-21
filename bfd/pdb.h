#ifndef _BFD_PDB_H_
#define _BFD_PDB_H_

#define PDB_MAGIC "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\0\0"

static bfd_cleanup pdb_check_format (bfd *abfd);

static bfd *pdb_archive_openr_next_archived_file (bfd *archive, bfd *last_file);
static bfd *pdb_archive_get_elt_at_index (bfd *abfd, symindex sym_index);
static int pdb_archive_generic_stat_arch_elt (bfd *abfd, struct stat *buf);

static file_ptr pdb_bread (struct bfd *abfd, void *buf, file_ptr nbytes);
static file_ptr pdb_bwrite (struct bfd *abfd, const void *where,
			    file_ptr nbytes);
static file_ptr pdb_btell (struct bfd *abfd);
static int pdb_bseek (struct bfd *abfd, file_ptr offset, int whence);
static int pdb_bclose (struct bfd *abfd);
static int pdb_bflush (struct bfd *abfd);
static int pdb_bstat (struct bfd *abfd, struct stat *sb);

static void *pdb_bmmap (struct bfd *abfd, void *addr,
			bfd_size_type len, int prot,
			int flags, file_ptr offset,
			void **map_addr, bfd_size_type *map_len);

struct pdb_superblock
{
  char magic[sizeof(PDB_MAGIC)];
  uint32_t block_size;
  uint32_t free_block_map;
  uint32_t num_blocks;
  uint32_t num_directory_bytes;
  uint32_t unknown;
  uint32_t block_map_addr;
};

struct pdb_data_struct
{
  uint32_t block_size;
  uint32_t free_block_map;
  uint32_t num_blocks;
  uint32_t num_directory_bytes;
  uint32_t block_map_addr;
  uint32_t num_streams;
  bfd **streams;
  unsigned int index;
  uint32_t size;
  file_ptr pos;
  uint32_t *blocks;
};

#define bfd_pdb_get_data(abfd) ((abfd)->tdata.pdb_data)

#endif
