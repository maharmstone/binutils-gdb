/* Simulator instruction operand reader for m32r.

THIS FILE IS MACHINE GENERATED WITH CGEN.

Copyright (C) 1996, 1997, 1998 Free Software Foundation, Inc.

This file is part of the GNU Simulators.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#ifdef DEFINE_LABELS
#undef DEFINE_LABELS

  /* The labels have the case they have because the enum of insn types
     is all uppercase and in the non-stdc case the fmt symbol is built
     into the enum name.  */

  static struct {
    int index;
    void *label;
  } labels[] = {
    { M32RX_XINSN_ILLEGAL, && case_read_READ_ILLEGAL },
    { M32RX_XINSN_ADD, && case_read_READ_FMT_ADD },
    { M32RX_XINSN_ADD3, && case_read_READ_FMT_ADD3 },
    { M32RX_XINSN_AND, && case_read_READ_FMT_ADD },
    { M32RX_XINSN_AND3, && case_read_READ_FMT_AND3 },
    { M32RX_XINSN_OR, && case_read_READ_FMT_ADD },
    { M32RX_XINSN_OR3, && case_read_READ_FMT_OR3 },
    { M32RX_XINSN_XOR, && case_read_READ_FMT_ADD },
    { M32RX_XINSN_XOR3, && case_read_READ_FMT_AND3 },
    { M32RX_XINSN_ADDI, && case_read_READ_FMT_ADDI },
    { M32RX_XINSN_ADDV, && case_read_READ_FMT_ADDV },
    { M32RX_XINSN_ADDV3, && case_read_READ_FMT_ADDV3 },
    { M32RX_XINSN_ADDX, && case_read_READ_FMT_ADDX },
    { M32RX_XINSN_BC8, && case_read_READ_FMT_BC8 },
    { M32RX_XINSN_BC24, && case_read_READ_FMT_BC24 },
    { M32RX_XINSN_BEQ, && case_read_READ_FMT_BEQ },
    { M32RX_XINSN_BEQZ, && case_read_READ_FMT_BEQZ },
    { M32RX_XINSN_BGEZ, && case_read_READ_FMT_BEQZ },
    { M32RX_XINSN_BGTZ, && case_read_READ_FMT_BEQZ },
    { M32RX_XINSN_BLEZ, && case_read_READ_FMT_BEQZ },
    { M32RX_XINSN_BLTZ, && case_read_READ_FMT_BEQZ },
    { M32RX_XINSN_BNEZ, && case_read_READ_FMT_BEQZ },
    { M32RX_XINSN_BL8, && case_read_READ_FMT_BL8 },
    { M32RX_XINSN_BL24, && case_read_READ_FMT_BL24 },
    { M32RX_XINSN_BCL8, && case_read_READ_FMT_BCL8 },
    { M32RX_XINSN_BCL24, && case_read_READ_FMT_BCL24 },
    { M32RX_XINSN_BNC8, && case_read_READ_FMT_BC8 },
    { M32RX_XINSN_BNC24, && case_read_READ_FMT_BC24 },
    { M32RX_XINSN_BNE, && case_read_READ_FMT_BEQ },
    { M32RX_XINSN_BRA8, && case_read_READ_FMT_BRA8 },
    { M32RX_XINSN_BRA24, && case_read_READ_FMT_BRA24 },
    { M32RX_XINSN_BNCL8, && case_read_READ_FMT_BCL8 },
    { M32RX_XINSN_BNCL24, && case_read_READ_FMT_BCL24 },
    { M32RX_XINSN_CMP, && case_read_READ_FMT_CMP },
    { M32RX_XINSN_CMPI, && case_read_READ_FMT_CMPI },
    { M32RX_XINSN_CMPU, && case_read_READ_FMT_CMP },
    { M32RX_XINSN_CMPUI, && case_read_READ_FMT_CMPI },
    { M32RX_XINSN_CMPEQ, && case_read_READ_FMT_CMP },
    { M32RX_XINSN_CMPZ, && case_read_READ_FMT_CMPZ },
    { M32RX_XINSN_DIV, && case_read_READ_FMT_DIV },
    { M32RX_XINSN_DIVU, && case_read_READ_FMT_DIV },
    { M32RX_XINSN_REM, && case_read_READ_FMT_DIV },
    { M32RX_XINSN_REMU, && case_read_READ_FMT_DIV },
    { M32RX_XINSN_DIVH, && case_read_READ_FMT_DIV },
    { M32RX_XINSN_JC, && case_read_READ_FMT_JC },
    { M32RX_XINSN_JNC, && case_read_READ_FMT_JC },
    { M32RX_XINSN_JL, && case_read_READ_FMT_JL },
    { M32RX_XINSN_JMP, && case_read_READ_FMT_JMP },
    { M32RX_XINSN_LD, && case_read_READ_FMT_LD },
    { M32RX_XINSN_LD_D, && case_read_READ_FMT_LD_D },
    { M32RX_XINSN_LDB, && case_read_READ_FMT_LDB },
    { M32RX_XINSN_LDB_D, && case_read_READ_FMT_LDB_D },
    { M32RX_XINSN_LDH, && case_read_READ_FMT_LDH },
    { M32RX_XINSN_LDH_D, && case_read_READ_FMT_LDH_D },
    { M32RX_XINSN_LDUB, && case_read_READ_FMT_LDB },
    { M32RX_XINSN_LDUB_D, && case_read_READ_FMT_LDB_D },
    { M32RX_XINSN_LDUH, && case_read_READ_FMT_LDH },
    { M32RX_XINSN_LDUH_D, && case_read_READ_FMT_LDH_D },
    { M32RX_XINSN_LD_PLUS, && case_read_READ_FMT_LD_PLUS },
    { M32RX_XINSN_LD24, && case_read_READ_FMT_LD24 },
    { M32RX_XINSN_LDI8, && case_read_READ_FMT_LDI8 },
    { M32RX_XINSN_LDI16, && case_read_READ_FMT_LDI16 },
    { M32RX_XINSN_LOCK, && case_read_READ_FMT_LOCK },
    { M32RX_XINSN_MACHI_A, && case_read_READ_FMT_MACHI_A },
    { M32RX_XINSN_MACLO_A, && case_read_READ_FMT_MACHI_A },
    { M32RX_XINSN_MACWHI_A, && case_read_READ_FMT_MACHI_A },
    { M32RX_XINSN_MACWLO_A, && case_read_READ_FMT_MACHI_A },
    { M32RX_XINSN_MUL, && case_read_READ_FMT_ADD },
    { M32RX_XINSN_MULHI_A, && case_read_READ_FMT_MULHI_A },
    { M32RX_XINSN_MULLO_A, && case_read_READ_FMT_MULHI_A },
    { M32RX_XINSN_MULWHI_A, && case_read_READ_FMT_MULHI_A },
    { M32RX_XINSN_MULWLO_A, && case_read_READ_FMT_MULHI_A },
    { M32RX_XINSN_MV, && case_read_READ_FMT_MV },
    { M32RX_XINSN_MVFACHI_A, && case_read_READ_FMT_MVFACHI_A },
    { M32RX_XINSN_MVFACLO_A, && case_read_READ_FMT_MVFACHI_A },
    { M32RX_XINSN_MVFACMI_A, && case_read_READ_FMT_MVFACHI_A },
    { M32RX_XINSN_MVFC, && case_read_READ_FMT_MVFC },
    { M32RX_XINSN_MVTACHI_A, && case_read_READ_FMT_MVTACHI_A },
    { M32RX_XINSN_MVTACLO_A, && case_read_READ_FMT_MVTACHI_A },
    { M32RX_XINSN_MVTC, && case_read_READ_FMT_MVTC },
    { M32RX_XINSN_NEG, && case_read_READ_FMT_MV },
    { M32RX_XINSN_NOP, && case_read_READ_FMT_NOP },
    { M32RX_XINSN_NOT, && case_read_READ_FMT_MV },
    { M32RX_XINSN_RAC_DSI, && case_read_READ_FMT_RAC_DSI },
    { M32RX_XINSN_RACH_DSI, && case_read_READ_FMT_RAC_DSI },
    { M32RX_XINSN_RTE, && case_read_READ_FMT_RTE },
    { M32RX_XINSN_SETH, && case_read_READ_FMT_SETH },
    { M32RX_XINSN_SLL, && case_read_READ_FMT_ADD },
    { M32RX_XINSN_SLL3, && case_read_READ_FMT_SLL3 },
    { M32RX_XINSN_SLLI, && case_read_READ_FMT_SLLI },
    { M32RX_XINSN_SRA, && case_read_READ_FMT_ADD },
    { M32RX_XINSN_SRA3, && case_read_READ_FMT_SLL3 },
    { M32RX_XINSN_SRAI, && case_read_READ_FMT_SLLI },
    { M32RX_XINSN_SRL, && case_read_READ_FMT_ADD },
    { M32RX_XINSN_SRL3, && case_read_READ_FMT_SLL3 },
    { M32RX_XINSN_SRLI, && case_read_READ_FMT_SLLI },
    { M32RX_XINSN_ST, && case_read_READ_FMT_ST },
    { M32RX_XINSN_ST_D, && case_read_READ_FMT_ST_D },
    { M32RX_XINSN_STB, && case_read_READ_FMT_STB },
    { M32RX_XINSN_STB_D, && case_read_READ_FMT_STB_D },
    { M32RX_XINSN_STH, && case_read_READ_FMT_STH },
    { M32RX_XINSN_STH_D, && case_read_READ_FMT_STH_D },
    { M32RX_XINSN_ST_PLUS, && case_read_READ_FMT_ST_PLUS },
    { M32RX_XINSN_ST_MINUS, && case_read_READ_FMT_ST_PLUS },
    { M32RX_XINSN_SUB, && case_read_READ_FMT_ADD },
    { M32RX_XINSN_SUBV, && case_read_READ_FMT_ADDV },
    { M32RX_XINSN_SUBX, && case_read_READ_FMT_ADDX },
    { M32RX_XINSN_TRAP, && case_read_READ_FMT_TRAP },
    { M32RX_XINSN_UNLOCK, && case_read_READ_FMT_UNLOCK },
    { M32RX_XINSN_SATB, && case_read_READ_FMT_SATB },
    { M32RX_XINSN_SATH, && case_read_READ_FMT_SATB },
    { M32RX_XINSN_SAT, && case_read_READ_FMT_SAT },
    { M32RX_XINSN_PCMPBZ, && case_read_READ_FMT_CMPZ },
    { M32RX_XINSN_SADD, && case_read_READ_FMT_SADD },
    { M32RX_XINSN_MACWU1, && case_read_READ_FMT_MACWU1 },
    { M32RX_XINSN_MSBLO, && case_read_READ_FMT_MSBLO },
    { M32RX_XINSN_MULWU1, && case_read_READ_FMT_MULWU1 },
    { M32RX_XINSN_MACLH1, && case_read_READ_FMT_MACWU1 },
    { M32RX_XINSN_SC, && case_read_READ_FMT_SC },
    { M32RX_XINSN_SNC, && case_read_READ_FMT_SC },
    { 0, 0 }
  };
  int i;

  for (i = 0; labels[i].label != 0; ++i)
    CPU_IDESC (current_cpu) [labels[i].index].read = labels[i].label;

#endif /* DEFINE_LABELS */

#ifdef DEFINE_SWITCH
#undef DEFINE_SWITCH

{
  SWITCH (read, decode->read)
    {

    CASE (read, READ_ILLEGAL) :
    {
      sim_engine_illegal_insn (current_cpu, NULL_CIA /*FIXME*/);
    }
    BREAK (read);

    CASE (read, READ_FMT_ADD) : /* e.g. add $dr,$sr */
    {
#define OPRND(f) par_exec->operands.fmt_add.f
  EXTRACT_FMT_ADD_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_ADD_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (dr) = CPU (h_gr[f_r1]);
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_ADD3) : /* e.g. add3 $dr,$sr,$hash$slo16 */
    {
#define OPRND(f) par_exec->operands.fmt_add3.f
  EXTRACT_FMT_ADD3_VARS /* f-op1 f-r1 f-op2 f-r2 f-simm16 */
  EXTRACT_FMT_ADD3_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (sr) = CPU (h_gr[f_r2]);
      OPRND (slo16) = f_simm16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_AND3) : /* e.g. and3 $dr,$sr,$uimm16 */
    {
#define OPRND(f) par_exec->operands.fmt_and3.f
  EXTRACT_FMT_AND3_VARS /* f-op1 f-r1 f-op2 f-r2 f-uimm16 */
  EXTRACT_FMT_AND3_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (sr) = CPU (h_gr[f_r2]);
      OPRND (uimm16) = f_uimm16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_OR3) : /* e.g. or3 $dr,$sr,$hash$ulo16 */
    {
#define OPRND(f) par_exec->operands.fmt_or3.f
  EXTRACT_FMT_OR3_VARS /* f-op1 f-r1 f-op2 f-r2 f-uimm16 */
  EXTRACT_FMT_OR3_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (sr) = CPU (h_gr[f_r2]);
      OPRND (ulo16) = f_uimm16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_ADDI) : /* e.g. addi $dr,$simm8 */
    {
#define OPRND(f) par_exec->operands.fmt_addi.f
  EXTRACT_FMT_ADDI_VARS /* f-op1 f-r1 f-simm8 */
  EXTRACT_FMT_ADDI_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (dr) = CPU (h_gr[f_r1]);
      OPRND (simm8) = f_simm8;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_ADDV) : /* e.g. addv $dr,$sr */
    {
#define OPRND(f) par_exec->operands.fmt_addv.f
  EXTRACT_FMT_ADDV_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_ADDV_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (dr) = CPU (h_gr[f_r1]);
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_ADDV3) : /* e.g. addv3 $dr,$sr,$simm16 */
    {
#define OPRND(f) par_exec->operands.fmt_addv3.f
  EXTRACT_FMT_ADDV3_VARS /* f-op1 f-r1 f-op2 f-r2 f-simm16 */
  EXTRACT_FMT_ADDV3_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (sr) = CPU (h_gr[f_r2]);
      OPRND (simm16) = f_simm16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_ADDX) : /* e.g. addx $dr,$sr */
    {
#define OPRND(f) par_exec->operands.fmt_addx.f
  EXTRACT_FMT_ADDX_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_ADDX_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (dr) = CPU (h_gr[f_r1]);
      OPRND (sr) = CPU (h_gr[f_r2]);
      OPRND (condbit) = CPU (h_cond);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_BC8) : /* e.g. bc.s $disp8 */
    {
#define OPRND(f) par_exec->operands.fmt_bc8.f
  EXTRACT_FMT_BC8_VARS /* f-op1 f-r1 f-disp8 */
  EXTRACT_FMT_BC8_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (condbit) = CPU (h_cond);
      OPRND (disp8) = f_disp8;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_BC24) : /* e.g. bc.l $disp24 */
    {
#define OPRND(f) par_exec->operands.fmt_bc24.f
  EXTRACT_FMT_BC24_VARS /* f-op1 f-r1 f-disp24 */
  EXTRACT_FMT_BC24_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (condbit) = CPU (h_cond);
      OPRND (disp24) = f_disp24;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_BEQ) : /* e.g. beq $src1,$src2,$disp16 */
    {
#define OPRND(f) par_exec->operands.fmt_beq.f
  EXTRACT_FMT_BEQ_VARS /* f-op1 f-r1 f-op2 f-r2 f-disp16 */
  EXTRACT_FMT_BEQ_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src1) = CPU (h_gr[f_r1]);
      OPRND (src2) = CPU (h_gr[f_r2]);
      OPRND (disp16) = f_disp16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_BEQZ) : /* e.g. beqz $src2,$disp16 */
    {
#define OPRND(f) par_exec->operands.fmt_beqz.f
  EXTRACT_FMT_BEQZ_VARS /* f-op1 f-r1 f-op2 f-r2 f-disp16 */
  EXTRACT_FMT_BEQZ_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src2) = CPU (h_gr[f_r2]);
      OPRND (disp16) = f_disp16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_BL8) : /* e.g. bl.s $disp8 */
    {
#define OPRND(f) par_exec->operands.fmt_bl8.f
  EXTRACT_FMT_BL8_VARS /* f-op1 f-r1 f-disp8 */
  EXTRACT_FMT_BL8_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (pc) = CPU (h_pc);
      OPRND (disp8) = f_disp8;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_BL24) : /* e.g. bl.l $disp24 */
    {
#define OPRND(f) par_exec->operands.fmt_bl24.f
  EXTRACT_FMT_BL24_VARS /* f-op1 f-r1 f-disp24 */
  EXTRACT_FMT_BL24_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (pc) = CPU (h_pc);
      OPRND (disp24) = f_disp24;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_BCL8) : /* e.g. bcl.s $disp8 */
    {
#define OPRND(f) par_exec->operands.fmt_bcl8.f
  EXTRACT_FMT_BCL8_VARS /* f-op1 f-r1 f-disp8 */
  EXTRACT_FMT_BCL8_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (condbit) = CPU (h_cond);
      OPRND (pc) = CPU (h_pc);
      OPRND (disp8) = f_disp8;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_BCL24) : /* e.g. bcl.l $disp24 */
    {
#define OPRND(f) par_exec->operands.fmt_bcl24.f
  EXTRACT_FMT_BCL24_VARS /* f-op1 f-r1 f-disp24 */
  EXTRACT_FMT_BCL24_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (condbit) = CPU (h_cond);
      OPRND (pc) = CPU (h_pc);
      OPRND (disp24) = f_disp24;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_BRA8) : /* e.g. bra.s $disp8 */
    {
#define OPRND(f) par_exec->operands.fmt_bra8.f
  EXTRACT_FMT_BRA8_VARS /* f-op1 f-r1 f-disp8 */
  EXTRACT_FMT_BRA8_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (disp8) = f_disp8;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_BRA24) : /* e.g. bra.l $disp24 */
    {
#define OPRND(f) par_exec->operands.fmt_bra24.f
  EXTRACT_FMT_BRA24_VARS /* f-op1 f-r1 f-disp24 */
  EXTRACT_FMT_BRA24_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (disp24) = f_disp24;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_CMP) : /* e.g. cmp $src1,$src2 */
    {
#define OPRND(f) par_exec->operands.fmt_cmp.f
  EXTRACT_FMT_CMP_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_CMP_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src1) = CPU (h_gr[f_r1]);
      OPRND (src2) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_CMPI) : /* e.g. cmpi $src2,$simm16 */
    {
#define OPRND(f) par_exec->operands.fmt_cmpi.f
  EXTRACT_FMT_CMPI_VARS /* f-op1 f-r1 f-op2 f-r2 f-simm16 */
  EXTRACT_FMT_CMPI_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src2) = CPU (h_gr[f_r2]);
      OPRND (simm16) = f_simm16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_CMPZ) : /* e.g. cmpz $src2 */
    {
#define OPRND(f) par_exec->operands.fmt_cmpz.f
  EXTRACT_FMT_CMPZ_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_CMPZ_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src2) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_DIV) : /* e.g. div $dr,$sr */
    {
#define OPRND(f) par_exec->operands.fmt_div.f
  EXTRACT_FMT_DIV_VARS /* f-op1 f-r1 f-op2 f-r2 f-simm16 */
  EXTRACT_FMT_DIV_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (dr) = CPU (h_gr[f_r1]);
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_JC) : /* e.g. jc $sr */
    {
#define OPRND(f) par_exec->operands.fmt_jc.f
  EXTRACT_FMT_JC_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_JC_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (condbit) = CPU (h_cond);
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_JL) : /* e.g. jl $sr */
    {
#define OPRND(f) par_exec->operands.fmt_jl.f
  EXTRACT_FMT_JL_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_JL_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (pc) = CPU (h_pc);
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_JMP) : /* e.g. jmp $sr */
    {
#define OPRND(f) par_exec->operands.fmt_jmp.f
  EXTRACT_FMT_JMP_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_JMP_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_LD) : /* e.g. ld $dr,@$sr */
    {
#define OPRND(f) par_exec->operands.fmt_ld.f
  EXTRACT_FMT_LD_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_LD_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (h_memory_sr) = GETMEMSI (current_cpu, CPU (h_gr[f_r2]));
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_LD_D) : /* e.g. ld $dr,@($slo16,$sr) */
    {
#define OPRND(f) par_exec->operands.fmt_ld_d.f
  EXTRACT_FMT_LD_D_VARS /* f-op1 f-r1 f-op2 f-r2 f-simm16 */
  EXTRACT_FMT_LD_D_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (h_memory_add__VM_sr_slo16) = GETMEMSI (current_cpu, ADDSI (CPU (h_gr[f_r2]), f_simm16));
      OPRND (sr) = CPU (h_gr[f_r2]);
      OPRND (slo16) = f_simm16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_LDB) : /* e.g. ldb $dr,@$sr */
    {
#define OPRND(f) par_exec->operands.fmt_ldb.f
  EXTRACT_FMT_LDB_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_LDB_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (h_memory_sr) = GETMEMQI (current_cpu, CPU (h_gr[f_r2]));
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_LDB_D) : /* e.g. ldb $dr,@($slo16,$sr) */
    {
#define OPRND(f) par_exec->operands.fmt_ldb_d.f
  EXTRACT_FMT_LDB_D_VARS /* f-op1 f-r1 f-op2 f-r2 f-simm16 */
  EXTRACT_FMT_LDB_D_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (h_memory_add__VM_sr_slo16) = GETMEMQI (current_cpu, ADDSI (CPU (h_gr[f_r2]), f_simm16));
      OPRND (sr) = CPU (h_gr[f_r2]);
      OPRND (slo16) = f_simm16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_LDH) : /* e.g. ldh $dr,@$sr */
    {
#define OPRND(f) par_exec->operands.fmt_ldh.f
  EXTRACT_FMT_LDH_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_LDH_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (h_memory_sr) = GETMEMHI (current_cpu, CPU (h_gr[f_r2]));
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_LDH_D) : /* e.g. ldh $dr,@($slo16,$sr) */
    {
#define OPRND(f) par_exec->operands.fmt_ldh_d.f
  EXTRACT_FMT_LDH_D_VARS /* f-op1 f-r1 f-op2 f-r2 f-simm16 */
  EXTRACT_FMT_LDH_D_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (h_memory_add__VM_sr_slo16) = GETMEMHI (current_cpu, ADDSI (CPU (h_gr[f_r2]), f_simm16));
      OPRND (sr) = CPU (h_gr[f_r2]);
      OPRND (slo16) = f_simm16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_LD_PLUS) : /* e.g. ld $dr,@$sr+ */
    {
#define OPRND(f) par_exec->operands.fmt_ld_plus.f
  EXTRACT_FMT_LD_PLUS_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_LD_PLUS_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (h_memory_sr) = GETMEMSI (current_cpu, CPU (h_gr[f_r2]));
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_LD24) : /* e.g. ld24 $dr,$uimm24 */
    {
#define OPRND(f) par_exec->operands.fmt_ld24.f
  EXTRACT_FMT_LD24_VARS /* f-op1 f-r1 f-uimm24 */
  EXTRACT_FMT_LD24_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (uimm24) = f_uimm24;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_LDI8) : /* e.g. ldi8 $dr,$simm8 */
    {
#define OPRND(f) par_exec->operands.fmt_ldi8.f
  EXTRACT_FMT_LDI8_VARS /* f-op1 f-r1 f-simm8 */
  EXTRACT_FMT_LDI8_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (simm8) = f_simm8;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_LDI16) : /* e.g. ldi16 $dr,$hash$slo16 */
    {
#define OPRND(f) par_exec->operands.fmt_ldi16.f
  EXTRACT_FMT_LDI16_VARS /* f-op1 f-r1 f-op2 f-r2 f-simm16 */
  EXTRACT_FMT_LDI16_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (slo16) = f_simm16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_LOCK) : /* e.g. lock $dr,@$sr */
    {
#define OPRND(f) par_exec->operands.fmt_lock.f
  EXTRACT_FMT_LOCK_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_LOCK_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (h_memory_sr) = GETMEMSI (current_cpu, CPU (h_gr[f_r2]));
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_MACHI_A) : /* e.g. machi $src1,$src2,$acc */
    {
#define OPRND(f) par_exec->operands.fmt_machi_a.f
  EXTRACT_FMT_MACHI_A_VARS /* f-op1 f-r1 f-acc f-op23 f-r2 */
  EXTRACT_FMT_MACHI_A_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (acc) = m32rx_h_accums_get (current_cpu, f_acc);
      OPRND (src1) = CPU (h_gr[f_r1]);
      OPRND (src2) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_MULHI_A) : /* e.g. mulhi $src1,$src2,$acc */
    {
#define OPRND(f) par_exec->operands.fmt_mulhi_a.f
  EXTRACT_FMT_MULHI_A_VARS /* f-op1 f-r1 f-acc f-op23 f-r2 */
  EXTRACT_FMT_MULHI_A_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src1) = CPU (h_gr[f_r1]);
      OPRND (src2) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_MV) : /* e.g. mv $dr,$sr */
    {
#define OPRND(f) par_exec->operands.fmt_mv.f
  EXTRACT_FMT_MV_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_MV_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_MVFACHI_A) : /* e.g. mvfachi $dr,$accs */
    {
#define OPRND(f) par_exec->operands.fmt_mvfachi_a.f
  EXTRACT_FMT_MVFACHI_A_VARS /* f-op1 f-r1 f-op2 f-accs f-op3 */
  EXTRACT_FMT_MVFACHI_A_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (accs) = m32rx_h_accums_get (current_cpu, f_accs);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_MVFC) : /* e.g. mvfc $dr,$scr */
    {
#define OPRND(f) par_exec->operands.fmt_mvfc.f
  EXTRACT_FMT_MVFC_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_MVFC_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (scr) = m32rx_h_cr_get (current_cpu, f_r2);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_MVTACHI_A) : /* e.g. mvtachi $src1,$accs */
    {
#define OPRND(f) par_exec->operands.fmt_mvtachi_a.f
  EXTRACT_FMT_MVTACHI_A_VARS /* f-op1 f-r1 f-op2 f-accs f-op3 */
  EXTRACT_FMT_MVTACHI_A_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (accs) = m32rx_h_accums_get (current_cpu, f_accs);
      OPRND (src1) = CPU (h_gr[f_r1]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_MVTC) : /* e.g. mvtc $sr,$dcr */
    {
#define OPRND(f) par_exec->operands.fmt_mvtc.f
  EXTRACT_FMT_MVTC_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_MVTC_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_NOP) : /* e.g. nop */
    {
#define OPRND(f) par_exec->operands.fmt_nop.f
  EXTRACT_FMT_NOP_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_NOP_CODE
      /* Fetch the input operands for the semantic handler.  */
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_RAC_DSI) : /* e.g. rac $accd,$accs,$imm1 */
    {
#define OPRND(f) par_exec->operands.fmt_rac_dsi.f
  EXTRACT_FMT_RAC_DSI_VARS /* f-op1 f-accd f-bits67 f-op2 f-accs f-bit14 f-imm1 */
  EXTRACT_FMT_RAC_DSI_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (accs) = m32rx_h_accums_get (current_cpu, f_accs);
      OPRND (imm1) = f_imm1;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_RTE) : /* e.g. rte */
    {
#define OPRND(f) par_exec->operands.fmt_rte.f
  EXTRACT_FMT_RTE_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_RTE_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (h_bsm_0) = CPU (h_bsm);
      OPRND (h_bie_0) = CPU (h_bie);
      OPRND (h_bcond_0) = CPU (h_bcond);
      OPRND (h_bpc_0) = CPU (h_bpc);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_SETH) : /* e.g. seth $dr,$hash$hi16 */
    {
#define OPRND(f) par_exec->operands.fmt_seth.f
  EXTRACT_FMT_SETH_VARS /* f-op1 f-r1 f-op2 f-r2 f-hi16 */
  EXTRACT_FMT_SETH_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (hi16) = f_hi16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_SLL3) : /* e.g. sll3 $dr,$sr,$simm16 */
    {
#define OPRND(f) par_exec->operands.fmt_sll3.f
  EXTRACT_FMT_SLL3_VARS /* f-op1 f-r1 f-op2 f-r2 f-simm16 */
  EXTRACT_FMT_SLL3_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (sr) = CPU (h_gr[f_r2]);
      OPRND (simm16) = f_simm16;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_SLLI) : /* e.g. slli $dr,$uimm5 */
    {
#define OPRND(f) par_exec->operands.fmt_slli.f
  EXTRACT_FMT_SLLI_VARS /* f-op1 f-r1 f-shift-op2 f-uimm5 */
  EXTRACT_FMT_SLLI_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (dr) = CPU (h_gr[f_r1]);
      OPRND (uimm5) = f_uimm5;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_ST) : /* e.g. st $src1,@$src2 */
    {
#define OPRND(f) par_exec->operands.fmt_st.f
  EXTRACT_FMT_ST_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_ST_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src2) = CPU (h_gr[f_r2]);
      OPRND (src1) = CPU (h_gr[f_r1]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_ST_D) : /* e.g. st $src1,@($slo16,$src2) */
    {
#define OPRND(f) par_exec->operands.fmt_st_d.f
  EXTRACT_FMT_ST_D_VARS /* f-op1 f-r1 f-op2 f-r2 f-simm16 */
  EXTRACT_FMT_ST_D_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src2) = CPU (h_gr[f_r2]);
      OPRND (slo16) = f_simm16;
      OPRND (src1) = CPU (h_gr[f_r1]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_STB) : /* e.g. stb $src1,@$src2 */
    {
#define OPRND(f) par_exec->operands.fmt_stb.f
  EXTRACT_FMT_STB_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_STB_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src2) = CPU (h_gr[f_r2]);
      OPRND (src1) = CPU (h_gr[f_r1]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_STB_D) : /* e.g. stb $src1,@($slo16,$src2) */
    {
#define OPRND(f) par_exec->operands.fmt_stb_d.f
  EXTRACT_FMT_STB_D_VARS /* f-op1 f-r1 f-op2 f-r2 f-simm16 */
  EXTRACT_FMT_STB_D_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src2) = CPU (h_gr[f_r2]);
      OPRND (slo16) = f_simm16;
      OPRND (src1) = CPU (h_gr[f_r1]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_STH) : /* e.g. sth $src1,@$src2 */
    {
#define OPRND(f) par_exec->operands.fmt_sth.f
  EXTRACT_FMT_STH_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_STH_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src2) = CPU (h_gr[f_r2]);
      OPRND (src1) = CPU (h_gr[f_r1]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_STH_D) : /* e.g. sth $src1,@($slo16,$src2) */
    {
#define OPRND(f) par_exec->operands.fmt_sth_d.f
  EXTRACT_FMT_STH_D_VARS /* f-op1 f-r1 f-op2 f-r2 f-simm16 */
  EXTRACT_FMT_STH_D_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src2) = CPU (h_gr[f_r2]);
      OPRND (slo16) = f_simm16;
      OPRND (src1) = CPU (h_gr[f_r1]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_ST_PLUS) : /* e.g. st $src1,@+$src2 */
    {
#define OPRND(f) par_exec->operands.fmt_st_plus.f
  EXTRACT_FMT_ST_PLUS_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_ST_PLUS_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src2) = CPU (h_gr[f_r2]);
      OPRND (src1) = CPU (h_gr[f_r1]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_TRAP) : /* e.g. trap $uimm4 */
    {
#define OPRND(f) par_exec->operands.fmt_trap.f
  EXTRACT_FMT_TRAP_VARS /* f-op1 f-r1 f-op2 f-uimm4 */
  EXTRACT_FMT_TRAP_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (pc) = CPU (h_pc);
      OPRND (h_cr_0) = m32rx_h_cr_get (current_cpu, ((HOSTUINT) 0));
      OPRND (uimm4) = f_uimm4;
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_UNLOCK) : /* e.g. unlock $src1,@$src2 */
    {
#define OPRND(f) par_exec->operands.fmt_unlock.f
  EXTRACT_FMT_UNLOCK_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_UNLOCK_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (h_lock_0) = CPU (h_lock);
      OPRND (src2) = CPU (h_gr[f_r2]);
      OPRND (src1) = CPU (h_gr[f_r1]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_SATB) : /* e.g. satb $dr,$sr */
    {
#define OPRND(f) par_exec->operands.fmt_satb.f
  EXTRACT_FMT_SATB_VARS /* f-op1 f-r1 f-op2 f-r2 f-uimm16 */
  EXTRACT_FMT_SATB_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_SAT) : /* e.g. sat $dr,$sr */
    {
#define OPRND(f) par_exec->operands.fmt_sat.f
  EXTRACT_FMT_SAT_VARS /* f-op1 f-r1 f-op2 f-r2 f-uimm16 */
  EXTRACT_FMT_SAT_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (condbit) = CPU (h_cond);
      OPRND (sr) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_SADD) : /* e.g. sadd */
    {
#define OPRND(f) par_exec->operands.fmt_sadd.f
  EXTRACT_FMT_SADD_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_SADD_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (h_accums_1) = m32rx_h_accums_get (current_cpu, ((HOSTUINT) 1));
      OPRND (h_accums_0) = m32rx_h_accums_get (current_cpu, ((HOSTUINT) 0));
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_MACWU1) : /* e.g. macwu1 $src1,$src2 */
    {
#define OPRND(f) par_exec->operands.fmt_macwu1.f
  EXTRACT_FMT_MACWU1_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_MACWU1_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (h_accums_1) = m32rx_h_accums_get (current_cpu, ((HOSTUINT) 1));
      OPRND (src1) = CPU (h_gr[f_r1]);
      OPRND (src2) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_MSBLO) : /* e.g. msblo $src1,$src2 */
    {
#define OPRND(f) par_exec->operands.fmt_msblo.f
  EXTRACT_FMT_MSBLO_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_MSBLO_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (accum) = m32rx_h_accum_get (current_cpu);
      OPRND (src1) = CPU (h_gr[f_r1]);
      OPRND (src2) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_MULWU1) : /* e.g. mulwu1 $src1,$src2 */
    {
#define OPRND(f) par_exec->operands.fmt_mulwu1.f
  EXTRACT_FMT_MULWU1_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_MULWU1_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (src1) = CPU (h_gr[f_r1]);
      OPRND (src2) = CPU (h_gr[f_r2]);
#undef OPRND
    }
    BREAK (read);

    CASE (read, READ_FMT_SC) : /* e.g. sc */
    {
#define OPRND(f) par_exec->operands.fmt_sc.f
  EXTRACT_FMT_SC_VARS /* f-op1 f-r1 f-op2 f-r2 */
  EXTRACT_FMT_SC_CODE
      /* Fetch the input operands for the semantic handler.  */
      OPRND (condbit) = CPU (h_cond);
#undef OPRND
    }
    BREAK (read);

    }
  ENDSWITCH (read) /* End of read switch.  */
}

#endif /* DEFINE_SWITCH */
