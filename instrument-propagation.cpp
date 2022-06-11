/*
 * dift-addr --- Dynamic Information Flow Tracking on memory ADDResses
 * Copyright (C) 2022  Xiaoyue Chen
 *
 * This file is part of dift-addr.
 *
 * dift-addr is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dift-addr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dift-addr.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "instrument-propagation.h"

#include "operand.hpp"
#include "propagation.h"
#include "util.hpp"
#include "xed-iclass-enum.h"
#include "xed-reg-enum.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <list>
#include <string>
#include <unordered_map>
#include <unordered_set>

struct REG_ARRAY
{
  static constexpr size_t MAX_NREG = 16;
  REG data[MAX_NREG];
  size_t size;
};

struct INS_REG
{
  REG_ARRAY reg_w, reg_r, mem_w, mem_r;
};

struct INS_INFO
{
  void *addr;
  INS_REG regs;
  std::string disassemble;
  std::string rtn;
  std::string img;
  void *load_offset;
};

static FILE *out = stderr;
static size_t warmup = 0;
static size_t period = 1;
static size_t last_dump_nexecuted = 0;
static PG_PROPAGATOR *pg;
using ADDR_SET = std::tr1::unordered_set<void *>;
static ADDR_SET addr_any;
static ADDR_SET ins_addr;
using ADDR_TAB = std::unordered_map<void *, void *>;
static ADDR_TAB addr_mem_tab;

static std::list<INS_INFO> ins_info;
static const INS_INFO *current_ins_info;
static size_t nexecuted;

static constexpr uint32_t
MapReg (REG reg)
{
  if (REG_GR_BASE <= reg && reg <= REG_GR_LAST)
    return reg - REG_GR_BASE;

  if (REG_MM_BASE <= reg && reg <= REG_ZMM_LAST)
    return (REG_GR_LAST - REG_GR_BASE + 1) + reg - REG_MM_BASE;

  assert (false && "reg must be in domain");
  return reg;
}

static constexpr REG
InverseMapReg (uint32_t reg)
{
  if (reg <= REG_GR_LAST - REG_GR_BASE)
    {
      return (REG)(REG_GR_BASE + reg);
    }

  if (reg < REG_GR_LAST - REG_GR_BASE + REG_ZMM_LAST - REG_MM_BASE)
    {
      return (REG)(reg - (REG_GR_LAST - REG_GR_BASE + 1) + REG_MM_BASE);
    }

  assert (false);
  return REG_INVALID ();
}

static bool
IsRegRelevant (REG reg)
{
  return REG_valid (reg)
         && (REG_is_gr (REG_FullRegName (reg)) || REG_is_xmm_ymm_zmm (reg));
}

static bool
IsOpRelevant (OP op)
{
  bool relevant = false;
  switch (op.t)
    {
    case OP_T_REG:
      relevant = IsRegRelevant (op.content.reg);
      break;

    case OP_T_MEM:
      relevant = true;
      break;

    case OP_T_ADR:
      relevant = IsRegRelevant (op.content.mem.base)
                 || IsRegRelevant (op.content.mem.index);
      break;

    case OP_T_IMM:
    case OP_T_NONE:
    default:
      break;
    }
  return relevant;
}

static bool
IsInsRelevant (INS ins)
{
  bool irrelevant = INS_IsBranch (ins) || INS_IsCall (ins) || INS_IsNop (ins);
  return !irrelevant;
}

static size_t
FilterOp (OP *dst, const OP *const op, size_t n, OP_T type, OP_RW rw)
{
  OP *last = std::remove_copy_if (op, op + n, dst, [=] (OP op) {
    return !(op.t == type && (op.rw & rw) == rw);
  });
  return last - dst;
}

static size_t
CopyMemReg (REG *dst, const OP *const op, size_t n, OP_T t, OP_RW rw)
{
  OP adr[OP_MAX_OP_COUNT];
  size_t nadr = FilterOp (adr, op, n, t, rw);
  size_t nreg = 0;
  for (size_t i = 0; i < nadr; ++i)
    {
      if (IsRegRelevant (adr[i].content.mem.base))
        {
          dst[nreg++] = adr[i].content.mem.base;
        }
      if (IsRegRelevant (adr[i].content.mem.index))
        {
          dst[nreg++] = adr[i].content.mem.index;
        }
    }
  return nreg;
}

static size_t
CopyReg (REG *dst, const OP *const op, size_t n, OP_RW rw)
{
  auto copy_reg_reg = [] (REG *dst, const OP *const op, size_t n, OP_RW rw) {
    OP reg[OP_MAX_OP_COUNT];
    size_t nreg = FilterOp (reg, op, n, OP_T_REG, rw);
    std::transform (reg, reg + nreg, dst,
                    [] (OP op) { return op.content.reg; });
    return nreg;
  };

  size_t nreg_reg = copy_reg_reg (dst, op, n, rw);
  size_t nadr_reg = CopyMemReg (dst + nreg_reg, op, n, OP_T_ADR, rw);
  return nreg_reg + nadr_reg;
}

static void
InitInsReg (INS_REG *regs, INS ins)
{
  OP op[OP_MAX_OP_COUNT];
  size_t nop = std::remove_if (op, op + INS_Operands (ins, op),
                               [] (OP op) { return !IsOpRelevant (op); })
               - op;
  regs->reg_r.size = CopyReg (regs->reg_r.data, op, nop, OP_RW_R);
  regs->reg_w.size = CopyReg (regs->reg_w.data, op, nop, OP_RW_W);
  regs->mem_r.size = CopyMemReg (regs->mem_r.data, op, nop, OP_T_MEM, OP_RW_R);
  regs->mem_w.size = CopyMemReg (regs->mem_w.data, op, nop, OP_T_MEM, OP_RW_W);

  REG_ARRAY *ra[] = { &regs->reg_r, &regs->reg_w, &regs->mem_r, &regs->mem_w };
  for (auto r : ra)
    {
      r->size = std::unique (r->data, r->data + r->size) - r->data;
      std::transform (r->data, r->data + r->size, r->data, [] (REG reg) {
        return (REG)MapReg (REG_FullRegName (reg));
      });
    }
}

static void
InitInsInfo (INS_INFO *info, INS ins)
{
  info->addr = (void *)INS_Address (ins);
  info->disassemble = INS_Disassemble (ins);
  info->rtn = RTN_Valid (INS_Rtn (ins)) ? RTN_Name (INS_Rtn (ins)) : "";
  if (RTN_Valid (INS_Rtn (ins))
      && IMG_Valid (SEC_Img (RTN_Sec (INS_Rtn (ins)))))
    {
      IMG img = SEC_Img (RTN_Sec (INS_Rtn (ins)));
      info->img = UT_StripPath (IMG_Name (img).c_str ());
      info->load_offset = (void *)IMG_LoadOffset (img);
    }
  InitInsReg (&info->regs, ins);
}

static void
InsertAddr (void *addr)
{
  addr_any.insert (addr);
}

static void
DumpHeader ()
{
  fprintf (
      out,
      "executed,addr_mem,addr_any,ins_addr,img,rtn,load_offset,from,val\n");
}

static void
DumpState (const INS_INFO *info)
{
  fprintf (out, "%zu,%zu,%zu,%p,%s,%s,%p\n", nexecuted, addr_mem_tab.size (),
           addr_any.size (), info->addr, info->img.c_str (),
           info->rtn.c_str (), info->load_offset);
}

static void
DumpDetailedState (const INS_INFO *info, void *from, void *val)
{
  fprintf (out, "%zu,%zu,%zu,%p,%s,%s,%p,%p,%p\n", nexecuted,
           addr_mem_tab.size (), addr_any.size (), info->addr,
           info->img.c_str (), info->rtn.c_str (), info->load_offset, from,
           val);
}

static void
OnAddrMark (void *from, void *val, void *)
{
  auto it = addr_mem_tab.find (from);
  if (it == addr_mem_tab.end ())
    {
      addr_mem_tab[from] = val;
      if (period == 1)
        {
          DumpDetailedState (current_ins_info, from, val);
        }
      else if (nexecuted > warmup && nexecuted - last_dump_nexecuted >= period)
        {
          DumpState (current_ins_info);
          last_dump_nexecuted = nexecuted;
        }
    }
}

static void
OnAddrUnmark (void *ea, void *)
{
  auto it = addr_mem_tab.find (ea);
  if (it != addr_mem_tab.end ())
    {
      addr_mem_tab.erase (it);
      if (period == 1)
        {
          DumpDetailedState (current_ins_info, ea, nullptr);
        }
      else if (nexecuted > warmup && nexecuted - last_dump_nexecuted >= period)
        {
          DumpState (current_ins_info);
          last_dump_nexecuted = nexecuted;
        }
    }
}

void
IPG_Init ()
{
  pg = PG_CreatePropagator ();
  PG_AddToAddressMarkHook (pg, OnAddrMark, 0);
  PG_AddToAddressUnmarkHook (pg, OnAddrUnmark, 0);
  PG_SetRegMapFn (pg, [] (uint32_t reg, char str[16]) {
    std::string cppstr = "%" + REG_StringShort (InverseMapReg (reg));
    std::strcpy (str, cppstr.c_str ());
  });
  PG_SetInsAddrFn (pg, [] () {
    return (uint64_t)current_ins_info->addr
           - (uint64_t)current_ins_info->load_offset;
  });
}

void
IPG_SetDumpFile (FILE *file)
{
  out = file;
}

void
IPG_SetDumpPeriod (size_t every_nins)
{
  period = every_nins;
}

void
IPG_SetWarmup (size_t nins)
{
  warmup = nins;
}

void
IPG_SetWatch (bool shouldWatch)
{
  PG_SetWatch (pg, shouldWatch);
}

void
IPG_DumpHeader ()
{
  DumpHeader ();
}

void
IPG_InstrumentIns (INS ins)
{
  if (ins_addr.count ((void *)INS_Address (ins)))
    return;

  INS_InsertCall (
      ins, IPOINT_BEFORE, (AFUNPTR)(void (*) ())[] { ++nexecuted; }, IARG_END);

  if (!IsInsRelevant (ins))
    return;

  ins_info.push_back (INS_INFO ());
  INS_INFO &info = ins_info.back ();
  InitInsInfo (&info, ins);

  INS_InsertCall (
      ins, IPOINT_BEFORE,
      (AFUNPTR)(void (*) (const INS_INFO *))[](const INS_INFO *info) {
        current_ins_info = info;
      },
      IARG_PTR, &info, IARG_END);

  INS_REG &regs = info.regs;

  if (!regs.mem_r.size && !regs.mem_w.size)
    {
      INS_InsertCall (
          ins, IPOINT_BEFORE,                                       /**/
          (AFUNPTR)PG_PropagateRegToReg,                            /**/
          IARG_PTR, pg,                                             /**/
          IARG_PTR, regs.reg_w.data, IARG_ADDRINT, regs.reg_w.size, /**/
          IARG_PTR, regs.reg_r.data, IARG_ADDRINT, regs.reg_r.size, /**/
          IARG_END);
    }

  if (regs.mem_r.size)
    {
      INS_InsertCall (
          ins, IPOINT_BEFORE,                                       /**/
          (AFUNPTR)PG_PropagateMemToReg,                            /**/
          IARG_PTR, pg,                                             /**/
          IARG_PTR, regs.reg_w.data, IARG_ADDRINT, regs.reg_w.size, /**/
          IARG_PTR, regs.mem_r.data, IARG_ADDRINT, regs.mem_r.size, /**/
          IARG_PTR, regs.reg_r.data, IARG_ADDRINT, regs.reg_r.size, /**/
          IARG_MEMORYREAD_EA,                                       /**/
          IARG_END);

      INS_InsertCall (ins, IPOINT_BEFORE,  /**/
                      (AFUNPTR)InsertAddr, /**/
                      IARG_MEMORYREAD_EA,  /**/
                      IARG_END);
    }

  if (regs.mem_w.size)
    {
      INS_InsertCall (
          ins, IPOINT_BEFORE,                                       /**/
          (AFUNPTR)PG_PropagateRegToMem,                            /**/
          IARG_PTR, pg,                                             /**/
          IARG_PTR, regs.mem_w.data, IARG_ADDRINT, regs.mem_w.size, /**/
          IARG_PTR, regs.reg_r.data, IARG_ADDRINT, regs.reg_r.size, /**/
          IARG_MEMORYWRITE_EA,                                      /**/
          IARG_END);

      INS_InsertCall (ins, IPOINT_BEFORE,  /**/
                      (AFUNPTR)InsertAddr, /**/
                      IARG_MEMORYWRITE_EA, /**/
                      IARG_END);
    }

  if (INS_Opcode (ins) == XED_ICLASS_XOR && !regs.mem_r.size
      && regs.reg_r.size == 1 && regs.reg_w.size == 1
      && regs.reg_r.data[0] == regs.reg_w.data[0])
    {
      INS_InsertCall (ins, IPOINT_BEFORE,              /**/
                      (AFUNPTR)PG_PropagateRegClear,   /**/
                      IARG_PTR, pg,                    /**/
                      IARG_UINT32, regs.reg_r.data[0], /**/
                      IARG_END);
    }
}

void
IPG_InstrumentWatch (RTN watch)
{
  RTN_InsertCall (
      watch, IPOINT_BEFORE, /**/
      (AFUNPTR)(void (*) (void *, size_t))[](void *addr, size_t size) {
        PG_Watch (pg, addr, size);
      },                                /**/
      IARG_FUNCARG_ENTRYPOINT_VALUE, 0, /**/
      IARG_FUNCARG_ENTRYPOINT_VALUE, 1, /**/
      IARG_END);
}

void
IPG_InstrumentUnwatch (RTN unwatch)
{
  RTN_InsertCall (
      unwatch, IPOINT_BEFORE, /**/
      (AFUNPTR)(void (*) (void *))[](void *addr) {
        PG_Unwatch (pg, addr);
      },                                /**/
      IARG_FUNCARG_ENTRYPOINT_VALUE, 0, /**/
      IARG_END);
}

void
IPG_Fini ()
{
  PG_DestroyPropagator (pg);
}
