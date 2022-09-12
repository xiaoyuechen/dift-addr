/*
 * dift-addr --- Dynamic Information Flow Tracking on memory ADDResses
 * Copyright (C) 2022  Xiaoyue Chen
 *
 * This file is part of dift-addr.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "propagation.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <set>
#include <stl/_algo.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "taint-cache.hpp"
#include "taint-queue.hpp"
#include "taint-table.hpp"
#include "taint.hpp"

#ifndef DEBUG
#define DEBUG 1
#endif

#define NREG 128

struct ADDRESS_MARK_CALLBACK
{
  PG_ADDRESS_MARK_FN fn;
  void *user_ptr;
};

struct ADDRESS_UNMARK_CALLBACK
{
  PG_ADDRESS_UNMARK_FN fn;
  void *user_ptr;
};

using PG_ADDRESS_MARK_HOOK = std::vector<ADDRESS_MARK_CALLBACK>;
using PG_ADDRESS_UNMARK_HOOK = std::vector<ADDRESS_UNMARK_CALLBACK>;

struct WATCH_BLOCK
{
  void *begin, *end;
};

constexpr bool
operator< (WATCH_BLOCK lhs, WATCH_BLOCK rhs)
{
  return lhs.begin < rhs.begin;
}

struct PG_PROPAGATOR
{
  TAINT_TABLE<NREG> tt{};
  TAINT_CACHE<64, 4> tc{};
  TAINT_QUEUE queue{};

  void *tea[NTAINT] = {};
  PG_ADDRESS_MARK_HOOK addr_mark_hook;
  PG_ADDRESS_UNMARK_HOOK addr_unmark_hook;
  bool watch = false;
  std::set<WATCH_BLOCK> watch_set{};
  PG_REG_MAP_FN reg_map_fn{};
  PG_INS_ADDR_FN ins_addr_fn{};
};

static bool
IsAddressWatched (const PG_PROPAGATOR *pg, void *addr)
{
  if (!pg->watch)
    {
      return true;
    }

  if (!pg->watch_set.empty ())
    {
      auto lub = pg->watch_set.upper_bound (WATCH_BLOCK{ addr, nullptr });
      auto glb = lub == pg->watch_set.begin () ? lub : --lub;
      if (glb->begin <= addr && addr < glb->end)
        {
          return true;
        }
    }
  return false;
}

PG_PROPAGATOR *
PG_CreatePropagator ()
{
  return new PG_PROPAGATOR{};
}

void
PG_DestroyPropagator (PG_PROPAGATOR *pg)
{
  delete pg;
}

void
PG_SetWatch (PG_PROPAGATOR *pg, bool shouldWatch)
{
  pg->watch = shouldWatch;
}

void
PG_Watch (PG_PROPAGATOR *pg, void *addr, size_t size)
{
  /* TODO: detect overlapping watch */
  pg->watch_set.insert (WATCH_BLOCK{ addr, (unsigned char *)addr + size });
}

void
PG_Unwatch (PG_PROPAGATOR *pg, void *addr)
{
  pg->watch_set.erase (WATCH_BLOCK{ addr, nullptr });
}

void
PG_AddToAddressMarkHook (PG_PROPAGATOR *pg, PG_ADDRESS_MARK_FN fn,
                         void *user_ptr)
{
  pg->addr_mark_hook.emplace_back (ADDRESS_MARK_CALLBACK{ fn, user_ptr });
}

void
PG_AddToAddressUnmarkHook (PG_PROPAGATOR *pg, PG_ADDRESS_UNMARK_FN fn,
                           void *user_ptr)
{
  pg->addr_unmark_hook.emplace_back (ADDRESS_UNMARK_CALLBACK{ fn, user_ptr });
}

void
PG_SetRegMapFn (PG_PROPAGATOR *pg, PG_REG_MAP_FN fn)
{
  pg->reg_map_fn = fn;
}

void
PG_SetInsAddrFn (PG_PROPAGATOR *pg, PG_INS_ADDR_FN fn)
{
  pg->ins_addr_fn = fn;
}

void
InvokeAddressMarkCallback (const ADDRESS_MARK_CALLBACK *callback, size_t n,
                           void *from, void *val)
{
  for (size_t i = 0; i < n; ++i)
    {
      callback[i].fn (from, val, callback[i].user_ptr);
    }
}

void
InvokeAddressUnmarkCallback (const ADDRESS_UNMARK_CALLBACK *callback, size_t n,
                             void *from)
{
  for (size_t i = 0; i < n; ++i)
    {
      callback[i].fn (from, callback[i].user_ptr);
    }
}

void
ClearTaint (PG_PROPAGATOR *pg, TAINT t)
{
  pg->tt.ClearTaint (t);
  pg->tc.ClearTaint (t);
}

std::string
RegsToString (PG_REG_MAP_FN map, const uint32_t *reg, size_t n)
{
  std::string str{};
  for (size_t i = 0; i < n; ++i)
    {
      char reg_str[16];
      if (map)
        {
          map (reg[i], reg_str);
        }
      else
        {
          sprintf (reg_str, "reg %u", reg[i]);
        }
      str += reg_str;
      if (i != n - 1)
        {
          str += " ";
        }
    }
  return str;
}

std::string
TaintedRegsToString (const TAINT_TABLE<NREG> &tt, PG_REG_MAP_FN map,
                     const uint32_t *reg, size_t n)
{
  uint32_t copy[16];
  std::copy (reg, reg + n, copy);
  n = std::remove_if (copy, copy + n,
                      [&] (uint32_t r) { return tt.Read (r).none (); })
      - copy;
  return RegsToString (map, copy, n);
}

std::string
TaintArrayToString (TAINT_ARRAY ta)
{
  std::string str;
  str += "{";
  for (TAINT t = 0; t < NTAINT; ++t)
    {
      if (ta[t])
        {
          char t_str[10];
          sprintf (t_str, " %zu", t);
          str += t_str;
        }
    }
  str += " }";
  return str;
}

void
MarkTaintsAsAddr (PG_PROPAGATOR *pg, TAINT_ARRAY ta, void *ea)
{
  for (TAINT t = 0; t < NTAINT; ++t)
    {
      if (ta[t])
        {
          ClearTaint (pg, t);
          InvokeAddressMarkCallback (&pg->addr_mark_hook[0],
                                     pg->addr_mark_hook.size (), pg->tea[t],
                                     ea);
        }
    }
}

TAINT_ARRAY
OrTaints (const TAINT_TABLE<NREG> &tt, const uint32_t *reg, size_t nreg)
{
  TAINT_ARRAY ta{};
  for (size_t i = 0; i < nreg; ++i)
    {
      ta |= tt.Read (reg[i]);
    }
  return ta;
}

void
PG_PropagateRegToReg (PG_PROPAGATOR *pg, const uint32_t *w, size_t nw,
                      const uint32_t *r, size_t nr)
{
  TAINT_ARRAY src = {};
  for (size_t i = 0; i < nr; ++i)
    {
      src |= pg->tt.Read (r[i]);
    }

  for (size_t i = 0; i < nw; ++i)
    {
      pg->tt.Write (w[i], src);
    }

#if DEBUG
  if (src.any ())
    {
      printf ("%lx:\t%s %s -> %s\n", pg->ins_addr_fn (),
              TaintedRegsToString (pg->tt, pg->reg_map_fn, r, nr).c_str (),
              TaintArrayToString (src).c_str (),
              TaintedRegsToString (pg->tt, pg->reg_map_fn, w, nw).c_str ());
    }
#endif
}

static bool
FindUnusedTaint (const PG_PROPAGATOR *pg, TAINT *out)
{
  for (TAINT t = 0; t < NTAINT; ++t)
    {
      if (!pg->tt.Count (t) && !pg->tc.Count (t))
        {
          *out = t;
          return true;
        }
    }

  return false;
}

void
PG_PropagateMemToReg (PG_PROPAGATOR *pg, const uint32_t *reg_w, size_t nreg_w,
                      const uint32_t *mem_r, size_t nmem_r,
                      const uint32_t *reg_r, size_t nreg_r, void *ea)
{
  {
    TAINT_ARRAY ta = OrTaints (pg->tt, mem_r, nmem_r);
#if DEBUG
    if (ta.any ())
      {
        printf ("%lx:\t[ %s %s ] = %p ->\n", pg->ins_addr_fn (),
                TaintedRegsToString (pg->tt, pg->reg_map_fn, mem_r, nmem_r)
                    .c_str (),
                TaintArrayToString (ta).c_str (), ea);
      }
#endif
    MarkTaintsAsAddr (pg, ta, ea);
  }

  TAINT_ARRAY src_taint_array{};
  for (size_t i = 0; i < nreg_r; ++i)
    {
      src_taint_array |= pg->tt.Read (reg_r[i]);
    }

  for (size_t i = 0; i < nreg_w; ++i)
    {
      pg->tt.Write (reg_w[i], src_taint_array);
    }

  if (src_taint_array.any ())
    {
      printf (
          "%lx:\t%s %s -> %s\n", pg->ins_addr_fn (),
          TaintedRegsToString (pg->tt, pg->reg_map_fn, reg_r, nreg_r).c_str (),
          TaintArrayToString (src_taint_array).c_str (),
          TaintedRegsToString (pg->tt, pg->reg_map_fn, reg_w, nreg_w)
              .c_str ());
    }

  if (IsAddressWatched (pg, ea))
    {
      TAINT t;
      if (!FindUnusedTaint (pg, &t))
        {
          t = pg->queue.LRU ();
          ClearTaint (pg, t);
        }
      pg->queue.MakeMRU (t);

      pg->tea[t] = ea;
      for (size_t i = 0; i < nreg_w; ++i)
        {
          pg->tt.Write (reg_w[i], src_taint_array | TAINT_ARRAY{}.set (t));
        }
#if DEBUG
      printf ("%lx:\t%p %s -> %s\n", pg->ins_addr_fn (), ea,
              TaintArrayToString (TAINT_ARRAY{}.set (t)).c_str (),
              TaintedRegsToString (pg->tt, pg->reg_map_fn, reg_w, nreg_w)
                  .c_str ());
#endif
    }

  TAINT_ARRAY ta;
  if (pg->tc.Read (ea, &ta) && ta.any ())
    {
      for (size_t i = 0; i < nreg_w; ++i)
        {
          pg->tt.Write (reg_w[i], pg->tt.Read (reg_w[i]) | ta);
        }

#if DEBUG
      printf ("%lx:\t%p %s -> %s\n", pg->ins_addr_fn (), ea,
              TaintArrayToString (ta).c_str (),
              TaintedRegsToString (pg->tt, pg->reg_map_fn, reg_w, nreg_w)
                  .c_str ());
#endif
    }
}

void
PG_PropagateRegToMem (PG_PROPAGATOR *pg, const uint32_t *mem_w, size_t nmem_w,
                      const uint32_t *reg_r, size_t nreg_r, void *ea)
{
  TAINT_ARRAY src = OrTaints (pg->tt, reg_r, nreg_r);
  if (src.any ())
    {
#if DEBUG
      printf (
          "%lx:\t%s %s -> %p\n", pg->ins_addr_fn (),
          TaintedRegsToString (pg->tt, pg->reg_map_fn, reg_r, nreg_r).c_str (),
          TaintArrayToString (src).c_str (), ea);
#endif
      pg->tc.Write (ea, src);
    }

  TAINT_ARRAY mem = OrTaints (pg->tt, mem_w, nmem_w);
  if (mem.any ())
    {
#if DEBUG
      printf (
          "%lx:\t-> [ %s %s ] = %p\n", pg->ins_addr_fn (),
          TaintedRegsToString (pg->tt, pg->reg_map_fn, mem_w, nmem_w).c_str (),
          TaintArrayToString (mem).c_str (), ea);
#endif
      MarkTaintsAsAddr (pg, mem, ea);
    }

  InvokeAddressUnmarkCallback (&pg->addr_unmark_hook[0],
                               pg->addr_unmark_hook.size (), ea);
}

void
PG_PropagateRegClear (PG_PROPAGATOR *pg, uint32_t r)
{
  pg->tt.Write (r, TAINT_ARRAY{});
}

void
PG_PropagateRegExchange (PG_PROPAGATOR *pg, uint32_t r1, uint32_t r2)
{
  TAINT_ARRAY tmp = pg->tt.Read (r1);
  pg->tt.Write (r1, pg->tt.Read (r2));
  pg->tt.Write (r2, tmp);
}
