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

#include "taint-table.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

static constexpr size_t TT_TMP_ROW = TT_NUM_ROW + 1;
using PG_TAINT_TABLE = TAINT_TABLE<TT_TMP_ROW + 1, TT_NUM_TAINT>;
using PG_HASH_TAINT_TABLE = HASH_TAINT_TABLE<TT_TMP_ROW + 1, TT_NUM_TAINT>;

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
  PG_TAINT_TABLE tt{};
  PG_HASH_TAINT_TABLE htt{};
  void *tea[TT_NUM_TAINT] = {};
  PG_ADDRESS_MARK_HOOK addr_mark_hook;
  PG_ADDRESS_UNMARK_HOOK addr_unmark_hook;
  bool watch = false;
  std::set<WATCH_BLOCK> watch_set{};
};

void *watch_addr;

bool
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
  watch_addr = addr;
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
PG_PropagateRegToReg (PG_PROPAGATOR *pg, const uint32_t *w, size_t nw,
                      const uint32_t *r, size_t nr)
{
  PG_TAINT_TABLE &tt = pg->tt;
  for (size_t i = 0; i < nr; ++i)
    {
      tt.Union (TT_TMP_ROW, TT_TMP_ROW, r[i]);
    }
  for (size_t i = 0; i < nw; ++i)
    {
      tt.Diff (w[i], w[i], w[i]);
      tt.Union (w[i], TT_TMP_ROW, TT_TMP_ROW);
    }
  tt.Diff (TT_TMP_ROW, TT_TMP_ROW, TT_TMP_ROW);
}

void
PG_PropagateMemToReg (PG_PROPAGATOR *pg, const uint32_t *reg_w, size_t nreg_w,
                      const uint32_t *mem_r, size_t nmem_r, void *ea)
{
  PG_TAINT_TABLE &tt = pg->tt;
  PG_HASH_TAINT_TABLE &htt = pg->htt;
  void **tea = pg->tea;

  for (size_t i = 0; i < nmem_r; ++i)
    for (size_t t = 0; t < TT_NUM_TAINT; ++t)
      if (tt.IsTainted (mem_r[i], t))
        {
          tt.UntaintCol (t);
          htt.UntaintCol (t);
          InvokeAddressMarkCallback (&pg->addr_mark_hook[0],
                                     pg->addr_mark_hook.size (), tea[t], ea);
        }

  for (size_t i = 0; i < nreg_w; ++i)
    {
      tt.Diff (reg_w[i], reg_w[i], reg_w[i]);
    }

  if (IsAddressWatched (pg, ea))
    {
      size_t t = tt.NextAvailableTaint ();
      tea[t] = ea;
      for (size_t i = 0; i < nreg_w; ++i)
        {
          tt.Taint (reg_w[i], t);
        }
    }
  else if (pg->watch)
    {
      for (size_t i = 0; i < nreg_w; ++i)
        for (size_t t = 0; t < TT_NUM_TAINT; ++t)
          if (pg->htt.IsTainted (ea, t))
            {
              tt.Taint (reg_w[i], t);
            }
    }
}

void
PG_PropagateRegToMem (PG_PROPAGATOR *pg, const uint32_t *mem_w, size_t nmem_w,
                      const uint32_t *reg_r, size_t nreg_r, void *ea)
{
  PG_TAINT_TABLE &tt = pg->tt;
  PG_HASH_TAINT_TABLE &htt = pg->htt;
  void **tea = pg->tea;

  for (size_t i = 0; i < nmem_w; ++i)
    for (size_t t = 0; t < TT_NUM_TAINT; ++t)
      if (tt.IsTainted (mem_w[i], t))
        {
          tt.UntaintCol (t);
          InvokeAddressMarkCallback (&pg->addr_mark_hook[0],
                                     pg->addr_mark_hook.size (), tea[t], ea);
        }

  if (pg->watch)
    {
      for (size_t i = 0; i < nreg_r; ++i)
        for (size_t t = 0; t < TT_NUM_TAINT; ++t)
          if (tt.IsTainted (reg_r[i], t))
            {
              htt.Taint (ea, t);
            }
    }

  InvokeAddressUnmarkCallback (&pg->addr_unmark_hook[0],
                               pg->addr_unmark_hook.size (), ea);
}

void
PG_PropagateRegClear (PG_PROPAGATOR *pg, uint32_t r)
{
  pg->tt.Diff (r, r, r);
}

void
PG_PropagateRegExchange (PG_PROPAGATOR *pg, uint32_t r1, uint32_t r2)
{
  PG_TAINT_TABLE &tt = pg->tt;
  tt.Union (TT_TMP_ROW, TT_TMP_ROW, r1);
  tt.Diff (r1, r1, r1);
  tt.Union (r1, r1, r2);
  tt.Diff (r2, r2, r2);
  tt.Union (r2, TT_TMP_ROW, TT_TMP_ROW);
  tt.Diff (TT_TMP_ROW, TT_TMP_ROW, TT_TMP_ROW);
}

size_t
PG_TaintExhaustionCount (const PG_PROPAGATOR *pg)
{
  return pg->tt.GetExhaustionCount ();
}

bool
PG_IsTainted (const PG_PROPAGATOR *pg, uint32_t r, uint32_t t)
{
  return pg->tt.IsTainted (r, t);
}
