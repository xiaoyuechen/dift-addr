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
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "taint-cache.hpp"
#include "taint-queue.hpp"
#include "taint-table.hpp"
#include "taint.hpp"

#define NREG 64

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
  TAINT_TABLE<64> tt{};
  TAINT_CACHE<64, 4> tc{};
  TAINT_QUEUE queue{};

  void *tea[NTAINT] = {};
  PG_ADDRESS_MARK_HOOK addr_mark_hook;
  PG_ADDRESS_UNMARK_HOOK addr_unmark_hook;
  bool watch = false;
  std::set<WATCH_BLOCK> watch_set{};
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

void
OnRegAsAddr (PG_PROPAGATOR *pg, const uint32_t *reg, size_t n, void *ea)
{
  for (size_t i = 0; i < n; ++i)
    {
      for (size_t t = 0; t < NTAINT; ++t)
        {
          if (pg->tt.Read (reg[i])[t])
            {
              ClearTaint (pg, t);
              InvokeAddressMarkCallback (&pg->addr_mark_hook[0],
                                         pg->addr_mark_hook.size (),
                                         pg->tea[t], ea);
            }
        }
    }
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
                      const uint32_t *mem_r, size_t nmem_r, void *ea)
{
  OnRegAsAddr (pg, mem_r, nmem_r, ea);

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
          pg->tt.Write (reg_w[i], TAINT_ARRAY{}.set (t));
        }
    }
  else
    {
      for (size_t i = 0; i < nreg_w; ++i)
        {
          pg->tt.Write (reg_w[i], TAINT_ARRAY{});
        }
    }

  TAINT_ARRAY ta;
  if (pg->tc.Read (ea, &ta))
    {
      for (size_t i = 0; i < nreg_w; ++i)
        {
          pg->tt.Write (reg_w[i], pg->tt.Read (reg_w[i]) | ta);
        }
    }
}

void
PG_PropagateRegToMem (PG_PROPAGATOR *pg, const uint32_t *mem_w, size_t nmem_w,
                      const uint32_t *reg_r, size_t nreg_r, void *ea)
{
  TAINT_ARRAY src = {};
  for (size_t i = 0; i < nreg_r; ++i)
    {
      src |= pg->tt.Read (reg_r[i]);
    }

  pg->tc.Write (ea, src);

  OnRegAsAddr (pg, mem_w, nmem_w, ea);
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
