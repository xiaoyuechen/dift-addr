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

#ifndef TAINT_CACHE_HPP
#define TAINT_CACHE_HPP

#include <cstddef>

#include "taint.hpp"

template <size_t NSET> class ADDR_MAP
{
public:
  static constexpr size_t NWORD_BIT = 2;
  static constexpr size_t NIDX_BIT
      = (unsigned)(8 * sizeof (size_t) - __builtin_clzll ((NSET)) - 1);
  static constexpr size_t NTAG_BIT
      = 8 * sizeof (size_t) - NIDX_BIT - NWORD_BIT;

  static constexpr size_t
  Idx (void *addr)
  {
    return ((size_t)addr & IdxMask ()) >> NWORD_BIT;
  }

  static constexpr size_t
  Tag (void *addr)
  {
    return ((size_t)addr & TagMask ()) >> (NIDX_BIT + NWORD_BIT);
  }

private:
  static constexpr size_t
  IdxMask ()
  {
    size_t mask = 0;
    for (size_t offset = NWORD_BIT; offset < NIDX_BIT + NWORD_BIT; ++offset)
      {
        mask |= 1ull << offset;
      }
    return mask;
  }

  static constexpr size_t
  TagMask ()
  {
    size_t mask = 0;
    for (size_t offset = NIDX_BIT + NWORD_BIT;
         offset < NIDX_BIT + NWORD_BIT + NTAG_BIT; ++offset)
      {
        mask |= 1ull << offset;
      }
    return mask;
  }
};

template <size_t NSET, size_t NASS> class TAINT_CACHE
{
  using MAP = ADDR_MAP<NSET>;

public:
  bool
  Read (void *addr, TAINT_ARRAY *out) const
  {
    size_t it = set[MAP::Idx (addr)].head;
    do
      {
        if (set[MAP::Idx (addr)].entry[it].tag == MAP::Tag (addr))
          {
            *out = set[MAP::Idx (addr)].entry[it].taint_array;
            return true;
          }
        it = CACHE_SET::NextEntry (it);
      }
    while (it != set[MAP::Idx (addr)].head);
    return false;
  }

  void
  Write (void *addr, TAINT_ARRAY ta)
  {
    size_t it = set[MAP::Idx (addr)].head;
    do
      {
        if (set[MAP::Idx (addr)].entry[it].tag == MAP::Tag (addr))
          {
            set[MAP::Idx (addr)].entry[it].taint_array = ta;
            return;
          }
        it = CACHE_SET::NextEntry (it);
      }
    while (it != set[MAP::Idx (addr)].head);

    size_t evict = CACHE_SET::PreviousEntry (set[MAP::Idx (addr)].head);
    set[MAP::Idx (addr)].entry[evict] = { MAP::Tag (addr), ta };
    set[MAP::Idx (addr)].head = evict;
  }

  void
  ClearTaint (TAINT t)
  {
    for (size_t s = 0; s < NSET; ++s)
      {
        for (size_t ass = 0; ass < NASS; ++ass)
          {
            set[s].entry[ass].taint_array[t] = false;
          }
      }
  }

  size_t
  Count (TAINT t) const
  {
    size_t count = 0;
    for (size_t s = 0; s < NSET; ++s)
      {
        for (size_t ass = 0; ass < NASS; ++ass)
          {
            count += set[s].entry[ass].taint_array[t];
          }
      }

    return count;
  }

private:
  struct CACHE_SET
  {
    size_t head;

    struct CACHE_ENTRY
    {
      size_t tag = MAP::Tag ((void *)~size_t{ 0 });
      TAINT_ARRAY taint_array{};
    } entry[NASS]{};

    static constexpr size_t
    NextEntry (size_t cur)
    {
      return (cur + 1) % NASS;
    }

    static constexpr size_t
    PreviousEntry (size_t cur)
    {
      return (cur + NASS - 1) % NASS;
    }

  } set[NSET]{};
};

#endif
