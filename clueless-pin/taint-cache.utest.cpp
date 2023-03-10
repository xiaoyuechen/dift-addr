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

#include "taint-cache.hpp"
#include "minicut-main.h"
#include "minicut-mini.h"
#include "taint.hpp"
#include <cstddef>

MC_test (number_of_index_and_tag_bits)
{
  MC_assert ((ADDR_MAP<128>::NIDX_BIT) == 7);
  MC_assert ((ADDR_MAP<128>::NTAG_BIT) == 55);
  MC_assert ((ADDR_MAP<64>::NIDX_BIT) == 6);
  MC_assert ((ADDR_MAP<64>::NTAG_BIT) == 56);
}

MC_test (can_map_addr)
{
  MC_assert (ADDR_MAP<64>::Idx (0) == 0);
  MC_assert (ADDR_MAP<64>::Tag (0) == 0);

  MC_assert (ADDR_MAP<64>::Idx ((void *)1) == 0);
  MC_assert (ADDR_MAP<64>::Tag ((void *)1) == 0);

  MC_assert (ADDR_MAP<64>::Idx ((void *)3) == 0);
  MC_assert (ADDR_MAP<64>::Tag ((void *)3) == 0);

  MC_assert (ADDR_MAP<64>::Idx ((void *)4) == 1);
  MC_assert (ADDR_MAP<64>::Tag ((void *)4) == 0);

  MC_assert (ADDR_MAP<64>::Idx ((void *)0b110100001000) == 0b10);
  MC_assert (ADDR_MAP<64>::Tag ((void *)0b110100001000) == 0b1101);

  MC_assert (ADDR_MAP<64>::Idx ((void *)0b110100001011) == 0b10);
  MC_assert (ADDR_MAP<64>::Tag ((void *)0b110100001011) == 0b1101);
}

MC_test (can_construct_cache) { TAINT_CACHE<128, 8> cache; }

MC_test (can_read)
{
  TAINT_CACHE<64, 4> cache;
  TAINT_ARRAY ta;
  MC_assert (cache.Read ((void *)(~size_t (0)), &ta));
  MC_assert (ta == TAINT_ARRAY{});

  MC_assert (!cache.Read ((void *)0xffff, &ta));
}

MC_test (can_write)
{
  TAINT_CACHE<64, 4> cache;

  TAINT_ARRAY ta{ 0b0111 };
  void *addr = (void *)0x7fffff0d3;
  cache.Write (addr, ta);

  TAINT_ARRAY out_ta;
  MC_assert (cache.Read (addr, &out_ta));
  MC_assert (ta == out_ta);

  TAINT_ARRAY ta2{ 0b0110 };
  void *addr2 = (void *)0x8fffff0d3;
  cache.Write (addr2, ta2);
  MC_assert (cache.Read (addr2, &out_ta));
  MC_assert (ta2 == out_ta);
  MC_assert (cache.Read (addr, &out_ta));
  MC_assert (ta == out_ta);

  TAINT_ARRAY ta3{ 0b0110 };
  void *addr3 = (void *)0x9fffff0d3;
  cache.Write (addr3, ta3);
  MC_assert (cache.Read (addr, &out_ta));
  MC_assert (ta == out_ta);

  void *addr4 = (void *)0xafffff0d3;
  cache.Write (addr4, ta3);
  MC_assert (cache.Read (addr, &out_ta));
  MC_assert (ta == out_ta);

  void *addr5 = (void *)0xbfffff0d3;
  cache.Write (addr5, ta3);
  MC_assert (!cache.Read (addr, &out_ta));
}
