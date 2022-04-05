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

#include "taint-table.hpp"
#include "minicut-main.h"
#include "minicut-mini.h"
#include "operand.hpp"
#include <cstddef>

static constexpr size_t nrow = 32;
static constexpr size_t ntaint = 8;

MC_test (clean_after_construction)
{
  TAINT_TABLE<nrow, ntaint> tt;
  for (size_t r = 0; r < nrow; ++r)
    for (size_t t = 0; t < ntaint; ++t)
      MC_assert (!tt.IsTainted (r, t));

  MC_assert (tt.NextAvailableTaint () == 0);
  MC_assert (tt.GetExhaustionCount () == 0);
}

MC_test (next_available_taint)
{
  TAINT_TABLE<nrow, ntaint> tt;
  MC_assert (tt.NextAvailableTaint () == 0);
  tt.Taint (0, 0);
  MC_assert (tt.NextAvailableTaint () == 1);
  tt.Taint (1, 0);
  MC_assert (tt.NextAvailableTaint () == 1);
  tt.Taint (1, 1);
  MC_assert (tt.NextAvailableTaint () == 2);
  tt.Taint (1, 3);
  MC_assert (tt.NextAvailableTaint () == 2);
  tt.Untaint (1, 1);
  MC_assert (tt.NextAvailableTaint () == 1);
  tt.Untaint (1, 0);
  MC_assert (tt.NextAvailableTaint () == 1);
  tt.Untaint (0, 0);
  MC_assert (tt.NextAvailableTaint () == 0);
}

MC_test (to_string)
{
  TAINT_TABLE<1, ntaint> tt;
  MC_assert (tt.ToString () == "00000000\n");
  tt.Taint (0, 1);
  MC_assert (tt.ToString () == "00000010\n");
}
