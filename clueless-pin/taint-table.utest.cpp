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
  TAINT_TABLE<nrow> tt;
  for (size_t r = 0; r < nrow; ++r)
    MC_assert (tt.Read (r).none ());
}
