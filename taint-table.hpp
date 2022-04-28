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

#ifndef TAINT_TABLE_HPP
#define TAINT_TABLE_HPP

#include <cassert>
#include <cstddef>

#include "taint.hpp"

template <size_t NROW> class TAINT_TABLE
{
public:
  TAINT_ARRAY
  Read (size_t row) const
  {
    assert (row < NROW);
    return table[row];
  }

  void
  Write (size_t row, TAINT_ARRAY ta)
  {
    assert (row < NROW);
    table[row] = ta;
  }

  void
  ClearTaint (TAINT t)
  {
    for (size_t r = 0; r < NROW; ++r)
      {
        table[r][t] = false;
      }
  }

  size_t
  Count (TAINT t) const
  {
    size_t count = 0;
    for (size_t r = 0; r < NROW; ++r)
      {
        count += table[r][t];
      }
    return count;
  }

private:
  TAINT_ARRAY table[NROW]{};
};

#endif
