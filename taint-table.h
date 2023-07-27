/*
 * clueless --- Characterises vaLUEs Leaking as addrESSes
 * Copyright (C) 2023  Xiaoyue Chen
 *
 * This file is part of clueless.
 *
 * clueless is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * clueless is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with clueless.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef TAINT_TABLE_H
#define TAINT_TABLE_H

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <optional>
#include <ranges>

#include "taint-set.h"

namespace clueless
{

class reg_taint_table
{
public:
  static constexpr size_t NREG = 256;

  using value_type = taint_set;
  using reference = taint_set &;
  using const_reference = const value_type &;

  constexpr const_reference &
  operator[] (size_t reg) const
  {
    return table_[reg];
  }

  constexpr reference &
  operator[] (size_t reg)
  {
    return table_[reg];
  }

  void
  remove_all (taint t)
  {
    using namespace std::ranges;
    transform (table_, begin (table_),
               [=] (auto ts) { return ts.remove (t); });
  }

  size_t
  count (taint t) const
  {
    using namespace std::ranges;
    return count_if (table_, [=] (auto ts) { return ts.test (t); });
  }

private:
  std::array<value_type, NREG> table_ = {};
};

class taint_address_table
{
public:
  using value_type = unsigned long long;
  using reference = value_type &;
  using const_reference = const value_type &;

  constexpr const_reference &
  operator[] (taint t) const
  {
    assert (t < taint::N);
    return table_[t];
  }

  constexpr reference &
  operator[] (taint t)
  {
    assert (t < taint::N);
    return table_[t];
  }

private:
  std::array<value_type, taint::N> table_;
};
}

#endif
