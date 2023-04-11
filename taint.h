/*
 * clueless --- Characterises vaLUEs Leaking as addrESSes
 * Copyright (C) 2022, 2023  Xiaoyue Chen
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

#ifndef TAINT_H
#define TAINT_H

#include <bitset>
#include <cstddef>

namespace clueless
{

class taint
{
public:
  constexpr static size_t N = 128;

  taint () = default;

  constexpr bool
  operator== (taint other) const
  {
    return i_ == other.i_;
  }

  constexpr bool
  operator!= (taint other) const
  {
    return !(*this == other);
  }

  constexpr operator size_t () const { return i_; }

private:
  explicit constexpr
  taint (size_t i)
      : i_ (i)
  {
  }

  size_t i_ = 0;

  friend class taint_set;
  friend class taint_queue;
};

}

#endif
