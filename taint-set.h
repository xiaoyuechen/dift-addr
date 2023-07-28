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

#ifndef TAINT_SET_H
#define TAINT_SET_H

#include "taint.h"

#include <algorithm>
#include <bitset>
#include <cstddef>
#include <iterator>
#include <ranges>

namespace clueless
{

class taint_set
{
public:
  class const_iterator
  {
  public:
    using iterator_category = std::forward_iterator_tag;
    using difference_type = ptrdiff_t;
    using value_type = taint;

    constexpr const_iterator () = default;

    constexpr
    const_iterator (taint t, const taint_set &ts)
        : taint_ (t), taint_set_ (&ts)
    {
    }

    constexpr bool
    operator== (const_iterator other) const
    {
      return taint_ == other.taint_;
    };

    constexpr bool
    operator!= (const_iterator other) const
    {
      return !(*this == other);
    }

    constexpr const taint &
    operator* () const
    {
      return taint_;
    }

    const_iterator &
    operator++ ()
    {
      using namespace std::ranges;
      auto range = views::iota (taint_ + 1, taint::N);
      auto found = find_if (
          range, [this] (auto i) { return taint_set_->set_.test (i); });
      taint_ = found == range.end () ? taint (taint::N) : taint (*found);
      return *this;
    }

    const_iterator
    operator++ (int)
    {
      auto rtn = *this;
      ++(*this);
      return rtn;
    }

  private:
    taint taint_ = {};
    const taint_set *taint_set_ = nullptr;
  };

  taint_set &
  operator|= (taint_set other)
  {
    set_ |= other.set_;
    return *this;
  }

  taint_set &
  add (taint t)
  {
    set_.set (t);
    return *this;
  }

  taint_set &
  remove (taint t)
  {
    set_.reset (t);
    return *this;
  }

  bool
  test (taint t) const
  {
    return set_.test (t);
  }

  bool
  empty () const
  {
    return !set_.any ();
  }

  const_iterator
  begin () const
  {
    for (size_t i = 0; i < taint::N; ++i)
      {
        if (set_.test (i))
          {
            return const_iterator{ taint{ i }, *this };
          }
      }
    return const_iterator{ taint{ taint::N }, *this };
  }

  const_iterator
  end () const
  {
    return const_iterator{ taint{ taint::N }, *this };
  }

private:
  std::bitset<taint::N> set_ = {};
};

inline taint_set
operator| (taint_set lhs, taint_set rhs)
{
  return lhs |= rhs;
}

}

#endif
