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

#include <algorithm>
#include <bitset>
#include <cassert>
#include <cstddef>
#include <sstream>
#include <string>
#include <unordered_map>

template <size_t NUM_ROW, size_t NUM_TAINT> class TAINT_TABLE
{
public:
  using ROW = size_t;
  using TAINT = size_t;
  using TAINT_SET = std::bitset<NUM_TAINT>;

  bool
  IsTainted (ROW row, TAINT taint) const
  {
    assert (row < NUM_ROW && taint < NUM_TAINT);

    return table_[row][taint];
  }

  void
  Taint (ROW row, TAINT taint)
  {
    assert (row < NUM_ROW && taint < NUM_TAINT);

    if (table_[row][taint])
      return;

    table_[row][taint] = true;

    timestamp_[taint] = time_++;
  }

  void
  Untaint (ROW row, TAINT taint)
  {
    assert (row < NUM_ROW && taint < NUM_TAINT);

    if (!table_[row][taint])
      return;

    table_[row][taint] = false;
  }

  void
  UntaintCol (TAINT taint)
  {
    assert (taint < NUM_TAINT);

    for (size_t row = 0; row < NUM_ROW; ++row)
      {
        Untaint (row, taint);
      }
  }

  void
  Union (ROW dst, ROW src1, ROW src2)
  {
    assert (dst < NUM_ROW && src1 < NUM_ROW && src2 < NUM_ROW);

    table_[dst] = table_[src1] | table_[src2];
  }

  void
  Diff (ROW dst, ROW src1, ROW src2)
  {
    assert (dst < NUM_ROW && src1 < NUM_ROW && src2 < NUM_ROW);

    table_[dst] = table_[src1] ^ table_[src2];
  }

  TAINT
  NextAvailableTaint ()
  {
    TAINT taint;

    size_t taint_count[NUM_TAINT]{};
    for (ROW r = 0; r < NUM_ROW; ++r)
      {
        for (TAINT t = 0; t < NUM_TAINT; ++t)
          {
            taint_count[t] += table_[r][t];
          }
      }

    size_t *available = std::find (taint_count, taint_count + NUM_TAINT, 0);
    if (available != taint_count + NUM_TAINT)
      {
        taint = available - taint_count;
      }
    else
      {
        size_t *oldest = std::min_element (timestamp_, timestamp_ + NUM_TAINT);
        taint = oldest - timestamp_;
        UntaintCol (taint);

        ++exhaustion_count_;
      }

    return taint;
  }

  std::string
  ToString (std::string (*start_line) (ROW) = nullptr, ROW first = 0,
            ROW last = NUM_ROW) const
  {
    std::stringstream buff{};
    for (const std::bitset<NUM_TAINT> *it = table_ + first;
         it != table_ + last; ++it)
      {
        if (start_line)
          {
            buff << start_line (it - table_);
          }
        buff << *it << "\n";
      }
    return buff.str ();
  }

  size_t
  GetExhaustionCount () const
  {
    return exhaustion_count_;
  }

private:
  TAINT_SET table_[NUM_ROW]{};
  size_t time_ = 0;
  size_t timestamp_[NUM_TAINT]{};
  size_t exhaustion_count_ = 0;
};

template <size_t NUM_ROW, size_t NUM_TAINT> class HASH_TAINT_TABLE
{
public:
  using ROW = void *;
  using TAINT = size_t;
  using TAINT_SET = std::bitset<NUM_TAINT>;

  bool
  IsTainted (ROW row, TAINT taint) const
  {
    auto it = table_.find (row);
    if (it != table_.end ())
      {
        return it->second[taint];
      }

    return false;
  }

  void
  Taint (ROW row, TAINT taint)
  {
    table_[row][taint] = true;
  }

  void
  Untaint (ROW row, TAINT taint)
  {
    auto it = table_.find (row);
    if (it == table_.end ())
      return;

    it->second[taint] = false;
    if (it->second.none ())
      {
        table_.erase (it);
      }
  }

  void
  UntaintCol (TAINT taint)
  {
    assert (taint < NUM_TAINT);

    for (auto it = table_.begin (); it != table_.end (); ++it)
      {
        it->second[taint] = false;
      }
  }

private:
  std::unordered_map<void *, TAINT_SET> table_{};
};

#endif
