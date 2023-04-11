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

#ifndef TAINT_QUEUE_H
#define TAINT_QUEUE_H

#include "taint.h"
#include <algorithm>
#include <list>

namespace clueless
{

class taint_queue
{
public:
  using queue = std::list<taint>;
  using const_iterator = queue::const_iterator;
  using const_reverse_iterator = queue::const_reverse_iterator;

  taint_queue ()
  {
    queue_.resize (taint::N);
    generate (std::rbegin (queue_), std::rend (queue_),
              [i = size_t{ 0 }] () mutable { return taint{ i++ }; });
  }

  const_iterator
  begin () const
  {
    return queue_.begin ();
  }

  const_iterator
  end () const
  {
    return queue_.end ();
  }

  const_reverse_iterator
  rbegin () const
  {
    return queue_.rbegin ();
  }

  const_reverse_iterator
  rend () const
  {
    return queue_.rend ();
  }

  void
  move_to_front (const_iterator it)
  {
    queue_.splice (std::begin (queue_), queue_, it);
  }

private:
  queue queue_;
};

}

#endif
