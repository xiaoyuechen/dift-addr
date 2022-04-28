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

#ifndef TAINT_QUEUE_HPP
#define TAINT_QUEUE_HPP

#include <cstddef>

#include "taint.hpp"

class TAINT_QUEUE
{
public:
  TAINT_QUEUE ()
  {
    for (TAINT t = 0; t < NTAINT; ++t)
      {
        node[t].taint = t;
        if (t > 1)
          {
            node[t].previous = &node[t - 1];
          }
        if (t < NTAINT - 1)
          {
            node[t].next = &node[t + 1];
          }
      }
    head = &node[0];
    tail = &node[NTAINT - 1];
  }

  size_t
  LRU () const
  {
    return head->taint;
  }

  size_t
  MRU () const
  {
    return tail->taint;
  }

  void
  MakeMRU (TAINT t)
  {
    if (node[t].previous)
      {
        node[t].previous->next = node[t].next;
      }

    if (node[t].next)
      {
        node[t].next->previous = node[t].previous;
      }

    if (head == &node[t])
      {
        head = node[t].next;
      }

    tail->next = &node[t];
    node[t].previous = tail;
    node[t].next = nullptr;
    tail = &node[t];
  }

private:
  struct NODE
  {
    TAINT taint = 0;
    NODE *previous = nullptr;
    NODE *next = nullptr;
  };

  NODE *head, *tail;
  NODE node[NTAINT];
};

#endif
