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

#include "taint-queue.hpp"
#include "minicut-main.h"
#include "minicut-mini.h"

MC_test (correct_LRU)
{
  TAINT_QUEUE tq;
  MC_assert (tq.LRU () == TAINT (0));
}

MC_test (can_make_MRU)
{
  TAINT_QUEUE tq;
  tq.MakeMRU (0);
  MC_assert (tq.LRU () == TAINT (1));

  tq.MakeMRU (2);
  MC_assert (tq.LRU () == TAINT (1));

  tq.MakeMRU (1);
  MC_assert (tq.LRU () == TAINT (3));

  tq.MakeMRU (1);
  MC_assert (tq.LRU () == TAINT (3));
  MC_assert (tq.MRU () == TAINT (1));
}
