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

#include "propagator.h"
#include <algorithm>
#include <cstdio>
#include <limits>
#include <numeric>
#include <ranges>

namespace clueless
{

void
propagator::propagate (const instr &ins)
{
  switch (ins.op)
    {
    case instr::opcode::OP_REG:
      reg_to_reg (ins);
      break;
    case instr::opcode::OP_LOAD:
      mem_to_reg (ins);
      break;
    case instr::opcode::OP_STORE:
      reg_to_mem (ins);
      break;
    case instr::opcode::OP_BRANCH:
    default:
      break;
    }
}

void
propagator::reg_to_reg (const instr &ins)
{
  if (!(ins.src_reg.size () && ins.dst_reg.size ()))
    return;

  using namespace std::ranges;

  /* Union all source registers' taint sets */
  auto ts = union_reg_taint_sets (ins.src_reg);

  /* Union the taint set with each destination register's taint set */
  for_each (ins.dst_reg, [=, this] (auto reg) { reg_taint_[reg] |= ts; });

  /* Set propagation depth */
  auto depth_of = [this] (auto reg) { return reg_propagation_depth_[reg]; };
  auto min_src_propagation_depth
      = min (ins.src_reg | views::transform (depth_of));
  for_each (ins.dst_reg, [=, this] (auto reg) {
    reg_propagation_depth_[reg] = min_src_propagation_depth + 1;
  });
}

void
propagator::mem_to_reg (const instr &ins)
{
  handle_mem_taint (ins);

  if (!ins.dst_reg.size ())
    return;

  using namespace std::ranges;

  /* Allocate and add new taint to all destination registers' taint sets */
  auto t = alloc_taint ();
  for_each (ins.dst_reg, [=, this] (auto reg) { reg_taint_[reg].add (t); });

  /* Reset propagation depth */
  for_each (ins.dst_reg,
            [=, this] (auto reg) { reg_propagation_depth_[reg] = 0; });

  /* Update taint to pointer table */
  taint_address_[t] = ins.address;
  taint_ip_[t] = ins.ip;
}

void
propagator::reg_to_mem (const instr &ins)
{
  handle_mem_taint (ins);
}

void
propagator::handle_mem_taint (const instr &ins)
{
  if (!ins.mem_reg.size ())
    return;

  using namespace std::ranges;

  /* Union all memory operands' taint sets */
  auto ts = union_reg_taint_sets (ins.mem_reg);

  /* Free every taint in the taint set */
  for_each (ts, [this] (auto t) { free_taint (t); });

  /* Run pointer found hook */
  auto depth_of = [this] (auto reg) { return reg_propagation_depth_[reg]; };
  auto propagation_depth = min (ins.mem_reg | views::transform (depth_of));
  auto run_hook = [=, this] (auto t) {
    secret_exposed_hook_.run ({ taint_address_[t], ins.address, taint_ip_[t],
                                ins.ip, propagation_depth });
  };
  for_each (ts, run_hook);
}

taint_set
propagator::union_reg_taint_sets (const auto &reg_set) const
{
  using namespace std;
  return transform_reduce (
      begin (reg_set), end (reg_set), taint_set{},
      [] (auto lhs, auto rhs) { return lhs | rhs; },
      [this] (auto reg) { return reg_taint_[reg]; });
}

taint
propagator::alloc_taint ()
{
  using namespace std::ranges;
  auto found = find_if (rbegin (taint_queue_), rend (taint_queue_),
                        [=, this] (auto t) { return !reg_taint_.count (t); });
  auto t_rit = found;
  if (found == rend (taint_queue_))
    {
      t_rit = taint_queue_.rbegin ();
      free_taint (*t_rit);
      taint_exhausted_hook_.run (*t_rit);
    }

  taint_queue_.move_to_front (next (t_rit).base ());
  return *t_rit;
}

void
propagator::free_taint (taint t)
{
  reg_taint_.remove_all (t);
}

}
