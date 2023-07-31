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
#include <bits/ranges_algo.h>
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
    case instr::opcode::OP_NOP:
    default:
      break;
    }
}

void
propagator::reg_to_reg (const instr &ins)
{
  if (!(ins.src_reg.size () && ins.dst_reg.size ()))
    return;

  /* Union all source registers' taint sets */
  auto ts = union_reg_taint_sets (ins.src_reg);

  for (auto dst_reg : ins.dst_reg)
    {
      for (auto src_reg : ins.src_reg)
        {
          for (auto t : reg_taint_[src_reg])
            {
              propagation_level_[dst_reg][t]
                  = propagation_level_[src_reg][t] + 1;
            }
        }
    }

  using namespace std::ranges;
  for_each (ins.dst_reg, [=, this] (auto reg) { reg_taint_[reg] = ts; });
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
  for_each (ins.dst_reg, [=, this] (auto reg) {
    for_each (propagation_level_[reg], [] (auto &lvl) { lvl = 0; });
  });

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

  /* Run pointer found hook */
  auto exposed_secret = std::vector<secret_exposed_hook_param::secret>{};
  for (auto reg : ins.mem_reg)
    {
      for (auto t : reg_taint_[reg])
        {
          exposed_secret.emplace_back (secret_exposed_hook_param::secret{
              taint_address_[t], taint_ip_[t], propagation_level_[reg][t] });
        }
    }

  if (!exposed_secret.size ())
    return;

  secret_exposed_hook_.run (secret_exposed_hook_param{
      std::move (exposed_secret), ins.address, ins.ip });
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
  auto t = taint_allocator_.alloc ();
  reg_taint_.remove_all (t);
  return t;
}
}
