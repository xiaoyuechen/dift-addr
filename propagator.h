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

#ifndef PROPAGATOR_H
#define PROPAGATOR_H

#include "hook.h"
#include "taint-queue.h"
#include "taint-table.h"
#include <array>
#include <functional>
#include <vector>

namespace clueless
{

class propagator
{
public:
  struct instr
  {
    using reg_set = std::vector<unsigned char>;

    enum class opcode
    {
      OP_REG,
      OP_LOAD,
      OP_STORE,
      OP_BRANCH
    } op;

    unsigned long long ip;

    reg_set src_reg;
    reg_set dst_reg;
    reg_set mem_reg;

    unsigned long long address;
  };

  struct secret_exposed_hook_param
  {
    unsigned long long secret_address, transmit_address, access_ip,
        transmit_ip;
    bool is_indirect;
  };

  using secret_exposed_hook = hook<secret_exposed_hook_param>;

  using taint_exhausted_hook = hook<taint>;

  void propagate (const instr &ins);

  void
  add_secret_exposed_hook (secret_exposed_hook::function f)
  {
    secret_exposed_hook_.add (f);
  }

  void
  add_taint_exhausted_hook (taint_exhausted_hook::function f)
  {
    taint_exhausted_hook_.add (f);
  }

private:
  void reg_to_reg (const instr &ins);
  void mem_to_reg (const instr &ins);
  void reg_to_mem (const instr &ins);
  void handle_mem_taint (const instr &ins);

  taint_set union_reg_taint_sets (const auto &reg_set) const;

  taint alloc_taint ();
  void free_taint (taint t);

  taint_queue taint_queue_ = {};
  reg_taint_table reg_taint_ = {};
  taint_address_table taint_address_ = {};
  taint_address_table taint_ip_ = {};
  secret_exposed_hook secret_exposed_hook_ = {};
  taint_exhausted_hook taint_exhausted_hook_ = {};
  using reg_propagation_indirect_table = std::array<bool, 256>;
  reg_propagation_indirect_table reg_propagation_indirect_ = {};
};

}

#endif
