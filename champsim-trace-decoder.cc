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

#include "champsim-trace-decoder.h"

namespace clueless
{

static constexpr unsigned char REG_STACK_POINTER = 6;
static constexpr unsigned char REG_FLAGS = 25;
static constexpr unsigned char REG_INSTRUCTION_POINTER = 26;

static auto count_non_zero = [] (auto begin, auto end) {
  return std::count_if (begin, end, [] (auto test) { return test; });
};

static auto reg_pred = [] (auto reg) {
  return reg && reg != REG_FLAGS && reg != REG_INSTRUCTION_POINTER;
};

const propagator::instr &
chamsim_trace_decoder::decode (const input_instr &input)
{
  using namespace std::ranges;

  reset ();

  auto ins = propagator::instr{ .ip = input.ip };
  if (input.is_branch)
    {
      ins_.op = propagator::instr::opcode::OP_BRANCH;
      return ins_;
    };

  auto src_mem = input.source_memory[0];
  auto dst_mem = input.destination_memory[0];

  if (!src_mem && !dst_mem)
    {
      ins_.op = propagator::instr::opcode::OP_REG;

      copy (input.source_registers | views::filter (reg_pred),
            back_inserter (ins_.src_reg));

      copy (input.destination_registers | views::filter (reg_pred),
            back_inserter (ins_.dst_reg));
    }
  else if (src_mem && !dst_mem)
    {
      ins_.op = propagator::instr::opcode::OP_LOAD;

      copy_if (begin (input.source_registers), end (input.source_registers),
               back_inserter (ins_.mem_reg), [=] (auto reg) {
                 return reg_pred (reg)
                        && find (begin (input.destination_registers),
                                 end (input.destination_registers), reg)
                               == end (input.destination_registers);
               });

      copy_if (begin (input.destination_registers),
               end (input.destination_registers), back_inserter (ins_.dst_reg),
               reg_pred);

      ins_.address = src_mem;
    }
  else if (!src_mem && dst_mem)
    {
      ins_.op = propagator::instr::opcode::OP_STORE;

      /* push or call */
      if (count_non_zero (begin (input.destination_registers),
                          end (input.destination_registers)))
        {
          ins_.mem_reg.push_back (REG_STACK_POINTER);
        }
      else
        {
          copy_if (begin (input.source_registers),
                   rbegin (input.source_registers).base (),
                   back_inserter (ins_.mem_reg), reg_pred);
        }

      ins_.address = dst_mem;
    }
  /*
   * Rare instructions, e.g. add [rcx] rax.
   * Should be treat as stores, but we ignore them FTM.
   */
  else
    {
      ins_.op = propagator::instr::opcode::OP_BRANCH;
    }

  return ins_;
}

}
