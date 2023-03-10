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

#include "operand.hpp"

static const char *OP_T_STR[OP_T_COUNT] = {
#define X(name) #name,
#define X0(name) "---",
  OP_T_LIST
#undef X0
#undef X
};

std::string
OP_ToString (OP op)
{
  static const size_t MAX_CHAR_COUNT = 64;
  char buff[MAX_CHAR_COUNT];
  int offset = snprintf (buff, MAX_CHAR_COUNT, "%s %d%d ", OP_T_STR[op.t],
                         op.rw & OP_RW_R ? 1 : 0, op.rw & OP_RW_W ? 1 : 0);
  switch (op.t)
    {
    case OP_T_REG:
      snprintf (buff + offset, MAX_CHAR_COUNT, "%s",
                REG_StringShort (op.content.reg).c_str ());
      break;
    case OP_T_MEM:
    case OP_T_ADR:
      snprintf (buff + offset, MAX_CHAR_COUNT, "%s %s",
                REG_valid (op.content.mem.base)
                    ? REG_StringShort (op.content.mem.base).c_str ()
                    : "",
                REG_valid (op.content.mem.index)
                    ? REG_StringShort (op.content.mem.index).c_str ()
                    : "");
      break;
    case OP_T_IMM:
      snprintf (buff + offset, MAX_CHAR_COUNT, "0x%x", op.content.imm);
      break;
    default:
      break;
    }

  return std::string (buff);
}

OP_T
OP_Type (INS ins, UINT32 n)
{
  return INS_OperandIsImmediate (ins, n)          ? OP_T_IMM
         : INS_OperandIsReg (ins, n)              ? OP_T_REG
         : INS_OperandIsMemory (ins, n)           ? OP_T_MEM
         : INS_OperandIsAddressGenerator (ins, n) ? OP_T_ADR
                                                  : OP_T_NONE;
}

int
INS_Operands (INS ins, OP *op)
{
  for (UINT32 n = 0; n < INS_OperandCount (ins); ++n)
    {
      op[n].t = OP_Type (ins, n);
      op[n].rw
          = (OP_RW)((INS_OperandRead (ins, n) ? OP_RW_R : OP_RW_NONE)
                    | (INS_OperandWritten (ins, n) ? OP_RW_W : OP_RW_NONE));
      switch (op[n].t)
        {
        case OP_T_REG:
          op[n].content.reg = INS_OperandReg (ins, n);
          break;
        case OP_T_MEM:
        case OP_T_ADR:
          op[n].content.mem.base = INS_MemoryBaseReg (ins);
          op[n].content.mem.index = INS_MemoryIndexReg (ins);
          break;
        case OP_T_IMM:
          op[n].content.imm = (long)INS_OperandImmediate (ins, n);
          break;
        default:
          break;
        }
    }
  return INS_OperandCount (ins);
}
