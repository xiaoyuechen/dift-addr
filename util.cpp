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

#include "util.h"
#include "operand.hpp"
#include <string>

std::string
UT_InsOpString (INS ins)
{
  OP op[OP_MAX_OP_COUNT];
  int nop = INS_Operands (ins, op);

  static constexpr size_t MAX_CHAR_COUNT = 256;
  char buff[MAX_CHAR_COUNT];
  int offset = snprintf (buff, MAX_CHAR_COUNT, "%s\n",
                         INS_Disassemble (ins).c_str ());

  for (int i = 0; i < nop; ++i)
    {
      offset
          += snprintf (buff + offset, MAX_CHAR_COUNT - offset,
                       "    OP %d: %s\n", i + 1, OP_ToString (op[i]).c_str ());
    }

  return std::string (buff);
}

const char *
UT_StripPath (const char *path)
{
  const char *file = strrchr (path, '/');
  if (file)
    return file + 1;
  else
    return path;
}

std::string
UT_InsRtnString (INS ins, RTN rtn)
{
  static constexpr size_t MAX_CHAR_COUNT = 512;
  char buff[MAX_CHAR_COUNT];
  int offset
      = snprintf (buff, MAX_CHAR_COUNT, "%p ", (void *)INS_Address (ins));
  if (RTN_Valid (rtn))
    {
      IMG img = SEC_Img (RTN_Sec (rtn));
      if (IMG_Valid (img))
        {
          offset += snprintf (buff + offset, MAX_CHAR_COUNT - offset, "%s:%s ",
                              UT_StripPath (IMG_Name (img).c_str ()),
                              RTN_Name (rtn).c_str ());
        }
    }
  snprintf (buff + offset, MAX_CHAR_COUNT - offset, "%s\n",
            INS_Disassemble (ins).c_str ());
  return std::string (buff);
}
