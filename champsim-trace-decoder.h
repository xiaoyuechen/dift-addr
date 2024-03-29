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

#ifndef CHAMPSIM_TRACE_DECODER_H
#define CHAMPSIM_TRACE_DECODER_H

#include "propagator.h"
#include "trace-instruction.h"

namespace clueless
{

class champsim_trace_decoder
{
public:
  const propagator::instr &decode (const input_instr &input);

private:
  void reset ();

  propagator::instr ins_ = {};
  unsigned long long i_ = {};
};

}

#endif
