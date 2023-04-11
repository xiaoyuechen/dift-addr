/*
 *    Copyright 2023 The ChampSim Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TRACEREADER_H
#define TRACEREADER_H

#include "trace-instruction.h"
#include <cstdio>
#include <string>

namespace clueless
{

class tracereader
{
public:
  explicit tracereader (const char *trace_string);
  tracereader (const tracereader &other) = delete;
  ~tracereader ();

  input_instr read_single_instr ();

private:
  void open (std::string trace_string);
  void close ();

  FILE *trace_file = NULL;
  std::string trace_string;
  std::string cmd_fmtstr;
  std::string decomp_program;
};

}

#endif
