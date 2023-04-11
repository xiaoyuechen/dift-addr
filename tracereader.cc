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

#include "tracereader.h"
#include <cassert>
#include <fstream>
#include <iostream>

namespace clueless
{

tracereader::tracereader (const char *_ts) : trace_string (_ts)
{
  std::string last_dot = trace_string.substr (trace_string.find_last_of ("."));

  std::ifstream testfile (trace_string);
  if (!testfile.good ())
    {
      std::cerr << "TRACE FILE NOT FOUND" << std::endl;
      assert (0);
    }
  cmd_fmtstr = "%1$s -dc %2$s";

  if (last_dot[1] == 'g') // gzip format
    decomp_program = "gzip";
  else if (last_dot[1] == 'x') // xz
    decomp_program = "xz";
  else
    {
      std::cout << "ChampSim does not support traces other than gz or xz "
                   "compression!"
                << std::endl;
      assert (0);
    }

  open (trace_string);
}

tracereader::~tracereader () { close (); }

input_instr
tracereader::read_single_instr ()
{
  input_instr trace_read_instr;

  while (!fread (&trace_read_instr, sizeof (trace_read_instr), 1, trace_file))
    {
      // reached end of file for this trace
      std::cout << "*** Reached end of trace: " << trace_string << std::endl;

      // close the trace file and re-open it
      close ();
      open (trace_string);
    }

  return trace_read_instr;
}

void
tracereader::open (std::string trace_string)
{
  char gunzip_command[4096];
  sprintf (gunzip_command, cmd_fmtstr.c_str (), decomp_program.c_str (),
           trace_string.c_str ());
  trace_file = popen (gunzip_command, "r");
  if (trace_file == NULL)
    {
      std::cerr << std::endl
                << "*** CANNOT OPEN TRACE FILE: " << trace_string << " ***"
                << std::endl;
      assert (0);
    }
}

void
tracereader::close ()
{
  if (trace_file != NULL)
    {
      pclose (trace_file);
    }
}

}
