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

#include "pin.H" /* pin.H must be included first */

#include "instlib.H"
#include "instrument-propagation.h"
#include "util.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <map>

#ifndef NUM_TAINT
#define NUM_TAINT 16
#endif

using std::string;

INSTLIB::FILTER filter;

FILE *out = stderr;

KNOB<string> KnobOutputFile (KNOB_MODE_WRITEONCE, "pintool", "o",
                             "dift-addr.out",
                             "The output file name for dift-addr");

KNOB<size_t> KnobWarmupIns (
    KNOB_MODE_WRITEONCE, "pintool", "warmup", "0",
    "Do not dump before WARMUP number of instructions have been executed");

KNOB<size_t> KnobDumpPeriod (KNOB_MODE_WRITEONCE, "pintool", "dumpperiod", "1",
                             "Dump every DUMPPERIOD instructions");

KNOB<bool>
    KnobWatchMode (KNOB_MODE_WRITEONCE, "pintool", "watch", "",
                   "Watch secret using libsecwatch. Do not track everything");

int
Usage ()
{
  fprintf (stderr, "%s%s\n",
           "This tool prints out the addresses that contains addresses\n",
           KNOB_BASE::StringKnobSummary ().c_str ());
  return -1;
}

void
Banner ()
{
  fprintf (stderr, "===============================================\n"
                   "This application is instrumented by dift-addr\n");
  if (!KnobOutputFile.Value ().empty ())
    {
      fprintf (stderr, "See file %s for analysis results\n",
               KnobOutputFile.Value ().c_str ());
    }
  fprintf (stderr, "===============================================\n");
}

void
Init (int argc, char *argv[])
{
  if (PIN_Init (argc, argv))
    exit (Usage ());

  Banner ();

  PIN_InitSymbols ();

  out = KnobOutputFile.Value ().empty ()
            ? stderr
            : fopen (KnobOutputFile.Value ().c_str (), "w");

  filter.Activate ();

  IPG_Init ();
  IPG_SetDumpFile (out);
  IPG_SetWarmup (KnobWarmupIns.Value ());
  IPG_SetWatch (KnobWatchMode.Value ());
  IPG_SetDumpPeriod (KnobDumpPeriod.Value ());
  IPG_DumpHeader ();
}

void
Trace (TRACE trace, void *val)
{
  if (!filter.SelectTrace (trace))
    return;

  for (BBL bbl = TRACE_BblHead (trace); BBL_Valid (bbl); bbl = BBL_Next (bbl))
    {
      for (INS ins = BBL_InsHead (bbl); INS_Valid (ins); ins = INS_Next (ins))
        {
          IPG_InstrumentIns (ins);
        }
    }
}

void
ImgLoad (IMG img, void *)
{
  if (strstr (UT_StripPath (IMG_Name (img).c_str ()), "libsecwatch.so"))
    {
      RTN watch = RTN_FindByName (img, "SEC_Watch");
      if (RTN_Valid (watch))
        {
          RTN_Open (watch);
          IPG_InstrumentWatch (watch);
          RTN_Close (watch);
        }

      RTN unwatch = RTN_FindByName (img, "SEC_Unwatch");
      if (RTN_Valid (unwatch))
        {
          RTN_Open (unwatch);
          IPG_InstrumentUnwatch (unwatch);
          RTN_Close (unwatch);
        }
    }
}

void
Fini (INT32 code, void *v)
{
  IPG_Fini ();
  fclose (out);
}

int
main (int argc, char *argv[])
{
  Init (argc, argv);

  TRACE_AddInstrumentFunction (Trace, 0);
  if (KnobWatchMode.Value ())
    {
      IMG_AddInstrumentFunction (ImgLoad, 0);
    }

  PIN_AddFiniFunction (Fini, 0);

  PIN_StartProgram ();

  return 0;
}
