/*
 * dift-addr --- Dynamic Information Flow Tracking on memory ADDResses
 * Copyright (C) 2022, 2023  Xiaoyue Chen
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
#include "instrument-propagation.hpp"
#include "util.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <map>
#include <time.h>
#include <types.h>

#ifndef NUM_TAINT
#define NUM_TAINT 16
#endif

using std::string;

INSTLIB::FILTER filter;

FILE *out = stderr;
FILE *out_img = stderr;
FILE *out_trace = stderr;
static UINT64 icount = 0;
static UINT64 nwarmup = 0;
static UINT64 nexit = ~UINT64 (0);

KNOB<string> KnobOutputFile (KNOB_MODE_WRITEONCE, "pintool", "o",
                             "dift-addr.out",
                             "The output file name for dift-addr");

KNOB<string> KnobOutputImgFile (KNOB_MODE_WRITEONCE, "pintool", "oimg",
                                "dift-addr.img.out",
                                "The output file name for images");

KNOB<string>
    KnobOutputTraceFile (KNOB_MODE_WRITEONCE, "pintool", "otrace",
                         "dift-addr.trace.out",
                         "The output file name for the trace if -trace is on");

KNOB<size_t> KnobWarmupIns (KNOB_MODE_WRITEONCE, "pintool", "warmup", "0",
                            "Do not instrument before WARMUP number of "
                            "instructions have been executed");

KNOB<INT64>
    KnobExitIns (KNOB_MODE_WRITEONCE, "pintool", "exit", "-1",
                 "Exit after EXIT number of instructions have been executed");

KNOB<size_t> KnobDumpPeriod (KNOB_MODE_WRITEONCE, "pintool", "dumpperiod", "1",
                             "Dump every DUMPPERIOD instructions");

KNOB<bool>
    KnobWatchMode (KNOB_MODE_WRITEONCE, "pintool", "watch", "",
                   "Watch secret using libsecwatch. Do not track everything");

KNOB<bool> KnobTraceMode (KNOB_MODE_WRITEONCE, "pintool", "trace", "",
                          "Privide a propagation trace");

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

  out_img = KnobOutputImgFile.Value ().empty ()
                ? stderr
                : fopen (KnobOutputImgFile.Value ().c_str (), "w");

  out_trace = KnobOutputTraceFile.Value ().empty ()
                  ? stderr
                  : fopen (KnobOutputTraceFile.Value ().c_str (), "w");

  nwarmup = KnobWarmupIns.Value ();
  nexit = KnobExitIns.Value () > 0 ? KnobExitIns.Value () : nexit;

  filter.Activate ();

  IPG_Init ();
  IPG_SetDumpFile (out);
  IPG_SetWatch (KnobWatchMode.Value ());
  IPG_SetDumpPeriod (KnobDumpPeriod.Value ());
  IPG_SetTrace (KnobTraceMode.Value ());
  IPG_SetTraceFile (out_trace);
  IPG_DumpHeader ();
}

bool started = false;
time_t start;

VOID PIN_FAST_ANALYSIS_CALL
docount (ADDRINT c)
{
  icount += c;
  if (icount > nwarmup && !started)
    {
      time (&start);
      started = true;
    }

  if (icount > nwarmup && icount - nwarmup > nexit)
    {
      time_t end;
      time (&end);
      double duration = difftime (end, start);
      printf ("%lf seconds", duration);
      PIN_ExitApplication (0);
    }
}

void
Trace (TRACE trace, void *val)
{
  if (!filter.SelectTrace (trace))
    return;

  for (BBL bbl = TRACE_BblHead (trace); BBL_Valid (bbl); bbl = BBL_Next (bbl))
    {
      BBL_InsertCall (bbl, IPOINT_ANYWHERE, AFUNPTR (docount),
                      IARG_FAST_ANALYSIS_CALL, IARG_UINT32, BBL_NumIns (bbl),
                      IARG_END);

      if (icount > nwarmup)
        {
          for (INS ins = BBL_InsHead (bbl); INS_Valid (ins);
               ins = INS_Next (ins))
            {
              IPG_InstrumentIns (ins);
            }
        }
    }
}

void
ImgLoad (IMG img, void *)
{
  if (IMG_Valid (img))
    {
      fprintf (out_img, "%s,%p,%p\n", IMG_Name (img).c_str (),
               (void *)IMG_LowAddress (img), (void *)IMG_HighAddress (img));
    }

  if (KnobWatchMode.Value ()
      && strstr (UT_StripPath (IMG_Name (img).c_str ()), "libsecwatch.so"))
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
  fclose (out_img);
  fclose (out_trace);
}

int
main (int argc, char *argv[])
{
  Init (argc, argv);

  TRACE_AddInstrumentFunction (Trace, 0);
  IMG_AddInstrumentFunction (ImgLoad, 0);

  PIN_AddFiniFunction (Fini, 0);

  PIN_StartProgram ();

  return 0;
}
