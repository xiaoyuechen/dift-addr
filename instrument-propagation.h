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

#ifndef INSTRUMENT_PROPAGATION_H
#define INSTRUMENT_PROPAGATION_H

#include "pin.H"

#include <stddef.h>
#include <stdio.h>

void IPG_Init ();

void IPG_SetDumpFile (FILE *file);

void IPG_SetDumpPeriod (size_t every_nins);

void IPG_SetWarmup (size_t nins);

void IPG_SetWatch (bool shouldWatch);

void IPG_DumpHeader ();

void IPG_InstrumentIns (INS ins);

void IPG_InstrumentWatch (RTN watch);

void IPG_InstrumentUnwatch (RTN unwatch);

void IPG_Fini ();

#endif
