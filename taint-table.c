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

#include "taint-table.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TT_TAINT_SIZE ((TT_NTAINT + 7) / 8)

struct TT_TAINT_TABLE
{
  uint8_t row[TT_NROW][TT_TAINT_SIZE];
  size_t timestamp[TT_NTAINT];
  size_t time;
  size_t ntaint_exhaustion;
};

TT_TAINT_TABLE *
TT_CreateTaintTable (size_t nrow)
{
  TT_TAINT_TABLE *tt = malloc (sizeof (*tt));
  memset (tt->row, 0, sizeof (tt->row));
  return tt;
}

void
TT_DestroyTaintTable (TT_TAINT_TABLE *tt)
{
  free (tt);
}

bool
TT_IsTainted (const TT_TAINT_TABLE *tt, TT_ROW r, TT_TAINT t)
{
  return tt->row[r][t / 8] & (1u << t % 8);
}

void
TT_Taint (TT_TAINT_TABLE *tt, TT_ROW r, TT_TAINT t)
{
  tt->timestamp[t] = tt->time++;
  tt->row[r][t / 8] |= (1u << t % 8);
}

void
TT_Untaint (TT_TAINT_TABLE *tt, TT_ROW r, TT_TAINT t)
{
  tt->row[r][t / 8] &= ~(1u << t % 8);
}

void
TT_UntaintC (TT_TAINT_TABLE *tt, TT_TAINT t)
{
  for (TT_ROW r = 0; r < TT_NROW; ++r)
    {
      TT_Untaint (tt, r, t);
    }
}

void
TT_Union (TT_TAINT_TABLE *tt, TT_ROW dst, TT_ROW src1, TT_ROW src2)
{
  for (size_t b = 0; b < TT_TAINT_SIZE; ++b)
    {
      tt->row[dst][b] = tt->row[src1][b] | tt->row[src2][b];
    }
}

void
TT_Diff (TT_TAINT_TABLE *tt, TT_ROW dst, TT_ROW src1, TT_ROW src2)
{
  for (size_t b = 0; b < TT_TAINT_SIZE; ++b)
    {
      tt->row[dst][b] = tt->row[src1][b] ^ tt->row[src2][b];
    }
}

static bool
FindUnusedTaint (const TT_TAINT_TABLE *tt, TT_TAINT *out)
{
  size_t t_count[TT_NTAINT];
  memset (t_count, 0, sizeof (t_count));
  for (TT_ROW r = 0; r < TT_NROW; ++r)
    {
      for (TT_TAINT t = 0; t < TT_NTAINT; ++t)
        {
          t_count[t] += TT_IsTainted (tt, r, t);
        }
    }

  for (TT_TAINT t = 0; t < TT_NTAINT; ++t)
    {
      if (!t_count[t])
        {
          *out = t;
          return true;
        }
    }
  return false;
}

TT_TAINT
FindOldestTaint (const TT_TAINT_TABLE *tt)
{
  TT_TAINT oldest_taint = 0;
  for (TT_TAINT t = 0; t < TT_NTAINT; ++t)
    {
      oldest_taint
          = tt->timestamp[t] < tt->timestamp[oldest_taint] ? t : oldest_taint;
    }
  return oldest_taint;
}

TT_TAINT
TT_MakeTaint (TT_TAINT_TABLE *tt)
{
  TT_TAINT t;
  if (FindUnusedTaint (tt, &t))
    {
      return t;
    }

  t = FindOldestTaint (tt);
  TT_UntaintC (tt, t);
  return t;
}

void
TT_PrintRow (const TT_TAINT_TABLE *tt, FILE *file, TT_ROW r)
{
  for (TT_TAINT t = 0; t < TT_NTAINT; ++t)
    {
      fprintf (file, "%c", TT_IsTainted (tt, r, t) ? '+' : '-');
    }
  printf ("\n");
}
