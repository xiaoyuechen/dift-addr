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

#ifndef TAINT_TABLE_H
#define TAINT_TABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifndef TT_NTAINT
#define TT_NTAINT 64
#endif

#ifndef TT_NROW
#define TT_NROW 256
#endif

typedef struct TT_TAINT_TABLE TT_TAINT_TABLE;
typedef size_t TT_ROW;
typedef size_t TT_TAINT;

TT_TAINT_TABLE *TT_CreateTaintTable (size_t nrow);
void TT_DestroyTaintTable (TT_TAINT_TABLE *tt);

bool TT_IsTainted (const TT_TAINT_TABLE *tt, TT_ROW r, TT_TAINT t);
void TT_Taint (TT_TAINT_TABLE *tt, TT_ROW r, TT_TAINT t);
void TT_Untaint (TT_TAINT_TABLE *tt, TT_ROW r, TT_TAINT t);
void TT_UntaintC (TT_TAINT_TABLE *tt, TT_TAINT t);

void TT_Union (TT_TAINT_TABLE *tt, TT_ROW dst, TT_ROW src1, TT_ROW src2);
void TT_Diff (TT_TAINT_TABLE *tt, TT_ROW dst, TT_ROW src1, TT_ROW src2);

TT_TAINT TT_MakeTaint (TT_TAINT_TABLE *tt);

void TT_PrintRow (const TT_TAINT_TABLE *tt, FILE *file, TT_ROW r);

#endif
