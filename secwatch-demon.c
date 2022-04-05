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

#include "secwatch.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const unsigned char a[256 * 64];

static void
access (const char *data, size_t n)
{
  for (size_t i = 0; i < n; ++i)
    {
      asm volatile("mov (%0), %%rax\n" : : "c"(a + data[i] * 64) : "rax");
    }
}

int
main (int argc, char *argv[argc + 1])
{
  size_t size = 64;
  char *s0 = malloc (size);
  SEC_Watch (s0, size);
  encrypt (dst, s0);
  free (s0);
  SEC_Unwatch (s0);

  return 0;
}
