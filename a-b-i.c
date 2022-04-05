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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main (int argc, char *argv[])
{
  size_t sum = 0;
  size_t size = 10000;
  size_t *b = malloc (size * sizeof (*b));
  size_t *a = malloc (size * sizeof (*a));

  for (size_t i = 0; i < size; ++i)
    {
      b[i] = i;
    }
  for (size_t i = 0; i < size; ++i)
    {
      a[i] = 1;
    }

  for (size_t i = 0; i < size; ++i)
    {
      sum += a[b[i]];
    }

  memset (b, 0, size * sizeof (*b));

  printf ("a %p, b %p, sum %zu\n", a, b, sum);
  return 0;
}
