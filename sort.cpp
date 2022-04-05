/*
 * dift-addr --- Dynamic Information Flow Tracking on memory ADDResses
 * Copyright (C) 2022  Xiaoyue Chen
 *
 * This file is part of dift-addr.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <algorithm>
#include <cstddef>
#include <cstdio>

int
main (int argc, char *argv[])
{
  size_t size = 10000;
  int *a = new int[size];
  for (size_t i = 0; i < size; ++i)
    {
      a[i] = size - i - 1;
    }
  std::sort (a, a + size);
  for (size_t i = 0; i < size; ++i)
    {
      printf ("%d\n", a[i]);
    }

  delete[] a;
}
