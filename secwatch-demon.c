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
#include <openssl/aes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char a[256 * 64];

static void
access (const unsigned char *data, size_t n)
{
  for (size_t i = 0; i < n; ++i)
    {
      asm volatile("mov (%0), %%rax\n" : : "c"(a + data[i] * 64) : "rax");
    }
}

int
main (int argc, char *argv[argc + 1])
{
  size_t size = 512;
  unsigned char *s0 = malloc (size);
  unsigned char *s1 = malloc (size);
  unsigned char *s2 = malloc (size);

  SEC_Watch (s0, size);

  printf ("a %p\n", a);
  printf ("s0 %p\n", s0);
  printf ("s1 %p\n", s1);

  printf ("cp s0->s1\n");
  for (size_t i = 0; i < size; ++i)
    {
      s1[i] = s0[i] + s0[(i + 64) % size] + 5;
    }
  printf ("cp s1->s2\n");
  for (size_t i = 0; i < size; ++i)
    {
      s2[i] = s1[i] / 3 + 10;
    }

  access (s2, size);

  SEC_Unwatch (s0);

  free (s0);
  free (s1);

  return 0;
}
