/*
 * clueless --- Characterises vaLUEs Leaking as addrESSes
 * Copyright (C) 2023  Xiaoyue Chen
 *
 * This file is part of clueless.
 *
 * clueless is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * clueless is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with clueless.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HOOK_H
#define HOOK_H

#include <functional>
#include <vector>

namespace clueless
{

template <typename... Args> class hook
{
public:
  using function = std::function<void (Args...)>;

  void
  add (function f)
  {
    hook_.push_back (f);
  }

  void
  run (Args... args)
  {
    for (const auto &f : hook_)
      {
        f (std::forward<Args> (args)...);
      }
  }

private:
  std::vector<function> hook_;
};

}

#endif
