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

#include "champsim-trace-decoder.h"
#include "propagator.h"
#include "tracereader.h"
#include <algorithm>
#include <argp.h>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>

const char *argp_program_version = "reuse-distance 0.1";
const char *argp_program_bug_address = "<xiaoyue.chen@it.uu.se>";

static char doc[] = "Find the minimal reuse distance for each memory address";

static char args_doc[] = "TRACE";

const struct argp_option option[]
    = { { "simulate", 's', "N", 0, "Simulate N instructions" },
        { "heartbeat", 'b', "N", 0, "Print heartbeat every N instructions" },
        { 0 } };

struct knobs
{
  size_t nsimulate = 10000000;
  size_t heartbeat = 100000;
  char *trace_file = nullptr;
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  auto knbs = (knobs *)state->input;

  switch (key)
    {
    case 's':
      knbs->nsimulate = atoll (arg);
      break;

    case 'b':
      knbs->heartbeat = atoll (arg);
      break;

    case ARGP_KEY_ARG:
      if (state->arg_num >= 1)
        argp_usage (state);

      knbs->trace_file = arg;
      break;

    case ARGP_KEY_END:
      if (state->arg_num < 1)
        argp_usage (state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { option, parse_opt, args_doc, doc };

struct reuse_distance_sampler
{
  explicit reuse_distance_sampler (size_t timestamp)
      : timestamp (timestamp), naccess (1)
  {
    using namespace std::ranges;
    fill (distance_set, std::numeric_limits<size_t>::max ());
  }

  static constexpr size_t NSAMPLE = 10;

  std::array<size_t, NSAMPLE> distance_set;
  size_t timestamp;
  size_t naccess;
};

std::ostream &
operator<< (std::ostream &os, const reuse_distance_sampler &sampler)
{
  const auto &distance_set = sampler.distance_set;
  auto mean = 0.0;
  for (auto dist : distance_set)
    {
      mean += dist / (double)distance_set.size ();
    }

  auto ssq = 0.0;
  for (auto dist : distance_set)
    {
      ssq += (dist - mean) * (dist - mean);
    }
  auto variance = ssq / distance_set.size ();
  auto sd = sqrt (variance);
  using namespace std::ranges;
  os << mean << " " << min (distance_set) << " " << max (distance_set) << " "
     << sd << " " << sampler.naccess;
  return os;
}

std::ostream &
operator<< (std::ostream &os,
            const std::pair<void *, const reuse_distance_sampler &> &pair)
{
  os << pair.first << " " << pair.second;
  return os;
}

int
main (int argc, char *argv[])
{
  auto knbs = knobs{};

  argp_parse (&argp, argc, argv, 0, 0, &knbs);

  using namespace clueless;
  auto reader = tracereader{ knbs.trace_file };
  auto decoder = champsim_trace_decoder{};
  auto pp = propagator{};

  using namespace std::ranges;

  auto reuse_distance
      = std::unordered_map<unsigned long long, reuse_distance_sampler>{};

  size_t reuse_distance_clk = 0;

  constexpr auto block_address_of
      = [] (auto addr) constexpr { return addr >> 6; };

  auto init_address_reuse_distance = [&] (auto param) {
    auto [secret_addr, transmit_addr, access_ip, transmit_ip, direct] = param;
    reuse_distance.emplace (
        std::make_pair (block_address_of (secret_addr),
                        reuse_distance_sampler{ reuse_distance_clk }));
  };

  pp.add_secret_exposed_hook (init_address_reuse_distance);

  for_each (
      views::iota (size_t{ 0 }) | views::take (knbs.nsimulate), [&] (auto) {
        auto input_ins = reader.read_single_instr ();
        const auto &decoded_ins = decoder.decode (input_ins);
        pp.propagate (decoded_ins);

        if (decoded_ins.op == propagator::instr::opcode::OP_LOAD
            || decoded_ins.op == propagator::instr::opcode::OP_STORE)
          {
            ++reuse_distance_clk;

            if (auto it
                = reuse_distance.find (block_address_of (decoded_ins.address));
                it != reuse_distance.end ())
              {
                auto &sampler = it->second;
                auto max_dist_it = max_element (sampler.distance_set);
                auto dist = reuse_distance_clk - sampler.timestamp - 1;
                if (dist < *max_dist_it)
                  {
                    *max_dist_it = dist;
                  }
                sampler.timestamp = reuse_distance_clk;
                ++sampler.naccess;
              }
          }
      });

  std::cout << "address mean min max sd naccess" << std::endl;
  std::cout << std::fixed << std::setprecision (2);
  auto cout_it = std::ostream_iterator<
      std::pair<void *, const reuse_distance_sampler &> > (std::cout, "\n");

  copy (reuse_distance | views::transform ([] (const auto &pair) {
          const auto &[address, sampler] = pair;
          return std::make_pair ((void *)address, std::cref (sampler));
        }),
        cout_it);
}
