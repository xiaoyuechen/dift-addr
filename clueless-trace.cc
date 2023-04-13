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
#include <argp.h>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <unordered_set>

const char *argp_program_version = "clueless-trace 0.1.0";
const char *argp_program_bug_address = "<xiaoyue.chen@it.uu.se>";

static char doc[]
    = "Characterises vaLUEs Leaking as addrESSes in an execution TRACE";

static char args_doc[] = "TRACE";

const struct argp_option option[]
    = { { "warmup", 'w', "N", 0, "Skip the first N instructions" },
        { "simulate", 's', "N", 0, "Simulate N instructions" },
        { "heartbeat", 'b', "N", 0, "Print heartbeat every N instructions" },
        { 0 } };

struct knobs
{
  size_t nwarmup = 0;
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
    case 'w':
      knbs->nwarmup = atoll (arg);
      break;

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

int
main (int argc, char *argv[])
{
  auto knbs = knobs{};

  argp_parse (&argp, argc, argv, 0, 0, &knbs);

  using namespace clueless;
  auto reader = tracereader{ knbs.trace_file };
  auto decoder = chamsim_trace_decoder{};
  auto pp = propagator{};

  auto directly_leaked = std::unordered_set<unsigned long long>{};
  auto indirectly_leaked = std::unordered_set<unsigned long long>{};
  auto all = std::unordered_set<unsigned long long>{};
  auto taint_exhausted_count = size_t{ 0 };

  pp.add_secret_exposed_hook ([&] (auto param) {
    auto [secret_addr, transmit_addr, access_ip, transmit_ip, indirect]
        = param;
    auto &set = indirect ? indirectly_leaked : directly_leaked;
    set.insert (secret_addr);
  });

  pp.add_taint_exhausted_hook ([&] (auto taint) { ++taint_exhausted_count; });

  auto print_header = [] { printf ("ins direct indirect gtt all exhaust\n"); };
  auto print_result = [&] (auto i) {
    auto global_taint_tracking = directly_leaked;
    std::ranges::for_each (indirectly_leaked, [&] (auto pair) {
      global_taint_tracking.insert (pair);
    });
    printf ("%zu %zu %zu %zu %zu %zu\n", i, directly_leaked.size (),
            indirectly_leaked.size (), global_taint_tracking.size (),
            all.size (), taint_exhausted_count);
    fflush (stdout);
  };

  for (auto i = size_t{ 0 }; i < knbs.nwarmup; ++i)
    {
      reader.read_single_instr ();
    }

  print_header ();

  for (auto i = size_t{ 0 }; i < knbs.nsimulate; ++i)
    {
      if (!(i % knbs.heartbeat))
        {
          print_result (i);
        }

      auto input_ins = reader.read_single_instr ();
      const auto &decoded_ins = decoder.decode (input_ins);
      pp.propagate (decoded_ins);
      if (decoded_ins.op == propagator::instr::opcode::OP_STORE)
        {
          directly_leaked.erase (decoded_ins.address);
          indirectly_leaked.erase (decoded_ins.address);
          all.insert (decoded_ins.address);
        }
      else if (decoded_ins.op == propagator::instr::opcode::OP_LOAD)
        {
          all.insert (decoded_ins.address);
        }
    }

  print_result (knbs.nsimulate);
}
