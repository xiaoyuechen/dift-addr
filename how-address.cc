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
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <unordered_set>

const char *argp_program_version = "how-address 0.1.0";
const char *argp_program_bug_address = "<xchen@vvvu.org>";

static char doc[] = "How memory addresses are made";

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
  auto decoder = champsim_trace_decoder{};
  static auto pp = propagator{};

  auto level_leaked = std::array<std::unordered_set<unsigned long long>, 4>{};
  auto num_taint = std::array<std::unordered_set<unsigned long long>, 8>{};
  auto all = std::unordered_set<unsigned long long>{};

  pp.add_secret_exposed_hook ([&] (auto param) {
    auto &&[exposed_secret, transmit_addr, transmit_ip] = param;

    using namespace std::ranges;

    auto propagation_level = min (exposed_secret, {},
                                  &propagator::secret_exposed_hook_param::
                                      secret::propagation_level)
                                 .propagation_level;
    auto &lvl_set = propagation_level < level_leaked.size () - 1
                        ? level_leaked[propagation_level]
                        : *level_leaked.rbegin ();

    auto &num_taint_set = exposed_secret.size () < num_taint.size ()
                              ? num_taint[exposed_secret.size () - 1]
                              : *num_taint.rbegin ();

    for (auto &sec : exposed_secret)
      {
        if (find_if (
                level_leaked,
                [=] (auto &set) { return set.contains (sec.secret_address); })
            != end (level_leaked))
          {
            continue;
          }
        lvl_set.insert (sec.secret_address);
      }

    if (find_if (num_taint,
                 [=] (auto &set) { return set.contains (transmit_addr); })
        == end (num_taint))
      {
        num_taint_set.insert (transmit_addr);
      }
  });

  auto print_header = [] {
    printf ("ins lvl0 lvl1 lvl2 lvl3+ t1 t2 t3 t4 t5 t6 t7 t8+ gtt all\n");
  };
  auto print_result = [&] (auto i) {
    auto global_taint_tracking = std::unordered_set<unsigned long long>{};
    using namespace std::ranges;
    for_each (level_leaked, [&] (const auto &set) {
      for_each (set, [&] (auto pair) { global_taint_tracking.insert (pair); });
    });
    printf ("%zu ", i);
    for (auto &set : level_leaked)
      printf ("%zu ", set.size ());
    for (auto &set : num_taint)
      printf ("%zu ", set.size ());
    printf ("%zu ", global_taint_tracking.size ());
    printf ("%zu", all.size ());
    printf ("\n");
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
          all.insert (decoded_ins.address);
        }
      else if (decoded_ins.op == propagator::instr::opcode::OP_LOAD)
        {
          all.insert (decoded_ins.address);
        }
    }

  print_result (knbs.nsimulate);
}
