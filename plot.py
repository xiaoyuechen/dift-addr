#!/usr/bin/python3

# Copyright (C) 2022  Xiaoyue Chen

# This file is part of dift-addr.

# dift-addr is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# dift-addr is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with dift-addr.  If not, see <http://www.gnu.org/licenses/>.

import pandas as pd
import numpy as np
import sys
from matplotlib import pyplot as plt

df = pd.read_csv(sys.stdin)

if len(sys.argv) > 1:
    plt.title(sys.argv[1])

plt.rcParams.update({
    "text.usetex": True,
    "legend.fancybox": False,
    "legend.framealpha": 1.0,
    "pgf.texsystem": "pdflatex",
    'font.family': 'serif',
    'pgf.rcfonts': False,
    'figure.figsize': (4, 3),
    'figure.dpi': 300
})

fig = plt.figure()
ax = fig.add_subplot(111)

plt.plot(df.executed, df.addr_any, label='$|A_i|$', color='tab:red')
ax.plot(df.executed, df.addr_mem, label='$|L_i|$', color='tab:blue')
# ax.plot(df.executed, df.addr_any, label='any seen address')
for i, row in df[df["from"].notna()].iterrows():
    from_lt = int(row["from"], 0) - int(row["load_offset"], 0)
    print(f"{i}: {row['val']}")
    val_lt = int(row['val'], 0) - int(row['load_offset'], 0)
    leak = (val_lt - int('0x2020', 0)) // 64
    if leak in range(1, 128):
        ax.annotate(f"{hex(val_lt)}\n`{chr(leak)}'\n",
                    xy=(row["executed"], row["addr_mem"]),
                    fontsize=8,
                    ha='center')

ax.grid(axis='y')
ax.set_xlabel('$i$')
ax.legend()
plt.subplots_adjust(bottom=0.14, top=0.93)
plt.savefig(sys.argv[1])
# plt.show()
