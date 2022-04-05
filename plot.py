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

fig = plt.figure()
ax = fig.add_subplot(111)

ax.plot(df.executed, df.addr_mem, label='contains memory address')
# ax.plot(df.executed, df.addr_any, label='any seen address')
for i, row in df[df["from"].notna()].iterrows():
    from_lt = int(row["from"], 0) - int(row["load_offset"], 0)
    val_lt = int(row['val'], 0) - int(row['load_offset'], 0)
    leak = (val_lt - int('0x2020', 0)) // 64
    ax.annotate(
        f"{row['from']}\n{hex(from_lt)}\n{row['val']}\n{hex(val_lt)}\n\'{chr(leak)}\'\n",
        xy=(row["executed"], row["addr_mem"]),
        fontsize=6,
        ha='center')
ax.set_xlabel('#ins executed')
ax.set_ylabel('#addresses')
ax.legend()
plt.show()
