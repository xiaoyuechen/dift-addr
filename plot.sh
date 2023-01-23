#!/bin/bash

for f in alpha-results/*.dump; do
    bench=$(echo $f | cut -d / -f 2 | cut -d . -f 1)
    echo $bench
    ./plot-simple.py ../writing/common/fig/${bench}.png < $f
done
