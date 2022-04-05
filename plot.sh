#!/bin/bash

for f in alpha-results/*.dump; do
    ./plot.py $(basename $f) < $f &
done
