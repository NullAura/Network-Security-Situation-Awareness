#!/usr/bin/env python3
import collections
import sys


counts = collections.Counter()

for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    try:
        key, value = line.rsplit("\t", 1)
        counts[key] += int(value)
    except ValueError:
        continue

for key, count in sorted(counts.items()):
    print(f"{key}\t{count}")
