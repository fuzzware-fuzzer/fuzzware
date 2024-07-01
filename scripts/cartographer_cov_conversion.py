#!/usr/bin/env python3
import sys
if len(sys.argv) < 3:
    print("Usage: cartographer_cov_conversion.py <input_file> <output_file>")
    exit(0)

with open(sys.argv[1], "r") as f:
    addrs = [int(l, 16) for l in f.readlines()]

out = "EZCOV VERSION: 1\n"
for addr in addrs:
    out += f"{hex(addr)}, 1, [ MAIN ]\n"

with open(sys.argv[2], "w") as f:
    f.write(out)
