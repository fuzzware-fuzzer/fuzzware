from idaapi import *

def dump_syms(outfile_path="syms.yml"):
    with open(outfile_path, "w") as f:
        f.write("symbols:\n")
        for addr, name in Names():
            f.write("  0x{:x}: '{}'\n".format(addr, name))

dump_syms()
