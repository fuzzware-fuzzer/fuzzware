import idaapi
from idaapi import *

inifinite_loops = [
    b"\x00\xbf\xfd\xe7", # loop: nop; b loop
    b"\xfe\xe7", # loop: b loop
]

whitelist = [
    "Reset_Handler",
    "main"
]

def detect_noret_funcs():
    exit_locs_name_pairs = []
    for func_addr in Functions():
        if get_func_flags(func_addr) & idaapi.FUNC_NORET:
            name = get_func_name(func_addr)
            
            if name not in whitelist:
                print("noret function: '{}' at 0x{:x}".format(name, func_addr))
                exit_locs_name_pairs.append((func_addr, name))
    return exit_locs_name_pairs

def detect_exit_ats(add_noret_functions=False):
    # 0. find BKPTs
    exit_locs = []

    # 1. find noret functions if requested
    if add_noret_functions:
        exit_locs += detect_noret_funcs()

    cnt = 0
    # 2. find infinite loops and BKPT instructions
    for segea in Segments():
        for funcea in Functions(segea, get_segm_end(segea)):
            functionName = get_func_name(funcea)
            for (startea, endea) in Chunks(funcea):
                for head in Heads(startea, endea):
                    # print(functionName, ":", "0x%08x"%(head), ":", GetDisasm(head))
                    for loop_code in inifinite_loops:
                        if get_bytes(head, len(loop_code)) == loop_code:
                            print("Found endless loop: 0x{:x} (function {})".format(head, functionName))
                            exit_locs.append((head, "endless_loop_{:02d}_{}".format(cnt, functionName)))
                            cnt += 1
                    if print_insn_mnem(head) == 'BKPT':
                        print("Found bkpt: 0x{:x} (function {})".format(head, functionName))
                        exit_locs.append((head, "bkpt_{:02d}_{}".format(cnt, functionName)))
                        cnt += 1

    return exit_locs

def print_exit_ats(add_noret_functions=False):
    exit_locs = detect_exit_ats(add_noret_functions=add_noret_functions)
    print("exit_at:")
    for addr, name in exit_locs:
        print("  {}: 0x{:08x}".format(name, addr))

def dump_exit_ats(filename="exit_ats.yml"):
    exit_locs = detect_exit_ats()
    with open(filename, "w") as f:
        f.write("exit_at:\n")
        for addr, name in exit_locs:
            f.write("  {}: 0x{:08x}\n".format(name, addr))

dump_exit_ats()
