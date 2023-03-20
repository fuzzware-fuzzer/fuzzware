import idaapi
from idaapi import *

# While opening in IDA, set processor options to ARMv7-M for P2IM / uEmu targets
# Otherwise, some instructions will be interpreted as data rather than instructions

SegEnd = get_segm_end
GetFunctionName = get_func_name
def collect_post_call_instruction_starts():
    res = set()

    # collect all heads following calls within functions
    for segea in Segments():
        for funcea in Functions(segea, SegEnd(segea)):
            functionName = GetFunctionName(funcea)
            for (startea, endea) in Chunks(funcea):
                for head in Heads(startea, endea):
                    mnem = print_insn_mnem(prev_head(head, head-4))
                    if mnem and "bl" in mnem.lower():
                        res.add(head)

    return res

def collect_bbs_from_flowchart():
    result = set()

    for fn_addr in Functions():
        f = idaapi.FlowChart(idaapi.get_func(fn_addr))
        for block in f:
            result.add(block.start_ea)
            for succ_block in block.succs():
                result.add(succ_block.start_ea)
            for pred_block in block.preds():
                result.add(pred_block.start_ea)

    return result

def dump_bbl_starts_txt(out_file_path="valid_basic_blocks.txt"):
    instruction_starts = collect_bbs_from_flowchart() | collect_post_call_instruction_starts()
    with open(out_file_path, "wb") as f:
        for instr in sorted(instruction_starts):
            f.write("{:x}\n".format(instr).encode())
            
dump_bbl_starts_txt()
