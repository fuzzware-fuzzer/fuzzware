import logging
import angr
import archinfo
from typing import Tuple

l = logging.getLogger("QUIRKS")
from fuzzware_modeling.angr_utils import all_states

OPCODE_BYTE_BKPT = 0xbe
OPCODE_INF_LOOP = 0xe7fe
OPCODE_WFI = 0xbf30

def try_handling_decode_error(simulation, stash_name, addr):
    sample_state = simulation.stashes[stash_name][0]
    if addr & 1 == 1 and sample_state.mem_concrete(addr, 1) == OPCODE_BYTE_BKPT:
        # Clear block translation cache
        sample_state.project.factory.default_engine._block_cache.clear()
        for state in all_states(simulation):
            assert(state.mem_concrete(addr, 1) == OPCODE_BYTE_BKPT)
            state.memory.store(addr-1, OPCODE_WFI, 2, disable_actions=True, inspect=False, endness=state.project.arch.memory_endness)
        return True
    else:
        return False

def find_itstate_value(initial_state, regs):
    """
    Derives the value of the ITSTATE register from a given memory dump and register assignments.

    This works by disassembling backwards from PC and looking for an IT instruction and then deriving
    the value from the current PC's offset to the IT instruction.
    """

    # ITSTATE hacks
    # We try to recover the IT state in the vex-expected format
    # The format is described here: https://github.com/angr/vex/blob/master/pub/libvex_guest_arm.h#L161
    # From the current PC, we try to step backwards, each time looking for an IT instruction
    # If such an instruction is found, we recover the IT-state, knowing that our current instruction
    # is the one to be executed (the required condition is the one which was met in the emulator)
    # We can just find our position in the IT block, parse the IT mnemonic to find our condition and
    # apply the state based on the rest of the mnemonic

    # Constants derived from their documentation (lower nibble 1: is itblock instr, upper nibble: 0 for always, 1 for never)
    ITSTATE_BYTE_EXEC_NEVER  = 0xf1
    ITSTATE_BYTE_EXEC_ALWAYS = 0x01

    it_state = 0 # normally: no state, just execute
    try:
        l.info("Looking for IT instruction before us")
        start_addr = regs['pc'] # XXX TODO: testing
        cs = archinfo.ArchARMCortexM().capstone
        look_back = 6 + 2 # 3*2 for 3 previous instructions plus the IT instruction
        size = look_back + 4 * 4

        mem = initial_state.solver.eval(initial_state.memory.load(start_addr - look_back, size), cast_to=bytes)

        cs_address, own_size, own_mnemonic, own_opstr = list(cs.disasm_lite(bytes(mem[look_back:]), 8))[0]
        # l.info("Own Instr (size: {}): {:#08x}:\t{}\t{}".format(own_size, start_addr, own_mnemonic, own_opstr))
        if own_size == 2:
            # We might be in an IT block
            # Now look back for a maximum of 4 times, until
            # a) we find a 4-byte instruction -> cannot be in it block
            # b) we find an IT instruction
            for i in range(4):
                insns = list(cs.disasm_lite(bytes(mem[look_back - 2 * i - 2:]), 0x1000))
                if not insns:
                    # disassembling did not make sense at that offset, no need to look further
                    break
                cs_address, cs_size, it_mnemonic, cs_opstr = insns[0]
                if cs_size != 2:
                    break
                if it_mnemonic.lower().startswith("it"):
                    it_block_len = len(it_mnemonic) - 1
                    if i >= it_block_len:
                        l.info("Outside it block")
                        # we are already outside the block
                        break

                    it_state = ITSTATE_BYTE_EXEC_ALWAYS
                    if it_block_len == 1:
                        l.info("Single instruction IT block")
                        # simple conditional execution, exit
                        break

                    l.info("Found ITSTATE instruction!")

                    # the current instruction is instruction number
                    own_position = i
                    num_following_members = it_block_len - own_position - 1
                    # l.info("num_following_members: {}".format(num_following_members))
                    own_modifier = it_mnemonic[1+own_position]
                    for offset in range(1, num_following_members+1):
                        if own_modifier == it_mnemonic[1 + offset]:
                            # l.info("equal modifier, activate!")
                            it_state |= (ITSTATE_BYTE_EXEC_ALWAYS << (8 * offset))
                        else:
                            # l.info("other modifier, deactivate...")
                            it_state |= (ITSTATE_BYTE_EXEC_NEVER << (8 * offset))

                    #it_block_insns = list(cs.disasm_lite(bytes(mem[look_back - 2 * i - 2:look_back - 2 * i - 2 + (it_block_len + 1) * 2]), (it_block_len + 1) * 2))
                    ## we need to skip the IT instruction and our own instruction
                    #following_insns = it_block_insns[own_position+2:]
                    #for (cs_address, cs_size, cs_mnemonic, cs_opstr) in following_insns:
                    #    l.info("    Instr: {:#08x}:\t{}\t{}".format(regs['pc'], cs_mnemonic, cs_opstr))
                    l.info("Generated itstate: 0x{:08x}".format(it_state))
                    break
    except:
        l.info("ERROR during ITSTATE recovery, resetting to 0")
        it_state = 0

    return it_state

ARMG_CC_OP_COPY = 0
def add_special_initstate_reg_vals(initial_state, regs):
    # In state restoration, restore condition flags. Execution may rely on condition flags set before.
    regs['cc_op'] = ARMG_CC_OP_COPY

    # Also try figuring out the current itstate value
    regs['itstate'] = find_itstate_value(initial_state, regs)

def model_special_strex(initial_state, insn):
    """
    STREX Instructions
    https://developer.arm.com/documentation/dht0008/a/ch01s02s01

    Model accesses performed by strex specifically.

    This is necessary as Unicorn performs an MMIO read access while angr just moves
    the value 0 into the destination register

    For example, the instruction STREX R2, R1, [R0] in
    - angr: just stores the value 0 in R2
    - unicorn/qemu: reads from address [R0] during the instruction

    The way we handle this is by assigning a passthrough model returning the last written
    value to let unicorn figure out whether the value has stayed the same and thus whether
    the store operation has succeeded.

    NOTE: This may be a failure case in nieche cases where the firmware requires the operation
    to fail (in something like a low-level hardware funtionality debug case). However, this
    should never really occur and can still be handled manually.

    To perform the modeling, extract the memory location from the instruction, evaluate it,
    and assign a model for the address.
    """
    addr_operand = insn.operands[-1].mem

    reg_id = addr_operand.base
    offset = addr_operand.disp
    reg_name = insn.reg_name(reg_id)

    mmio_addr = initial_state.solver.eval(getattr(initial_state.regs, reg_name.lower()) + offset)
    access_pc = initial_state.liveness.base_snapshot.initial_pc

    # Handle sizes of strexb/h/d
    # TODO: how is strexd handled? it performs two MMIO accesses at the same time
    mmio_access_size = {
        'b': 1,
        'h': 2
    }.get(insn.mnemonic[-1:].lower(), 4)

    config_snippet = {
        "passthrough": {
            f"pc_{access_pc:08x}_mmio_{mmio_addr:08x}": {
                'addr': mmio_addr,
                'pc': access_pc,
                'access_size': mmio_access_size,
                'init_val': 0
            }
        }
    }
    descr_string = f"pc: 0x{access_pc:08x}, mmio: 0x{mmio_addr:08x}, special handling: STREX, passthrough model"

    return descr_string, config_snippet

def model_arch_specific(project, initial_state, base_snapshot, simulation) -> Tuple[str, dict]:
    try:
        block = project.factory.block(initial_state.addr)
        insn = block.capstone.insns[0].insn

        if insn.mnemonic.lower().startswith("strex"):
            l.info(f"Got arm/thumb-specific instruction {insn.mnemonic} {insn.op_str}")
            insn = block.capstone.insns[0]
            return model_special_strex(initial_state, insn.insn)

    except Exception as e:
        l.info(f"Got error: {e}")
        return None, None

    return None, None