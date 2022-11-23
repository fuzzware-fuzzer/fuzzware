""" WIP place for ARM Thumb specific constants.
This is the result from scraping architecture-specific register name lists from the code.

TODO: Unify and replace this with archinfo
"""
STATE_SNAPSHOT_REG_LIST = ['r0', 'r1', 'r2', 'r3', 'r4',
        'r5', 'r6', 'r7', 'r8', 'r9',
        'r10', 'r11', 'r12', 'lr', 'pc',
        'sp', 'xpsr']

SCOPE_REG_NAMES = ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r10', 'r11', 'r12', 'lr', 'sp', 'pc')

REGULAR_REGISTER_NAMES = ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'lr', 'sp')

NEWLY_ADDED_CONSTRAINTS_REG_NAMES = ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r10', 'r11', 'r12', 'lr')

REG_NAME_PC = 'pc'
REG_NAME_SP = 'sp'

def return_reg(state):
    return state.regs.r0

def translate_reg_name_to_vex_internal_name(name):
    name = name.lower()

    if name == 'xpsr':
        name = 'cc_dep1'

    return name

def leave_reg_untainted(name):
    return name in ['itstate', 'cc_op']