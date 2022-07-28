import itertools
import pyvex
import angr

import logging
l = logging.getLogger("utils")

from .arch_specific.arm_thumb_regs import scope_reg_names, return_reg

MAX_ACTIVE_STATES = 100

MAX_DEAD_VARS = 3
MAX_STATES = 20
MAX_CALL_DEPTH = 2
MAX_BB_VISITS = 5
NON_FORKING_STATE_MAX_BB_VISITS = 50
# In order to detect constant models we need to have enough dead variables to reason about
assert(MAX_DEAD_VARS+2 <= MAX_BB_VISITS)
NVIC_RET_START = 0xfffff000
CUSTOM_STASH_NAMES = ['returning_val', 'deep_calls', 'loops', 'vars_dead_but_path_constrained', 'too_many_out_of_scope']
mmio_addr = None

def all_states(simulation):
    return itertools.chain(*simulation.stashes.values())

def has_conditional_statements(state, unconditionals_cache=None):
    for bbl_addr in state.history.bbl_addrs:
        if unconditionals_cache is not None and bbl_addr in unconditionals_cache:
            continue

        block = state.project.factory.block(bbl_addr | 1).vex
        if list(block.exit_statements):
            return True

        for statement in block.statements:
            #statement.pp()
            for expr in statement.expressions:
                if isinstance(expr, pyvex.expr.ITE):
                    return True

        unconditionals_cache.add(bbl_addr)
    return False

def contains_var(ast, var):
    return var._encoded_name.decode() in ast.variables

def in_scope_register_values(state):
    if state.liveness.returned:
        return [return_reg(state)]
    else:
        return [getattr(state.regs, name) for name in scope_reg_names]

def is_mmio_address(state, addr):
    return state.liveness.base_snapshot.is_mmio_addr(addr)

def is_ast_mmio_address(state, ast):
    try:
        addr = state.solver.eval_one(ast)
    except Exception as e:
        l.info(f"[is_ast_mmio_address] exception for ast={ast}: {e}")
        return False

    return is_mmio_address(state, addr)

def state_returns_val(state):
    return (not state.globals['dead_write_to_env']) and any([contains_var(return_reg(state), var) for var in state.liveness.tracked_vars])

def state_vars_out_of_scope(state):
    # We wrote an mmio value to the environment. Definitely not dead
    if state.globals['dead_write_to_env']:
        return False

    # Straight up no alive variables are present
    if state.liveness.all_vars_dead or not state.liveness.alive_varname_counts:
        return True

    # We had a lot of variables go out of scope and only one is left
    if state.globals['dead_too_many_out_of_scope'] and len(state.liveness.alive_varname_counts) <= 1:
        return True

    # Unless shown otherwise, we assume vars exist in scope
    return False

def state_contains_tracked_mmio_path_constraints(state):
    constraint_actions = [action for action in state.history.actions if isinstance(action, angr.state_plugins.sim_action.SimActionConstraint)]
    for var in state.liveness.tracked_vars:
        for action in constraint_actions:
            constraint = action.constraint
            if contains_var(constraint, var):
                # If the variable is in the constraints, make sure it is not an instruction signal handler
                block = state.project.factory.block(action.ins_addr, num_inst=1, thumb=True)
                if [ jk for jk in block.vex.constant_jump_targets_and_jumpkinds.values() if jk.startswith("Ijk_Sig") ]:
                    l.info("Skipping signal related path constraint on mmio access")
                else:
                    return True
    return False

def state_variables_involved_in_loop(state):
    constraint_actions = [action for action in state.history.actions if isinstance(action, angr.state_plugins.sim_action.SimActionConstraint)]
    for var in state.liveness.tracked_vars:
        seen_pcs = set()
        for action in constraint_actions:
            constraint = action.constraint
            if contains_var(constraint, var):
                pc = action.ins_addr
                if (pc, constraint) in seen_pcs:
                    return True
                seen_pcs.add((pc, constraint))
    return False

def insn_addr_from_SimIRSBNoDecodeError(e):
    # IR decoding error at 0x10006533.
    TOK = "IR decoding error at "
    msg = str(e)
    addr_str_start = msg.index(TOK) + len(TOK)
    addr_str_end = msg.index(".", addr_str_start)
    addr = int(msg[addr_str_start: addr_str_end], 16)
    return addr