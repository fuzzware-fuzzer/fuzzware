import angr
import claripy

from itertools import chain

from .angr_utils import is_ast_mmio_address, contains_var, all_states, has_conditional_statements, state_vars_out_of_scope, state_contains_tracked_mmio_path_constraints, state_variables_involved_in_loop, in_scope_register_values

MAX_SET_MODEL_VAL_NUM = 16

# ======= Passthrough Model =======
def check_is_passthrough_model(state, mmio_constrains_path, returned, vars_dead):
    """ Compute Passthrough model
    Check whether a state represents a passthrough access
    """

    if mmio_constrains_path:
        print("[PASSTHROUGH] [-] Path is constrained")
        return False

    if not vars_dead:
        print("[PASSTHROUGH] [-] Vars not dead")
        return False

    if state.liveness.tracked_vars:
        print("[PASSTHROUGH] [*] Checking vars in path")

        print("[PASSTHROUGH] [*] Vars: {}".format(state.liveness.tracked_vars))
        mmio_write_actions = [ev for ev in state.history.actions
            if isinstance(ev, angr.state_plugins.sim_action.SimActionData)
                and ev.action == "write" and is_ast_mmio_address(state, ev.addr)]

        all_vars_written = True
        for var in state.liveness.tracked_vars:
            all_vars_written = all_vars_written and any([contains_var(action.data, var) for action in mmio_write_actions])

        if all_vars_written:
            print("[PASSTHROUGH] [+] All MMIO vars written to mmio location")
            return True

    print("[PASSTHROUGH] [-] Default case")
    return False

# ======= Constant Model =======
def check_is_constant_model(states):
    """ Compute Constant model prerequesites
    Check whether an MMIO output can be set to a constant value.

    Two situations can lead there:
    1. MMIO is used as a guarding status value for a busy while(MMIO_VAL){} loop
    2. MMIO value is not used at all and no conditional statements are present in the executed code until function return
    """

    if any([not state_vars_out_of_scope(state) for state in states]):
        print("[CONST] [-] vars not dead")
        return False
    else:
        paths_constrained = [state_contains_tracked_mmio_path_constraints(state) for state in states]
        if not all(paths_constrained):
            if any(paths_constrained):
                print("[CONST] [-] Vars are dead and some some paths are constrained, but not all. We might be shadowed")
                return False

            known_unconditional_bbls = set()
            for state in states:
                if has_conditional_statements(state, known_unconditional_bbls):
                    print("[CONST] [-] Vars are dead but path is not constrained by MMIO for all states and we found conditionals. We might be shadowed")
                    return False

            # There are no conditional statements, we are not shadowed and the variable is indeed not used
            print("[CONST] [+] Variable is not used and no conditional statements may be shadowing us")
            return True

    print("[CONST] got {} states, #tracked_mmio_vars: {}".format(len(states), list(map(lambda s: len(s.liveness.tracked_vars), states))))

    # First collect a representative last and prev-to-last constraint, making sure they are the same amongst states along the way
    reference_var = None
    normalized_last_constraint = None
    normalized_prev_to_last_constraint = None
    for state in sorted(states, key=lambda s:len(s.liveness.tracked_vars)):
        last_var = state.liveness.tracked_vars[-1]
        if reference_var is None:
            reference_var = claripy.BVS("ref", last_var.size())
        last_tracked_var_constraints = [state.solver.simplify(state.liveness.base_snapshot.unconstrain(guard)) for guard in state.history.jump_guards if contains_var(guard, last_var)]
        
        # We are looking for a busy loop that gets exited by a single jump on the last variable meeting a condition
        if len(last_tracked_var_constraints) != 1:
            print("[CONST] [-] More than one constraint on last variable, assuming non-constant")
            return False

        # We also need all states to have the same (presumably inevitable) exit condition
        curr_last_constraint = last_tracked_var_constraints[0].replace(last_var, reference_var)
        if normalized_last_constraint is None:
            normalized_last_constraint = curr_last_constraint
        elif not claripy.is_true(normalized_last_constraint == curr_last_constraint):
            print("[CONST] [-] Encountered different exit conditions amongst states ('{}' != '{}')".format(normalized_last_constraint, curr_last_constraint))
            return False
        
        if len(state.liveness.tracked_vars) == 1:
            continue

        pre_to_last_vars = state.liveness.tracked_vars[:-1]
        # Next up we make sure that all previous-to-last constraints are the same in nature
        prev_to_last_tracked_var_constraints = []
        for var in pre_to_last_vars:
            prev_to_last_tracked_var_constraints += [state.solver.simplify(guard).replace(var, reference_var) for guard in state.history.jump_guards if contains_var(guard, var)]

        for constraint in prev_to_last_tracked_var_constraints:
            if normalized_prev_to_last_constraint is None:
                normalized_prev_to_last_constraint = constraint
            elif not claripy.is_true(normalized_prev_to_last_constraint == constraint):
                print("[CONST] [-] Encountered different previous-to-last constraint amongst states")

    if normalized_prev_to_last_constraint is None:
        print("[CONST] [-] We have no previous constraint to compare exit condition against")
        return False

    # Now check that all previous conditions are exactly Not(exit condition)
    if not claripy.is_true(state.solver.simplify(
            normalized_last_constraint == claripy.Not(normalized_prev_to_last_constraint)
        )):
        print("[CONST] [-] Not(prev-to-last constraint) != last constraint")
        return False

    print("[CONST] [+] All checks done")
    return True

# ======= Set Model =======
def check_and_gen_set_model(states):
    """ Compute Set model
    Idea: Model representing access to status register which is used in conditional execution, if-statements or a switch/case construct
    Goal: Find exhaustive set of values triggering all paths, knowing that values outside the set do not contribute additional behavior
    """

    # Check set model preconditions
    for state in states:
        # If not all variables are out of scope, we don't know whether they are still going to be checked later
        if not state_vars_out_of_scope(state):
            print("[SET Model] [-] some states have live variables ({})".format(state))
            return None
        if state_variables_involved_in_loop(state):
            print("[SET Model] [-] variable used in loop")
            return None

    # Collect variables
    variables = set()
    for state in states:
        for var in state.liveness.tracked_vars:
            variables.add(var)

    # For every variable, collect and process constraints per state
    vals = None
    for var in variables:
        # Collect constraints for variable per state (position in guards corresponds to index of state)
        guards = []
        for state in states:
            curr_guards = [guard for guard in state.history.jump_guards if guard.symbolic and contains_var(guard, var)]
            guards.append(claripy.And(*curr_guards))

        if any(map(lambda guard: any(map(lambda state_restore_reg_bitvec: contains_var(guard, state_restore_reg_bitvec), state.liveness.base_snapshot.all_initial_bitvecs)), guards)):
            print("[SET Model] [-] detected state-defined register in relevant jump guard, not assigning a set model")
            vals = None
            break

        # Combine constraints on variable for each other state
        constraints = []
        for i in range(len(states)):
            own_jumpguard = guards[i]
            curr_constraint = own_jumpguard

            # For the current state, make all constraints not collide with other state's constraints
            for j in range(len(guards)):
                # Skip our own constraints
                if j != i:
                    other_jumpguard = guards[j]
                    curr_constraint = claripy.And(curr_constraint, claripy.Or(
                        # a) either own_jumpguard implies other_jumpguard
                        own_jumpguard == claripy.Or(own_jumpguard, other_jumpguard)
                        ,
                        # b) or we need to find a value which does not take other path
                        claripy.Not(other_jumpguard)
                    ))

            # Add the variable's combined constraints for the current state
            constraints.append(curr_constraint)

        # After collecting constraints
        curr_vals = set()
        for i in range(len(states)):
            curr_vals.add(states[i].solver.min(var, extra_constraints=[constraints[i]]))

        if vals is None:
            vals = curr_vals
        elif vals != curr_vals:
            print("[SET Model] [-] got ambiguous sets")
            return None

    if vals is None:
        print("[SET Model] [-] could not find values")
        return None

    print("[SET Model]: [+] Got vals: {}".format(vals))

    # For single-valued sets, apply constant model
    if len(vals) == 1:
        return None
    else:
        return sorted(vals)

def min_bitmask(state, ast, var):
    ast = state.liveness.base_snapshot.unconstrain(ast)

    simplified_ast = state.solver.simplify(ast)
    num_bits = var.size()
    mask = claripy.BVV((1 << num_bits) - 1, num_bits)
    for i in range(num_bits):
        # flip bit to 0 and retry
        mask &= ~(1 << i)

        replacement_var = var & mask
        replaced_ast = state.solver.simplify(simplified_ast.replace(var, replacement_var))

        if not state.solver.is_true(state.solver.simplify(simplified_ast == replaced_ast)):
            mask |= (1 << i)

    return state.solver.eval(mask)


# ======= Bitextract Model =======
def compute_bitextract_mask(state):
    """ Compute Bitextract model

    """

    write_actions = [ action for action in state.history.actions if
        isinstance(action, angr.state_plugins.sim_action.SimActionData)
        and action.action == 'write' and action.type == 'mem'
        # and (print(action),print(action.actual_value) or True)
        and action.actual_value is not None
        and state.solver.symbolic(action.actual_value) ]

    masks = {}
    # Look at all writes
    for action in write_actions:
        for var in state.liveness.tracked_vars:
            if contains_var(action.actual_value, var):
                if var not in masks:
                    masks[var] = set()
                masks[var].add(min_bitmask(state, action.actual_value, var))
                break

    # Look at all jump guards
    for guard in state.history.jump_guards:
        for var in state.liveness.tracked_vars:
            if contains_var(guard, var):
                if var not in masks:
                    masks[var] = set()
                masks[var].add(min_bitmask(state, guard, var))
                break

    # Look at all in-scope registers
    for regval in in_scope_register_values(state):
        for var in state.liveness.tracked_vars:
            if contains_var(regval, var):
                if var not in masks:
                    masks[var] = set()
                masks[var].add(min_bitmask(state, regval, var))

    return masks

# ======= Config Map Creation =======
def bitmask_to_byte_shift_config(bitmask):
    if bitmask == 0:
        return 0xffffffff, 0

    min_bit, max_bit = -1, -1
    for i in range(32):
        if bitmask & 1:
            if min_bit == -1:
                min_bit = i
            max_bit = i
        bitmask >>= 1

    min_byte, max_byte = min_bit // 8, max_bit // 8
    shift = min_byte * 8
    size = max_byte - min_byte + 1
    return size, shift

def create_model_config_map_errored(pc):
    return {'errored': {'0x{:08x}'.format(pc): 'TBD'}}

def hamming_weight(val):
    res = 0
    while val:
        if val & 1:
            res += 1
        val = val >> 1
    return res

def create_model_config_map(pc, representative_state, is_passthrough, is_constant, bitmask, set_vals):
    mmio_addr, mmio_access_size = representative_state.liveness.base_snapshot.mmio_addr, representative_state.liveness.base_snapshot.mmio_access_size
    result = {}
    pc &= (~0x1)
    entry_name = "pc_{:08x}_mmio_{:08x}".format(pc, mmio_addr)
    config_entry_map = {}
    config_entry_map['addr'] = mmio_addr
    config_entry_map['pc'] = pc
    config_entry_map['access_size'] = mmio_access_size
    model_type = "unmodeled"
    if is_passthrough:
        model_type = "passthrough"
        config_entry_map['init_val'] = 0
    elif is_constant:
        assert(representative_state is not None)
        model_type = "constant"
        config_entry_map['val'] = representative_state.solver.min(representative_state.liveness.tracked_vars[-1])
    elif set_vals is not None and len(set_vals) <= MAX_SET_MODEL_VAL_NUM:
        model_type = "set"
        config_entry_map['vals'] = set_vals
    elif bitmask != 0:
        # Only assign this if no completely replacing model was identified
        byte_size, left_shift = bitmask_to_byte_shift_config(bitmask)
        # Only assign bit mask if it actually reduces the access size
        if hamming_weight(bitmask) < mmio_access_size * 8:
            model_type = "bitextract"
            config_entry_map['size'] = byte_size
            config_entry_map['left_shift'] = left_shift
            config_entry_map['mask'] = bitmask

    result[model_type] = {}
    result[model_type][entry_name]=config_entry_map

    return result

def detect_model(pc, simulation, is_timed_out=False, pre_fork_state=None):
    if is_timed_out:
        states = [pre_fork_state]
    else:
        states = simulation.found

    bitmask = 0
    is_constant = False
    is_passthrough = False
    model_config_map = None
    set_vals = None
    state = None
    tracked_mmio_constrains_any_path = False

    if is_timed_out:
        """
        For the timeout case, we only have a parent state before the first split.
        In this case, only the following models may possibly apply:
            - bitextract (a mask/extraction has already been applied)
            - passthrough (value has already been discarded without applying path constraints)
        """
        state = states[0]
        returned = state.liveness.returned
        all_vars_out_of_scope = state_vars_out_of_scope(state)
        constrains_path = state_contains_tracked_mmio_path_constraints(state)
        tracked_mmio_constrains_any_path |= constrains_path

        # 1. Check for passthrough model
        if all_vars_out_of_scope:
            is_passthrough = check_is_passthrough_model(state, constrains_path, returned, all_vars_out_of_scope)
        else:
            print("[PASSTHROUGH] [-] Not all vars out of scope")

        # 2. Check for bitextract model
        min_masks = compute_bitextract_mask(state)
        print("Got minimal mask set: {}".format(min_masks)) # list(map(hex, min_masks)))
        if min_masks:
            for var, masks in min_masks.items():
                for mask in masks:
                    bitmask |= mask
        print("State: {}\nReturned: {}\nVars dead: {}\nIs config reg: {}\nbitmask: {:x}".format(state, returned, all_vars_out_of_scope, is_passthrough, bitmask))

    elif simulation.found:
        states = simulation.found

        is_passthrough = True
        for state in states:
            returned = state.liveness.returned
            all_vars_out_of_scope = state_vars_out_of_scope(state)
            constrains_path = state_contains_tracked_mmio_path_constraints(state)
            tracked_mmio_constrains_any_path |= constrains_path

            if is_passthrough:
                curr_is_passthrough = check_is_passthrough_model(state, constrains_path, returned, all_vars_out_of_scope)
                is_passthrough = is_passthrough and curr_is_passthrough
            
            min_masks = compute_bitextract_mask(state)
            print("Got minimal mask set: {}".format(min_masks)) # list(map(hex, min_masks)))
            if min_masks:
                for var, masks in min_masks.items():
                    for mask in masks:
                        bitmask |= mask
            
            print("State: {}\nReturned: {}\nVars dead: {}\nIs config reg: {}\nbitmask: {:x}".format(state, returned, all_vars_out_of_scope, curr_is_passthrough, bitmask))

        set_vals = check_and_gen_set_model(states)

        is_constant = check_is_constant_model(states)

    # We treat the config model in a special way here and ignore deep calls
    if not tracked_mmio_constrains_any_path and not is_passthrough and all(map(lambda state: state.globals['config_write_performed'], all_states(simulation))):
        print("[PASSTHROUGH] [WARNING] Assigning low-confidence config model")
        is_passthrough = True

    model_config_map = create_model_config_map(pc, state, is_passthrough, is_constant, bitmask, set_vals)

    return model_config_map, is_passthrough, is_constant, bitmask, set_vals