#!/usr/bin/env python
import os
import logging
import signal
import traceback

import angr
import claripy
import archinfo

from . import DEFAULT_TIMEOUT, EXPLORATION_TIMEOUT_FACTOR
from .angr_utils import CUSTOM_STASH_NAMES, insn_addr_from_SimIRSBNoDecodeError
from .base_state_snapshot import BaseStateSnapshot
from .fuzzware_utils.config import update_config_file, TRACE_NAME_TOKENS
from .model_detection import detect_model, create_model_config_map_errored
from .liveness_plugin import LivenessPlugin
from .exploration_techniques import MMIOVarScoper, FunctionReturner, FirstStateSplitDetector, TimeoutDetector, LoopEscaper, StateExplosionDetector
from .inspect_breakpoints import inspect_bp_track_newly_added_constraints, inspect_bp_trace_call, inspect_bp_trace_ret, inspect_bp_trace_liveness_reg, inspect_bp_trace_liveness_mem, inspect_cond_is_mmio_read, inspect_bp_mmio_intercept_read_after, inspect_bp_trace_reads, inspect_bp_trace_writes, inspect_bp_singleton_ensure_mmio, inspect_after_address_concretization
from .arch_specific.arm_thumb_regs import regular_register_names
from .arch_specific.arm_thumb_quirks import try_handling_decode_error, model_arch_specific
from .logging_utils import set_log_levels

l = logging.getLogger("ANA")

""" Execution Strategy
1. Run until no active anymore
- Finished stepping:
    - all variables dead
        - no path constraint -> found
        - path constraint -> vars_dead_but_path_constrained
    - return from function -> returns val ? returning_val : found
- Unfinished stepping:
    - limits:
        - too deep calls
        - too many loop iterations
        - too many steps
        - too many concurrent states
        - too many (tracked) variables dead
        - too much time spent (timeout)
    - analysis scope escapes:
        - write to non-local memory -> globals['dead_write_to_env']

2. Check different stashes upon hitting limits
    - Ignored
        - loops: assume that there is no functionality 'hiding' in later loop iterations
            - in edge cases this could happen such as: for(i=0;i<1000;++i){if(i = 750) do_stuff;}
        - too_many_out_of_scope: assume that last variable will similarly be killed and replaced by new one
    - Fall back to pre-fork state for too complex processing
        - deep_calls: stopped due to path explosion
        - active: still active when limit was reached
        - deferred: still active in DFS
    - If regular case, collect states for modelling
        - returning_val: function returned value
        - found: all vars dead and nothing to step
        - vars_dead_but_path_constrained: also vars dead
"""

def perform_analyses(statefiles, cfg, is_debug=False, timeout=DEFAULT_TIMEOUT):
    if is_debug:
        set_log_levels(logging.DEBUG)
        l.debug("debug logging enabled")

    result_lines, config_entries = [], []
    for statefile in statefiles:
        if any(tok in os.path.basename(statefile) for tok in TRACE_NAME_TOKENS):
            l.warning(f"Skipping trace file {statefile}")
            continue
        line, config = perform_analysis(statefile, cfg=cfg, is_debug=is_debug, timeout=timeout)
        result_lines.append(line), config_entries.append(config)
    return result_lines, config_entries

def setup_analysis(statefile, cfg=None):
    if not os.path.isfile(statefile):
        raise ValueError("State file does not exist: {}".format(statefile))

    # Load snapshot and pre-constrain state registers for tainting
    project, initial_state, base_snapshot = BaseStateSnapshot.from_state_file(statefile, cfg)

    # Breakpoints: MMIO handling
    initial_state.globals['tmp_mmio_bp'] = initial_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=inspect_bp_singleton_ensure_mmio)
    initial_state.inspect.b('mem_read', when=angr.BP_AFTER, action=inspect_bp_mmio_intercept_read_after, condition=inspect_cond_is_mmio_read)

    # Breakpoints: Liveness
    initial_state.inspect.b('reg_write', when=angr.BP_BEFORE, action=inspect_bp_trace_liveness_reg)
    initial_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=inspect_bp_trace_liveness_mem)
    initial_state.inspect.b('exit', when=angr.BP_BEFORE, action=inspect_bp_trace_ret)
    initial_state.inspect.b('call', when=angr.BP_BEFORE, action=inspect_bp_trace_call)

    # Breakpoints: Constraints
    initial_state.inspect.b('address_concretization', when=angr.BP_AFTER, action=inspect_after_address_concretization)
    initial_state.inspect.b('constraints', when=angr.BP_AFTER, action=inspect_bp_track_newly_added_constraints)

    # Set up state globals which are set by inspection breakpoints and exploration techniques
    initial_state.globals['dead_too_many_out_of_scope'] = False
    initial_state.globals['dead_write_to_env'] = False
    initial_state.globals['path_constrained'] = False
    initial_state.globals['meaningful_actions_while_constrained'] = False
    initial_state.globals['config_write_performed'] = False

    # Arch-specific reg constants
    initial_state.globals['regular_reg_offsets'] = frozenset([initial_state.arch.get_register_offset(name) for name in regular_register_names])

    # Make memory accesses show up in state histories
    initial_state.options.add(angr.options.TRACK_MEMORY_ACTIONS)

    # Register plugin to track dynamic liveness
    initial_state.register_plugin('liveness', LivenessPlugin(base_snapshot))

    return project, initial_state, base_snapshot

MAX_NODECODE_ERRORS = 5
def wrapped_explore(simulation, **kwargs):
    """
    Step while trying to handle decoding errors.
    """

    stash_name = kwargs.get('stash') or 'active'

    cnt = 0
    while cnt < MAX_NODECODE_ERRORS:
        cnt += 1
        try:
            simulation.explore(**kwargs)
        except angr.errors.SimIRSBNoDecodeError as e:
            l.warning(f"Got SimIRSBNoDecodeError error: {e}")
            addr = insn_addr_from_SimIRSBNoDecodeError(e)

            # Try recovering from things like breakpoints
            if not try_handling_decode_error(simulation, stash_name, addr):
                return False
        except (angr.errors.SimZeroDivisionException) as e:
            traceback.print_tb(e.__traceback__)
            return False
        except TimeoutError:
            return False

    return True

def timeout_handler(signal_no, stack_frame):
    l.warning("Hard timeout triggered. Raising exception...")
    raise TimeoutError()

def perform_analysis(statefile, cfg=None, is_debug=False, timeout=DEFAULT_TIMEOUT):
    project, initial_state, base_snapshot = setup_analysis(statefile, cfg)
    start_pc = base_snapshot.initial_pc

    if is_debug:
        initial_state.inspect.b('mem_read', when=angr.BP_AFTER, action=inspect_bp_trace_reads)
        initial_state.inspect.b('mem_write', when=angr.BP_AFTER, action=inspect_bp_trace_writes)

    simulation = project.factory.simgr(initial_state, resilience=False)

    # Handle quirky arch-specific instruction modeling
    result_line, config_entry = model_arch_specific(project, initial_state, base_snapshot, simulation)
    if result_line is not None and config_entry is not None:
        return result_line, config_entry

    for stash_name in CUSTOM_STASH_NAMES:
        simulation.populate(stash_name, [])

    # Simulation techniques
    simulation.use_technique(angr.exploration_techniques.DFS())
    timeout_detector_technique = simulation.use_technique(TimeoutDetector(EXPLORATION_TIMEOUT_FACTOR * timeout))
    state_explosion_detector_technique = simulation.use_technique(StateExplosionDetector())
    first_state_split_detector_technique = simulation.use_technique(FirstStateSplitDetector())
    simulation.use_technique(FunctionReturner())
    simulation.use_technique(MMIOVarScoper())
    simulation.use_technique(LoopEscaper(debug=is_debug))

    # Set Hard timeout
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

    l.warning("Starting simulation now...")

    MAX_STEPS = 750
    explore_failed = wrapped_explore(simulation, n=MAX_STEPS, num_find=0xffff, opt_level=0) is False

    l.info("### Stashes (after stepping):\n" \
        + "active:        {}\n".format(simulation.active) \
        + "loops:         {}\n".format(simulation.loops) \
        + "too_many_out_of_scope: {}\n".format(simulation.too_many_out_of_scope) \
        + "deep_calls:    {}\n".format(simulation.deep_calls) \
        + "vars_dead_but_path_constrained: {}\n".format(simulation.vars_dead_but_path_constrained) \
        + "returning_val: {}\n".format(simulation.returning_val) \
        + "errored:       {}\n".format(simulation.errored) \
        + "unsat:         {}\n".format(simulation.unsat) \
        + "found:         {}".format(simulation.found))
    simulation.move(from_stash="deferred", to_stash="active")

    # Check different error cases to trigger pre-fork state fallback
    if explore_failed:
        l.critical("Got exception during stepping. Skipping further execution...")
        timeout_detector_technique.timed_out = True
    elif simulation.active or simulation.deep_calls:
        l.critical("Active / deep call states are present after first round of exploration, too complex processing. Skipping further execution...")
        timeout_detector_technique.timed_out = True
    elif state_explosion_detector_technique.is_exploded:
        l.critical("State explosion detected. Skipping further execution...")
        timeout_detector_technique.timed_out = True
    elif timeout_detector_technique.timed_out:
        l.critical("Hit timeout")

    # Collect finished states
    # If unfinished states (active / deep_calls) are present, we will be in timeout case
    simulation.move(from_stash='returning_val', to_stash='found')
    simulation.move(from_stash='vars_dead_but_path_constrained', to_stash='found')

    if not simulation.found:
        simulation.move(from_stash='loops', to_stash='found')

    mmio_addr = initial_state.liveness.base_snapshot.mmio_addr
    if timeout_detector_technique.timed_out or not simulation.found:
        if first_state_split_detector_technique.pre_fork_state:
           l.warning("Falling back to pre-fork state examination: {}".format(first_state_split_detector_technique.pre_fork_state))
           config_entry, is_passthrough, is_constant, bitmask, set_vals = detect_model(start_pc, simulation, is_timed_out=True, pre_fork_state=first_state_split_detector_technique.pre_fork_state)

           result_line = "pc: 0x{:08x}, mmio: 0x{:08x}, is_passthrough: {}, is_constant: {}, bitmask: {:x}, set vals: {}\n".format(start_pc, mmio_addr, is_passthrough, is_constant, bitmask, set_vals)
        else:
           config_entry = create_model_config_map_errored(start_pc)
           result_line = "pc: 0x{:08x} NO SOLUTIONS\n".format(start_pc)

    else:
        l.info("Number of solution states (pc: {:08x}): {}".format(start_pc, len(simulation.found)))

        config_entry, is_passthrough, is_constant, bitmask, set_vals = detect_model(start_pc, simulation)

        result_line = "pc: 0x{:08x}, mmio: 0x{:08x}, is_passthrough: {}, is_constant: {}, bitmask: {:x}, set vals: {}\n".format(start_pc, mmio_addr, is_passthrough, is_constant, bitmask, set_vals)

    return result_line, config_entry


def analyze_mmio_and_store(statefiles, out_path, fuzzware_config_map=None, timeout=DEFAULT_TIMEOUT, is_debug=False):
    """
    The wrapper which is invoked by the pipeline's modeling workers
    """
    _, model_entries = perform_analyses(statefiles, fuzzware_config_map, is_debug=is_debug, timeout=timeout)

    update_config_file(out_path, model_entries)
    return True
