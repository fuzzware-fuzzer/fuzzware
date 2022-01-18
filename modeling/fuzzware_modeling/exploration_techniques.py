import time
import logging

import angr, claripy

from .angr_utils import contains_var, state_returns_val, MAX_CALL_DEPTH, MAX_BB_VISITS, NON_FORKING_STATE_MAX_BB_VISITS, MAX_ACTIVE_STATES
from .arch_specific.arm_thumb_regs import return_reg

l = logging.getLogger("EXPLORE")

class MMIOVarScoper(angr.exploration_techniques.ExplorationTechnique):
    """
    Exploration technique reacting to dynamic liveness tracking.
    """
    def __init__(self):
        super(MMIOVarScoper, self).__init__()

    def filter(self, simgr, state, **kwargs):
        found = False
        if state.liveness.all_vars_dead:
            try:
                block = state.block(state.addr)
            except angr.errors.SimEngineError:
                # We can run in here in case we are returning from interrupt handlers
                block = None

            if block is not None and state.liveness.base_snapshot.access_pc in block.instruction_addrs:
                # We are back to the first block of our MMIO access instruction. Keep on stepping
                # The loop detector will prevent us from going overboard with executions
                state.liveness.all_vars_dead = False
                state.globals['path_constrained'] = False
            elif not state.globals['path_constrained']:
                found = True
                l.warning("State (pc={:x}) MMIO variables all went out of scope and no path constraint: {}".format(state.addr, state))
            else:
                l.warning("State (pc={:x}) MMIO variables all went out of scope but path is constrained: {}".format(state.addr, state))
                return 'vars_dead_but_path_constrained'

        if found:
            return 'found'
        return simgr.filter(state, **kwargs)

class FunctionReturner(angr.exploration_techniques.ExplorationTechnique):
    """
    Exploration technique catching returned states and too deep call stacks.
    """
    def __init__(self):
        super(FunctionReturner, self).__init__()
        self.has_deep_call = False

    def filter(self, simgr, state, **kwargs):
        if state.liveness.returned:
            l.critical("State (pc={:x}) returned from initial function: {}. retval: {}".format(state.addr, state, return_reg(state)))
            if state_returns_val(state):
                l.warning("Function returns val, putting into 'returning_val' stash")
                return 'returning_val'
            else:
                return 'found'

        elif state.liveness.call_depth > MAX_CALL_DEPTH:
            l.warning("State {} got deep call stack ({}), shifting to alternative stash".format(state, state.liveness.call_depth))
            self.has_deep_call = True
            return 'deep_calls'
        else:
            return simgr.filter(state, **kwargs)

    def successors(self, simgr, state, **kwargs):
        successors = simgr.successors(state, **kwargs)

        for successor_state in successors.successors:
            if (not successor_state.globals['path_constrained']):
                for var in successor_state.liveness.tracked_vars:
                    # TODO: Convert this to successor_state.history.jump_guards instead as soon as a jump guard shows up for all (including CBZ) instructions
                    if any([contains_var(guard, var) for guard in successor_state.solver.constraints]):
                        l.warning("State is now constrained: {}".format(successor_state))
                        successor_state.globals['path_constrained'] = True
                        break

        return successors

    def complete(self, simgr):
        if self.has_deep_call:
            self.has_deep_call = False
            l.warning("State is deep in call stack, completing simulation")
            return True
        return False

class FirstStateSplitDetector(angr.exploration_techniques.ExplorationTechnique):
    """
    Exploration technique collecting the state prior to the first split.
    This state can be used as backup in case we run into errors or explode.
    """
    def __init__(self):
        super(FirstStateSplitDetector, self).__init__()
        self.pre_fork_state = None
        self.has_forked_state = False

    def step_state(self, simgr, state, **kwargs):
        self.pre_fork_state = state
        return simgr.step_state(state, **kwargs)

    def successors(self, simgr, state, **kwargs):
        successors = simgr.successors(state, **kwargs)

        if (not self.has_forked_state) and (len(successors.successors) > 1):
            self.has_forked_state = True

            msg = "\n=========== FirstStateSplitDetector ================\n"
            msg += str(successors) + "\n"
            for successor_state in successors.successors:
                msg += str(successor_state) + "\n"
            msg += "Parent state: {}\n".format(self.pre_fork_state)
            msg += "===================================================="
            l.warning(msg)

        return successors

class TimeoutDetector(angr.exploration_techniques.ExplorationTechnique):
    """
    Exploration technique stopping execution upon timeout.
    """
    def __init__(self, timeout):
        self.start = time.time()
        self.end = self.start + timeout
        self.timeout = timeout
        self.timed_out = False

        super(TimeoutDetector, self).__init__()

    def complete(self, simgr):
        if time.time() > self.end:
            l.warning("[TimeoutDetector] time is up! Timeout of {} seconds expired".format(self.timeout))
            self.timed_out = True
            return True
        return False

class StateExplosionDetector(angr.exploration_techniques.ExplorationTechnique):
    """
    Exploration technique stopping execution in case too many parallel states are encountered.
    """
    def __init__(self):
        self.is_exploded = False
        super(StateExplosionDetector, self).__init__()

    def complete(self, simgr):
        if len(simgr.deferred) > MAX_ACTIVE_STATES:
            l.warn("[StateExplosionDetector] Too many parallel states in 'deferred'. Stop stepping")
            self.is_exploded = True
            return True
        return False

class LoopEscaper(angr.exploration_techniques.ExplorationTechnique):
    """
    Exploration technique to avoid taking loops too many times.
    """
    def __init__(self, max_visits=MAX_BB_VISITS, debug=False):
        super(LoopEscaper, self).__init__()
        self.max_visits = max_visits
        self.debug = debug

    def filter(self, simgr, state, **kwargs):

        # TODO: maybe we want to keep a count manually if this is impeding performance
        num_visits = state.history.bbl_addrs.count(state.addr)
        if num_visits >= self.max_visits:
            # While we are at too many iterations, see whether there is no state explosion happening, then go on for longer
            # For states that exhibit meaningful behavior while being constrained, we cut down on the extended number of loop times
            if state.history.jump_guard is claripy.true and (num_visits < (NON_FORKING_STATE_MAX_BB_VISITS if (not state.globals['meaningful_actions_while_constrained']) and state.liveness.call_depth == 0 else NON_FORKING_STATE_MAX_BB_VISITS//5)):
                l.info("Stepping through loop at 0x{:08x} an additional time ({}) because no additional states are created".format(state.addr, num_visits))
            else:
                l.critical("State (pc={:x}) exceeded max back edge visits: {}".format(state.addr, state))

                # Put at least one state into the stash to let the analysis know about it
                if (not simgr.loops) or self.debug:
                    return 'loops'
                else:
                    return '_DROP'
        elif state.globals['dead_too_many_out_of_scope']:    
            l.critical("State (pc={:x}) too many MMIO variables went out of scope: {}".format(state.addr, state))

            # Put at least one state into the stash to let the analysis know about it
            if (not simgr.too_many_out_of_scope) or self.debug:
                return 'too_many_out_of_scope'
            else:
                return '_DROP'
        else:
            return simgr.filter(state, **kwargs)
