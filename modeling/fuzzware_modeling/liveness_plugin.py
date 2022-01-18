import angr
import claripy
import archinfo
import copy
import logging
from .base_state_snapshot import BaseStateSnapshot

from .angr_utils import MAX_DEAD_VARS, NVIC_RET_START
l = logging.getLogger("LIVENESS")

class StackFrame:
    def __init__(self, base_sp=None, tracked_addrs=None):
        # We use a None base_sp as the catchall base_sp for the first frame as we do not know the real stack start
        self.base_sp = base_sp
        self.tracked_addrs = {} if tracked_addrs is None else tracked_addrs

    def holds_local_var(self, addr):
        return addr in self.tracked_addrs

    def add_local_var_addr(self, addr, size):
        self.tracked_addrs[addr] = size

    def remove_local_var_addr(self, addr):
        return self.tracked_addrs.pop(addr)

    def possibly_in_frame(self, addr):
        return self.base_sp is None or self.base_sp >= addr

    def copy(self):
        return StackFrame(self.base_sp, copy.deepcopy(self.tracked_addrs))

class LivenessPlugin(angr.SimStatePlugin):
    base_snapshot: BaseStateSnapshot

    alive_varname_counts: dict
    tracked_vars: list
    stackframes: list
    returned: bool
    all_vars_dead: bool

    def __init__(self, base_snapshot, alive_vars=None, tracked_vars=None, returned=False, stackframes=None, all_vars_dead=False):
        super(LivenessPlugin, self).__init__()
        # Type: {<bytes>: [<total_counter>, <stack_var_counter>], <bytes>: [<total_counter>, <stack_var_counter>]}
        self.alive_varname_counts = alive_vars if alive_vars is not None else {}
        self.tracked_vars = tracked_vars if tracked_vars is not None else []

        # The base snapshot is a singleton for each restored state
        self.base_snapshot = base_snapshot
        self.returned = returned
        self.all_vars_dead = all_vars_dead

        if stackframes is None:
            # Create initial stackframe
            self.stackframes = [StackFrame()]
        else:
            self.stackframes = stackframes

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return LivenessPlugin(self.base_snapshot, copy.deepcopy(self.alive_varname_counts), copy.deepcopy(self.tracked_vars), returned=self.returned, stackframes=[f.copy() for f in self.stackframes], all_vars_dead=self.all_vars_dead)

    @property
    def call_depth(self):
        return len(self.stackframes) - 1

    def _remove_ref(self, varname):
        self.alive_varname_counts[varname] -= 1
        l.warning("[%x] Decreasing alive var ref: %r, #refs now: %d", self.state.addr, varname, self.alive_varname_counts[varname])
        if self.alive_varname_counts[varname] == 0:
            l.warning("Removing %r from mmio alive list", varname)
            self.alive_varname_counts.pop(varname)

            if not self.alive_varname_counts:
                self.all_vars_dead = True
            elif len(self.tracked_vars) >= MAX_DEAD_VARS and not self.state.globals['dead_too_many_out_of_scope']:
                l.warning("################# GOT more than maximum number of tracked vars")
                kill = True
                for var in self.tracked_vars[:MAX_DEAD_VARS]:
                    if var._encoded_name.decode() in self.alive_varname_counts:
                        kill = False
                if kill:
                    l.warning("Too many first variables went out of scope, setting flag")
                    self.state.globals['dead_too_many_out_of_scope'] = True

    def _add_ref(self, varname):
        self.alive_varname_counts[varname] += 1
        l.warning("[%x] Increasing alive var ref: %r, #refs now: %d", self.state.addr, varname, self.alive_varname_counts[varname])

    def _remove_scratch_reg_refs(self):
        for reg in [self.state.regs.r1, self.state.regs.r2, self.state.regs.r3, self.state.regs.lr]:
            for varname in reg.variables:
                if varname in self.alive_varname_counts:
                    l.debug("Function return liveness updates; decreasing count for variable: %r", varname)
                    self._remove_ref(varname)

    def enter_function(self, state):
        """
        Called upon function calls.

        This sets up a stack frame to track local variable writes.
        """
        # Do not add any frames after we already
        if self.stackframes:
            self.stackframes.append(StackFrame(state.solver.eval(state.regs.sp)))

    def leave_function(self, state):
        """
        Called upon function return.

        This deals with the cleanup of stack frames and their references.
        """
        l.warning("[%x] Returning from function", state.addr)

        # In case we already returned from the top level function, don't deal with stack writes anymore
        if not self.stackframes:
            return

        # Pop stack frame and remove all remaining references to 
        curr_frame = self.stackframes.pop()
        for addr, size in curr_frame.tracked_addrs.items():
            contents = state.memory.load(addr, size, disable_actions=True, inspect=False)
            for varname in contents.variables:
                if varname in self.alive_varname_counts:
                    self._remove_ref(varname)

        # For top level function return, also remove scratch registers from scope
        if not self.stackframes:
            l.warning("[{:x}] Returned from top level function".format(state.addr))
            self.returned = True
            self._remove_scratch_reg_refs()
            if NVIC_RET_START <= state.addr <= NVIC_RET_START | 0xfff:
                l.critical("returning from ISR")

    def on_before_reg_write(self, write_expr, reg_write_offset, write_len):
        """
        Called before register is written to.

        This tracks variable references in registers.
        """
        # Tick up written references
        if write_expr.symbolic:
            # angr may keep an ast expression around which contains a var which is meaningless
            write_expr = self.state.solver.simplify(write_expr)
            for varname in write_expr.variables:
                if varname in self.alive_varname_counts:
                    self._add_ref(varname)

        # Kill overwritten references
        old_val = self.state.registers.load(reg_write_offset, write_len, disable_actions=True, inspect=False, endness=archinfo.Endness.LE)
        if old_val.symbolic:
            for varname in self.state.solver.simplify(old_val).variables:
                if varname in self.alive_varname_counts:
                    self._remove_ref(varname)

    def on_before_stack_mem_write(self, write_addr, write_expr, write_len):
        """
        Called before memory is written to the stack.

        This tracks variable references in stack frames.
        """
        l.debug("Stack write. write_addr: %x, write_expr: %r, write_len: %r", write_addr, write_expr, write_len)

        # 0. We might write to the stack after we left the toplevel function
        if not self.stackframes:
            # Just track normally in this case
            for varname in write_expr.variables:
                if varname in self.alive_varname_counts:
                    self._add_ref(varname)

            old_val = self.state.memory.load(write_addr, write_len, disable_actions=True, inspect=False, endness=archinfo.Endness.LE)
            for varname in old_val.variables:
                if varname in self.alive_varname_counts:
                    self._remove_ref(varname)

            return

        # 1. First find the stack frame the value is written to
        frame = self.stackframes[0]
        for i in range(len(self.stackframes)-1, 0, -1):
            if self.stackframes[i].base_sp != self.stackframes[i - 1].base_sp and self.stackframes[i].possibly_in_frame(write_addr):
                frame = self.stackframes[i]
                l.debug("Using deep stack frame at index %d, base_sp: %x", i, frame.base_sp)
                break

        # 2. Tick the reference count up
        for varname in write_expr.variables:
            if varname in self.alive_varname_counts:
                self._add_ref(varname)

        l.debug("Stack variable write to %x [tracked addresses: %r]", write_addr, list(map(hex, frame.tracked_addrs)))

        # 3. Now do bookkeeping about the address. If the address is not yet tracked, don't look at old_val
        if write_addr in frame.tracked_addrs:
            old_val = self.state.memory.load(write_addr, write_len, disable_actions=True, inspect=False, endness=archinfo.Endness.LE)
            l.debug("Address already tracked, checking previous contents for override: %r", old_val)
            for varname in old_val.variables:
                if varname in self.alive_varname_counts:
                    self._remove_ref(varname)
        else:
            l.debug("Not yet tracking stack variable, adding %x", write_addr)
            frame.tracked_addrs[write_addr] = write_len

    def on_after_mmio_mem_read(self, read_addr, read_expr, read_len):
        """
        Called after memory is read.
        
        This adds MMIO variables and possibly tracks them
        """
        addr = self.state.solver.eval(read_addr)

        new_var = claripy.BVS('mmio_{:08x}'.format(addr), 8* read_len)

        if not self.returned and addr == self.base_snapshot.mmio_addr and self.state.addr == self.base_snapshot.access_pc:
            l.warning(f"Adding mmio variable {new_var} {new_var._encoded_name}")
            self.alive_varname_counts[new_var._encoded_name.decode()] = 0
            self.tracked_vars.append(new_var)

        self.state.inspect.mem_read_expr = new_var
