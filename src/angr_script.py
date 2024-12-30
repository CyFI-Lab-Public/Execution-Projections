import angr
import claripy
import time
import sys
import os
import ipdb
import time
import atexit
import signal
import logging
import copy
import traceback as tb
import random
import pickle
import angrcli.full
import angrcli.plugins.ContextView          # Print the state: state.context_view.pprint()

from multiprocessing import Process, Queue

# Local Imports
sys.path.append('../')
from log_parsing.parser_perf import parse_perf_script_output
from log_parsing.parser_gdb import parse_gdb_log_triggered, parse_gdb_log_all
from log_parsing.parser_nginx_mapped import parse_nginx_mappings
from pretty_print import print_msg_box


# Process Cleanup
def cleanup():
    os.kill(os.getpid(), signal.SIGTERM)
atexit.register(cleanup)



grep_path = '/home/dinko/exec-proj/grep/grep-3.11/src/grep'
grep_perf_log = '..../perf_script_dynamic.log'
grep_gdb_log = '/home/dinko/exec-proj/log/grep/function_trace_BRsrc.log'


nginx_path = '/usr/local/nginx/sbin/nginx'
nginx_gdb_log = '/home/dinko/exec-proj/log/nginx/function_trace_src.log'
nginx_mapped_logs = '/home/dinko/exec-proj/log_parsing/mapped_nginx_logs_2.log'





""" CONFIGURABLE OPTIONS """

bin_path = nginx_path
gdb_log_path = None
mapped_applogs_path = nginx_mapped_logs
EXPLORE_MAX_SECS = 5000          # exploration time (s) limit (between each log)
FOUND_LIMIT = 1                  # found paths limit
RESTORE = False                  # whether to restore angr simgr from previous run (./nginx_simgr.angr)

bin_name = os.path.basename(bin_path)

print(f"bin_path: {bin_path}\ngdb_log_path: {gdb_log_path}\nEXPLORE_MAX_SECS: {EXPLORE_MAX_SECS}\nmapped_applogs_path: {mapped_applogs_path}\n\n", flush=True)
# print_msg_box("HELLO")
global_start = time.time()
SIMGR = None
ITER = 0
step_count = 0

outfile = "execution_path.log"
with open(outfile, "w"):            # clear file
    pass



sys.set_int_max_str_digits(0)       # exception: Exceeds the limit (4300) for integer string conversion




""" Logging """

# Create log file handler with formatter
fh = logging.FileHandler(f'log_{bin_name}_{EXPLORE_MAX_SECS}_HOOK0.1.log', mode='w')
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(levelname)s - %(name)s - %(message)s - %(pathname)s:%(lineno)d',        # - %(asctime)s.%(msecs)03d - %(funcName)s()
    datefmt='%Y-%m-%d %H:%M:%S'
)
fh.setFormatter(formatter)

# Add logging for SimulationManagers
logger_simgr = logging.getLogger('angr.sim_manager')
logger_simgr.setLevel(logging.DEBUG)
logger_simgr.addHandler(fh)

# Add logging for SimProcedures
logger_simprocedures = logging.getLogger('angr.procedures')
logger_simprocedures.setLevel(logging.DEBUG)
logger_simprocedures.addHandler(fh)

# Add procedure logging
logger_procedures = logging.getLogger('angr.engines.procedure')
logger_procedures.setLevel(logging.DEBUG)
logger_procedures.addHandler(fh)

# Add logging for symbol resolution/loading
logger_loader = logging.getLogger('angr.loader')
logger_loader.setLevel(logging.DEBUG)
logger_loader.addHandler(fh)

# Add hook logging
logger_hooks = logging.getLogger('angr.project')
logger_hooks.setLevel(logging.DEBUG)
logger_hooks.addHandler(fh)





""" Log Parsing """

# LOG: 'perf script'
"""syscall_data = parse_perf_script_output(grep_perf_log)

for entry in syscall_data:
    print(f"Syscall: {entry['syscall']}, Callsite: {entry['callsite']}", flush=True)
print_msg_box(f"===== {len(syscall_data)} syscall callsites =====")"""


# LOG: gdb func trace
base_address = 0x555555554005           # if ASLR disabled, this is always the load address
base_angr = 0x400000

# parse all breakpoints
"""gdb_all = parse_gdb_log_all(gdb_log_path)
for i in range(len(gdb_all)):
    gdb_all[i] = int(gdb_all[i], 16) + base_angr
gdb_all = set(gdb_all)"""

# # parse sequence of triggered callsites to use as 'find' in angr explore
# gdb_logs = parse_gdb_log_triggered(gdb_log_path)

all_addrs = [] # get all callsites to use for 'avoid' in angr_explore

# for entry in gdb_logs[1:]:
#     addr = int(entry['Addr'], 16) - base_address + base_angr
#     all_addrs.append(addr)
#     entry['Addr'] = hex(addr)
#     print(f"{entry['Addr']}, {entry['Func']}", flush=True)
# print_msg_box(f"===== {len(gdb_logs)} callsites =====")


# parse the mapped nginx application logs for lea_addr, func_name, and msg
nginx_logs = parse_nginx_mappings(nginx_mapped_logs)
for entry in nginx_logs:
    addrs = entry['lea_addr']
    for idx, addr in enumerate(addrs):
        new_addr = int(addr, 16) + base_angr
        all_addrs.append(new_addr)
        entry['lea_addr'][idx] = hex(new_addr)
    print(f"Log Msg: {entry['log_msg']}", flush=True)
    print(f"LEA addr: {entry['lea_addr']}", flush=True)
    print(f"Func: {entry['function']}", flush=True)
    print(f"Fmt Str: {entry['fmt_str']}", flush=True)
    print(f"Concrete: {entry['concrete_vals']}\n", flush=True)

print_msg_box(f"===== {len(nginx_logs)} log sites =====")
all_addrs = set(all_addrs)      # remove dups





""" angr project save and load functions """

def save_angr_simgr(simgr, iteration, filename):
    """
    Save an angr simgr to disk using pickle.
    
    Since angr Project objects themselves aren't directly serializable,
    we save the simgr directly.
    
    Args:
        simgr: The angr simgr object
        iteration: The explore iteration (log checkpoint) at which analysis failed to find any paths
        filename: Base filename to save to
    """
    # Create a dictionary with all the necessary information
    save_data = {
        'simgr': simgr,
        'iteration': iteration
    }

    # Save everything to a single pickle file
    with open(filename + '.angr', 'wb') as f:
        pickle.dump(save_data, f)


def load_angr_simgr(filename):
    """
    Load a previously saved angr project state.
    
    Args:
        filename: Filename to load from
    
    Returns:
        tuple: (loaded simgr object, iteration when failed)
    """
    # Load the saved data
    with open(filename + '.angr', 'rb') as f:
        save_data = pickle.load(f)
    
    
    return save_data['simgr'], save_data['iteration']





""" angr SymEx Setup"""

def setup_grep_symex_state(proj):    
    # Get the address of main
    main_addr = proj.loader.find_symbol('main').rebased_addr
    
    # Create symbolic file contents and size
    symbolic_content = claripy.BVS('file_content', 8 * 1024)  # 1KB symbolic buffer to start
    symbolic_size = claripy.BVS('file_size', 64)  # 64-bit size
    
    # Create concrete command line arguments
    argv = [
        claripy.BVV(b"grep\x00"), 
        claripy.BVV(b"-E\x00"),
        claripy.BVV(b'^([A-Za-z]+( [A-Za-z]+)*) - \\[(ERROR|WARN|INFO)\\] ([0-9]{4}-[0-9]{2}-[0-9]{2}) <([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,})>$\x00'),
        claripy.BVV(b"testfile.txt\x00")
    ]
    
    state = proj.factory.entry_state(
        addr=main_addr,
        args=argv,
        add_options={
            angr.options.SYMBOLIC_WRITE_ADDRESSES,
            angr.options.SYMBOLIC,
            angr.options.SYMBOLIC_INITIAL_VALUES,
            angr.options.TRACK_MEMORY_ACTIONS,
            angr.options.TRACK_JMP_ACTIONS,
            angr.options.TRACK_CONSTRAINT_ACTIONS,
            angr.options.LAZY_SOLVES,
        }
    )
    
    # Set up file system
    simfile = angr.SimFile('testfile.txt', content=symbolic_content, size=symbolic_size)
    state.fs.insert('testfile.txt', simfile)
    
    # Add constraints on the symbolic size
    state.solver.add(symbolic_size >= 0)
    state.solver.add(symbolic_size <= 1024)  # Limit size to 1KB for now
    
    return state


def setup_nginx_symex_state(proj):   
    # start_addr = proj.loader.find_symbol('ngx_epoll_process_events').rebased_addr
    # state = proj.factory.blank_state(
    #     addr=start_addr,
    # )

    # # ngx_single_process_cycle
    # start_addr = proj.loader.find_symbol('ngx_single_process_cycle').rebased_addr
    # state = proj.factory.blank_state(
    #     addr=start_addr,
    # )

    start_addr = proj.entry
    print_msg_box(f"START_ADDR: {hex(start_addr)}")
    state = proj.factory.entry_state()


    return state


def hook_init_localeinfo(state):
    print(f"[HOOK] init_localeinfo called at {state.regs.rip}", flush=True)
    # Log callsite info if available
    if state.history.jumpkind == 'Ijk_Call':
        print(f"[HOOK] Called from {state.history.jump_source}", flush=True)
    return


def hook_c_stack_action(state):
    print(f"[HOOK] c_stack_action called at {state.regs.rip}", flush=True)
    if state.history.jumpkind == 'Ijk_Call':
        print(f"[HOOK] Called from {state.history.jump_source}", flush=True)
    # Just return 0 to indicate success
    return claripy.BVV(0, state.arch.bits)


class InitLocaleInfoHook(angr.SimProcedure):
    def run(self):
        # ip_val = self.state.solver.eval(self.state.regs.ip)
        print(f"[HOOK] init_localeinfo ENTRY: {hex(self.state.addr)}", flush=True)

        # in hooks, the recent_bbl_addrs[0] is the current bb, same as state.addr
        # print(f"[HOOK] Callsite: {hex(self.state.history.recent_bbl_addrs[0])}", flush=True)

        try:
            # Use jump_source - address of the call instruction
            print(f"[HOOK] Callsite (jump_source): {hex(self.state.history.jump_source)}", flush=True)
        except Exception as e:
            # print(f"[InitLocaleInfoHook] {e}")
            pass

        try:
            # Or get caller address from call stack
            if len(self.state.callstack) > 1:
                print(f"[HOOK] Callsite (callstack): {hex(self.state.callstack.current_return_target)}", flush=True)
        except Exception as e:
            print(f"[InitLocaleInfoHook] {e}", flush=True)
        # No return value needed for void function

class CStackActionHook(angr.SimProcedure):
    def run(self):
        # ip_val = self.state.solver.eval(self.state.regs.ip)
        print(f"[HOOK] c_stack_action ENTRY: {hex(self.state.addr)}", flush=True)

        # print(f"[HOOK] Callsite: {hex(self.state.history.recent_bbl_addrs[0])}", flush=True)

        try:
            # Use jump_source - address of the call instruction
            print(f"[HOOK] Callsite (jump_source): {hex(self.state.history.jump_source)}", flush=True)
        except Exception as e:
            # print(f"[CStackActionHook] {e}")
            pass
            
        try:
            # Or get caller address from call stack
            if len(self.state.callstack) > 1:
                print(f"[HOOK] Callsite (callstack): {hex(self.state.callstack.current_return_target)}", flush=True)
        except Exception as e:
            print(f"[CStackActionHook] {e}", flush=True)

        return claripy.BVV(0, self.state.arch.bits)         # 0 x 64bits BVV
    
class Handler_DrainConnections_Hook(angr.SimProcedure):
    def run(self):
        # ip_val = self.state.solver.eval(self.state.regs.ip)
        print(f"[HOOK] Drain Connections ENTRY: {hex(self.state.addr)}", flush=True)

        try:
            # Use jump_source - address of the call instruction
            print(f"[HOOK] Callsite (jump_source): {hex(self.state.history.jump_source)}", flush=True)
        except Exception as e:
            # print(f"[CStackActionHook] {e}")
            pass
            
        try:
            # Or get caller address from call stack
            if len(self.state.callstack) > 1:
                print(f"[HOOK] Callsite (callstack): {hex(self.state.callstack.current_return_target)}", flush=True)
        except Exception as e:
            print(f"[Drain Connections Hook] {e}", flush=True)


# Function to hook that does nothing (skip hooked instruction)
def nothing(state):
    pass


def nothing_success(state):
    return 1



""" Concretization Functions """

def constrain_log_accept(state):
    """
    accept on 0.0.0.0:8080, ready: 0
    LEA instruction address: 0x402e0
    """

    # r9d is the lower 32 bits of r9
    ready_val = state.regs.r9[31:0]  # Get the lower 32 bits
    if ready_val.symbolic:
        state.add_constraints(ready_val == 0)

    # address string (0.0.0.0:8080)
    str_struct_addr = state.regs.r8

    """
    typedef struct {
        size_t      len;
        u_char     *data;
    } ngx_str_t;
    """

    str_len_addr = str_struct_addr
    str_len = state.memory.load(str_len_addr, 8)
    if str_len.symbolic:
        state.add_constraints(str_len == len("0.0.0.0:8080"))

    str_data_ptr_addr = str_struct_addr + 8
    str_data_ptr = state.memory.load(str_data_ptr_addr, 8)

    concrete_string = b"0.0.0.0:8080"

    if str_data_ptr.symbolic:
        # Choose a concrete address for our string - we'll use a high address unlikely 
        # to conflict with other allocations
        target_addr = 0x7fff00000000
        
        # Constrain the symbolic pointer to point to our chosen address
        state.add_constraints(str_data_ptr == target_addr)
        
        # Now write our concrete string to that location
        state.memory.store(target_addr, concrete_string)
        
        # Don't forget to set the length in the ngx_str_t structure
        state.memory.store(str_struct_addr, len(concrete_string), size=8)
    else:
        # If the pointer is concrete, we can directly constrain the memory it points to
        concrete_addr = state.solver.eval(str_data_ptr)

        # Constrain each byte of the string
        for i, byte in enumerate(concrete_string):
            byte_addr = concrete_addr + i
            byte_val = state. memory.load(byte_addr, 1)
            if byte_val.symbolic:
                state.add_constraints(byte_val == byte)

    # Return the modified state
    return state


""" angr Analysis"""

def handler_accept_call(state):
    pass

def handler_initconn_call(state):
    pass


print_msg_box(f"Creating angr project")
# Load the binary
proj = angr.Project(bin_path, load_options={'auto_load_libs': False})

print_msg_box(f"Hooking Procedures:")
if bin_name == 'grep':
    init_locale_symbol = proj.loader.find_symbol('init_localeinfo')
    init_locale_addr = init_locale_symbol.rebased_addr
    print(f"init_localeinfo address: {hex(init_locale_addr)}", flush=True)

    c_stack_symbol = proj.loader.find_symbol('c_stack_action')
    c_stack_addr = c_stack_symbol.rebased_addr
    print(f"c_stack_action address: {hex(c_stack_addr)}", flush=True)

    if init_locale_symbol is None or c_stack_symbol is None:
        print("WARNING: Could not find one or both symbols to hook!", flush=True)
    # Hook functions that cause state explosion, return immediately
    proj.hook_symbol('init_localeinfo', InitLocaleInfoHook())
    proj.hook_symbol('c_stack_action', CStackActionHook())

elif bin_name == 'nginx':
    gettimeofday_symbol = proj.loader.find_symbol('gettimeofday')
    gettimeofday_addr = gettimeofday_symbol.rebased_addr
    print(f"gettimeofday address: {hex(gettimeofday_addr)}", flush=True)

    clock_gettime_symbol = proj.loader.find_symbol('clock_gettime')
    clock_gettime_addr = clock_gettime_symbol.rebased_addr
    print(f"clock_gettime address: {hex(clock_gettime_addr)}", flush=True)

    ngx_time_update_symbol = proj.loader.find_symbol('ngx_time_update')
    ngx_time_update_addr = ngx_time_update_symbol.rebased_addr
    print(f"ngx_time_update address: {hex(ngx_time_update_addr)}", flush=True)

    ngx_log_error_core_symbol = proj.loader.find_symbol('ngx_log_error_core')
    ngx_log_error_core_addr = ngx_log_error_core_symbol.rebased_addr
    print(f"ngx_log_error_core address: {hex(ngx_log_error_core_addr)}", flush=True)

    # ngx_log_error_core

    accept_handler_calladdr = 0x4475eb         # basic block addr: 0x4475e8
    ngx_event_accept_symbol = proj.loader.find_symbol('ngx_event_accept')
    ngx_event_accept_addr = ngx_event_accept_symbol.rebased_addr
    @proj.hook(accept_handler_calladdr, length=4)
    def handler_accept_call(state):
        ret_addr = accept_handler_calladdr + 4

        return_addr_bv = claripy.BVV(ret_addr, 64)

        # First adjust stack pointer down
        state.regs.rsp -= 8
        # Then store return address at the new top of stack
        state.memory.store(state.regs.rsp, return_addr_bv)

        state.regs.ip = ngx_event_accept_addr


    """
        .text:000000000002A9BE loc_2A9BE:                              ; CODE XREF: ngx_get_connection+158↓j
        .text:000000000002A9BE                                         ; ngx_get_connection+175↓j
        .text:000000000002A9BE                 or      byte ptr [rbx+2Ah], 2
        .text:000000000002A9C2                                 mov     rax, [rbx-0A8h]
        .text:000000000002A9C9                 mov     rdi, rax
        .text:000000000002A9CC                 call    qword ptr [rax+10h]          ; ngx_http_request_handler() - maybe?
        .text:000000000002A9CF                 add     r12, 1
        .text:000000000002A9D3                 cmp     r12, r15
        .text:000000000002A9D6                 jz      short loc_2AA18
    """
    proj.hook(0x42A9C2, nothing, length=13)     # Covers from mov rax through call          TODO: don't skip... call correct handler

    # proj.hook_symbol('ngx_os_init', nothing)
    ngx_os_init_symbol = proj.loader.find_symbol('ngx_os_init')
    ngx_os_init_addr = ngx_os_init_symbol.rebased_addr
    proj.hook_symbol('ngx_os_init', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    print(f"ngx_os_init_addr address: {hex(ngx_os_init_addr)}", flush=True)

    init_connection_handler_calladdr = 0x43ca2d
    ngx_http_init_connection_symbol = proj.loader.find_symbol('ngx_http_init_connection')
    ngx_http_init_connection_addr = ngx_http_init_connection_symbol.rebased_addr
    @proj.hook(init_connection_handler_calladdr, length=3)
    def handler_initconn_call(state):
        ret_addr = init_connection_handler_calladdr + 3

        return_addr_bv = claripy.BVV(ret_addr, 64)

        # Function will push 6 registers (6 * 8 = 48 bytes) and allocate 0x18 bytes
        # So our return address needs to be placed considering this stack frame
        total_stack_size = 48 + 0x18

        # adjust stack pointer to account for the return address
        state.regs.rsp -= 8
        # Then store return address at the new top of stack
        state.memory.store(state.regs.rsp + total_stack_size, return_addr_bv)

        state.regs.ip = ngx_http_init_connection_addr


    proj.hook_symbol('gettimeofday', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook_symbol('clock_gettime', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook_symbol('ngx_time_update', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook_symbol('ngx_log_error_core', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())

    if gettimeofday_symbol is None or clock_gettime_symbol is None or ngx_time_update_symbol is None or ngx_log_error_core_symbol is None:
        print("WARNING: Could not find one or both symbols to hook!", flush=True)


    ngx_event_flags_symbol = proj.loader.find_symbol('ngx_event_flags')
    if ngx_event_flags_symbol:
        ngx_event_flags_addr = ngx_event_flags_symbol.rebased_addr
    else:
        ngx_event_flags_addr = 'Missing'

    print(f"ngx_event_flags_addr: {hex(ngx_event_flags_addr)}", flush=True)             # 0x4d4bf0

    @proj.hook(0x43bc28)
    def debug_flags_hook(state):
        ngx_event_flags_addr2 = state.solver.eval(state.regs.rdx)  # Get the address loaded by the mov instruction
        print(f"ngx_event_flags_addr solver: {hex(ngx_event_flags_addr2)}", flush=True)

        ngx_event_flags_addr = 0x4d4bf0
        state.mem[ngx_event_flags_addr].uint64_t = 0x4


    epoll_add_event_handler_calladdr = 0x43bc49
    ngx_epoll_add_event_symbol = proj.loader.find_symbol('ngx_epoll_add_event')
    ngx_epoll_add_event_addr = ngx_epoll_add_event_symbol.rebased_addr
    @proj.hook(epoll_add_event_handler_calladdr, length=6)
    def handler_addevent_call(state):
        ret_addr = epoll_add_event_handler_calladdr + 6
        return_addr_bv = claripy.BVV(ret_addr, 64)

         # First, let's understand our stack frame components
        register_save_size = 3 * 8     # 24 bytes for saved registers
        local_vars_size = 0x20         # 32 bytes for local variables

        # Now, let's calculate the alignment adjustment needed
        # The stack pointer must be 16-byte aligned AFTER we push our return address
        # This means before our push, it should be at (16-byte aligned - 8)

        # Get current concrete RSP value for calculation
        current_rsp = state.solver.eval(state.regs.rsp)

        # Calculate how far we are from desired alignment
        # We want (rsp - 8) to be 16-byte aligned
        desired_rsp = ((current_rsp - 8) & ~0xF) + 0x10  # Round down to 16 and add 16
        alignment_adjustment = current_rsp - desired_rsp
        print(f"alignment_adjustment: {alignment_adjustment}", flush=True)

        # Apply the alignment adjustment
        if alignment_adjustment != 0:
            state.regs.rsp -= alignment_adjustment

        # Now adjust stack for return address
        state.regs.rsp -= 8

        # Calculate total stack frame size including our alignment
        total_stack_size = register_save_size + local_vars_size

        # Store return address at the correct location
        target_addr = state.regs.rsp + claripy.BVV(total_stack_size, 64)
        state.memory.store(target_addr, return_addr_bv)

        # Add debug prints to verify our alignment
        concrete_rsp = state.solver.eval(state.regs.rsp)
        # print(f"Adjusted RSP value: 0x{concrete_rsp:x}", flush=True)
        # print(f"RSP alignment check: {concrete_rsp & 0xF:x}", flush=True)  # Should be 8
        # print(f"Target address: 0x{state.solver.eval(target_addr):x}", flush=True)
        # print(f"Target alignment check: {state.solver.eval(target_addr) & 0xF:x}", flush=True)

        # Set instruction pointer to function start
        state.regs.ip = ngx_epoll_add_event_addr


    # ngx_epoll_process_events
    epoll_process_events_handler_calladdr = 0x43bb43
    ngx_epoll_process_events_symbol = proj.loader.find_symbol('ngx_epoll_process_events')
    ngx_epoll_process_events_addr = ngx_epoll_process_events_symbol.rebased_addr
    @proj.hook(epoll_process_events_handler_calladdr, length=6)
    def handler_process_event_call(state):
        ret_addr = epoll_process_events_handler_calladdr + 6
        return_addr_bv = claripy.BVV(ret_addr, 64)

         # First, let's understand our stack frame components
        register_save_size = 6 * 8     # 48 bytes for saved registers
        local_vars_size = 0x18         # 24 bytes for local variables

        # Now, let's calculate the alignment adjustment needed
        # The stack pointer must be 16-byte aligned AFTER we push our return address
        # This means before our push, it should be at (16-byte aligned - 8)

        # Get current concrete RSP value for calculation
        current_rsp = state.solver.eval(state.regs.rsp)

        # Calculate how far we are from desired alignment
        # We want (rsp - 8) to be 16-byte aligned
        desired_rsp = ((current_rsp - 8) & ~0xF) + 0x10  # Round down to 16 and add 16
        alignment_adjustment = current_rsp - desired_rsp
        print(f"alignment_adjustment: {alignment_adjustment}", flush=True)

        # Apply the alignment adjustment
        if alignment_adjustment != 0:
            state.regs.rsp -= alignment_adjustment

        # Now adjust stack for return address
        state.regs.rsp -= 8

        # Calculate total stack frame size including our alignment
        total_stack_size = register_save_size + local_vars_size

        # Store return address at the correct location
        target_addr = state.regs.rsp + claripy.BVV(total_stack_size, 64)
        state.memory.store(target_addr, return_addr_bv)

        # Add debug prints to verify our alignment
        concrete_rsp = state.solver.eval(state.regs.rsp)
        # print(f"Adjusted RSP value: 0x{concrete_rsp:x}", flush=True)
        # print(f"RSP alignment check: {concrete_rsp & 0xF:x}", flush=True)  # Should be 8
        # print(f"Target address: 0x{state.solver.eval(target_addr):x}", flush=True)
        # print(f"Target alignment check: {state.solver.eval(target_addr) & 0xF:x}", flush=True)

        # Set instruction pointer to function start
        state.regs.ip = ngx_epoll_process_events_addr

    @proj.hook(0x42ae53, length=3)
    def branch_hook(state):
        state.regs.ip = 0x42af20


    # 0x45652f -> hook to ngx_unix_recv
    ngx_unix_recv_handler_calladdr = 0x45652f
    ngx_unix_recv_symbol = proj.loader.find_symbol('ngx_unix_recv')
    ngx_unix_recv_addr = ngx_unix_recv_symbol.rebased_addr
    @proj.hook(ngx_unix_recv_handler_calladdr, length=6)
    def handler_unix_recv_call(state):
        ret_addr = ngx_unix_recv_handler_calladdr + 6
        return_addr_bv = claripy.BVV(ret_addr, 64)

         # First, let's understand our stack frame components
        register_save_size = 6 * 8     # 48 bytes for saved registers
        local_vars_size = 8         # 8 bytes for local variables

        # Now, let's calculate the alignment adjustment needed
        # The stack pointer must be 16-byte aligned AFTER we push our return address
        # This means before our push, it should be at (16-byte aligned - 8)

        # Get current concrete RSP value for calculation
        current_rsp = state.solver.eval(state.regs.rsp)

        # Calculate how far we are from desired alignment
        # We want (rsp - 8) to be 16-byte aligned
        desired_rsp = ((current_rsp - 8) & ~0xF) + 0x10  # Round down to 16 and add 16
        alignment_adjustment = current_rsp - desired_rsp
        print(f"alignment_adjustment: {alignment_adjustment}", flush=True)

        # Apply the alignment adjustment
        if alignment_adjustment != 0:
            state.regs.rsp -= alignment_adjustment

        # Now adjust stack for return address
        state.regs.rsp -= 8

        # Calculate total stack frame size including our alignment
        total_stack_size = register_save_size + local_vars_size

        # Store return address at the correct location
        target_addr = state.regs.rsp + claripy.BVV(total_stack_size, 64)
        state.memory.store(target_addr, return_addr_bv)

        # Add debug prints to verify our alignment
        concrete_rsp = state.solver.eval(state.regs.rsp)
        # print(f"Adjusted RSP value: 0x{concrete_rsp:x}", flush=True)
        # print(f"RSP alignment check: {concrete_rsp & 0xF:x}", flush=True)  # Should be 8
        # print(f"Target address: 0x{state.solver.eval(target_addr):x}", flush=True)
        # print(f"Target alignment check: {state.solver.eval(target_addr) & 0xF:x}", flush=True)

        # Set instruction pointer to function start
        state.regs.ip = ngx_unix_recv_addr






    # print(f"[setup_concrete_config]", flush=True)
    # ngx_conf_parse_addr = proj.loader.find_symbol('ngx_conf_parse').rebased_addr
    # # Hook ngx_conf_parse to ensure it sees our concrete filename
    # @proj.hook(ngx_conf_parse_addr, length=0)
    # def concrete_conf_parse_hook(state):
    #     # Define the concrete nginx.conf path
    #     config_path = b"/usr/local/nginx/conf/nginx.conf\0"
    #     filename_len = len(config_path) - 1                          # exclude null terminator

    #     # Create ngx_str_t structure for filename
    #     filename_str = state.heap.allocate(16)                       # sizeof(ngx_str_t) is typically 16 bytes
    #     state.memory.store(filename_str, claripy.BVV(filename_len, 64))  # len field

    #     path_addr = state.heap.allocate(len(config_path))
    #     state.memory.store(path_addr, claripy.BVV(config_path, len(config_path) * 8))
    #     state.memory.store(filename_str + 8, claripy.BVV(path_addr, 64))  # data field

    #     # Add explicit constraints for each byte of the path
    #     for i in range(len(config_path)):
    #         byte = state.memory.load(path_addr + i, 1)
    #         state.add_constraints(byte == claripy.BVV(config_path[i], 8))

    #     # Create concrete content for nginx.conf
    #     config_content = b"""# /usr/local/nginx/conf/nginx.conf
    # worker_processes 1;        # Force single process
    # daemon off;                # Run in foreground
    # master_process off;        # Disable master process

    # # Main context logging - applies to startup/shutdown and global events. Main error_log captures everything
    # error_log /usr/local/nginx/logs/error.log debug_core debug_alloc debug_mutex debug_event debug_http 
    #     debug_mail debug_stream;
    # # For our execution reconstruction purpose, having a single comprehensive error log and a detailed access log is cleaner and sufficient.

    # events {
    #     worker_connections 16; # Minimize connections
    #     multi_accept off;      # Disable multiple accepts
    # }

    # http {
    #     # Basic MIME type mappings needed for serving files
    #     include       mime.types;
    #     default_type  application/octet-stream;

    #     # Define detailed log format
    #     log_format detailed '$remote_addr - $remote_user [$time_local] '
    #                         '"$request" $status $body_bytes_sent '
    #                         '"$http_referer" "$http_user_agent" '
    #                         '$request_time $upstream_response_time '
    #                         '$pipe $connection $connection_requests '
    #                         '$request_id '                    # Unique request identifier
    #                         '$request_length '                # Request length including headers
    #                         '$request_completion '            # Whether request completed normally
    #                         '$server_protocol '               # HTTP protocol version
    #                         '$request_filename '              # File path for the request
    #                         '$document_root '                 # Root directory
    #                         '$hostname'                      # Server hostname
    #                         'tcp_info=$tcpinfo_rtt,$tcpinfo_rttvar,$tcpinfo_snd_cwnd,$tcpinfo_rcv_space '
    #                         'connection=$connection '
    #                         'connection_time=$connection_time '
    #                         'pid=$pid '
    #                         'msec=$msec '
    #                         'request_time=$request_time '
    #                         'upstream_connect_time=$upstream_connect_time '
    #                         'upstream_header_time=$upstream_header_time '
    #                         'upstream_response_time=$upstream_response_time '
    #                         'upstream_response_length=$upstream_response_length '
    #                         'upstream_cache_status=$upstream_cache_status '
    #                         'upstream_status=$upstream_status '
    #                         'scheme=$scheme '
    #                         'request_method=$request_method '
    #                         'server_port=$server_port '
    #                         'server_addr=$server_addr '
    #                         'body_bytes_sent=$body_bytes_sent '
    #                         'request_body=$request_body '
    #                         'request_body_file=$request_body_file '
    #                         'connection_requests=$connection_requests '
    #                         'realpath_root=$realpath_root '
    #                         'nginx_version=$nginx_version '
    #                         'server_name=$server_name '
    #                         'request_completion=$request_completion '
    #                         'pipe=$pipe '
    #                         'sent_http_content_length=$sent_http_content_length '
    #                         'sent_http_content_type=$sent_http_content_type '
    #                         'sent_http_last_modified=$sent_http_last_modified '
    #                         'sent_http_connection=$sent_http_connection '
    #                         'sent_http_keep_alive=$sent_http_keep_alive '
    #                         'sent_http_transfer_encoding=$sent_http_transfer_encoding '
    #                         'sent_http_cache_control=$sent_http_cache_control '
    #                         'sent_http_location=$sent_http_location '
    #                         'http_host=$http_host '
    #                         'http_x_forwarded_for=$http_x_forwarded_for '
    #                         'http_x_real_ip=$http_x_real_ip';

    #     # Enhanced access logging with minimal buffering for real-time logging
    #     access_log /usr/local/nginx/logs/access.log detailed buffer=4k flush=1s;

    #     # More aggressive file operation logging
    #     open_log_file_cache max=1000 inactive=10s valid=30s min_uses=1;

    #     server {
    #         listen 8080;
    #         server_name localhost;

    #         # Enable detailed error logging at server level
    #         # error_log /usr/local/nginx/logs/server-error.log debug;

    #         location / {
    #             root /usr/local/nginx/html;
    #             index index.html;

    #             # Add location-specific error log for even more granular debugging
    #             # error_log /usr/local/nginx/logs/location-error.log debug;

    #             # Log request body
    #             client_body_in_file_only on;
    #             client_body_buffer_size 16k;

    #             # Log all file operations
    #             log_not_found on;         # Log 404 errors
    #             log_subrequest on;        # Log subrequests

    #             # Log response headers
    #             add_header X-Debug-Request-ID $request_id always;
    #             add_header X-Debug-Connection $connection always;
    #             add_header X-Debug-Connection-Requests $connection_requests always;
    #         }
    #     }
    # }\0"""

    #     # Simulate the file system for this file
    #     # We'll create a SimFile with our concrete content
    #     simfile = angr.SimFile('nginx.conf', content=config_content)
    #     state.fs.insert('/usr/local/nginx/conf/nginx.conf', simfile)

    #     filename_ptr = state.regs.rsi  # Assuming x86_64 calling convention where second arg is in rsi
    #     if filename_ptr is not None:
    #         # Store the concrete path at the filename pointer
    #         state.memory.store(filename_ptr, claripy.BVV(filename_str, 64), endness=proj.arch.memory_endness)













# Verify hooks are installed
print_msg_box("Verifying hooks...")
for addr, hook in proj._sim_procedures.items():
    print(f"Hook at {hex(addr)}: {hook}", flush=True)

if RESTORE:
    print_msg_box(f"Restoring SimStates")
    SIMGR, iter = load_angr_simgr('nginx_simgr_0_HOOK')
    # binname, restored_states = load_angr_project('nginx_analysis')
    # print(f"bin name: {binname}", flush=True)
    # print(f"states: {restored_states}\n", flush=True)
    print(f"restored_SIMGR: {SIMGR}", flush=True)
    print(f"restored_iter: {iter}\n", flush=True)
else:
    # Set up the initial state
    initial_state = None
    iter = 0
    if bin_name == 'grep':
        initial_state = setup_grep_symex_state(proj)
    elif bin_name == 'nginx':
        initial_state = setup_nginx_symex_state(proj)

# Find the address of 'main'
main_symbol = proj.loader.find_symbol('main')
main_addr = main_symbol.rebased_addr

# Generate CFG
start = time.time()
cfg = proj.analyses.CFGFast(show_progressbar=True)
end = time.time()
print(f"CFGFast: {cfg.graph}, {round(end - start, 2)}s", flush=True)
# grep: CFGFast: DiGraph with 131172 nodes and 361298 edges, 275.39s



# dynamic CFG (symbolic)
"""start = time.time()
cfg = proj.analyses.CFGEmulated(
    starts=[main_addr],  # Start from main
    context_sensitivity_level=2,  # Increase context sensitivity
    keep_state=True,  # Keep the state to resolve indirect jumps
    call_depth=20,
    normalize=True,
    enable_function_hints=True  # Disable hints to force analysis
)
end = time.time()
print(f"CFGEmulated: {cfg.graph}, {round(end - start, 2)}", flush=True)"""

if RESTORE:
    if hasattr(SIMGR, "active") and len(SIMGR.active) > 0:
        prev_addr = SIMGR.active[0].addr
    elif iter > 0:
        prev_addr = nginx_logs[iter]['lea_addr']
    else:
        prev_addr = proj.entry

    if iter > 0:
        prev_call = nginx_logs[iter-1]['function']
    else:
        prev_call = "start"
else:
    if bin_name == 'grep':
        prev_addr = cfg.kb.functions.function(name='main').addr
        prev_call = "main"
    elif bin_name == 'nginx':
        # prev_addr = cfg.kb.functions.function(name='ngx_epoll_process_events').addr
        # prev_call = "ngx_epoll_process_events"

        # prev_addr = cfg.kb.functions.function(name='ngx_single_process_cycle').addr
        # prev_call = "ngx_single_process_cycle"

        prev_addr = proj.entry
        prev_call = "start"

prev_addr_str = hex(prev_addr)
print_msg_box(f"prev_call: {prev_call}, {prev_addr_str}")

# # Check if the callsites exist in the CFG
# for entry in gdb_logs[1:]:
#     addr = int(entry['Addr'], 16)
#     addr_str = hex(addr)
#     func_name = entry['Func']
#     node = cfg.model.get_any_node(addr, anyaddr=True)
#     if node:
#         print(f"Callsite {addr_str} exists in CFG.", flush=True)
#     else:
#         print(f"Callsite {addr_str} not found in CFG.", flush=True)

# ipdb.set_trace()


# Check if the LEA addrs (callsites) exist in the CFG
count = 0
for entry in nginx_logs:
    addrs = entry['lea_addr']
    for idx, addr_str in enumerate(addrs):
        addr = int(addr_str, 16)
        node = cfg.model.get_any_node(addr, anyaddr=True)
        if node:
            print(f"Log site {addr_str} exists in CFG.", flush=True)
            count += 1
        else:
            print(f"Log site {addr_str} not found in CFG.", flush=True)
    print(f"--------------------------------------------")

print_msg_box(f"{count} log sites exist")


def compare_simgrs(simgr1, simgr2):
    # First check if they're the exact same object
    if simgr1 is simgr2:
        print("Same object identity", flush=True)
        return True
        
    # Compare basic attributes
    print("\nComparing attributes:", flush=True)
    for attr in ['active', 'deadended', 'found', 'avoided', 'errored']:
        if hasattr(simgr1, attr) and hasattr(simgr2, attr):
            states1 = getattr(simgr1, attr)
            states2 = getattr(simgr2, attr)
            print(f"{attr}:", flush=True)
            print(f"  simgr1: {states1}", flush=True)
            print(f"  simgr2: {states2}", flush=True)
            print(f"  Length match: {len(states1) == len(states2)}", flush=True)
            
    # Compare state attributes if there are active states
    if simgr1.active and simgr2.active:
        print("\nComparing first active state:", flush=True)
        state1 = simgr1.active[0]
        state2 = simgr2.active[0]
        print(f"IP: {state1.ip} vs {state2.ip}", flush=True)
        print(f"Regs: {state1.regs} vs {state2.regs}", flush=True)
        
    return False  # Return False by default since deep equality is complex


# def timeout(seconds):
#     def decorator(func):
#         def wrapper(*args, **kwargs):
#             result = None
#             queue = kwargs.pop("queue", None)
#             while not result:
#                 p = Process(target=func, args=args, kwargs={**kwargs, "queue": queue})
#                 p.start()

#                 start_time = time.time()
#                 result = None

#                 # # Poll the queue for a result within the timeout
#                 # while time.time() - start_time < seconds:
#                 #     if queue and not queue.empty():
#                 #         result = queue.get()  # Get simgr from queue if available
#                 #         print(f"Result found in queue: {result}", flush=True)
#                 #         # p.terminate()  # Kill process immediately after getting result
#                 #         break
#                 #     time.sleep(0.5)  # Small sleep to avoid busy waiting

#                 try:
#                     result = queue.get(timeout=seconds)
#                     print(f"Result found in queue: {result}", flush=True)
#                 except Exception as e:
#                     print(f"Queue get timeout? : {e}", flush=True)
#                 finally:
#                     if p.is_alive():
#                         print("Terminating process", flush=True)
#                         p.terminate()
#                         p.join()  # Ensure cleanup

#                 print(f"--> Intermediate Result: {result}", flush=True)
#             print(f"--> Final Result: {result}", flush=True)
#             return result   # Return simgr if available, otherwise None
#         return wrapper
#     return decorator

explore_starttime = 0

# @timeout(300)
def angr_explore(simgr, prev_addr, target_addr, avoid_addrs):
    """
    Passing simgr to subprocess does not yield same results, instead pass simstates.
    """
    print(f"[angr_explore] simgr arg: {simgr}", flush=True)

    if simgr and hasattr(simgr, 'found') and len(simgr.found) > 0:
        simgr.stash(from_stash='found', to_stash='active')
    if not simgr or not hasattr(simgr, 'active') or len(simgr.active) < 1:
        simstates = proj.factory.blank_state(addr=get_single_addr(prev_addr))
        simgr = proj.factory.simgr(simstates)
    
    print(f"[angr_explore] running simgr: {simgr}", flush=True)
    explore_count = 0
    found_count = 0
    global explore_starttime
    global FOUND_LIMIT
    while hasattr(simgr, "active") and simgr.active and found_count < FOUND_LIMIT:           # XXX: limit exploration to N found paths
        try:
            print(f"simgr explore_count [{explore_count}]", flush=True)
            explore_starttime = time.time()
            simgr.explore(find=target_addr, avoid=avoid_addrs, step_func=step_function)

            # steps = 0
            # while not simgr.found:
            #     simgr.step()
            #     steps += 1
            #     if steps % 10 == 0:         # update queue every 10 steps
            #         if not queue.empty():
            #             queue.get()         # remove old state
            #         queue.put(simgr)        # latest state
        except TimeoutError:
            print("\t--> Function took too long to execute", flush=True)
        finally:
            print(f"simgr: {simgr}", flush=True)
            # print(f"found: " + (f"{len(simgr.found)}" if (simgr and hasattr(simgr, 'found') and len(simgr.found) > 0) else "No found path"), flush=True)
            # print(f"active: " + (f"{len(simgr.active)}" if (simgr and hasattr(simgr, 'active')) else "No active path"), flush=True)
            if simgr and hasattr(simgr, 'found') and simgr.found:
                found_count = len(simgr.found)

            # if not queue.empty():
            #     queue.get()         # remove old state
            # q_size1 = queue.qsize()
            # queue.put(simgr)        # latest state
            # q_size2 = queue.qsize()
            with open(outfile, "a") as f:
                if (explore_count == 0):
                    f.write(f"=============== Explore {ITER} ===============\n")
                f.write(f"--> explore count [{explore_count}]\n")
                if hasattr(simgr, "found"):
                    for idx, found_path in enumerate(simgr.found):
                        # Extract the list of basic block addresses traversed
                        trace = found_path.history.bbl_addrs.hardcopy
                        trace = [hex(i) for i in trace]
                        f.write(f"\t--> simgr trace {idx}: {trace}\n")
                    if len(simgr.found) > 1:
                        f.write(f"WARNING: simgr multiple found\n")

                    # execution_path.extend(trace)                    # TODO: fork when multiple paths found
                else:
                    f.write(f"[simgr has no attribute <found>]\n")
                f.write(f"\n\n")
            # print(f"q_size before: {q_size1}, after: {q_size2}", flush=True)
            print(f"Finished explore_count [{explore_count}], continuing...", flush=True)
            explore_count += 1
    # qsize = queue.qsize()
    # print(f"=== final q_size: {qsize} ===", flush=True)
    print(f"=== final simgr: {simgr} ===", flush=True)
    print("finished angr_explore() and exiting...", flush=True)

    return simgr


# Add custom step callback to log state information
def log_state_info(simgr):
    logger = logging.getLogger('angr.sim_manager')
    # Log active states
    if hasattr(simgr, "active"):
        logger.debug(f"======= Active States [{len(simgr.active)}] =======")
        # fh = logging.FileHandler('simgr_DEBUG.log', mode='a')
        # logger.addHandler(fh)
        logger.debug(f"simgr: {simgr}")
        for i, state in enumerate(simgr.active):
            # Get containing function from project
            func = None
            curr_instr = "Unknown"
            prev_instr = "Unknown"
            prev_ip = 0x0

            # Convert bitvectors to integers before formatting
            ip_val = state.solver.eval(state.regs.ip)

            try:
                node = cfg.model.get_any_node(ip_val, anyaddr=True)
                curr_instr = state.block().capstone.insns[0].insn_name() + " " + state.block().capstone.insns[0].op_str if state.block() else "Unknown"
                prev_ip = state.history.recent_bbl_addrs[0]
                prev_block = proj.factory.block(prev_ip)
                prev_instr = prev_block.capstone.insns[0].insn_name() + " " + prev_block.capstone.insns[0].op_str if state.block() else "Unknown"

                # TODO move to separate step function
                if bin_name == "nginx":
                    # TODO: debug why register was overconstrained
                    if ip_val == 0x447474:
                        logger.debug(f"\nWARNING: 0x447474")
                        logger.debug(f"Splitting into: {[hex(n.addr) for n in node.successors]}")

                        # Instead of using a flag, force direct jumps to successor blocks
                        state_copy1 = state.copy()
                        state_copy2 = state.copy()

                        # Force jump to 0x447485
                        state_copy1.regs.ip = claripy.BVV(0x447485, state_copy1.arch.bits)

                        # Force jump to 0x447559
                        state_copy2.regs.ip = claripy.BVV(0x447559, state_copy2.arch.bits)

                        # Remove current state and add our new states
                        simgr.active.remove(state)
                        simgr.active.append(state_copy1)
                        simgr.active.append(state_copy2)
                    elif ip_val == 0x42A9BE:
                        logger.debug(f"\nWARNING 0x42A9BE")
                    elif ip_val == 0x42A9CF:
                        logger.debug(f"\nWARNING 0x42A9CF")
                    elif ip_val == 0x43c7f0:
                        logger.debug(f"\nNow @ 0x43c7f0")
                        logger.debug(f"Splitting into: {[hex(n.addr) for n in node.successors]}")

                        state_copy1 = state.copy()
                        state_copy2 = state.copy()

                        state_copy1.regs.ip = claripy.BVV(0x43caec, state_copy1.arch.bits)
                        state_copy2.regs.ip = claripy.BVV(0x43c7fc, state_copy2.arch.bits)

                        simgr.active.remove(state)
                        simgr.active.append(state_copy1)
                        simgr.active.append(state_copy2)
                    elif ip_val == 0x42ae3f:                    # not exploring one branch
                        logger.debug(f"\nWARNING 0x42ae3f")
                        # state.memory.store(state.regs.rsi, claripy.BVV(0x10, 8))
                    elif ip_val == 0x43c5d5:
                        constrain_log_accept(state)
                    elif ip_val == 0x43bb1a:
                        state.regs.ip = claripy.BVV(0x43bb33, state.arch.bits)
                    elif ip_val == 0x42e296:
                        rax_val = state.regs.rax
                        rcx_val = state.regs.rcx
                        rbx_val = state.regs.rbx
                        rdx_val = state.regs.rdx
                        rsi_val = state.regs.rsi

                        logger.debug(f"[DEBUG CRC LOOP] @ {hex(state.addr)}")
                        logger.debug(f"  rax (counter): {rax_val}")
                        logger.debug(f"  rcx (limit): {rcx_val}")
                        logger.debug(f"  rbx (crc): {rbx_val}")
                        logger.debug(f"  rdx: {rdx_val}")
                        logger.debug(f"  rsi (table): {rsi_val}")
                        logger.debug(f"  Is rax symbolic: {rax_val.symbolic}")
                        logger.debug(f"  Is rcx symbolic: {rcx_val.symbolic}")
                        logger.debug("------------------------")
                    elif ip_val == 0x42E176:
                        logger.debug(f"[DEBUG conf_parse] @ {hex(state.addr)}")
                        # Get the filename pointer (rsi register)
                        filename_ptr = state.regs.rsi
                        logger.debug(f"[Debug] filename_ptr (rsi): {filename_ptr}")

                        if not filename_ptr.concrete:
                            logger.debug(f"[Warning] filename_ptr is symbolic: {filename_ptr}")

                        # Read the ngx_str_t structure
                        try:
                            # Read the length field (first 8 bytes)
                            length = state.memory.load(filename_ptr, 8, endness=state.arch.memory_endness)
                            logger.debug(f"[Debug] str.len: {length}")
                            
                            # Read the data pointer (next 8 bytes)
                            data_ptr = state.memory.load(filename_ptr + 8, 8, endness=state.arch.memory_endness)
                            logger.debug(f"[Debug] str.data pointer: {data_ptr}")

                            if data_ptr.concrete:
                                # Try to read the actual string content
                                concrete_addr = state.solver.eval(data_ptr)
                                # Read up to 100 bytes or until null terminator
                                content = []
                                for i in range(100):  # Safety limit
                                    byte = state.memory.load(concrete_addr + i, 1)
                                    if byte.concrete:
                                        byte_val = state.solver.eval(byte)
                                        if byte_val == 0:  # Null terminator
                                            break
                                        content.append(byte_val)
                                    else:
                                        logger.debug(f"[Warning] Found symbolic byte at offset {i}")
                                        break
                                
                                if content:
                                    try:
                                        string_content = bytes(content).decode('utf-8')
                                        logger.debug(f"[Debug] String content: {string_content}")
                                    except UnicodeDecodeError:
                                        logger.debug(f"[Debug] Raw content (hex): {bytes(content).hex()}")
                            else:
                                logger.debug("[Warning] data_ptr is symbolic")

                            logger.debug("[*] Raw memory dump:")
                            for i in range(-8, 24, 8):
                                val = state.memory.load(filename_ptr + i, 8, endness=state.arch.memory_endness)
                                if val.concrete:
                                    logger.debug(f"[*] Offset {i:2d}: {val} (concrete: {hex(state.solver.eval(val))})")
                                else:
                                    logger.debug(f"[*] Offset {i:2d}: {val} (symbolic)")

                        except Exception as e:
                            logger.debug(f"[Error] Failed to read memory: {str(e)}")
                    elif ip_val == 0x42C185:        # conf_parse_ret_addr = 0x42C185
                        reg_a = state.solver.eval(state.regs.rax)
                        logger.debug(f"[conf parse return] @ 0x42C185, rax = {hex(reg_a)}")
                        if reg_a == 0xFFFFFFFFFFFFFFFF:
                            logger.debug(f"     [conf parse return] @ 0x42C185, PRUNING")
                            simgr.active.remove(state)
                            simgr.pruned.append(state)
                        hist = state.history.bbl_addrs.hardcopy[::-1] if len(state.history.bbl_addrs) > 1 else None
                        logger.debug(f"     History: {[hex(h) for h in hist]}")
                    elif ip_val == 0x4196C2:        # init_cycle ret addr = 0x4196C2
                        reg_a = state.solver.eval(state.regs.rax)
                        logger.debug(f"[init_cycle return] @ 0x4196C2, rax = {reg_a}")
                        if reg_a == 0:
                            logger.debug(f"     [init_cycle return] @ 0x4196C2, PRUNING")
                            simgr.active.remove(state)
                            simgr.pruned.append(state)
                        hist = state.history.bbl_addrs.hardcopy[::-1] if len(state.history.bbl_addrs) > 1 else None
                        logger.debug(f"     History: {[hex(h) for h in hist]}")
                    elif ip_val == 0x42E5A9:
                        logger.debug(f"[configuration parsing !] @ 0x42E5A9")
                        rsp = state.regs.rsp
                        r12 = state.regs.r12  # cf_0 pointer
                        rbx = state.regs.rbx  # buffer pointer
                        
                        try:
                            # Get conf_file
                            conf_file = state.memory.load(r12 + 0x28, 8, endness=state.arch.memory_endness)
                            if conf_file.concrete:
                                logger.debug(f"     [Good] conf_file concrete [{conf_file}]")
                                conf_file_addr = conf_file.concrete_value
                                
                                # Get all buffer fields
                                buf_pos = state.memory.load(rbx + 0x0, 8, endness=state.arch.memory_endness)      # pos
                                buf_last = state.memory.load(rbx + 0x8, 8, endness=state.arch.memory_endness)     # last
                                buf_file_pos = state.memory.load(rbx + 0x10, 8, endness=state.arch.memory_endness)   # file_pos
                                buf_file_last = state.memory.load(rbx + 0x18, 8, endness=state.arch.memory_endness)  # file_last
                                buf_start = state.memory.load(rbx + 0x20, 8, endness=state.arch.memory_endness)   # start
                                buf_end = state.memory.load(rbx + 0x28, 8, endness=state.arch.memory_endness)     # end
                                
                                logger.debug(f"     Buffer state:                   ")
                                if buf_pos.concrete and buf_last.concrete:
                                    logger.debug(f"     [Good] pos={buf_pos.concrete_value:x} last={buf_last.concrete_value:x}")
                                    
                                    content_len = buf_last.concrete_value - buf_pos.concrete_value
                                    if content_len > 0 and content_len < 1024:
                                        content = state.memory.load(buf_pos.concrete_value, content_len)
                                        if content.concrete:
                                            try:
                                                content_bytes = bytes(content.concrete_value)
                                                logger.debug(f"     [Good] Buffer content: {content_bytes.decode('utf-8', errors='ignore')}")
                                            except:
                                                logger.debug(f"     [Good] Buffer content (hex): {content.concrete_value:x}")
                                        else:
                                            logger.debug(f"     [Warning] Buffer content symbolic: {content}")
                                else:
                                    logger.debug(f"     [Warning] buf_pos OR buf_last symbolic: pos={buf_pos} last={buf_last}")
                                
                                logger.debug(f"     file_pos={buf_file_pos}")
                                logger.debug(f"     file_last={buf_file_last}")
                                logger.debug(f"     start={buf_start}")
                                logger.debug(f"     end={buf_end}")
                                
                                # Get line number
                                line_num = state.memory.load(conf_file_addr + 0xD8, 8, endness=state.arch.memory_endness)
                                if line_num.concrete:
                                    logger.debug(f"     Current line: {line_num.concrete_value}")
                            else:
                                logger.debug(f"     [Warning] conf_file NOT concrete: {conf_file}")
                            
                            # Get return code
                            rc = state.memory.load(rsp, 8, endness=state.arch.memory_endness)
                            if rc.concrete:
                                rc_val = rc.concrete_value
                                rc_name = {
                                    0xffffffffffffffff: "NGX_ERROR",
                                    0: "NGX_OK",
                                    1: "NGX_CONF_BLOCK_START",
                                    2: "NGX_CONF_BLOCK_DONE", 
                                    3: "NGX_CONF_FILE_DONE"
                                }.get(rc_val, "UNKNOWN")
                                logger.debug(f"     Return code: {rc_val} ({rc_name})")
                            else:
                                logger.debug(f"     [Warning] rc symbolic: {rc}")
                                
                        except Exception as e:
                            logger.debug(f"[Error] Failed to read state: {str(e)}")

                    elif ip_val == 0x42E51A:  # Before ngx_read_file
                        logger.debug(f"[Before ngx_read_file] @ 0x42E51A")
                        r12 = state.regs.r12  # cf_0
                        rbx = state.regs.rbx  # buffer pointer

                        try:
                            # Print buffer start, pos, last, end positions
                            buf_pos = state.memory.load(rbx + 0x0, 8, endness=state.arch.memory_endness)      # pos
                            buf_last = state.memory.load(rbx + 0x8, 8, endness=state.arch.memory_endness)     # last
                            buf_file_pos = state.memory.load(rbx + 0x10, 8, endness=state.arch.memory_endness)   # file_pos
                            buf_file_last = state.memory.load(rbx + 0x18, 8, endness=state.arch.memory_endness)  # file_last
                            buf_start = state.memory.load(rbx + 0x20, 8, endness=state.arch.memory_endness)   # start
                            buf_end = state.memory.load(rbx + 0x28, 8, endness=state.arch.memory_endness)     # end
                            
                            logger.debug(f"     Buffer pointers:")
                            logger.debug(f"     - pos: {buf_pos}")
                            logger.debug(f"     - last: {buf_last}")
                            logger.debug(f"     - file_pos: {buf_file_pos}")
                            logger.debug(f"     - file_last: {buf_file_last}")
                            logger.debug(f"     - start: {buf_start}")
                            logger.debug(f"     - end: {buf_end}")

                            # Print the arguments that will be passed to ngx_read_file
                            rdi = state.memory.load(r12 + 0x28, 8, endness=state.arch.memory_endness)  # file
                            rsi = state.regs.rsi  # buf
                            r14 = state.regs.r14  # will be size

                            sym_fn = r12
                            fn = state.solver.eval(sym_fn)
                            logger.debug(f"     [*] - concrete fn ptr: {hex(fn)}")
                            
                            # Read back the string to verify
                            content = []
                            for i in range(27):
                                try:
                                    byte = state.memory.load(fn + i, 1)
                                    if byte.concrete:
                                        content.append(state.solver.eval(byte))
                                except Exception:
                                    pass
                            if content:
                                logger.debug(f"     filename: {bytes(content).decode('utf-8')}")

                            logger.debug(f"     ngx_read_file args:")
                            logger.debug(f"     - file: {rdi}")
                            logger.debug(f"     - buf: {rsi}")
                            logger.debug(f"     - size (r14): {r14}")

                        except Exception as e:
                            logger.debug(f"[Error] Failed to read buffer state: {str(e)}")

                    elif ip_val == 0x42E54B:  # After ngx_read_file
                        logger.debug(f"[After ngx_read_file] @ 0x42E54B")
                        rbx = state.regs.rbx
                        rax = state.regs.rax  # return value from ngx_read_file

                        try:
                            # Print buffer positions after read
                            buf_pos = state.memory.load(rbx + 0x0, 8, endness=state.arch.memory_endness)      # pos
                            buf_last = state.memory.load(rbx + 0x8, 8, endness=state.arch.memory_endness)     # last
                            buf_file_pos = state.memory.load(rbx + 0x10, 8, endness=state.arch.memory_endness)   # file_pos
                            buf_file_last = state.memory.load(rbx + 0x18, 8, endness=state.arch.memory_endness)  # file_last
                            buf_start = state.memory.load(rbx + 0x20, 8, endness=state.arch.memory_endness)   # start
                            buf_end = state.memory.load(rbx + 0x28, 8, endness=state.arch.memory_endness)     # end
                            
                            logger.debug(f"     Buffer pointers:")
                            logger.debug(f"     - pos: {buf_pos}")
                            logger.debug(f"     - last: {buf_last}")
                            logger.debug(f"     - file_pos: {buf_file_pos}")
                            logger.debug(f"     - file_last: {buf_file_last}")
                            logger.debug(f"     - start: {buf_start}")
                            logger.debug(f"     - end: {buf_end}")

                            logger.debug(f"     Read result (rax): {state.solver.eval(rax)}")
                            logger.debug(f"     Bytes read matches size? {state.solver.eval(rax) == state.solver.eval(state.regs.r14)}")

                        except Exception as e:
                            logger.debug(f"[Error] Failed to read buffer state: {str(e)}")

                    elif ip_val == 0x42E287:   # After buf alloc before read
                        logger.debug(f"[BUF alloc finished] @ 0x42E287")
                        rsp = state.regs.rsp

                        try:
                            # print the actual allocated pointer
                            rax = state.regs.rax
                            logger.debug(f"     Allocation result (rax): {rax}")

                            # Calculate base of buf structure
                            buf_base = rsp + 0x1E8 - 0x178
                            
                            # Read the buffer structure fields
                            buf_pos = state.memory.load(buf_base + 0x0, 8, endness=state.arch.memory_endness)      # pos
                            buf_last = state.memory.load(buf_base + 0x8, 8, endness=state.arch.memory_endness)     # last
                            buf_file_pos = state.memory.load(buf_base + 0x10, 8, endness=state.arch.memory_endness)   # file_pos
                            buf_file_last = state.memory.load(buf_base + 0x18, 8, endness=state.arch.memory_endness)  # file_last
                            buf_start = state.memory.load(buf_base + 0x20, 8, endness=state.arch.memory_endness)   # start
                            buf_end = state.memory.load(buf_base + 0x28, 8, endness=state.arch.memory_endness)     # end
                            
                            logger.debug(f"     Buffer pointers:")
                            logger.debug(f"     - pos: {buf_pos}")
                            logger.debug(f"     - last: {buf_last}")
                            logger.debug(f"     - file_pos: {buf_file_pos}")
                            logger.debug(f"     - file_last: {buf_file_last}")
                            logger.debug(f"     - start: {buf_start}")
                            logger.debug(f"     - end: {buf_end}")

                        except Exception as e:
                            logger.debug(f"[Error] Failed to read buffer state: {str(e)}")
                        

                if node:
                    func = proj.kb.functions.function(node.function_address)
                # func = proj.kb.functions.get_by_addr(ip_val)
            except Exception as e:
                logger.debug(f"Exception [log_state_info] {e}")

            func_name = func.name if func else "Unknown"
            len_f = len(func_name)
            logger.debug(f"State {' ' if i < 10 else ''}{i} | {func_name}{' ' * (24 - len_f) if len_f < 24 else ''} | 0x{ip_val:x}, {curr_instr} | {hex(prev_ip)} - {prev_instr} | Constraints: {len(state.solver.constraints)}")
            
            # if ip_val == init_locale_addr:
            #     logger.debug(f"WARNING ^^^: Hit init_localeinfo() hook!")
            # elif ip_val == c_stack_addr:
            #     logger.debug(f"WARNING ^^^: Hit c_stack_action() hook!")

    # Log errored states
    if hasattr(simgr, "errored"):
        logger.debug(f"======= Errored States [{len(simgr.errored)}] =======")
        for i, errored_state in enumerate(simgr.errored):
            logger.debug(f"Errored State {i}:")
            logger.debug(f"    Error type: {type(errored_state.error)}")
            logger.debug(f"    Error message: {errored_state.error}")
            logger.debug(f"    Errored at addr: {hex(errored_state.state.addr)}")
            logger.debug(f"    Recent blocks: {[hex(x) for x in errored_state.state.history.recent_bbl_addrs]}")
            logger.debug(f"    Stack trace:\n{''.join(tb.format_tb(errored_state.traceback))}")

        # move errored, for later analysis if needed
        # simgr.drop(stash='errored')     # TODO: why not working?!?!
        simgr.stash(from_stash='errored', to_stash='old_err')

    # Log unconstrained states
    if hasattr(simgr, "unconstrained"):
        logger.debug(f"======= Unconstrained States [{len(simgr.unconstrained)}] =======")
        unique_ip_vals = set()
        cnt_dups = 0
        for i, state in enumerate(simgr.unconstrained):
            ip_val = state.solver.eval(state.regs.ip)
            if ip_val in unique_ip_vals:
                cnt_dups += 1
                break
            else:
                unique_ip_vals.add(ip_val)
            logger.debug(f"Unconstrained State {i}:")
            logger.debug(f"    IP: 0x{ip_val:x} (symbolic: {state.regs.ip.symbolic})")
            logger.debug(f"    Recent blocks: {[hex(x) for x in state.history.recent_bbl_addrs]}")
            # Log why it became unconstrained
            if hasattr(state, "unconstrained_reason"):
                logger.debug(f"    Reason: {state.unconstrained_reason}")
            # Log possible IP values
            if state.regs.ip.symbolic:
                possible_ips = state.solver.eval_upto(state.regs.ip, 10)
                logger.debug(f"    Possible IP values: {[hex(x) for x in possible_ips]}")
                
        logger.debug(f"    Duplicate Count: {cnt_dups}")
        # move unconstrained, for later analysis if needed
        simgr.stash(from_stash='unconstrained', to_stash='old_unc')

    # Log deadended states
    if hasattr(simgr, "deadended"):
        logger.debug(f"======= Deadended States [{len(simgr.deadended)}] =======")
        for i, errored_state in enumerate(simgr.deadended):
            logger.debug(f"Deadended State {i}:")
            logger.debug(f"    State: {errored_state}")

        # move errored, for later analysis if needed
        # simgr.drop(stash='errored')     # TODO: why not working?!?!
        simgr.stash(from_stash='deadended', to_stash='old_dead')
    

    return simgr

# Log when new paths are found
def log_path_found(simgr):
    if hasattr(simgr, "found"):
        logger = logging.getLogger('angr.sim_manager')
        logger.debug(f"======= Found States [{len(simgr.found)}] =======")
        for state in simgr.found:
            logger.info(f"Found path to target: {[hex(addr) for addr in state.history.bbl_addrs]}")


def is_address_in_whitelist(cfg, addr, whitelist, logger):
    """Check if an address belongs to a given function"""
    try:
        node = cfg.model.get_any_node(addr, anyaddr=True)
        if node:
            func = proj.kb.functions.function(node.function_address)
        else:
            func = None
        func_name = func.name if func else "Unknown"
        in_whitelist = func_name in whitelist
        if not in_whitelist:
            logger.debug(f"[is_address_in_whitelist] WARNING: func_name = {func_name}, NOT whitelisted ({in_whitelist})")
        return in_whitelist
    except Exception as e:
        logger.debug(f"[is_address_in_whitelist] {e}")
    return False


def prune_states(simgr):
    logger = logging.getLogger('angr.sim_manager')
    prune_count = {"depth":     0,
                   "memory":    0,
                   "loop":      0,
                   "symbolic":  0,}

    WHITELIST_FUNCTIONS = {
        'ngx_log_error_core',    # Logging function
        'ngx_palloc',            # Memory allocation
        'ngx_pnalloc',           # Memory allocation
        'ngx_alloc',             # Memory allocation
        'ngx_sprintf',           # String formatting
        'ngx_memcpy',            # Memory operations
        'ngx_strlen',            # String operations
        'ngx_cpystrn',           # String operations
        'ngx_palloc_block',
        'ngx_destroy_pool',
        'ngx_vslprintf',
        'main',
        'malloc',
        'ngx_sprintf_str',
        'ngx_preinit_modules',
        'memcpy',
        'memset',
    }

    logger.debug(f"======= Pruning States =======")
    
    for state in simgr.active:
        # 1. Prune based on execution depth
        # if state.history.depth > 1000:
        #     logger.debug(f"PRUNING - DEPTH: {state}")
        #     simgr.active.remove(state)
        #     # simgr.drop(stash='active', filter_func=lambda s: s is state)
        #     prune_count["depth"] += 1
        #     continue

        # # 2. Prune based on memory usage
        # # Check number of symbolic variables as a proxy for memory complexity
        # if len(state.solver.variables) > 1000:
        #     logger.debug(f"PRUNING - MEMORY: {state}")
        #     simgr.active.remove(state)
        #     # simgr.drop(stash='active', filter_func=lambda s: s is state)
        #     prune_count["memory"] += 1
        #     continue

        # 3. Prune paths that loop too many times
        bb_counter = {}
        threshold = 3
        for addr in state.history.bbl_addrs:
            bb_counter[addr] = bb_counter.get(addr, 0) + 1
            if bb_counter[addr] > threshold:  # Loop threshold
                # Check if this address belongs to any whitelisted function
                global cfg
                is_whitelisted = is_address_in_whitelist(cfg, addr, WHITELIST_FUNCTIONS, logger)

                if not is_whitelisted:
                    logger.debug(f"PRUNING - LOOP: {state} due to {threshold} * [{hex(addr)}]")
                    simgr.active.remove(state)
                    # simgr.drop(stash='active', filter_func=lambda s: s is state)
                    prune_count["loop"] += 1
                    break

        # # 4. Prune based on symbolic variable complexity
        # for var in state.solver.variables:
        #     if state.solver.symbolic(var):
        #         constraints = state.solver.constraints_by_variable(var)
        #         if len(constraints) > 50:  # Constraint complexity threshold
        #             logger.debug(f"PRUNING - SYMBOLIC")
        #             simgr.active.remove(state)
        #             # simgr.drop(stash='active', filter_func=lambda s: s is state)
        #             prune_count["symbolic"] += 1
        #             break

    logger.debug(f"      Pruned States [{prune_count}]=======")


# Log when paths are pruned
def log_path_pruned(simgr):
    if hasattr(simgr, 'pruned'):
        logger = logging.getLogger('angr.sim_manager')
        logger.debug(f"======= Pruned States [{len(simgr.pruned)}] =======")
        for state in simgr.pruned:
            prune_addr = state.solver.eval(state.regs.ip)
            logger.debug(f"Pruned path at 0x{prune_addr:x}")

def log_path_removed(simgr):
    if hasattr(simgr, 'active'):
        logger = logging.getLogger('angr.sim_manager')
        if len(simgr.active) > 10:
            # states_keep = random.sample(simgr.active, min(10, len(simgr.active)))
            states_keep = simgr.active[:10]
            states_remove = [s for s in simgr.active if s not in states_keep]

            # Move states to pruned stash
            if 'removed' not in simgr.stashes:
                simgr.stashes['removed'] = []
            simgr.stashes['removed'].extend(states_remove)

            # Update active states to only keep the sampled ones
            simgr.stashes['active'] = states_keep

            logger.debug(f"======= Removed States [{len(states_remove)}] =======")

            
def explore_timeout():
    logger = logging.getLogger('angr.sim_manager')
    global explore_starttime
    logger.debug(f"*** explore time: [ {round((time.time() - explore_starttime) / 60, 2)} mins ] ***")
    if (time.time() - explore_starttime) > EXPLORE_MAX_SECS:
        return True
    
    return False

def step_function(simgr):
    logger = logging.getLogger('angr.sim_manager')

    global step_count
    logger.debug(f"[ STEP COUNT ] - {step_count}")
    step_count += 1

    # Log all current states
    log_state_info(simgr)
    
    # Log if we found targets
    log_path_found(simgr)

    # pruning techniques to prevent state explosion
    # prune_states(simgr)

    # Log pruned paths
    log_path_pruned(simgr)

    # Remove Paths
    log_path_removed(simgr)


    if step_count % 500 == 0:
        logger.debug(f"----------- Step Count {step_count} : clearing stashes -----------")
        if hasattr(simgr, "unconstrained"):
            simgr.unconstrained.clear()
        if hasattr(simgr, "old_unc"):
            simgr.old_unc.clear()
        if hasattr(simgr, "errored"):
            simgr.errored.clear()
        if hasattr(simgr, "old_err"):
            simgr.old_err.clear()
        if hasattr(simgr, "avoid"):
            simgr.avoid.clear()
        if hasattr(simgr, "timeout"):
            simgr.timeout.clear()
        if hasattr(simgr, "unsat"):
            # XXX: some debug output
            simgr.unsat.clear()
        if hasattr(simgr, "deadended"):
            simgr.deadended.clear()
        if hasattr(simgr, "old_dead"):
            simgr.old_dead.clear()
        if hasattr(simgr, "pruned"):
            simgr.pruned.clear()
        if hasattr(simgr, "removed"):
            simgr.removed.clear()
    
    # time limit check
    timed_out = explore_timeout()
    if timed_out:                       # move 'active' stash to 'timeout' stash
        logger.debug(f"\n*** TIMEOUT reached ***")
        simgr.stash(from_stash='active', to_stash='timeout')

    logger.debug(f"\n-------------------------------------------------------------------------------------------")

    # Tell explorer to continue
    return True

# Utility functions
def to_set(x):
    if isinstance(x, (list, tuple)):
        return set(x)
    return {x}

def get_single_addr(addr):
    # print(f"Input addr: {addr}, type: {type(addr)}")  # Debug print
    
    if isinstance(addr, list):
        if len(addr) != 1:
            raise ValueError(f"Expected single address, got multiple: {addr}")
        addr = addr[0]
        # print(f"After list extract: {addr}, type: {type(addr)}")  # Debug print
    
    if isinstance(addr, str):
        if addr.startswith('0x'):
            result = int(addr, 16)
        else:
            result = int(addr)
        # print(f"Final result: {result}, type: {type(result)}")  # Debug print
        return result
    
    # print(f"Final result: {addr}, type: {type(addr)}")  # Debug print
    return addr

def finish_stats():
    # Time to complete
    global_end = time.time()
    print_msg_box(f"Runtime = {round(global_end - global_start, 2)} seconds")

    # Display the execution path
    print_msg_box("Reconstructed Execution Path:")
    for addr in execution_path:
        print(addr, flush=True)


def concretize_argc_argv(state):
    logger.debug("[*] Running concretize_argc_argv at main")
    # Concretize argc to 1 (just program name)
    state.regs.rdi = 1
    
    # Create concrete "nginx" string with specific length
    program_name = b"nginx\0"
    program_name_addr = state.heap.allocate(len(program_name))
    
    # Debug the allocated address
    logger.debug(f"[*] Allocated address for program name: {hex(program_name_addr)}")
    
    # Store the string byte by byte and verify each byte
    for i, b in enumerate(program_name):
        state.memory.store(
            program_name_addr + i,
            claripy.BVV(b, 8),
            endness=state.arch.memory_endness
        )
        # Debug each byte being stored
        stored_byte = state.memory.load(program_name_addr + i, 1)
        logger.debug(f"[*] Stored byte {i}: {hex(state.solver.eval(stored_byte))}")

    # Create argv array with concrete pointer
    argv_array_addr = state.heap.allocate(16)  # Space for two pointers
    
    # Store program name pointer
    state.memory.store(
        argv_array_addr,
        claripy.BVV(program_name_addr, 64),
        size=8,
        endness=state.arch.memory_endness
    )
    
    # Store null pointer
    state.memory.store(
        argv_array_addr + 8,
        claripy.BVV(0, 64),
        size=8,
        endness=state.arch.memory_endness
    )

    # Point rsi to argv array
    state.regs.rsi = argv_array_addr

    # Verification section with explicit byte handling
    verify_name_addr = state.memory.load(argv_array_addr, 8, endness=state.arch.memory_endness)
    verify_null = state.memory.load(argv_array_addr + 8, 8, endness=state.arch.memory_endness)
    
    # Get concrete address
    concrete_addr = state.solver.eval(verify_name_addr)
    logger.debug(f"[*] Loading string from concrete address: {hex(concrete_addr)}")
    
    # Load and verify each byte individually
    name_bytes = []
    for i in range(len(program_name) - 1):  # -1 to exclude null terminator
        byte = state.memory.load(concrete_addr + i, 1, endness='Iend_BE')
        byte_val = state.solver.eval(byte)
        name_bytes.append(byte_val)
    
    try:
        con_name = bytes(name_bytes).decode('utf-8')
    except UnicodeDecodeError:
        con_name = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in name_bytes)

    logger.debug(f"[*] argv/argc verification:")
    logger.debug(f"[*] - name_addr: {verify_name_addr}")
    logger.debug(f"[*] - name     : {con_name}")
    logger.debug(f"[*] - null     : {verify_null}")

    # Additional verification of the entire string
    full_string = state.memory.load(concrete_addr, len(program_name))
    logger.debug(f"[*] Full string as BVV: {full_string}")



def setup_concrete_config(state):
    logger.debug("[*] Running setup_concrete_config at conf_parse")
    
    # Create ngx_str_t structure for filename
    filename_str = state.heap.allocate(16)
    logger.debug(f"[*] Allocated ngx_str_t at: {hex(filename_str)}")
    
    # Define the concrete nginx.conf path
    config_path = b"/usr/local/nginx/conf/nginx.conf\0"
    filename_len = len(config_path) - 1
    
    # Allocate and store the path with alignment
    path_addr = state.heap.allocate(len(config_path))
    logger.debug(f"[*] Allocated path at: {hex(path_addr)}")
    
    # Store the path string with explicit byte-by-byte storage
    for i, b in enumerate(config_path):
        state.memory.store(path_addr + i, claripy.BVV(b, 8), endness=state.arch.memory_endness)
    
    # Store length and data pointer with explicit endianness
    state.memory.store(filename_str, 
                      claripy.BVV(filename_len, 64), 
                      endness=state.arch.memory_endness)
    state.memory.store(filename_str + 8, 
                      claripy.BVV(path_addr, 64), 
                      endness=state.arch.memory_endness)
    
    # Set RSI to point to our structure
    state.regs.rsi = claripy.BVV(filename_str, 64)
    
    # Add explicit constraints
    len_var = state.memory.load(filename_str, 8, endness=state.arch.memory_endness)
    data_ptr_var = state.memory.load(filename_str + 8, 8, endness=state.arch.memory_endness)
    
    state.add_constraints(len_var == filename_len)
    state.add_constraints(data_ptr_var == path_addr)
    
    # Verify the structure immediately after setting it up
    verify_len = state.memory.load(filename_str, 8, endness=state.arch.memory_endness)
    verify_ptr = state.memory.load(filename_str + 8, 8, endness=state.arch.memory_endness)
    
    logger.debug(f"[*] Immediate verification:")
    logger.debug(f"[*] - len field: {verify_len}")
    logger.debug(f"[*] - data field: {verify_ptr}")
    
    if verify_len.concrete and verify_ptr.concrete:
        ver_len = state.solver.eval(verify_len)
        ver_ptr = state.solver.eval(verify_ptr)
        logger.debug(f"[*] - concrete len: {hex(ver_len)}")
        logger.debug(f"[*] - concrete ptr: {hex(ver_ptr)}")
        
        # Read back the string to verify
        content = []
        for i in range(ver_len):
            byte = state.memory.load(ver_ptr + i, 1)
            if byte.concrete:
                content.append(state.solver.eval(byte))
        if content:
            logger.debug(f"[*] - stored string: {bytes(content).decode('utf-8')}")

    # Create concrete content for nginx.conf
    config_content = b"""# /usr/local/nginx/conf/nginx.conf
worker_processes 1;        # Force single process
daemon off;                # Run in foreground
master_process off;        # Disable master process

# Main context logging - applies to startup/shutdown and global events. Main error_log captures everything
error_log /usr/local/nginx/logs/error.log debug_core debug_alloc debug_mutex debug_event debug_http 
    debug_mail debug_stream;

events {
    worker_connections 16; # Minimize connections
    multi_accept off;      # Disable multiple accepts
}

http {
    # Basic MIME type mappings needed for serving files
    include       mime.types;
    default_type  application/octet-stream;

    # Enhanced access logging with minimal buffering for real-time logging
    access_log /usr/local/nginx/logs/access.log detailed buffer=4k flush=1s;

    # More aggressive file operation logging
    open_log_file_cache max=1000 inactive=10s valid=30s min_uses=1;

    server {
        listen 8080;
        server_name localhost;

        # Enable detailed error logging at server level
        # error_log /usr/local/nginx/logs/server-error.log debug;

        location / {
            root /usr/local/nginx/html;
            index index.html;

            # Add location-specific error log for even more granular debugging
            # error_log /usr/local/nginx/logs/location-error.log debug;

            # Log request body
            client_body_in_file_only on;
            client_body_buffer_size 16k;

            # Log all file operations
            log_not_found on;         # Log 404 errors
            log_subrequest on;        # Log subrequests

            # Log response headers
            add_header X-Debug-Request-ID $request_id always;
            add_header X-Debug-Connection $connection always;
            add_header X-Debug-Connection-Requests $connection_requests always;
        }
    }
}\0"""

    simfile = angr.SimFile('nginx.conf', content=config_content)
    state.fs.insert('/usr/local/nginx/conf/nginx.conf', simfile)

def constrain_init_cycle(state):
    logger.debug(f"[ @ ] init_cycle reached, constrained!")
    state.add_constraints(state.regs.rax != 0)
    rax = state.regs.rax
    logger.debug(f"         rax = {rax}   ->   if NULL(0), path should be move to unsat?")



logger = logging.getLogger('angr.sim_manager')

if not RESTORE:
    start_state = proj.factory.entry_state()
    main_addr = proj.loader.find_symbol('main').rebased_addr
    start_state.inspect.b('instruction', instruction=main_addr, action=concretize_argc_argv)                # concretize cli args

    conf_parse_addr = proj.loader.find_symbol('ngx_conf_parse').rebased_addr
    # start_state.inspect.b('instruction', instruction=conf_parse_addr, action=setup_concrete_config)         # concretize nginx.conf file      
    start_state.inspect.b('instruction',                                                                      # concretize nginx.conf file   
               when=angr.BP_BEFORE,
               instruction=conf_parse_addr,
               action=setup_concrete_config)
    
    init_cycle_ret_block_addr = 0x42BEDD
    start_state.inspect.b('instruction',                                                                      # concretize nginx.conf file   
               when=angr.BP_BEFORE,
               instruction=init_cycle_ret_block_addr,
               action=constrain_init_cycle)
    

    # start_state = proj.factory.blank_state(addr=prev_addr)
    SIMGR = proj.factory.simgr(start_state)



# # custom avoid addresses to narrow exploration space
# ngx_init_cycle_error_handling = [
#     0x42BE6D,
#     0x42BE7A,
#     0x42BE87,
#     0x42BE94,
#     0x42BEA1,
#     0x42BEAE,
#     0x42BEBB,
#     0x42BEF2,
#     0x42C24C,
#     0x42C25C,
#     0x42C276,
#     0x42C2AC,
#     0x42C2BC,
#     0x42C31E,
#     0x42C331,
#     0x42C341,
#     0x42C351,
#     0x42C36D,
#     0x42C3F9,
#     0x42C42B,
# ]
# custom_avoids = ngx_init_cycle_error_handling



if hasattr(SIMGR, 'active') and len(SIMGR.active) > 0:
    simgr = proj.factory.simgr(SIMGR.active)                                    # simgr updated at every explore()
elif hasattr(SIMGR, 'timeout') and len(SIMGR.timeout) > 0:
    simgr = proj.factory.simgr(SIMGR.timeout)
else:
    print(f"WARNING: entered ELSE at simgr assignment")
    simgr = None

if RESTORE:
    ITER = iter

execution_path = []
for idx, entry in enumerate(nginx_logs[0+iter:]):      # enumerate(gdb_logs[1:])
    # ipdb.set_trace()

    """ GDB logs"""
    # target_addr = int(entry['Addr'], 16)
    # target_addr_str = hex(target_addr)
    # func_name = entry['Func']
    """ nginx logs"""
    addrs = entry['lea_addr']
    target_addr = [int(addr, 16) for addr in addrs]
    target_addr_str = [hex(addr) for addr in target_addr]
    func_name = entry['function']

    if target_addr[0] == 0x43bbef:
        # TODO debug the gap to this log
        msg = f"<--- No path found from {prev_addr_str} to {target_addr_str} --->"
        execution_path.extend([prev_addr_str, msg])                   # TODO: fork when multiple paths found
        print_msg_box("Current Execution Path")
        print(f"{execution_path}", flush=True)
        print(f"Skipping: 0x43bbef - {func_name}", flush=True)

        # new hook for handler in ngx_epoll_process_events
        wait_handler_calladdr = 0x4475eb         # basic block addr: 0x4475e8
        ngx_http_wait_request_handler_symbol = proj.loader.find_symbol('ngx_http_wait_request_handler')
        ngx_http_wait_request_handler_addr = ngx_http_wait_request_handler_symbol.rebased_addr
        @proj.hook(wait_handler_calladdr, length=4, replace=True)
        def handler_wait_call(state):
            ret_addr = wait_handler_calladdr + 4

            return_addr_bv = claripy.BVV(ret_addr, 64)

            register_save_size = 6 * 8     # 48 bytes for saved registers
            local_vars_size = 8            # 24 bytes for local variables

            # Get current concrete RSP value for calculation
            current_rsp = state.solver.eval(state.regs.rsp)

            # Calculate how far we are from desired alignment
            # We want (rsp - 8) to be 16-byte aligned
            desired_rsp = ((current_rsp - 8) & ~0xF) + 0x10  # Round down to 16 and add 16
            alignment_adjustment = current_rsp - desired_rsp
            print(f"alignment_adjustment: {alignment_adjustment}", flush=True)

            # Apply the alignment adjustment
            if alignment_adjustment != 0:
                state.regs.rsp -= alignment_adjustment

            # Now adjust stack for return address
            state.regs.rsp -= 8

            # Calculate total stack frame size including our alignment
            total_stack_size = register_save_size + local_vars_size

            # Store return address at the correct location
            target_addr = state.regs.rsp + claripy.BVV(total_stack_size, 64)
            state.memory.store(target_addr, return_addr_bv)

            state.regs.ip = ngx_http_wait_request_handler_addr


        ngx_process_events_and_timers_symbol = proj.loader.find_symbol('ngx_process_events_and_timers')
        ngx_process_events_and_timers_addr = ngx_process_events_and_timers_symbol.rebased_addr
        prev_addr_str = hex(ngx_process_events_and_timers_addr)         # target_addr_str
        prev_call = 'ngx_process_events_and_timers'                     # func_name
        prev_addr = [ngx_process_events_and_timers_addr]
        print(f"prev_addr: {prev_addr}")
        print(f"prev_addr[0]: {prev_addr[0]}")
        new_state = proj.factory.blank_state(addr=prev_addr[0])
        simgr = proj.factory.simgr(new_state)
        simgr.move(from_stash='active', to_stash='found')
        print(f"new simgr: {simgr}", flush=True)
        ITER = ITER + 1
        continue

    print_msg_box(f"Explore {ITER}")
    if ITER > 0:
        sys.exit(0)
    finding_str = f"Finding path from {prev_addr_str} ({prev_call}) to {target_addr_str} ({func_name})"
    print(finding_str, flush=True)
    # Find a path from prev_addr to syscall_addr
    try:
        queue = Queue()
        avoid = [element for element in all_addrs - (to_set(prev_addr) | to_set(target_addr))]
        # avoid.extend(custom_avoids)


        print(f"\t[simgr first] {simgr} : {simgr.active}", flush=True)
        # clear simgr active list to clear up memory
        if idx > 0 and simgr:
            if hasattr(simgr, "active"):
                simgr.active.clear()
            if hasattr(simgr, "unconstrained"):
                simgr.unconstrained.clear()
            if hasattr(simgr, "old_unc"):
                simgr.old_unc.clear()
            if hasattr(simgr, "errored"):
                simgr.errored.clear()
            if hasattr(simgr, "old_err"):
                simgr.old_err.clear()
            if hasattr(simgr, "avoid"):
                simgr.avoid.clear()
            if hasattr(simgr, "timeout"):
                simgr.timeout.clear()
            if hasattr(simgr, "unsat"):
                # XXX: some debug output
                simgr.unsat.clear()
            if hasattr(simgr, "deadended"):
                simgr.deadended.clear()
            if hasattr(simgr, "old_dead"):
                simgr.old_dead.clear()

        if simgr and hasattr(simgr, "found"):
            found_states = random.sample(simgr.found, min(FOUND_LIMIT, len(simgr.found)))
            simgr.active.extend(found_states)
            simgr.found.clear()

        print(f"\t[simgr final] {simgr} : {simgr.active}", flush=True)
        print(f"\t[SIMGR final] {SIMGR} : {SIMGR.active}", flush=True)

        logger.info(f"\n\n================================ Explore {ITER} ================================\n{finding_str}\n\n")
        simgr = angr_explore(simgr, prev_addr, target_addr, avoid)
        ITER = ITER + 1

        # if using simgr.explore() several times, use simgr.unstash() to move states from the found stash to the active stash
        # ipdb.set_trace()
        if simgr and simgr.found:
            print(f"\t[simgr.found = TRUE]", flush=True)
            num_found = len(simgr.found)
            print(f"\t--> {num_found} paths found", flush=True)
            if num_found > 1:
                print(f"WARNING: multiple paths found, account for all", flush=True)
            for idx, found_path in enumerate(simgr.found):
                # Extract the list of basic block addresses traversed
                trace = found_path.history.bbl_addrs.hardcopy
                trace = [hex(i) for i in trace]
                print(f"\t--> Trace {idx} {trace}", flush=True)
                # ipdb.set_trace()
            SIMGR = proj.factory.simgr(simgr.found)

            # copy.deepcopy(simgr)
            # SIMGR.unstash()
            # execution_path.extend(trace)    # XXX
        else:
            # no simgr OR no simgr.found, debug by step()
            if not simgr:
                print(f"\t[NO simgr]", flush=True)
            else:
                print(f"\t[NO simgr.found]", flush=True)
            msg = f"<--- No path found from {prev_addr_str} to {target_addr_str} --->"
            print(f"\t--> {msg}", flush=True)
            print(f"[...recording SIMGR found path]", flush=True)

            if hasattr(SIMGR, "found") and len(SIMGR.found) > 0:
                for idx, found_path in enumerate(SIMGR.found):
                    # Extract the list of basic block addresses traversed
                    trace = found_path.history.bbl_addrs.hardcopy
                    trace = [hex(i) for i in trace]
                    print(f"\t--> SIMGR trace {idx}: {trace}", flush=True)
                    if len(SIMGR.found) > 1:
                        print(f"WARNING: global SIMGR multiple found", flush=True)
                        # ipdb.set_trace()
                execution_path.extend(trace)                    # TODO: fork when multiple paths found
            elif hasattr(SIMGR, "active") and len(SIMGR.active) > 0:            # we moved found paths to active stash
                for idx, found_path in enumerate(SIMGR.active):
                    # Extract the list of basic block addresses traversed
                    trace = found_path.history.bbl_addrs.hardcopy
                    trace = [hex(i) for i in trace]
                    print(f"\t--> SIMGR trace {idx}: {trace}", flush=True)
                    if len(SIMGR.active) > 1:
                        print(f"WARNING: global SIMGR multiple found", flush=True)
                        # ipdb.set_trace()
                execution_path.extend(trace)
            else:
                print(f"[SIMGR has 0 <found> or <active>]", flush=True)

            execution_path.extend([prev_addr_str, msg])                   # TODO: fork when multiple paths found
            print_msg_box("Current Execution Path")
            print(f"{execution_path}", flush=True)
            if not isinstance(prev_addr, int):
                print(f"About to process prev_addr: {[hex(a) for a in prev_addr]}", flush=True)
            else:
                print(f"About to process prev_addr: [{hex(prev_addr)}]", flush=True)

            if not RESTORE:
                fn = f"{bin_name}_simgr_{ITER-1}_HOOK0.0"
                if ITER-1 == 0:
                    save_angr_simgr(simgr, ITER - 1, fn)
                    print(f"Saved simgr {simgr} @ {fn}", flush=True)
                else:
                    save_angr_simgr(SIMGR, ITER - 1, fn)
                    print(f"Saved simgr {SIMGR} @ {fn}", flush=True)
                    print(f"Saved iter  {ITER - 1}", flush=True)

            finish_stats()
            exit(0)
            # new_state = proj.factory.blank_state(addr=get_single_addr(prev_addr))
            # SIMGR = proj.factory.simgr(new_state)
    except Exception as e:
        print(f"\t--> Error finding path to {target_addr_str}: {e}", flush=True)
        print(f"{tb.format_exc()}", flush=True)
    finally:
        print(f"---------------------------------------------------------------\n", flush=True)
        if simgr and hasattr(simgr, "found") and simgr.found:
            prev_addr = simgr.found[0].addr
        else:
            if isinstance(target_addr, list):
                prev_addr = target_addr[0]
                print(f"WARNING: prev_addr is likely INCORRECT", flush=True)
            else:
                prev_addr = target_addr 
        prev_addr_str = target_addr_str
        prev_call = func_name

# ipdb.set_trace()




# ltrace logs
"""
for entry in ltrace:
    syscall_addr = entry
    syscall_name = 'None'
    print(f"Finding path from {hex(prev_addr)} ({prev_call})  to {hex(syscall_addr)} ({syscall_name})", flush=True)
    
    # Find a path from prev_addr to syscall_addr
    try:
        start_state = proj.factory.blank_state(addr=prev_addr)
        simgr = proj.factory.simgr(start_state)
        simgr.explore(find=syscall_addr)

        ipdb.set_trace()
        
        if simgr.found:
            print(f"\t--> {len(simgr.found)} paths found", flush=True)
            found_path = simgr.found[0]
            # Extract the list of basic block addresses traversed
            trace = found_path.history.bbl_addrs.hardcopy
            trace = [hex(i) for i in trace]
            print(f"\t--> Trace {trace}", flush=Truez)
            execution_path.extend(trace)
            # prev_addr = syscall_addr  # Update for next syscall
        else:
            print(f"\t--> No path found from {hex(prev_addr)} to {hex(syscall_addr)}", flush=True)
        prev_addr = syscall_addr  # Update for next syscall
        prev_call = syscall_name 
    except Exception as e:
        print(f"Error finding path to {hex(syscall_addr)}: {e}")"""

# PERF syscall logs
"""for entry in syscall_data:
    syscall_addr = int(entry['callsite'], 16)
    syscall_name = entry['syscall']
    print(f"Finding path from {hex(prev_addr)} ({prev_call})  to {hex(syscall_addr)} ({syscall_name})", flush=True)
    
    # Find a path from prev_addr to syscall_addr
    try:
        start_state = proj.factory.blank_state(addr=prev_addr)
        simgr = proj.factory.simgr(start_state)
        simgr.explore(find=syscall_addr)

        ipdb.set_trace()
        
        if simgr.found:
            print(f"\t--> {len(simgr.found)} paths found", flush=True)
            found_path = simgr.found[0]
            # Extract the list of basic block addresses traversed
            trace = found_path.history.bbl_addrs.hardcopy
            trace = [hex(i) for i in trace]
            print(f"\t--> Trace {trace}", flush=True)
            execution_path.extend(trace)
            # prev_addr = syscall_addr  # Update for next syscall
        else:
            print(f"\t--> No path found from {hex(prev_addr)} to {hex(syscall_addr)}", flush=True)
        prev_addr = syscall_addr  # Update for next syscall
        prev_call = syscall_name 
    except Exception as e:
        print(f"Error finding path to {hex(syscall_addr)}: {e}", flush=True)"""


# # Remove duplicates while preserving order
# seen = set()
# ordered_execution_path = []
# for addr in execution_path:
#     if addr not in seen:
#         seen.add(addr)
#         ordered_execution_path.append(addr)


finish_stats()
