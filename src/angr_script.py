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
nginx_mapped_logs = '/home/dinko/exec-proj/log_parsing/mapped_nginx_logs_FIXED.log'





""" CONFIGURABLE OPTIONS """

bin_path = nginx_path
gdb_log_path = None
mapped_applogs_path = nginx_mapped_logs
explore_max_secs = 60

bin_name = os.path.basename(bin_path)

print(f"bin_path: {bin_path}\ngdb_log_path: {gdb_log_path}\nexplore_max_secs: {explore_max_secs}\nmapped_applogs_path: {mapped_applogs_path}\n\n", flush=True)
# print_msg_box("HELLO")
global_start = time.time()
# SIMGR = None
ITER = 0





""" Logging """

# Create log file handler with formatter
fh = logging.FileHandler(f'log_{bin_name}_{explore_max_secs}TEST.log', mode='w')
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
    start_addr = proj.loader.find_symbol('ngx_epoll_process_events').rebased_addr
    state = proj.factory.blank_state(
        addr=start_addr,
    )

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
    return state.solver.BVV(0, state.arch.bits)


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



""" angr Analysis"""

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
    print(f"ngx_time_update address: {hex(ngx_log_error_core_addr)}", flush=True)

    # ngx_log_error_core

    proj.hook_symbol('gettimeofday', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook_symbol('clock_gettime', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook_symbol('ngx_time_update', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook_symbol('ngx_log_error_core', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())

    if gettimeofday_symbol is None or clock_gettime_symbol is None or ngx_time_update_symbol is None or ngx_log_error_core_symbol is None:
        print("WARNING: Could not find one or both symbols to hook!", flush=True)

# Verify hooks are installed
print_msg_box("Verifying hooks...")
for addr, hook in proj._sim_procedures.items():
    print(f"Hook at {hex(addr)}: {hook}", flush=True)


# Set up the initial state
initial_state = None
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

if bin_name == 'grep':
    prev_addr = cfg.kb.functions.function(name='main').addr
    prev_call = "main"
    print_msg_box(f"MAIN address: {hex(prev_addr)}")
elif bin_name == 'nginx':
    prev_addr = cfg.kb.functions.function(name='ngx_epoll_process_events').addr
    prev_call = "ngx_epoll_process_events"
    print_msg_box(f"ngx_epoll_process_events address: {hex(prev_addr)}")

prev_addr_str = hex(prev_addr)

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


def timeout(seconds):
    def decorator(func):
        def wrapper(*args, **kwargs):
            queue = kwargs.pop("queue", None)
            p = Process(target=func, args=args, kwargs={**kwargs, "queue": queue})
            p.start()

            start_time = time.time()
            result = None

            # Poll the queue for a result within the timeout
            while time.time() - start_time < seconds:
                if queue and not queue.empty():
                    result = queue.get()  # Get simgr from queue if available
                    print(f"Result found in queue: {result}", flush=True)
                    p.terminate()  # Kill process immediately after getting result
                    break
                time.sleep(0.5)  # Small sleep to avoid busy waiting
            
            # Check if process is still alive after the loop, if no result was found
            if p.is_alive():
                print("Process is still alive after timeout. Terminating now.", flush=True)
                p.terminate()

            print(f"--> Final Result: {result}", flush=True)
            return result   # Return simgr if available, otherwise None
        return wrapper
    return decorator


@timeout(150)
def angr_explore(simstates, prev_addr, target_addr, avoid_addrs, queue=None):
    """
    Passing simgr to subprocess does not yield same results, instead pass simstates.
    """
    print(f"[angr_explore] simstates arg: {simstates}", flush=True)
    if len(simstates) < 1:
        simstates = proj.factory.blank_state(addr=get_single_addr(prev_addr))

    simgr = proj.factory.simgr(simstates)
    explore_count = 0
    while hasattr(simgr, "active") and simgr.active and (not hasattr(simgr, "found") or not simgr.found):
        try:
            print(f"simgr explore_count [{explore_count}]", flush=True)
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
            # simgr = None
        finally:
            print(f"SIMGR: {simgr}", flush=True)
            print(f"found: " + (f"{simgr.found}" if simgr and hasattr(simgr, 'found') and len(simgr.found) > 1 else "No found path"), flush=True)
            print(f"active: " + (f"{len(simgr.active)}" if simgr and hasattr(simgr, 'active') else "No active path"), flush=True)
            explore_count += 1
    if not queue.empty():
        queue.get()         # remove old state
    queue.put(simgr)        # latest state

    print(f"queue size: {queue.qsize()}", flush=True)
    print("Finished angr_explore(), exiting...", flush=True)


# Add custom step callback to log state information
def log_state_info(simgr):
    logger = logging.getLogger('angr.sim_manager')
    # Log active states
    if hasattr(simgr, "active"):
        logger.debug(f"======= Active States [{len(simgr.active)}] =======")
        # fh = logging.FileHandler('simgr_DEBUG.log', mode='a')
        # logger.addHandler(fh)
        logger.debug(f"SIMGR: {simgr}")
        for i, state in enumerate(simgr.active):
            # Convert bitvectors to integers before formatting
            ip_val = state.solver.eval(state.regs.ip)

            # Get containing function from project
            func = None
            try:
                node = cfg.model.get_any_node(ip_val, anyaddr=True)

                if ip_val == 0x447474:
                    logger.debug(f"\n!!! HERE NOW !!!\n")
                    logger.debug(f"{[hex(n.addr) for n in node.successors]}")

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
                if node:
                    func = proj.kb.functions.function(node.function_address)
                # func = proj.kb.functions.get_by_addr(ip_val)
            except Exception as e:
                logger.debug(f"Exception [log_state_info] {e}")
            func_name = func.name if func else "Unknown"
            len_f = len(func_name)
            curr_instr = state.block().capstone.insns[0].insn_name() + " " + state.block().capstone.insns[0].op_str if state.block() else "Unknown"
            prev_ip = state.history.recent_bbl_addrs[0]
            prev_block = proj.factory.block(prev_ip)
            prev_instr = prev_block.capstone.insns[-1].mnemonic
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
            logger.debug(f"  Error type: {type(errored_state.error)}")
            logger.debug(f"  Error message: {errored_state.error}")
            logger.debug(f"  Errored at addr: {hex(errored_state.state.addr)}")
            logger.debug(f"  Recent blocks: {[hex(x) for x in errored_state.state.history.recent_bbl_addrs]}")
            logger.debug(f"  Stack trace:\n{''.join(tb.format_tb(errored_state.traceback))}")

        # move errored, for later analysis if needed
        simgr.drop(stash='errored')     # TODO: why not working?!?!

    # Log unconstrained states
    if hasattr(simgr, "unconstrained"):
        logger.debug(f"======= Unconstrained States [{len(simgr.unconstrained)}] =======")
        for i, state in enumerate(simgr.unconstrained):
            ip_val = state.solver.eval(state.regs.ip)
            logger.debug(f"Unconstrained State {i}:")
            logger.debug(f"  IP: 0x{ip_val:x} (symbolic: {state.regs.ip.symbolic})")
            logger.debug(f"  Recent blocks: {[hex(x) for x in state.history.recent_bbl_addrs]}")
            # Log why it became unconstrained
            if hasattr(state, "unconstrained_reason"):
                logger.debug(f"  Reason: {state.unconstrained_reason}")
            # Log possible IP values
            if state.regs.ip.symbolic:
                possible_ips = state.solver.eval_upto(state.regs.ip, 10)
                logger.debug(f"  Possible IP values: {[hex(x) for x in possible_ips]}")
                
        # move unconstrained, for later analysis if needed
        simgr.stash(from_stash='unconstrained', to_stash='old_unc')

    return simgr

# Log when new paths are found
def log_path_found(simgr):
    if hasattr(simgr, "found"):
        logger = logging.getLogger('angr.sim_manager')
        logger.debug(f"======= Found States [{len(simgr.found)}] =======")
        for state in simgr.found:
            logger.info(f"Found path to target: {[hex(addr) for addr in state.history.bbl_addrs]}")

# Log when paths are pruned
def log_path_pruned(simgr):
    if hasattr(simgr, 'pruned'):
        logger = logging.getLogger('angr.sim_manager')
        logger.debug(f"======= Pruned States [{len(simgr.pruned)}] =======")
        for state in simgr.pruned:
            prune_addr = state.solver.eval(state.regs.ip)
            logger.debug(f"Pruned path at 0x{prune_addr:x}")

def step_function(simgr):
    # Log all current states
    log_state_info(simgr)
    
    # Log if we found targets
    log_path_found(simgr)
    
    # Log pruned paths
    # log_path_pruned(simgr)

    logger = logging.getLogger('angr.sim_manager')
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

logger = logging.getLogger('angr.sim_manager')

# start_state_entry = proj.factory.entry_state(addr=prev_addr)
start_state = proj.factory.blank_state(addr=prev_addr)
SIMGR = proj.factory.simgr(start_state)       # global simgr
found_states = [initial_state]                    # begin at the initial state from setup_<bin>_symex()
simgr = None                                    # simgr updated at every explore()
execution_path = []
for idx, entry in enumerate(nginx_logs):      # enumerate(gdb_logs[1:])
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

    print_msg_box(f"Explore {ITER}")
    print(f"Finding path from {prev_addr_str} ({prev_call}) to {target_addr_str} ({func_name})", flush=True)
    # Find a path from prev_addr to syscall_addr
    try:
        queue = Queue()
        avoid = [element for element in all_addrs - (to_set(prev_addr) | to_set(target_addr))]
        # print_msg_box("AVOID")
        # print(f"len(gdb_all): {len(all_addrs)}", flush=True)
        # print(f"len(avoid): {len(avoid)}", flush=True)
        # print(f"prev in gdb: {prev_addr in all_addrs}", flush=True)
        # print(f"prev in avoid: {prev_addr in avoid}", flush=True)
        # print(f"target in gdb: {target_addr in all_addrs}", flush=True)
        # print(f"target in avoid: {target_addr in avoid}", flush=True)
        # for i in avoid:
        #     print(hex(i), flush=True)
        
        # simgr = copy.deepcopy(SIMGR)

        if idx > 0:
            found_states = []
        if simgr and hasattr(simgr, "found"):
            found_states = simgr.found

        logger.info(f"\n\n================================ Explore {ITER} ================================\n\n")
        simgr = angr_explore(found_states, prev_addr, target_addr, avoid, queue=queue)
        ITER = ITER + 1

        # TODO: if using simgr.explore() several times, use simgr.unstash() to move states from the found stash to the active stash
        # ipdb.set_trace()
        if simgr and simgr.found:
            print(f"\t[simgr.found = TRUE]", flush=True)
            print(f"\t--> {len(simgr.found)} paths found", flush=True)
            for idx, found_path in enumerate(simgr.found):
                # Extract the list of basic block addresses traversed
                trace = found_path.history.bbl_addrs.hardcopy
                trace = [hex(i) for i in trace]
                print(f"\t--> Trace {idx} {trace}", flush=True)
                if len(simgr.found) > 1:
                    print(f"MULTIPLE FOUND 1", flush=True)
                    # ipdb.set_trace()
            SIMGR = simgr
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
            print(f"[...recording SIMGR found path, and starting anew]", flush=True)
            if hasattr(SIMGR, "found"):
                for idx, found_path in enumerate(SIMGR.found):
                    # Extract the list of basic block addresses traversed
                    trace = found_path.history.bbl_addrs.hardcopy
                    trace = [hex(i) for i in trace]
                    print(f"\t--> trace {idx} Extension {trace}", flush=True)
                    if len(SIMGR.found) > 1:
                        print(f"MULTIPLE FOUND 2", flush=True)
                        # ipdb.set_trace()
                execution_path.extend(trace)                    # TODO: fork when multiple paths found
            else:
                print(f"[SIMGR has no attribute <found>]", flush=True)
            execution_path.extend([prev_addr_str, msg])                                    # add "no path from X to Y" msg
            print_msg_box("Current Execution Path")
            print(f"{execution_path}", flush=True)
            print(f"About to process prev_addr: {prev_addr}, type: {type(prev_addr)}")
            new_state = proj.factory.blank_state(addr=get_single_addr(prev_addr))
            SIMGR = proj.factory.simgr(new_state)
    except Exception as e:
        print(f"\t--> Error finding path to {target_addr_str}: {e}", flush=True)
    finally:
        print(f"---------------------------------------------------------------\n", flush=True)
        prev_addr = target_addr  # Update for next syscall TODO: select the 'found' addr when target was list
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


# Time to complete
global_end = time.time()
print_msg_box(f"Runtime = {round(global_end - global_start, 2)} seconds")


# Display the execution path
print_msg_box("Reconstructed Execution Path:")
for addr in execution_path:
    print(addr, flush=True)
