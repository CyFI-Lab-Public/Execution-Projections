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
import angrcli.full
import angrcli.plugins.ContextView          # Print the state: state.context_view.pprint()

from multiprocessing import Process, Queue


# Local Imports
sys.path.append('../')
from log_parsing.parser_perf import parse_perf_script_output
from log_parsing.parser_gdb import parse_gdb_log_triggered, parse_gdb_log_all
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





""" CONFIGURABLE OPTIONS """

bin_path = grep_path
gdb_log_path = grep_gdb_log
explore_max_secs = 100

print_msg_box(f"bin_path: {bin_path}\ngdb_log_path: {gdb_log_path}\nexplore_max_secs: {explore_max_secs}")
global_start = time.time()
# SIMGR = None
ITER = 0





""" Logging """

# Create log file handler with formatter
fh = logging.FileHandler(f'log_grep_{explore_max_secs}.log', mode='w')
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(levelname)s - %(name)s - %(message)s - %(asctime)s.%(msecs)03d - %(funcName)s() - %(pathname)s:%(lineno)d',
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

# parse sequence of triggered callsites to use as 'find' in angr explore
gdb_logs = parse_gdb_log_triggered(gdb_log_path)

all_addrs = [] # get all callsites to use for 'avoid' in angr_explore

for entry in gdb_logs[1:]:
    addr = int(entry['Addr'], 16) - base_address + base_angr
    all_addrs.append(addr)
    entry['Addr'] = hex(addr)
    print(f"{entry['Addr']}, {entry['Func']}", flush=True)
print_msg_box(f"===== {len(gdb_logs)} callsites =====")

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


def hook_init_localeinfo(state):
    print(f"[HOOK] init_localeinfo called at {state.regs.rip}")
    # Log callsite info if available
    if state.history.jumpkind == 'Ijk_Call':
        print(f"[HOOK] Called from {state.history.jump_source}")
    return


def hook_c_stack_action(state):
    print(f"[HOOK] c_stack_action called at {state.regs.rip}")
    if state.history.jumpkind == 'Ijk_Call':
        print(f"[HOOK] Called from {state.history.jump_source}")
    # Just return 0 to indicate success
    return state.solver.BVV(0, state.arch.bits)


class InitLocaleInfoHook(angr.SimProcedure):
    def run(self):
        print(f"[HOOK] init_localeinfo ENTRY at {hex(self.state.addr)}")
        print(f"[HOOK] Callsite: {hex(self.state.history.jump_source)}")
        # No return value needed for void function

class CStackActionHook(angr.SimProcedure):
    def run(self):
        print(f"[HOOK] c_stack_action ENTRY at {hex(self.state.addr)}")
        print(f"[HOOK] Callsite: {hex(self.state.history.jump_source)}")
        return self.state.solver.BVV(0, self.state.arch.bits)




""" angr Analysis"""

# Load the binary
proj = angr.Project(bin_path, load_options={'auto_load_libs': False})

print_msg_box(f"Hooking Procedures:")

init_locale_symbol = proj.loader.find_symbol('init_localeinfo')
init_locale_addr = init_locale_symbol.rebased_addr
print(f"init_localeinfo address: {hex(init_locale_addr)}", flush=True)

c_stack_symbol = proj.loader.find_symbol('c_stack_action')
c_stack_addr = c_stack_symbol.rebased_addr
print(f"c_stack_action address: {hex(c_stack_addr)}", flush=True)

if init_locale_symbol is None or c_stack_symbol is None:
    print("WARNING: Could not find one or both symbols to hook!")


# Hook functions that cause state explosion, return immediately
proj.hook_symbol('init_localeinfo', InitLocaleInfoHook())
proj.hook_symbol('c_stack_action', CStackActionHook())

# Verify hooks are installed
print_msg_box("Verifying hooks...")
for addr, hook in proj._sim_procedures.items():
    print(f"Hook at {hex(addr)}: {hook}", flush=True)


# Set up the initial state
initial_state = setup_grep_symex_state(proj)

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

prev_addr = cfg.kb.functions.function(name='main').addr
prev_call = "main"
print_msg_box(f"MAIN address: {hex(prev_addr)}")

# Check if the callsites exist in the CFG
for entry in gdb_logs[1:]:
    addr = int(entry['Addr'], 16)
    addr_str = hex(addr)
    func_name = entry['Func']
    node = cfg.model.get_any_node(addr, anyaddr=True)
    if node:
        print(f"Callsite {addr_str} exists in CFG.", flush=True)
    else:
        print(f"Callsite {addr_str} not found in CFG.", flush=True)

# ipdb.set_trace()


def compare_simgrs(simgr1, simgr2):
    # First check if they're the exact same object
    if simgr1 is simgr2:
        print("Same object identity")
        return True
        
    # Compare basic attributes
    print("\nComparing attributes:")
    for attr in ['active', 'deadended', 'found', 'avoided', 'errored']:
        if hasattr(simgr1, attr) and hasattr(simgr2, attr):
            states1 = getattr(simgr1, attr)
            states2 = getattr(simgr2, attr)
            print(f"{attr}:")
            print(f"  simgr1: {states1}")
            print(f"  simgr2: {states2}")
            print(f"  Length match: {len(states1) == len(states2)}")
            
    # Compare state attributes if there are active states
    if simgr1.active and simgr2.active:
        print("\nComparing first active state:")
        state1 = simgr1.active[0]
        state2 = simgr2.active[0]
        print(f"IP: {state1.ip} vs {state2.ip}")
        print(f"Regs: {state1.regs} vs {state2.regs}")
        
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


@timeout(60)
def angr_explore(simstates, prev_addr, target_addr, avoid_addrs, queue=None):
    """
    Passing simgr to subprocess does not yield same results, instead pass simstates.
    """
    print(f"[angr_explore] simstates arg: {simstates}", flush=True)
    try:
        if len(simstates) < 1:
            simstates = proj.factory.blank_state(addr=prev_addr)
        
        simgr = proj.factory.simgr(simstates)
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
        print(f"found: {simgr.found if simgr and hasattr(simgr, 'found') else 'No found path'}", flush=True)
        print(f"active: {simgr.active if simgr and hasattr(simgr, 'active') else 'No active path'}", flush=True)
        if not queue.empty():
            queue.get()         # remove old state
        queue.put(simgr)        # latest state

        print(f"queue size: {queue.qsize()}", flush=True)
    print("Finished angr_explore(), exiting...", flush=True)


# Add custom step callback to log state information
def log_state_info(simgr):
    if hasattr(simgr, "active"):
        logger = logging.getLogger('angr.sim_manager')
        # fh = logging.FileHandler('simgr_DEBUG.log', mode='a')
        # logger.addHandler(fh)
        logger.debug(f"SIMGR: {simgr}")
        for i, state in enumerate(simgr.active):
            # Convert bitvectors to integers before formatting
            ip_val = state.solver.eval(state.regs.ip)
            logger.debug(f"State {i}  |  IP: 0x{ip_val:x}  |  Recent BB: {hex(state.history.recent_bbl_addrs[0])}  |  Active constraints: {len(state.solver.constraints)}")
            if ip_val == init_locale_addr:
                logger.debug(f"WARNING ^^^: Hitting init_localeinfo despite hook!")
            elif ip_val == c_stack_addr:
                logger.debug(f"WARNING ^^^: Hitting c_stack_addr despite hook!")
    return simgr

# Log when new paths are found
def log_path_found(simgr):
    if hasattr(simgr, "found"):
        logger = logging.getLogger('angr.sim_manager')
        for state in simgr.found:
            logger.info(f"Found path to target: {[hex(addr) for addr in state.history.bbl_addrs]}")

# Log when paths are pruned
def log_path_pruned(simgr):
    if hasattr(simgr, 'pruned'):
        logger = logging.getLogger('angr.sim_manager')
        for state in simgr.pruned:
            prune_addr = state.solver.eval(state.regs.ip)
            logger.debug(f"Pruned path at 0x{prune_addr:x}")

def step_function(simgr):
    # Log all current states
    log_state_info(simgr)
    
    # # Log if we found target
    # log_path_found(simgr)
    
    # # Log pruned paths
    # log_path_pruned(simgr)
    
    # Tell explorer to continue
    return True


start_state_entry = proj.factory.entry_state(addr=prev_addr)
start_state = proj.factory.blank_state(addr=prev_addr)
SIMGR = proj.factory.simgr(start_state)       # global simgr
found_states = [initial_state]                    # begin at the initial state from setup_grep_symex()
simgr = None                                    # simgr updated at every explore()
execution_path = []
for idx, entry in enumerate(gdb_logs[1:]):
    # ipdb.set_trace()
    target_addr = int(entry['Addr'], 16)
    target_addr_str = hex(target_addr)
    func_name = entry['Func']
    print_msg_box(f"Explore {ITER}")
    print(f"Finding path from {hex(prev_addr)} ({prev_call})  to {target_addr_str} ({func_name})", flush=True)
    # Find a path from prev_addr to syscall_addr
    try:
        queue = Queue()
        avoid = [element for element in all_addrs - {prev_addr, target_addr}]
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
            msg = f"<--- No path found from {hex(prev_addr)} to {target_addr_str} --->"
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
            execution_path.extend([hex(prev_addr), msg])                                    # add "no path from X to Y" msg
            print_msg_box("Current Execution Path")
            print(f"{execution_path}", flush=True)
            new_state = proj.factory.blank_state(addr=prev_addr)
            SIMGR = proj.factory.simgr(new_state)
    except Exception as e:
        print(f"\t--> Error finding path to {target_addr_str}: {e}", flush=True)
    finally:
        print(f"---------------------------------------------------------------\n", flush=True)
        prev_addr = target_addr  # Update for next syscall
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
