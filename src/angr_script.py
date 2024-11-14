import angr
import time
import sys
import os
import ipdb
import time
import atexit
import signal
import logging

from multiprocessing import Process, Queue


# Local Imports
sys.path.append('../')
from log_parsing.parser_perf import parse_perf_script_output
from log_parsing.parser_gdb import parse_gdb_log_triggered, parse_gdb_log_all
from pretty_print import print_msg_box


# Logging Levels
logger_simgr = logging.getLogger('angr.simgr')
logger_simgr.setLevel(logging.DEBUG)
# logger = logging.getLogger('angr')
# logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('angr.log')
# logger.addHandler(fh)


# Process Cleanup
def cleanup():
    os.kill(os.getpid(), signal.SIGTERM)
atexit.register(cleanup)



grep_path = '/home/dinko/exec-proj/grep/grep-3.11/src/grep'
grep_perf_log = '..../perf_script_dynamic.log'
grep_gdb_log = '/home/dinko/exec-proj/log/grep/function_trace_BRsrc.log'

bin_path = grep_path



""" Log Parsing """

# LOG: 'perf script'
"""syscall_data = parse_perf_script_output(grep_perf_log)

for entry in syscall_data:
    print(f"Syscall: {entry['syscall']}, Callsite: {entry['callsite']}")
print_msg_box(f"===== {len(syscall_data)} syscall callsites =====")"""


# LOG: gdb func trace
base_address = 0x555555554005
base_angr = 0x400000

# parse all breakpoints
"""gdb_all = parse_gdb_log_all(grep_gdb_log)
for i in range(len(gdb_all)):
    gdb_all[i] = int(gdb_all[i], 16) + base_angr
gdb_all = set(gdb_all)"""

# parse sequence of triggered callsites to use as 'find' in angr explore
gdb_logs = parse_gdb_log_triggered(grep_gdb_log)

all_addrs = [] # get all callsites to use for 'avoid' in angr_explore

for entry in gdb_logs[1:]:
    addr = int(entry['Addr'], 16) - base_address + base_angr
    all_addrs.append(addr)
    entry['Addr'] = hex(addr)
    print(f"{entry['Addr']}, {entry['Func']}")
print_msg_box(f"===== {len(gdb_logs)} callsites =====")

all_addrs = set(all_addrs)      # remove dups






""" ANGR Analysis"""

proj = angr.Project(bin_path, load_options={'auto_load_libs': False})

# Find the address of 'main'
main_symbol = proj.loader.find_symbol('main')
main_addr = main_symbol.rebased_addr

# Generate CFG
start = time.time()
cfg = proj.analyses.CFGFast(show_progressbar=True)
end = time.time()
print(f"CFGFast: {cfg.graph}, {round(end - start, 2)}s")
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
print(f"CFGEmulated: {cfg.graph}, {round(end - start, 2)}")"""

execution_path = []
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
        print(f"Callsite {addr_str} exists in CFG.")
    else:
        print(f"Callsite {addr_str} not found in CFG.")

# ipdb.set_trace()



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
                    print("Result found in queue, terminating angr_explore process.")
                    p.terminate()  # Kill process immediately after getting result
                    break
                time.sleep(0.1)  # Small sleep to avoid busy waiting
            
            # Check if process is still alive after the loop, if no result was found
            if p.is_alive():
                print("Process is still alive after timeout. Terminating now.")
                p.terminate()

            return result   # Return simgr if available, otherwise None
        return wrapper
    return decorator


@timeout(60)
def angr_explore(prev_addr, target_addr, avoid_addrs, queue=None):
    try:
        start_state = proj.factory.blank_state(addr=prev_addr)
        simgr = proj.factory.simgr(start_state)
        simgr.explore(find=target_addr, avoid=avoid_addrs)
    except TimeoutError:
        print("\t--> Function took too long to execute")
        # simgr = None
    finally:
        print(f"SIMGR: {simgr}")
        print(f"found: {simgr.found if simgr else 'No found path'}")
        # print(f"q size before: {queue.qsize()}")
        if queue:
            queue.put(simgr)  # Place the simgr in the queue

        print(f"queue size: {queue.qsize()}")
    print("Finished angr_explore(), exiting...")


for entry in gdb_logs[1:]:
    # ipdb.set_trace()
    target_addr = int(entry['Addr'], 16)
    target_addr_str = hex(target_addr)
    func_name = entry['Func']
    print(f"Finding path from {hex(prev_addr)} ({prev_call})  to {target_addr_str} ({func_name})")
    # Find a path from prev_addr to syscall_addr
    try:
        queue = Queue()
        avoid = [element for element in all_addrs - {prev_addr, target_addr}]
        # print_msg_box("AVOID")
        # print(f"len(gdb_all): {len(all_addrs)}")
        # print(f"len(avoid): {len(avoid)}")
        # print(f"prev in gdb: {prev_addr in all_addrs}")
        # print(f"prev in avoid: {prev_addr in avoid}")
        # print(f"target in gdb: {target_addr in all_addrs}")
        # print(f"target in avoid: {target_addr in avoid}")
        # for i in avoid:
        #     print(hex(i))
            
        simgr = angr_explore(prev_addr, target_addr, avoid, queue=queue)
        # ipdb.set_trace()

        if simgr.found:
            print(f"\t--> {len(simgr.found)} paths found")
            for i, f in enumerate(simgr.found):
                found_path = simgr.found[0]
                # Extract the list of basic block addresses traversed
                trace = found_path.history.bbl_addrs.hardcopy
                trace = [hex(i) for i in trace]
                print(f"\t--> Trace {i} {trace}")

            execution_path.extend(trace)
        else:
            print(f"\t--> No path found from {hex(prev_addr)} to {target_addr_str}")
    except Exception as e:
        print(f"\t--> Error finding path to {target_addr_str}: {e}")
    finally:
        print(f"---------------------------------------------------------------\n")
        prev_addr = target_addr  # Update for next syscall
        prev_call = func_name

# ipdb.set_trace()



# ltrace logs
"""
for entry in ltrace:
    syscall_addr = entry
    syscall_name = 'None'
    print(f"Finding path from {hex(prev_addr)} ({prev_call})  to {hex(syscall_addr)} ({syscall_name})")
    
    # Find a path from prev_addr to syscall_addr
    try:
        start_state = proj.factory.blank_state(addr=prev_addr)
        simgr = proj.factory.simgr(start_state)
        simgr.explore(find=syscall_addr)

        ipdb.set_trace()
        
        if simgr.found:
            print(f"\t--> {len(simgr.found)} paths found")
            found_path = simgr.found[0]
            # Extract the list of basic block addresses traversed
            trace = found_path.history.bbl_addrs.hardcopy
            trace = [hex(i) for i in trace]
            print(f"\t--> Trace {trace}")
            execution_path.extend(trace)
            # prev_addr = syscall_addr  # Update for next syscall
        else:
            print(f"\t--> No path found from {hex(prev_addr)} to {hex(syscall_addr)}")
        prev_addr = syscall_addr  # Update for next syscall
        prev_call = syscall_name 
    except Exception as e:
        print(f"Error finding path to {hex(syscall_addr)}: {e}")"""

# PERF syscall logs
"""for entry in syscall_data:
    syscall_addr = int(entry['callsite'], 16)
    syscall_name = entry['syscall']
    print(f"Finding path from {hex(prev_addr)} ({prev_call})  to {hex(syscall_addr)} ({syscall_name})")
    
    # Find a path from prev_addr to syscall_addr
    try:
        start_state = proj.factory.blank_state(addr=prev_addr)
        simgr = proj.factory.simgr(start_state)
        simgr.explore(find=syscall_addr)

        ipdb.set_trace()
        
        if simgr.found:
            print(f"\t--> {len(simgr.found)} paths found")
            found_path = simgr.found[0]
            # Extract the list of basic block addresses traversed
            trace = found_path.history.bbl_addrs.hardcopy
            trace = [hex(i) for i in trace]
            print(f"\t--> Trace {trace}")
            execution_path.extend(trace)
            # prev_addr = syscall_addr  # Update for next syscall
        else:
            print(f"\t--> No path found from {hex(prev_addr)} to {hex(syscall_addr)}")
        prev_addr = syscall_addr  # Update for next syscall
        prev_call = syscall_name 
    except Exception as e:
        print(f"Error finding path to {hex(syscall_addr)}: {e}")"""


# # Remove duplicates while preserving order
# seen = set()
# ordered_execution_path = []
# for addr in execution_path:
#     if addr not in seen:
#         seen.add(addr)
#         ordered_execution_path.append(addr)


# Display the execution path
print_msg_box("Reconstructed Execution Path:")
for addr in execution_path:
    print(addr)
