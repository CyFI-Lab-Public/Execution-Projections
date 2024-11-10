import angr
import time
import sys
import os
import ipdb
import multiprocessing
import time

import logging
# logging.getLogger('angr').setLevel(logging.DEBUG)

sys.path.append('../')
from log_parsing.parser_perf import parse_perf_script_output
from log_parsing.parser_gdb import parse_gdb_log
from pretty_print import print_msg_box


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
gdb_logs = parse_gdb_log(grep_gdb_log)
base_address = 0x555555554005
base_angr = 0x400000

for entry in gdb_logs[1:]:
    entry['Addr'] = hex(int(entry['Addr'], 16) - base_address + base_angr)
    print(f"{entry['Addr']}, {entry['Func']}")
print_msg_box(f"===== {len(gdb_logs)} callsites =====")





""" ANGR Analysis"""

proj = angr.Project(bin_path, load_options={'auto_load_libs': False})

# Find the address of 'main'
main_symbol = proj.loader.find_symbol('main')
main_addr = main_symbol.rebased_addr

# Generate CFG
start = time.time()
cfg = proj.analyses.CFGFast()
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



def timeout(seconds):
    def decorator(func):
        def wrapper(*args, **kwargs):
            p = multiprocessing.Process(target=func, args=args, kwargs=kwargs)
            p.start()
            p.join(seconds)
            if p.is_alive():
                p.terminate()
                raise TimeoutError("Function execution timed out")
            return p.exitcode
        return wrapper
    return decorator


@timeout(60)
def angr_explore(prev_addr, target_addr):
    try:
        start_state = proj.factory.blank_state(addr=prev_addr)
        simgr = proj.factory.simgr(start_state)
        simgr.explore(find=target_addr)
    except TimeoutError:
        print("\t--> Function took too long to execute")
    finally:
        print(f"SIMGR: {simgr}")
        print(f"found: {simgr.found}")
        return simgr


for entry in gdb_logs[1:]:
    # ipdb.set_trace()
    target_addr = int(entry['Addr'], 16)
    target_addr_str = hex(target_addr)
    func_name = entry['Func']
    print(f"Finding path from {hex(prev_addr)} ({prev_call})  to {target_addr_str} ({func_name})")
    # Find a path from prev_addr to syscall_addr
    try:
        simgr = angr_explore(prev_addr, target_addr)
        ipdb.set_trace()
        if simgr.found:
            print(f"\t--> {len(simgr.found)} paths found")
            found_path = simgr.found[0]
            # Extract the list of basic block addresses traversed
            trace = found_path.history.bbl_addrs.hardcopy
            trace = [hex(i) for i in trace]
            print(f"\t--> Trace {trace}")
            execution_path.extend(trace)
        else:
            print(f"\t--> No path found from {hex(prev_addr)} to {target_addr_str}")
    except Exception as e:
        print(f"\t--> Error finding path to {target_addr_str}: {e}")
    finally:
        prev_addr = target_addr  # Update for next syscall
        prev_call = func_name 

ipdb.set_trace()



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
print("Reconstructed Execution Path:")
for addr in execution_path:
    print(addr)
