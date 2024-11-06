import angr
import time
import sys

from parser_perf_script import parse_perf_script_output
from pretty_print import print_msg_box


grep_path = '/home/dinko/exec-proj/grep/grep-3.11/src/grep'
grep_perf_path = '/home/dinko/exec-proj/grep/perf_script.log'

bin_path = grep_path



""" Log Parsing """

# 'perf script' log
syscall_data = parse_perf_script_output(grep_perf_path)

for entry in syscall_data:
    print(f"Syscall: {entry['syscall']}, Callsite: {entry['callsite']}")
print_msg_box(f"===== {len(syscall_data)} syscall callsites =====")







""" ANGR Analysis"""

proj = angr.Project(bin_path, load_options={'auto_load_libs': False})


# # Generate CFG
# start = time.time()
# cfg = proj.analyses.CFGFast()
# end = time.time()
# print(f"CFGFast: {cfg.graph}, {round(end - start, 2)}s")
# # grep: CFGFast: DiGraph with 58508 nodes and 125044 edges, 133.84s


# dynamic CFG (symbolic)
start = time.time()
cfg = proj.analyses.CFGEmulated(
    starts=[proj.entry],  # Start from the entry point
    context_sensitivity_level=2,  # Increase context sensitivity
    keep_state=True,  # Keep the state to resolve indirect jumps
    # enable_function_hints=False  # Disable hints to force analysis
)

end = time.time()
print(f"CFGEmulated: {cfg.graph}, {round(end - start, 2)}")



# Reconstruct the Execution Path
execution_path = []
prev_addr = cfg.kb.functions.function(name='main').addr
prev_call = "main"
print_msg_box(f"MAIN address: {hex(prev_addr)}")

for entry in syscall_data:
    syscall_addr = int(entry['callsite'], 16)
    syscall_name = entry['syscall']
    print(f"Finding path from {hex(prev_addr)} ({prev_call})  to {hex(syscall_addr)} ({syscall_name})")
    
    # Find a path from prev_addr to syscall_addr
    try:
        start_state = proj.factory.blank_state(addr=prev_addr)
        simgr = proj.factory.simgr(start_state)
        simgr.explore(find=syscall_addr)
        
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
        print(f"Error finding path to {hex(syscall_addr)}: {e}")

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
