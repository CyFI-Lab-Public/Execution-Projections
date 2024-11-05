import angr
import time
import sys

from parser_perf_script import parse_perf_script_output
from pretty_print import print_msg_box


grep_path = '/home/dinko/exec-proj/grep/grep-3.11/src/grep'
grep_perf_path = '/home/dinko/exec-proj/grep/perf_script_output.txt'

bin_path = grep_path



""" Log Parsing """
syscall_data = parse_perf_script_output(grep_perf_path)

# Display the results
for entry in syscall_data:
    print(f"Syscall: {entry['syscall']}, Callsite: {entry['callsite']}")

print_msg_box(f"===== {len(syscall_data)} syscall callsites =====")

sys.exit(0)


""" ANGR Analysis"""

proj = angr.Project(bin_path, load_options={'auto_load_libs': False})

# static CFG
start = time.time()
cfg = proj.analyses.CFGFast()
end = time.time()
print(f"CFGFast: {cfg.graph}, {round(end - start, 2)}s")
# CFGFast: DiGraph with 58508 nodes and 125044 edges, 133.84s

# # dynamic CFG (symbolic)
# start = time.time()
# cfgE = proj.analyses.CFGEmulated(keep_state=True)
# end = time.time()
# print(f"CFGEmul: {cfgE.graph}, {round(end - start, 2)}")


main_func = cfg.kb.functions.function(name='main')

start_state = proj.factory.blank_state(addr=main_func.addr)
simgr = proj.factory.simgr(start_state)
target_addr = 0x4923A9  # Address of first openat syscall
simgr.explore(find=target_addr)
