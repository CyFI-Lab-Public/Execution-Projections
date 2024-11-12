import angr
import time

# Path to the binary
grep_path = '/home/dinko/exec-proj/grep/grep-3.11/src/grep'
proj = angr.Project(grep_path, load_options={'auto_load_libs': False})

# Perform CFG analysis to detect functions and basic blocks
start = time.time()
cfg = proj.analyses.CFGFast(show_progressbar=True)
end = time.time()
print(f"CFGFast: {cfg.graph}, {round(end - start, 2)}s")

base_angr = 0x400000
# Function to get basic block entry points
def get_basic_block_addresses(proj):
    entry_points = []
    for func_addr in proj.kb.functions:
        func = proj.kb.functions[func_addr]
        func_name = func.name
        addrs = []
        for block in func.blocks:
            addrs.append(hex(block.addr - base_angr))
        entry_points.append({func_name: addrs})
    return entry_points

def get_funcs(proj):
    funcs = set()
    for func_addr in proj.kb.functions:
        func = proj.kb.functions[func_addr]
        funcs.add(func.name)
    return funcs

# Collect the entry points and write them to a file
basic_block_addresses = get_basic_block_addresses(proj)
funcs = get_funcs(proj)
with open("basic_block_addresses.txt", "w") as f:
    for func_dict in basic_block_addresses:
        for func_name, addrs in func_dict.items():
            f.write(f"{func_name} : {addrs}\n")
    f.write(f"=======================================\n")
    for func in funcs:
        f.write(f"{func}\n")
