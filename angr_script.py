import angr
import time

bin_path = '/usr/local/bin/ziptool'

p = angr.Project(bin_path, load_options={'auto_load_libs': False})

# static CFG
start = time.time()
cfg = p.analyses.CFGFast()
end = time.time()
print(f"CFGFast: {cfg.graph}, {round(end - start, 2)}s")

# dynamic CFG (symbolic)
start = time.time()
cfgE = p.analyses.CFGEmulated(keep_state=True)
end = time.time()
print(f"CFGEmul: {cfgE.graph}, {round(end - start, 2)}")