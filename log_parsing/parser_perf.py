import re

def parse_perf_script_output(filename):
    syscall_data = []  # List to store syscall trace data

    # RegEx
    syscall_pattern = re.compile(r'syscalls:sys_enter_(\w+):')  # Matches syscalls with names
    ip_pattern = re.compile(r'^\s+([0-9a-f]+)')  # Matches instruction pointers

    with open(filename, 'r') as file:
        current_syscall = None
        current_ip = None

        for line in file:
            # Check if the line has a syscall entry
            syscall_match = syscall_pattern.search(line)
            if syscall_match:
                # Capture syscall name
                syscall_name = syscall_match.group(1)
                current_syscall = syscall_name  # Update current syscall
                current_ip = None  # Reset IP for new syscall
                continue

            # If we are within a syscall block -> find the first IP
            if current_syscall:
                ip_match = ip_pattern.match(line)
                if ip_match:
                    # Capture the first instruction pointer
                    current_ip = ip_match.group(1)
                    # Store the syscall and its IP, then reset
                    syscall_data.append({
                        'syscall': current_syscall,
                        'callsite': hex(int(current_ip, 16) - 2)    # XXX: -2 because perf records IP after instr is executed
                    })
                    current_syscall = None  # Reset syscall for the next entry

    return syscall_data