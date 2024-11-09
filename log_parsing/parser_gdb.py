import re
import ipdb

def parse_gdb_log(filename):
    with open(filename, 'r') as file:
        log_data = file.read()


    # remove initial gdb output and breakpoint setting
    log_data = log_data.split("Using host lib")[1:][0]
    
    # Split log data by "Breakpoint" to parse each section individually
    breakpoint_sections = log_data.split("Breakpoint ")[1:]  # skip first part before 'Breakpoint'

    # Define function to extract function name and address from each section
    def parse_breakpoint_section(section):
        # Capture function name on the first line after "Breakpoint"
        func_name_match = re.search(r"^\d+, ([\w_]+)", section)
        func_name = func_name_match.group(1) if func_name_match else "n/a"

        # Capture address, specifically from lines starting with '#1' if available
        addr_match = re.search(r"#1\s+(0x[0-9a-fA-F]+)", section)
        address = addr_match.group(1) if addr_match else "n/a"

        return {"Func": func_name, "Addr": address}

    # Applying parsing on each section
    results = [parse_breakpoint_section(section) for section in breakpoint_sections]

    return results