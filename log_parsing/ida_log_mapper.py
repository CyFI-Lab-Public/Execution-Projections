from idaapi import *
from idautils import *
from idc import *
import re
from typing import Dict, List, Tuple, Optional

class LogMapper:
    def __init__(self):
        self.format_strings: Dict[int, Tuple[str, str, int]] = {}  # str_addr -> (fmt_str, func_name, lea_addr)
        self.log_patterns: Dict[str, List[Tuple[int, str, int]]] = {}  # partial_str -> [(str_addr, func_name, lea_addr)]
        
    def find_format_strings(self):
        """Find format strings and their loading instructions"""
        for seg in Segments():
            if get_segm_name(seg) in ['.rodata', '.rdata', '.data']:
                curr_addr = seg
                end_addr = get_segm_end(seg)
                
                while curr_addr < end_addr:
                    string = get_strlit_contents(curr_addr, -1, STRTYPE_C)
                    if string:
                        if b'%' in string:  # Potential format string
                            for xref in XrefsTo(curr_addr, 0):
                                if print_insn_mnem(xref.frm) == "lea":
                                    func = get_func(xref.frm)
                                    if func:
                                        self.format_strings[curr_addr] = (
                                            string.decode('utf-8', errors='ignore'),
                                            get_func_name(func.start_ea),
                                            xref.frm
                                        )
                                        break
                        curr_addr += len(string) + 1
                    else:
                        curr_addr += 1
                        
    def build_log_patterns(self):
        """Create searchable patterns from format strings"""
        for str_addr, (fmt_str, func_name, lea_addr) in self.format_strings.items():
            parts = re.split(r'%[svdVDuUxXpP]', fmt_str)
            for part in parts:
                part = part.strip()
                if len(part) > 3:  # Ignore very short strings
                    if part not in self.log_patterns:
                        self.log_patterns[part] = []
                    self.log_patterns[part].append((str_addr, func_name, lea_addr))

    def extract_concrete_values(self, message: str, fmt_str: str) -> Dict[str, Dict[str, str]]:
        """Extract concrete values based on format string type"""
        concrete_values = {}

        # Special case handling based on format string patterns
        if "bind()" in fmt_str:
            match = re.search(r'bind\(\) ([0-9.:]+) #(\d+)', message)
            if match:
                concrete_values['param_1'] = {'fmt': '%V', 'val': match.group(1)}
                concrete_values['param_2'] = {'fmt': '%d', 'val': match.group(2)}

        elif "using the" in fmt_str:
            match = re.search(r'using the "([^"]+)" event method', message)
            if match:
                concrete_values['param_1'] = {'fmt': '%s', 'val': match.group(1)}

        elif "write:" in fmt_str:
            match = re.search(r'write: (\d+), ([0-9A-F]+), (\d+), (\d+)', message)
            if match:
                concrete_values['param_1'] = {'fmt': '%d', 'val': match.group(1)}
                concrete_values['param_2'] = {'fmt': '%p', 'val': match.group(2)}
                concrete_values['param_3'] = {'fmt': '%uz', 'val': match.group(3)}
                concrete_values['param_4'] = {'fmt': '%O', 'val': match.group(4)}

        elif "add cleanup:" in fmt_str:
            match = re.search(r'add cleanup: ([0-9A-F]+)', message)
            if match:
                concrete_values['param_1'] = {'fmt': '%p', 'val': match.group(1)}

        elif "malloc:" in fmt_str:
            match = re.search(r'malloc: ([0-9A-F]+):(\d+)', message)
            if match:
                concrete_values['param_1'] = {'fmt': '%p', 'val': match.group(1)}
                concrete_values['param_2'] = {'fmt': '%uz', 'val': match.group(2)}

        elif "notify eventfd:" in fmt_str:
            match = re.search(r'notify eventfd: (\d+)', message)
            if match:
                concrete_values['param_1'] = {'fmt': '%d', 'val': match.group(1)}

        else:
            # Generic format string handling for unrecognized patterns
            try:
                regex_pattern = fmt_str
                regex_pattern = re.escape(regex_pattern)
                # Handle all nginx format specifiers
                regex_pattern = regex_pattern.replace(r'\%V', '([0-9.:]+)')  # IP:port
                regex_pattern = regex_pattern.replace(r'\%d', '(-?\d+)')     # Signed integers
                regex_pattern = regex_pattern.replace(r'\%u', '(\d+)')       # Unsigned integers
                regex_pattern = regex_pattern.replace(r'\%s', '([^"\s]+)')   # Strings
                regex_pattern = regex_pattern.replace(r'\%p', '([0-9A-F]+)') # Pointers
                regex_pattern = regex_pattern.replace(r'\%uz', '(\d+)')      # Size_t
                regex_pattern = regex_pattern.replace(r'\%O', '(\d+)')       # Off_t

                match = re.search(regex_pattern, message)
                if match:
                    format_specs = re.findall(r'%[svdVDuUxXpPz]', fmt_str)
                    for i, value in enumerate(match.groups()):
                        if i < len(format_specs):
                            concrete_values[f'param_{i+1}'] = {
                                'fmt': format_specs[i],
                                'val': value
                            }
            except re.error:
                pass

        return concrete_values
    
    def map_log_line(self, log_line: str) -> Optional[Tuple[int, str, str, Dict[str, str]]]:
        """Map a log line to its format string loading instruction"""
        match = re.match(r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[[^]]+\] \d+#\d+: (.*)', log_line)
        if not match:
            return None
            
        message = match.group(1)
        
        # Find matching format string
        best_match = None
        best_match_len = 0
        
        for pattern, locations in self.log_patterns.items():
            if pattern in message and len(pattern) > best_match_len:
                best_match = (pattern, locations)
                best_match_len = len(pattern)
        
        if not best_match:
            return None
            
        pattern, locations = best_match
        if not locations:
            return None
            
        str_addr, func_name, lea_addr = locations[0]
        fmt_str = self.format_strings[str_addr][0]
        
        # Extract concrete values using specialized handler
        concrete_values = self.extract_concrete_values(message, fmt_str)
            
        return (lea_addr, func_name, fmt_str, concrete_values)

def main():
    mapper = LogMapper()
    mapper.find_format_strings()
    mapper.build_log_patterns()
    
    # Specify the path to your log file
    # log_file_path = "/path/to/your/nginx/error.log"  # Change this to your log file path
    log_file_path = "/nethome/ddermendzhiev3/exec-proj/error.log"
    
    print("Format String Mappings:\n")
    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:  # Skip empty lines
                    result = mapper.map_log_line(line)
                    if result:
                        lea_addr, func_name, fmt_str, concrete_values = result
                        print(f"Log: {line}")
                        print(f"LEA instruction address: {hex(lea_addr)}")
                        print(f"Function: {func_name}")
                        print(f"Format string: {fmt_str}")
                        print(f"Concrete values: {concrete_values}")
                        print()
    except FileNotFoundError:
        print(f"Error: Could not find log file at {log_file_path}")
    except Exception as e:
        print(f"Error reading log file: {str(e)}")

if __name__ == '__main__':
    main()
