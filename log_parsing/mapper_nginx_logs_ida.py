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

        print(f"\n\nFORMAT STRINGSS : {self.format_strings}\n\n")
                        
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
        if fmt_str == "epoll add event: fd:%d op:%d ev:%08XD":
            match = re.search(r'epoll add event: fd:(\d+) op:(\d+) ev:([0-9A-F]+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%d', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%d', 'val': match.group(2)}
                concrete_values['par_3'] = {'fmt': '%08XD', 'val': match.group(3)}

        elif fmt_str == "epoll: fd:%d ev:%04XD d:%p":
            match = re.search(r'epoll: fd:(\d+) ev:([0-9A-F]+) d:([0-9A-F]+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%d', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%04XD', 'val': match.group(2)}
                concrete_values['par_3'] = {'fmt': '%p', 'val': match.group(3)}

        elif fmt_str == "posix_memalign: %p:%uz @%uz":
            match = re.search(r'posix_memalign: ([0-9A-F]+):(\d+) @(\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%p', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%uz', 'val': match.group(2)}
                concrete_values['par_3'] = {'fmt': '%uz', 'val': match.group(3)}

        elif fmt_str == "event timer add: %d: %M:%M":
            match = re.search(r'event timer add: (\d+): (\d+):(\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%d', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%M', 'val': match.group(2)}
                concrete_values['par_3'] = {'fmt': '%M', 'val': match.group(3)}

        elif fmt_str == "reusable connection: %ui":
            match = re.search(r'reusable connection: (\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%ui', 'val': match.group(1)}

        elif fmt_str == "recv: fd:%d %z of %uz":
            match = re.search(r'recv: fd:(\d+) (\d+) of (\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%d', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%z', 'val': match.group(2)}
                concrete_values['par_3'] = {'fmt': '%uz', 'val': match.group(3)}

        # HTTP URI, args, and extension handling - these have quoted values
        elif fmt_str in ["http uri: \"%V\"", "http args: \"%V\"", "http exten: \"%V\""]:
            match = re.search(r': "([^"]*)"', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%V', 'val': match.group(1)}

        # HTTP write filter with multiple parameters
        elif fmt_str == "http write filter: l:%ui f:%ui s:%O":
            match = re.search(r'l:(\d+) f:(\d+) s:(\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%ui', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%ui', 'val': match.group(2)}
                concrete_values['par_3'] = {'fmt': '%O', 'val': match.group(3)}

        # HTTP output filter
        elif fmt_str == "http output filter \"%V?%V\"":
            match = re.search(r'http output filter "([^"]+)"', message)
            if match:
                path = match.group(1)
                if '?' in path:
                    base, query = path.split('?', 1)
                    concrete_values['par_1'] = {'fmt': '%V', 'val': base}
                    concrete_values['par_2'] = {'fmt': '%V', 'val': query}
                else:
                    concrete_values['par_1'] = {'fmt': '%V', 'val': path}
                    concrete_values['par_2'] = {'fmt': '%V', 'val': ''}

        # HTTP copy filter
        elif fmt_str == "http copy filter: \"%V?%V\"":
            match = re.search(r'http copy filter: "([^"]+)"', message)
            if match:
                path = match.group(1)
                if '?' in path:
                    base, query = path.split('?', 1)
                    concrete_values['par_1'] = {'fmt': '%V', 'val': base}
                    concrete_values['par_2'] = {'fmt': '%V', 'val': query}
                else:
                    concrete_values['par_1'] = {'fmt': '%V', 'val': path}
                    concrete_values['par_2'] = {'fmt': '%V', 'val': ''}

        elif "bind()" in fmt_str:
            match = re.search(r'bind\(\) ([0-9.:]+) #(\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%V', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%d', 'val': match.group(2)}

        elif "using the" in fmt_str:
            match = re.search(r'using the "([^"]+)" event method', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%s', 'val': match.group(1)}

        # Configuration with path
        elif fmt_str == "using configuration \"%s%V\"":
            match = re.search(r'using configuration "([^"]+)"', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%s', 'val': match.group(1)}

        # Generic/content phase
        elif fmt_str in ["generic phase: %ui", "content phase: %ui"]:
            match = re.search(r'phase: (\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%ui', 'val': match.group(1)}
        
        # Read operation
        elif fmt_str == "read: %d, %p, %uz, %O":
            match = re.search(r'read: (\d+), ([0-9A-F]+), (\d+), (\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%d', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%p', 'val': match.group(2)}
                concrete_values['par_3'] = {'fmt': '%uz', 'val': match.group(3)}
                concrete_values['par_4'] = {'fmt': '%O', 'val': match.group(4)}

        elif fmt_str == "write: %d, %p, %uz, %O":
            match = re.search(r'write: (\d+), ([0-9A-F]+), (\d+), (\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%d', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%p', 'val': match.group(2)}
                concrete_values['par_3'] = {'fmt': '%uz', 'val': match.group(3)}
                concrete_values['par_4'] = {'fmt': '%O', 'val': match.group(4)}

        elif fmt_str == "add cleanup: %p":
            match = re.search(r'add cleanup: ([0-9A-F]+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%p', 'val': match.group(1)}

        elif fmt_str == "malloc: %p:%uz":
            match = re.search(r'malloc: ([0-9A-F]+):(\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%p', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%uz', 'val': match.group(2)}

        elif "notify eventfd:" in fmt_str:
            match = re.search(r'notify eventfd: (\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%d', 'val': match.group(1)}

        # Post access phase
        elif fmt_str == "post access phase: %ui":
            match = re.search(r'post access phase: (\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%ui', 'val': match.group(1)}

        # HTTP postpone filter
        elif fmt_str == "http postpone filter \"%V?%V\" %p":
            match = re.search(r'filter "([^"?]+)\??([^"]*)" ([0-9A-F]+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%V', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%V', 'val': match.group(2)}
                concrete_values['par_3'] = {'fmt': '%p', 'val': match.group(3)}

        # Write old buf
        elif fmt_str == "pipe buf ls:%d %p, pos %p, size: %z":
            match = re.search(r't:(\d+) f:(\d+) ([0-9A-F]+), pos ([0-9A-F]+), size: (\d+) file: \d+, size: \d+', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%d', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%p', 'val': match.group(3)}
                concrete_values['par_3'] = {'fmt': '%p', 'val': match.group(4)}
                concrete_values['par_4'] = {'fmt': '%z', 'val': match.group(5)}

        elif fmt_str == "http write filter limit %O":
            match = re.search(r'http write filter limit (\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%O', 'val': match.group(1)}
        
        # HTTP write filter with pointer
        elif fmt_str == "http write filter %p":
            match = re.search(r'http write filter ([0-9A-F]+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%p', 'val': match.group(1)}
    
        # Free with unused size
        elif fmt_str == "free: %p, unused: %uz":
            match = re.search(r'free: ([0-9A-F]+), unused: (\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%p', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%uz', 'val': match.group(2)}
    
        # HC busy with pointer and integer
        elif fmt_str == "hc busy: %p %i":
            match = re.search(r'hc busy: ([0-9A-F]+) (\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%p', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%i', 'val': match.group(2)}
    
        # Epoll wait error
        elif fmt_str == "chown(\"%s\", %d) failed":
            match = re.search(r'epoll_wait\(\) failed \((\d+): ([^)]+)\)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%d', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%s', 'val': match.group(2)}
    
        # Epoll del event
        elif fmt_str == "epoll del event: fd:%d op:%d ev:%08XD":
            match = re.search(r'epoll del event: fd:(\d+) op:(\d+) ev:([0-9A-F]+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%d', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%d', 'val': match.group(2)}
                concrete_values['par_3'] = {'fmt': '%08XD', 'val': match.group(3)}
    
        # Close listening
        elif fmt_str == "close listening %V #%d ":
            match = re.search(r'close listening ([0-9.:]+) #(\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%V', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%d', 'val': match.group(2)}

        # Writev operation
        elif fmt_str == "writev: %d, %uz, %O":
            match = re.search(r'writev: (\d+) of (\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%d', 'val': match.group(1)}
                concrete_values['par_2'] = {'fmt': '%uz', 'val': match.group(2)}

        # Close cached file
        elif fmt_str == "close cached open file: %s, fd:%d, c:%d, u:%d, %d":
            match = re.search(r'http finalize request: (\d+), "([^"]+)" a:(\d+), c:(\d+)', message)
            if match:
                concrete_values['par_1'] = {'fmt': '%s', 'val': match.group(2)}  # file path
                concrete_values['par_2'] = {'fmt': '%d', 'val': match.group(1)}  # fd
                concrete_values['par_3'] = {'fmt': '%d', 'val': match.group(4)}  # c value
                concrete_values['par_4'] = {'fmt': '%d', 'val': match.group(3)}  # a value

        else:
            # Generic format string handling as fallback
            try:
                regex_pattern = fmt_str
                regex_pattern = re.escape(regex_pattern)
                regex_pattern = regex_pattern.replace(r'\%V', '([^"]+)')
                regex_pattern = regex_pattern.replace(r'\%d', '(-?\d+)')
                regex_pattern = regex_pattern.replace(r'\%u', '(\d+)')
                regex_pattern = regex_pattern.replace(r'\%ui', '(\d+)')
                regex_pattern = regex_pattern.replace(r'\%s', '([^"\s]+)')
                regex_pattern = regex_pattern.replace(r'\%p', '([0-9A-F]+)')
                regex_pattern = regex_pattern.replace(r'\%uz', '(\d+)')
                regex_pattern = regex_pattern.replace(r'\%z', '(-?\d+)')
                regex_pattern = regex_pattern.replace(r'\%O', '(\d+)')
                regex_pattern = regex_pattern.replace(r'\%M', '(\d+)')
                regex_pattern = regex_pattern.replace(r'\%XD', '([0-9A-F]+)')

                match = re.search(regex_pattern, message)
                if match:
                    format_specs = re.findall(r'%[svdVDuUxXpPzMui]+', fmt_str)
                    for i, value in enumerate(match.groups()):
                        if i < len(format_specs):
                            concrete_values[f'par_{i+1}'] = {
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
