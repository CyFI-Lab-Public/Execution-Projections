

def parse_nginx_mappings(log_file_path):
    mappings = []
    current_entry = {}
    
    with open(log_file_path, 'r') as f:
        lines = f.readlines()
        
    for line in lines:
        line = line.strip()
        if line.startswith('Log:'):
            if current_entry:
                mappings.append(current_entry)
            current_entry = {'log_msg': line.split(':', 1)[1].strip()}
        elif line.startswith('LEA instruction address:'):
            current_entry['lea_addr'] = line.split(':')[1].strip()
        elif line.startswith('Function:'):
            current_entry['function'] = line.split(':')[1].strip()
    
    if current_entry:
        mappings.append(current_entry)
        
    return mappings