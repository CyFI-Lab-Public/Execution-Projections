

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
            # Split the addresses and clean them up
            addresses = line.split(':', 1)[1].strip()
            # Handle both single and multiple addresses
            if ',' in addresses:
                # Split on comma and clean each address
                addr_list = [addr.strip() for addr in addresses.split(',')]
            else:
                # Single address case
                addr_list = [addresses]
            current_entry['lea_addr'] = addr_list
        elif line.startswith('Function:'):
            current_entry['function'] = line.split(':')[1].strip()
        elif line.startswith('Format string:'):
            current_entry['fmt_str'] = line.split(':', 1)[1].strip()
        elif line.startswith('Concrete values:'):
            current_entry['concrete_vals'] = line.split(':', 1)[1].strip()
    
    if current_entry:
        mappings.append(current_entry)
        
    return mappings