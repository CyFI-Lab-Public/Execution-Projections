#!/usr/bin/env python3
import os
import argparse

def generate_breakpoints(src_dir, output_file):
    """Generate GDB breakpoint commands for all .c files in src directory recursively."""
    c_files = []
    
    # Walk through directory recursively
    for root, _, files in os.walk(src_dir):
        for file in files:
            if file.endswith('.c'):
                # Get relative path from src_dir
                rel_path = os.path.relpath(os.path.join(root, file), src_dir)
                c_files.append(rel_path)
    
    # Write breakpoint commands to output file
    with open(output_file, 'w') as f:
        for c_file in sorted(c_files):
            f.write(f'set_rbreak_with_commands {c_file}:.\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate GDB breakpoint commands for C files')
    parser.add_argument('src_dir', help='Source directory containing .c files')
    parser.add_argument('output_file', help='Output file for breakpoint commands')
    args = parser.parse_args()
    
    generate_breakpoints(args.src_dir, args.output_file)