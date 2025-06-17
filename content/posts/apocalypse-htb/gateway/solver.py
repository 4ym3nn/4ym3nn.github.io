#!/usr/bin/env python3
import pexpect
import re
import sys
import traceback
import json

def run_gdb_interaction(binary_path, password):
    try:
        # Spawn GDB process with verbose output
        gdb = pexpect.spawn(f'gdb {binary_path}', encoding='utf-8', logfile=sys.stdout)
        gdb.timeout = 10
        
        # Set breakpoint
        gdb.sendline('break *0x08049f05')
        
        # Run the program
        gdb.sendline('run')
        
        # Wait for program prompts or events
        while True:
            index = gdb.expect([
                'Breakpoint 1, ', 
                'Recall the ✨ enchantments ✨ of your forefathers: ', 
                'Program received signal', 
                'No such file or directory',
                pexpect.TIMEOUT, 
                pexpect.EOF
            ])
            
            if index == 0:
                print(f"[DEBUG] Breakpoint hit with password: {password}")
                break
            elif index == 1:
                print(f"[DEBUG] Sending password: {password}")
                gdb.sendline(password)
                break
            elif index in [2, 3, 4, 5]:
                print(f"[DEBUG] Unexpected event. Index: {index}")
                gdb.close()
                return None
        
        gdb.expect_exact("(gdb)")
        # Examine memory location
        gdb.sendline('x/32xw $ebp-0x19c')
        gdb.expect_exact("(gdb)")
        memory_output = gdb.before
        gdb.sendline('x/32xw $ebp-0x11c')
        gdb.expect_exact("(gdb)")
        flag_output = gdb.before
                
        # Quit GDB
        gdb.sendline('quit')
        gdb.close()
        
        return parse_memory_output(memory_output),parse_memory_output(flag_output)

    except Exception as e:
        print("[DEBUG] Unexpected error:")
        print(traceback.format_exc())
        return None

def parse_memory_output(output):
    memory_values = []
    
    for line in output.splitlines():
        match = re.search(r':\s*(.*)', line)
        if match:
            values = match.group(1).split()
            memory_values.extend(values)
    
    return memory_values

def map_character_transformations(binary_path):
    # Initial password with all 'A's
    base_password = 'HTB{' + 'A' * 27 + '}'
    
    # Dictionary to store character transformations
    transformation_map = {}
    
    # Iterate through each position to map
    for pos in range(len(base_password)):  # Skip 'HTB{' and '}'
        print(f"\n[DEBUG] Mapping transformations for position {pos}")
        
        # Prepare passwords with A and B at the current position
        a_password = list(base_password)
        b_password = list(base_password)
        a_password[pos] = 'A'
        b_password[pos] = 'B'
        
        # Convert to strings
        a_password_str = ''.join(a_password)
        b_password_str = ''.join(b_password)
        
        # Get memory values for A and B
        a_memory,flag_output1 = run_gdb_interaction(binary_path, a_password_str)
        b_memory,flag_output2 = run_gdb_interaction(binary_path, b_password_str)
        
        if a_memory is None or b_memory is None:
            print(f"[ERROR] Failed to get memory for position {pos}")
            continue
        j=0;
        for i in  range(len(a_memory)):
            if a_memory[i]!=b_memory[i]:
                j=i;
                
        # Find indices where memory differs
        different_indices = j;
        
        # Store transformation details
        transformation_map[pos] = {
            'changed_indices': different_indices,
            'a_values': a_memory[j] ,
            'b_values': b_memory[j],
            'you_have_to_match':flag_output1[j],
            'you_have_to_match2':flag_output2[j],
            
        }
        

    
    return transformation_map

def main():
    binary_path = "./gateway"  # Replace with actual binary path
    
    # Map character transformations
    transformation_map = map_character_transformations(binary_path)
    
    # Write the transformation map to a JSON file
    with open('transformation_map.json', 'w') as json_file:
        json.dump(transformation_map, json_file, indent=4)
    # Print summary
    print("\n[SUMMARY] Transformation Map:")
    for pos, details in transformation_map.items():
        print(f"Position {pos}:")
        print(f"  Changed Indices: {details['changed_indices']}")
        print(f"  A Values: {details['a_values']}")
        print(f"  B Values: {details['b_values']}")

if __name__ == "__main__":
    main()