import re

def parse_assembly_equations(assembly_lines):
    equations = []
    current_constants = []
    in_sequence = False
    load_count = 0
    prev_instruction = None
    
    for line in assembly_lines:
        match = re.match(r'^\d+:\s*(\w+)\s*(?:([A-Z]+\s*\(\d+\))|\(\d+\))?', line.strip())
        if not match:
            continue
        instruction = match.group(1)
        
        if instruction == 'LOAD' and not in_sequence:
            in_sequence = True
            load_count = 1
            current_constants = []
        
        elif in_sequence and instruction == 'PUSH':
            value = match.group(2)
            if value:
                constant = re.search(r'\((\d+)\)', value).group(1)
                current_constants.append(constant)
        
        elif in_sequence and instruction == 'LOAD':
            load_count += 1
        
        elif in_sequence and instruction == 'ADD':
            prev_instruction = 'ADD'
        
        elif in_sequence and instruction == 'STORE' and prev_instruction == 'ADD':
            if load_count == len(current_constants) and load_count == 49:
                equation = f"sum_{{i=0}}^{{48}} flag[i] × J[i], where J[i] = [{', '.join(current_constants)}]"
                eq_number_match = re.search(r'\((\d+)\)', line)
                if eq_number_match:
                    eq_number = int(eq_number_match.group(1))
                    equations.append((eq_number, equation))
                else:
                    print(f"Warning: Could not find equation number in line: {line}")
            in_sequence = False
            prev_instruction = 'STORE'
        
        elif in_sequence and instruction == 'LOAD' and prev_instruction != 'STORE':
            if load_count == len(current_constants) and load_count == 49:
                equation = f"sum_{{i=0}}^{{48}} flag[i] × J[i], where J[i] = [{', '.join(current_constants)}]"
                equations.append((None, equation))
            in_sequence = False
            load_count = 1
            current_constants = []
            prev_instruction = 'LOAD'
        
        else:
            prev_instruction = instruction
    
    return equations

with open('asm.txt', 'r') as f:
    lines = f.readlines()

equations = parse_assembly_equations(lines)
print(len(equations), "equations found:")
for eq_number, eq in equations:
    print(f"Equation stored at {eq_number}: {eq}")