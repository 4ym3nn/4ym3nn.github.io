

import sys
from typing import List, Tuple, Dict

class DynamicDNADisassembler:
    def __init__(self):
        
        self.initial_nm = {'A': 0, 'T': 1, 'G': 2, 'C': 3}
        
        
        self.instructions = {
            0: "PUSH",      
            1: "POP",       
            2: "LOAD",      
            3: "STORE",     
            4: "ADD",       
            5: "SUB",       
            6: "MUL",       
            7: "MOD",       
            8: "EQ",        
            9: "JMP",       
            10: "JEQ",      
            11: "JNE",      
            12: "PRINT",    
            13: "CALL",     
            14: "SWAP",     
            15: "HALT"      
        }
        
        
        self.mapping_transforms = {
            
            111: {'A': 1, 'T': 2, 'G': 3, 'C': 0},
            
            117: {'A': 3, 'G': 2, 'C': 1, 'T': 0},
            
            105: {'A': 2, 'G': 1, 'C': 3, 'T': 0}
        }
        
        
        self.predefined_values = {22: 105, 26: 111, 27: 117}
    
    def trans(self, dna_sequence: str, nm: Dict[str, int]) -> int:
        return sum((nm[c] << 2 * i for i, c in enumerate(dna_sequence)))
    
    def reverse_trans(self, value: int, length: int) -> str:
        nucleotides = ['A', 'T', 'G', 'C']
        result = []
        for i in range(length):
            result.append(nucleotides[(value >> (2 * i)) & 3])
        return ''.join(result)
    
    def predict_call_key(self, instructions_so_far: List, current_stack: List[int]) -> int:
        
        for addr, instr, operand_dna, operand in reversed(instructions_so_far[-10:]):
            if instr == "LOAD" and operand in self.predefined_values:
                return self.predefined_values[operand]
        
        
        return None
    
    def disassemble_dynamic(self, code: str) -> List[Tuple[int, str, str, int, Dict[str, int]]]:
        instructions = []
        pc = 0
        current_nm = self.initial_nm.copy()
        call_count = 0
        
        while pc < len(code):
            
            if pc + 2 > len(code):
                break
                
            opcode_dna = code[pc:pc + 2]
            opcode = self.trans(opcode_dna, current_nm)
            
            
            if opcode in [1, 4, 5, 6, 7, 8, 12, 13, 14, 15]:
                
                operand_dna = ""
                operand = 0
                instruction_length = 2
            else:
                
                if pc + 12 > len(code):
                    break
                operand_dna = code[pc + 2:pc + 12]
                operand = self.trans(operand_dna, current_nm)
                instruction_length = 12
            
            
            instr_name = self.instructions.get(opcode, f"UNKNOWN_{opcode}")
            
            
            instructions.append((pc, instr_name, operand_dna, operand, current_nm.copy()))
            
            
            if instr_name == "CALL":
                call_count += 1
                
                predicted_key = None
                
                
                if call_count == 1:
                    predicted_key = 111
                elif call_count == 2:
                    predicted_key = 117
                elif call_count >= 3:
                    predicted_key = 105
                
                if predicted_key and predicted_key in self.mapping_transforms:
                    current_nm = self.mapping_transforms[predicted_key].copy()
                    print(f"DEBUG: After CALL #{call_count}, nm updated to: {current_nm}")
            
            pc += instruction_length
        
        return instructions
    
    def format_instruction_dynamic(self, addr: int, instr: str, operand_dna: str, 
                                 operand: int, nm: Dict[str, int], call_count: int = 0) -> str:
        addr_str = f"{addr:04d}"
        
        
        nm_str = f"[nm: A={nm['A']},T={nm['T']},G={nm['G']},C={nm['C']}]"
        
        if operand_dna:
            base_str = f"{addr_str}: {instr:<8} {operand_dna} ({operand})"
            
            if instr in ["LOAD", "STORE"]:
                if operand == 666:
                    base_str += " ; debug marker"
                elif operand >= 640 and operand < 696:
                    base_str += f" ; flag[{operand-640}]"
                elif operand in [22, 26, 27]:
                    value = self.predefined_values.get(operand, "unknown")
                    base_str += f" ; predefined value={value}"
            return f"{base_str} {nm_str}"
        else:
            
            if instr == "CALL":
                return f"{addr_str}: {instr:<8} ; will change nucleotide mapping {nm_str}"
            return f"{addr_str}: {instr} {nm_str}"
    
    def disassemble_file_dynamic(self, filename: str) -> str:
        try:
            with open(filename, 'r') as f:
                code = f.read().strip()
        except FileNotFoundError:
            return f"Error: File '{filename}' not found"
        except Exception as e:
            return f"Error reading file: {e}"
        
        instructions = self.disassemble_dynamic(code)
        
        if not instructions:
            return "No valid instructions found"
        
        
        output_lines = []
        output_lines.append("Dynamic DNA Virtual Machine Disassembly")
        output_lines.append("=" * 50)
        output_lines.append("Nucleotide mappings change after each CALL instruction")
        output_lines.append("")
        
        call_count = 0
        for addr, instr, operand_dna, operand, nm in instructions:
            if instr == "CALL":
                call_count += 1
            output_lines.append(self.format_instruction_dynamic(addr, instr, operand_dna, operand, nm, call_count))
        
        output_lines.append("")
        output_lines.append(f"Total instructions: {len(instructions)}")
        output_lines.append(f"CALL operations: {call_count}")
        
        return "\n".join(output_lines)
    
    def analyze_mapping_evolution(self, code: str) -> Dict:
        instructions = self.disassemble_dynamic(code)
        
        mapping_states = []
        call_positions = []
        
        for addr, instr, operand_dna, operand, nm in instructions:
            if instr == "CALL":
                call_positions.append(addr)
            mapping_states.append((addr, nm.copy()))
        
        return {
            'mapping_evolution': mapping_states,
            'call_positions': call_positions,
            'total_calls': len(call_positions)
        }
    
    
def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <dna_bytecode_file>")
        sys.exit(1)
    
    disassembler = DynamicDNADisassembler()
    
    print("=== DYNAMIC DISASSEMBLY ===")
    result = disassembler.disassemble_file_dynamic(sys.argv[1])
    print(result)
if __name__ == "__main__":
    main()
