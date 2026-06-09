+++
date = '2025-06-17T22:29:05+01:00'
draft = false
title = 'brainrot'
+++
# tamu2025 - rev Challenge: brainrot

## Description

This challenge involves reverse engineering a custom "brain" simulation to extract a flag. The brain operates on a set of neurons and performs transformations using a combination of hashing, rotation, and matrix operations. The goal is to deduce the input that produces the required outputs.

## Solution

The solution involves implementing the brain simulation in Python and using the Z3 solver to reverse the transformations. Below is the code and explanation:

### Brain Class

```python
import hashlib
from z3 import *

class Brain:
    def __init__(self, neurons):
        self.neurons = neurons
        self.thought_size = 10
        
    def brainstem(self):
        return hashlib.sha256(",".join(str(x) for x in sum(self.neurons, [])).encode()).hexdigest()
        
    def rot(self, data):
        for i in range(len(data)):
            self.neurons[(3 * i + 7) % self.thought_size][(9 * i + 3) % self.thought_size] ^= data[i]
            
    def think(self, data):
        thought = [0] * self.thought_size
        for i in range(self.thought_size):
            thought[i] = sum(self.neurons[i][j] * data[j] for j in range(self.thought_size))
        self.neurons[:-1] = self.neurons[1:]
        self.neurons[-1] = thought
        return thought
```

### Initialization

The brain is initialized with the following neuron values:

```python
healthy_brain = [
    [71, 101, 18, 37, 41, 69, 80, 28, 23, 48], 
    [35, 32, 44, 24, 27, 20, 34, 58, 24, 9], 
    [73, 29, 37, 94, 27, 58, 104, 65, 116, 44], 
    [26, 83, 77, 116, 9, 96, 111, 118, 52, 62], 
    [100, 15, 119, 53, 59, 34, 38, 68, 104, 110], 
    [51, 1, 54, 62, 56, 120, 4, 80, 60, 120], 
    [125, 92, 95, 98, 97, 110, 93, 33, 128, 93], 
    [70, 23, 123, 40, 75, 23, 104, 73, 52, 6], 
    [14, 11, 99, 16, 124, 52, 14, 73, 47, 66], 
    [128, 11, 49, 111, 64, 108, 14, 66, 128, 101]
]
```

The `brainrot` data is a reversed string:

```python
brainrot = b"gnilretskdi ,coffee ,ymotobol ,amenic etulosba ,oihO ni ylno ,oihO ,pac eht ..."[::-1]
```

### Solving for the Flag

The required thoughts for each chunk are provided:

```python
required_thoughts = [
    [59477, 41138, 59835, 73146, 77483, 59302, 102788, 67692, 62102, 85259],
    [40039, 59831, 72802, 77436, 57296, 101868, 69319, 59980, 84518, 73579466],
    [59783, 73251, 76964, 58066, 101937, 68220, 59723, 85312, 73537261, 7793081533],
    [71678, 77955, 59011, 102453, 66381, 60215, 86367, 74176247, 9263142620, 982652150581],
]
```

Using Z3, we solve for each 10-byte chunk of the flag:

```python
flag = bytearray(40)

for chunk_index in range(4):
    current_brain = Brain([row[:] for row in brain.neurons])
    solver = Solver()
    flag_chunk = [BitVec(f'flag_{chunk_index}_{i}', 8) for i in range(10)]
    
    for i in range(10):
        solver.add(flag_chunk[i] >= 32)
        solver.add(flag_chunk[i] <= 126)
    
    expected_thought = required_thoughts[chunk_index]
    thought = [0] * current_brain.thought_size
    
    for i in range(current_brain.thought_size):
        thought_expr = 0
        for j in range(current_brain.thought_size):
            thought_expr += current_brain.neurons[i][j] * flag_chunk[j]
        solver.add(thought_expr == expected_thought[i])
    
    if solver.check() == sat:
        model = solver.model()
        for i in range(10):
            flag[chunk_index * 10 + i] = model[flag_chunk[i]].as_long()
        brain.think([model[flag_chunk[i]].as_long() for i in range(10)])
    else:
        print(f"No solution found for chunk {chunk_index}")
        exit(1)

solved_flag = bytes(flag)
print(f"Found flag: {solved_flag.decode()}")
```

### Verification

The solution is verified by reapplying the transformations:

```python
brain = Brain([row[:] for row in healthy_brain])
brain.rot(brainrot)

failed_to_think = False
for i in range(0, len(solved_flag), 10):
    thought = brain.think(solved_flag[i:i + 10])
    if thought != required_thoughts[i//10]:
        failed_to_think = True
        print(f"Verification failed for chunk {i//10}")

if failed_to_think or brain.brainstem() != "4fe4bdc54342d22189d129d291d4fa23da12f22a45bca01e75a1f0e57588bf16":
    print("Solution is incorrect")
else:
    print("Solution verified! Flag is correct")
```

### Flag

The extracted flag is:

```
gigem{whats_up_my_fellow_skibidi_sigmas}
```
