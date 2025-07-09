/* Summary of what the core code is doing (ignoring irrelevant calls like _logwtmp, _nextup, etc.): */

/*
The main chunk of logic is located in `sub_17712`, which appears to be performing operations on a 2D grid.
Here's what it's doing:

- It creates and updates a grid of 21x51 (most likely representing terminal or visual map data).
- It uses characters `#` and `' '` (space) to mark positions in the grid.
- It uses a disjoint-set / union-find data structure to track connections.
- Based on some conditions, it merges nodes in the grid.
- It eventually flattens/updates values based on connected components.
*/

__int64 __fastcall sub_17712(__int64 grid_base, double val) {
    // grid_base is probably pointing to memory representing the grid (21x51)
    // val is some floating-point value used in logb

    // Logb and nextafterl do some FP operations. Likely obfuscation or dummy logic
    double v2 = logb(val);
    long double v3 = nextafterl(...);

    // fd appears to be a dynamically allocated array (could be malloced elsewhere) used for storing edges
    int fd[2];

    *((_QWORD *)&v13 + 1) = grid_base;
    *((_QWORD *)&v17 + 1) = 0x100000000; // This sets the high dword of v17 to 0

    // Outer loop: for each row (up to 20)
    while ( SHIDWORD(v17) <= 19 ) {
        // Inner loop: for each column (1 to 49)
        for (i = 1; i <= 49; ++i) {
            // Determine character: space or hash
            if ((i & 1) != 0 && (BYTE12(v17) & 1) != 0)
                v5 = ' ';
            else
                v5 = '#';

            // Store character in the grid at position [row][column]
            *(_BYTE *)(grid_base + 51 * SHIDWORD(v17) + i) = v5;

            // If even column and odd row: create an edge from (row, col)
            if ((i & 1) == 0 && SHIDWORD(v17) % 2 == 1) {
                int index = DWORD2(v17)++;
                _DWORD* edge = (_DWORD *)(8LL * index + fd);
                edge[0] = HIDWORD(v17); // row
                edge[1] = i;            // col
            }

            // If even row and odd column: another kind of edge
            if ((BYTE12(v17) & 1) == 0 && i % 2 == 1) {
                int index = DWORD2(v17)++;
                _DWORD* edge = (_DWORD *)(8LL * index + fd);
                edge[0] = HIDWORD(v17);
                edge[1] = i;
            }
        }
        ++HIDWORD(v17); // next row
    }

    // Use tcsendbreak() and some FP operations – irrelevant for main logic

    // Fill array v27 with 250 entries, just values 0..249 (maybe used for DSU or mapping)
    for (j = 0; j < 250; ++j)
        *(_DWORD *)(v10 + 4LL * j) = j;

    // Now for each collected edge, perform Union-Find on 1D index mappings
    for (k = 0; k < v18; ++k) {
        int row = *(fd + 2*k);
        int col = *(fd + 2*k + 1);

        if (col is odd) {
            v22 = 25 * ((row - 1)/2) + col / 2;
            v23 = 25 * ((row + 1)/2) + col / 2;
        } else {
            v22 = 25 * (row / 2) + (col - 1)/2;
            v23 = 25 * (row / 2) + (col + 1)/2;
        }

        if (find(v22) != find(v23)) {
            union(v22, v23);
            grid[row][col] = ' '; // remove wall
        }
    }

    // Final return, likely dummy or used for further calls
}

/* Helper: sub_175FB implements FIND for union-find (with path compression) */
__int64 __fastcall sub_175FB(unsigned int a1, __int64 base) {
    if (a1 == *(int *)(base + 4 * a1)) return a1;
    int* ptr = (int *)(base + 4 * a1);
    *ptr = sub_175FB(*ptr, base);
    return *ptr;
}

/* Helper: sub_17673 implements UNION */
__int64 __fastcall sub_17673(unsigned int a1, unsigned int a2, __int64 base) {
    int root1 = sub_175FB(a1, base);
    int root2 = sub_175FB(a2, base);
    if (root1 != root2)
        *(int *)(base + 4 * root2) = root1;
    return root1;
}
