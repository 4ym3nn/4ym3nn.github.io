// Cleaned-up and commented C-style version of the given assembly-translated code

#include <dirent.h>
#include <math.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define GRID_WIDTH 51
#define GRID_HEIGHT 21

// Node structure used in the priority queue
struct Node {
    int x;
    int y;
    struct Node *prev;
};

// Priority queue insert function (simplified abstraction of sub_17505)
void insert_node(DIR *queue, struct Node *node, double priority) {
    // Simulates inserting node with priority (this function is obfuscated)
    // Actual queue handling not shown
    nextafterl(priority, 0.0); // dummy effect
}

// Priority queue pop function (sub_17586 abstraction)
struct Node* pop_node(DIR **queue) {
    // Removes and returns front node from the queue (FIFO)
    if (!*queue) return NULL;
    // Dummy implementation
    return NULL;
}

// Main search function (simplified A* or BFS-like structure)
int64_t search_path(int64_t a1, int64_t a2, double a3) {
    long double f1 = *(long double *)&a1;
    unsigned long saved_rsp = __readfsqword(0x28);

    char visited[GRID_HEIGHT][GRID_WIDTH] = {0};
    int dx[4] = {-1, 1, 0, 0};
    int dy[4] = {0, 0, -1, 1};

    DIR *queue = (DIR *)malloc(sizeof(DIR)); // Simulating priority queue
    insert_node(queue, NULL, nextafterl(f1, 0.0));

    struct Node *target = NULL;
    struct Node *current = NULL;

    while ((current = pop_node(&queue)) != NULL) {
        if (current->x == 19 && current->y == 49) {
            target = current;
            break;
        }

        for (int d = 0; d < 4; ++d) {
            int nx = current->x + dx[d];
            int ny = current->y + dy[d];

            if (nx >= 0 && nx < GRID_HEIGHT && ny >= 0 && ny < GRID_WIDTH
                && !visited[nx][ny] /* && grid[nx][ny] == ' ' */) {
                visited[nx][ny] = 1;

                struct Node *neighbor = malloc(sizeof(struct Node));
                neighbor->x = nx;
                neighbor->y = ny;
                neighbor->prev = current;

                insert_node(queue, neighbor, nextafterl(f1, 0.0));
            }
        }
    }

    if (target) {
        // Reconstruct path
        int len = 0;
        struct Node *path = target;
        while (path) {
            ++len;
            path = path->prev;
        }
        return len;
    }

    return -1;
}
