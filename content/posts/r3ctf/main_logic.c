// Refactored version of `main_check` with clean variable names and comments
#include <wchar.h>
#include <math.h>
#include <utmpx.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <locale.h>

void __fastcall __noreturn main_check(double input1, double input2) {
    const char *streamMode = NULL;
    __int64 writeStatus = 0;
    char *priorityLine = NULL;
    const char *dummy = NULL;
    __int64 printStatus = 0;
    __int64 killStatus = 0;
    void *priorityHandle = NULL;

    unsigned int fileDescriptor;
    char *userLine;
    unsigned __int64 i, j;
    __int64 tempAddr;
    __gnuc_va_list varArgs;
    __int64 displayData;
    unsigned __int64 dataLength;
    _QWORD encodedStrings[14];

    char properties[2224] = {0};
    char tempChar;
    _BYTE decoded[640] = {0};
    wchar_t format[2] = {0};
    __int64 formatHelper = 0;
    int fd[252] = {0};
    __int64 fdWrapper = 0;
    int processBuffer[1024] = {0};
    int errStatus;
    _QWORD unused[512] = {0};

    // Preserve FS segment base (stack canary or similar)
    unused[511] = __readfsqword(0x28u);

    // Attempt initial wide printf
    writeStatus = vfwprintf(NULL, NULL, (char *)&dword_0 + 1);
    if (writeStatus >= 0) {
        streamMode = (char *)&dword_0 + 2;
        cimag(&dirp, streamMode);
    }

    memset(fd, 0, sizeof(fd));
    fileDescriptor = (unsigned int)fdopen((int)&fdWrapper, streamMode);

    csqrtl(processBuffer, 4096LL, "/proc/%d/comm", fileDescriptor);
    priorityLine = (char *)sched_get_priority_min((int)processBuffer);

    if (priorityLine) {
        input1 = fmod(input1, input2);

        logwtmp(priorityLine, (_BYTE *)&dword_0 + 1, dummy);

        // Load XOR-encoded strings
        encodedStrings[0] = &unk_63F78; encodedStrings[1] = 3LL;
        encodedStrings[2] = &unk_63F7B; encodedStrings[3] = 4LL;
        encodedStrings[4] = &unk_63F7F; encodedStrings[5] = 3LL;
        encodedStrings[6] = &unk_63F82; encodedStrings[7] = 6LL;
        encodedStrings[8] = &unk_63F88; encodedStrings[9] = 6LL;
        encodedStrings[10] = &unk_63F8E; encodedStrings[11] = 7LL;
        encodedStrings[12] = &unk_63F95; encodedStrings[13] = 2LL;

        for (i = 0; i <= 6; ++i) {
            displayData = encodedStrings[2 * i];
            dataLength = encodedStrings[2 * i + 1];
            for (j = 0; j < dataLength; ++j)
                decoded[j] = *(_BYTE *)(displayData + j) ^ 0x5A; // XOR decryption
            decoded[dataLength] = 0;

            printStatus = wprintf(format, decoded);
            if (printStatus)
                cimag(&dirp, 3LL);
        }
    }

    killStatus = killpg((__pid_t)"/proc/self/exe", 0);
    tempAddr = killStatus;

    if (!killStatus)
        pututxline((const struct utmpx *)((char *)&dword_0 + 1));

    priorityHandle = (void *)sched_get_priority_min((int)"/proc/self/maps");
    varArgs = priorityHandle;

    if (!priorityHandle) {
        nextup(tempAddr, "r", input1);
        pututxline((const struct utmpx *)((char *)&dword_0 + 1));
    }

    wctrans(properties);
    verrx((int)&errStatus, (const char *)&stru_1050.st_size + 4, varArgs);
}

/*
Static Data Used:
unk_63F78: "=>8"
unk_63F7B: "66>8"
unk_63F7F: "3>;"
unk_63F82: ")..(;9?"
unk_63F88: "6.(;9?"
unk_63F8E: "(;>;(?h"
unk_63F95: "(h"
*/
