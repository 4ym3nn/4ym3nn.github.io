+++
date = '2025-07-28T19:41:23+01:00'
draft = false
title = 'Emulator'
hideToc = false
+++

# WorldWideCTF 2025: rev/Emulator

# Team : TroJeun


**Challenge Details:**
- Points: 500
- Category: Mobile
- Author: em07robot

## Description
"Inside an emulator, reality bends - only shadows find the hidden truth."

We are provided with a large zstd compressed file:

```bash
└─$ zstd -d chall_dist.zst                                                           
chall_dist.zst      : 10778972160 bytes  
```

## Initial Analysis

After decompression, we get an Android Virtual Device (AVD) directory structure:

```bash
└─$ tar -tvf chall_dist
drwxrwxr-x em07robot/em07robot 0 2025-07-10 17:16 chall.avd/
-rw-r--r-- em07robot/em07robot 69206016 2025-07-10 17:16 chall.avd/cache.img
-rw-r--r-- em07robot/em07robot  1966149 2025-07-10 17:16 chall.avd/encryptionkey.img.qcow2
-rw------- em07robot/em07robot        0 2025-07-10 17:16 chall.avd/bootcompleted.ini
-rw-rw-r-- em07robot/em07robot     1245 2025-07-10 17:16 chall.avd/config.ini
-rw-rw-r-- em07robot/em07robot       18 2025-07-10 17:16 chall.avd/quickbootChoice.ini
-rw-rw-r-- em07robot/em07robot     4227 2025-07-10 17:16 chall.avd/hardware-qemu.ini
drwxr--r-- em07robot/em07robot        0 2025-07-10 17:16 chall.avd/snapshots/
<..SNIP..>
-rw-rw-r-- em07robot/em07robot        116 2025-07-10 17:16 chall.ini
-rw-rw-r-- em07robot/em07robot  939493689 2025-07-10 17:10 chall.zst.bk
-rw-rw-r-- em07robot/em07robot         76 2025-07-10 17:13 chal
```

This appears to be an Android emulator reverse engineering challenge. The first step is to set up and run the emulator using the [Android Command Line Tools](https://developer.android.com/tools).

## Setting Up the Emulator

To run the emulator, we need to check the `chall.ini` configuration file:

```bash
➜  mob cat chall.ini 
avd.ini.encoding=UTF-8
path=/home/em07robot/.config/.android/avd/chall.avd
path.rel=avd/chall.avd
target=android-30
```

**Important:** We must update the absolute path in the `.ini` file to match our local system, while keeping the relative path (`path.rel`) unchanged.

Starting the emulator:

```bash
➜  ~ emulator -avd chall \
  -no-snapshot-load \
  -gpu off \
  -skin pixel_4a \
  -skindir "$ANDROID_SDK_ROOT/skins"
```

## Android System Structure

The emulator shows a rooted Pixel 4a device. Key Android directories for analysis:

```bash
chall.avd/
├── userdata.img          <- Contains user-installed apps (APK data, app data)
├── system.img            <- Contains the base Android OS and pre-installed system apps
├── vendor.img            <- May contain vendor-specific apps
```

## Getting Shell Access

After running the emulator, we can access the Android shell:

```bash
adb shell
generic_x86_64_arm64:/ $ ls
acct      apex  bugreports  config  data         debug_ramdisk  dev  init             linkerconfig  metadata  odm  proc     res     storage  system      vendor
adb_keys  bin   cache       d       data_mirror  default.prop   etc  init.environ.rc  lost+found    mnt       oem  product  sdcard  sys      system_ext
generic_x86_64_arm64:/ $ su
generic_x86_64_arm64:/ #
```

Since we have root access, we can explore the system. All installed apps are located in `/data/data/`, so we check:

```bash
ls /data/data
```

## Finding the Challenge App

I discovered `com.em07robot.chall` - this is our target application! I extracted the APK for local analysis:

```bash
adb pull /data/app/com.em07robot.chall-1/base.apk
```

## Code Analysis

### MainActivity Class

After analyzing the APK, I found the main logic in `MainActivity.java`:

```java
package com.em07robot.chall;

import V0.a;
import android.content.res.Resources;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
// ... other imports

public final class MainActivity extends i {
    public static final /* synthetic */ int f1846u = 0;

    @Override // b.i, android.app.Activity
    public final void onCreate(Bundle bundle) {
        int i2 = 0;
        super.onCreate(bundle);
        
        // UI setup code (setting up window, decor view, status bar, etc.)
        int i3 = j.f1129a;
        u uVar = u.f1147d;
        v vVar = new v(0, 0, uVar);
        v vVar2 = new v(j.f1129a, j.f1130b, uVar);
        View decorView = getWindow().getDecorView();
        
        // Dynamic handler selection based on Android SDK version
        int i4 = Build.VERSION.SDK_INT;
        k nVar = i4 >= 30 ? new n() : i4 >= 29 ? new m() : i4 >= 28 ? new l() : new k();
        
        // Configure window settings
        Window window = getWindow();
        nVar.b(vVar, vVar2, window, decorView, booleanValue, booleanValue2);
        Window window2 = getWindow();
        nVar.a(window2);
        
        // **KEY LINE:** Launch security check thread
        new Thread(new a(this, i2)).start();
    }
}
```

**MainActivity's primary functions:**
1. Setting up the UI window (decor view, status bar, etc.)
2. Dynamically selecting a handler (k, l, m, or n) based on the Android SDK version
3. **Most importantly:** Launching a new thread running a method from `V0.a`

### Security Check Logic (V0.a class)

The core security logic is in the `V0.a` class:

```java
package V0;

// ... imports

public final /* synthetic */ class a implements Runnable {
    public final /* synthetic */ int f844c;
    public final /* synthetic */ MainActivity f845d;

    @Override // java.lang.Runnable
    public final void run() {
        String str;
        switch (this.f844c) {
            case SecurityConfig.$stable /* 0 */:
                // Performance timing
                long elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos();
                final MainActivity mainActivity = this.f845d;
                
                // **CRITICAL:** Perform security checks
                final SecurityCheckResult performSecurityChecks = new SecurityChecker(mainActivity).performSecurityChecks();
                
                // **FIRST CHECK:** Invalid AVD detection (kills app immediately)
                if (performSecurityChecks.getIssues().contains("Invalid AVD")) {
                    Logger.INSTANCE.logError("Invalid AVD");
                    mainActivity.finish();
                    Process.killProcess(Process.myPid());
                    return;
                }
                
                // **MAIN SECURITY CHECKS:** Multiple anti-tampering measures
                if (performSecurityChecks.getIssues().contains("Root detected") || 
                    performSecurityChecks.getIssues().contains("Debugger detected") || 
                    performSecurityChecks.getIssues().contains("Native security breach") || 
                    performSecurityChecks.getIssues().contains("Frida detected") || 
                    performSecurityChecks.getIssues().contains("Invalid AVD") || 
                    performSecurityChecks.getIssues().contains("QEMU pipe detected")) {
                    
                    str = "SECURITY BREACH";
                } else {
                    // **SUCCESS PATH:** Get the flag from native code
                    str = NativeBridge.INSTANCE.getFlag();
                    Logger.INSTANCE.logInfo("Flag decrypted successfully: " + str);
                }
                
                // Display result in UI
                final String str2 = str;
                final long elapsedRealtimeNanos2 = (SystemClock.elapsedRealtimeNanos() - elapsedRealtimeNanos) / 1000000;
                
                // Update UI on main thread
                mainActivity.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        // UI update code...
                    }
                });
                return;
        }
    }
}
```

## Security Checks Analysis

The application performs multiple security checks:

1. **Invalid AVD Detection:** If detected, immediately kills the app
2. **Root Detection:** Checks if the device is rooted
3. **Debugger Detection:** Looks for attached debuggers
4. **Frida Detection:** Detects dynamic instrumentation framework
5. **Native Security Breach:** Checks for native-level tampering
6. **QEMU Pipe Detection:** Detects if running in QEMU emulator

**Logic Flow:**
- If ANY security check fails → Display "SECURITY BREACH"
- If ALL security checks pass → Call `NativeBridge.getFlag()` to get the actual flag
- 
so i just wrote a frida script to pass the 5 checks but i get this which wasn't expected
```js
Java.perform(function () {
    console.log("[*] performSecurityChecks() called - bypassing security checks");

    const SecurityChecker = Java.use("com.em07robot.chall.security.SecurityChecker");
    const SecurityCheckResult = Java.use("com.em07robot.chall.security.SecurityCheckResult");
    const ArrayList = Java.use("java.util.ArrayList");

    SecurityChecker.performSecurityChecks.implementation = function () {
        console.log("[+] Hooked performSecurityChecks");

        // Create empty list
        const emptyIssues = ArrayList.$new();

        // Call constructor with (int, List)
        const fakeResult = SecurityCheckResult.$new(0, emptyIssues);
        return fakeResult;
    };

    const NativeBridge = Java.use("com.em07robot.chall.NativeBridge");
    NativeBridge.getFlag.implementation = function () {
        const flag = this.getFlag();
        console.log("[+] NativeBridge.getFlag() called! Flag =", flag);
        return flag;
    };
});
```

When this hook is triggered, it prints that

```bash
(frida-env) ➜  patch frida -U -f com.em07robot.chall -l hook.js
     ____
    / _  |   Frida 17.0.5 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Android Emulator 5554 (id=emulator-5554)
Spawned `com.em07robot.chall`. Resuming main thread!                    
[Android Emulator 5554::com.em07robot.chall ]-> [*] performSecurityChecks() called - bypassing security checks
[+] Hooked performSecurityChecks
[+] NativeBridge.getFlag() called! Flag = DECRYPTION_ERROR
[Android Emulator 5554::com.em07robot.chall ]->                                              
[Android Emulator 5554::com.em07robot.chall ]->
```

### Investigating getFlag() and the DECRYPTION_ERROR

After hooking the method `com.em07robot.chall.NativeBridge.getFlag()`, we observed the following output:

`[+] NativeBridge.getFlag() called! Flag = DECRYPTION_ERROR`

This indicates that the method was called successfully, but the returned value was not the expected flag — instead, it was the error message DECRYPTION_ERROR. To understand why, we need to investigate where the getFlag() method is actually implemented.
Locating the Native Implementation of getFlag()

Since getFlag() is defined in a Java class (NativeBridge) but implemented as a native method, its logic resides in one of the app’s native libraries (.so files). These are compiled binaries, typically written in C or C++.

#### Step 1: Identify Which Library Contains getFlag()

To find where the native code for getFlag() is located, we use the strings utility to scan the native libraries for any symbol containing the word "Flag":
```bash
strings base/lib/x86_64/libhyperguard.so | grep "Flag"
```
Output:
```bash
Java_com_em07robot_chall_NativeBridge_getFlag
```
This confirms that the method NativeBridge.getFlag() is implemented in the libhyperguard.so library.

The symbol:

`Java_com_em07robot_chall_NativeBridge_getFlag`

follows the JNI naming convention, which maps to:

`com.em07robot.chall.NativeBridge.getFlag()`

### Next Step: Decompiling libhyperguard.so

Now that we’ve confirmed the native implementation is inside libhyperguard.so, the next step is to reverse engineer this library to understand why DECRYPTION_ERROR is being returned. We’ll need to open this binary in tools like Ghidra, IDA Pro, or Radare2, and analyze the logic inside Java_com_em07robot_chall_NativeBridge_getFlag.
## Native Bridge Analysis

The flag retrieval happens in native code:

```c
__int64 __fastcall Java_com_em07robot_chall_NativeBridge_getFlag(__int64 a1)
{
  char *v1; // rbx
  __int64 (__fastcall *v2)(__int64, const char *); // rcx
  __int64 v3; // r14

  v1 = (char *)decrypt_flag(a1);
  v2 = *(__int64 (__fastcall **)(__int64, const char *))(*(_QWORD *)a1 + 1336LL);
  if ( !v1 )
    return v2(a1, "DECRYPTION_ERROR");
  v3 = v2(a1, v1);
  free(v1);
  return v3;
}
```
so it simply calls the `decrypt_flag()`
but why we are falling here 
```
if ( !v1 )
    return v2(a1, "DECRYPTION_ERROR");
```
### Flag Decryption Process

The `decrypt_flag()` function performs multiple layers of decryption and verification:

```c
_BYTE *decrypt_flag()
{
  // Initial security checks
  if ( (unsigned __int8)sub_ED3F0() || (unsigned __int8)sub_ED570() )
    return 0LL;
    
  // Check for QEMU-specific files
  if ( access("/dev/qemu_pipe", 0) || access("/dev/qemu_trace", 0) )
    return 0LL;
    
  // Additional native security checks
  if ( (unsigned __int8)sub_ED6B0() )
    return 0LL;
    
  // **CRITICAL:** Verify specific Android build properties
  if ( !(unsigned __int8)sub_ED890("ro.build.fingerprint", "google/sdk_gphone_x86_64/generic_x86_64_arm64:11/RSR1.240422.006/12134477:userdebug/dev-keys") ||
       !(unsigned __int8)sub_ED890("ro.hardware", "ranchu") ||
       !(unsigned __int8)sub_ED890("ro.product.model", "sdk_gphone_x86_64") ||
       !(unsigned __int8)sub_ED890("ro.product.device", "generic_x86_64_arm64") )
  {
    return 0LL;
  }
  
  // If all checks pass, perform multi-layer decryption:
  // 1. Initialize OpenSSL crypto
  // 2. Generate key material
  // 3. Multiple rounds of:
  //    - ChaCha20 decryption
  //    - RC4 decryption  
  //    - AES-CBC decryption
  //    - XOR operations
  
  // Final decrypted flag is returned
}
```
# Anti-Analysis Functions Documentation

## Overview

Two C functions that implement **anti-debugging and anti-analysis checks**:

```c
if ( (unsigned __int8)sub_ED3F0() || (unsigned __int8)sub_ED570() )
    return 0LL; // Exit if analysis tools detected
```

If either function returns `true`, the program terminates.

---

## Function 1: `sub_ED3F0()` - Frida Detection

**Purpose:** Detects Frida dynamic instrumentation framework

### Detection Methods

#### Port Scanning
Attempts to connect to localhost on Frida ports:

| Signed Int16 | Actual Port | Hex |
|--------------|-------------|-----|
| -23959 | 41759 | 0xA31F |
| -23703 | 41833 | 0xA369 |
| -22679 | 42373 | 0xA585 |
| -18398 | 47138 | 0xB822 |
| 3879 | 27015 | 0x6977 |

#### File System Check
- Checks for: `/data/local/tmp/frida-server`

### Return Logic
- **Returns `true`**: If any port connection succeeds OR Frida server file exists
- **Returns `false`**: If all checks fail

---

## Function 2: `sub_ED570()` - Debugger Detection

**Purpose:** Detects if process is being debugged or traced

### Detection Methods

#### 1. TracerPid Check
- Reads `/proc/self/status`
- Looks for `TracerPid:` field
- If TracerPid > 0 → process is being traced

#### 2. Ptrace Self-Attach
- Calls `ptrace(PTRACE_TRACEME, 0, 0, 0)`
- If returns -1 → already being traced by debugger

#### 3. Network Test
- Attempts connection to localhost:16962 (0x4242)
- May detect sandboxed environments

### Return Logic
- **Returns `true`**: If TracerPid > 0 OR ptrace fails OR network connection succeeds
- **Returns `false`**: If no debugging detected

---

## Port Number Conversion

Negative numbers represent ports in little-endian signed 16-bit format:

```c
*(_WORD *)buf.sa_data = -23959;  // Actually sets port to 41759
```

**Formula:** 
- Negative signed int16 → Add 65536 to get actual port
- Example: -23959 + 65536 = 41577 (incorrect)
- Actually: 0xA31F = 41759 (correct interpretation)

---


### Bypassing anti-debugging methods

- **`sub_ED3F0()`**: Anti-Frida (dynamic analysis prevention)
- **`sub_ED570()`**: Anti-debugger (static/dynamic debugging prevention)

so i just patch them to look like this  
```c
sub_ED570() {
return 0
}
```

```c
sub_ED5F0() {
return 0
}
```


To force the function to always return zero, you can patch it by adding this instruction after the call:

`xor al, al    ; sets al = 0`

### Bypassing Emulator Detection via access() Checks

Originally, the application performed checks on the existence of certain QEMU-specific files using the following code:
```c
if ( access("/dev/qemu_pipe", 0) || access("/dev/qemu_trace", 0) )
    return 0LL;
```
This means if either `/dev/qemu_pipe` or `/dev/qemu_trace` exists, the application will immediately terminate or block further execution, indicating detection of an emulator environment.

To bypass this detection, we patched the code to remove the conditional logic entirely, effectively neutralizing the check. After patching, the relevant code looks like this:
```c
sub_ED3F0();
sub_ED570();
access("/dev/qemu_pipe", 0);
access("/dev/qemu_trace", 0);
```

By eliminating the conditional branches (e.g., jz, jne, etc.), the access() calls still execute but their results are ignored. This allows execution to continue regardless of whether those files exist, successfully bypassing the emulator detection.

### Ignoring Build Property Checks

The following block of code verifies whether the device's build properties match specific values typically associated with a particular emulator profile:
```c
if (
    !(unsigned __int8)sub_ED890("ro.build.fingerprint", "google/sdk_gphone_x86_64/generic_x86_64_arm64:11/RSR1.240422.006/12134477:userdebug/dev-keys") ||
    !(unsigned __int8)sub_ED890("ro.hardware", "ranchu") ||
    !(unsigned __int8)sub_ED890("ro.product.model", "sdk_gphone_x86_64") ||
    !(unsigned __int8)sub_ED890("ro.product.device", "generic_x86_64_arm64")
)
```

This is meant to ensure that the app is running in a specific emulator environment by comparing the values returned from getprop with hardcoded strings.

However, since I had already checked my emulator environment using the following adb commands:
```shell
adb shell getprop ro.build.fingerprint
# → google/sdk_gphone_x86_64/generic_x86_64_arm64:11/RSR1.240422.006/12134477:userdebug/dev-keys

adb shell getprop ro.hardware
# → ranchu

adb shell getprop ro.product.model
# → sdk_gphone_x86_64

adb shell getprop ro.product.device
# → generic_x86_64_arm64
```

And confirmed that all values match exactly what the function is checking for, there's no need to patch or modify this part of the code. The emulator already satisfies all these conditions, so these checks will naturally pass without any interference.

At this point, we can be confident that the execution flow reaches the cryptographic decryption routine

```
  v57[0].m128i_i64[0] = __readfsqword(0x28u);
  sub_ED3F0();
  sub_ED570();
  access("/dev/qemu_pipe", 0);
  access("/dev/qemu_trace", 0);
  sub_ED6B0();
  v2 = sub_ED890(
         "ro.build.fingerprint",
         "google/sdk_gphone_x86_64/generic_x86_64_arm64:11/RSR1.240422.006/12134477:userdebug/dev-keys");
  if ( !v2
    || !(unsigned __int8)sub_ED890("ro.hardware", "ranchu")
    || !(unsigned __int8)sub_ED890("ro.product.model", "sdk_gphone_x86_64") )
  {
    return 0LL;
  }
  v0 = 0LL;
  if ( (unsigned __int8)sub_ED890("ro.product.device", "generic_x86_64_arm64") )
  {
    OPENSSL_init_crypto(12LL, 0LL);
    OPENSSL_init_crypto(2LL, 0LL);

```
### Results :

so running the script 

```bash
(frida-env) ➜  patch frida -U -f com.em07robot.chall -l hook.js
     ____
    / _  |   Frida 17.0.5 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Android Emulator 5554 (id=emulator-5554)
Spawned `com.em07robot.chall`. Resuming main thread!                    
[Android Emulator 5554::com.em07robot.chall ]-> [*] performSecurityChecks() called - bypassing security checks
[+] Hooked performSecurityChecks
[+] NativeBridge.getFlag() called! Flag = wwf{wh3n_th3_m1nd_1s_fr33_th3_b@rri3rs_0f_th3_syst3m_1nt0_s1l3nc3} 
[Android Emulator 5554::com.em07robot.chall ]->                                              
[Android Emulator 5554::com.em07robot.chall ]->
```



