+++
date = '2025-02-23T22:24:46+01:00'
draft = false
title = 'Dados'
+++
# ingehack2k25 - reverse/dados



- Write-Up Author : 4ymen

- Flag: ingehack{security_by_obscurity}

## Challenge Description:

>infinite luck in exchange for a flag
>
>[dados.apk](https://drive.google.com/file/d/1hMyVNwUrK-X0PvlPQIUjNnDt17W9gB_M/view?usp=sharing)
>
```
title: "Reverse Engineering Challenge "
difficulty: Easy
category: Reverse Engineering
platform: Android
tools: ["apktool", "smali", "Frida", "adb"]
author : "godsword"
date: "2025-02-23"
tags: ["Reverse Engineering", "Android", "Frida", "Smali", "CTF"]
---
```

# Write up  


### **Step 1: Identifying the Main Activity**
![Screenshot From 2025-02-23 17-12-51](https://hackmd.io/_uploads/BkQItTO5Jg.png)

After decompiling `dados.apk`, I checked `AndroidManifest.xml` 
to find the app's entry point. The `<activity>` tag with `<intent-filter>` containing `android.intent.action.MAIN` and `android.intent.category.LAUNCHER` revealed that the main activity is:

🔹 **`ctf.ingehack.dados.MainActivity`** (Exported: ✅)

Now, let’s analyze its code. 

### **Step 2: Analyzing `MainActivity`**


Inside `MainActivity`, I found a method that checks a condition and calls `win()` if true:

```java
public static void r(MainActivity mainActivity) {
    new Thread(new F(1, mainActivity)).start();
    MediaPlayer mediaPlayer = mainActivity.f1979K;
    if (mediaPlayer != null) {
        mediaPlayer.start();
    }
    Boolean bool = Boolean.TRUE;
    for (int i2 = 1; i2 < mainActivity.f1974F.length; i2++) {
        Object[] objArr = mainActivity.f1976H;
        if (!objArr[i2].equals(objArr[i2 - 1])) {
            bool = Boolean.FALSE;
        }
    }
    if (bool.booleanValue()) {
        mainActivity.win();
    }
}
```
This function verifies if all elements in `mainActivity.f1976H` are equal. If so, it calls `mainActivity.win()`.

### **Step 3: Patching the Condition**

To bypass the check, I modified the Smali code:

1. Opened `/smali/ctf/ingehack/MainActivity.smali`.
2. Found the condition:

   ```smali
   if-nez v0, :cond_0
   ```

3. Changed it to:

   ```smali
   if-eqz v0, :cond_0
   ```

4. Rebuilt and signed the APK (`apktool b`, then sign).

### **Step 4: Unexpected Outcome**

Upon running the patched APK, the game displayed **"GG you win !!"**, but no flag was shown. This suggests that the `win()` method might not be directly responsible for revealing the flag.
![photo_2025-02-23_16-34-20](https://hackmd.io/_uploads/By2Gep_qkl.jpg)
![photo_2025-02-23_16-34-13](https://hackmd.io/_uploads/S13QxTuckg.jpg)

**Next Step:** Let's explore other approaches to extract the flag. 


### **Step 5: Solving Dynamically with Frida**

To dynamically retrieve the flag, I used Frida:

1. **Push Frida Server to the device**
   ```sh
   adb push frida-server-16.6.6-android-x86 /data/local/tmp/
   ```
2. **Set permissions and start the server**
   ```sh
   adb shell chmod 755 /data/local/tmp/frida-server
   adb shell
   su
   /data/local/tmp/frida-server &
   ```
3. **Start the target application**
   ```sh
   adb shell am start -n ctf.ingehack.dados/.MainActivity
   ```
4. **Find the process ID (PID)**
   ```sh
   adb shell ps -A | grep ctf.ingehack.dados
   ```
5. **Create a Frida script (`solver.js`)**
   ```javascript
   Java.perform(() => {
       Java.scheduleOnMainThread(() => {
           // Get the current MainActivity instance
           Java.choose("ctf.ingehack.dados.MainActivity", {
               onMatch: function(instance) {
                   console.log("[*] Found MainActivity instance:", instance);
                   try {
                       // Call the win() method on the found instance
                       var flag = instance.win();
                       console.log("[+] Flag:", flag);
                   } catch(err) {
                       console.log("[-] Error calling win():", err);
                   }
               },
               onComplete: function() {}
           });
       });
   });
   ```
6. **Run Frida with the script**
   ```sh
   frida -U -p <PID> -l solver.js
   ```

### **Final Outcome**

```
[One::PID::2283 ]-> [*] Found MainActivity instance: ctf.ingehack.dados.MainActivity@b981555
[+] Flag: ingehack{security_by_obscurity}
```

**GG! We successfully extracted the flag! **


