+++
date = '2025-02-23T22:24:52+01:00'
draft = false
title = 'Mjsc'
+++
# ingehack2k25 - reverse/mjsc


# MJSC CTF Challenge Write-up
**Challenge: reverse/mjsc**  
**Event: IngeHack 2k25**  
**Author: 4ymen**  
**Points: 469**  
**Solves: 4**  
**Difficulty: Medium**  
**Original Challenge Author: itskarudo**

## Challenge Information
- **Category**: Reverse Engineering
- **Type**: Web/JavaScript
- **Flag**: ingehack{i_hate_js_rev_chals_they_never_have_a_new_idea}


## Initial Analysis
The challenge presented us with a web application that needed to be analyzed. The initial reconnaissance showed:

1. Web interface requiring input validation
2. Heavy use of JavaScript for validation
3. Obfuscated code to hide the validation logic

## Technical Environment
```yaml
Platform: Web
Primary Language: JavaScript
Key Components:
  - React Application
  - Obfuscated JavaScript
  - Client-side validation
```

## Investigation Process
1. **Source Code Retrieval**
   - Downloaded the website source using wget:
   ```bash
   wget -r https://mjsc.ctf.ingeniums.club/
   ```
   - Located key assets:
     - index-B2ZWtlH3.css
     - index-CEf6fI_2.js

2. **Code Analysis**
   - Identified React components and their structure
   - Located the main validation logic in obfuscated form
   - Analyzed the onSubmit handler containing the core challenge logic
## Tools
- Web Browser Developer Tools
- JavaScript Deobfuscator
- Code Analysis Tools


## Challenge Impact
This challenge effectively demonstrates:
- The importance of proper security implementation
- Why client-side-only validation is insufficient
- The limitations of code obfuscation as a security measure

# Write up  

## Initial Reconnaissance

First, I discovered the challenge website at `https://mjsc.ctf.ingeniums.club/`. The site appeared to have some form of input validation that needed to be investigated.

## Source Code Analysis

### Downloading the Source
I downloaded the website source using wget:
```bash
wget -r https://mjsc.ctf.ingeniums.club/
```

### File Structure
The downloaded files revealed two key assets:
- `index-B2ZWtlH3.css`
- `index-CEf6fI_2.js`

## Dynamic Analysis

During dynamic analysis of the website, I identified that the main validation logic was located in the `index-CEf6fI_2.js` file. The critical part of the code was in the React app's onSubmit handler, which contained obfuscated code.
## Code Investigation

### Deobfuscating the `onSubmit` Function

The obfuscated code in the `onSubmit` function needed to be deobfuscated for better understanding. Looking at the React component, I found:

From this:
![Screenshot From 2025-02-24 10-23-57](https://github.com/user-attachments/assets/64f71608-8578-424a-947a-6a3fcac7ff3b)

Using the following command:
```sh
webcrack index-CEf6fI_2.js
```

I obtained this:
![Screenshot From 2025-02-24 10-25-13](https://github.com/user-attachments/assets/f35a89da-c001-4916-b9b0-38bc1409214d)

We can see that the `onSubmit` event is calling the `p` function, which appears to be the validation function. Let's analyze it further:

![Screenshot From 2025-02-23 20-28-04](https://github.com/user-attachments/assets/3669bb81-6119-4948-aed7-e5b1d2bade3e)

Nothing looks particularly interesting except for the obfuscated code. So, let's go through it step by step:
![Screenshot From 2025-02-24 10-30-56](https://github.com/user-attachments/assets/ea668db2-fb3d-4fba-8a76-00937e0d971d)
and here is the key ....

It looks complicated, but I used AI tools for deobfuscation and found that it is implementing RSA encryption. The modulus `n` was factorized using [factordb.com](http://factordb.com/), revealing its prime factors.

With this, I was able to proceed further in decrypting the encrypted values.


```python 
from Crypto.Util.number import long_to_bytes,bytes_to_long
factors=[409 , 421 , 443 , 463 , 521 , 613 , 617 , 631 , 661 , 673 , 859 , 881 , 911 , 937 , 953 , 991 , 1021 , 1123 , 1171 , 1249 , 1321 , 1327 , 1361 , 1429 , 1531 , 1871 , 1873 , 2003 , 2081 , 2143 , 2311 , 2381 , 2731 , 2857 , 2861 , 3061 , 3169 , 3361 , 3433 , 3571 , 3697 , 4421 , 4621 , 5237 , 5281 , 6007 , 6121 , 6553 , 6733 , 7481 , 8009 , 8191 , 8581 , 8737 , 9241 , 9283 , 10711 , 12377 , 13729 , 14281 , 16831 , 17137 , 17681 , 18481 , 19891 , 20021 , 20593 , 21841 , 23563 , 24481 , 25741 , 26209 , 27847 , 29173 , 29921 , 30941 , 34273 , 36037 , 42841 , 43759 , 46411 , 48049 , 52361 , 53857 , 55441 , 63649 , 65521 , 72073 , 72931 , 74257 ,78541 ,79561 , 87517 , 92821 , 96097 , 97241 , 110881 , 116689 , 117811 , 131041 , 145861 , 148513 , 157081 , 180181 , 185641 , 209441 , 235621 , 269281 , 291721 , 314161 , 371281 , 388961 , 445537 , 471241 , 680681 , 700129 , 816817 , 1633633 , 8168161]
k=1;
for i in factors:
    k*=i-1
    
n=59857999685097510058704903303340275550835640940514904342609260821117098340506319476802302889863926430165796687108736694628663794024203081690831548926936527743286188479060985861546093711311571900661759884274719541236402441770905441176260283697893506556009435089259190308034118717196693029323272007089714272903225216389846915864612112381878100108428287917605430965442572234711074146363466926780699151173555904751392997928289187479977403795442182731620805949932616667193358004913424246140299423521
pt=9552250522031949421638862596466028874959664135990378944930610649050829114580816653549121561543414280914915955024423028045246147975154695636106060938335299887833399513605532232339992834555678292389803487517198475313799474137878912299409679963542771170996276018758394611416081529116162976136562129480128004033192434211594290655366631087302510792719773367480622157400456815223142391198477030085034818278773050995985562380964819034466087156010585672758629818663474812348343052593843066985508176737;
# print(long_to_bytes(pt))
e=0x10001;

def decrypt_rsa(ct, n, e):    

    phi = k;

    # Calculate private key d
    d = pow(e,-1,phi)

    # Decrypt ciphertext
    pt = pow(ct, d, n)
    return long_to_bytes(pt)
print(plaintext)

# Decrypt the given ciphertext
plaintext = decrypt_rsa(pt, n, e)
```

and finally gg :
```➜  mjsc.ctf.ingeniums.club python ~/sol.py 
b'ingehack{i_hate_js_rev_chals_they_never_have_a_new_idea}'```



## Credit
Original challenge created by itskarudo for IngeHack 2k25
Write-up authored by 4ymen
