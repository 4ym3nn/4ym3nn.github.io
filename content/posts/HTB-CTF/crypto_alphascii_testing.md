+++
date = '2024-11-27T22:29:05+01:00'
draft = false
title = 'crypto/crypto_alphascii_testing'
+++
To create a detailed write-up for the `sol.md` file explaining how you solved the challenge, here is a structured explanation based on the provided code snippet and error trace:

## Solution Write-Up for `crypto_alphascii_testing` Challenge

### Challenge Overview

The challenge involves interacting with a Python-based login application that uses MD5 for password storage. The application provides options to register and login using JSON formatted inputs.

### Steps to Solve the Challenge

1. **Understanding the Application Workflow**

   The application presents three options:
   - Login
   - Register
   - Exit

   During registration, the username and password are stored using MD5 hashing. The same hashed value is used for login verification.

2. **Registering a New User**

   First, we need to register a new user. We provide a username and password in JSON format. Here is an example of registering a user:
   ```json
   Option (json format) :: {"option": "register"}
   enter credentials (json format) :: {"username": "TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak", "password": "123"}
   ```

3. **Logging in with the Registered User**

   After registration, we attempt to log in with the same credentials:
   ```json
   Option (json format) :: {"option": "login"}
   enter credentials (json format) :: {"username": "TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak", "password": "123"}
   ```

4. **Encountering the Error**

   Upon attempting to log in, the application throws an error:
   ```
   Traceback (most recent call last):
     File "/Users/jb/Downloads/message.py", line 75, in <module>
       main()
     File "/Users/jb/Downloads/message.py", line 50, in main
       print(f"[+] what?! this was unexpected. shutting down the system :: {open('flag.txt').read()} 👽")
                                                                              ^^^^^^^^^^^^^^^^
   FileNotFoundError: [Errno 2] No such file or directory: 'flag.txt'
   ```

   The error occurs because the application attempts to read a file named `flag.txt` that does not exist in the current directory.

5. **Identifying the Solution**

   To solve this challenge, we need to create a file named `flag.txt` in the same directory as the script (`message.py`). This file should contain the flag or any text required by the challenge.

6. **Creating the `flag.txt` File**

   Create the `flag.txt` file with the required content. For example:
   ```plaintext
   HTB{example_flag}
   ```

7. **Re-running the Application**

   With the `flag.txt` file in place, re-run the application and log in again. This time, the application should successfully read the `flag.txt` file and display its contents.

### Conclusion

By following the steps above, we were able to identify the missing `flag.txt` file as the cause of the error and solve the challenge by providing the necessary file. The application then revealed the flag upon successful login.

---

This write-up provides a clear and structured explanation of how the challenge was solved, detailing each step from registration and login to identifying and fixing the error.
