+++
date = '2025-02-23T22:24:57+01:00'
draft = false
title = 'Printer'
+++
# IngeHack2k25 - reverse/mjsc Write-up

## Challenge Overview
**Challenge Name**: reverse/printer  
**Category**: Reverse Engineering  
**Event**: IngeHack 2k25  
**Difficulty**: Medium  
**Flag**: `ingehack{...}`  
## Fourier Transformation-Based Image Decryption

### **Challenge Analysis**

Upon analyzing the provided files, we observed the following directory structure:
```
➜  solver ls 
decrypted.png  enc  main  reconstructed_data.txt  sol.py
```
The main objective is to decrypt the file `enc` to retrieve an image. By inspecting `main`, we determined that it applies a Fourier transformation, meaning the encryption likely involves transforming the image into the frequency domain. 

To recover the original image, we need to apply the **Inverse Fourier Transform (IFFT)** to `enc` and reconstruct the original pixel data.

### **Decryption Process**
The `decrypt_image()` function in `sol.py` implements the decryption using NumPy’s FFT functions. Below is a step-by-step breakdown of how it works:

1. **Read the Encrypted File**
   - The function reads `enc` as a binary file.
   - The binary data is interpreted as an array of `float64` values.

2. **Reshape into Complex Numbers**
   - The data is reshaped into pairs of real and imaginary components.
   - These are converted into complex numbers representing frequency-domain data.

3. **Apply Inverse FFT (IFFT)**
   - The inverse Fourier transform is applied to reconstruct the time-domain (original pixel) data.

4. **Convert Back to Byte Values**
   - The real part of the transformed data is extracted.
   - Values are rounded, clipped between 0-255, and converted to `uint8` format.

5. **Save as PNG File**
   - The decrypted image is written to `decrypted.png`.

### **Execution**
To decrypt the image, simply run:
```python
import numpy as np

def decrypt_image():
    # Read the encrypted file
    with open("enc", "rb") as f:
        data = f.read()
    
    # Convert to numpy array of doubles
    doubles = np.frombuffer(data, dtype=np.float64)
    
    # Reshape into complex numbers (real + imaginary pairs)
    complex_data = doubles.reshape(-1, 2)
    complex_numbers = complex_data[:, 0] + 1j * complex_data[:, 1]
    
    # Apply inverse FFT to get back to time domain
    time_domain_data = np.fft.ifft(complex_numbers)
    
    # Convert the real parts to bytes
    # Round and clip to ensure valid byte values (0-255)
    byte_data = np.clip(np.round(np.real(time_domain_data)), 0, 255).astype(np.uint8)
    
    # Write the decrypted data to a PNG file
    with open("decrypted.png", "wb") as f:
        f.write(bytes(byte_data))

if __name__ == "__main__":
    try:
        decrypt_image()
        print("Image decrypted successfully. Saved as 'decrypted.png'")
    except Exception as e:
        print(f"Error occurred: {e}")
```

### **Flag**
After running the decryption, examining `decrypted.png` reveals the flag:
![decrypted](https://github.com/user-attachments/assets/a7723893-ea29-4ca2-a527-b2a7e4662af5)


---


