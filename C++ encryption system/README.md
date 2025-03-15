# AES Encryption System

A basic AES encryption system implemented in C++ that can be transpiled to JavaScript using Emscripten.

## Features

- AES-128 encryption in CBC mode
- Support for encrypting/decrypting:
  - Strings
  - Integers
  - Floating-point numbers
  - Long integers
- PKCS#7 padding
- JavaScript wrapper for use in web applications

## Building

### Native Build

```bash
mkdir build
cd build
cmake ..
make
```

### Emscripten Build

Make sure you have Emscripten installed and activated in your environment.

```bash
mkdir build_em
cd build_em
emcmake cmake ..
emmake make
```

This will generate:
- `aes_encryption.js` - JavaScript glue code
- `aes_encryption.wasm` - WebAssembly binary
- `aes_encryption.html` - Example HTML page

## Usage

### C++ Usage

```cpp
#include "aes_encryption.h"

// Create an encryption instance
std::string key = "MySecretKey12345";  // 16 bytes for AES-128
std::string iv = "InitVector123456";   // 16 bytes
AESEncryption aes(key, iv);

// String encryption
std::string plaintext = "Hello, this is a secret message!";
std::string encrypted = aes.encryptString(plaintext);
std::string decrypted = aes.decryptString(encrypted);

// Integer encryption
int originalInt = 12345;
std::vector<unsigned char> encryptedInt = aes.encrypt<int>(originalInt);
int decryptedInt = aes.decrypt<int>(encryptedInt);

// Float encryption
float originalFloat = 3.14159f;
std::vector<unsigned char> encryptedFloat = aes.encrypt<float>(originalFloat);
float decryptedFloat = aes.decrypt<float>(encryptedFloat);

// Long int encryption
long int originalLong = 1234567890L;
std::vector<unsigned char> encryptedLong = aes.encrypt<long int>(originalLong);
long int decryptedLong = aes.decrypt<long int>(encryptedLong);
```

### JavaScript Usage (after Emscripten build)

```html
<!DOCTYPE html>
<html>
<head>
    <title>AES Encryption Demo</title>
    <script src="aes_encryption.js"></script>
    <script src="aes_wrapper.js"></script>
    <script>
        function runDemo() {
            const key = "MySecretKey12345";
            const iv = "InitVector123456";
            
            // String encryption
            const plaintext = "Hello, this is a secret message!";
            const encrypted = encryptString(plaintext, key, iv);
            const decrypted = decryptString(encrypted, key, iv);
            
            console.log("Original:", plaintext);
            console.log("Encrypted:", encrypted);
            console.log("Decrypted:", decrypted);
            
            // Integer encryption
            const num = 12345;
            const encryptedNum = encryptInt(num, key, iv);
            const decryptedNum = decryptInt(encryptedNum, key, iv);
            
            console.log("Original number:", num);
            console.log("Encrypted number:", encryptedNum);
            console.log("Decrypted number:", decryptedNum);
        }
        
        // Run the demo when the module is ready
        Module.onRuntimeInitialized = runDemo;
    </script>
</head>
<body>
    <h1>AES Encryption Demo</h1>
    <p>Check the console for results.</p>
</body>
</html>
```

## Implementation Notes

This is a simplified implementation of AES for educational purposes. For production use, consider using established cryptographic libraries like OpenSSL, Crypto++, or the Web Crypto API in browsers.

## License

MIT 