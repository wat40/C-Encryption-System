#include <iostream>
#include <string>
#include <vector>
#include "aes_encryption.h"

int main() {
    try {
        // Create an AES encryption instance with a key and IV
        std::string key = "MySecretKey12345";  // 16 bytes for AES-128
        std::string iv = "InitVector123456";   // 16 bytes
        
        AESEncryption aes(key, iv);
        
        // String encryption/decryption
        std::string plaintext = "Hello, this is a secret message!";
        std::cout << "Original text: " << plaintext << std::endl;
        
        std::string encrypted = aes.encryptString(plaintext);
        std::cout << "Encrypted (hex): " << encrypted << std::endl;
        
        std::string decrypted = aes.decryptString(encrypted);
        std::cout << "Decrypted: " << decrypted << std::endl;
        std::cout << std::endl;
        
        // Integer encryption/decryption
        int originalInt = 12345;
        std::cout << "Original int: " << originalInt << std::endl;
        
        std::vector<unsigned char> encryptedInt = aes.encrypt<int>(originalInt);
        
        // Convert to hex for display
        std::cout << "Encrypted int (hex): ";
        for (unsigned char byte : encryptedInt) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::cout << std::dec << std::endl;
        
        int decryptedInt = aes.decrypt<int>(encryptedInt);
        std::cout << "Decrypted int: " << decryptedInt << std::endl;
        std::cout << std::endl;
        
        // Float encryption/decryption
        float originalFloat = 3.14159f;
        std::cout << "Original float: " << originalFloat << std::endl;
        
        std::vector<unsigned char> encryptedFloat = aes.encrypt<float>(originalFloat);
        
        // Convert to hex for display
        std::cout << "Encrypted float (hex): ";
        for (unsigned char byte : encryptedFloat) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::cout << std::dec << std::endl;
        
        float decryptedFloat = aes.decrypt<float>(encryptedFloat);
        std::cout << "Decrypted float: " << decryptedFloat << std::endl;
        std::cout << std::endl;
        
        // Long int encryption/decryption
        long int originalLong = 1234567890L;
        std::cout << "Original long: " << originalLong << std::endl;
        
        std::vector<unsigned char> encryptedLong = aes.encrypt<long int>(originalLong);
        
        // Convert to hex for display
        std::cout << "Encrypted long (hex): ";
        for (unsigned char byte : encryptedLong) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::cout << std::dec << std::endl;
        
        long int decryptedLong = aes.decrypt<long int>(encryptedLong);
        std::cout << "Decrypted long: " << decryptedLong << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
} 