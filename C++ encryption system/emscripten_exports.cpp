#include "aes_encryption.h"
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#else
// Define EMSCRIPTEN_KEEPALIVE for non-Emscripten builds
#define EMSCRIPTEN_KEEPALIVE
#endif

// Create a global instance with default values
// In a real application, you might want to create instances on demand
static AESEncryption* defaultAes = nullptr;

// Helper function to ensure we have a valid AES instance
AESEncryption* getAesInstance(const std::string& key, const std::string& iv) {
    if (defaultAes == nullptr) {
        defaultAes = new AESEncryption(key, iv);
    } else {
        // Update the instance with new key/iv
        delete defaultAes;
        defaultAes = new AESEncryption(key, iv);
    }
    return defaultAes;
}

// String encryption/decryption
extern "C" {

EMSCRIPTEN_KEEPALIVE
const char* encryptString(const char* text, const char* key, const char* iv) {
    try {
        AESEncryption* aes = getAesInstance(key, iv);
        std::string result = aes->encryptString(text);
        
        // Allocate memory that will be managed by JavaScript
        char* output = (char*)malloc(result.length() + 1);
        strcpy(output, result.c_str());
        return output;
    } catch (const std::exception& e) {
        return nullptr;
    }
}

EMSCRIPTEN_KEEPALIVE
const char* decryptString(const char* encryptedHex, const char* key, const char* iv) {
    try {
        AESEncryption* aes = getAesInstance(key, iv);
        std::string result = aes->decryptString(encryptedHex);
        
        // Allocate memory that will be managed by JavaScript
        char* output = (char*)malloc(result.length() + 1);
        strcpy(output, result.c_str());
        return output;
    } catch (const std::exception& e) {
        return nullptr;
    }
}

// Integer encryption/decryption
EMSCRIPTEN_KEEPALIVE
const char* encryptInt(int value, const char* key, const char* iv) {
    try {
        AESEncryption* aes = getAesInstance(key, iv);
        std::vector<unsigned char> encrypted = aes->encrypt<int>(value);
        
        // Convert to hex string
        std::stringstream ss;
        for (unsigned char byte : encrypted) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::string result = ss.str();
        
        // Allocate memory that will be managed by JavaScript
        char* output = (char*)malloc(result.length() + 1);
        strcpy(output, result.c_str());
        return output;
    } catch (const std::exception& e) {
        return nullptr;
    }
}

EMSCRIPTEN_KEEPALIVE
int decryptInt(const char* encryptedHex, const char* key, const char* iv) {
    try {
        AESEncryption* aes = getAesInstance(key, iv);
        
        // Convert hex string back to bytes
        std::vector<unsigned char> encryptedData;
        for (size_t i = 0; i < strlen(encryptedHex); i += 2) {
            std::string byteString = std::string(encryptedHex + i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            encryptedData.push_back(byte);
        }
        
        return aes->decrypt<int>(encryptedData);
    } catch (const std::exception& e) {
        return 0;
    }
}

// Float encryption/decryption
EMSCRIPTEN_KEEPALIVE
const char* encryptFloat(float value, const char* key, const char* iv) {
    try {
        AESEncryption* aes = getAesInstance(key, iv);
        std::vector<unsigned char> encrypted = aes->encrypt<float>(value);
        
        // Convert to hex string
        std::stringstream ss;
        for (unsigned char byte : encrypted) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::string result = ss.str();
        
        // Allocate memory that will be managed by JavaScript
        char* output = (char*)malloc(result.length() + 1);
        strcpy(output, result.c_str());
        return output;
    } catch (const std::exception& e) {
        return nullptr;
    }
}

EMSCRIPTEN_KEEPALIVE
float decryptFloat(const char* encryptedHex, const char* key, const char* iv) {
    try {
        AESEncryption* aes = getAesInstance(key, iv);
        
        // Convert hex string back to bytes
        std::vector<unsigned char> encryptedData;
        for (size_t i = 0; i < strlen(encryptedHex); i += 2) {
            std::string byteString = std::string(encryptedHex + i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            encryptedData.push_back(byte);
        }
        
        return aes->decrypt<float>(encryptedData);
    } catch (const std::exception& e) {
        return 0.0f;
    }
}

// Long int encryption/decryption
EMSCRIPTEN_KEEPALIVE
const char* encryptLong(long value, const char* key, const char* iv) {
    try {
        AESEncryption* aes = getAesInstance(key, iv);
        std::vector<unsigned char> encrypted = aes->encrypt<long>(value);
        
        // Convert to hex string
        std::stringstream ss;
        for (unsigned char byte : encrypted) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::string result = ss.str();
        
        // Allocate memory that will be managed by JavaScript
        char* output = (char*)malloc(result.length() + 1);
        strcpy(output, result.c_str());
        return output;
    } catch (const std::exception& e) {
        return nullptr;
    }
}

EMSCRIPTEN_KEEPALIVE
long decryptLong(const char* encryptedHex, const char* key, const char* iv) {
    try {
        AESEncryption* aes = getAesInstance(key, iv);
        
        // Convert hex string back to bytes
        std::vector<unsigned char> encryptedData;
        for (size_t i = 0; i < strlen(encryptedHex); i += 2) {
            std::string byteString = std::string(encryptedHex + i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            encryptedData.push_back(byte);
        }
        
        return aes->decrypt<long>(encryptedData);
    } catch (const std::exception& e) {
        return 0L;
    }
}

// Cleanup function
EMSCRIPTEN_KEEPALIVE
void cleanupAes() {
    if (defaultAes != nullptr) {
        delete defaultAes;
        defaultAes = nullptr;
    }
}

} // extern "C" 