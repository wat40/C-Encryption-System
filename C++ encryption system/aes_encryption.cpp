#include "aes_encryption.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>

// AES S-box for SubBytes operation
static const unsigned char SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Inverse S-box for InvSubBytes operation
static const unsigned char INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rcon values for key expansion
static const unsigned char RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Galois field multiplication for MixColumns
unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char high_bit;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        high_bit = (a & 0x80);
        a <<= 1;
        if (high_bit) {
            a ^= 0x1b; // Irreducible polynomial x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return p;
}

// Constructors
AESEncryption::AESEncryption(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    // AES-128 requires a 16-byte key
    if (key.size() != 16) {
        throw std::invalid_argument("Key must be 16 bytes (128 bits) for AES-128");
    }
    
    // IV should also be 16 bytes
    if (iv.size() != 16) {
        throw std::invalid_argument("IV must be 16 bytes (128 bits)");
    }
    
    this->key = key;
    this->iv = iv;
}

AESEncryption::AESEncryption(const std::string& keyStr, const std::string& ivStr) {
    // Convert string key to bytes
    for (char c : keyStr) {
        key.push_back(static_cast<unsigned char>(c));
    }
    
    // Ensure key is exactly 16 bytes (pad or truncate)
    if (key.size() < 16) {
        // Pad with zeros
        key.resize(16, 0);
    } else if (key.size() > 16) {
        // Truncate
        key.resize(16);
    }
    
    // Convert string IV to bytes
    for (char c : ivStr) {
        iv.push_back(static_cast<unsigned char>(c));
    }
    
    // Ensure IV is exactly 16 bytes (pad or truncate)
    if (iv.size() < 16) {
        // Pad with zeros
        iv.resize(16, 0);
    } else if (iv.size() > 16) {
        // Truncate
        iv.resize(16);
    }
}

// String encryption
std::string AESEncryption::encryptString(const std::string& plaintext) {
    std::vector<unsigned char> bytes(plaintext.begin(), plaintext.end());
    std::vector<unsigned char> paddedData = padData(bytes);
    std::vector<unsigned char> result;
    
    // Process in blocks
    for (size_t i = 0; i < paddedData.size(); i += AES_BLOCK_SIZE) {
        std::vector<unsigned char> block(paddedData.begin() + i, paddedData.begin() + i + AES_BLOCK_SIZE);
        std::vector<unsigned char> encryptedBlock = encryptBlock(block);
        result.insert(result.end(), encryptedBlock.begin(), encryptedBlock.end());
    }
    
    // Convert to hex string for safe storage/transmission
    std::stringstream ss;
    for (unsigned char byte : result) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    
    return ss.str();
}

// String decryption
std::string AESEncryption::decryptString(const std::string& ciphertext) {
    // Convert hex string back to bytes
    std::vector<unsigned char> encryptedData;
    for (size_t i = 0; i < ciphertext.length(); i += 2) {
        std::string byteString = ciphertext.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        encryptedData.push_back(byte);
    }
    
    // Check if data size is valid
    if (encryptedData.size() % AES_BLOCK_SIZE != 0) {
        throw std::invalid_argument("Encrypted data size must be a multiple of the block size");
    }
    
    std::vector<unsigned char> decryptedData;
    
    // Process in blocks
    for (size_t i = 0; i < encryptedData.size(); i += AES_BLOCK_SIZE) {
        std::vector<unsigned char> block(encryptedData.begin() + i, encryptedData.begin() + i + AES_BLOCK_SIZE);
        std::vector<unsigned char> decryptedBlock = decryptBlock(block);
        decryptedData.insert(decryptedData.end(), decryptedBlock.begin(), decryptedBlock.end());
    }
    
    // Remove padding
    std::vector<unsigned char> unpaddedData = removePadding(decryptedData);
    
    // Convert back to string
    return std::string(unpaddedData.begin(), unpaddedData.end());
}

// PKCS#7 padding
std::vector<unsigned char> AESEncryption::padData(const std::vector<unsigned char>& data) {
    size_t paddingSize = AES_BLOCK_SIZE - (data.size() % AES_BLOCK_SIZE);
    std::vector<unsigned char> paddedData = data;
    
    // Add padding bytes (value equals the number of padding bytes)
    for (size_t i = 0; i < paddingSize; i++) {
        paddedData.push_back(static_cast<unsigned char>(paddingSize));
    }
    
    return paddedData;
}

// Remove PKCS#7 padding
std::vector<unsigned char> AESEncryption::removePadding(const std::vector<unsigned char>& data) {
    if (data.empty()) {
        return data;
    }
    
    unsigned char paddingSize = data.back();
    
    // Validate padding
    if (paddingSize > AES_BLOCK_SIZE || paddingSize == 0) {
        throw std::runtime_error("Invalid padding");
    }
    
    // Check if all padding bytes have the correct value
    for (size_t i = data.size() - paddingSize; i < data.size(); i++) {
        if (data[i] != paddingSize) {
            throw std::runtime_error("Invalid padding");
        }
    }
    
    // Remove padding
    return std::vector<unsigned char>(data.begin(), data.end() - paddingSize);
}

// Encrypt a single block (simplified AES for demonstration)
std::vector<unsigned char> AESEncryption::encryptBlock(const std::vector<unsigned char>& block) {
    if (block.size() != AES_BLOCK_SIZE) {
        throw std::invalid_argument("Block size must be 16 bytes");
    }
    
    // XOR with IV (for first block) or previous ciphertext block (for CBC mode)
    std::vector<unsigned char> state = block;
    for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= iv[i];
    }
    
    // Apply SubBytes transformation
    state = subBytes(state);
    
    // Apply ShiftRows transformation
    state = shiftRows(state);
    
    // Apply MixColumns transformation
    state = mixColumns(state);
    
    // Apply AddRoundKey transformation (simplified for demonstration)
    for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= key[i];
    }
    
    // Update IV for next block (CBC mode)
    iv = state;
    
    return state;
}

// Decrypt a single block (simplified AES for demonstration)
std::vector<unsigned char> AESEncryption::decryptBlock(const std::vector<unsigned char>& block) {
    if (block.size() != AES_BLOCK_SIZE) {
        throw std::invalid_argument("Block size must be 16 bytes");
    }
    
    // Save current ciphertext for next IV
    std::vector<unsigned char> nextIv = block;
    
    // Apply AddRoundKey transformation (simplified for demonstration)
    std::vector<unsigned char> state = block;
    for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= key[i];
    }
    
    // Apply InvMixColumns transformation
    state = invMixColumns(state);
    
    // Apply InvShiftRows transformation
    state = invShiftRows(state);
    
    // Apply InvSubBytes transformation
    state = invSubBytes(state);
    
    // XOR with IV (for first block) or previous ciphertext block (for CBC mode)
    for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= iv[i];
    }
    
    // Update IV for next block (CBC mode)
    iv = nextIv;
    
    return state;
}

// SubBytes transformation
std::vector<unsigned char> AESEncryption::subBytes(const std::vector<unsigned char>& state) {
    std::vector<unsigned char> result = state;
    for (size_t i = 0; i < state.size(); i++) {
        result[i] = SBOX[state[i]];
    }
    return result;
}

// InvSubBytes transformation
std::vector<unsigned char> AESEncryption::invSubBytes(const std::vector<unsigned char>& state) {
    std::vector<unsigned char> result = state;
    for (size_t i = 0; i < state.size(); i++) {
        result[i] = INV_SBOX[state[i]];
    }
    return result;
}

// ShiftRows transformation
std::vector<unsigned char> AESEncryption::shiftRows(const std::vector<unsigned char>& state) {
    std::vector<unsigned char> result = state;
    
    // Row 1: shift left by 1
    unsigned char temp = result[1];
    result[1] = result[5];
    result[5] = result[9];
    result[9] = result[13];
    result[13] = temp;
    
    // Row 2: shift left by 2
    temp = result[2];
    result[2] = result[10];
    result[10] = temp;
    temp = result[6];
    result[6] = result[14];
    result[14] = temp;
    
    // Row 3: shift left by 3 (or right by 1)
    temp = result[15];
    result[15] = result[11];
    result[11] = result[7];
    result[7] = result[3];
    result[3] = temp;
    
    return result;
}

// InvShiftRows transformation
std::vector<unsigned char> AESEncryption::invShiftRows(const std::vector<unsigned char>& state) {
    std::vector<unsigned char> result = state;
    
    // Row 1: shift right by 1
    unsigned char temp = result[13];
    result[13] = result[9];
    result[9] = result[5];
    result[5] = result[1];
    result[1] = temp;
    
    // Row 2: shift right by 2
    temp = result[2];
    result[2] = result[10];
    result[10] = temp;
    temp = result[6];
    result[6] = result[14];
    result[14] = temp;
    
    // Row 3: shift right by 3 (or left by 1)
    temp = result[3];
    result[3] = result[7];
    result[7] = result[11];
    result[11] = result[15];
    result[15] = temp;
    
    return result;
}

// MixColumns transformation
std::vector<unsigned char> AESEncryption::mixColumns(const std::vector<unsigned char>& state) {
    std::vector<unsigned char> result = state;
    
    for (int i = 0; i < 4; i++) {
        unsigned char s0 = state[i * 4];
        unsigned char s1 = state[i * 4 + 1];
        unsigned char s2 = state[i * 4 + 2];
        unsigned char s3 = state[i * 4 + 3];
        
        result[i * 4] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3;
        result[i * 4 + 1] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3;
        result[i * 4 + 2] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3);
        result[i * 4 + 3] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3);
    }
    
    return result;
}

// InvMixColumns transformation
std::vector<unsigned char> AESEncryption::invMixColumns(const std::vector<unsigned char>& state) {
    std::vector<unsigned char> result = state;
    
    for (int i = 0; i < 4; i++) {
        unsigned char s0 = state[i * 4];
        unsigned char s1 = state[i * 4 + 1];
        unsigned char s2 = state[i * 4 + 2];
        unsigned char s3 = state[i * 4 + 3];
        
        result[i * 4] = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
        result[i * 4 + 1] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
        result[i * 4 + 2] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
        result[i * 4 + 3] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
    }
    
    return result;
}

// AddRoundKey transformation
std::vector<unsigned char> AESEncryption::addRoundKey(const std::vector<unsigned char>& state, const std::vector<unsigned char>& roundKey) {
    std::vector<unsigned char> result = state;
    for (size_t i = 0; i < state.size(); i++) {
        result[i] ^= roundKey[i];
    }
    return result;
}

// Key expansion helpers (simplified for demonstration)
void AESEncryption::expandKey() {
    // This is a simplified version - a real implementation would expand the key for all rounds
}

std::vector<unsigned char> AESEncryption::subWord(const std::vector<unsigned char>& word) {
    std::vector<unsigned char> result = word;
    for (size_t i = 0; i < word.size(); i++) {
        result[i] = SBOX[word[i]];
    }
    return result;
}

std::vector<unsigned char> AESEncryption::rotWord(const std::vector<unsigned char>& word) {
    std::vector<unsigned char> result = word;
    unsigned char temp = result[0];
    result[0] = result[1];
    result[1] = result[2];
    result[2] = result[3];
    result[3] = temp;
    return result;
} 