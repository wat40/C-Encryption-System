#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>

class AESEncryption {
private:
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
    
    static const int AES_BLOCK_SIZE = 16;
    
    void expandKey();
    std::vector<unsigned char> subWord(const std::vector<unsigned char>& word);
    std::vector<unsigned char> rotWord(const std::vector<unsigned char>& word);
    
    std::vector<unsigned char> addRoundKey(const std::vector<unsigned char>& state, const std::vector<unsigned char>& roundKey);
    std::vector<unsigned char> subBytes(const std::vector<unsigned char>& state);
    std::vector<unsigned char> invSubBytes(const std::vector<unsigned char>& state);
    std::vector<unsigned char> shiftRows(const std::vector<unsigned char>& state);
    std::vector<unsigned char> invShiftRows(const std::vector<unsigned char>& state);
    std::vector<unsigned char> mixColumns(const std::vector<unsigned char>& state);
    std::vector<unsigned char> invMixColumns(const std::vector<unsigned char>& state);
    
    std::vector<unsigned char> padData(const std::vector<unsigned char>& data);
    std::vector<unsigned char> removePadding(const std::vector<unsigned char>& data);
    
    std::vector<unsigned char> encryptBlock(const std::vector<unsigned char>& block);
    std::vector<unsigned char> decryptBlock(const std::vector<unsigned char>& block);
    
public:
    AESEncryption(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);
    AESEncryption(const std::string& keyStr, const std::string& ivStr);
    
    std::string encryptString(const std::string& plaintext);
    std::string decryptString(const std::string& ciphertext);
    
    template<typename T>
    std::vector<unsigned char> encrypt(const T& data) {
        std::vector<unsigned char> bytes(sizeof(T));
        std::memcpy(bytes.data(), &data, sizeof(T));
        
        std::vector<unsigned char> paddedData = padData(bytes);
        std::vector<unsigned char> result;
        
        for (size_t i = 0; i < paddedData.size(); i += AES_BLOCK_SIZE) {
            std::vector<unsigned char> block(paddedData.begin() + i, paddedData.begin() + i + AES_BLOCK_SIZE);
            std::vector<unsigned char> encryptedBlock = encryptBlock(block);
            result.insert(result.end(), encryptedBlock.begin(), encryptedBlock.end());
        }
        
        return result;
    }
    
    template<typename T>
    T decrypt(const std::vector<unsigned char>& encryptedData) {
        if (encryptedData.size() % AES_BLOCK_SIZE != 0) {
            throw std::invalid_argument("Encrypted data size must be a multiple of the block size");
        }
        
        std::vector<unsigned char> decryptedData;
        
        for (size_t i = 0; i < encryptedData.size(); i += AES_BLOCK_SIZE) {
            std::vector<unsigned char> block(encryptedData.begin() + i, encryptedData.begin() + i + AES_BLOCK_SIZE);
            std::vector<unsigned char> decryptedBlock = decryptBlock(block);
            decryptedData.insert(decryptedData.end(), decryptedBlock.begin(), decryptedBlock.end());
        }
        
        std::vector<unsigned char> unpaddedData = removePadding(decryptedData);
        
        T result;
        if (unpaddedData.size() < sizeof(T)) {
            throw std::runtime_error("Decrypted data is too small for the requested type");
        }
        std::memcpy(&result, unpaddedData.data(), sizeof(T));
        
        return result;
    }
};

#endif 