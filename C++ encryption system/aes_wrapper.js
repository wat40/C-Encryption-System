/**
 * AES Encryption JavaScript Wrapper
 * This file provides a simple JavaScript API for the C++ AES encryption library
 */

// Wait for the Emscripten module to be ready
Module.onRuntimeInitialized = function() {
    console.log("AES Encryption module initialized");
};

/**
 * Encrypt a string using AES
 * @param {string} text - The plaintext to encrypt
 * @param {string} key - The encryption key (will be padded/truncated to 16 bytes)
 * @param {string} iv - The initialization vector (will be padded/truncated to 16 bytes)
 * @returns {string} - Hex-encoded encrypted string
 */
function encryptString(text, key, iv) {
    // Create a wrapper for the C++ function
    const encryptStringFunc = Module.cwrap('encryptString', 'string', ['string', 'string', 'string']);
    return encryptStringFunc(text, key, iv);
}

/**
 * Decrypt a string using AES
 * @param {string} encryptedHex - The hex-encoded encrypted string
 * @param {string} key - The encryption key (must match the one used for encryption)
 * @param {string} iv - The initialization vector (must match the one used for encryption)
 * @returns {string} - Decrypted plaintext
 */
function decryptString(encryptedHex, key, iv) {
    // Create a wrapper for the C++ function
    const decryptStringFunc = Module.cwrap('decryptString', 'string', ['string', 'string', 'string']);
    return decryptStringFunc(encryptedHex, key, iv);
}

/**
 * Encrypt an integer using AES
 * @param {number} value - The integer to encrypt
 * @param {string} key - The encryption key
 * @param {string} iv - The initialization vector
 * @returns {string} - Hex-encoded encrypted data
 */
function encryptInt(value, key, iv) {
    const encryptIntFunc = Module.cwrap('encryptInt', 'string', ['number', 'string', 'string']);
    return encryptIntFunc(value, key, iv);
}

/**
 * Decrypt an integer using AES
 * @param {string} encryptedHex - The hex-encoded encrypted data
 * @param {string} key - The encryption key
 * @param {string} iv - The initialization vector
 * @returns {number} - Decrypted integer
 */
function decryptInt(encryptedHex, key, iv) {
    const decryptIntFunc = Module.cwrap('decryptInt', 'number', ['string', 'string', 'string']);
    return decryptIntFunc(encryptedHex, key, iv);
}

/**
 * Encrypt a float using AES
 * @param {number} value - The float to encrypt
 * @param {string} key - The encryption key
 * @param {string} iv - The initialization vector
 * @returns {string} - Hex-encoded encrypted data
 */
function encryptFloat(value, key, iv) {
    const encryptFloatFunc = Module.cwrap('encryptFloat', 'string', ['number', 'string', 'string']);
    return encryptFloatFunc(value, key, iv);
}

/**
 * Decrypt a float using AES
 * @param {string} encryptedHex - The hex-encoded encrypted data
 * @param {string} key - The encryption key
 * @param {string} iv - The initialization vector
 * @returns {number} - Decrypted float
 */
function decryptFloat(encryptedHex, key, iv) {
    const decryptFloatFunc = Module.cwrap('decryptFloat', 'number', ['string', 'string', 'string']);
    return decryptFloatFunc(encryptedHex, key, iv);
}

/**
 * Encrypt a long integer using AES
 * @param {number} value - The long integer to encrypt
 * @param {string} key - The encryption key
 * @param {string} iv - The initialization vector
 * @returns {string} - Hex-encoded encrypted data
 */
function encryptLong(value, key, iv) {
    const encryptLongFunc = Module.cwrap('encryptLong', 'string', ['number', 'string', 'string']);
    return encryptLongFunc(value, key, iv);
}

/**
 * Decrypt a long integer using AES
 * @param {string} encryptedHex - The hex-encoded encrypted data
 * @param {string} key - The encryption key
 * @param {string} iv - The initialization vector
 * @returns {number} - Decrypted long integer
 */
function decryptLong(encryptedHex, key, iv) {
    const decryptLongFunc = Module.cwrap('decryptLong', 'number', ['string', 'string', 'string']);
    return decryptLongFunc(encryptedHex, key, iv);
}

// Export functions for use in other JavaScript modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        encryptString,
        decryptString,
        encryptInt,
        decryptInt,
        encryptFloat,
        decryptFloat,
        encryptLong,
        decryptLong
    };
} 