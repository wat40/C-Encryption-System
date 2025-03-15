#include <iostream>
#include <string>
#include "aes_encryption.h"

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#endif

int main() {
    std::cout << "AES Encryption System" << std::endl;
    std::cout << "=====================" << std::endl;
    
    // This is just a placeholder for the Emscripten build
    // The actual functionality is exposed through the exported functions
    
    return 0;
} 