cmake_minimum_required(VERSION 3.10)
project(AESEncryption)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    aes_encryption.cpp
    main.cpp
)

# Native build
if(NOT EMSCRIPTEN)
    add_executable(aes_encryption ${SOURCES})
    
    # Add any additional libraries if needed
    # target_link_libraries(aes_encryption ...)
    
    # Installation rules
    install(TARGETS aes_encryption DESTINATION bin)
# Emscripten build
else()
    # Emscripten specific settings
    set(CMAKE_EXECUTABLE_SUFFIX ".js")
    
    # Add emscripten exports file for Emscripten build
    set(EMSCRIPTEN_SOURCES
        aes_encryption.cpp
        emscripten_exports.cpp
        emscripten_main.cpp
    )
    
    add_executable(aes_encryption ${EMSCRIPTEN_SOURCES})
    
    # Emscripten specific flags
    set_target_properties(aes_encryption PROPERTIES
        LINK_FLAGS "-s WASM=1 -s EXPORTED_FUNCTIONS='[\"_main\", \"_encryptString\", \"_decryptString\", \"_encryptInt\", \"_decryptInt\", \"_encryptFloat\", \"_decryptFloat\", \"_encryptLong\", \"_decryptLong\", \"_cleanupAes\"]' -s EXPORTED_RUNTIME_METHODS='[\"ccall\", \"cwrap\"]' -s ALLOW_MEMORY_GROWTH=1"
    )
    
    # Create HTML output
    set_target_properties(aes_encryption PROPERTIES SUFFIX ".html")
    
    # Installation rules for Emscripten
    install(TARGETS aes_encryption DESTINATION web)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/aes_encryption.js ${CMAKE_CURRENT_BINARY_DIR}/aes_encryption.wasm DESTINATION web)
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/demo.html DESTINATION web)
endif()

# Add JavaScript wrapper for Emscripten
if(EMSCRIPTEN)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/aes_wrapper.js ${CMAKE_CURRENT_BINARY_DIR}/aes_wrapper.js COPYONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/aes_wrapper.js DESTINATION web)
endif() 