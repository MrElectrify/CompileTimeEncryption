# CompileTimeEncryption
C++20's introduction of structures as template parameters has introduced an easy way of compile-time string encryption.

## Features
- Different keys and ciphertext generated with each compilation
- Different keys and ciphertext per-source file and line number. Encrypting the same string twice will yield two different ciphertexts and keys
- Works in release and debug builds, no matter the optimization
- Uses SSE instructions to decrypt 16 bytes of plaintext at a time
- CMake option ENCRYPT_STRINGS, which can be used to selectively disable string encryption for some build types (if you do not use CMake, you must define CTE_ENCRYPTSTRINGS yourself)

## Usage
- Simply include `XorStr.h`, and wrap plaintext strings in `XorStr`, which will return a `const char*`. An optional `XorStr_` macro is also provided that will return the underlying `std::array<char>`, aligned and padded to 16 bytes
