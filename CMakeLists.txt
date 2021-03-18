cmake_minimum_required(VERSION 3.10)

project(CompileTimeEncryption)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(CompileTimeEncryption INTERFACE)

target_include_directories(CompileTimeEncryption
	INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

option(ENCRYPT_STRINGS "Encrypt all strings" ON)
if (ENCRYPT_STRINGS)
    target_compile_definitions(CompileTimeEncryption
		INTERFACE -DCTE_ENCRYPTSTRINGS=1)
endif()