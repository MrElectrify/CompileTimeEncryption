cmake_minimum_required(VERSION 3.10)

project(CompileTimeEncryption)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

option(ENCRYPT_STRINGS "Encrypt all strings" ON)
if (ENCRYPT_STRINGS)
    add_definitions(-CTE_ENCRYPTSTRINGS=1)
endif()

add_library(CompileTimeEncryption INTERFACE)

target_include_directories(CompileTimeEncryption
	INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)