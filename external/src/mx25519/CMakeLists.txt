cmake_minimum_required(VERSION 3.5)

set(mx25519_sources
    portable/scalarmult.c
    cpu.c
    impl.c
    mx25519.c
    scalar.c
    platform.c)

if(NOT ARCH_ID)
  if(CMAKE_SYSTEM_PROCESSOR STREQUAL "")
    set(CMAKE_SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
  endif()
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" ARCH_ID)
endif()

if(NOT ARM_ID)
  set(ARM_ID "${ARCH_ID}")
endif()

message(STATUS "mx25519 build architecture: ${ARCH_ID}")

# AMD64
if(ARCH_ID STREQUAL "x86_64" OR ARCH_ID STREQUAL "x86-64" OR ARCH_ID STREQUAL "amd64")
  if(MSVC)
    enable_language(ASM_MASM)
    list(APPEND mx25519_sources amd64/scalarmult_masm.asm)
    set_property(SOURCE amd64/scalarmult_masm.asm PROPERTY LANGUAGE ASM_MASM)
  else()
    list(APPEND mx25519_sources amd64/scalarmult_gnu.S)
    set_property(SOURCE amd64/scalarmult_gnu.S PROPERTY LANGUAGE C)
    set_property(SOURCE amd64/scalarmult_gnu.S PROPERTY XCODE_EXPLICIT_FILE_TYPE sourcecode.asm)
  endif()
endif()

# ARM64
if(ARM_ID STREQUAL "aarch64" OR ARM_ID STREQUAL "arm64" OR ARM_ID STREQUAL "armv8-a")
  list(APPEND mx25519_sources arm64/scalarmult.S)
  set_property(SOURCE arm64/scalarmult.S PROPERTY LANGUAGE C)
  set_property(SOURCE arm64/scalarmult.S PROPERTY XCODE_EXPLICIT_FILE_TYPE sourcecode.asm)
endif()

add_library(mx25519 STATIC ${mx25519_sources})
set_property(TARGET mx25519 PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(mx25519 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(mx25519 PRIVATE MX25519_STATIC)
