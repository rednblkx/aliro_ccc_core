cmake_minimum_required(VERSION 3.22)
project(UwbCppCore VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

# -----------------------------------------------------------------------------
# DW3000 Driver
# -----------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/dwt_uwb_driver/deca_device_api.h")
    set(DWT_DRIVER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/dwt_uwb_driver")
else()
    message(STATUS "Fetching DW3000 driver...")
    FetchContent_Declare(
        decadriver
        GIT_REPOSITORY https://github.com/br101/dw3000-decadriver-source.git
        GIT_TAG        master
    )
    FetchContent_MakeAvailable(decadriver)
    set(DWT_DRIVER_DIR "${decadriver_SOURCE_DIR}/dwt_uwb_driver")
    set(DWT_PLATFORM_DIR "${decadriver_SOURCE_DIR}/platform")
endif()
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBED_LIBRARY OFF CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
FetchContent_Declare(mbedtls
        URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.6/mbedtls-3.6.6.tar.bz2
        URL_HASH SHA256=8fb65fae8dcae5840f793c0a334860a411f884cc537ea290ce1c52bb64ca007a)
FetchContent_MakeAvailable(mbedtls)

add_library(dwt_uwb_driver STATIC
    ${DWT_DRIVER_DIR}/deca_interface.c
    ${DWT_PLATFORM_DIR}/deca_compat.c
    ${DWT_DRIVER_DIR}/deca_rsl.c
    ${DWT_DRIVER_DIR}/dw3000/dw3000_device.c
    ${DWT_DRIVER_DIR}/lib/qmath/src/qmath.c
    deca_port.c
)
set_source_files_properties(
        ${DWT_DRIVER_DIR}/dw3000/dw3000_device.c
        PROPERTIES COMPILE_DEFINITIONS "static="
)
target_compile_options(dwt_uwb_driver PUBLIC "-DCONFIG_DW3000_CHIP_DW3000")
target_include_directories(dwt_uwb_driver PUBLIC
    ${DWT_DRIVER_DIR}
    ${DWT_DRIVER_DIR}/dw3000
    ${DWT_PLATFORM_DIR}
    ${DWT_DRIVER_DIR}/lib/qmath/include
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(dwt_uwb_driver PRIVATE -w)
endif()

# -----------------------------------------------------------------------------
# Core UWB Library
# -----------------------------------------------------------------------------
add_library(uwb_core
        src/ranging/AoAEstimator.cpp
        src/ranging/DistanceEstimator.cpp
        src/ranging/HoppingCalculator.cpp
        src/ranging/RangeConsensusFilter.cpp
        src/crypto/MbedTlsCryptoProvider.cpp
        src/crypto/CccKeyDerivationEngine.cpp
        src/crypto/Sp0SecurityEngine.cpp
        src/protocol/FrameCodec.cpp
        src/protocol/SetupMessageCodec.cpp
        src/transceiver/DW3000Controller.cpp
        src/session/RangingSession.cpp
)

target_include_directories(uwb_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        src
)

target_link_libraries(uwb_core PUBLIC mbedtls mbedcrypto dwt_uwb_driver)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(uwb_core PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wnon-virtual-dtor
        -Wcast-align
        -Woverloaded-virtual
    )
endif()
