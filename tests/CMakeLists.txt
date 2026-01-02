cmake_minimum_required(VERSION 3.16)

project(ad_vpn_tests
    VERSION 1.0
    LANGUAGES CXX C
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find GoogleTest
find_package(GTest QUIET)
if(NOT GTest_FOUND)
    # Use prebuilt googletest
    set(GTEST_ROOT ${CMAKE_SOURCE_DIR}/../prebuilt/googletest)
    set(GTEST_INCLUDE_DIR ${GTEST_ROOT}/googletest/include)
    set(GTEST_LIBRARY ${GTEST_ROOT}/build/lib/libgtest.a)
    set(GTEST_MAIN_LIBRARY ${GTEST_ROOT}/build/lib/libgtest_main.a)
    set(GMOCK_LIBRARY ${GTEST_ROOT}/build/lib/libgmock.a)
    set(GMOCK_MAIN_LIBRARY ${GTEST_ROOT}/build/lib/libgmock_main.a)
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/../modules/ad_logger/include
    ${CMAKE_SOURCE_DIR}/../modules/ad_tun/include
    ${CMAKE_SOURCE_DIR}/../modules/ad_transport/include
    ${CMAKE_SOURCE_DIR}/../modules/ad_auth/include
    ${CMAKE_SOURCE_DIR}/../modules/ad_kex/include
    ${CMAKE_SOURCE_DIR}/../modules/ad_crypt/include
    ${CMAKE_SOURCE_DIR}/../modules/ad_routing/include
    ${GTEST_INCLUDE_DIR}
)

# Test executable
add_executable(test_ad_vpn
    test_ad_vpn.cpp
    test_main.cpp
)

# Create a library version of ad_vpn for testing
add_library(ad_vpn_lib STATIC
    ${CMAKE_SOURCE_DIR}/../src/ad_vpn.c
)

target_include_directories(ad_vpn_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/../modules/ad_logger/include
    ${CMAKE_SOURCE_DIR}/../modules/ad_tun/include
    ${CMAKE_SOURCE_DIR}/../modules/ad_transport/include
    ${CMAKE_SOURCE_DIR}/../modules/ad_auth/include
    ${CMAKE_SOURCE_DIR}/../modules/ad_kex/include
    ${CMAKE_SOURCE_DIR}/../modules/ad_crypt/include
    ${CMAKE_SOURCE_DIR}/../modules/ad_routing/include
)

target_link_libraries(ad_vpn_lib
    ad_transport
    ad_tun
    ad_auth
    ad_kex
    ad_crypt
    ad_logger
    ad_routing
)

# Link libraries
target_link_libraries(test_ad_vpn
    ad_vpn_lib
    ad_transport
    ad_tun
    ad_auth
    ad_kex
    ad_crypt
    ad_logger
    ad_routing
    ${GTEST_LIBRARY}
    ${GTEST_MAIN_LIBRARY}
    ${GMOCK_LIBRARY}
    pthread
    m
)

# Add test
add_test(NAME ad_vpn_tests COMMAND test_ad_vpn)

