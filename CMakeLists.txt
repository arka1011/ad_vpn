cmake_minimum_required(VERSION 3.16)

project(ad_vpn
    VERSION 1.0
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---- OUTPUT DIRECTORIES ----
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ---- ADD MODULES IN BUILD ORDER ----
# Order matters because of target dependencies
add_subdirectory(modules/ad_logger)
add_subdirectory(modules/ad_tun)
add_subdirectory(modules/ad_auth)
add_subdirectory(modules/ad_kex)
add_subdirectory(modules/ad_crypt)
add_subdirectory(modules/ad_transport)

# ---- AD_VPN EXECUTABLE ----
add_executable(ad_vpn
    src/ad_vpn.c
)

# ---- INCLUDE DIRS ----
target_include_directories(ad_vpn PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    modules/ad_logger/include
    modules/ad_tun/include
    modules/ad_kex/include
    modules/ad_auth/include
    modules/ad_crypt/include
    modules/ad_transport/include
)

# ---- LINK MODULE LIBRARIES ----
target_link_libraries(ad_vpn
    ad_transport
    ad_tun
    ad_auth
    ad_kex
    ad_crypt
    ad_logger
)

enable_testing()