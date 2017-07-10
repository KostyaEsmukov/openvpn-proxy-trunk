cmake_minimum_required(VERSION 3.7)
project(openvpn_proxy_trunk)

set(CMAKE_CXX_STANDARD 11)

find_package(openssl REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(SOURCE_FILES utils.c prot.c connect.c main.c)
add_executable(openvpn_proxy_trunk ${SOURCE_FILES})

target_link_libraries(openvpn_proxy_trunk ${OPENSSL_LIBRARIES})
