cmake_minimum_required(VERSION 3.5)
project(openvpn_proxy_trunk)

set(CMAKE_C_STANDARD 99)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(SOURCE_FILES log.c utils.c prot.c connect.c bind.c subflow.c run_forever.c main.c)
add_executable(openvpn_proxy_trunk ${SOURCE_FILES})

target_link_libraries(openvpn_proxy_trunk ${OPENSSL_LIBRARIES})
