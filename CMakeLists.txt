cmake_minimum_required(VERSION 3.7)
project(openvpn_proxy_trunk)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.c)
add_executable(openvpn_proxy_trunk ${SOURCE_FILES})