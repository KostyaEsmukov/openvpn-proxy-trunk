# openvpn-proxy-trunk

Tunnel UDP traffic through multiple TCP connections (possibly via HTTP CONNECT proxy).
The goal is to overcome bandwidth capping of a single TCP connection.

## build

### macos

cmake . -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl -DOPENSSL_LIBRARIES=/usr/local/opt/openssl/lib

### debian

    apt install build-essentials cmake extra-cmake-modules libssl-dev
    cmake .
    make
