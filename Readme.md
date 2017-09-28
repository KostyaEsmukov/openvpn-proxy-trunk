# openvpn-proxy-trunk

Tunnel UDP traffic through multiple TCP connections (possibly via HTTP CONNECT proxy).
The goal is to overcome bandwidth capping of a single TCP connection.

## build

### macos

    brew install openssl
    cmake . -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl -DOPENSSL_LIBRARIES=/usr/local/opt/openssl/lib
    make

### debian

    apt install build-essentials cmake extra-cmake-modules libssl-dev
    cmake -DCMAKE_BUILD_TYPE=Release .
    make
    sudo cp openvpn_proxy_trunk /usr/local/bin/

### centos 7

    yum install cmake3 gcc gcc-c++ make openssl-devel
    cmake3 -DCMAKE_BUILD_TYPE=Release .
    make
    sudo cp openvpn_proxy_trunk /usr/local/bin/

