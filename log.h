//
// Created by Kostya on 11/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_LOG_H
#define OPENVPN_PROXY_TRUNK_LOG_H

// https://stackoverflow.com/a/12144620
#define log(...) _log(__FILE__, __LINE__, __func__, __VA_ARGS__)


void _log(const char *file, int line, const char *func,
          int syslog_priority, const char *fmt, ...);

void printf_bytes(void * buf, size_t len);

#endif //OPENVPN_PROXY_TRUNK_LOG_H
