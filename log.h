//
// Created by Kostya on 11/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_LOG_H
#define OPENVPN_PROXY_TRUNK_LOG_H

#ifdef DEBUG
// https://stackoverflow.com/a/12144620
#define log(...) _log_dbg(__FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define log(...) _log(__VA_ARGS__)
#endif

void _log_dbg(const char *file, int line, const char *func,
              int syslog_priority, const char *fmt, ...);

void _log(int syslog_priority, const char *fmt, ...);

void printf_bytes(void *buf, size_t len);

void logger_daemonize();

#endif //OPENVPN_PROXY_TRUNK_LOG_H
