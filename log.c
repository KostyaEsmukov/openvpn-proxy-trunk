//
// Created by Kostya on 11/07/2017.
//

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <time.h>

#include "conf.h"


static volatile int log_to_syslog = 0;

void _printf_time() {
    time_t timer;
    char buffer[26];
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    printf("[%s] ", buffer);
}

void _log_dbg(const char *file, int line, const char *func,
              int syslog_priority, const char *fmt, ...) {
    // https://stackoverflow.com/a/12144620

    va_list args;
    if (log_to_syslog) {
        va_start(args, fmt);
        vsyslog(syslog_priority, fmt, args);
        va_end(args);
    } else {
        printf("%s:%d:%s: ", file, line, func);
        _printf_time();
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
        printf("\n"); // flush buffer
    }
}

void _log(int syslog_priority, const char *fmt, ...) {
    va_list args;
    if (log_to_syslog) {
        va_start(args, fmt);
        vsyslog(syslog_priority, fmt, args);
        va_end(args);
    } else {
        _printf_time();
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
        printf("\n"); // flush buffer
    }
}

void printf_bytes(void *buf, size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", (unsigned int) ((unsigned char *) buf)[i]);
    }
    printf("\n");
}

void logger_daemonize() {
    log_to_syslog = 1;
}