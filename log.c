//
// Created by Kostya on 11/07/2017.
//

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include "conf.h"


void _log(const char *file, int line, const char *func,
          int syslog_priority, const char *fmt, ...) {
    // https://stackoverflow.com/a/12144620

    va_list args;
#ifndef DEBUG
    va_start(args, fmt);
    vsyslog(syslog_priority, fmt, args);
    va_end(args);
#endif
#ifdef DEBUG
    printf("SYSLOG:%s:%d:%s: ", file, line, func);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n"); // flush buffer
#endif
}

void printf_bytes(void *buf, size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", (unsigned int) ((unsigned char *) buf)[i]);
    }
    printf("\n");
}