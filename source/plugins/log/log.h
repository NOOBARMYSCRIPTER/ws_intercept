#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "../../ws.h"

#define LOGGING 1

#if LOGGING == 0
#define LOG(x,...) do { printf(x, ##__VA_ARGS__); printf("\n"); } while(0)
#define LOGn(x,...) do { printf(x, ##__VA_ARGS__); } while(0)

#elif LOGGING == 1
FILE *logfile = NULL;
#define LOG(x,y,z) do { fwrite(x,y,z,logfile); fflush(logfile); } while(0)
#define LOGn(x,...) do { } while(0)
#endif

#endif //LOG_H
