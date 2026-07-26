/**
 * @file mnv_hal_host.c
 * @brief Host (Linux/macOS/Windows) HAL — for unit testing only
 */

#include "mnv_hal.h"

#if defined(MNV_TARGET_HOST)
#include <stdio.h>
#include <stdlib.h>

void mnv_hal_fatal(void)
{
    fprintf(stderr, "[MINERVA] FATAL: security violation — halting.\n");
    abort();
}

#endif
