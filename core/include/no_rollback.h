#pragma once

#include <squareup/subzero/internal.pb.h>

#include "config.h"

Result no_rollback(void);
Result no_rollback_write_version(uint32_t magic, uint32_t version);

Result no_rollback_read(char buf[static VERSION_SIZE]);
Result no_rollback_write(char buf[static VERSION_SIZE]);
