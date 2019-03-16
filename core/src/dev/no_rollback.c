#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "no_rollback.h"
#include "config.h"
#include "log.h"

Result no_rollback_read(char buf[static VERSION_SIZE]) {
  FILE *f = fopen(NO_ROLLBACK_DEV_FILE, "r");
  if (f == NULL) {
    // create the file
    no_rollback_write_version(VERSION_MAGIC, VERSION);
    f = fopen(NO_ROLLBACK_DEV_FILE, "r");
  }
  fread(buf, 1, VERSION_SIZE, f);
  fclose(f);
  return Result_SUCCESS;
}

Result no_rollback_write(char buf[static VERSION_SIZE]) {
  FILE *f = fopen(NO_ROLLBACK_DEV_FILE, "w");
  if (f == NULL) {
    ERROR("no_rollback_write failed");
    return Result_NO_ROLLBACK_FILE_NOT_FOUND;
  }
  int bytes_written = fwrite(buf, 1, VERSION_SIZE, f);
  fclose(f);
  if (bytes_written != VERSION_SIZE) {
    INFO("fwrite returned %d, expecting %d", bytes_written, VERSION_SIZE);
    return Result_NO_ROLLBACK_FILE_NOT_FOUND;
  }
  return Result_SUCCESS;
}

