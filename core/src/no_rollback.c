#include "no_rollback.h"
#include "log.h"

/**
 * Prevents running an older version of the CodeSafe software after a newer version has run. This limits the attack
 * surface to only the current version of the signed CodeSafe vs any version which ever existed.
 *
 * This code is dev/ncipher agnostic. In dev, we use a file (/tmp/.subzero-no-rollback) whereas with a nCipher we use
 * the NVRAM, which supports setting ACLs.
 */
Result no_rollback_check(bool allow_upgrade, uint32_t expected_magic, uint32_t expected_version);

Result no_rollback(void) {
  INFO("in no_rollback");

  return no_rollback_check(true, VERSION_MAGIC, VERSION);
}

Result no_rollback_check(bool allow_upgrade, uint32_t expected_magic, uint32_t expected_version) {
  char buf[VERSION_SIZE];

  Result r = no_rollback_read(buf);
  if (r != Result_SUCCESS) {
    ERROR("no_rollback_check failed");
    return r;
  }

  uint32_t magic, version, matches;
  matches = sscanf(buf, "%u-%u", &magic, &version);
  if (matches != 2) {
    ERROR("no_rollback_check failed");
    return Result_NO_ROLLBACK_INVALID_FORMAT;
  }
  if (magic != expected_magic) {
    ERROR("no_rollback_check failed");
    return Result_NO_ROLLBACK_INVALID_MAGIC;
  }

  if (allow_upgrade && (version < expected_version)) {
    INFO("bumping version from %d => %d", version, expected_version);
    r = no_rollback_write_version(expected_magic, expected_version);
    if (r != Result_SUCCESS) {
      return r;
    }

    // re-read to ensure everything is ok
    return no_rollback_check(false, expected_magic, expected_version);
  } else if (version == expected_version) {
    INFO("no_rollback: ok");
    return Result_SUCCESS;
  }
  ERROR("no_rollback_check failed");
  return Result_NO_ROLLBACK_INVALID_VERSION;
}

Result no_rollback_write_version(uint32_t magic, uint32_t version) {
  char buf[VERSION_SIZE];
  bzero(buf, VERSION_SIZE);
  snprintf(buf, sizeof(buf), "%d-%d", magic, version);
  return no_rollback_write(buf);
}
