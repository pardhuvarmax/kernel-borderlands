// SPDX-License-Identifier: GPL-2.0
// Minimal, self-contained SHA-256 for CWP's hash-tier identity
// verification (docs/features/CWP.md §5, §15). No OpenSSL dev headers
// are available in this build environment (libcrypto.so is present at
// runtime, but /usr/include/openssl is not, and libssl-dev isn't
// installed) — rather than add a new external build dependency for one
// hash function, this is a small public-domain-style implementation
// (FIPS 180-4), self-contained and dependency-free like the rest of
// kb-core's userspace side.
#ifndef KB_SHA256_H
#define KB_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define KB_SHA256_DIGEST_SIZE 32

// Hashes the full contents of the file at path. Returns 0 on success
// (out filled with the 32-byte digest), -1 on any I/O error (file
// missing, unreadable, etc.) — callers must treat -1 as "could not
// verify", not "hash is zero".
int kb_sha256_file(const char *path, uint8_t out[KB_SHA256_DIGEST_SIZE]);

// Cached wrapper around kb_sha256_file(), keyed by (device, inode,
// mtime) so an unchanged binary is never re-hashed on every containment
// decision (CWP.md §15 "Hash caching"). Same return convention as
// kb_sha256_file().
int kb_sha256_cached_file(const char *path, uint8_t out[KB_SHA256_DIGEST_SIZE]);

// Renders a 32-byte digest as a 64-char lowercase hex string plus NUL
// terminator (out must be at least 65 bytes) — used for audit logging.
void kb_sha256_to_hex(const uint8_t hash[KB_SHA256_DIGEST_SIZE], char out[65]);

#endif // KB_SHA256_H
