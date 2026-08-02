// SPDX-License-Identifier: GPL-2.0
// See kb_sha256.h for why this exists instead of linking OpenSSL.
// Straightforward FIPS 180-4 SHA-256 — single-shot, whole-buffer API
// only (kb_sha256_file() reads the whole file before hashing), which is
// fine for the executable-sized binaries CWP hashes; not intended as a
// general streaming-hash API.

#include "kb_sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct kb_sha256_ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buffer[64];
    size_t   buffer_len;
};

static const uint32_t kb_sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

#define KB_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void kb_sha256_transform(struct kb_sha256_ctx *ctx, const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = KB_ROTR(w[i - 15], 7) ^ KB_ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = KB_ROTR(w[i - 2], 17) ^ KB_ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t s1 = KB_ROTR(e, 6) ^ KB_ROTR(e, 11) ^ KB_ROTR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + ch + kb_sha256_k[i] + w[i];
        uint32_t s0 = KB_ROTR(a, 2) ^ KB_ROTR(a, 13) ^ KB_ROTR(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void kb_sha256_init(struct kb_sha256_ctx *ctx)
{
    static const uint32_t iv[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    };
    memcpy(ctx->state, iv, sizeof(iv));
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

static void kb_sha256_update(struct kb_sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->bitlen += (uint64_t)len * 8;
    while (len > 0) {
        size_t take = 64 - ctx->buffer_len;
        if (take > len) take = len;
        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        data += take;
        len -= take;
        if (ctx->buffer_len == 64) {
            kb_sha256_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

static void kb_sha256_final(struct kb_sha256_ctx *ctx, uint8_t out[KB_SHA256_DIGEST_SIZE])
{
    uint64_t bitlen = ctx->bitlen;
    uint8_t pad = 0x80;
    kb_sha256_update(ctx, &pad, 1);

    uint8_t zero = 0x00;
    while (ctx->buffer_len != 56)
        kb_sha256_update(ctx, &zero, 1);

    uint8_t len_bytes[8];
    for (int i = 0; i < 8; i++)
        len_bytes[i] = (uint8_t)(bitlen >> (56 - i * 8));
    // Append directly rather than via kb_sha256_update (which would
    // re-enter the padding branch above) — buffer_len is exactly 56 here.
    memcpy(ctx->buffer + 56, len_bytes, 8);
    kb_sha256_transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

int kb_sha256_file(const char *path, uint8_t out[KB_SHA256_DIGEST_SIZE])
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    struct kb_sha256_ctx ctx;
    kb_sha256_init(&ctx);

    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        kb_sha256_update(&ctx, buf, n);
    }
    if (ferror(f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    kb_sha256_final(&ctx, out);
    return 0;
}

// Bounded linear cache — CWP protects a small number of distinct
// executables per host (CWP.md §15's sizing rationale), so a fixed small
// array with round-robin eviction on overflow is simpler than a real
// hash table and comfortably sufficient.
#define KB_SHA256_CACHE_SIZE 128

struct kb_sha256_cache_entry {
    int      valid;
    dev_t    dev;
    ino_t    ino;
    time_t   mtime;
    uint8_t  hash[KB_SHA256_DIGEST_SIZE];
};

static struct kb_sha256_cache_entry kb_sha256_cache[KB_SHA256_CACHE_SIZE];
static int kb_sha256_cache_next_slot;

int kb_sha256_cached_file(const char *path, uint8_t out[KB_SHA256_DIGEST_SIZE])
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    for (int i = 0; i < KB_SHA256_CACHE_SIZE; i++) {
        struct kb_sha256_cache_entry *e = &kb_sha256_cache[i];
        if (e->valid && e->dev == st.st_dev && e->ino == st.st_ino && e->mtime == st.st_mtime) {
            memcpy(out, e->hash, KB_SHA256_DIGEST_SIZE);
            return 0;
        }
    }

    if (kb_sha256_file(path, out) != 0) return -1;

    struct kb_sha256_cache_entry *slot = &kb_sha256_cache[kb_sha256_cache_next_slot];
    slot->valid = 1;
    slot->dev = st.st_dev;
    slot->ino = st.st_ino;
    slot->mtime = st.st_mtime;
    memcpy(slot->hash, out, KB_SHA256_DIGEST_SIZE);
    kb_sha256_cache_next_slot = (kb_sha256_cache_next_slot + 1) % KB_SHA256_CACHE_SIZE;

    return 0;
}

void kb_sha256_to_hex(const uint8_t hash[KB_SHA256_DIGEST_SIZE], char out[65])
{
    static const char hexdigits[] = "0123456789abcdef";
    for (int i = 0; i < KB_SHA256_DIGEST_SIZE; i++) {
        out[i * 2]     = hexdigits[(hash[i] >> 4) & 0xF];
        out[i * 2 + 1] = hexdigits[hash[i] & 0xF];
    }
    out[64] = '\0';
}
