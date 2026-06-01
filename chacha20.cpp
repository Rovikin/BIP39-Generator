// chacha20.cpp
// ChaCha20 stream cipher used as CSPRNG (RFC 8439)
//
// Key:     256 bits (32 bytes) from /dev/urandom
// Nonce:   96 bits  (12 bytes) zeroed — safe because key is never reused
// Counter: 32 bits, starts at 0
//
// Security note:
//   A fixed nonce is acceptable here because each program invocation generates
//   a fresh random key. The (key, nonce) pair is therefore unique per session.

#include "chacha20.h"
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>

// ── ChaCha20 primitives ───────────────────────────────────────────────────────

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d)        \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d,  8); \
    c += d; b ^= c; b = ROTL32(b,  7)

static void chacha20_block(const uint32_t in[16], uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, in, 64);

    for (int i = 0; i < 10; ++i) {
        // Column rounds
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        // Diagonal rounds
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }

    for (int i = 0; i < 16; ++i) {
        uint32_t v = x[i] + in[i];
        out[i*4]   = (uint8_t)(v        & 0xff);
        out[i*4+1] = (uint8_t)((v >>  8) & 0xff);
        out[i*4+2] = (uint8_t)((v >> 16) & 0xff);
        out[i*4+3] = (uint8_t)((v >> 24) & 0xff);
    }
}

static inline uint32_t load_le32(const uint8_t* p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

// ── ChaCha20RNG ───────────────────────────────────────────────────────────────

ChaCha20RNG::ChaCha20RNG() : ks_pos_(64) {
    memset(state_,     0, sizeof(state_));
    memset(keystream_, 0, sizeof(keystream_));
}

ChaCha20RNG::~ChaCha20RNG() {
    wipe();
}

void ChaCha20RNG::seed_from_os() {
    // Read 32-byte key from /dev/urandom
    uint8_t key[32] = {0};

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/urandom");
        exit(1);
    }

    size_t got = 0;
    while (got < 32) {
        ssize_t r = read(fd, key + got, 32 - got);
        if (r <= 0) {
            perror("read /dev/urandom");
            close(fd);
            exit(1);
        }
        got += (size_t)r;
    }
    close(fd);

    // ChaCha20 initial state (RFC 8439 §2.3):
    // state[0..3]  = "expa", "nd 3", "2-by", "te k" (constants)
    // state[4..11] = key (256 bits)
    // state[12]    = counter (starts at 0)
    // state[13..15]= nonce (96 bits, zeroed — safe, key is fresh per session)

    state_[ 0] = 0x61707865;
    state_[ 1] = 0x3320646e;
    state_[ 2] = 0x79622d32;
    state_[ 3] = 0x6b206574;

    for (int i = 0; i < 8; ++i)
        state_[4 + i] = load_le32(key + i * 4);

    state_[12] = 0; // counter
    state_[13] = 0; // nonce[0]
    state_[14] = 0; // nonce[1]
    state_[15] = 0; // nonce[2]

    // Wipe key from stack
    volatile uint8_t* vp = key;
    for (int i = 0; i < 32; ++i) vp[i] = 0;

    // Pre-generate first block
    ks_pos_ = 64;
}

void ChaCha20RNG::block() {
    chacha20_block(state_, keystream_);
    // Increment 32-bit counter (state[12])
    state_[12]++;
    ks_pos_ = 0;
}

void ChaCha20RNG::fill(uint8_t* buf, size_t n) {
    size_t written = 0;
    while (written < n) {
        if (ks_pos_ >= 64)
            block();

        size_t avail = 64 - ks_pos_;
        size_t take  = (n - written < avail) ? (n - written) : avail;
        memcpy(buf + written, keystream_ + ks_pos_, take);
        ks_pos_  += take;
        written  += take;
    }
}

void ChaCha20RNG::wipe() {
    volatile uint32_t* vs = state_;
    for (int i = 0; i < 16; ++i) vs[i] = 0;
    volatile uint8_t* vk = keystream_;
    for (int i = 0; i < 64; ++i) vk[i] = 0;
    ks_pos_ = 64;
}
