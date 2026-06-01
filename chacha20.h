#ifndef CHACHA20_H
#define CHACHA20_H

#include <cstdint>
#include <cstddef>

// ChaCha20-based CSPRNG
//
// Usage:
//   ChaCha20RNG rng;
//   rng.seed_from_os();          // seed 32 bytes from /dev/urandom (once)
//   rng.fill(buf, n);            // fill n bytes with CSPRNG output
//
// Security properties:
//   - Seeded with 32 bytes (256 bits) of OS entropy via /dev/urandom
//   - ChaCha20 stream cipher: 256-bit key, 64-bit counter, 96-bit nonce
//   - Forward secrecy: key material wiped after seeding
//   - State wiped on destruction via volatile zeroing
//   - Output is indistinguishable from random (IND-CPA secure)
//
// Reference: RFC 8439

class ChaCha20RNG {
public:
    ChaCha20RNG();
    ~ChaCha20RNG();

    // Seed from /dev/urandom. Must be called once before fill().
    // Aborts on failure.
    void seed_from_os();

    // Fill buf[0..n-1] with CSPRNG bytes.
    void fill(uint8_t* buf, size_t n);

private:
    // ChaCha20 state: 16 x uint32 = 512 bits
    // Layout: constants(4) | key(8) | counter(1) | nonce(3)
    uint32_t state_[16];

    // Keystream buffer: one ChaCha20 block = 64 bytes
    uint8_t  keystream_[64];
    size_t   ks_pos_;   // current position in keystream buffer

    void block();       // generate one 64-byte block into keystream_
    void wipe();        // volatile zero of all sensitive state
};

#endif
