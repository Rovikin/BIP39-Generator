#include <iostream>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include "sha256.h"

// ── Wordlist ─────────────────────────────────────────────────────────────────
static const char* const wordlist[] = {
#include "wordlist.inc"
};
static const int WORDLIST_SIZE = 2048;

// ── Entropy source ────────────────────────────────────────────────────────────
// /dev/urandom fd is opened once at startup and reused for all iterations.
// Reusing the fd is cryptographically equivalent to reopening it each time:
// /dev/urandom on Linux >= 3.17 draws from a fully-seeded CSPRNG regardless
// of how many times it is opened.
static int urandom_fd = -1;

static void init_entropy() {
    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0) {
        perror("open /dev/urandom");
        exit(1);
    }
}

static void fill_entropy(uint8_t* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(urandom_fd, buf + got, n - got);
        if (r <= 0) {
            perror("read /dev/urandom");
            exit(1);
        }
        got += (size_t)r;
    }
}

// ── BIP-39 mnemonic generation ────────────────────────────────────────────────
//
// All intermediate state lives on the stack; zero heap allocation per seed.
//
// Security:
//   - entropy_buf and hash_buf are explicitly zeroed after use via a volatile
//     pointer to prevent the compiler from optimizing away the wipe.
//   - Output buffer (out) is caller-owned stack memory; caller is responsible
//     for zeroing if the mnemonic is sensitive.
//
static void generate_mnemonic(int bits, char* out, size_t out_size) {
    const int entropy_bytes = bits / 8;        // 16 (12-word) or 32 (24-word)
    const int cs_bits       = bits / 32;       //  4 or 8
    const int total_bits    = bits + cs_bits;  // 132 or 264
    const int word_count    = total_bits / 11; // 12 or 24

    uint8_t entropy_buf[32] = {0};
    uint8_t hash_buf[32]    = {0};

    fill_entropy(entropy_buf, (size_t)entropy_bytes);
    SHA256::hash_raw(entropy_buf, (size_t)entropy_bytes, hash_buf);

    // Extract 11-bit word indices directly from the bit stream without
    // building an intermediate string representation.
    auto get_bit = [&](int idx) -> int {
        if (idx < bits)
            return (entropy_buf[idx / 8] >> (7 - idx % 8)) & 1;
        else {
            int ci = idx - bits;
            return (hash_buf[ci / 8] >> (7 - ci % 8)) & 1;
        }
    };

    size_t pos = 0;
    for (int w = 0; w < word_count; ++w) {
        int idx = 0;
        for (int b = 0; b < 11; ++b)
            idx = (idx << 1) | get_bit(w * 11 + b);

        const char* word = wordlist[idx];
        size_t wlen = strlen(word);

        if (pos + wlen + 2 <= out_size) {
            memcpy(out + pos, word, wlen);
            pos += wlen;
            if (w < word_count - 1)
                out[pos++] = ' ';
        }
    }
    out[pos] = '\0';

    // Wipe sensitive material — volatile prevents compiler from eliding this.
    volatile uint8_t* vp = entropy_buf;
    for (int i = 0; i < 32; ++i) vp[i] = 0;
    vp = hash_buf;
    for (int i = 0; i < 32; ++i) vp[i] = 0;
}

// ── main ──────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (WORDLIST_SIZE != 2048) {
        std::cerr << "Wordlist tidak valid (harus 2048 kata).\n";
        return 1;
    }

    int count = 1;
    int bits  = 128;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--words") == 0 && i + 1 < argc) {
            int words = atoi(argv[++i]);
            if      (words == 12) bits = 128;
            else if (words == 24) bits = 256;
            else {
                std::cerr << "--words hanya mendukung 12 atau 24\n";
                return 1;
            }
        }
    }

    init_entropy();

    // 24 words x ~8 chars + 23 spaces + null = ~216 bytes; 256 gives headroom.
    char mnemonic[256];

    for (int i = 0; i < count; ++i) {
        generate_mnemonic(bits, mnemonic, sizeof(mnemonic));
        std::cout << mnemonic << '\n';
    }

    return 0;
}
