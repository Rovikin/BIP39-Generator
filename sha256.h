#ifndef SHA256_H
#define SHA256_H

#include <vector>
#include <cstdint>

class SHA256 {
public:
    // Original interface (preserved for compatibility)
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data);

    // Non-allocating interface: writes 32 bytes into out[32]
    static void hash_raw(const uint8_t* data, size_t len, uint8_t out[32]);
};

#endif
