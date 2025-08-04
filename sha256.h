#ifndef SHA256_H
#define SHA256_H

#include <vector>
#include <cstdint>

class SHA256 {
public:
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data);
};

#endif
