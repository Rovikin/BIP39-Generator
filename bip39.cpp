#include <iostream>
#include <vector>
#include <random>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include "sha256.h" // SHA256 implementation (pure C++) dari sha256.cpp

// Embed wordlist langsung dari seed.cpp
const std::vector<std::string> wordlist = {
#include "seed.cpp"
};

// Generate 128-bit entropy (default)
std::vector<uint8_t> generate_entropy(int bits = 128) {
    std::random_device rd;
    std::vector<uint8_t> entropy(bits / 8);
    for (auto& byte : entropy) byte = static_cast<uint8_t>(rd());
    return entropy;
}

// Convert bytes to bit string
std::string to_bit_string(const std::vector<uint8_t>& bytes) {
    std::string bit_string;
    for (uint8_t byte : bytes) {
        for (int i = 7; i >= 0; --i) {
            bit_string += ((byte >> i) & 1) ? '1' : '0';
        }
    }
    return bit_string;
}

// Get checksum bits from SHA256(entropy)
std::string get_checksum_bits(const std::vector<uint8_t>& entropy) {
    std::vector<uint8_t> hash = SHA256::hash(entropy);
    int cs_len = entropy.size() * 8 / 32;
    std::string checksum_bits;
    for (int i = 0; i < cs_len; ++i) {
        checksum_bits += ((hash[0] >> (7 - i)) & 1) ? '1' : '0';
    }
    return checksum_bits;
}

// Convert entropy + checksum => mnemonic words
std::string entropy_to_mnemonic(const std::vector<uint8_t>& entropy) {
    std::string entropy_bits = to_bit_string(entropy);
    std::string checksum_bits = get_checksum_bits(entropy);
    std::string full_bits = entropy_bits + checksum_bits;

    std::vector<std::string> words;
    for (size_t i = 0; i < full_bits.size(); i += 11) {
        std::string segment = full_bits.substr(i, 11);
        int index = std::stoi(segment, nullptr, 2);
        words.push_back(wordlist[index]);
    }

    std::ostringstream oss;
    for (size_t i = 0; i < words.size(); ++i) {
        oss << words[i];
        if (i != words.size() - 1) oss << " ";
    }
    return oss.str();
}

int main() {
    if (wordlist.size() != 2048) {
        std::cerr << "❌ Wordlist tidak valid (harus 2048 kata).\n";
        return 1;
    }

    auto entropy = generate_entropy(); // 128-bit
    std::string mnemonic = entropy_to_mnemonic(entropy);

    std::cout << "\n============================================\n\n";
    std::cout << mnemonic;
    std::cout << "\n\n============================================\n";

    return 0;
}
