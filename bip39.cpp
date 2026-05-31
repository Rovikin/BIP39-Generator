#include <iostream>
#include <vector>
#include <random>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include "sha256.h" 

const std::vector<std::string> wordlist = {
#include "wordlist.inc"
};

std::vector<uint8_t> generate_entropy(int bits = 128) {
    std::vector<uint8_t> entropy(bits / 8);
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        std::cerr << "Gagal membuka /dev/urandom\n";
        exit(1);
    }
    if (fread(entropy.data(), 1, entropy.size(), urandom) != entropy.size()) {
        std::cerr << "Gagal membaca entropy\n";
        fclose(urandom);
        exit(1);
    }
    fclose(urandom);
    return entropy;
}

std::string to_bit_string(const std::vector<uint8_t>& bytes) {
    std::string bit_string;
    for (uint8_t byte : bytes) {
        for (int i = 7; i >= 0; --i) {
            bit_string += ((byte >> i) & 1) ? '1' : '0';
        }
    }
    return bit_string;
}

std::string get_checksum_bits(const std::vector<uint8_t>& entropy) {
    std::vector<uint8_t> hash = SHA256::hash(entropy);
    int cs_len = entropy.size() * 8 / 32;
    std::string checksum_bits;
    for (int i = 0; i < cs_len; ++i) {
        checksum_bits += ((hash[0] >> (7 - i)) & 1) ? '1' : '0';
    }
    return checksum_bits;
}

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

int main(int argc, char* argv[]) {
    if (wordlist.size() != 2048) {
        std::cerr << "Wordlist tidak valid (harus 2048 kata).\n";
        return 1;
    }

    int count = 1;
    int bits = 128;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--count" && i + 1 < argc) {
            count = std::stoi(argv[i + 1]);
            ++i;
        } else if (std::string(argv[i]) == "--words" && i + 1 < argc) {
            int words = std::stoi(argv[i + 1]);
            if (words == 24) bits = 256;
            else if (words == 12) bits = 128;
            else { std::cerr << "--words hanya mendukung 12 atau 24\n"; return 1; }
            ++i;
        }
    }

    for (int i = 0; i < count; ++i) {
        auto entropy = generate_entropy(bits);
        std::string mnemonic = entropy_to_mnemonic(entropy);
        std::cout << mnemonic << "\n";
    }

    return 0;
}
