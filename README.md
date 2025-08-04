# BIP39 Generator

C++ offline mnemonic tool with embedded wordlist and SHA256.

This is a tool to generate the Bitcoin standard 12-word seed phrase (BIP-39). Compatible with various other crypto wallets such as Ethereum, Binance, Solana, Litecoin, Tron, and others. And most importantly, everything runs offline

## How to use

follow this command in termux:

```
pkg update && pkg upgrade -y
pkg install g++ curl git
git clone https://github.com/Rovikin/BIP39-Generator.git
cd BIP39-Generator
g++ bip39.cpp sha256.cpp -o bip39
./bip39
```

to run just type the command

```
./bip39
```

---
