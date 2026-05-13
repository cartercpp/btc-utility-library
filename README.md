# btc-utility-library

C++20 utilities for Bitcoin protocol primitives. Implemented from scratch with no third-party cryptography.

## What's in it

**Data model**
- `block_header` — version, previous block hash, Merkle root, timestamp, bits, nonce
- `transaction`, `tx_in`, `tx_out` — full UTXO transaction model

**Cryptography**
- `apply_sha256(std::span<const std::uint8_t>)` — SHA-256 hashing
- `hash_block` / `hash_transaction` — block and transaction hashing
- `merkle_root` — computes a Merkle root over a vector of transaction hashes

**Serialization**
- `serialize(block_header)` / `deserialize` — round-trip the 80-byte block header format
- `serialize(transaction)` — produces the variable-length transaction byte stream

**Validation**
- `is_valid(block_header)` — checks the proof-of-work target

**Difficulty**
- `bits_to_target` / `bits_to_difficulty` — converts the compact difficulty encoding to a target value and a numerical difficulty

A `big_endian` sub-namespace exposes factory functions (`create_block`, `create_input`, `create_output`, `create_transaction`) that take hex strings and handle endian-flipping internally, so callers don't have to.

## Build

```bash
g++ -std=c++20 -O2 main.cpp btc.cpp -o btc
./btc
```
