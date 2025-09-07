#pragma once

#include <string>
#include <array>
#include <vector>
#include <span>
#include <cstdint>

namespace btc
{
	struct block_header
	{
		std::uint32_t m_version;
		std::array<std::uint8_t, 32> m_prevBlockHash;
		std::array<std::uint8_t, 32> m_merkleRoot;
		std::uint32_t m_timestamp;
		std::uint32_t m_bits;
		std::uint32_t m_nonce;
	};

	struct tx_in
	{
		std::array<std::uint8_t, 32> m_prevTxId;
		std::uint32_t m_vout;
		std::vector<std::uint8_t> m_scriptSig;
		std::uint32_t m_sequence;
	};

	struct tx_out
	{
		std::uint64_t m_value;
		std::vector<std::uint8_t> m_scriptPubKey;
	};

	struct transaction
	{
		std::uint32_t m_version;
		std::vector<tx_in> m_inputs;
		std::vector<tx_out> m_outputs;
		std::uint32_t m_locktime;
	};

	namespace big_endian
	{
		block_header create_block(std::uint32_t version, std::string prevBlockHash,
			std::string merkleRoot, std::uint32_t timestamp, std::uint32_t bits,
			std::uint32_t nonce);

		tx_in create_input(std::string prevTxId, std::uint32_t vout,
			std::string scriptSig, std::uint32_t sequence);

		tx_out create_output(std::uint64_t value, std::string scriptPubKey);

		transaction create_transaction(std::uint32_t version, const std::vector<tx_in>& inputs,
			const std::vector<tx_out>& outputs, std::uint32_t locktime) noexcept;
	}

	std::array<std::uint32_t, 8> apply_sha256(std::span<const std::uint8_t>) noexcept;
	std::array<std::uint8_t, 32> digest_to_bytes(const std::array<std::uint32_t, 8>&) noexcept;
								//hash-to-bytes
	
	std::array<std::uint8_t, 80> serialize(const block_header&) noexcept;
	block_header deserialize(const std::array<std::uint8_t, 80>&) noexcept;
	std::array<std::uint8_t, 32> hash_block(const block_header&) noexcept;
	bool is_valid(const block_header&) noexcept;

	std::vector<std::uint8_t> serialize(const transaction&) noexcept;
	std::array<std::uint8_t, 32> hash_transaction(const transaction&) noexcept;

	double bits_to_target(std::uint32_t) noexcept;
	double bits_to_difficulty(std::uint32_t) noexcept;

	std::array<std::uint8_t, 32> merkle_root(std::vector<std::array<std::uint8_t, 32>>);
}