#include "btc.hpp"
#include <string>
#include <stdexcept>
#include <array>
#include <vector>
#include <span>
#include <algorithm>
#include <utility>
#include <concepts>
#include <cstdint>
#include <cstddef>
#include <cmath>

template <std::unsigned_integral numType>
constexpr numType rotr(numType num, int count) noexcept
{
	constexpr int numTypeBits = sizeof(numType) * 8;
	count %= numTypeBits;
	return (num >> count) | (num << (numTypeBits - count));
}

template <std::unsigned_integral numType>
constexpr numType reverse_endian(numType num) noexcept
{
	numType output = 0;

	for (int byteIndex = 0; byteIndex < sizeof(numType); ++byteIndex)
	{
		const std::uint8_t byteValue = static_cast<std::uint8_t>(
			num >> ((sizeof(numType) - byteIndex - 1) * 8)
		);

		output |= static_cast<numType>(byteValue) << (byteIndex * 8);
	}

	return output;
}

static int HexCharToValue(char hexChar)
{
	if ((hexChar >= '0') && (hexChar <= '9'))
		return hexChar - '0';
	else if ((hexChar >= 'a') && (hexChar <= 'f'))
		return 10 + (hexChar - 'a');
	else if ((hexChar >= 'A') && (hexChar <= 'F'))
		return 10 + (hexChar - 'A');
	else
		throw std::invalid_argument{ "Hexadecimal characters: 0-9/a-f" };
}

static std::array<std::uint8_t, 32> ToU256(std::string hexStr)
{
	if (hexStr.starts_with("0x"))
		hexStr.erase(hexStr.begin(), hexStr.begin() + 2);

	const auto newStartIter = std::find_if(hexStr.begin(), hexStr.end(),
		[](char c) {return c != '0'; });

	if (newStartIter == hexStr.end())
		return std::array<std::uint8_t, 32>{};

	hexStr.erase(hexStr.begin(), newStartIter);

	if (hexStr.size() > 64)
		throw std::invalid_argument{ "Hexadecimal string is too long" };

	std::string temp(64 - hexStr.size(), '0');
	hexStr.insert(hexStr.begin(), temp.begin(), temp.end());

	std::array<std::uint8_t, 32> output{};

	for (std::size_t i = 0; i < hexStr.size(); i += 2)
	{
		const char
			hexChar1 = hexStr[i],
			hexChar2 = hexStr[i + 1];

		output[i / 2] = static_cast<std::uint8_t>(
			(HexCharToValue(hexChar1) << 4) | HexCharToValue(hexChar2)
		);
	}

	return output;
}

static std::vector<std::uint8_t> ToBytes(std::string hexStr)
{
	if (hexStr.starts_with("0x"))
		hexStr.erase(hexStr.begin(), hexStr.begin() + 2);

	std::vector<std::uint8_t> output((hexStr.size() % 2 == 0)
		? (hexStr.size() / 2) : (hexStr.size() / 2 + 1), 0);

	for (std::size_t i = 0; i < hexStr.size(); i += 2)
	{
		const char
			hexChar1 = hexStr[i],
			hexChar2 = (i + 1 < hexStr.size()) ? hexStr[i + 1] : '0';

		output[i / 2] = static_cast<std::uint8_t>(
			(HexCharToValue(hexChar1) << 4) | HexCharToValue(hexChar2)
			);
	}

	return output;
}

btc::block_header btc::big_endian::create_block(std::uint32_t version, std::string prevBlockHash,
	std::string merkleRoot, std::uint32_t timestamp, std::uint32_t bits, std::uint32_t nonce)
{
	return block_header{
		.m_version = version,
		.m_prevBlockHash = ToU256(prevBlockHash),
		.m_merkleRoot = ToU256(merkleRoot),
		.m_timestamp = timestamp,
		.m_bits = bits,
		.m_nonce = nonce
	};
}

static constexpr std::array<std::uint32_t, 64> K{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

std::array<std::uint32_t, 8> btc::apply_sha256(std::span<const std::uint8_t> bytes) noexcept
{
	const std::size_t ArraySize = bytes.size();
	const std::size_t BinarySize = ArraySize * 8;
	const std::size_t pBinarySize = [BinarySize]() {
		std::size_t size = BinarySize + 1;
		while (size % 512 != 448)
			++size;
		size += 64;
		return size;
	}();

	std::array<std::uint32_t, 8> H{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

	std::vector<std::uint8_t> preprocessedBytes(pBinarySize / 8, 0);

	for (std::size_t i = 0; i < ArraySize; ++i)
		preprocessedBytes[i] = bytes[i];
	preprocessedBytes[ArraySize] = 128;

	preprocessedBytes[pBinarySize / 8 - 8] = static_cast<std::uint8_t>(BinarySize >> 56);
	preprocessedBytes[pBinarySize / 8 - 7] = static_cast<std::uint8_t>(BinarySize >> 48);
	preprocessedBytes[pBinarySize / 8 - 6] = static_cast<std::uint8_t>(BinarySize >> 40);
	preprocessedBytes[pBinarySize / 8 - 5] = static_cast<std::uint8_t>(BinarySize >> 32);
	preprocessedBytes[pBinarySize / 8 - 4] = static_cast<std::uint8_t>(BinarySize >> 24);
	preprocessedBytes[pBinarySize / 8 - 3] = static_cast<std::uint8_t>(BinarySize >> 16);
	preprocessedBytes[pBinarySize / 8 - 2] = static_cast<std::uint8_t>(BinarySize >> 8);
	preprocessedBytes[pBinarySize / 8 - 1] = static_cast<std::uint8_t>(BinarySize);

	for (std::size_t pIndex = 0; pIndex < pBinarySize; pIndex += 512)
	{
		const std::size_t offset = pIndex / 8;
		std::array<std::uint32_t, 64> W{};

		for (std::size_t i = 0; i < 16; ++i)
		{
			const std::uint8_t
				byte1 = preprocessedBytes[offset + i * 4],
				byte2 = preprocessedBytes[offset + i * 4 + 1],
				byte3 = preprocessedBytes[offset + i * 4 + 2],
				byte4 = preprocessedBytes[offset + i * 4 + 3];

			W[i] = (static_cast<std::uint32_t>(byte1) << 24)
				| (static_cast<std::uint32_t>(byte2) << 16)
				| (static_cast<std::uint32_t>(byte3) << 8)
				| byte4;
		}

		for (std::size_t i = 16; i < 64; ++i)
		{
			const std::uint32_t
				s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >> 3),
				s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >> 10);
			W[i] = W[i - 16] + s0 + W[i - 7] + s1;
		}

		std::uint32_t
			a = H[0],
			b = H[1],
			c = H[2],
			d = H[3],
			e = H[4],
			f = H[5],
			g = H[6],
			h = H[7];

		for (std::size_t i = 0; i < 64; ++i)
		{
			const std::uint32_t
				S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25),
				ch = (e & f) ^ ((~e) & g),
				temp1 = h + S1 + ch + K[i] + W[i];

			const std::uint32_t
				S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22),
				maj = (a & b) ^ (a & c) ^ (b & c),
				temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;
	}

	return H;
}

std::array<std::uint8_t, 32> btc::digest_to_bytes(const std::array<std::uint32_t, 8>& hash) noexcept
{
	std::array<std::uint8_t, 32> output{};

	for (std::size_t i = 0; i < 8; ++i)
	{
		const std::uint32_t dWord = hash[i];
		output[i * 4] = static_cast<std::uint8_t>(dWord >> 24);
		output[i * 4 + 1] = static_cast<std::uint8_t>(dWord >> 16);
		output[i * 4 + 2] = static_cast<std::uint8_t>(dWord >> 8);
		output[i * 4 + 3] = static_cast<std::uint8_t>(dWord);
	}

	return output;
}

std::array<std::uint8_t, 80> btc::serialize(const block_header& header) noexcept
{
	std::array<std::uint8_t, 80> output{};
	std::size_t writeIndex = 0;

	auto WriteU32 = [&](std::uint32_t dWord) {
		output[writeIndex] = static_cast<std::uint8_t>(dWord);
		++writeIndex;
		output[writeIndex] = static_cast<std::uint8_t>(dWord >> 8);
		++writeIndex;
		output[writeIndex] = static_cast<std::uint8_t>(dWord >> 16);
		++writeIndex;
		output[writeIndex] = static_cast<std::uint8_t>(dWord >> 24);
		++writeIndex;
	};

	auto WriteU256 = [&](const std::array<std::uint8_t, 32>& hash) {
		for (auto iter = hash.rbegin(); iter != hash.rend(); ++iter)
		{
			output[writeIndex] = *iter;
			++writeIndex;
		}
	};

	WriteU32(header.m_version);
	WriteU256(header.m_prevBlockHash);
	WriteU256(header.m_merkleRoot);
	WriteU32(header.m_timestamp);
	WriteU32(header.m_bits);
	WriteU32(header.m_nonce);

	return output;
}

btc::block_header btc::deserialize(const std::array<std::uint8_t, 80>& bytes) noexcept
{
	auto to_u32 = [](std::uint8_t byte1, std::uint8_t byte2, std::uint8_t byte3,
		std::uint8_t byte4) {
			return (static_cast<std::uint32_t>(byte1) << 24)
				| (static_cast<std::uint32_t>(byte2) << 16)
				| (static_cast<std::uint32_t>(byte3) << 8)
				| byte4;
		};

	return block_header{
		.m_version = to_u32(bytes[0], bytes[1], bytes[2], bytes[3]),
		.m_prevBlockHash = [&bytes]() {
			std::array<std::uint8_t, 32> output{};
			for (std::size_t i = 0; i < 32; ++i)
				output[i] = bytes[4 + i];
			return output;
		}(),
		.m_merkleRoot = [&bytes]() {
			std::array<std::uint8_t, 32> output{};
			for (std::size_t i = 0; i < 32; ++i)
				output[i] = bytes[36 + i];
			return output;
		}(),
		.m_timestamp = to_u32(bytes[68], bytes[69], bytes[70], bytes[71]),
		.m_bits = to_u32(bytes[72], bytes[73], bytes[74], bytes[75]),
		.m_nonce = to_u32(bytes[76], bytes[77], bytes[78], bytes[79])
	};
}

std::array<std::uint8_t, 32> btc::hash_block(const block_header& header) noexcept
{
	const auto hash1 = apply_sha256(serialize(header));
	auto hash2 = apply_sha256(digest_to_bytes(hash1));
	std::reverse(hash2.begin(), hash2.end());

	for (std::uint32_t& dWordRef : hash2)
	{
		const std::uint8_t
			byte1 = static_cast<std::uint8_t>(dWordRef >> 24),
			byte2 = static_cast<std::uint8_t>(dWordRef >> 16),
			byte3 = static_cast<std::uint8_t>(dWordRef >> 8),
			byte4 = static_cast<std::uint8_t>(dWordRef);

		dWordRef = (static_cast<std::uint32_t>(byte4) << 24)
			| (static_cast<std::uint32_t>(byte3) << 16)
			| (static_cast<std::uint32_t>(byte2) << 8)
			| byte1;
	}

	return digest_to_bytes(hash2);
}

bool btc::is_valid(const block_header& header) noexcept
{
	const auto hash = hash_block(header);
	double
		hashValue = 0,
		intValue = 0;

	for (auto iter = hash.rbegin(); iter != hash.rend(); ++iter)
	{
		const std::uint8_t dWord = *iter;
		std::uint8_t n = 1;

		for (int i = 0; i < 8; ++i)
		{
			hashValue += ((dWord & n) != 0) * intValue;
			intValue *= 2;
			n <<= 1;
		}
	}

	return hashValue <= bits_to_target(header.m_bits);
}

double btc::bits_to_target(std::uint32_t bits) noexcept
{
	const std::uint8_t
		exponent = static_cast<std::uint8_t>(bits >> 24);
	const std::uint32_t mantissa = (bits << 8) >> 8;
	return mantissa * std::pow(2.0, 8 * (exponent - 3));
}

double btc::bits_to_difficulty(std::uint32_t bits) noexcept
{
	return bits_to_target(bits) / bits_to_target(486'604'799);
}

btc::tx_in btc::big_endian::create_input(std::string prevTxId, std::uint32_t vout,
	std::string scriptSig, std::uint32_t sequence)
{
	return tx_in{
		.m_prevTxId = ToU256(prevTxId),
		.m_vout = vout,
		.m_scriptSig = ToBytes(scriptSig),
		.m_sequence = sequence
	};
}

btc::tx_out btc::big_endian::create_output(std::uint64_t value, std::string scriptPubKey)
{
	return tx_out{
		.m_value = value,
		.m_scriptPubKey = ToBytes(scriptPubKey)
	};
}

btc::transaction btc::big_endian::create_transaction(std::uint32_t version,
	const std::vector<tx_in>& inputs, const std::vector<tx_out>& outputs,
	std::uint32_t locktime) noexcept
{
	return transaction{
		.m_version = version,
		.m_inputs = inputs,
		.m_outputs = outputs,
		.m_locktime = locktime
	};
}

static void WriteVarInt(std::vector<std::uint8_t>& out, std::uint64_t value)
{
	if (value < 0xfd)
		out.emplace_back(static_cast<std::uint8_t>(value));
	else if (value <= 0xffff)
	{
		out.emplace_back(0xfd);
		out.emplace_back(static_cast<std::uint8_t>(value));
		out.emplace_back(static_cast<std::uint8_t>(value >> 8));
	}
	else if (value <= 0xFFFFFFFF)
	{
		out.emplace_back(0xfe);
		for (int i = 0; i < 4; ++i)
			out.emplace_back(static_cast<std::uint8_t>(value >> (8 * i)));
	}
	else
	{
		out.emplace_back(0xff);
		for (int i = 0; i < 8; ++i)
			out.emplace_back(static_cast<std::uint8_t>(value >> (8 * i)));
	}
}

std::vector<std::uint8_t> btc::serialize(const transaction& tx) noexcept
{
	std::vector<std::uint8_t> output;

	auto WriteU32 = [&](std::uint32_t dWord) {
		output.emplace_back(static_cast<std::uint8_t>(dWord));
		output.emplace_back(static_cast<std::uint8_t>(dWord >> 8));
		output.emplace_back(static_cast<std::uint8_t>(dWord >> 16));
		output.emplace_back(static_cast<std::uint8_t>(dWord >> 24));
	};

	auto WriteU64 = [&](std::uint64_t qWord) {
		output.emplace_back(static_cast<std::uint8_t>(qWord));
		output.emplace_back(static_cast<std::uint8_t>(qWord >> 8));
		output.emplace_back(static_cast<std::uint8_t>(qWord >> 16));
		output.emplace_back(static_cast<std::uint8_t>(qWord >> 24));
		output.emplace_back(static_cast<std::uint8_t>(qWord >> 32));
		output.emplace_back(static_cast<std::uint8_t>(qWord >> 40));
		output.emplace_back(static_cast<std::uint8_t>(qWord >> 48));
		output.emplace_back(static_cast<std::uint8_t>(qWord >> 56));
	};

	auto WriteTxIn = [&](const tx_in& in) {
		output.insert(output.end(), in.m_prevTxId.rbegin(), in.m_prevTxId.rend());
		WriteU32(in.m_vout);

		WriteVarInt(output, in.m_scriptSig.size());
		output.insert(output.end(), in.m_scriptSig.begin(), in.m_scriptSig.end());

		WriteU32(in.m_sequence);
	};

	auto WriteTxOut = [&](const tx_out& out) {
		WriteU64(out.m_value);

		WriteVarInt(output, out.m_scriptPubKey.size());
		output.insert(output.end(), out.m_scriptPubKey.begin(), out.m_scriptPubKey.end());
	};

	WriteU32(tx.m_version);

	WriteVarInt(output, tx.m_inputs.size());
	for (const tx_in& in : tx.m_inputs)
		WriteTxIn(in);

	WriteVarInt(output, tx.m_outputs.size());
	for (const tx_out& out : tx.m_outputs)
		WriteTxOut(out);

	WriteU32(tx.m_locktime);

	return output;
}

std::array<std::uint8_t, 32> btc::hash_transaction(const transaction& tx) noexcept
{
	const auto hash1 = apply_sha256(serialize(tx));
	auto hash2 = apply_sha256(digest_to_bytes(hash1));
	std::reverse(hash2.begin(), hash2.end());

	for (std::uint32_t& dWordRef : hash2)
	{
		const std::uint8_t
			byte1 = static_cast<std::uint8_t>(dWordRef >> 24),
			byte2 = static_cast<std::uint8_t>(dWordRef >> 16),
			byte3 = static_cast<std::uint8_t>(dWordRef >> 8),
			byte4 = static_cast<std::uint8_t>(dWordRef);

		dWordRef = (static_cast<std::uint32_t>(byte4) << 24)
			| (static_cast<std::uint32_t>(byte3) << 16)
			| (static_cast<std::uint32_t>(byte2) << 8)
			| byte1;
	}

	return digest_to_bytes(hash2);
}

std::array<std::uint8_t, 32> btc::merkle_root(std::vector<std::array<std::uint8_t, 32>> hashes)
{
	if (hashes.empty())
		throw std::invalid_argument{ "Cannot compute the merkle root of 0 hashes" };

	while (hashes.size() > 1)
	{
		std::vector<std::array<std::uint8_t, 32>> newLayer;
		newLayer.reserve((hashes.size() % 2 == 0) ? (hashes.size() / 2) : (hashes.size() / 2 + 1));

		for (std::size_t i = 0; i < hashes.size(); i += 2)
		{
			std::vector<std::uint8_t> inputBytes;
			inputBytes.reserve(64);

			std::array<std::uint8_t, 32>
				left{ hashes[i] },
				right{ (i + 1 < hashes.size()) ? hashes[i + 1] : hashes[i] };

			inputBytes.insert(inputBytes.end(), left.rbegin(), left.rend());
			inputBytes.insert(inputBytes.end(), right.rbegin(), right.rend());

			const auto hash1 = apply_sha256(inputBytes);
			auto hash2 = apply_sha256(digest_to_bytes(hash1));

			std::reverse(hash2.begin(), hash2.end());
			for (std::uint32_t& dWordRef : hash2)
			{
				const std::uint8_t
					byte1 = static_cast<std::uint8_t>(dWordRef >> 24),
					byte2 = static_cast<std::uint8_t>(dWordRef >> 16),
					byte3 = static_cast<std::uint8_t>(dWordRef >> 8),
					byte4 = static_cast<std::uint8_t>(dWordRef);

				dWordRef = (static_cast<std::uint32_t>(byte4) << 24)
					| (static_cast<std::uint32_t>(byte3) << 16)
					| (static_cast<std::uint32_t>(byte2) << 8)
					| byte1;
			}

			newLayer.emplace_back(digest_to_bytes(hash2));
		}

		hashes = std::move(newLayer);
	}

	return hashes.front();
}