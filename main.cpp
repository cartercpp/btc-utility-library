#include <iostream>
#include <iomanip>
#include <cstdint>
#include "btc.hpp"

int main()
{
	const auto block = btc::big_endian::create_block(
		0x22812000,
		"00000000000000000001804e83d263f373a6bd0eab58e1fe578218bf678ffeee",
		"1502c7c49d4a1cf4e4eecd5f13be4e6d85f19fa46da76d2bc6bb4fa2b49eb76e",
		1757203247,
		386011564,
		3781194024
	);
	const auto blockHash = btc::hash_block(block);

	std::cout << "Hash of block 913,501...\n";
	for (const std::uint8_t byte : blockHash)
		std::cout << std::hex << std::setw(2) << std::setfill('0') << int(byte);
	std::cin.get();
	
	return 0;
}