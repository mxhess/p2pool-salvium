#include "../src/side_chain.h"
#include <iostream>
#include <iomanip>

int main() {
    using namespace p2pool;
    SideChain s(nullptr, NetworkType::Mainnet, "salvium_main");
    auto& id = s.consensus_id();
    
    std::cout << "constexpr uint64_t expected_consensus_id[HASH_SIZE / sizeof(uint64_t)] = {\n";
    for (int i = 0; i < 4; i++) {
        std::cout << "    0x" << std::hex << std::setfill('0') << std::setw(16) 
                  << reinterpret_cast<const uint64_t*>(id.data())[i] << "ull";
        if (i < 3) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "};\n";
    return 0;
}
