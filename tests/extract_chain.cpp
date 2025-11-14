#include <fstream>
#include <iostream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <cstring>

static constexpr uint32_t BLOCK_SIZE = 96 * 1024;
static constexpr uint32_t NUM_BLOCKS = 4608;

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <cache_file> <output> <num_blocks>\n";
        return 1;
    }
    
    std::ifstream cache(argv[1], std::ios::binary);
    std::ofstream out(argv[2], std::ios::binary);
    int want_blocks = std::stoi(argv[3]);
    
    // Read all slots to find the last written block
    std::vector<std::pair<int, std::vector<uint8_t>>> slots;
    std::vector<uint8_t> slot(BLOCK_SIZE);
    
    for (int i = 0; i < NUM_BLOCKS; ++i) {
        cache.read(reinterpret_cast<char*>(slot.data()), BLOCK_SIZE);
        uint32_t size = *reinterpret_cast<uint32_t*>(slot.data());
        
        if (size > 0 && size < BLOCK_SIZE - 4) {
            std::vector<uint8_t> data(size);
            memcpy(data.data(), slot.data() + 4, size);
            slots.push_back({i, std::move(data)});
        }
    }
    
    std::cout << "Found " << slots.size() << " valid blocks in cache\n";
    
    // Take the last N blocks (most recent)
    int start = std::max(0, (int)slots.size() - want_blocks);
    int written = 0;
    
    for (int i = start; i < slots.size(); ++i) {
        uint32_t size = slots[i].second.size();
        out.write(reinterpret_cast<char*>(&size), 4);
        out.write(reinterpret_cast<char*>(slots[i].second.data()), size);
        written++;
    }
    
    std::cout << "Extracted " << written << " consecutive blocks (slots " << slots[start].first << " to " << slots.back().first << ")\n";
    return 0;
}
