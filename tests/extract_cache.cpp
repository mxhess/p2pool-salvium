#include <fstream>
#include <iostream>
#include <vector>
#include <cstdint>

static constexpr uint32_t BLOCK_SIZE = 96 * 1024;

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <cache_file> <output> <num_blocks>\n";
        return 1;
    }
    
    std::ifstream in(argv[1], std::ios::binary);
    std::ofstream out(argv[2], std::ios::binary);
    int max_blocks = std::stoi(argv[3]);
    
    std::vector<uint8_t> slot(BLOCK_SIZE);
    int blocks_written = 0;
    
    while (in && blocks_written < max_blocks) {
        // Read 96KB slot
        in.read(reinterpret_cast<char*>(slot.data()), BLOCK_SIZE);
        if (!in) break;
        
        // Read size from first 4 bytes
        uint32_t size = *reinterpret_cast<uint32_t*>(slot.data());
        
        // Skip empty slots
        if (size == 0 || size > BLOCK_SIZE - 4) continue;
        
        // Write: size + data
        out.write(reinterpret_cast<char*>(&size), sizeof(size));
        out.write(reinterpret_cast<char*>(slot.data() + 4), size);
        blocks_written++;
    }
    
    std::cout << "Extracted " << blocks_written << " blocks\n";
    return 0;
}
