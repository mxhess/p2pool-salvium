#include <fstream>
#include <iostream>
#include <cstdint>

int main(int argc, char* argv[]) {
    std::ifstream in(argv[1], std::ios::binary);
    
    uint32_t size;
    in.read(reinterpret_cast<char*>(&size), 4);
    
    std::cout << "First block size: " << size << " bytes\n";
    std::cout << "Total blocks in file: ";
    
    int count = 1;
    while (in) {
        in.seekg(size, std::ios::cur);
        in.read(reinterpret_cast<char*>(&size), 4);
        if (in) count++;
    }
    
    std::cout << count << "\n";
    return 0;
}
