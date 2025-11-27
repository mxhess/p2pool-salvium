#include "protocol_tx_hash.h"
#include "keccak.h"
#include <cstring>
#include <vector>

namespace p2pool {

// Minimal varint encoder matching salviumd's format
static void write_varint(uint64_t value, std::vector<uint8_t>& dest) {
    while (value >= 0x80) {
        dest.push_back(static_cast<uint8_t>((value & 0x7f) | 0x80));
        value >>= 7;
    }
    dest.push_back(static_cast<uint8_t>(value));
}

void calculate_protocol_tx_hash(uint64_t height, hash& result) {
    std::vector<uint8_t> prefix_serialized;
    prefix_serialized.reserve(32);
    
    // Serialize transaction_prefix (everything except RCT type byte)
    write_varint(4, prefix_serialized);           // version
    write_varint(60, prefix_serialized);          // unlock_time
    write_varint(1, prefix_serialized);           // vin.size()
    prefix_serialized.push_back(0xff);            // TXIN_GEN
    write_varint(height, prefix_serialized);      // gen.height
    write_varint(0, prefix_serialized);           // vout.size()
    write_varint(2, prefix_serialized);           // extra.size()
    prefix_serialized.push_back(0x02);            // extra[0]
    prefix_serialized.push_back(0x00);            // extra[1]
    write_varint(2, prefix_serialized);           // type = PROTOCOL
    
    // Hash the three components as salviumd does for v2+ transactions
    hash prefix_hash, base_rct_hash;
    uint8_t rct_type = 0;
    
    keccak(prefix_serialized.data(), prefix_serialized.size(), prefix_hash.h);
    keccak(&rct_type, 1, base_rct_hash.h);
    
    // Combine: prefix_hash + base_rct_hash + null_hash (32 zeros)
    uint8_t combined[HASH_SIZE * 3];
    memcpy(combined, prefix_hash.h, HASH_SIZE);
    memcpy(combined + HASH_SIZE, base_rct_hash.h, HASH_SIZE);
    memset(combined + HASH_SIZE * 2, 0, HASH_SIZE);  // null hash for RCTTypeNull
    
    keccak(combined, sizeof(combined), result.h);
}

} // namespace p2pool

