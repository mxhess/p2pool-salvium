#pragma once

#include "common.h"
#include <cstdint>

namespace p2pool {

void calculate_protocol_tx_hash(uint64_t height, hash& result);

} // namespace p2pool
