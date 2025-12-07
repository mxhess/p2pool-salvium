/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2025 SChernykh <https://github.com/SChernykh>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"
#include "pool_block.h"
#include "keccak.h"
#include "side_chain.h"
#include "pow_hash.h"
#include "protocol_tx_hash.h"
#include "crypto.h"
#include "merkle.h"
#include <sstream>

LOG_CATEGORY(PoolBlock)

#include "pool_block_parser.inl"

namespace p2pool {

ReadWriteLock* PoolBlock::s_precalculatedSharesLock = nullptr;

PoolBlock::PoolBlock()
	: m_majorVersion(0)
	, m_minorVersion(0)
	, m_timestamp(0)
	, m_prevId{}
	, m_nonce(0)
	, m_txinGenHeight(0)
	, m_txkeyPub{}
	, m_extraNonceSize(0)
	, m_extraNonce(0)
	, m_merkleTreeDataSize(1)
	, m_merkleTreeData(0)
	, m_merkleRoot{}
	, m_txkeySecSeed{}
	, m_txkeySec{}
	, m_parent{}
	, m_sidechainHeight(0)
	, m_difficulty{}
	, m_cumulativeDifficulty{}
	, m_merkleProof{}
	, m_merkleProofPath(0)
	, m_mergeMiningExtra{}
	, m_sidechainExtraBuf{}
	, m_sidechainId{}
	, m_depth(0)
	, m_verified(false)
	, m_invalid(false)
	, m_broadcasted(false)
	, m_wantBroadcast(false)
	, m_precalculated(false)
	, m_localTimestamp(seconds_since_epoch())
	, m_receivedTimestamp(0)
	, m_auxNonce(0)
{
}

PoolBlock::PoolBlock(const PoolBlock& b)
{
	operator=(b);
}

// cppcheck-suppress operatorEqVarError
PoolBlock& PoolBlock::operator=(const PoolBlock& b)
{
	if (this == &b) {
		return *this;
	}

#if POOL_BLOCK_DEBUG
	m_mainChainDataDebug = b.m_mainChainDataDebug;
	m_sideChainDataDebug = b.m_sideChainDataDebug;
#endif

	m_majorVersion = b.m_majorVersion;
	m_minorVersion = b.m_minorVersion;
	m_timestamp = b.m_timestamp;
	m_prevId = b.m_prevId;
	m_nonce = b.m_nonce;
	m_txinGenHeight = b.m_txinGenHeight;
	m_ephPublicKeys = b.m_ephPublicKeys;
	m_outputAmounts = b.m_outputAmounts;
        m_viewTags = b.m_viewTags;
        m_encryptedAnchors = b.m_encryptedAnchors;
        m_amountBurnt = b.m_amountBurnt;
	m_txkeyPub = b.m_txkeyPub;
        m_additionalPubKeys = b.m_additionalPubKeys;
	m_extraNonceSize = b.m_extraNonceSize;
	m_extraNonce = b.m_extraNonce;
	m_merkleTreeDataSize = b.m_merkleTreeDataSize;
	m_merkleTreeData = b.m_merkleTreeData;
	m_merkleRoot = b.m_merkleRoot;
	m_transactions = b.m_transactions;
	m_minerWallet = b.m_minerWallet;
	m_txkeySecSeed = b.m_txkeySecSeed;
	m_txkeySec = b.m_txkeySec;
	m_parent = b.m_parent;
	m_uncles = b.m_uncles;
	m_sidechainHeight = b.m_sidechainHeight;
	m_difficulty = b.m_difficulty;
	m_cumulativeDifficulty = b.m_cumulativeDifficulty;
	m_merkleProof = b.m_merkleProof;
	m_merkleProofPath = b.m_merkleProofPath;
	m_mergeMiningExtra = b.m_mergeMiningExtra;
	memcpy(m_sidechainExtraBuf, b.m_sidechainExtraBuf, sizeof(m_sidechainExtraBuf));
	m_sidechainId = b.m_sidechainId;
	m_depth = b.m_depth;
	m_verified = b.m_verified;
	m_invalid = b.m_invalid;
	m_broadcasted = b.m_broadcasted;
	m_wantBroadcast = b.m_wantBroadcast;
	m_precalculated = b.m_precalculated;
	{
		WriteLock lock(*s_precalculatedSharesLock);
		m_precalculatedShares = b.m_precalculatedShares;
	}

	m_localTimestamp = seconds_since_epoch();
	m_receivedTimestamp = b.m_receivedTimestamp;

	m_auxChains = b.m_auxChains;
	m_auxNonce = b.m_auxNonce;

	m_hashingBlob = b.m_hashingBlob;

	m_powHash = b.m_powHash;
	m_seed = b.m_seed;

	return *this;
}

std::vector<uint8_t> PoolBlock::serialize_mainchain_data(size_t* header_size, size_t* miner_tx_size, int* outputs_offset, int* outputs_blob_size, const uint32_t* nonce, const uint32_t* extra_nonce, bool include_tx_hashes) const
{
	std::vector<uint8_t> data;
	data.reserve(std::min<size_t>(128 + m_outputAmounts.size() * 39 + m_transactions.size() * HASH_SIZE, 131072));

	// Header
	data.push_back(m_majorVersion);
	data.push_back(m_minorVersion);
	writeVarint(m_timestamp, data);
	data.insert(data.end(), m_prevId.h, m_prevId.h + HASH_SIZE);

	if (!nonce) {
		nonce = &m_nonce;
	}
	data.insert(data.end(), reinterpret_cast<const uint8_t*>(nonce), reinterpret_cast<const uint8_t*>(nonce) + NONCE_SIZE);

	const size_t header_size0 = data.size();
	if (header_size) {
		*header_size = header_size0;
	}

	// Miner tx
	data.push_back(TX_VERSION);
	writeVarint(MINER_REWARD_UNLOCK_TIME, data);
	data.push_back(1);
	data.push_back(TXIN_GEN);
	writeVarint(m_txinGenHeight, data);

	const int outputs_offset0 = static_cast<int>(data.size());
	if (outputs_offset) {
		*outputs_offset = outputs_offset0;
	}

	writeVarint(m_outputAmounts.size(), data);

        LOGINFO(0, "DEBUG serialize: numOutputs=" << m_outputAmounts.size() << " numEphKeys=" << m_ephPublicKeys.size() << " numViewTags=" << m_viewTags.size() << " numEncAnchors=" << m_encryptedAnchors.size() << " sidechainHeight=" << m_sidechainHeight);

        if (!m_ephPublicKeys.empty()) {
             LOGINFO(0, "DEBUG serialize K_o[0]=" << m_ephPublicKeys[0]);
        }

        if (!m_viewTags.empty() && m_viewTags[0].size() >= 3) {
            char buf[16]; snprintf(buf, sizeof(buf), "%02x%02x%02x", m_viewTags[0][0], m_viewTags[0][1], m_viewTags[0][2]);
            LOGINFO(0, "DEBUG serialize viewTag[0]=" << (const char*)buf);
        }
        if (!m_encryptedAnchors.empty() && m_encryptedAnchors[0].size() >= 16) {
            std::string hex;
            for (int i = 0; i < 16; ++i) { char buf[4]; snprintf(buf, sizeof(buf), "%02x", m_encryptedAnchors[0][i]); hex += buf; }
            LOGINFO(0, "DEBUG serialize encAnchor[0]=" << hex);
        }

        LOGINFO(0, "DEBUG serialize D_e=" << m_txkeyPub);

        LOGINFO(0, "DEBUG serialize merkleRoot=" << static_cast<const hash&>(m_merkleRoot));

        for (size_t i = 0, n = m_outputAmounts.size(); i < n; ++i) {
            const TxOutput& output = m_outputAmounts[i];

            writeVarint(output.m_reward, data);
            data.push_back(TXOUT_TO_CARROT_V1);
            const hash h = m_ephPublicKeys[i];
            data.insert(data.end(), h.h, h.h + HASH_SIZE);
    
            // Carrot v1: asset_len + "SAL1" + 3-byte view_tag + 16-byte encrypted_anchor
            data.push_back(4);
            data.push_back('S');
            data.push_back('A');
            data.push_back('L');
            data.push_back('1');
            data.insert(data.end(), m_viewTags[i].begin(), m_viewTags[i].end());
            data.insert(data.end(), m_encryptedAnchors[i].begin(), m_encryptedAnchors[i].end());
        }

	if (outputs_blob_size) {
		*outputs_blob_size = static_cast<int>(data.size()) - outputs_offset0;
	}

        std::vector<uint8_t> tx_extra(128 + (1 + m_additionalPubKeys.size()) * HASH_SIZE);
        uint8_t* p = tx_extra.data();

        if (m_additionalPubKeys.empty()) {
                // Single output: use TX_EXTRA_TAG_PUBKEY
                *(p++) = TX_EXTRA_TAG_PUBKEY;
                memcpy(p, m_txkeyPub.h, HASH_SIZE);
                p += HASH_SIZE;
        } else {
                // Multiple outputs: TX_EXTRA_TAG_ADDITIONAL_PUBKEYS with ALL D_e values
                *(p++) = TX_EXTRA_TAG_ADDITIONAL_PUBKEYS;
                size_t total_pubkeys = 1 + m_additionalPubKeys.size();
                writeVarint(total_pubkeys, [&p](uint8_t b) { *(p++) = b; });
                // First D_e (stored in m_txkeyPub)
                memcpy(p, m_txkeyPub.h, HASH_SIZE);
                p += HASH_SIZE;
                // Remaining D_e values
                for (const auto& pk : m_additionalPubKeys) {
                        memcpy(p, pk.h, HASH_SIZE);
                        p += HASH_SIZE;
                }
        }

	uint64_t extra_nonce_size = m_extraNonceSize;
	if (extra_nonce_size > EXTRA_NONCE_MAX_SIZE) {
		LOGERR(1, "extra nonce size is too large (" << extra_nonce_size << "), fix the code!");
		extra_nonce_size = EXTRA_NONCE_MAX_SIZE;
	}

	*(p++) = TX_EXTRA_NONCE;
	*(p++) = static_cast<uint8_t>(extra_nonce_size);

	if (!extra_nonce) {
		extra_nonce = &m_extraNonce;
	}
	memcpy(p, extra_nonce, EXTRA_NONCE_SIZE);
	p += EXTRA_NONCE_SIZE;
	if (extra_nonce_size > EXTRA_NONCE_SIZE) {
		memset(p, 0, extra_nonce_size - EXTRA_NONCE_SIZE);
		p += extra_nonce_size - EXTRA_NONCE_SIZE;
	}

	*(p++) = TX_EXTRA_MERGE_MINING_TAG;

	*(p++) = static_cast<uint8_t>(m_merkleTreeDataSize + HASH_SIZE);
	writeVarint(m_merkleTreeData, [&p](const uint8_t b) { *(p++) = b; });
	memcpy(p, m_merkleRoot.h, HASH_SIZE);
	p += HASH_SIZE;

        writeVarint(static_cast<size_t>(p - tx_extra.data()), data);
        data.insert(data.end(), tx_extra.data(), p);

        // For Carrot v1+ (major_version >= 10), add type and amount_burnt instead of vin_rct_type
        if (m_majorVersion >= 10) {
            // type = MINER
            writeVarint(1, data);
    
            writeVarint(m_amountBurnt, data);

            data.push_back(0);

        }
        else {
            // vin_rct_type (only for legacy transactions)
            data.push_back(0);
        }

        if (miner_tx_size) {
		*miner_tx_size = data.size() - header_size0;
	}

        // Protocol tx (Salvium Carrot v1+)
        if (m_majorVersion >= 10) {
                writeVarint(4, data);  // version = TRANSACTION_VERSION_CARROT
                writeVarint(60, data);  // unlock_time = 60
                
                // vin (1 txin_gen)
                writeVarint(1, data);  // vin.size() = 1
                data.push_back(TXIN_GEN);
                writeVarint(m_txinGenHeight, data);
                
                // vout (empty)
                writeVarint(0, data);  // vout.size() = 0
                
                // extra (2 bytes: 0x02 0x00)
                writeVarint(2, data);  // extra.size() = 2
                data.push_back(0x02);
                data.push_back(0x00);
                
                // type = PROTOCOL
                writeVarint(2, data);  // transaction_type::PROTOCOL = 2
                data.push_back(0); // RCT
                
                // Calculate protocol tx hash using salviumd-compatible serialization
                hash protocol_tx_hash;
                calculate_protocol_tx_hash(m_txinGenHeight, protocol_tx_hash);
                LOGINFO(3, "Sidechain protocol TX hash: " << protocol_tx_hash);
        }
        if (include_tx_hashes) {
		writeVarint(m_transactions.size() - 1, data);

                if (m_transactions.size() > 1) {
                        LOGINFO(0, "DEBUG serialize tx: m_transactions[1]=" << m_transactions[1] << " sidechainHeight=" << m_sidechainHeight);
                }

#ifdef WITH_INDEXED_HASHES
		for (size_t i = 1, n = m_transactions.size(); i < n; ++i) {
			const hash h = m_transactions[i];
			data.insert(data.end(), h.h, h.h + HASH_SIZE);
		}
#else
		const uint8_t* t = reinterpret_cast<const uint8_t*>(m_transactions.data());
		data.insert(data.end(), t + HASH_SIZE, t + m_transactions.size() * HASH_SIZE);
#endif
	}

#if POOL_BLOCK_DEBUG
	if ((nonce == &m_nonce) && (extra_nonce == &m_extraNonce) && !m_mainChainDataDebug.empty() && (data != m_mainChainDataDebug)) {
		LOGERR(1, "serialize_mainchain_data() has a bug, fix it!");
		PANIC_STOP();
	}
#endif

	return data;
}

std::vector<uint8_t> PoolBlock::serialize_sidechain_data() const
{
	std::vector<uint8_t> data;

	data.reserve((m_uncles.size() + 4) * HASH_SIZE + 36);

	const hash& spend = m_minerWallet.spend_public_key();
	const hash& view = m_minerWallet.view_public_key();

	data.insert(data.end(), spend.h, spend.h + HASH_SIZE);
	data.insert(data.end(), view.h, view.h + HASH_SIZE);
	data.insert(data.end(), m_txkeySecSeed.h, m_txkeySecSeed.h + HASH_SIZE);
	data.insert(data.end(), m_parent.h, m_parent.h + HASH_SIZE);

	writeVarint(m_uncles.size(), data);

	for (const hash& id : m_uncles) {
		data.insert(data.end(), id.h, id.h + HASH_SIZE);
	}

	writeVarint(m_sidechainHeight, data);

	writeVarint(m_difficulty.lo, data);
	writeVarint(m_difficulty.hi, data);

	writeVarint(m_cumulativeDifficulty.lo, data);
	writeVarint(m_cumulativeDifficulty.hi, data);

	const uint8_t n = static_cast<uint8_t>(m_merkleProof.size());
	data.push_back(n);

	for (uint8_t i = 0; i < n; ++i) {
		const hash& h = m_merkleProof[i];
		data.insert(data.end(), h.h, h.h + HASH_SIZE);
	}

	writeVarint(m_mergeMiningExtra.size(), data);

	for (const auto& mm_extra_data : m_mergeMiningExtra) {
		data.insert(data.end(), mm_extra_data.first.h, mm_extra_data.first.h + HASH_SIZE);

		writeVarint(mm_extra_data.second.size(), data);
		data.insert(data.end(), mm_extra_data.second.begin(), mm_extra_data.second.end());
	}

	const uint8_t* p = reinterpret_cast<const uint8_t*>(m_sidechainExtraBuf);
	data.insert(data.end(), p, p + sizeof(m_sidechainExtraBuf));

#if POOL_BLOCK_DEBUG
	if (!m_sideChainDataDebug.empty() && (data != m_sideChainDataDebug)) {
		LOGERR(1, "serialize_sidechain_data() has a bug, fix it!");
		PANIC_STOP();
	}
#endif

	return data;
}

void PoolBlock::reset_offchain_data()
{
	// Defaults for off-chain variables
	m_depth = 0;

	m_verified = false;
	m_invalid = false;

	m_broadcasted = false;
	m_wantBroadcast = false;

	m_precalculated = false;
	{
		WriteLock lock(*s_precalculatedSharesLock);
		m_precalculatedShares.clear();
		m_precalculatedShares.shrink_to_fit();
	}

	m_localTimestamp = seconds_since_epoch();
	m_receivedTimestamp = 0;

	m_auxChains.clear();
	m_auxChains.shrink_to_fit();

	m_auxNonce = 0;

	m_hashingBlob.clear();
	m_hashingBlob.shrink_to_fit();

	m_powHash = {};
	m_seed = {};
}

bool PoolBlock::get_pow_hash(RandomX_Hasher_Base* hasher, uint64_t height, const hash& seed_hash, hash& pow_hash, bool force_light_mode)
{
	// Calculate the coinbase tx hash, then the merkle root of all transactions in the block - this merkle root is what goes into the hashing blob

	// Monero transactions are hashed in 3 separate parts, the resulting 3 hashes are then hashed together to get the final result
	// For the reference, see "calculate_transaction_hash" in Monero's src/cryptonote_basic/cryptonote_format_utils.cpp

	alignas(8) uint8_t hashes[HASH_SIZE * 3];

	// Second hash is keccak of base rct data (it doesn't exist for the coinbase transaction, so it's a hash of a single 0x00 byte)
	memcpy(hashes + HASH_SIZE, keccak_0x00.h, HASH_SIZE);

	// Third hash is null because there is no rct data in the coinbase transaction
	memset(hashes + HASH_SIZE * 2, 0, HASH_SIZE);

	uint64_t count;

	uint8_t blob[128];
	size_t blob_size = 0;

        {
                // For Carrot v1 blocks, ensure m_transactions has space for protocol TX before serializing
                if (m_majorVersion >= 10) {
                        if (m_transactions.size() < 2) {
                                m_transactions.resize(2);
                        }
                        hash protocol_tx_hash;
                        calculate_protocol_tx_hash(m_txinGenHeight, protocol_tx_hash);
                        m_transactions[1] = static_cast<indexed_hash>(protocol_tx_hash);
                }
                size_t header_size, miner_tx_size;
                const std::vector<uint8_t> mainchain_data = serialize_mainchain_data(&header_size, &miner_tx_size, nullptr, nullptr, nullptr, nullptr);

		if (!header_size || !miner_tx_size || (mainchain_data.size() < header_size + miner_tx_size)) {
			LOGERR(1, "tried to calculate PoW of uninitialized block");
			return false;
		}

		blob_size = header_size;
		memcpy(blob, mainchain_data.data(), blob_size);

		const uint8_t* miner_tx = mainchain_data.data() + header_size;

                // DEBUG: dump miner TX for comparison
                LOGINFO(0, "get_pow_hash: header_size=" << header_size << " miner_tx_size=" << miner_tx_size);
                {
                    std::string hex_dump;
                    for (size_t dbg_i = 0; dbg_i < std::min(miner_tx_size, size_t(160)); ++dbg_i) {
                        char dbg_buf[4];
                        snprintf(dbg_buf, sizeof(dbg_buf), "%02x", miner_tx[dbg_i]);
                        hex_dump += dbg_buf;
                    }
                    LOGINFO(0, "miner_tx bytes: " << hex_dump);
                }

		hash tmp;

		// "miner_tx_size - 1" because the last byte is 0x00 (base rct data), it goes into the second hash
		keccak(miner_tx, static_cast<int>(miner_tx_size) - 1, tmp.h);
		memcpy(hashes, tmp.h, HASH_SIZE);

		count = m_transactions.size();

		keccak(reinterpret_cast<uint8_t*>(hashes), HASH_SIZE * 3, tmp.h);

                // Save the coinbase tx hash into the first element of m_transactions
                m_transactions[0] = static_cast<indexed_hash>(tmp);

                // DEBUG: dump m_transactions for comparison
                LOGINFO(0, "get_pow_hash: m_transactions.size()=" << m_transactions.size());
                for (size_t dbg_i = 0; dbg_i < m_transactions.size(); ++dbg_i) {
                    const hash& dbg_h = m_transactions[dbg_i];
                    std::string hex;
                    for (size_t j = 0; j < HASH_SIZE; ++j) {
                        char buf[4];
                        snprintf(buf, sizeof(buf), "%02x", dbg_h.h[j]);
                        hex += buf;
                    }
                    LOGINFO(0, "get_pow_hash: m_transactions[" << dbg_i << "]=" << hex);
                }

                root_hash tmp_root;

#ifdef WITH_INDEXED_HASHES
		std::vector<hash> transactions;
		transactions.reserve(m_transactions.size());

		for (const auto& h : m_transactions) {
			transactions.emplace_back(h);
		}

		merkle_hash(transactions, tmp_root);
#else
		merkle_hash(m_transactions, tmp_root);
#endif

		memcpy(blob + blob_size, tmp_root.h, HASH_SIZE);
		blob_size += HASH_SIZE;
	}

	writeVarint(count, [&blob, &blob_size](uint8_t b) { blob[blob_size++] = b; });

	// cppcheck-suppress danglingLifetime
	m_hashingBlob.assign(blob, blob + blob_size);

        {
            std::string hex;
            for (size_t i = 0; i < blob_size; ++i) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02x", blob[i]);
                hex += buf;
            }
            LOGINFO(0, "DEBUG hashing blob (" << blob_size << " bytes): " << hex);
        }

	return hasher->calculate(blob, blob_size, height, seed_hash, pow_hash, force_light_mode);
}

uint64_t PoolBlock::get_payout(const Wallet& w) const
{
    const hash tx_key_seed = m_txkeySecSeed;
    
    LOGINFO(3, "get_payout: checking " << m_outputAmounts.size() << " outputs, tx_key_seed=" << tx_key_seed);
    
    for (size_t i = 0, n = m_outputAmounts.size(); i < n; ++i) {
        const TxOutput& out = m_outputAmounts[i];
        hash eph_public_key;
        uint8_t view_tag;
        
        const bool derived = w.get_eph_public_key_carrot(tx_key_seed, m_txinGenHeight, i, out.m_reward, eph_public_key, view_tag);
        const bool match = (m_ephPublicKeys[i] == eph_public_key);
        
        LOGINFO(3, "get_payout: output " << i << " reward=" << out.m_reward 
            << " derived=" << (derived ? 1 : 0)
            << " expected=" << m_ephPublicKeys[i] 
            << " got=" << eph_public_key
            << " match=" << (match ? 1 : 0));
        
        if (derived && match) {
            return out.m_reward;
        }
    }
    return 0;
}

hash PoolBlock::calculate_tx_key_seed() const
{
	const char domain[] = "tx_key_seed";
	const uint32_t zero = 0;

        // For Carrot v1 (v10+), exclude transaction hashes for canonical serialization
	// The tx list differs between local creation and P2P reception
	const bool include_tx_hashes = (m_majorVersion < 10);
	const std::vector<uint8_t> mainchain_data = serialize_mainchain_data(nullptr, nullptr, nullptr, nullptr, &zero, &zero, include_tx_hashes);
	const std::vector<uint8_t> sidechain_data = serialize_sidechain_data();

        // DEBUG: Log sizes for tx_key_seed comparison
        LOGINFO(3, "calculate_tx_key_seed: height=" << m_sidechainHeight 
                << " mainchain_size=" << mainchain_data.size() 
                << " sidechain_size=" << sidechain_data.size()
                << " m_transactions.size=" << m_transactions.size()
                << " m_viewTags.size=" << m_viewTags.size()
                << " m_encryptedAnchors.size=" << m_encryptedAnchors.size());

	hash result;
	keccak_custom([&domain, &mainchain_data, &sidechain_data](int offset) -> uint8_t {
		size_t k = offset;

		if (k < sizeof(domain)) return domain[k];
		k -= sizeof(domain);

		if (k < mainchain_data.size()) return mainchain_data[k];
		k -= mainchain_data.size();

		return sidechain_data[k];
	}, static_cast<int>(sizeof(domain) + mainchain_data.size() + sidechain_data.size()), result.h, HASH_SIZE);

	return result;
}

} // namespace p2pool
