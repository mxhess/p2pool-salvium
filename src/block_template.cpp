/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2025 SChernykh <https://github.com/SChernykh>
 * Portions Copyright (c) 2012-2013 The Cryptonote developers
 * Portions Copyright (c) 2014-2021 The Monero Project
 * Portions Copyright (c) 2021 XMRig <https://github.com/xmrig>
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
#include "block_template.h"
#include "wallet.h"
#include "carrot_crypto.h"
#include "crypto.h"
#include "keccak.h"
#include "mempool.h"
#include "p2pool.h"
#include "side_chain.h"
#include "pool_block.h"
#include "protocol_tx_hash.h"
#include "merkle.h"
#include <zmq.hpp>
#include <ctime>
#include <numeric>

LOG_CATEGORY(BlockTemplate)

namespace p2pool {

BlockTemplate::BlockTemplate(SideChain* sidechain, RandomX_Hasher_Base* hasher)
	: m_sidechain(sidechain)
	, m_hasher(hasher)
	, m_templateId(0)
	, m_lastUpdated(seconds_since_epoch())
	, m_blockHeaderSize(0)
	, m_minerTxOffsetInTemplate(0)
	, m_minerTxSize(0)
	, m_nonceOffset(0)
	, m_extraNonceOffsetInTemplate(0)
	, m_numTransactionHashes(0)
	, m_prevId{}
	, m_height(0)
	, m_difficulty{}
	, m_auxDifficulty{}
	, m_seedHash{}
	, m_timestamp(0)
	, m_poolBlockTemplate(new PoolBlock())
	, m_finalReward(0)
	, m_minerTxKeccakState{}
	, m_minerTxKeccakStateInputLength(0)
	, m_sidechainHashKeccakState{}
	, m_sidechainHashInputLength(0)
	, m_rng(RandomDeviceSeed::instance)
{
	// Diffuse the initial state in case it has low quality
	m_rng.discard(10000);

	uv_rwlock_init_checked(&m_lock);

	m_blockHeader.reserve(64);
	m_minerTx.reserve(49152);
	m_minerTxExtra.reserve(64);
	m_transactionHashes.reserve(8192);
	m_rewards.reserve(100);
	m_blockTemplateBlob.reserve(65536);
	m_fullDataBlob.reserve(65536);
	m_sidechainHashBlob.reserve(65536);
	m_merkleTreeMainBranch.reserve(HASH_SIZE * 10);
	m_mempoolTxs.reserve(1024);
	m_mempoolTxsOrder.reserve(1024);
	m_mempoolTxsOrder2.reserve(1024);
	m_shares.reserve(m_sidechain->chain_window_size() * 2);

	for (size_t i = 0; i < array_size(&BlockTemplate::m_oldTemplates); ++i) {
		m_oldTemplates[i] = new BlockTemplate(*this);
	}

#if TEST_MEMPOOL_PICKING_ALGORITHM
	m_knapsack.reserve(512 * 309375);
#endif
}

BlockTemplate::~BlockTemplate()
{
	for (size_t i = 0; i < array_size(&BlockTemplate::m_oldTemplates); ++i) {
		delete m_oldTemplates[i];
	}

	uv_rwlock_destroy(&m_lock);

	delete m_poolBlockTemplate;
}

BlockTemplate::BlockTemplate(const BlockTemplate& b)
	: m_poolBlockTemplate(new PoolBlock())
{
	uv_rwlock_init_checked(&m_lock);
	*this = b;
}

// cppcheck-suppress operatorEqVarError
BlockTemplate& BlockTemplate::operator=(const BlockTemplate& b)
{
	if (this == &b) {
		return *this;
	}

	WriteLock lock(m_lock);

	m_sidechain = b.m_sidechain;
	m_hasher = b.m_hasher;
	m_templateId = b.m_templateId;
	m_lastUpdated = b.m_lastUpdated.load();
	m_blockTemplateBlob = b.m_blockTemplateBlob;
	m_fullDataBlob = b.m_fullDataBlob;
	m_sidechainHashBlob = b.m_sidechainHashBlob;
	m_merkleTreeMainBranch = b.m_merkleTreeMainBranch;
	m_blockHeaderSize = b.m_blockHeaderSize;
	m_minerTxOffsetInTemplate = b.m_minerTxOffsetInTemplate;
	m_minerTxSize = b.m_minerTxSize;
	m_nonceOffset = b.m_nonceOffset;
	m_extraNonceOffsetInTemplate = b.m_extraNonceOffsetInTemplate;
	m_numTransactionHashes = b.m_numTransactionHashes;
	m_prevId = b.m_prevId;
	m_height = b.m_height.load();
	m_difficulty = b.m_difficulty;
	m_auxDifficulty = b.m_auxDifficulty;
	m_seedHash = b.m_seedHash;
	m_timestamp = b.m_timestamp;
	*m_poolBlockTemplate = *b.m_poolBlockTemplate;
	m_finalReward = b.m_finalReward.load();

	m_minerTxKeccakState = b.m_minerTxKeccakState;
	m_minerTxKeccakStateInputLength = b.m_minerTxKeccakStateInputLength;

	m_sidechainHashKeccakState = b.m_sidechainHashKeccakState;
	m_sidechainHashInputLength = b.m_sidechainHashInputLength;

	m_minerTx.clear();
	m_blockHeader.clear();
	m_minerTxExtra.clear();
	m_transactionHashes.clear();
	m_rewards.clear();
	m_mempoolTxs.clear();
	m_mempoolTxsOrder.clear();
	m_mempoolTxsOrder2.clear();
	m_shares.clear();

	m_rng = b.m_rng;

#if TEST_MEMPOOL_PICKING_ALGORITHM
	m_knapsack.clear();
#endif

	return *this;
}

static FORCEINLINE uint64_t get_base_reward(uint64_t already_generated_coins)
{
        // Salvium emission formula
        if (already_generated_coins == 0) {
                return PREMINE_AMOUNT;
        }
        
        uint64_t base_reward = (MONEY_SUPPLY - already_generated_coins) >> EMISSION_SPEED_FACTOR;
        
        if (base_reward < BASE_BLOCK_REWARD) {
                base_reward = BASE_BLOCK_REWARD;
        }
        
        return base_reward;
}

static FORCEINLINE uint64_t get_block_reward(uint64_t base_reward, uint64_t median_weight, uint64_t fees, uint64_t weight)
{
	if (weight <= median_weight) {
		return base_reward + fees;
	}

	if (weight > median_weight * 2) {
		return 0;
	}

	// This will overflow if median_weight >= 2^32
	// Maybe fix it later like in Monero code, but it'll be fiiiine for now...
	// Performance of this code is more important

	uint64_t product[2];
	product[0] = umul128(base_reward, (median_weight * 2 - weight) * weight, &product[1]);

	uint64_t rem;
	uint64_t reward = udiv128(product[1], product[0], median_weight * median_weight, &rem);

	return reward + fees;
}

void BlockTemplate::shuffle_tx_order()
{
	const uint64_t n = m_mempoolTxsOrder.size();
	if (n > 1) {
		for (uint64_t i = 0, k; i < n - 1; ++i) {
			umul128(m_rng(), n - i, &k);
			std::swap(m_mempoolTxsOrder[i], m_mempoolTxsOrder[i + k]);
		}
	}
}

void BlockTemplate::update(const MinerData& data, const Mempool& mempool, const Params* params, bool in_donation_mode)
{
	if (data.major_version > HARDFORK_SUPPORTED_VERSION) {
		LOGERR(1, "got hardfork version " << data.major_version << ", expected <= " << HARDFORK_SUPPORTED_VERSION);
		return;
	}

	// Block template construction is relatively slow, but it's better to keep the lock the whole time
	// instead of using temporary variables and making a quick swap in the end
	// 
	// All readers will line up for the new template instead of using the outdated template
	WriteLock lock(m_lock);

	if (m_templateId > 0) {
		*m_oldTemplates[m_templateId % array_size(&BlockTemplate::m_oldTemplates)] = *this;
	}

	++m_templateId;
	m_lastUpdated = seconds_since_epoch();

	// When block template generation fails for any reason
	auto use_old_template = [this]() {
		const uint32_t id = m_templateId - 1;
		LOGWARN(4, "using old block template with ID = " << id);
		*this = *m_oldTemplates[id % array_size(&BlockTemplate::m_oldTemplates)];
	};

	m_height = data.height;
        m_majorVersion = data.major_version;
	m_difficulty = data.difficulty;
	m_seedHash = data.seed_hash;

	m_blockHeader.clear();
	m_poolBlockTemplate->m_verified = false;

	// Major and minor hardfork version
	m_blockHeader.push_back(data.major_version);
	m_blockHeader.push_back(HARDFORK_SUPPORTED_VERSION);
	m_poolBlockTemplate->m_majorVersion = data.major_version;
	m_poolBlockTemplate->m_minorVersion = HARDFORK_SUPPORTED_VERSION;

	// Timestamp
	m_timestamp = time(nullptr);
	if (m_timestamp <= data.median_timestamp) {
		LOGWARN(2, "timestamp adjusted from " << m_timestamp << " to " << data.median_timestamp + 1 << ". Fix your system time!");
		m_timestamp = data.median_timestamp + 1;
	}

	writeVarint(m_timestamp, m_blockHeader);
	m_poolBlockTemplate->m_timestamp = m_timestamp;

	// Previous block id
	m_blockHeader.insert(m_blockHeader.end(), data.prev_id.h, data.prev_id.h + HASH_SIZE);
	m_prevId = data.prev_id;
	m_poolBlockTemplate->m_prevId = m_prevId;

	// Miner nonce
	m_nonceOffset = m_blockHeader.size();
	m_blockHeader.insert(m_blockHeader.end(), NONCE_SIZE, 0);
	m_poolBlockTemplate->m_nonce = 0;

	// Fill in m_txinGenHeight here so get_shares() can use it to calculate the correct PPLNS window
	m_poolBlockTemplate->m_txinGenHeight = data.height;

	m_blockHeaderSize = m_blockHeader.size();

        m_poolBlockTemplate->m_minerWallet = params->m_miningWallet;

	if (!m_sidechain->fill_sidechain_data(*m_poolBlockTemplate, m_shares)) {
		use_old_template();
		return;
	}

	// Whole-block donation: replace all miner shares with single dev wallet output
	if (in_donation_mode && !m_shares.empty()) {
		difficulty_type total_weight;
		for (const auto& share : m_shares) {
			total_weight += share.m_weight;
		}
		m_shares.clear();
		m_shares.emplace_back(total_weight, &params->m_devWallet);
		LOGINFO(4, "Donation mode: entire block reward goes to dev wallet");
	}

	// Pre-calculate outputs to speed up miner tx generation
	if (!m_shares.empty()) {
		struct Precalc
		{
			FORCEINLINE Precalc(const std::vector<MinerShare>& s, const hash& k) : txKeySec(k)
			{
				const size_t N = s.size();
				counter = static_cast<int>(N) - 1;
				shares = reinterpret_cast<std::pair<hash, hash>*>(malloc_hook(sizeof(std::pair<hash, hash>) * N));
				if (shares) {
					const MinerShare* src = &s[0];
					std::pair<hash, hash>* dst = shares;
					const std::pair<hash, hash>* e = shares + N;

					for (; dst < e; ++src, ++dst) {
						const Wallet* w = src->m_wallet;
						dst->first = w->view_public_key();
						dst->second = w->spend_public_key();
					}
				}
			}

			FORCEINLINE Precalc(Precalc&& rhs) noexcept : txKeySec(rhs.txKeySec), counter(rhs.counter.load()), shares(rhs.shares) { rhs.shares = nullptr; }
			FORCEINLINE ~Precalc() { free_hook(shares); }

			// Disable any other way of copying/moving Precalc
			Precalc(const Precalc&) = delete;
			Precalc& operator=(const Precalc&) = delete;
			Precalc& operator=(Precalc&&) = delete;

			FORCEINLINE void operator()()
			{
				if (shares) {
					hash derivation, eph_public_key;
					int i;
					while ((i = counter.fetch_sub(1)) >= 0) {
						uint8_t view_tag;
						generate_key_derivation(shares[i].first, txKeySec, i, derivation, view_tag);
						derive_public_key(derivation, i, shares[i].second, eph_public_key);
					}
				}
			}

			hash txKeySec;
			std::atomic<int> counter;
			std::pair<hash, hash>* shares;
		};
		parallel_run(uv_default_loop_checked(), Precalc(m_shares, m_poolBlockTemplate->m_txkeySec));
	}

	m_poolBlockTemplate->m_merkleTreeData = PoolBlock::encode_merkle_tree_data(static_cast<uint32_t>(data.aux_chains.size() + 1), data.aux_nonce);
	m_poolBlockTemplate->m_merkleTreeDataSize = 0;
	writeVarint(m_poolBlockTemplate->m_merkleTreeData, [this](uint8_t) { ++m_poolBlockTemplate->m_merkleTreeDataSize; });

	select_mempool_transactions(mempool);

	uint64_t base_reward = get_base_reward(data.already_generated_coins);

        // Save the FULL reward before the split
        uint64_t full_block_reward = base_reward;  // ADD THIS LINE

        // Salvium: 20% goes to staking, miners get 80%
        base_reward = base_reward - (base_reward / 5);  // 80% of total reward

	uint64_t total_tx_fees = 0;
	uint64_t total_tx_weight = 0;
	for (const TxMempoolData& tx : m_mempoolTxs) {
		total_tx_fees += tx.fee;
		total_tx_weight += tx.weight;
	}

	const uint64_t max_reward = base_reward + total_tx_fees;

	LOGINFO(3, "base  reward = " << log::Gray() << log::XMRAmount(base_reward) << log::NoColor() <<
		", " << log::Gray() << m_mempoolTxs.size() << log::NoColor() <<
		" transactions, fees = " << log::Gray() << log::XMRAmount(total_tx_fees) << log::NoColor() <<
		", weight = " << log::Gray() << total_tx_weight);

	if (!SideChain::split_reward(max_reward, m_shares, m_rewards)) {
		use_old_template();
		return;
	}

        // DEBUG: Show share/reward assignment
        for (size_t i = 0; i < m_shares.size(); ++i) {
            LOGINFO(3, "BlockTemplate share[" << i << "]: spend_key=" << m_shares[i].m_wallet->spend_public_key() << " weight=" << m_shares[i].m_weight << " reward=" << m_rewards[i]);
        }

	auto get_reward_amounts_weight = [this]() {
		return std::accumulate(m_rewards.begin(), m_rewards.end(), 0ULL,
			[](uint64_t a, uint64_t b)
			{
				writeVarint(b, [&a](uint8_t) { ++a; });
				return a;
			});
	};
	uint64_t max_reward_amounts_weight = get_reward_amounts_weight();

	if (create_miner_tx(data, m_shares, max_reward_amounts_weight, true, full_block_reward) < 0) {
		use_old_template();
		return;
	}

	uint64_t miner_tx_weight = m_minerTx.size();

	// Select transactions from the mempool
	uint64_t final_reward, final_fees, final_weight;

	m_mempoolTxsOrder.resize(m_mempoolTxs.size());
	for (size_t i = 0; i < m_mempoolTxs.size(); ++i) {
		m_mempoolTxsOrder[i] = static_cast<int>(i);
	}

	// if a block doesn't get into the penalty zone, just pick all transactions
	if (total_tx_weight + miner_tx_weight <= data.median_weight) {
		final_fees = 0;
		final_weight = miner_tx_weight;

		shuffle_tx_order();

		m_numTransactionHashes = m_mempoolTxsOrder.size();
		m_transactionHashes.assign(HASH_SIZE, 0);
		m_transactionHashesSet.clear();
		m_transactionHashesSet.reserve(m_mempoolTxsOrder.size());
		for (size_t i = 0; i < m_mempoolTxsOrder.size(); ++i) {
			const TxMempoolData& tx = m_mempoolTxs[m_mempoolTxsOrder[i]];
			if (!m_transactionHashesSet.insert(tx.id).second) {
				LOGERR(1, "Added transaction " << tx.id << " twice. Fix the code!");
				continue;
			}
			const hash h = tx.id;
			m_transactionHashes.insert(m_transactionHashes.end(), h.h, h.h + HASH_SIZE);
			final_fees += tx.fee;
			final_weight += tx.weight;
		}

		final_reward = base_reward + final_fees;
	}
	else {
		// Picking all transactions will result in the base reward penalty
		// Use a heuristic algorithm to pick transactions and get the maximum possible reward
		// Testing has shown that this algorithm is very close to the optimal selection
		// Usually no more than 0.5 micronero away from the optimal discrete knapsack solution
		// Sometimes it even finds the optimal solution

		// Sort all transactions by fee per byte (highest to lowest)
		std::sort(m_mempoolTxsOrder.begin(), m_mempoolTxsOrder.end(), [this](int a, int b) { return m_mempoolTxs[a] < m_mempoolTxs[b]; });

		final_reward = base_reward;
		final_fees = 0;
		final_weight = miner_tx_weight;

		m_mempoolTxsOrder2.clear();
		for (int i = 0; i < static_cast<int>(m_mempoolTxsOrder.size()); ++i) {
			const TxMempoolData& tx = m_mempoolTxs[m_mempoolTxsOrder[i]];

			int k = -1;

			const uint64_t reward = get_block_reward(base_reward, data.median_weight, final_fees + tx.fee, final_weight + tx.weight);
			if (reward > final_reward) {
				// If simply adding this transaction increases the reward, remember it
				final_reward = reward;
				k = i;
			}

			// Try replacing other transactions when we are above the limit
			if (final_weight + tx.weight > data.median_weight) {
				// Don't check more than 100 transactions deep because they have higher and higher fee/byte
				const int n = static_cast<int>(m_mempoolTxsOrder2.size());
				for (int j = n - 1, j1 = std::max<int>(0, n - 100); j >= j1; --j) {
					const TxMempoolData& prev_tx = m_mempoolTxs[m_mempoolTxsOrder2[j]];
					const uint64_t reward2 = get_block_reward(base_reward, data.median_weight, final_fees + tx.fee - prev_tx.fee, final_weight + tx.weight - prev_tx.weight);
					if (reward2 > final_reward) {
						// If replacing some other transaction increases the reward even more, remember it
						// And keep trying to replace other transactions
						final_reward = reward2;
						k = j;
					}
				}
			}

			if (k == i) {
				// Simply adding this tx improves the reward
				m_mempoolTxsOrder2.push_back(m_mempoolTxsOrder[i]);
				final_fees += tx.fee;
				final_weight += tx.weight;
			}
			else if (k >= 0) {
				// Replacing another tx with this tx improves the reward
				const TxMempoolData& prev_tx = m_mempoolTxs[m_mempoolTxsOrder2[k]];
				m_mempoolTxsOrder2[k] = m_mempoolTxsOrder[i];
				final_fees += tx.fee - prev_tx.fee;
				final_weight += tx.weight - prev_tx.weight;
			}
		}
		m_mempoolTxsOrder = m_mempoolTxsOrder2;

		final_fees = 0;
		final_weight = miner_tx_weight;

		shuffle_tx_order();

		m_numTransactionHashes = m_mempoolTxsOrder.size();
		m_transactionHashes.assign(HASH_SIZE, 0);
		m_transactionHashesSet.clear();
		m_transactionHashesSet.reserve(m_mempoolTxsOrder.size());
		for (size_t i = 0; i < m_mempoolTxsOrder.size(); ++i) {
			const TxMempoolData& tx = m_mempoolTxs[m_mempoolTxsOrder[i]];
			if (!m_transactionHashesSet.insert(tx.id).second) {
				LOGERR(1, "Added transaction " << tx.id << " twice. Fix the code!");
				continue;
			}
			const hash h = tx.id;
			m_transactionHashes.insert(m_transactionHashes.end(), h.h, h.h + HASH_SIZE);
			final_fees += tx.fee;
			final_weight += tx.weight;
		}

		final_reward = get_block_reward(base_reward, data.median_weight, final_fees, final_weight);

		if (final_reward < base_reward) {
			LOGERR(1, "final_reward < base_reward, this should never happen. Fix the code!");
		}

#if TEST_MEMPOOL_PICKING_ALGORITHM
		LOGINFO(3, "final_reward = " << log::XMRAmount(final_reward) << ", transactions = " << m_numTransactionHashes << ", final_weight = " << final_weight);

		uint64_t final_reward2;
		fill_optimal_knapsack(data, base_reward, miner_tx_weight, final_reward2, final_fees, final_weight);
		LOGINFO(3, "best_reward  = " << log::XMRAmount(final_reward2) << ", transactions = " << m_numTransactionHashes << ", final_weight = " << final_weight);
		if (final_reward2 < final_reward) {
			LOGERR(1, "fill_optimal_knapsack has a bug, found solution is not optimal. Fix it!");
		}
		LOGINFO(3, "difference   = " << static_cast<int64_t>(final_reward2 - final_reward));
		final_reward = final_reward2;
		{
			uint64_t fee_check = 0;
			uint64_t weight_check = miner_tx_weight;
			for (int i : m_mempoolTxsOrder) {
				const TxMempoolData& tx = m_mempoolTxs[i];
				fee_check += tx.fee;
				weight_check += tx.weight;
			}
			const uint64_t reward_check = get_block_reward(base_reward, data.median_weight, final_fees, final_weight);
			if ((reward_check != final_reward) || (fee_check != final_fees) || (weight_check != final_weight)) {
				LOGERR(1, "fill_optimal_knapsack has a bug, expected " << final_reward << ", got " << reward_check << " reward. Fix it!");
			}
		}
#endif
	}

        // Salvium: 1/5 of block reward is burnt, only 4/5 goes to miners
	if (!SideChain::split_reward(final_reward, m_shares, m_rewards)) {
		use_old_template();
		return;
	}

	m_finalReward = final_reward;
        m_fullBlockReward = full_block_reward;

	const int create_miner_tx_result = create_miner_tx(data, m_shares, max_reward_amounts_weight, false, full_block_reward);
	if (create_miner_tx_result < 0) {
		if (create_miner_tx_result == -3) {
			// Too many extra bytes were added, refine max_reward_amounts_weight and miner_tx_weight
			LOGINFO(4, "Readjusting miner_tx to reduce extra nonce size");

			// The difference between max possible reward and the actual reward can't reduce the size of output amount varints by more than 1 byte each
			// So block weight will be >= current weight - number of outputs
			const uint64_t w = (final_weight > m_rewards.size()) ? (final_weight - m_rewards.size()) : 0;

			// Block reward will be <= r due to how block size penalty works
			const uint64_t r = get_block_reward(base_reward, data.median_weight, final_fees, w);

			if (!SideChain::split_reward(r, m_shares, m_rewards)) {
				use_old_template();
				return;
			}

			max_reward_amounts_weight = get_reward_amounts_weight();

			if (create_miner_tx(data, m_shares, max_reward_amounts_weight, true, full_block_reward) < 0) {
				use_old_template();
				return;
			}

			final_weight -= miner_tx_weight;
			final_weight += m_minerTx.size();
			miner_tx_weight = m_minerTx.size();

			final_reward = get_block_reward(base_reward, data.median_weight, final_fees, final_weight);

			if (!SideChain::split_reward(final_reward, m_shares, m_rewards)) {
				use_old_template();
				return;
			}

			if (create_miner_tx(data, m_shares, max_reward_amounts_weight, false, full_block_reward) < 0) {
				use_old_template();
				return;
			}

			LOGINFO(4, "New extra nonce size = " << m_poolBlockTemplate->m_extraNonceSize);
		}
		else {
			use_old_template();
			return;
		}
	}

	if (m_minerTx.size() != miner_tx_weight) {
		LOGERR(1, "miner tx size changed after adjusting reward");
		use_old_template();
		return;
	}

        m_blockTemplateBlob = m_blockHeader;
        if (m_extraNonceOffsetInTemplate > 0) {
                m_extraNonceOffsetInTemplate += m_blockHeader.size();
        }
        m_minerTxOffsetInTemplate = m_blockHeader.size();
        m_minerTxSize = m_minerTx.size();
        m_blockTemplateBlob.insert(m_blockTemplateBlob.end(), m_minerTx.begin(), m_minerTx.end());

        // DEBUG: Show ALL of m_minerTx
        LOGINFO(6, "DEBUG: FULL m_minerTx (" << m_minerTx.size() << " bytes):");
        std::string full_tx_hex;
        full_tx_hex.reserve(m_minerTx.size() * 2);
        for (size_t i = 0; i < m_minerTx.size(); ++i) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", m_minerTx[i]);
            full_tx_hex.append(buf);
        }
        LOGINFO(6, full_tx_hex);

        LOGINFO(6, "DEBUG: major_version = " << data.major_version << ", checking if >= 10");
        // Protocol tx for Salvium Carrot v1+

        // First, calculate and store the miner TX hash
        hash miner_tx_hash = calc_miner_tx_hash(0);
        
        // m_transactionHashes currently has: [zeros placeholder][mempool tx 0][mempool tx 1]...
        // We need: [miner tx][protocol tx][mempool tx 0][mempool tx 1]...
        
        // Save mempool txs (everything after position 0)
        std::vector<uint8_t> mempool_txs;
        if (m_transactionHashes.size() > HASH_SIZE) {
                mempool_txs.assign(m_transactionHashes.begin() + HASH_SIZE, m_transactionHashes.end());
        }
        
        // Rebuild with correct order
        m_transactionHashes.clear();
        m_transactionHashes.reserve(HASH_SIZE * 2 + mempool_txs.size());
        m_transactionHashes.insert(m_transactionHashes.end(), miner_tx_hash.h, miner_tx_hash.h + HASH_SIZE);
        
        LOGINFO(3, "Stored miner TX hash at position 0: " << miner_tx_hash);
        
        // Write protocol tx bytes to blob
        writeVarint(4, m_blockTemplateBlob);           // version
        writeVarint(60, m_blockTemplateBlob);          // unlock_time
        writeVarint(1, m_blockTemplateBlob);           // vin count
        m_blockTemplateBlob.push_back(0xff);           // TXIN_GEN
        writeVarint(data.height, m_blockTemplateBlob); // height
        writeVarint(0, m_blockTemplateBlob);           // vout count
        writeVarint(2, m_blockTemplateBlob);           // extra size
        m_blockTemplateBlob.push_back(0x02);           // extra[0]
        m_blockTemplateBlob.push_back(0x00);           // extra[1]
        writeVarint(2, m_blockTemplateBlob);           // type PROTOCOL
        m_blockTemplateBlob.push_back(0);              // RCT type
        
        // Calculate protocol tx hash and store in member variable
        calculate_protocol_tx_hash(data.height, m_protocolTxHash);
        LOGINFO(3, "Protocol TX hash: " << m_protocolTxHash);
        
        // Add protocol tx hash after miner tx
        m_transactionHashes.insert(m_transactionHashes.end(), m_protocolTxHash.h, m_protocolTxHash.h + HASH_SIZE);
        
        // Add mempool txs back
        if (!mempool_txs.empty()) {
                m_transactionHashes.insert(m_transactionHashes.end(), mempool_txs.begin(), mempool_txs.end());
        }

        // Now write tx_hashes section
        // For HF10+, blob tx_count excludes protocol tx (it's implicit like miner tx)
        const uint64_t blob_tx_count = m_numTransactionHashes;
        writeVarint(blob_tx_count, m_blockTemplateBlob);
        
        // Miner tx hash is skipped here because it's not a part of block template
        m_blockTemplateBlob.insert(m_blockTemplateBlob.end(), m_transactionHashes.begin() + HASH_SIZE * 2, m_transactionHashes.end());

        // Build m_transactions directly from m_transactionHashes to ensure they match
        m_poolBlockTemplate->m_transactions.clear();
        m_poolBlockTemplate->m_transactions.resize(1);  // Placeholder for coinbase at [0]
        // m_transactionHashes layout: [miner_tx][protocol_tx][mempool_tx_0][mempool_tx_1]...
        // Copy protocol_tx and all mempool txs (skip miner_tx at position 0)
        for (size_t i = HASH_SIZE; i < m_transactionHashes.size(); i += HASH_SIZE) {
                hash h;
                memcpy(h.h, m_transactionHashes.data() + i, HASH_SIZE);
                m_poolBlockTemplate->m_transactions.push_back(static_cast<indexed_hash>(h));
        }

        m_poolBlockTemplate->m_minerWallet = params->m_miningWallet;

	// Layout: [software id, version, random number, sidechain extra_nonce]
	uint32_t* sidechain_extra = m_poolBlockTemplate->m_sidechainExtraBuf;
	sidechain_extra[0] = static_cast<uint32_t>(SoftwareID::P2Pool);
#ifdef P2POOL_SIDECHAIN_EXTRA_1
	sidechain_extra[1] = P2POOL_SIDECHAIN_EXTRA_1;
#else
	sidechain_extra[1] = P2POOL_VERSION;
#endif
	sidechain_extra[2] = static_cast<uint32_t>(m_rng() >> 32);
	sidechain_extra[3] = 0;

	m_poolBlockTemplate->m_nonce = 0;
	m_poolBlockTemplate->m_extraNonce = 0;
	m_poolBlockTemplate->m_sidechainId = {};
	m_poolBlockTemplate->m_merkleRoot = {};

	m_poolBlockTemplate->m_auxChains = data.aux_chains;
	m_poolBlockTemplate->m_auxNonce = data.aux_nonce;

	m_poolBlockTemplate->m_mergeMiningExtra.clear();
	
	for (const AuxChainData& c : data.aux_chains) {
		std::vector<uint8_t> v;
		v.reserve(HASH_SIZE + 16);

		v.assign(c.data.h, c.data.h + HASH_SIZE * 2);

		writeVarint(c.difficulty.lo, v);
		writeVarint(c.difficulty.hi, v);

		m_poolBlockTemplate->m_mergeMiningExtra.emplace(c.unique_id, std::move(v));
	}

	if (params->m_subaddress.valid()) {
		uint8_t buf[HASH_SIZE + 2] = {};
		memcpy(buf, params->m_subaddress.view_public_key().h, HASH_SIZE);

		m_poolBlockTemplate->m_mergeMiningExtra.emplace(keccak_subaddress_viewpub, std::vector(buf, buf + sizeof(buf)));
	}

	if (!params->m_onionPubkey.empty()) {
		uint8_t buf[HASH_SIZE + 2] = {};
		memcpy(buf, params->m_onionPubkey.h, HASH_SIZE);

		m_poolBlockTemplate->m_mergeMiningExtra.emplace(keccak_onion_address_v3, std::vector(buf, buf + sizeof(buf)));
	}

	init_merge_mining_merkle_proof();

	const std::vector<uint8_t> sidechain_data = m_poolBlockTemplate->serialize_sidechain_data();
	const std::vector<uint8_t>& consensus_id = m_sidechain->consensus_id();

	m_sidechainHashBlob = m_poolBlockTemplate->serialize_mainchain_data();
	m_sidechainHashBlob.insert(m_sidechainHashBlob.end(), sidechain_data.begin(), sidechain_data.end());
	m_sidechainHashBlob.insert(m_sidechainHashBlob.end(), consensus_id.begin(), consensus_id.end());

	{
		m_sidechainHashKeccakState = {};

		const size_t extra_nonce_offset = m_sidechainHashBlob.size() - HASH_SIZE - EXTRA_NONCE_SIZE;
		if (extra_nonce_offset >= KeccakParams::HASH_DATA_AREA) {
			// Sidechain data is big enough to cache keccak state up to extra_nonce
			m_sidechainHashInputLength = (extra_nonce_offset / KeccakParams::HASH_DATA_AREA) * KeccakParams::HASH_DATA_AREA;

			const uint8_t* in = m_sidechainHashBlob.data();
			int inlen = static_cast<int>(m_sidechainHashInputLength);

			keccak_step(in, inlen, m_sidechainHashKeccakState);
		}
		else {
			m_sidechainHashInputLength = 0;
		}
	}

	m_fullDataBlob = m_blockTemplateBlob;
	m_fullDataBlob.insert(m_fullDataBlob.end(), sidechain_data.begin(), sidechain_data.end());
	LOGINFO(6, "blob size = " << m_fullDataBlob.size());

	m_poolBlockTemplate->m_sidechainId = calc_sidechain_hash(0);
	{
		const uint32_t n_aux_chains = static_cast<uint32_t>(m_poolBlockTemplate->m_auxChains.size() + 1);
		const uint32_t aux_slot = get_aux_slot(m_sidechain->consensus_hash(), m_poolBlockTemplate->m_auxNonce, n_aux_chains);
		m_poolBlockTemplate->m_merkleRoot = get_root_from_proof(m_poolBlockTemplate->m_sidechainId, m_poolBlockTemplate->m_merkleProof, aux_slot, n_aux_chains);
	}

	if (pool_block_debug()) {

        LOGINFO(3, "DEBUG: pool_block_debug() is TRUE - executing debug block");

		const size_t merkle_root_offset = m_extraNonceOffsetInTemplate + m_poolBlockTemplate->m_extraNonceSize + 2 + m_poolBlockTemplate->m_merkleTreeDataSize;

		memcpy(m_blockTemplateBlob.data() + merkle_root_offset, m_poolBlockTemplate->m_merkleRoot.h, HASH_SIZE);
		memcpy(m_fullDataBlob.data() + merkle_root_offset, m_poolBlockTemplate->m_merkleRoot.h, HASH_SIZE);
		memcpy(m_minerTx.data() + merkle_root_offset - m_minerTxOffsetInTemplate, m_poolBlockTemplate->m_merkleRoot.h, HASH_SIZE);

		const std::vector<uint8_t> mainchain_data = m_poolBlockTemplate->serialize_mainchain_data();
		if (mainchain_data != m_blockTemplateBlob) {
			LOGERR(1, "serialize_mainchain_data() has a bug, fix it! ");
			LOGERR(1, "mainchain_data.size()      = " << mainchain_data.size());
			LOGERR(1, "m_blockTemplateBlob.size() = " << m_blockTemplateBlob.size());
			for (size_t i = 0, n = std::min(mainchain_data.size(), m_blockTemplateBlob.size()); i < n; ++i) {
				if (mainchain_data[i] != m_blockTemplateBlob[i]) {
					LOGERR(1, "mainchain_data is different at offset " << i);
					break;
				}
			}
		}
		PoolBlock check;
		const int result = check.deserialize(m_fullDataBlob.data(), m_fullDataBlob.size(), *m_sidechain, nullptr, false);
		if (result != 0) {
			LOGERR(1, "pool block blob generation and/or parsing is broken, error " << result);
		}
	}

	m_minerTxKeccakState = {};

	const size_t extra_nonce_offset = m_extraNonceOffsetInTemplate - m_minerTxOffsetInTemplate;
	if (extra_nonce_offset >= KeccakParams::HASH_DATA_AREA) {
		// Miner transaction is big enough to cache keccak state up to extra_nonce
		m_minerTxKeccakStateInputLength = (extra_nonce_offset / KeccakParams::HASH_DATA_AREA) * KeccakParams::HASH_DATA_AREA;

		const uint8_t* in = m_blockTemplateBlob.data() + m_minerTxOffsetInTemplate;
		int inlen = static_cast<int>(m_minerTxKeccakStateInputLength);

		keccak_step(in, inlen, m_minerTxKeccakState);
	}
	else {
		m_minerTxKeccakStateInputLength = 0;
	}

	const hash minerTx_hash = calc_miner_tx_hash(0);

	memcpy(m_transactionHashes.data(), minerTx_hash.h, HASH_SIZE);

	calc_merkle_tree_main_branch();

	// DEBUG: Log block template structure
	LOGINFO(5, "DEBUG P2POOL TEMPLATE (" << m_blockTemplateBlob.size() << " bytes)");
	std::string hex;
	hex.reserve(400);
	for (size_t i = 0; i < std::min<size_t>(200, m_blockTemplateBlob.size()); ++i) {
		char buf[3];
		snprintf(buf, 3, "%02x", m_blockTemplateBlob[i]);
		hex += buf;
	}
	LOGINFO(5, "P2POOL FIRST 200 BYTES: " << hex);

	LOGINFO(3, "final reward = " << log::Gray() << log::XMRAmount(final_reward) << log::NoColor() <<
		", weight = " << log::Gray() << final_weight << log::NoColor() <<
		", outputs = " << log::Gray() << m_poolBlockTemplate->m_outputAmounts.size() << log::NoColor() <<
		", " << log::Gray() << m_numTransactionHashes << log::NoColor() <<
		" of " << log::Gray() << m_mempoolTxs.size() << log::NoColor() << " transactions included");

	m_minerTx.clear();
	m_blockHeader.clear();
	m_minerTxExtra.clear();
	// m_transactionHashes.clear();
	m_transactionHashesSet.clear();
	m_rewards.clear();
	m_mempoolTxs.clear();
	m_mempoolTxsOrder.clear();
	m_mempoolTxsOrder2.clear();
}

#if TEST_MEMPOOL_PICKING_ALGORITHM
void BlockTemplate::fill_optimal_knapsack(const MinerData& data, uint64_t base_reward, uint64_t miner_tx_weight, uint64_t& best_reward, uint64_t& final_fees, uint64_t& final_weight)
{
	// Find the maximum possible fee for every weight value and remember which tx leads to this fee/weight
	// Run time is O(N*W) where N is the number of transactions and W is the maximum block weight
	// 
	// Actual run time is 0.02-0.05 seconds on real full blocks
	// It's too slow and uses too much memory to be practical

	constexpr uint64_t FEE_COEFF = 1000;

	const uint64_t n = m_mempoolTxs.size();
	const uint64_t max_weight = data.median_weight + (data.median_weight / 8) - miner_tx_weight;

	m_knapsack.resize((n + 1) * max_weight);
	memset(m_knapsack.data(), 0, max_weight * sizeof(uint32_t));

	for (size_t i = 1; i <= n; ++i) {
		const TxMempoolData& tx = m_mempoolTxs[i - 1];
		const uint32_t tx_fee = static_cast<uint32_t>(tx.fee / FEE_COEFF);
		const uint64_t tx_weight = tx.weight;

		uint32_t* row = m_knapsack.data() + i * max_weight;
		const uint32_t* prev_row = row - max_weight;

		row[0] = 0;
		memcpy(row + 1, prev_row + 1, (tx_weight - 1) * sizeof(uint32_t));

#define INNER_LOOP(k) { \
	const uint32_t fee_when_used = prev_row[w + k - tx_weight] + tx_fee; \
	const uint32_t fee_when_not_used = prev_row[w + k]; \
	row[w + k] = (fee_when_used > fee_when_not_used) ? fee_when_used : fee_when_not_used; \
}

		for (size_t w = tx_weight, max_w = max_weight - 3; w < max_w; w += 4) {
			INNER_LOOP(0);
			INNER_LOOP(1);
			INNER_LOOP(2);
			INNER_LOOP(3);
		}

#undef INNER_LOOP
	}

	// Now that we know which fee we can get for each weight, just find the maximum possible block reward
	best_reward = base_reward;
	uint64_t best_weight = 0;
	for (uint64_t w = 0, max_w = max_weight - 3; w < max_w; ++w) {
		const uint64_t fee = m_knapsack[n * max_weight + w] * FEE_COEFF;
		if (fee) {
			const uint64_t cur_reward = get_block_reward(base_reward, data.median_weight, fee, w + miner_tx_weight);
			if (cur_reward > best_reward) {
				best_reward = cur_reward;
				best_weight = w;
			}
		}
	}

	m_numTransactionHashes = 0;

	final_fees = 0;
	final_weight = miner_tx_weight;

	m_mempoolTxsOrder.clear();
	m_transactionHashes.assign(HASH_SIZE, 0);
	for (int i = static_cast<int>(n); (i > 0) && (best_weight > 0); --i) {
		if (m_knapsack[i * max_weight + best_weight] > m_knapsack[(i - 1) * max_weight + best_weight]) {
			m_mempoolTxsOrder.push_back(i - 1);
			const TxMempoolData& tx = m_mempoolTxs[i - 1];
			m_transactionHashes.insert(m_transactionHashes.end(), tx.id.h, tx.id.h + HASH_SIZE);
			++m_numTransactionHashes;
			best_weight -= tx.weight;
			final_fees += tx.fee;
			final_weight += tx.weight;
		}
	}

	m_knapsack.clear();
}
#endif

void BlockTemplate::select_mempool_transactions(const Mempool& mempool)
{
	// Only choose transactions that were received 5 or more seconds ago, or high fee (>= 0.006 XMR) transactions
	m_mempoolTxs.clear();

	const uint64_t cur_time = seconds_since_epoch();
	size_t total_mempool_transactions = 0;

	mempool.iterate([this, cur_time, &total_mempool_transactions](const hash&, const TxMempoolData& tx) {
		++total_mempool_transactions;

		if ((cur_time > tx.time_received + 5) || (tx.fee >= HIGH_FEE_VALUE)) {
			m_mempoolTxs.emplace_back(tx);
		}
	});

	// Safeguard for busy mempool moments
	// If the block template gets too big, nodes won't be able to send and receive it because of p2p packet size limit
	// Calculate how many transactions we can take

	PoolBlock* b = m_poolBlockTemplate;
	b->m_transactions.clear();
	b->m_transactions.resize(1);
        // For Carrot v1 blocks, protocol TX takes a slot
        if (b->m_majorVersion >= 10) {
                hash protocol_tx_hash;
                calculate_protocol_tx_hash(b->m_txinGenHeight, protocol_tx_hash);
                b->m_transactions.push_back(static_cast<indexed_hash>(protocol_tx_hash));
        }
	b->m_ephPublicKeys.clear();
	b->m_outputAmounts.clear();
        b->m_viewTags.clear();
        b->m_encryptedAnchors.clear();

	// Block template size without coinbase outputs and transactions (minus 2 bytes for output and tx count dummy varints)
	size_t k = b->serialize_mainchain_data().size() + b->serialize_sidechain_data().size() - 2;

	// Add output and tx count real varints
	writeVarint(m_shares.size(), [&k](uint8_t) { ++k; });
	writeVarint(m_mempoolTxs.size(), [&k](uint8_t) { ++k; });

	// Add a rough upper bound estimation of outputs' size. All outputs have <= 5 bytes for each output's reward (< 0.034359738368 XMR per output)
	k += m_shares.size() * (5 /* reward */ + 1 /* tx_type */ + HASH_SIZE /* stealth address */ + 1 /* viewtag */);

	// >= 0.034359738368 XMR is required for a 6 byte varint, add 1 byte per each potential 6-byte varint
	{
		uint64_t r = BASE_BLOCK_REWARD;
		for (const auto& tx : m_mempoolTxs) {
			r += tx.fee;
		}
		k += r / 34359738368ULL;
	}

	const uint32_t max_transactions = static_cast<uint32_t>((MAX_BLOCK_SIZE > k) ? ((MAX_BLOCK_SIZE - k) / HASH_SIZE) : 0);
	LOGINFO(6, max_transactions << " transactions can be taken with current block size limit");

	if (max_transactions == 0) {
		m_mempoolTxs.clear();
                
	}
	else if (m_mempoolTxs.size() > max_transactions) {
		std::nth_element(m_mempoolTxs.begin(), m_mempoolTxs.begin() + max_transactions, m_mempoolTxs.end());
		m_mempoolTxs.resize(max_transactions);
	}

	LOGINFO(4, "mempool has " << total_mempool_transactions << " transactions, taking " << m_mempoolTxs.size() << " transactions from it");
}

int BlockTemplate::create_miner_tx(const MinerData& data, const std::vector<MinerShare>& shares, uint64_t max_reward_amounts_weight, bool dry_run, uint64_t full_block_reward)
{
        m_minerTx.clear();

        const size_t num_outputs = shares.size();
        m_minerTx.reserve(num_outputs * 39 + 55);

        // For Carrot v1 (HF10+), use version 4
        m_minerTx.push_back(4);  // TRANSACTION_VERSION_CARROT

        writeVarint(MINER_REWARD_UNLOCK_TIME, m_minerTx);
        m_minerTx.push_back(1);  // Number of inputs
        m_minerTx.push_back(TXIN_GEN);
        writeVarint(data.height, m_minerTx);
        m_poolBlockTemplate->m_txinGenHeight = data.height;

        writeVarint(num_outputs, m_minerTx);

        m_poolBlockTemplate->m_ephPublicKeys.clear();
        m_poolBlockTemplate->m_outputAmounts.clear();
        m_poolBlockTemplate->m_viewTags.clear();
        m_poolBlockTemplate->m_encryptedAnchors.clear();
        m_poolBlockTemplate->m_ephPublicKeys.reserve(num_outputs);
        m_poolBlockTemplate->m_outputAmounts.reserve(num_outputs);

        uint64_t reward_amounts_weight = 0;

        // Carrot v1 outputs - prepare shared data for all outputs
        uint8_t input_context[33];
        carrot::make_input_context_coinbase(data.height, input_context);

        // Null payment ID for main addresses
        static const uint8_t null_payment_id[8] = {0};

        // Structure for Carrot output with pre-computed K_o
        struct CarrotOutput {
            size_t share_index;         // Original index into shares/m_rewards
            uint64_t amount;
            hash onetime_address;       // K_o
            hash eph_pubkey;            // D_e (per-output ephemeral pubkey)
            uint8_t view_tag[3];
            uint8_t encrypted_anchor[16];
        };
        std::vector<CarrotOutput> outputs;
        outputs.reserve(num_outputs);

        // Generate all outputs using single D_e, position-independent K_o
        for (size_t i = 0; i < num_outputs; ++i) {
            CarrotOutput out;
            out.share_index = i;
            out.amount = m_rewards[i];
            memset(out.onetime_address.h, 0, HASH_SIZE);
            memset(out.eph_pubkey.h, 0, HASH_SIZE);
            memset(out.view_tag, 0, 3);
            memset(out.encrypted_anchor, 0, 16);

            if (!dry_run) {
                // Derive anchor from wallet's spend public key (position-independent)
                uint8_t anchor[16];
                carrot::derive_deterministic_anchor_from_pubkey(
                    m_poolBlockTemplate->m_txkeySecSeed,
                    shares[i].m_wallet->spend_public_key(),
                    anchor);

                // Derive per-output ephemeral private key d_e from anchor
                hash eph_privkey;
                carrot::make_ephemeral_privkey(
                    anchor,
                    input_context,
                    shares[i].m_wallet->spend_public_key(),
                    null_payment_id,
                    eph_privkey);

                // Derive per-output ephemeral public key D_e = d_e * B
                carrot::make_ephemeral_pubkey_mainaddress(eph_privkey, out.eph_pubkey);

                // Generate shared secret using per-output d_e
                hash shared_secret_unctx;
                if (!carrot::make_shared_secret_sender(
                        eph_privkey,
                        shares[i].m_wallet->view_public_key(),
                        shared_secret_unctx)) {
                    LOGERR(1, "Failed to generate shared secret for output " << i);
                    return -4;
                }

                // Generate sender-receiver secret using per-output D_e
                hash sender_receiver_secret;
                carrot::make_sender_receiver_secret(
                    shared_secret_unctx,
                    out.eph_pubkey,
                    input_context,
                    sender_receiver_secret);

                // Generate onetime address K_o
                carrot::make_onetime_address_coinbase(
                    shares[i].m_wallet->spend_public_key(),
                    sender_receiver_secret,
                    out.amount,
                    out.onetime_address);

                // Generate 3-byte view tag
                carrot::make_view_tag(shared_secret_unctx, input_context, out.onetime_address, out.view_tag);

                // Encrypt anchor
                carrot::encrypt_anchor(anchor, sender_receiver_secret, out.onetime_address, out.encrypted_anchor);
            }
            outputs.push_back(out);
        }

        // Sort outputs by K_o (required by Salvium daemon)
        std::sort(outputs.begin(), outputs.end(),
            [](const CarrotOutput& a, const CarrotOutput& b) {
                return memcmp(a.onetime_address.h, b.onetime_address.h, HASH_SIZE) < 0;
            });

        // Write sorted outputs to miner tx (single D_e used for all)
        for (const auto& out : outputs) {
            // Amount
            writeVarint(out.amount, [this, &reward_amounts_weight](uint8_t b) {
                m_minerTx.push_back(b);
                ++reward_amounts_weight;
            });

            // txout_to_carrot_v1
            m_minerTx.push_back(TXOUT_TO_CARROT_V1);

            if (dry_run) {
                m_minerTx.insert(m_minerTx.end(), HASH_SIZE, 0);
                m_minerTx.push_back(4);
                m_minerTx.push_back('S');
                m_minerTx.push_back('A');
                m_minerTx.push_back('L');
                m_minerTx.push_back('1');
                m_minerTx.insert(m_minerTx.end(), 3, 0);
                m_minerTx.insert(m_minerTx.end(), 16, 0);
            } else {
                m_minerTx.insert(m_minerTx.end(), out.onetime_address.h, out.onetime_address.h + HASH_SIZE);
                m_minerTx.push_back(4);
                m_minerTx.push_back('S');
                m_minerTx.push_back('A');
                m_minerTx.push_back('L');
                m_minerTx.push_back('1');
                m_minerTx.insert(m_minerTx.end(), out.view_tag, out.view_tag + 3);
                m_minerTx.insert(m_minerTx.end(), out.encrypted_anchor, out.encrypted_anchor + 16);

                // Save for pool block template
                m_poolBlockTemplate->m_ephPublicKeys.emplace_back(out.onetime_address);
                m_poolBlockTemplate->m_outputAmounts.emplace_back(out.amount, out.view_tag[0]);
                std::vector<uint8_t> vt(out.view_tag, out.view_tag + 3);
                std::vector<uint8_t> ea(out.encrypted_anchor, out.encrypted_anchor + 16);
                m_poolBlockTemplate->m_viewTags.push_back(vt);
                m_poolBlockTemplate->m_encryptedAnchors.push_back(ea);
            }
        }

        if (dry_run) {
                if (reward_amounts_weight != max_reward_amounts_weight) {
                        LOGERR(1, "create_miner_tx: incorrect miner rewards during dry run");
                        return -1;
                }
        } else if (reward_amounts_weight > max_reward_amounts_weight) {
                LOGERR(1, "create_miner_tx: incorrect miner rewards during real run");
                return -2;
        }

        // TX_EXTRA - per-output D_e for Janus protection
        LOGINFO(3, "DEBUG: Carrot extra - major_version=" << data.major_version << ", dry_run=" << static_cast<int>(dry_run) << ", num_outputs=" << num_outputs);
        m_minerTxExtra.clear();
        m_poolBlockTemplate->m_additionalPubKeys.clear();

        if (num_outputs == 1) {
                // Single output: use TX_EXTRA_TAG_PUBKEY
                m_minerTxExtra.push_back(TX_EXTRA_TAG_PUBKEY);
                if (dry_run) {
                        m_minerTxExtra.insert(m_minerTxExtra.end(), HASH_SIZE, 0);
                } else {
                        m_poolBlockTemplate->m_txkeyPub = outputs[0].eph_pubkey;
                        m_minerTxExtra.insert(m_minerTxExtra.end(), 
                            outputs[0].eph_pubkey.h,
                            outputs[0].eph_pubkey.h + HASH_SIZE);
                }
        } else {
                // Multiple outputs: use TX_EXTRA_TAG_ADDITIONAL_PUBKEYS with ALL D_e values
                m_minerTxExtra.push_back(TX_EXTRA_TAG_ADDITIONAL_PUBKEYS);
                writeVarint(num_outputs, m_minerTxExtra);
                if (dry_run) {
                        m_minerTxExtra.insert(m_minerTxExtra.end(), num_outputs * HASH_SIZE, 0);
                } else {
                        // Store first D_e in m_txkeyPub for compatibility
                        m_poolBlockTemplate->m_txkeyPub = outputs[0].eph_pubkey;
                        for (size_t i = 0; i < num_outputs; ++i) {
                                m_minerTxExtra.insert(m_minerTxExtra.end(),
                                    outputs[i].eph_pubkey.h,
                                    outputs[i].eph_pubkey.h + HASH_SIZE);
                                if (i > 0) {
                                        m_poolBlockTemplate->m_additionalPubKeys.push_back(outputs[i].eph_pubkey);
                                }
                        }
                }
        }

        // Extra nonce
        m_minerTxExtra.push_back(TX_EXTRA_NONCE);
        const uint64_t corrected_extra_nonce_size = EXTRA_NONCE_SIZE + max_reward_amounts_weight - reward_amounts_weight;
        if (corrected_extra_nonce_size > EXTRA_NONCE_MAX_SIZE) {
                LOGWARN(5, "create_miner_tx: corrected_extra_nonce_size too large");
                return -3;
        }
        writeVarint(corrected_extra_nonce_size, m_minerTxExtra);
        uint64_t extraNonceOffsetInMinerTx = m_minerTxExtra.size();
        m_minerTxExtra.insert(m_minerTxExtra.end(), corrected_extra_nonce_size, 0);
        m_poolBlockTemplate->m_extraNonceSize = corrected_extra_nonce_size;

        // Merge mining tag
        m_minerTxExtra.push_back(TX_EXTRA_MERGE_MINING_TAG);
        m_minerTxExtra.push_back(static_cast<uint8_t>(m_poolBlockTemplate->m_merkleTreeDataSize + HASH_SIZE));
        writeVarint(m_poolBlockTemplate->m_merkleTreeData, m_minerTxExtra);
        m_minerTxExtra.insert(m_minerTxExtra.end(), HASH_SIZE, 0);

        // Write TX_EXTRA to miner tx
        writeVarint(m_minerTxExtra.size(), m_minerTx);
        extraNonceOffsetInMinerTx += m_minerTx.size();
        m_extraNonceOffsetInTemplate = extraNonceOffsetInMinerTx;
        m_minerTx.insert(m_minerTx.end(), m_minerTxExtra.begin(), m_minerTxExtra.end());

        m_minerTxExtra.clear();

        // type = MINER (1)
        writeVarint(1, m_minerTx);

        // amount_burnt = 20% of total block reward = 25% of miner outputs
        uint64_t miner_total = 0;
        for (size_t i = 0; i < num_outputs; ++i) {
                miner_total += m_rewards[i];
        }
        uint64_t stake_amount = full_block_reward / 5;
        writeVarint(stake_amount, m_minerTx);
        m_poolBlockTemplate->m_amountBurnt = stake_amount;

        // Save prefix size - everything up to here is the transaction prefix
        m_minerTxPrefixSize = static_cast<uint32_t>(m_minerTx.size());

        m_minerTx.push_back(0);  // RCT type
        return 1;
}

hash BlockTemplate::calc_sidechain_hash(uint32_t sidechain_extra_nonce) const
{
	// Calculate side-chain hash (all block template bytes + all side-chain bytes + consensus ID, replacing NONCE, EXTRA_NONCE and HASH itself with 0's)
	const size_t size = m_sidechainHashBlob.size();
	const size_t N = m_sidechainHashInputLength;

	const size_t sidechain_extra_nonce_offset = size - HASH_SIZE - EXTRA_NONCE_SIZE;
	const uint8_t sidechain_extra_nonce_buf[EXTRA_NONCE_SIZE] = {
		static_cast<uint8_t>(sidechain_extra_nonce >> 0),
		static_cast<uint8_t>(sidechain_extra_nonce >> 8),
		static_cast<uint8_t>(sidechain_extra_nonce >> 16),
		static_cast<uint8_t>(sidechain_extra_nonce >> 24)
	};

	hash result;
	uint8_t buf[288];

	const bool b = N && (N <= sidechain_extra_nonce_offset) && (N < size) && (size - N <= sizeof(buf));

	// Slow path: O(N)
	if (!b || pool_block_debug()) {
		keccak_custom([this, sidechain_extra_nonce_offset, &sidechain_extra_nonce_buf](int offset) -> uint8_t {
			const uint32_t k = static_cast<uint32_t>(offset - sidechain_extra_nonce_offset);
			if (k < EXTRA_NONCE_SIZE) {
				return sidechain_extra_nonce_buf[k];
			}
			return m_sidechainHashBlob[offset];
		}, static_cast<int>(size), result.h, HASH_SIZE);
	}

	// Fast path: O(1)
	if (b) {
		const int inlen = static_cast<int>(size - N);

		memcpy(buf, m_sidechainHashBlob.data() + N, size - N);
		memcpy(buf + sidechain_extra_nonce_offset - N, sidechain_extra_nonce_buf, EXTRA_NONCE_SIZE);

		std::array<uint64_t, 25> st = m_sidechainHashKeccakState;
		keccak_finish(buf, inlen, st);

		if (pool_block_debug() && (memcmp(st.data(), result.h, HASH_SIZE) != 0)) {
			LOGERR(1, "calc_sidechain_hash fast path is broken. Fix the code!");
		}

		memcpy(result.h, st.data(), HASH_SIZE);
	}

	return result;
}

hash BlockTemplate::calc_miner_tx_hash(uint32_t extra_nonce) const
{
        uint8_t hashes[HASH_SIZE * 3];
        const uint8_t* data = m_blockTemplateBlob.data() + m_minerTxOffsetInTemplate;
        const size_t prefix_size = m_minerTxPrefixSize;
        const size_t base_rct_size = m_minerTxSize - prefix_size;
        
        LOGINFO(3, "DEBUG: minerTxOffsetInTemplate=" << m_minerTxOffsetInTemplate << ", m_minerTxSize=" << m_minerTxSize);
        LOGINFO(3, "DEBUG: First 20 bytes of miner tx in template:");
        char hex_buf[128] = {0};
        for (size_t i = 0; i < 20 && i < m_minerTxSize; ++i) {
                snprintf(hex_buf + i*2, 3, "%02x", data[i]);
        }
        LOGINFO(3, static_cast<const char*>(hex_buf));

        // Pre-Carrot: original logic with patching
        const size_t extra_nonce_offset = m_extraNonceOffsetInTemplate - m_minerTxOffsetInTemplate;
        const uint8_t extra_nonce_buf[EXTRA_NONCE_SIZE] = {
                static_cast<uint8_t>(extra_nonce >> 0),
                static_cast<uint8_t>(extra_nonce >> 8),
                static_cast<uint8_t>(extra_nonce >> 16),
                static_cast<uint8_t>(extra_nonce >> 24)
        };

        hash merge_mining_root;
        {
                const hash sidechain_id = calc_sidechain_hash(extra_nonce);
                const uint32_t n_aux_chains = static_cast<uint32_t>(m_poolBlockTemplate->m_auxChains.size() + 1);
                const uint32_t aux_slot = get_aux_slot(m_sidechain->consensus_hash(), m_poolBlockTemplate->m_auxNonce, n_aux_chains);
                merge_mining_root = get_root_from_proof(sidechain_id, m_poolBlockTemplate->m_merkleProof, aux_slot, n_aux_chains);
        }

        const size_t merkle_root_offset = extra_nonce_offset + m_poolBlockTemplate->m_extraNonceSize + 2 + m_poolBlockTemplate->m_merkleTreeDataSize;

        // 1. Hash prefix with extra_nonce and merge_mining_root applied
        hash full_hash;
        uint8_t tx_buf[288];

        const size_t N = m_minerTxKeccakStateInputLength;
        const bool b = N && (N <= extra_nonce_offset) && (N < prefix_size) && (prefix_size - N <= sizeof(tx_buf));

        LOGINFO(6, "DEBUG: extra_nonce=" << extra_nonce << ", extra_nonce_offset=" << extra_nonce_offset << ", merkle_root_offset=" << merkle_root_offset);

        // DEBUG: Log what we're actually hashing
        std::vector<uint8_t> debug_prefix(prefix_size);
        for (size_t i = 0; i < prefix_size; ++i) {
            uint32_t k = static_cast<uint32_t>(i - extra_nonce_offset);
            if (k < EXTRA_NONCE_SIZE) {
                debug_prefix[i] = extra_nonce_buf[k];
            } else {
                k = static_cast<uint32_t>(i - merkle_root_offset);
                if (k < HASH_SIZE) {
                    debug_prefix[i] = merge_mining_root.h[k];
                } else {
                    debug_prefix[i] = data[i];
                }
            }
        }
        LOGINFO(6, "DEBUG: Hashing prefix (" << prefix_size << " bytes): " << log::hex_buf(debug_prefix.data(), std::min(size_t(120), prefix_size)));

        // Slow path: O(N)
        if (!b || pool_block_debug())
        {
                keccak_custom([data, extra_nonce_offset, &extra_nonce_buf, merkle_root_offset, &merge_mining_root](int offset) {
                        uint32_t k = static_cast<uint32_t>(offset - static_cast<int>(extra_nonce_offset));
                        if (k < EXTRA_NONCE_SIZE) {
                                return extra_nonce_buf[k];
                        }

                        k = static_cast<uint32_t>(offset - static_cast<int>(merkle_root_offset));
                        if (k < HASH_SIZE) {
                                return merge_mining_root.h[k];
                        }

                        return data[offset];
                }, static_cast<int>(prefix_size), full_hash.h, HASH_SIZE);
                memcpy(hashes, full_hash.h, HASH_SIZE);
        }

        // Fast path: O(1)
        if (b) {
                const int inlen = static_cast<int>(prefix_size - N);

                memcpy(tx_buf, data + N, inlen);
                memcpy(tx_buf + extra_nonce_offset - N, extra_nonce_buf, EXTRA_NONCE_SIZE);
                memcpy(tx_buf + merkle_root_offset - N, merge_mining_root.h, HASH_SIZE);

                std::array<uint64_t, 25> st = m_minerTxKeccakState;
                keccak_finish(tx_buf, inlen, st);

                if (pool_block_debug() && (memcmp(st.data(), full_hash.h, HASH_SIZE) != 0)) {
                        LOGERR(1, "calc_miner_tx_hash fast path is broken. Fix the code!");
                }

                memcpy(hashes, st.data(), HASH_SIZE);
        }

        // 2. Hash base RCT (type + amount_burnt bytes)
        uint8_t base_rct_hash[HASH_SIZE];
        keccak(data + prefix_size, static_cast<int>(base_rct_size), base_rct_hash);
        memcpy(hashes + HASH_SIZE, base_rct_hash, HASH_SIZE);

        // 3. Prunable RCT is null for coinbase
        memset(hashes + HASH_SIZE * 2, 0, HASH_SIZE);

        // Calculate miner transaction hash (hash of the 3 hashes)
        hash result;
        keccak(hashes, sizeof(hashes), result.h);

        // Debug: log the component hashes
        char prefix_hash_hex[65] = {0};
        char base_rct_hash_hex[65] = {0};
        char prunable_hash_hex[65] = {0};
        char final_hash_hex[65] = {0};
        for (int i = 0; i < 32; ++i) {
                snprintf(prefix_hash_hex + i*2, 3, "%02x", hashes[i]);
                snprintf(base_rct_hash_hex + i*2, 3, "%02x", hashes[32 + i]);
                snprintf(prunable_hash_hex + i*2, 3, "%02x", hashes[64 + i]);
                snprintf(final_hash_hex + i*2, 3, "%02x", result.h[i]);
        }
        LOGINFO(3, "Miner TX hash components:");
        LOGINFO(3, "  Prefix hash:   " << static_cast<const char*>(prefix_hash_hex));
        LOGINFO(3, "  Base RCT hash: " << static_cast<const char*>(base_rct_hash_hex));
        LOGINFO(3, "  Prunable hash: " << static_cast<const char*>(prunable_hash_hex));
        LOGINFO(3, "  Final TX hash: " << static_cast<const char*>(final_hash_hex));
        LOGINFO(3, "  Prefix size: " << prefix_size << ", Base RCT size: " << base_rct_size << ", Total TX size: " << m_minerTxSize);

        return result;
}

void BlockTemplate::calc_merkle_tree_main_branch()
{
        m_merkleTreeMainBranch.clear();
        const uint64_t count = m_numTransactionHashes + (m_majorVersion >= 10 ? 2 : 1);
        if (count == 1) {
                return;
        }
        const uint8_t* h = m_transactionHashes.data();
        if (count == 2) {
                hash protocol_hash;
                memcpy(protocol_hash.h, h + HASH_SIZE, HASH_SIZE);
                LOGINFO(3, "Merkle branch protocol tx hash: " << protocol_hash);
                m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), h + HASH_SIZE, h + HASH_SIZE * 2);
        }
	else {
		size_t i, j, cnt;

		for (i = 0, cnt = 1; cnt <= count; ++i, cnt <<= 1) {}

		cnt >>= 1;

		std::vector<uint8_t> ints(cnt * HASH_SIZE);
		memcpy(ints.data(), h, (cnt * 2 - count) * HASH_SIZE);

		hash tmp;

		for (i = cnt * 2 - count, j = cnt * 2 - count; j < cnt; i += 2, ++j) {
			if (i == 0) {
				m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), h + HASH_SIZE, h + HASH_SIZE * 2);
			}
			keccak(h + i * HASH_SIZE, HASH_SIZE * 2, tmp.h);
			memcpy(ints.data() + j * HASH_SIZE, tmp.h, HASH_SIZE);
		}

		while (cnt > 2) {
			cnt >>= 1;
			for (i = 0, j = 0; j < cnt; i += 2, ++j) {
				if (i == 0) {
					m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), ints.data() + HASH_SIZE, ints.data() + HASH_SIZE * 2);
				}
				keccak(ints.data() + i * HASH_SIZE, HASH_SIZE * 2, tmp.h);
				memcpy(ints.data() + j * HASH_SIZE, tmp.h, HASH_SIZE);
			}
		}

		m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), ints.data() + HASH_SIZE, ints.data() + HASH_SIZE * 2);
	}
        // DEBUG: Log the calculated merkle root
        if (m_majorVersion >= 10) {
            hash merkle_root;
            // The merkle root is the hash of (miner_hash + last_branch_element)
            uint8_t buf[HASH_SIZE * 2];
            memcpy(buf, m_transactionHashes.data(), HASH_SIZE);
            if (!m_merkleTreeMainBranch.empty()) {
                memcpy(buf + HASH_SIZE, m_merkleTreeMainBranch.data() + m_merkleTreeMainBranch.size() - HASH_SIZE, HASH_SIZE);
                keccak(buf, sizeof(buf), merkle_root.h);
                LOGINFO(6, "Calculated merkle root: " << merkle_root);
            }
        }
}

bool BlockTemplate::get_difficulties(const uint32_t template_id, uint64_t& height, uint64_t& sidechain_height, difficulty_type& mainchain_difficulty, difficulty_type& aux_diff, difficulty_type& sidechain_difficulty) const
{
	ReadLock lock(m_lock);

	if (template_id == m_templateId) {
		height = m_height;
		sidechain_height = m_poolBlockTemplate->m_sidechainHeight;
		mainchain_difficulty = m_difficulty;
		aux_diff = m_auxDifficulty;
		sidechain_difficulty = m_poolBlockTemplate->m_difficulty;
		return true;
	}

	const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];

	if (old && (template_id == old->m_templateId)) {
		return old->get_difficulties(template_id, height, sidechain_height, mainchain_difficulty, aux_diff, sidechain_difficulty);
	}

	return false;
}

uint32_t BlockTemplate::get_hashing_blob(const uint32_t template_id, uint32_t extra_nonce, uint8_t (&blob)[128], uint64_t& height, difficulty_type& difficulty, difficulty_type& aux_diff, difficulty_type& sidechain_difficulty, hash& seed_hash, size_t& nonce_offset) const
{
	ReadLock lock(m_lock);

	if (template_id == m_templateId) {
		height = m_height;
		difficulty = m_difficulty;
		aux_diff = m_auxDifficulty;
		sidechain_difficulty = m_poolBlockTemplate->m_difficulty;
		seed_hash = m_seedHash;
		nonce_offset = m_nonceOffset;

		return get_hashing_blob_nolock(extra_nonce, blob);
	}

	const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];

	if (old && (template_id == old->m_templateId)) {
		return old->get_hashing_blob(template_id, extra_nonce, blob, height, difficulty, aux_diff, sidechain_difficulty, seed_hash, nonce_offset);
	}

	return 0;
}

uint32_t BlockTemplate::get_hashing_blob(uint32_t extra_nonce, uint8_t (&blob)[128], uint64_t& height, uint64_t& sidechain_height, difficulty_type& difficulty, difficulty_type& aux_diff, difficulty_type& sidechain_difficulty, hash& seed_hash, size_t& nonce_offset, uint32_t& template_id) const
{
	ReadLock lock(m_lock);

	height = m_height;
	sidechain_height = m_poolBlockTemplate->m_sidechainHeight;
	difficulty = m_difficulty;
	aux_diff = m_auxDifficulty;
	sidechain_difficulty = m_poolBlockTemplate->m_difficulty;
	seed_hash = m_seedHash;
	nonce_offset = m_nonceOffset;
	template_id = m_templateId;

	return get_hashing_blob_nolock(extra_nonce, blob);
}

uint32_t BlockTemplate::get_hashing_blob_nolock(uint32_t extra_nonce, uint8_t* blob) const
{
        uint8_t* p = blob;
        // Block header
        memcpy(p, m_blockTemplateBlob.data(), m_blockHeaderSize);
        p += m_blockHeaderSize;

        // Merkle tree hash - build from all transactions and use merkle_hash()
        hash miner_tx_hash = calc_miner_tx_hash(extra_nonce);
        const size_t num_hashes = m_transactionHashes.size() / HASH_SIZE;
        
        if (num_hashes == 0) {
                LOGERR(3, "get_hashing_blob_nolock: m_transactionHashes is empty");
                return 0;
        }
        
        std::vector<hash> hashes(num_hashes);
        hashes[0] = miner_tx_hash;  // miner tx with current extra_nonce

        for (size_t i = 1; i < num_hashes; ++i) {
                memcpy(hashes[i].h, m_transactionHashes.data() + i * HASH_SIZE, HASH_SIZE);
        }
        root_hash merkle_root;
        merkle_hash(hashes, merkle_root);
        
        LOGINFO(6, "  m_transactionHashes size: " << m_transactionHashes.size() << " num_hashes: " << num_hashes);
        LOGINFO(6, "  Result merkle root: " << static_cast<const hash&>(merkle_root));
        memcpy(p, merkle_root.h, HASH_SIZE); 
        p += HASH_SIZE;

        // Total number of transactions in this block (including the miner tx)
        // FOR HF10+, include both miner tx and protocol tx
        const uint64_t tx_count_in_header = m_numTransactionHashes + (m_majorVersion >= 10 ? 2 : 1);
        writeVarint(tx_count_in_header, [&p](uint8_t b) { *(p++) = b; });

        // DEBUG: Show what hashing blob we're creating
        LOGINFO(6, "DEBUG get_hashing_blob result (" << static_cast<uint32_t>(p - blob) << " bytes): " << log::hex_buf(blob, std::min(size_t(76), static_cast<size_t>(p - blob))));
        
        return static_cast<uint32_t>(p - blob);
}

uint32_t BlockTemplate::get_hashing_blobs(uint32_t extra_nonce_start, uint32_t count, std::vector<uint8_t>& blobs, uint64_t& height, difficulty_type& difficulty, difficulty_type& aux_diff, difficulty_type& sidechain_difficulty, hash& seed_hash, size_t& nonce_offset, uint32_t& template_id) const
{
	blobs.clear();

	const size_t required_capacity = static_cast<size_t>(count) * 80;
	if (blobs.capacity() < required_capacity) {
		blobs.reserve(required_capacity * 2);
	}

	ReadLock lock(m_lock);

	height = m_height;
	difficulty = m_difficulty;
	aux_diff = m_auxDifficulty;
	sidechain_difficulty = m_poolBlockTemplate->m_difficulty;
	seed_hash = m_seedHash;
	nonce_offset = m_nonceOffset;
	template_id = m_templateId;

	constexpr size_t MIN_BLOB_SIZE = 76;
	constexpr size_t MAX_BLOB_SIZE = 128;

	blobs.resize(MAX_BLOB_SIZE);
	const uint32_t blob_size = get_hashing_blob_nolock(extra_nonce_start, blobs.data());

	if (blob_size > MAX_BLOB_SIZE) {
		LOGERR(1, "internal error: get_hashing_blob_nolock returned too large blob size " << blob_size << ", expected <= " << MAX_BLOB_SIZE);
		PANIC_STOP();
	}
	else if (blob_size < MIN_BLOB_SIZE) {
		LOGERR(1, "internal error: get_hashing_blob_nolock returned too little blob size " << blob_size << ", expected >= " << MIN_BLOB_SIZE);
	}

	blobs.resize(static_cast<size_t>(blob_size) * count);

	if (count > 1) {
		uint8_t* blobs_data = blobs.data();

		std::atomic<uint32_t> counter = 1;

		parallel_run(uv_default_loop_checked(), [this, blob_size, extra_nonce_start, count, &counter, blobs_data]() {
			for (;;) {
				const uint32_t i = counter.fetch_add(1);
				if (i >= count) {
					return;
				}

				const uint32_t n = get_hashing_blob_nolock(extra_nonce_start + i, blobs_data + static_cast<size_t>(i) * blob_size);
				if (n != blob_size) {
					LOGERR(1, "internal error: get_hashing_blob_nolock returned different blob size " << n << ", expected " << blob_size);
				}
			}
		}, true);
	}

	return blob_size;
}

std::vector<AuxChainData> BlockTemplate::get_aux_chains(const uint32_t template_id) const
{
	ReadLock lock(m_lock);

	if (template_id != m_templateId) {
		const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];
		if (old && (template_id == old->m_templateId)) {
			return old->get_aux_chains(template_id);
		}

		return {};
	}

	return m_poolBlockTemplate->m_auxChains;
}

bool BlockTemplate::get_aux_proof(const uint32_t template_id, uint32_t extra_nonce, const hash& h, std::vector<hash>& proof, uint32_t& path) const
{
	ReadLock lock(m_lock);

	if (template_id != m_templateId) {
		const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];
		if (old && (template_id == old->m_templateId)) {
			return old->get_aux_proof(template_id, extra_nonce, h, proof, path);
		}

		return false;
	}

	const hash sidechain_id = calc_sidechain_hash(extra_nonce);
	const uint32_t n_aux_chains = static_cast<uint32_t>(m_poolBlockTemplate->m_auxChains.size() + 1);

	uint32_t found_aux_slot = n_aux_chains;

	std::vector<hash> hashes(n_aux_chains);

	for (const AuxChainData& aux_data : m_poolBlockTemplate->m_auxChains) {
		const uint32_t aux_slot = get_aux_slot(aux_data.unique_id, m_poolBlockTemplate->m_auxNonce, n_aux_chains);
		hashes[aux_slot] = aux_data.data;

		if (aux_data.data == h) {
			found_aux_slot = aux_slot;
		}
	}

	const uint32_t aux_slot = get_aux_slot(m_sidechain->consensus_hash(), m_poolBlockTemplate->m_auxNonce, n_aux_chains);
	hashes[aux_slot] = sidechain_id;

	if (sidechain_id == h) {
		found_aux_slot = aux_slot;
	}

	if (found_aux_slot >= n_aux_chains) {
		return false;
	}

	root_hash root;
	const bool result = merkle_hash_with_proof(hashes, found_aux_slot, proof, path, root);

	if (pool_block_debug()) {
		std::vector<std::vector<hash>> tree;
		merkle_hash_full_tree(hashes, tree);

		std::vector<hash> proof2;
		uint32_t path2 = 0;

		const bool result2 = get_merkle_proof(tree, h, proof2, path2);
		
		if ((result2 != result) || (proof2 != proof) || (path2 != path)) {
			LOGERR(1, "get_aux_proof: merkle_hash_with_proof and get_merkle_proof returned different results. Fix the code!");
		}
	}

	return result;
}

std::vector<uint8_t> BlockTemplate::get_block_template_blob(uint32_t template_id, uint32_t sidechain_extra_nonce, size_t& nonce_offset, size_t& extra_nonce_offset, size_t& merkle_root_offset, hash& merge_mining_root, const BlockTemplate** pThis) const
{
        ReadLock lock(m_lock);
        if (template_id != m_templateId) {
                const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];
                if (old && (template_id == old->m_templateId)) {
                        return old->get_block_template_blob(template_id, sidechain_extra_nonce, nonce_offset, extra_nonce_offset, merkle_root_offset, merge_mining_root, pThis);
                }
                nonce_offset = 0;
                extra_nonce_offset = 0;
                merkle_root_offset = 0;
                merge_mining_root = {};
                return std::vector<uint8_t>();
        }

        nonce_offset = m_nonceOffset;
        extra_nonce_offset = m_extraNonceOffsetInTemplate;
        
        const hash sidechain_id = calc_sidechain_hash(sidechain_extra_nonce);
        const uint32_t n_aux_chains = static_cast<uint32_t>(m_poolBlockTemplate->m_auxChains.size() + 1);
        const uint32_t aux_slot = get_aux_slot(m_sidechain->consensus_hash(), m_poolBlockTemplate->m_auxNonce, n_aux_chains);
        merge_mining_root = get_root_from_proof(sidechain_id, m_poolBlockTemplate->m_merkleProof, aux_slot, n_aux_chains);
        
        if (m_extraNonceOffsetInTemplate > 0) {
                merkle_root_offset = m_extraNonceOffsetInTemplate + m_poolBlockTemplate->m_extraNonceSize + 2 + m_poolBlockTemplate->m_merkleTreeDataSize;
        } else {
                merkle_root_offset = 0;
        }
        
        *pThis = this;
        return m_blockTemplateBlob;
}

bool BlockTemplate::submit_sidechain_block(uint32_t template_id, uint32_t nonce, uint32_t extra_nonce)
{
	const uint64_t received_timestamp = microseconds_since_epoch();

	WriteLock lock(m_lock);

	if (template_id == m_templateId) {
		m_poolBlockTemplate->m_receivedTimestamp = received_timestamp;

		m_poolBlockTemplate->m_nonce = nonce;
		m_poolBlockTemplate->m_extraNonce = extra_nonce;
		m_poolBlockTemplate->m_sidechainId = calc_sidechain_hash(extra_nonce);
		m_poolBlockTemplate->m_sidechainExtraBuf[3] = extra_nonce;

		const uint32_t n_aux_chains = static_cast<uint32_t>(m_poolBlockTemplate->m_auxChains.size() + 1);
		const uint32_t aux_slot = get_aux_slot(m_sidechain->consensus_hash(), m_poolBlockTemplate->m_auxNonce, n_aux_chains);

		m_poolBlockTemplate->m_merkleRoot = get_root_from_proof(m_poolBlockTemplate->m_sidechainId, m_poolBlockTemplate->m_merkleProof, aux_slot, n_aux_chains);

		if (pool_block_debug()) {
			std::vector<uint8_t> buf = m_poolBlockTemplate->serialize_mainchain_data();
			const std::vector<uint8_t> sidechain_data = m_poolBlockTemplate->serialize_sidechain_data();

			memcpy(buf.data() + m_nonceOffset, &nonce, NONCE_SIZE);
			memcpy(buf.data() + m_extraNonceOffsetInTemplate, &extra_nonce, EXTRA_NONCE_SIZE);

			buf.insert(buf.end(), sidechain_data.begin(), sidechain_data.end());

			PoolBlock check;
			const int result = check.deserialize(buf.data(), buf.size(), *m_sidechain, nullptr, false);
			if (result != 0) {
				LOGERR(1, "pool block blob generation and/or parsing is broken, error " << result);
			}

			if (m_hasher) {
				hash pow_hash;
				if (!check.get_pow_hash(m_hasher, check.m_txinGenHeight, m_seedHash, pow_hash)) {
					LOGERR(1, "PoW check failed for the sidechain block. Fix it! ");
				}
				else if (!check.m_difficulty.check_pow(pow_hash)) {
					LOGERR(1, "Sidechain block has wrong PoW. Fix it! ");
				}
			}
		}

		m_poolBlockTemplate->m_verified = true;
		if (!m_sidechain->incoming_block_seen(*m_poolBlockTemplate)) {
			m_poolBlockTemplate->m_wantBroadcast = true;
			const bool result = m_sidechain->add_block(*m_poolBlockTemplate);
			if (!result) {
				LOGWARN(3, "failed to submit a share: add_block failed for template id " << template_id);
			}
			return result;
		}

		const PoolBlock* b = m_poolBlockTemplate;
		LOGWARN(3, "failed to submit a share: template id " << template_id << ", block " << b->m_sidechainId << ", nonce = " << b->m_nonce << ", extra_nonce = " << b->m_extraNonce << " was already added before");
		return false;
	}

	BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];

	if (old && (template_id == old->m_templateId)) {
		return old->submit_sidechain_block(template_id, nonce, extra_nonce);
	}

	LOGWARN(3, "failed to submit a share: template id " << template_id << " is too old/out of range, current template id is " << m_templateId);
	return false;
}

hash BlockTemplate::calc_tx_merkle_root(uint32_t extra_nonce) const
{
    const hash miner_hash = calc_miner_tx_hash(extra_nonce);
    const uint8_t* protocol_hash_ptr = m_transactionHashes.data() + HASH_SIZE;
    
    uint8_t combined[HASH_SIZE * 2];
    memcpy(combined, miner_hash.h, HASH_SIZE);
    memcpy(combined + HASH_SIZE, protocol_hash_ptr, HASH_SIZE);
    
    hash result;
    keccak(combined, HASH_SIZE * 2, result.h);
    return result;
}

void BlockTemplate::init_merge_mining_merkle_proof()
{
	const uint32_t n_aux_chains = static_cast<uint32_t>(m_poolBlockTemplate->m_auxChains.size() + 1);

	m_poolBlockTemplate->m_merkleProof.clear();
	m_auxDifficulty = diff_max;

	if (n_aux_chains == 1) {
		return;
	}

	std::vector<hash> hashes(n_aux_chains);
	std::vector<bool> used(n_aux_chains);

	for (const AuxChainData& aux_data : m_poolBlockTemplate->m_auxChains) {
		const uint32_t aux_slot = get_aux_slot(aux_data.unique_id, m_poolBlockTemplate->m_auxNonce, n_aux_chains);
		hashes[aux_slot] = aux_data.data;
		used[aux_slot] = true;

		if (aux_data.difficulty < m_auxDifficulty) {
			m_auxDifficulty = aux_data.difficulty;
		}
	}

	const uint32_t aux_slot = get_aux_slot(m_sidechain->consensus_hash(), m_poolBlockTemplate->m_auxNonce, n_aux_chains);
	hashes[aux_slot] = m_poolBlockTemplate->m_sidechainId;
	used[aux_slot] = true;

	for (bool b : used) {
		if (!b) {
			LOGERR(1, "aux nonce is invalid. Fix the code!");
			break;
		}
	}

	root_hash root;
	if (!merkle_hash_with_proof(hashes, aux_slot, m_poolBlockTemplate->m_merkleProof, m_poolBlockTemplate->m_merkleProofPath, root)) {
		LOGERR(1, "init_merge_mining_merkle_proof: merkle_hash_with_proof failed. Fix the code!");
		return;
	}

	if (pool_block_debug()) {
		std::vector<std::vector<hash>> tree;
		merkle_hash_full_tree(hashes, tree);

		std::vector<hash> proof;
		uint32_t path = 0;

		if (!get_merkle_proof(tree, m_poolBlockTemplate->m_sidechainId, proof, path)) {
			LOGERR(1, "init_merge_mining_merkle_proof: get_merkle_proof failed. Fix the code!");
			return;
		}

		if ((proof != m_poolBlockTemplate->m_merkleProof) || (path != m_poolBlockTemplate->m_merkleProofPath)) {
			LOGERR(1, "init_merge_mining_merkle_proof: merkle_hash_with_proof and get_merkle_proof returned different results. Fix the code!");
		}
	}
}

} // namespace p2pool
