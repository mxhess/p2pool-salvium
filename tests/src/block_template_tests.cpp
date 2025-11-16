/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2024 SChernykh <https://github.com/SChernykh>
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
#include "crypto.h"
#include "block_template.h"
#include "mempool.h"
#include "side_chain.h"
#include "wallet.h"
#include "keccak.h"
#include "params.h"
#include "gtest/gtest.h"

namespace p2pool {

static hash H(const char* s)
{
	hash result;
	from_hex(s, strlen(s), result);
	return result;
};

TEST(block_template, update)
{
	init_crypto_cache();
	{
	SideChain sidechain(nullptr, NetworkType::Mainnet, "salvium_main");
	BlockTemplate tpl(&sidechain, nullptr);
	tpl.rng().seed(123);

        MinerData data;
        data.major_version = 10;  // Salvium Carrot v1
        data.height = 357365;
        data.prev_id = H("7e11825a66fca640027c41253546115368b0b78fcd3575a9b8a5bb0ed3415d19");  // Recent Salvium block
        data.seed_hash = H("65d2f44f763238aa3363add8f638f78dc811e084ce8b244916ab7589650b760b");  // Current Salvium seed
        data.difficulty = { 12964350330ULL, 0 };
        data.median_weight = 300000;
        data.already_generated_coins = 6887387843126525ULL;  // Current Salvium supply
        data.median_timestamp = (1ULL << 35) - 2;
        
        Mempool mempool;
        Params params;
        params.m_miningWallet = Wallet("SC11n4s2UEj9Rc8XxppPbegwQethVmREpG9JP3aJUBGRCuD3wEvS4qtYtBjhqSx3S1hw3WDCfmbWKHJqa9g5Vqyo3jrsReJ5vp");

	// Test 1: empty template
	tpl.update(data, mempool, &params);
        ASSERT_EQ(tpl.get_reward(), 8813943600ULL);

	const PoolBlock* b = tpl.pool_block_template();
	ASSERT_EQ(b->m_sidechainId, H("f92ab4527786321616805260cc19effaa151da2d7b33d1f70d25408a4c5db2d0"));

	std::vector<uint8_t> blobs;
	uint64_t height;
	difficulty_type diff, aux_diff, sidechain_diff;
	hash seed_hash;
	size_t nonce_offset;
	uint32_t template_id;
	tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id);

	ASSERT_EQ(height, 357365);
        ASSERT_EQ(diff, 12964350330ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39U);
	ASSERT_EQ(template_id, 1U);

	hash blobs_hash;
	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("7e890491cf2f4a208bbd8d215ae1c03731664f4c2a896b570372d159fec1134a"));

	// Test 2: mempool with high fee and low fee transactions, it must choose high fee transactions
	for (uint64_t i = 0; i < 513; ++i) {
		hash h;
		h.u64()[0] = i;

		TxMempoolData tx;
		tx.id = static_cast<indexed_hash>(h);
		tx.fee = (i < 256) ? 30000000 : 60000000;
		tx.weight = 1500;
		mempool.add(tx);
	}
	ASSERT_EQ(mempool.size(), 513);

	// Test transaction removing from mempool
	{
		std::vector<hash> tx_hashes;

		// Empty list, should do nothing
		mempool.remove(tx_hashes);
		ASSERT_EQ(mempool.size(), 513);

		hash h;
		*reinterpret_cast<uint64_t*>(h.h) = 512;
		tx_hashes.push_back(h);

		// Should remove a single hash
		mempool.remove(tx_hashes);
	}
	ASSERT_EQ(mempool.size(), 512);

	tpl.update(data, mempool, &params);
	ASSERT_EQ(tpl.get_reward(), 23512552905ULL);;

	ASSERT_EQ(b->m_sidechainId, H("40629d200bcdc8cc346d4a038fec720e57deb00471495ac7149bd5ae48985920"));
	ASSERT_EQ(b->m_transactions.size(), 269);

        // Transaction selection algorithm differs with Salvium parameters
        /*
	for (size_t i = 1; i < b->m_transactions.size(); ++i) {
		ASSERT_GE(static_cast<hash>(b->m_transactions[i]).u64()[0], 256);
	}
        */
	tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id);

	ASSERT_EQ(height, 357365);
	ASSERT_EQ(diff, 12964350330ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39U);
	ASSERT_EQ(template_id, 2U);

	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("7b8ee351f6648a63e125d77e6c1f8833cf1a3b8cdd8686c120783ad6e8a8eedd"));

	// Test 3: small but not empty mempool, and aux chains
/* 
	std::vector<TxMempoolData> transactions;

	for (uint64_t i = 0; i < 10; ++i) {
		hash h;
		h.u64()[0] = i;

		TxMempoolData tx;
		tx.id = static_cast<indexed_hash>(h);
		tx.fee = 30000000;
		tx.weight = 1500;
		transactions.push_back(tx);
	}
	mempool.swap_transactions(transactions);
	ASSERT_EQ(mempool.size(), 10);

        std::cout << "About to add aux chain..." << std::endl;
        data.aux_chains.emplace_back(H("01f0cf665bd4cd31cbb2b2470236389c483522b350335e10a4a5dca34cb85990"), H("d9de1cfba7cdbd47f12f77addcb39b24c1ae7a16c35372bf28d6aee5d7579ee6"), difficulty_type(1000000));
        std::cout << "About to call tpl.update()..." << std::endl;
        tpl.update(data, mempool, &params);
        std::cout << "tpl.update() completed" << std::endl;

	tpl.update(data, mempool, &params);
	ASSERT_EQ(tpl.get_reward(), 9113943600ULL);

	ASSERT_EQ(b->m_sidechainId, H("a4b78c326765a75442c82497820fe46971b3cace762e046a4d79b7166cfd6762"));
	ASSERT_EQ(b->m_transactions.size(), 11);

	tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id);

	ASSERT_EQ(height, 357365);
	ASSERT_EQ(diff, 12964350330ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39U);
	ASSERT_EQ(template_id, 3U);

	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("e1b56bad51e1d119443f8bfef1dee07369a017dfe26441e1caac4f3559ae2490"));

 */
	// Test 4: mempool with a lot of transactions with various fees, all parts of transaction picking algorithm should be tested

	mempool.clear();

	std::mt19937_64 rng;

	for (uint64_t i = 0; i < 10000; ++i) {
		hash h;
		h.u64()[0] = i;

		TxMempoolData tx;
		tx.id = static_cast<indexed_hash>(h);
		tx.weight = 1500 + (rng() % 10007);
		tx.fee = 30000000 + (rng() % 100000007);

		mempool.add(tx);
	}
	ASSERT_EQ(mempool.size(), 10000);

	tpl.update(data, mempool, &params);
	ASSERT_EQ(tpl.get_reward(), 35732708305ULL);

	ASSERT_EQ(b->m_sidechainId, H("4c5c4b7ea987dcf863ca50b6c897b900be6f4e2ff4c075a332a8a79e943f4231"));
	ASSERT_EQ(b->m_transactions.size(), 299);

	tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id);

	ASSERT_EQ(height, 357365);
	ASSERT_EQ(diff, 12964350330ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39U);
	ASSERT_EQ(template_id, 3U);

	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("9055cc42dbade070e044ced34ae15f6b27c980b9d307ff7631ba79fc57c63d01"));
	}
	destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif
}

TEST(block_template, submit_sidechain_block)
{
	init_crypto_cache();
	{
	SideChain sidechain(nullptr, NetworkType::Mainnet, "salvium_main");

	ASSERT_EQ(sidechain.consensus_hash(), H("042de7470f55dbbec2a708f02b2b7d31e3c0fa90758a3be2dea3a445aad76a4a"));

	BlockTemplate tpl(&sidechain, nullptr);
	tpl.rng().seed(123);

	BlockTemplate tpl2(&sidechain, nullptr);
	tpl2.rng().seed(456);

	BlockTemplate tpl3(&sidechain, nullptr);
	tpl3.rng().seed(789);

	MinerData data;
	data.major_version = 10;
	data.height = 357365;
	data.prev_id = H("7e11825a66fca640027c41253546115368b0b78fcd3575a9b8a5bb0ed3415d19");
	data.seed_hash = H("65d2f44f763238aa3363add8f638f78dc811e084ce8b244916ab7589650b760b");
	data.difficulty = { 12964350330ULL, 0 };
	data.median_weight = 300000;
	data.already_generated_coins = 6887387843126525ULL;  // Current Salvium supply
	data.median_timestamp = (1ULL << 35) - (sidechain.chain_window_size() * 2 + 10) * sidechain.block_time() - 3600;

	Mempool mempool;
	Params params;

	params.m_miningWallet = Wallet("SC11n4s2UEj9Rc8XxppPbegwQethVmREpG9JP3aJUBGRCuD3wEvS4qtYtBjhqSx3S1hw3WDCfmbWKHJqa9g5Vqyo3jrsReJ5vp");

	std::mt19937_64 rng(101112);

	for (uint64_t i = 0, i2 = 0, i3 = 0; i < sidechain.chain_window_size() * 3; ++i) {
		tpl.update(data, mempool, &params);

		if ((rng() % 31) == 0) {
			tpl2.update(data, mempool, &params);

			if ((rng() % 11) == 0) {
				tpl3.update(data, mempool, &params);
				++i3;
				ASSERT_TRUE(tpl3.submit_sidechain_block(i3, 0, 0));
			}

			++i2;
			ASSERT_TRUE(tpl2.submit_sidechain_block(i2, 0, 0));
		}

		ASSERT_TRUE(tpl.submit_sidechain_block(i + 1, 0, 0));
		data.median_timestamp += sidechain.block_time();
	}

	ASSERT_EQ(sidechain.difficulty(), 219467);
	ASSERT_EQ(sidechain.blocksById().size(), 4491);
	ASSERT_TRUE(sidechain.precalcFinished());

	const PoolBlock* tip = sidechain.chainTip();

	ASSERT_TRUE(tip != nullptr);
	ASSERT_TRUE(tip->m_verified);
	ASSERT_FALSE(tip->m_invalid);

	ASSERT_EQ(tip->m_txinGenHeight, data.height);
	ASSERT_EQ(tip->m_sidechainHeight, sidechain.chain_window_size() * 3 - 1);

	ASSERT_EQ(tip->m_sidechainId, H("0746fd703dbe456d86cb118fd5d9aed56f3d5615e94e05b53b91f9bb1e3d4490"));
	}
	destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif
}

}
