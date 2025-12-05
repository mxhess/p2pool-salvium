

#pragma once

#include "common.h"

namespace p2pool {
namespace carrot {

// Generate random 16-byte janus anchor
void generate_janus_anchor(uint8_t (&anchor)[16]);

// Create coinbase input context: "C" || block_index (as 256-bit little-endian)
void make_input_context_coinbase(uint64_t block_index, uint8_t (&input_context)[33]);

// Generate ephemeral private key: d_e = H_n(anchor, input_context, K^j_s, pid)
void make_ephemeral_privkey(
    const uint8_t (&anchor)[16],
    const uint8_t (&input_context)[33],
    const hash& address_spend_pubkey,
    const uint8_t (&payment_id)[8],
    hash& ephemeral_privkey_out);

// Generate ephemeral public key: D_e = d_e * G (main address)
void make_ephemeral_pubkey_mainaddress(
    const hash& ephemeral_privkey,
    hash& ephemeral_pubkey_out);

// Generate uncontextualized shared secret (sender side): s_sr = d_e * ConvertPointE(K^j_v)
bool make_shared_secret_sender(
    const hash& ephemeral_privkey,
    const hash& address_view_pubkey,
    hash& shared_secret_out);

// Generate contextualized sender-receiver secret: s^ctx_sr = H_32(s_sr, D_e, input_context)
void make_sender_receiver_secret(
    const hash& shared_secret_unctx,
    const hash& ephemeral_pubkey,
    const uint8_t (&input_context)[33],
    hash& sender_receiver_out);

// Generate onetime address: K_o = K^j_s + (k^o_g * G + k^o_t * T)
// For coinbase with dummy commitment, T point is handled specially
void make_onetime_address_coinbase(
    const hash& address_spend_pubkey,
    const hash& sender_receiver_secret,
    uint64_t amount,
    hash& onetime_address_out);

// Generate 3-byte view tag: vt = H_3(s_sr, input_context, K_o)
void make_view_tag(
    const hash& shared_secret_unctx,
    const uint8_t (&input_context)[33],
    const hash& onetime_address,
    uint8_t (&view_tag)[3]);

// Encrypt janus anchor: anchor_enc = anchor XOR H_16(s^ctx_sr, K_o)
void encrypt_anchor(
    const uint8_t (&anchor)[16],
    const hash& sender_receiver_secret,
    const hash& onetime_address,
    uint8_t (&encrypted_anchor)[16]);

// Derive deterministic anchor for P2Pool validation
void derive_deterministic_anchor(
    const hash& tx_key_seed,
    uint32_t output_index,
    uint8_t (&anchor)[16]);

// Derive deterministic anchor from wallet spend public key (position-independent)
void derive_deterministic_anchor_from_pubkey(
    const hash& tx_key_seed,
    const hash& spend_public_key,
    uint8_t (&anchor)[16]);

void derive_transaction_ephemeral_privkey(
    const hash& tx_key_seed,
    const uint8_t (&input_context)[33],
    hash& ephemeral_privkey_out);

} // namespace carrot
} // namespace p2pool

