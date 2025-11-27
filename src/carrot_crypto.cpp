#include "common.h"
#include "carrot_crypto.h"
#include "crypto.h"

extern "C" {
#include "crypto-ops.h"
#include "mx25519.h"
#include "blake2/blake2.h"
}

#include <cstring>
#include <mutex>
#include "log.h"

namespace p2pool {
namespace carrot {

// Domain separators (must match Salvium's carrot_core/config.h)
static constexpr const char DOMAIN_SEP_EPHEMERAL_PRIVKEY[] = "Carrot sending key normal";
static constexpr const char DOMAIN_SEP_SENDER_RECEIVER_SECRET[] = "Carrot sender-receiver secret";
static constexpr const char DOMAIN_SEP_VIEW_TAG[] = "Carrot view tag";
static constexpr const char DOMAIN_SEP_ENCRYPTION_MASK_ANCHOR[] = "Carrot encryption mask anchor";
static constexpr const char DOMAIN_SEP_ONETIME_EXTENSION_G[] = "Carrot key extension G";
static constexpr const char DOMAIN_SEP_ONETIME_EXTENSION_T[] = "Carrot key extension T";

// T generator for Carrot (from Salvium generators.cpp)
static const uint8_t generator_T[32] = {
    0x96, 0x6f, 0xc6, 0x6b, 0x82, 0xcd, 0x56, 0xcf,
    0x85, 0xea, 0xec, 0x80, 0x1c, 0x42, 0x84, 0x5f,
    0x5f, 0x40, 0x88, 0x78, 0xd1, 0x56, 0x1e, 0x00,
    0xd3, 0xd7, 0xde, 0xd2, 0x79, 0x4d, 0x09, 0x4f
};

// H generator for Pedersen commitments (from RingCT)
static const uint8_t generator_H[32] = {
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
    0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
    0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94
};

// Curve order L for Ed25519
static const uint8_t curve_order[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static const uint8_t identity_point[32] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Get mx25519 implementation (cached)
static const mx25519_impl* get_mx25519_impl()
{
    static std::once_flag of;
    static const mx25519_impl *impl;
    std::call_once(of, [&](){ impl = mx25519_select_impl(MX25519_TYPE_AUTO); });
    return impl;
}

// Build transcript: [1-byte length][domain_sep][args...]
// Returns total size written to buffer
template<size_t N>
static size_t build_transcript(uint8_t* buf, const char (&domain_sep)[N])
{
    // N includes null terminator, actual length is N-1
    constexpr size_t len = N - 1;
    static_assert(len <= 255, "Domain separator too long");
    buf[0] = static_cast<uint8_t>(len);
    memcpy(buf + 1, domain_sep, len);
    return 1 + len;
}

// Debug helper to print hex
static void debug_hex(const char* label, const uint8_t* data, size_t len)
{
    static constexpr char log_category_prefix[] = "CarrotCrypto ";
    char hex[130] = {0};
    for (size_t i = 0; i < len && i < 64; ++i) {
        sprintf(hex + i*2, "%02x", data[i]);
    }
    LOGINFO(0, label << ": " << static_cast<const char*>(hex));
}

// BLAKE2b keyed hash wrapper
// key can be nullptr for unkeyed hash
static void blake2b_hash(void* out, size_t outlen, 
                         const void* data, size_t datalen,
                         const void* key, size_t keylen)
{
    blake2b(out, outlen, data, datalen, key, keylen);
}

static void derive_scalar(const void* transcript, size_t transcript_len,
                          const void* key, // 32 bytes or nullptr
                          uint8_t* scalar_out)
{
    uint8_t temp[64];
    blake2b_hash(temp, 64, transcript, transcript_len, 
                 key, key ? 32 : 0);
    sc_reduce(temp);  // Reduce 64 bytes mod l
    memcpy(scalar_out, temp, 32);
}

// derive_bytes_32: H_32 (32-byte output, no reduction)
static void derive_bytes_32(const void* transcript, size_t transcript_len,
                            const void* key, // 32 bytes
                            uint8_t* out)
{
    blake2b_hash(out, 32, transcript, transcript_len, key, 32);
}

// derive_bytes_3: H_3 (3-byte output)
static void derive_bytes_3(const void* transcript, size_t transcript_len,
                           const void* key, // 32 bytes
                           uint8_t* out)
{
    blake2b_hash(out, 3, transcript, transcript_len, key, 32);
}

// derive_bytes_16: H_16 (16-byte output)
static void derive_bytes_16(const void* transcript, size_t transcript_len,
                            const void* key, // 32 bytes
                            uint8_t* out)
{
    blake2b_hash(out, 16, transcript, transcript_len, key, 32);
}

void generate_janus_anchor(uint8_t (&anchor)[16])
{
    hash tmp;
    generate_keys(tmp, tmp);  // Use existing random generation
    memcpy(anchor, tmp.h, 16);
}

void make_input_context_coinbase(uint64_t block_index, uint8_t (&input_context)[33])
{
    // input_context = 'C' || block_index as little-endian 256-bit (32 bytes)
    input_context[0] = 'C';
    memset(input_context + 1, 0, 32);
    // Little-endian 64-bit at start of the 32-byte field
    memcpy(input_context + 1, &block_index, sizeof(block_index));
    
    debug_hex("input_context", input_context, 33);
}

void make_ephemeral_privkey(
    const uint8_t (&anchor)[16],
    const uint8_t (&input_context)[33],
    const hash& address_spend_pubkey,
    const uint8_t (&payment_id)[8],
    hash& ephemeral_privkey_out)
{
    // d_e = H_n("Carrot sending key normal" || anchor || input_context || K^j_s || pid)
    // Transcript: [len][domain_sep][anchor:16][input_context:33][K_s:32][pid:8]
    constexpr size_t domain_len = sizeof(DOMAIN_SEP_EPHEMERAL_PRIVKEY) - 1; // 25
    constexpr size_t transcript_size = 1 + domain_len + 16 + 33 + 32 + 8;   // 115
    
    uint8_t transcript[transcript_size];
    size_t offset = build_transcript(transcript, DOMAIN_SEP_EPHEMERAL_PRIVKEY);
    memcpy(transcript + offset, anchor, 16);
    offset += 16;
    memcpy(transcript + offset, input_context, 33);
    offset += 33;
    memcpy(transcript + offset, address_spend_pubkey.h, 32);
    offset += 32;
    memcpy(transcript + offset, payment_id, 8);
    
    // Unkeyed hash (key = nullptr)
    derive_scalar(transcript, transcript_size, nullptr, ephemeral_privkey_out.h);
    
    debug_hex("eph_priv anchor", anchor, 16);
    debug_hex("eph_priv K_s", address_spend_pubkey.h, 32);
    debug_hex("eph_priv d_e", ephemeral_privkey_out.h, 32);
}

void make_ephemeral_pubkey_mainaddress(
    const hash& ephemeral_privkey,
    hash& ephemeral_pubkey_out)
{
    // D_e = d_e * B (X25519 scalar mult with base point)
    mx25519_scmul_base(get_mx25519_impl(),
        reinterpret_cast<mx25519_pubkey*>(ephemeral_pubkey_out.h),
        reinterpret_cast<const mx25519_privkey*>(ephemeral_privkey.h));
    
    debug_hex("eph_pub D_e", ephemeral_pubkey_out.h, 32);
}

bool make_shared_secret_sender(
    const hash& ephemeral_privkey,
    const hash& address_view_pubkey,
    hash& shared_secret_out)
{
    // First verify the view pubkey is valid and convert to X25519
    ge_p3 view_point;
    if (ge_frombytes_vartime(&view_point, address_view_pubkey.h) != 0) {
        return false;
    }
    
    // Check if point is in prime order subgroup: l*P == identity
    ge_p2 check_point;
    ge_scalarmult(&check_point, curve_order, &view_point);
    uint8_t check_bytes[32];
    ge_tobytes(check_bytes, &check_point);
    if (memcmp(check_bytes, identity_point, 32) != 0) {
        return false;  // Point not in prime order subgroup
    }

    // D^j_v = ConvertPointE(K^j_v) - convert Ed25519 pubkey to X25519
    mx25519_pubkey address_view_pubkey_x25519;
    ge_p3_to_x25519(address_view_pubkey_x25519.data, &view_point);
    
    // s_sr = d_e * D^j_v (native X25519 scalar multiplication)
    mx25519_scmul_key(get_mx25519_impl(),
        reinterpret_cast<mx25519_pubkey*>(shared_secret_out.h),
        reinterpret_cast<const mx25519_privkey*>(ephemeral_privkey.h),
        &address_view_pubkey_x25519);
    
    debug_hex("shared K_v_ed25519", address_view_pubkey.h, 32);
    debug_hex("shared K_v_x25519", address_view_pubkey_x25519.data, 32);
    debug_hex("shared s_sr_unctx", shared_secret_out.h, 32);
    return true;
}

void make_sender_receiver_secret(
    const hash& shared_secret_unctx,
    const hash& ephemeral_pubkey,
    const uint8_t (&input_context)[33],
    hash& sender_receiver_out)
{
    // s^ctx_sr = H_32[s_sr]("Carrot sender-receiver secret" || D_e || input_context)
    // Transcript: [len][domain_sep][D_e:32][input_context:33]
    constexpr size_t domain_len = sizeof(DOMAIN_SEP_SENDER_RECEIVER_SECRET) - 1; // 29
    constexpr size_t transcript_size = 1 + domain_len + 32 + 33;                  // 95
    
    uint8_t transcript[transcript_size];
    size_t offset = build_transcript(transcript, DOMAIN_SEP_SENDER_RECEIVER_SECRET);
    memcpy(transcript + offset, ephemeral_pubkey.h, 32);
    offset += 32;
    memcpy(transcript + offset, input_context, 33);
    
    // Keyed with shared_secret_unctx
    derive_bytes_32(transcript, transcript_size, shared_secret_unctx.h, sender_receiver_out.h);
    
    debug_hex("s_sr_ctx result", sender_receiver_out.h, 32);
}

void make_onetime_address_coinbase(
    const hash& address_spend_pubkey,
    const hash& sender_receiver_secret,
    uint64_t amount,
    hash& onetime_address_out)
{
    // For coinbase: K_o = K^j_s + k^o_g * G + k^o_t * T
    // k^o_g = H_n[s^ctx_sr]("Carrot key extension G" || C_a)
    // k^o_t = H_n[s^ctx_sr]("Carrot key extension T" || C_a)
    // C_a = 1*G + amount*H (coinbase uses k_a = 1)

    // 1. Compute C_a = 1*G + amount*H
    // First: 1*G
    ge_p3 one_G;
    {
        uint8_t one_scalar[32] = {0};
        one_scalar[0] = 1;
        ge_scalarmult_base(&one_G, one_scalar);
    }
    
    // Second: amount*H
    ge_p3 H_point;
    if (ge_frombytes_vartime(&H_point, generator_H) != 0) {
        memcpy(onetime_address_out.h, address_spend_pubkey.h, 32);
        return;
    }
    
    ge_p2 amount_H_p2;
    uint8_t amount_le[32] = {0};
    memcpy(amount_le, &amount, sizeof(amount)); // little-endian
    ge_scalarmult(&amount_H_p2, amount_le, &H_point);
    
    // Convert amount_H to p3
    uint8_t amount_H_bytes[32];
    ge_tobytes(amount_H_bytes, &amount_H_p2);
    ge_p3 amount_H;
    ge_frombytes_vartime(&amount_H, amount_H_bytes);
    
    // C_a = 1*G + amount*H
    ge_cached one_G_cached;
    ge_p3_to_cached(&one_G_cached, &one_G);
    ge_p1p1 C_a_p1p1;
    ge_add(&C_a_p1p1, &amount_H, &one_G_cached);
    ge_p3 C_a_p3;
    ge_p1p1_to_p3(&C_a_p3, &C_a_p1p1);
    uint8_t C_a[32];
    ge_p3_tobytes(C_a, &C_a_p3);
    
    debug_hex("K_o C_a commitment", C_a, 32);

    // 2. k^o_g = H_n[s^ctx_sr]("Carrot key extension G" || C_a)
    constexpr size_t domain_len_g = sizeof(DOMAIN_SEP_ONETIME_EXTENSION_G) - 1;
    constexpr size_t transcript_size_g = 1 + domain_len_g + 32;
    uint8_t transcript_g[transcript_size_g];
    size_t offset_g = build_transcript(transcript_g, DOMAIN_SEP_ONETIME_EXTENSION_G);
    memcpy(transcript_g + offset_g, C_a, 32);
    
    uint8_t k_o_g[32];
    derive_scalar(transcript_g, transcript_size_g, sender_receiver_secret.h, k_o_g);
    debug_hex("K_o k^o_g scalar", k_o_g, 32);
    
    // 3. k^o_t = H_n[s^ctx_sr]("Carrot key extension T" || C_a)
    constexpr size_t domain_len_t = sizeof(DOMAIN_SEP_ONETIME_EXTENSION_T) - 1;
    constexpr size_t transcript_size_t = 1 + domain_len_t + 32;
    uint8_t transcript_t[transcript_size_t];
    size_t offset_t = build_transcript(transcript_t, DOMAIN_SEP_ONETIME_EXTENSION_T);
    memcpy(transcript_t + offset_t, C_a, 32);
    
    uint8_t k_o_t[32];
    derive_scalar(transcript_t, transcript_size_t, sender_receiver_secret.h, k_o_t);
    debug_hex("K_o k^o_t scalar", k_o_t, 32);

    // 4. K^o_ext = k^o_g * G + k^o_t * T
    // First: k^o_g * G
    ge_p3 k_o_g_G;
    ge_scalarmult_base(&k_o_g_G, k_o_g);
    
    // Second: k^o_t * T
    ge_p3 T_point;
    if (ge_frombytes_vartime(&T_point, generator_T) != 0) {
        memcpy(onetime_address_out.h, address_spend_pubkey.h, 32);
        return;
    }
    ge_p2 k_o_t_T_p2;
    ge_scalarmult(&k_o_t_T_p2, k_o_t, &T_point);
    uint8_t k_o_t_T_bytes[32];
    ge_tobytes(k_o_t_T_bytes, &k_o_t_T_p2);
    ge_p3 k_o_t_T;
    ge_frombytes_vartime(&k_o_t_T, k_o_t_T_bytes);
    
    // K^o_ext = k^o_g*G + k^o_t*T
    ge_cached k_o_g_G_cached;
    ge_p3_to_cached(&k_o_g_G_cached, &k_o_g_G);
    ge_p1p1 ext_p1p1;
    ge_add(&ext_p1p1, &k_o_t_T, &k_o_g_G_cached);
    ge_p3 extension_point;
    ge_p1p1_to_p3(&extension_point, &ext_p1p1);

    // 5. K_o = K^j_s + K^o_ext
    ge_p3 spend_point;
    if (ge_frombytes_vartime(&spend_point, address_spend_pubkey.h) != 0) {
        memcpy(onetime_address_out.h, address_spend_pubkey.h, 32);
        return;
    }
    
    ge_cached extension_cached;
    ge_p3_to_cached(&extension_cached, &extension_point);
    
    ge_p1p1 result_p1p1;
    ge_add(&result_p1p1, &spend_point, &extension_cached);
    
    ge_p3 result;
    ge_p1p1_to_p3(&result, &result_p1p1);
    ge_p3_tobytes(onetime_address_out.h, &result);
    
    debug_hex("K_o result", onetime_address_out.h, 32);
}

void make_view_tag(
    const hash& shared_secret_unctx,
    const uint8_t (&input_context)[33],
    const hash& onetime_address,
    uint8_t (&view_tag)[3])
{
    // vt = H_3[s_sr]("Carrot view tag" || input_context || K_o)
    // Transcript: [len][domain_sep][input_context:33][K_o:32]
    constexpr size_t domain_len = sizeof(DOMAIN_SEP_VIEW_TAG) - 1; // 15
    constexpr size_t transcript_size = 1 + domain_len + 33 + 32;   // 81
    
    uint8_t transcript[transcript_size];
    size_t offset = build_transcript(transcript, DOMAIN_SEP_VIEW_TAG);
    memcpy(transcript + offset, input_context, 33);
    offset += 33;
    memcpy(transcript + offset, onetime_address.h, 32);
    
    // Keyed with shared_secret_unctx (NOT contextualized s_sr)
    derive_bytes_3(transcript, transcript_size, shared_secret_unctx.h, view_tag);
    
    debug_hex("view_tag result", view_tag, 3);
}

void encrypt_anchor(
    const uint8_t (&anchor)[16],
    const hash& sender_receiver_secret,
    const hash& onetime_address,
    uint8_t (&encrypted_anchor)[16])
{
    // anchor_enc = anchor XOR H_16[s^ctx_sr]("Carrot encryption mask anchor" || K_o)
    // Transcript: [len][domain_sep][K_o:32]
    constexpr size_t domain_len = sizeof(DOMAIN_SEP_ENCRYPTION_MASK_ANCHOR) - 1; // 29
    constexpr size_t transcript_size = 1 + domain_len + 32;                       // 62
    
    uint8_t transcript[transcript_size];
    size_t offset = build_transcript(transcript, DOMAIN_SEP_ENCRYPTION_MASK_ANCHOR);
    memcpy(transcript + offset, onetime_address.h, 32);
    
    // Keyed with sender_receiver_secret (contextualized)
    uint8_t mask[16];
    derive_bytes_16(transcript, transcript_size, sender_receiver_secret.h, mask);
    
    for (size_t i = 0; i < 16; ++i) {
        encrypted_anchor[i] = anchor[i] ^ mask[i];
    }
    
    debug_hex("anchor mask", mask, 16);
    debug_hex("anchor encrypted", encrypted_anchor, 16);
}

} // namespace carrot
} // namespace p2pool

