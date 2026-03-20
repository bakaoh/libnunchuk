#include <wally.hpp>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_crypto.h>
#include <wally_elements.h>
#include <wally_script.h>
#include <wally_transaction.h>
#include <wally_transaction_members.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

template <typename T>
T&& check_wally_ret(T&& ret, const char* file, int line, const char* func) {
  if (ret != WALLY_OK) {
    throw std::runtime_error(std::string("Error in ") + func + " at line " +
                             std::to_string(line) + ": " + std::to_string(ret));
  }
  return std::forward<T>(ret);
}
#define CHECK_WALLY(ret) check_wally_ret(ret, __FILE__, __LINE__, __func__)

namespace nunchuk::wally {

const char* ADDRESS_FAMILY = "tex";
const char* CONFIDENTIAL_ADDRESS_FAMILY = "tlq";

struct LiquidUtxos {
  std::vector<unsigned char> prevTxid;             // 32 bytes (internal order)
  std::vector<unsigned char> asset_generators_in;  // 33*num
  std::vector<unsigned char> asset_ids_in;         // 32*num
  std::vector<uint64_t> values_in;                 // satoshis
  std::vector<unsigned char> abfs_in;              // 32*num
  std::vector<unsigned char> vbfs_in;              // 32*num
  std::vector<std::vector<unsigned char>> script_pubkeys_in;
  std::vector<std::vector<unsigned char>>
      value_commitments_in;  // 33 bytes each
  std::vector<uint32_t> vouts_in;
};

class WallySigner {
 private:
  struct ext_key* master_{nullptr};
  std::vector<unsigned char> master_blinding_key_;

 public:
  WallySigner(const std::string& mnemonic, const std::string& passphrase) {
    std::vector<unsigned char> seed(BIP39_SEED_LEN_512);
    CHECK_WALLY(bip39_mnemonic_to_seed512(mnemonic.c_str(), passphrase.c_str(),
                                          seed.data(), seed.size()));
    CHECK_WALLY(bip32_key_from_seed_alloc(seed.data(), seed.size(),
                                          BIP32_VER_TEST_PRIVATE, 0, &master_));
    master_blinding_key_.reserve(HMAC_SHA512_LEN);
    CHECK_WALLY(wally_asset_blinding_key_from_seed(
        seed.data(), seed.size(), master_blinding_key_.data(),
        master_blinding_key_.size()));
  }

  ~WallySigner() { bip32_key_free(master_); }

  std::string GetAddress() {
    struct ext_key* derived = nullptr;
    CHECK_WALLY(bip32_key_from_parent_alloc(master_, 8, BIP32_FLAG_KEY_PRIVATE,
                                            &derived));
    char* address = nullptr;
    CHECK_WALLY(
        wally_bip32_key_to_addr_segwit(derived, ADDRESS_FAMILY, 0, &address));
    return std::string(address);
    // free address
    // free derived
  }

  std::vector<unsigned char> GetScriptPubkey() {
    std::string address = GetAddress();
    std::vector<unsigned char> script_pubkey(128);
    size_t spk_len = 0;
    CHECK_WALLY(wally_addr_segwit_to_bytes(address.c_str(), ADDRESS_FAMILY, 0,
                                           script_pubkey.data(),
                                           script_pubkey.size(), &spk_len));
    script_pubkey.resize(spk_len);
    return script_pubkey;
  }

  std::vector<unsigned char> GetPrivateBlindingKey() {
    std::vector<unsigned char> script_pubkey = GetScriptPubkey();
    std::vector<unsigned char> private_blinding_key(EC_PRIVATE_KEY_LEN);
    CHECK_WALLY(wally_asset_blinding_key_to_ec_private_key(
        master_blinding_key_.data(), master_blinding_key_.size(),
        script_pubkey.data(), script_pubkey.size(), private_blinding_key.data(),
        private_blinding_key.size()));
    return private_blinding_key;
  }

  std::string GetConfidentialAddress() {
    std::string address = GetAddress();
    std::vector<unsigned char> private_blinding_key = GetPrivateBlindingKey();
    std::vector<unsigned char> public_blinding_key(EC_PUBLIC_KEY_LEN);
    CHECK_WALLY(wally_ec_public_key_from_private_key(
        private_blinding_key.data(), private_blinding_key.size(),
        public_blinding_key.data(), public_blinding_key.size()));
    char* conf_address = nullptr;
    CHECK_WALLY(wally_confidential_addr_from_addr_segwit(
        address.c_str(), ADDRESS_FAMILY, CONFIDENTIAL_ADDRESS_FAMILY,
        public_blinding_key.data(), public_blinding_key.size(), &conf_address));
    return std::string(conf_address);
    // free conf_address
  }

  std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
  GetSigningKey() {
    struct ext_key* derived = nullptr;
    CHECK_WALLY(bip32_key_from_parent_alloc(master_, 8, BIP32_FLAG_KEY_PRIVATE,
                                            &derived));

    std::vector<unsigned char> signing_priv_key(EC_PRIVATE_KEY_LEN);
    std::memcpy(signing_priv_key.data(), derived->priv_key + 1,
                EC_PRIVATE_KEY_LEN);
    std::vector<unsigned char> signing_pub_key(EC_PUBLIC_KEY_LEN);
    CHECK_WALLY(wally_ec_public_key_from_private_key(
        signing_priv_key.data(), signing_priv_key.size(),
        signing_pub_key.data(), signing_pub_key.size()));
    return {signing_priv_key, signing_pub_key};
  }

  LiquidUtxos GetUtxosFromTx(const std::string& txHex) {
    LiquidUtxos out;
    struct wally_tx* tx{nullptr};
    auto ourScriptPubKey = GetScriptPubkey();

    const uint32_t txflags =
        WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS;
    CHECK_WALLY(wally_tx_from_hex(txHex.c_str(), txflags, &tx));

    out.prevTxid.resize(32);
    CHECK_WALLY(
        wally_tx_get_txid(tx, out.prevTxid.data(), out.prevTxid.size()));

    size_t num_outputs = 0;
    CHECK_WALLY(wally_tx_get_num_outputs(tx, &num_outputs));

    for (size_t vout = 0; vout < num_outputs; vout++) {
      // libwally exposes `struct wally_tx`/`struct wally_tx_output`, so just
      // read members.
      const auto& txout = tx->outputs[vout];
      if (!txout.script || txout.script_len != ourScriptPubKey.size()) continue;
      std::vector<unsigned char> script(txout.script,
                                        txout.script + txout.script_len);
      if (script != ourScriptPubKey) continue;
      auto privateBlindingKey = GetPrivateBlindingKey();

      std::vector<unsigned char> nonce(txout.nonce,
                                       txout.nonce + txout.nonce_len);
      std::vector<unsigned char> rangeproof(
          txout.rangeproof, txout.rangeproof + txout.rangeproof_len);
      std::vector<unsigned char> asset_commitment(
          txout.asset, txout.asset + txout.asset_len);
      std::vector<unsigned char> value_commitment_from_tx(
          txout.value, txout.value + txout.value_len);

      // Unblind using the output nonce (ephemeral pubkey), rangeproof,
      // value+asset commitments
      std::vector<unsigned char> asset_out(ASSET_TAG_LEN);
      std::vector<unsigned char> abf_out(BLINDING_FACTOR_LEN);
      std::vector<unsigned char> vbf_out(BLINDING_FACTOR_LEN);
      uint64_t value_out = 0;

      CHECK_WALLY(wally_asset_unblind(
          nonce.data(), nonce.size(), privateBlindingKey.data(),
          privateBlindingKey.size(), rangeproof.data(), rangeproof.size(),
          value_commitment_from_tx.data(), value_commitment_from_tx.size(),
          ourScriptPubKey.data(), ourScriptPubKey.size(),
          asset_commitment.data(), asset_commitment.size(), asset_out.data(),
          asset_out.size(), abf_out.data(), abf_out.size(), vbf_out.data(),
          vbf_out.size(), &value_out));

      // Auto-detect asset-id byte order expected by generator_from_bytes by
      // matching generator to the txout asset commitment
      std::vector<unsigned char> asset_id_a(asset_out.begin(), asset_out.end());
      std::vector<unsigned char> asset_id_b(asset_out.rbegin(),
                                            asset_out.rend());

      std::vector<unsigned char> gen_a(ASSET_GENERATOR_LEN);
      std::vector<unsigned char> gen_b(ASSET_GENERATOR_LEN);
      CHECK_WALLY(wally_asset_generator_from_bytes(
          asset_id_a.data(), asset_id_a.size(), abf_out.data(), abf_out.size(),
          gen_a.data(), gen_a.size()));
      CHECK_WALLY(wally_asset_generator_from_bytes(
          asset_id_b.data(), asset_id_b.size(), abf_out.data(), abf_out.size(),
          gen_b.data(), gen_b.size()));

      const bool a_matches = (asset_commitment.size() == gen_a.size() &&
                              std::memcmp(asset_commitment.data(), gen_a.data(),
                                          gen_a.size()) == 0);
      const bool b_matches = (asset_commitment.size() == gen_b.size() &&
                              std::memcmp(asset_commitment.data(), gen_b.data(),
                                          gen_b.size()) == 0);
      if (!a_matches && !b_matches) {
        wally_tx_free(tx);
        throw std::runtime_error(
            "asset_generator mismatch with asset_commitment (asset_id byte "
            "order unknown)");
      }
      const auto& asset_id = a_matches ? asset_id_a : asset_id_b;
      const auto& asset_generator = a_matches ? gen_a : gen_b;

      // Recompute and sanity-check value commitment
      std::vector<unsigned char> recomputed_value_commitment(
          ASSET_COMMITMENT_LEN);
      CHECK_WALLY(wally_asset_value_commitment(
          value_out, vbf_out.data(), vbf_out.size(), asset_generator.data(),
          asset_generator.size(), recomputed_value_commitment.data(),
          recomputed_value_commitment.size()));
      if (value_commitment_from_tx.size() !=
              recomputed_value_commitment.size() ||
          std::memcmp(value_commitment_from_tx.data(),
                      recomputed_value_commitment.data(),
                      recomputed_value_commitment.size()) != 0) {
        wally_tx_free(tx);
        throw std::runtime_error(
            "value_commitment mismatch: unblind factors don't recompute "
            "original commitment");
      }

      out.asset_generators_in.insert(out.asset_generators_in.end(),
                                     asset_generator.begin(),
                                     asset_generator.end());
      out.asset_ids_in.insert(out.asset_ids_in.end(), asset_id.begin(),
                              asset_id.end());
      out.values_in.push_back(value_out);
      out.abfs_in.insert(out.abfs_in.end(), abf_out.begin(), abf_out.end());
      out.vbfs_in.insert(out.vbfs_in.end(), vbf_out.begin(), vbf_out.end());
      out.script_pubkeys_in.push_back(ourScriptPubKey);
      out.value_commitments_in.push_back(value_commitment_from_tx);
      out.vouts_in.push_back(static_cast<uint32_t>(vout));
    }

    wally_tx_free(tx);
    return out;
  }
};
}  // namespace nunchuk::wally