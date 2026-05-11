/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2026 Enigmo.
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * libnunchuk is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libnunchuk. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NUNCHUK_WALLY_SIGNER_HPP
#define NUNCHUK_WALLY_SIGNER_HPP

#include <liquid/wallyutils.hpp>

#include <util/bip32.h>
#include <util/strencodings.h>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <map>

namespace nunchuk::wally {

struct LiquidUtxos {
  std::vector<unsigned char> tx_id;                // 32 bytes (internal order)
  std::vector<unsigned char> asset_generators_in;  // 33*num
  std::vector<unsigned char> asset_ids_in;         // 32*num
  std::vector<uint64_t> values_in;                 // satoshis
  std::vector<unsigned char> abfs_in;              // 32*num
  std::vector<unsigned char> vbfs_in;              // 32*num
  std::vector<std::vector<unsigned char>> script_pubkeys_in;
  std::vector<std::vector<unsigned char>>
      value_commitments_in;  // 33 bytes each
  std::vector<uint32_t> vouts_in;
  std::vector<std::vector<unsigned char>> vins_tx_id;
  std::vector<uint32_t> vins_vout;
};

struct AddressDetail {
  uint32_t index;
  std::string address;
  bool isChange;
};

class WallySigner {
 private:
  struct ext_key* master_{nullptr};
  std::vector<unsigned char> master_blinding_key_;
  std::map<std::vector<unsigned char>, AddressDetail> spk_;
  uint32_t tx_flags_ = WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS;

  using PrevoutSpendData =
      std::pair<std::vector<unsigned char>, std::vector<unsigned char>>;

  static std::string MakePrevoutMapKey(const unsigned char* txid,
                                       uint32_t vout) {
    std::string k(reinterpret_cast<const char*>(txid), WALLY_TXHASH_LEN);
    k.push_back(static_cast<char>(vout & 0xff));
    k.push_back(static_cast<char>((vout >> 8) & 0xff));
    k.push_back(static_cast<char>((vout >> 16) & 0xff));
    k.push_back(static_cast<char>((vout >> 24) & 0xff));
    return k;
  }

  static std::map<std::string, PrevoutSpendData> BuildPrevoutSpendDataMap(
      const std::vector<LiquidUtxos>& inputs) {
    std::map<std::string, PrevoutSpendData> m;
    for (const auto& u : inputs) {
      if (u.tx_id.size() != WALLY_TXHASH_LEN) {
        throw std::runtime_error(
            "LiquidUtxos.tx_id must be WALLY_TXHASH_LEN (32) bytes");
      }
      const size_t n = u.vouts_in.size();
      if (u.script_pubkeys_in.size() != n ||
          u.value_commitments_in.size() != n) {
        throw std::runtime_error(
            "LiquidUtxos script_pubkeys_in/value_commitments_in must match "
            "vouts_in length");
      }
      for (size_t k = 0; k < n; ++k) {
        std::string key = MakePrevoutMapKey(u.tx_id.data(), u.vouts_in[k]);
        PrevoutSpendData val{u.script_pubkeys_in[k], u.value_commitments_in[k]};
        auto [it, inserted] = m.emplace(key, std::move(val));
        if (!inserted) {
          if (it->second.first != u.script_pubkeys_in[k] ||
              it->second.second != u.value_commitments_in[k]) {
            throw std::runtime_error(
                "Conflicting LiquidUtxos entries for the same prevout");
          }
        }
      }
    }
    return m;
  }

  void SignTxInPlace(
      struct wally_tx* tx,
      const std::vector<std::vector<unsigned char>>& script_pubkeys_in,
      const std::vector<std::vector<unsigned char>>& value_commitments_in) {
    if (tx == nullptr) throw std::runtime_error("SignTxInPlace: tx is null");

    size_t num_inputs = 0;
    CHECK_WALLY(wally_tx_get_num_inputs(tx, &num_inputs));

    if (script_pubkeys_in.size() != num_inputs ||
        value_commitments_in.size() != num_inputs) {
      throw std::runtime_error(
          "SignTxInPlace: script_pubkeys_in/value_commitments_in size mismatch "
          "with tx inputs");
    }

    for (size_t vin = 0; vin < num_inputs; vin++) {
      const auto& utxo_script = script_pubkeys_in[vin];
      if (!spk_.contains(utxo_script)) {
        throw std::runtime_error("Signing key not found");
      }
      uint32_t index = spk_[utxo_script].index;
      const auto& [signingPrivKey, signingPubKey] = GetSigningKey(index);
      std::vector<unsigned char> pubkeyhash(HASH160_LEN);
      CHECK_WALLY(wally_hash160(signingPubKey.data(), signingPubKey.size(),
                                pubkeyhash.data(), pubkeyhash.size()));

      std::vector<unsigned char> script_code(256);
      size_t script_code_len = 0;
      CHECK_WALLY(wally_scriptpubkey_p2pkh_from_bytes(
          pubkeyhash.data(), pubkeyhash.size(), 0, script_code.data(),
          script_code.size(), &script_code_len));
      script_code.resize(script_code_len);

      std::vector<unsigned char> sighash(SHA256_LEN);
      const auto& prevout_value = value_commitments_in[vin];  // 33 bytes
      CHECK_WALLY(wally_tx_get_elements_signature_hash(
          tx, vin, script_code.data(), script_code.size(), prevout_value.data(),
          prevout_value.size(), WALLY_SIGHASH_ALL, WALLY_TX_FLAG_USE_WITNESS,
          sighash.data(), sighash.size()));

      std::vector<unsigned char> sig64(EC_SIGNATURE_LEN);
      CHECK_WALLY(wally_ec_sig_from_bytes(
          signingPrivKey.data(), signingPrivKey.size(), sighash.data(),
          sighash.size(), EC_FLAG_ECDSA, sig64.data(), sig64.size()));

      CHECK_WALLY(wally_ec_sig_verify(
          signingPubKey.data(), signingPubKey.size(), sighash.data(),
          sighash.size(), EC_FLAG_ECDSA, sig64.data(), sig64.size()));

      size_t sig_der_len = 0;
      std::vector<unsigned char> sig_der(EC_SIGNATURE_DER_MAX_LEN);
      CHECK_WALLY(wally_ec_sig_to_der(sig64.data(), sig64.size(),
                                      sig_der.data(), sig_der.size(),
                                      &sig_der_len));
      sig_der.resize(sig_der_len);
      sig_der.push_back(static_cast<unsigned char>(WALLY_SIGHASH_ALL));

      struct wally_tx_witness_stack* wit = nullptr;
      CHECK_WALLY(wally_tx_witness_stack_init_alloc(2, &wit));
      CHECK_WALLY(
          wally_tx_witness_stack_add(wit, sig_der.data(), sig_der.size()));
      CHECK_WALLY(wally_tx_witness_stack_add(wit, signingPubKey.data(),
                                             signingPubKey.size()));
      CHECK_WALLY(wally_tx_set_input_witness(tx, vin, wit));
      wally_tx_witness_stack_free(wit);
    }
  }

 public:
  WallySigner(const std::string& mnemonic, const std::string& passphrase) {
    std::vector<unsigned char> seed(BIP39_SEED_LEN_512);
    CHECK_WALLY(bip39_mnemonic_to_seed512(mnemonic.c_str(), passphrase.c_str(),
                                          seed.data(), seed.size()));
    CHECK_WALLY(bip32_key_from_seed_alloc(seed.data(), seed.size(),
                                          BIP32_VER_TEST_PRIVATE, 0, &master_));
    master_blinding_key_.resize(HMAC_SHA512_LEN);
    CHECK_WALLY(wally_asset_blinding_key_from_seed(
        seed.data(), seed.size(), master_blinding_key_.data(),
        master_blinding_key_.size()));
  }

  WallySigner(const WallySigner&) = delete;
  WallySigner& operator=(const WallySigner&) = delete;

  WallySigner(WallySigner&& other) noexcept
      : master_(other.master_),
        master_blinding_key_(std::move(other.master_blinding_key_)),
        spk_(std::move(other.spk_)),
        tx_flags_(other.tx_flags_) {
    other.master_ = nullptr;
  }

  WallySigner& operator=(WallySigner&& other) noexcept {
    if (this == &other) return *this;
    bip32_key_free(master_);
    master_ = other.master_;
    other.master_ = nullptr;
    master_blinding_key_ = std::move(other.master_blinding_key_);
    spk_ = std::move(other.spk_);
    tx_flags_ = other.tx_flags_;
    return *this;
  }

  ~WallySigner() { bip32_key_free(master_); }

  std::string GetMasterFingerprint() const {
    std::vector<unsigned char> fingerprint(BIP32_KEY_FINGERPRINT_LEN);
    CHECK_WALLY(bip32_key_get_fingerprint(master_, fingerprint.data(),
                                          fingerprint.size()));
    return WallyUtils::HexFromBytes(fingerprint.data(), fingerprint.size());
  }

  std::vector<AddressDetail> CacheAddresses(const std::string& path,
                                            uint32_t start_index,
                                            uint32_t end_index,
                                            bool is_change) {
    std::vector<uint32_t> keypath;
    std::string formalized = path;
    std::replace(formalized.begin(), formalized.end(), 'h', '\'');
    if (!ParseHDKeypath(formalized, keypath)) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid hd keypath");
    }
    // keypath.push_back(is_change ? 1 : 0);
    keypath.push_back(start_index);
    std::vector<AddressDetail> rs{};
    for (uint32_t index = start_index; index < end_index; index++) {
      keypath.back() = index;
      std::string address = GetAddress(keypath);
      std::vector<unsigned char> script_pubkey =
          WallyUtils::GetScriptPubkeyFromAddress(address);
      AddressDetail detail{index, address, is_change};
      rs.push_back(detail);
      spk_.emplace(script_pubkey, detail);
    }
    return rs;
  }

  std::string GetAddress(const std::vector<uint32_t>& keypath) {
    struct ext_key* derived = nullptr;
    CHECK_WALLY(bip32_key_from_parent_path_alloc(
        master_, keypath.data(), keypath.size(), BIP32_FLAG_KEY_PRIVATE,
        &derived));
    char* address = nullptr;
    CHECK_WALLY(wally_bip32_key_to_addr_segwit(
        derived, WallyUtils::C().ADDRESS_FAMILY, 0, &address));
    std::string rs = std::string(address);
    wally_free_string(address);
    bip32_key_free(derived);
    return rs;
  }

  std::string GetConfidentialAddress(const std::vector<uint32_t>& path) {
    std::string address = GetAddress(path);
    std::vector<unsigned char> script_pubkey =
        WallyUtils::GetScriptPubkeyFromAddress(address);
    std::vector<unsigned char> private_blinding_key =
        GetBlindingKey(script_pubkey);

    std::vector<unsigned char> public_blinding_key(EC_PUBLIC_KEY_LEN);
    CHECK_WALLY(wally_ec_public_key_from_private_key(
        private_blinding_key.data(), private_blinding_key.size(),
        public_blinding_key.data(), public_blinding_key.size()));

    char* conf_address = nullptr;
    CHECK_WALLY(wally_confidential_addr_from_addr_segwit(
        address.c_str(), WallyUtils::C().ADDRESS_FAMILY,
        WallyUtils::C().CONFIDENTIAL_ADDRESS_FAMILY, public_blinding_key.data(),
        public_blinding_key.size(), &conf_address));
    std::string rs = std::string(conf_address);
    wally_free_string(conf_address);
    return rs;
  }

  std::vector<unsigned char> GetBlindingKey(
      const std::vector<unsigned char>& spk) {
    std::vector<unsigned char> private_blinding_key(EC_PRIVATE_KEY_LEN);
    CHECK_WALLY(wally_asset_blinding_key_to_ec_private_key(
        master_blinding_key_.data(), master_blinding_key_.size(), spk.data(),
        spk.size(), private_blinding_key.data(), private_blinding_key.size()));
    return private_blinding_key;
  }

  std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
  GetSigningKey(uint32_t index) {
    struct ext_key* derived = nullptr;
    CHECK_WALLY(bip32_key_from_parent_alloc(master_, index,
                                            BIP32_FLAG_KEY_PRIVATE, &derived));

    std::vector<unsigned char> signing_priv_key(EC_PRIVATE_KEY_LEN);
    std::memcpy(signing_priv_key.data(), derived->priv_key + 1,
                EC_PRIVATE_KEY_LEN);
    std::vector<unsigned char> signing_pub_key(EC_PUBLIC_KEY_LEN);
    CHECK_WALLY(wally_ec_public_key_from_private_key(
        signing_priv_key.data(), signing_priv_key.size(),
        signing_pub_key.data(), signing_pub_key.size()));
    return {signing_priv_key, signing_pub_key};
  }

  Transaction GetTransactionFromTx(const std::string& txHex, int height) {
    struct wally_tx* tx{nullptr};
    CHECK_WALLY(wally_tx_from_hex(txHex.c_str(), tx_flags_, &tx));
    std::vector<unsigned char> txid(32);
    CHECK_WALLY(wally_tx_get_txid(tx, txid.data(), txid.size()));
    std::reverse(txid.begin(), txid.end());

    Transaction rs;
    rs.set_txid(WallyUtils::HexFromBytes(txid.data(), txid.size()));
    rs.set_height(height);
    rs.set_lock_time(tx->locktime);
    rs.set_raw(txHex);
    bool all_signed = true;
    for (size_t vin = 0; vin < tx->num_inputs; vin++) {
      const auto& txin = tx->inputs[vin];
      std::vector<unsigned char> vin_txid(txin.txhash,
                                          txin.txhash + WALLY_TXHASH_LEN);
      std::reverse(vin_txid.begin(), vin_txid.end());
      std::string vin_txid_str =
          WallyUtils::HexFromBytes(vin_txid.data(), vin_txid.size());
      rs.add_input({vin_txid_str, txin.index, txin.sequence});
      size_t items = 0;
      CHECK_WALLY(wally_tx_get_input_witness_num_items(tx, vin, &items));
      if (items == 0) all_signed = false;
    }
    for (size_t vout = 0; vout < tx->num_outputs; vout++) {
      const auto& txout = tx->outputs[vout];
      std::vector<unsigned char> script(txout.script,
                                        txout.script + txout.script_len);
      if (!spk_.contains(script)) continue;
      auto privateBlindingKey = GetBlindingKey(script);

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
          script.data(), script.size(), asset_commitment.data(),
          asset_commitment.size(), asset_out.data(), asset_out.size(),
          abf_out.data(), abf_out.size(), vbf_out.data(), vbf_out.size(),
          &value_out));

      std::vector<unsigned char> asset_id(asset_out.begin(), asset_out.end());
      std::vector<unsigned char> asset_generator(ASSET_GENERATOR_LEN);
      CHECK_WALLY(wally_asset_generator_from_bytes(
          asset_id.data(), asset_id.size(), abf_out.data(), abf_out.size(),
          asset_generator.data(), asset_generator.size()));
      if (asset_commitment != asset_generator) {
        wally_tx_free(tx);
        throw std::runtime_error(
            "asset_generator mismatch with asset_commitment");
      }

      // Recompute and sanity-check value commitment
      std::vector<unsigned char> recomputed_value_commitment(
          ASSET_COMMITMENT_LEN);
      CHECK_WALLY(wally_asset_value_commitment(
          value_out, vbf_out.data(), vbf_out.size(), asset_generator.data(),
          asset_generator.size(), recomputed_value_commitment.data(),
          recomputed_value_commitment.size()));
      if (value_commitment_from_tx != recomputed_value_commitment) {
        wally_tx_free(tx);
        throw std::runtime_error(
            "value_commitment mismatch: unblind factors don't recompute "
            "original commitment");
      }

      AddressDetail address_detail = spk_[script];
      TxOutput output{address_detail.address, Amount(value_out)};
      output.isChange = address_detail.isChange;
      output.isReceive = true;
      output.assetId = AssetId(asset_id.begin(), asset_id.end());
      rs.add_output(output);
    }
    if (height == 0) {
      rs.set_status(TransactionStatus::PENDING_CONFIRMATION);
    } else if (height == -2) {
      rs.set_status(TransactionStatus::NETWORK_REJECTED);
    } else if (height == -1) {
      rs.set_status(all_signed ? TransactionStatus::READY_TO_BROADCAST
                               : TransactionStatus::PENDING_SIGNATURES);
    } else if (height > 0) {
      rs.set_status(TransactionStatus::CONFIRMED);
    }

    wally_tx_free(tx);
    return rs;
  }

  LiquidUtxos GetUtxosFromTx(const std::string& txHex,
                             const std::string& address = {}) {
    LiquidUtxos out;
    struct wally_tx* tx{nullptr};
    CHECK_WALLY(wally_tx_from_hex(txHex.c_str(), tx_flags_, &tx));

    out.tx_id.resize(32);
    CHECK_WALLY(wally_tx_get_txid(tx, out.tx_id.data(), out.tx_id.size()));

    size_t num_inputs = 0;
    CHECK_WALLY(wally_tx_get_num_inputs(tx, &num_inputs));
    out.vins_tx_id.resize(num_inputs);
    out.vins_vout.resize(num_inputs);
    for (size_t vin = 0; vin < num_inputs; vin++) {
      const auto& txin = tx->inputs[vin];
      out.vins_tx_id[vin] = std::vector<unsigned char>(
          txin.txhash, txin.txhash + WALLY_TXHASH_LEN);
      out.vins_vout[vin] = txin.index;
    }

    size_t num_outputs = 0;
    CHECK_WALLY(wally_tx_get_num_outputs(tx, &num_outputs));
    for (size_t vout = 0; vout < num_outputs; vout++) {
      const auto& txout = tx->outputs[vout];
      std::vector<unsigned char> script(txout.script,
                                        txout.script + txout.script_len);
      if (!spk_.contains(script)) continue;
      if (!address.empty() && spk_[script].address != address) continue;
      auto privateBlindingKey = GetBlindingKey(script);

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
          script.data(), script.size(), asset_commitment.data(),
          asset_commitment.size(), asset_out.data(), asset_out.size(),
          abf_out.data(), abf_out.size(), vbf_out.data(), vbf_out.size(),
          &value_out));

      std::vector<unsigned char> asset_id(asset_out.begin(), asset_out.end());
      std::vector<unsigned char> asset_generator(ASSET_GENERATOR_LEN);
      CHECK_WALLY(wally_asset_generator_from_bytes(
          asset_id.data(), asset_id.size(), abf_out.data(), abf_out.size(),
          asset_generator.data(), asset_generator.size()));
      if (asset_commitment != asset_generator) {
        wally_tx_free(tx);
        throw std::runtime_error(
            "asset_generator mismatch with asset_commitment");
      }

      // Recompute and sanity-check value commitment
      std::vector<unsigned char> recomputed_value_commitment(
          ASSET_COMMITMENT_LEN);
      CHECK_WALLY(wally_asset_value_commitment(
          value_out, vbf_out.data(), vbf_out.size(), asset_generator.data(),
          asset_generator.size(), recomputed_value_commitment.data(),
          recomputed_value_commitment.size()));
      if (value_commitment_from_tx != recomputed_value_commitment) {
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
      out.script_pubkeys_in.push_back(script);
      out.value_commitments_in.push_back(value_commitment_from_tx);
      out.vouts_in.push_back(static_cast<uint32_t>(vout));
    }

    wally_tx_free(tx);
    return out;
  }

  // Returns true iff every input of `tx_hex` has a non-empty witness stack.
  //
  // CreateTx leaves the witness empty on all inputs; SignTx fills the witness
  // (sig + pubkey for P2WPKH) on all of them. So "all witnesses non-empty"
  // is a reliable signal that the tx has been signed by this signer flow.
  //
  // Note: this only checks witness presence, not signature validity. It also
  // assumes a witness-based script type (P2WPKH/P2WSH). A legacy P2PKH input
  // would put its signature in scriptSig, which this check does not consider.
  bool IsTxSigned(const std::string& tx_hex) {
    struct wally_tx* tx = nullptr;
    CHECK_WALLY(wally_tx_from_hex(tx_hex.c_str(), tx_flags_, &tx));

    size_t num_inputs = 0;
    CHECK_WALLY(wally_tx_get_num_inputs(tx, &num_inputs));
    if (num_inputs == 0) {
      wally_tx_free(tx);
      return false;
    }

    bool all_signed = true;
    for (size_t vin = 0; vin < num_inputs; ++vin) {
      size_t items = 0;
      CHECK_WALLY(wally_tx_get_input_witness_num_items(tx, vin, &items));
      if (items == 0) {
        all_signed = false;
        break;
      }
    }
    wally_tx_free(tx);
    return all_signed;
  }

  // Build and blind a Liquid transaction; returns unsigned hex (no witness
  // signatures). Use SignTx(hex, inputs) when ready to sign.
  std::string CreateTx(
      const std::vector<LiquidUtxos>& inputs,
      const std::vector<std::string>& destinationConfAddrs,
      const std::string& feeChangeConfAddr,  // empty => no fee change output
      const std::vector<unsigned char>& assetIdToSend, uint64_t feeSats) {
    if (inputs.empty())
      throw std::runtime_error("prevTxHexes must be non-empty");
    if (destinationConfAddrs.empty())
      throw std::runtime_error("destinationConfAddrs must be non-empty");

    const std::vector<unsigned char> ZERO32(32, 0);

    // Merge
    std::vector<unsigned char> asset_generators_in;
    std::vector<unsigned char> asset_ids_in;
    std::vector<uint64_t> values_in;
    std::vector<unsigned char> abfs_in;
    std::vector<unsigned char> vbfs_in;
    std::vector<std::vector<unsigned char>> script_pubkeys_in;
    std::vector<std::vector<unsigned char>> value_commitments_in;
    std::vector<uint32_t> vouts_in;
    std::vector<std::vector<unsigned char>> input_prev_txid_for_vin;

    for (auto& u : inputs) {
      asset_generators_in.insert(asset_generators_in.end(),
                                 u.asset_generators_in.begin(),
                                 u.asset_generators_in.end());
      asset_ids_in.insert(asset_ids_in.end(), u.asset_ids_in.begin(),
                          u.asset_ids_in.end());
      values_in.insert(values_in.end(), u.values_in.begin(), u.values_in.end());
      abfs_in.insert(abfs_in.end(), u.abfs_in.begin(), u.abfs_in.end());
      vbfs_in.insert(vbfs_in.end(), u.vbfs_in.begin(), u.vbfs_in.end());
      script_pubkeys_in.insert(script_pubkeys_in.end(),
                               u.script_pubkeys_in.begin(),
                               u.script_pubkeys_in.end());
      value_commitments_in.insert(value_commitments_in.end(),
                                  u.value_commitments_in.begin(),
                                  u.value_commitments_in.end());
      vouts_in.insert(vouts_in.end(), u.vouts_in.begin(), u.vouts_in.end());

      // One tx_id per input
      for (size_t k = 0; k < u.vouts_in.size(); k++)
        input_prev_txid_for_vin.push_back(u.tx_id);
    }

    const size_t num_inputs = values_in.size();
    if (num_inputs == 0)
      throw std::runtime_error(
          "No spendable outputs found in prev tx(s) for our script_pubkey");

    // Determine which input indices are transfer-fee based on asset ids
    const bool feeAssetSame = assetIdToSend == WallyUtils::C().LBTC_ASSET_ID;
    std::vector<size_t> transferIdx;
    std::vector<size_t> feeIdx;
    transferIdx.reserve(num_inputs);
    feeIdx.reserve(num_inputs);

    for (size_t vin = 0; vin < num_inputs; vin++) {
      const unsigned char* id = asset_ids_in.data() + vin * 32;
      if (std::memcmp(id, assetIdToSend.data(), 32) == 0)
        transferIdx.push_back(vin);
      if (std::memcmp(id, WallyUtils::C().LBTC_ASSET_ID.data(), 32) == 0)
        feeIdx.push_back(vin);
    }

    if (transferIdx.empty()) {
      throw std::runtime_error("No inputs found for assetIdToSend");
    }

    if (feeAssetSame) {
      feeIdx = transferIdx;
    } else {
      if (feeIdx.empty())
        throw std::runtime_error("No inputs found for feeAssetId");
    }

    // Ensure there are no other assets besides transfer and fee assets
    std::vector<char> used(num_inputs, 0);
    for (auto i : transferIdx) used[i] = 1;
    for (auto i : feeIdx) used[i] = 1;
    for (size_t vin = 0; vin < num_inputs; vin++) {
      if (!used[vin])
        throw std::runtime_error(
            "Mixed assets present beyond assetIdToSend/feeAssetId; this "
            "example does not support it");
    }

    uint64_t transferTotalIn = 0;
    uint64_t feeTotalIn = 0;
    for (auto i : transferIdx) transferTotalIn += values_in[i];
    for (auto i : feeIdx) feeTotalIn += values_in[i];

    if (feeAssetSame) {
      if (transferTotalIn <= feeSats)
        throw std::runtime_error("Input amount is not enough to pay fee");
    } else {
      if (feeTotalIn < feeSats)
        throw std::runtime_error("Fee inputs are not enough to pay feeSats");
    }

    // Split recipient outputs
    const size_t n = destinationConfAddrs.size();
    uint64_t remaining = 0;
    if (feeAssetSame)
      remaining = transferTotalIn - feeSats;
    else
      remaining = transferTotalIn;

    std::vector<uint64_t> output_values;
    output_values.reserve(n);
    uint64_t perOut = remaining / static_cast<uint64_t>(n);
    uint64_t sum = 0;
    for (size_t i = 0; i + 1 < n; i++) {
      output_values.push_back(perOut);
      sum += perOut;
    }
    output_values.push_back(remaining - sum);

    const uint64_t feeRemaining = (feeAssetSame ? 0 : (feeTotalIn - feeSats));

    // fee change optional decomposition
    const bool createFeeChange =
        (!feeAssetSame && feeRemaining > 0 && !feeChangeConfAddr.empty());
    if (!feeAssetSame && feeRemaining > 0 && feeChangeConfAddr.empty()) {
      throw std::runtime_error(
          "feeChangeConfAddr is required when feeRemaining > 0 and feeAsset != "
          "assetIdToSend");
    }

    // Blinding factors for recipients:
    std::vector<std::vector<unsigned char>> abfs_recipient(
        n, std::vector<unsigned char>(32));
    std::vector<std::vector<unsigned char>> vbfs_recipient_all(
        n, std::vector<unsigned char>(32));

    for (size_t i = 0; i < n; i++)
      abfs_recipient[i] = WallyUtils::RandomBytes(32);
    for (size_t i = 0; i + 1 < n; i++)
      vbfs_recipient_all[i] = WallyUtils::RandomBytes(32);

    // Build transfer arrays for asset_final_vbf
    std::vector<uint64_t> transfer_values_in;
    transfer_values_in.reserve(transferIdx.size());
    std::vector<unsigned char> transfer_abfs_in;
    std::vector<unsigned char> transfer_vbfs_in;
    for (auto idx : transferIdx) {
      transfer_values_in.push_back(values_in[idx]);
      transfer_abfs_in.insert(transfer_abfs_in.end(),
                              abfs_in.begin() + idx * 32,
                              abfs_in.begin() + (idx + 1) * 32);
      transfer_vbfs_in.insert(transfer_vbfs_in.end(),
                              vbfs_in.begin() + idx * 32,
                              vbfs_in.begin() + (idx + 1) * 32);
    }

    // Prepare asset_final_vbf for transfer recipients
    std::vector<uint64_t> transfer_values_for_vbf = transfer_values_in;
    if (feeAssetSame) transfer_values_for_vbf.push_back(feeSats);
    transfer_values_for_vbf.insert(transfer_values_for_vbf.end(),
                                   output_values.begin(), output_values.end());

    std::vector<unsigned char> transfer_abfs_for_vbf = transfer_abfs_in;
    std::vector<unsigned char> transfer_vbfs_for_vbf = transfer_vbfs_in;
    if (feeAssetSame)
      transfer_abfs_for_vbf.insert(transfer_abfs_for_vbf.end(), ZERO32.begin(),
                                   ZERO32.end());
    // recipients abfs
    for (size_t i = 0; i < n; i++) {
      transfer_abfs_for_vbf.insert(transfer_abfs_for_vbf.end(),
                                   abfs_recipient[i].begin(),
                                   abfs_recipient[i].end());
    }
    if (feeAssetSame)
      transfer_vbfs_for_vbf.insert(transfer_vbfs_for_vbf.end(), ZERO32.begin(),
                                   ZERO32.end());
    // recipients vbf except last
    for (size_t i = 0; i + 1 < n; i++) {
      transfer_vbfs_for_vbf.insert(transfer_vbfs_for_vbf.end(),
                                   vbfs_recipient_all[i].begin(),
                                   vbfs_recipient_all[i].end());
    }

    std::vector<unsigned char> vbf_final(32, 0);
    CHECK_WALLY(wally_asset_final_vbf(
        transfer_values_for_vbf.data(), transfer_values_for_vbf.size(),
        transferIdx.size(), transfer_abfs_for_vbf.data(),
        transfer_abfs_for_vbf.size(), transfer_vbfs_for_vbf.data(),
        transfer_vbfs_for_vbf.size(), vbf_final.data(), vbf_final.size()));
    vbfs_recipient_all[n - 1] = vbf_final;

    // Prepare fee change blinding factors if needed
    std::vector<unsigned char> feeChange_abf(32, 0);
    std::vector<unsigned char> feeChange_vbf(32, 0);
    std::vector<unsigned char> fee_abfs_in;
    std::vector<unsigned char> fee_vbfs_in;
    std::vector<uint64_t> fee_values_in;

    if (createFeeChange) {
      for (auto idx : feeIdx) {
        fee_values_in.push_back(values_in[idx]);
        fee_abfs_in.insert(fee_abfs_in.end(), abfs_in.begin() + idx * 32,
                           abfs_in.begin() + (idx + 1) * 32);
        fee_vbfs_in.insert(fee_vbfs_in.end(), vbfs_in.begin() + idx * 32,
                           vbfs_in.begin() + (idx + 1) * 32);
      }
      feeChange_abf = WallyUtils::RandomBytes(32);

      // feeChange_vbf equation: values = feeValuesIn + [feeSats, feeRemaining]
      std::vector<uint64_t> fee_values_for_vbf = fee_values_in;
      fee_values_for_vbf.push_back(feeSats);
      fee_values_for_vbf.push_back(feeRemaining);

      std::vector<unsigned char> fee_abfs_for_vbf = fee_abfs_in;
      fee_abfs_for_vbf.insert(fee_abfs_for_vbf.end(), ZERO32.begin(),
                              ZERO32.end());  // explicit fee output abf=0
      fee_abfs_for_vbf.insert(fee_abfs_for_vbf.end(), feeChange_abf.begin(),
                              feeChange_abf.end());

      std::vector<unsigned char> fee_vbfs_for_vbf = fee_vbfs_in;
      fee_vbfs_for_vbf.insert(fee_vbfs_for_vbf.end(), ZERO32.begin(),
                              ZERO32.end());  // explicit fee output vbf=0

      CHECK_WALLY(wally_asset_final_vbf(
          fee_values_for_vbf.data(), fee_values_for_vbf.size(), feeIdx.size(),
          fee_abfs_for_vbf.data(), fee_abfs_for_vbf.size(),
          fee_vbfs_for_vbf.data(), fee_vbfs_for_vbf.size(),
          feeChange_vbf.data(), feeChange_vbf.size()));
    }

    // Build inputIdxCombined (vin order) and combined arrays for
    // surjectionproof
    std::vector<size_t> inputIdxCombined = transferIdx;
    if (!feeAssetSame)
      inputIdxCombined.insert(inputIdxCombined.end(), feeIdx.begin(),
                              feeIdx.end());
    const size_t num_inputs_combined = inputIdxCombined.size();

    std::vector<std::vector<unsigned char>> combined_input_prev_txid_for_vin;
    std::vector<uint32_t> combined_vouts_in;
    combined_input_prev_txid_for_vin.reserve(num_inputs_combined);
    combined_vouts_in.reserve(num_inputs_combined);

    for (auto idx : inputIdxCombined) {
      combined_input_prev_txid_for_vin.push_back(input_prev_txid_for_vin[idx]);
      combined_vouts_in.push_back(vouts_in[idx]);
    }

    std::vector<unsigned char> combined_asset_ids_in_for_surj;
    std::vector<unsigned char> combined_abfs_in_for_surj;
    std::vector<unsigned char> combined_asset_generators_in_for_surj;
    combined_asset_ids_in_for_surj.reserve(num_inputs_combined * 32);
    combined_abfs_in_for_surj.reserve(num_inputs_combined * 32);
    combined_asset_generators_in_for_surj.reserve(num_inputs_combined *
                                                  ASSET_GENERATOR_LEN);

    for (auto idx : inputIdxCombined) {
      combined_asset_ids_in_for_surj.insert(
          combined_asset_ids_in_for_surj.end(), asset_ids_in.begin() + idx * 32,
          asset_ids_in.begin() + (idx + 1) * 32);
      combined_abfs_in_for_surj.insert(combined_abfs_in_for_surj.end(),
                                       abfs_in.begin() + idx * 32,
                                       abfs_in.begin() + (idx + 1) * 32);
      combined_asset_generators_in_for_surj.insert(
          combined_asset_generators_in_for_surj.end(),
          asset_generators_in.begin() + idx * ASSET_GENERATOR_LEN,
          asset_generators_in.begin() + (idx + 1) * ASSET_GENERATOR_LEN);
    }

    // Create tx
    const size_t num_outputs = 1 + n + (createFeeChange ? 1 : 0);
    struct wally_tx* output_tx = nullptr;
    CHECK_WALLY(wally_tx_init_alloc(2, 0, num_inputs_combined, num_outputs,
                                    &output_tx));

    // Fee output explicit (vout0)
    std::vector<unsigned char> fee_asset(1 + 32);
    fee_asset[0] = 0x01;
    std::memcpy(fee_asset.data() + 1, WallyUtils::C().LBTC_ASSET_ID.data(), 32);

    std::vector<unsigned char> fee_value(WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN);
    CHECK_WALLY(wally_tx_confidential_value_from_satoshi(
        feeSats, fee_value.data(), fee_value.size()));

    CHECK_WALLY(wally_tx_add_elements_raw_output(
        output_tx, nullptr, 0, fee_asset.data(), fee_asset.size(),
        fee_value.data(), fee_value.size(), nullptr, 0, nullptr, 0, nullptr, 0,
        0));

    // Recipient outputs (transfer asset)
    for (size_t i = 0; i < n; i++) {
      const uint64_t value = output_values[i];
      const auto& abf = abfs_recipient[i];
      const auto& vbf = vbfs_recipient_all[i];
      const auto& blinding_pubkey =
          WallyUtils::GetBlindingPubKeyFromConfidentialAddress(
              destinationConfAddrs[i]);
      const auto& script_pubkey =
          WallyUtils::GetScriptPubkeyFromConfidentialAddress(
              destinationConfAddrs[i]);

      std::vector<unsigned char> generator(ASSET_GENERATOR_LEN);
      CHECK_WALLY(wally_asset_generator_from_bytes(
          assetIdToSend.data(), assetIdToSend.size(), abf.data(), abf.size(),
          generator.data(), generator.size()));

      std::vector<unsigned char> value_commitment_out(ASSET_COMMITMENT_LEN);
      CHECK_WALLY(wally_asset_value_commitment(
          value, vbf.data(), vbf.size(), generator.data(), generator.size(),
          value_commitment_out.data(), value_commitment_out.size()));

      auto eph_priv = WallyUtils::RandomEcPrivateKey();
      std::vector<unsigned char> eph_pub(EC_PUBLIC_KEY_LEN);
      CHECK_WALLY(wally_ec_public_key_from_private_key(
          eph_priv.data(), eph_priv.size(), eph_pub.data(), eph_pub.size()));

      std::vector<unsigned char> rangeproof(ASSET_RANGEPROOF_MAX_LEN);
      size_t rangeproof_len = 0;
      CHECK_WALLY(wally_asset_rangeproof(
          value, blinding_pubkey.data(), blinding_pubkey.size(),
          eph_priv.data(), eph_priv.size(), assetIdToSend.data(),
          assetIdToSend.size(), abf.data(), abf.size(), vbf.data(), vbf.size(),
          value_commitment_out.data(), value_commitment_out.size(),
          script_pubkey.data(), script_pubkey.size(), generator.data(),
          generator.size(), 1, 0, 36, rangeproof.data(), rangeproof.size(),
          &rangeproof_len));
      rangeproof.resize(rangeproof_len);

      std::vector<unsigned char> surj(ASSET_SURJECTIONPROOF_MAX_LEN);
      size_t surj_len = ASSET_SURJECTIONPROOF_MAX_LEN;
      auto surj_entropy = WallyUtils::RandomBytes(32);
      CHECK_WALLY(wally_asset_surjectionproof(
          assetIdToSend.data(), assetIdToSend.size(), abf.data(), abf.size(),
          generator.data(), generator.size(), surj_entropy.data(),
          surj_entropy.size(), combined_asset_ids_in_for_surj.data(),
          combined_asset_ids_in_for_surj.size(),
          combined_abfs_in_for_surj.data(), combined_abfs_in_for_surj.size(),
          combined_asset_generators_in_for_surj.data(),
          combined_asset_generators_in_for_surj.size(), surj.data(),
          surj.size(), &surj_len));
      surj.resize(surj_len);

      CHECK_WALLY(wally_tx_add_elements_raw_output(
          output_tx, script_pubkey.data(), script_pubkey.size(),
          generator.data(), generator.size(), value_commitment_out.data(),
          value_commitment_out.size(), eph_pub.data(), eph_pub.size(),
          surj.data(), surj.size(), rangeproof.data(), rangeproof.size(), 0));
    }

    // Fee change output (if any)
    if (createFeeChange) {
      std::vector<unsigned char> generator(ASSET_GENERATOR_LEN);
      CHECK_WALLY(wally_asset_generator_from_bytes(
          WallyUtils::C().LBTC_ASSET_ID.data(),
          WallyUtils::C().LBTC_ASSET_ID.size(), feeChange_abf.data(),
          feeChange_abf.size(), generator.data(), generator.size()));

      std::vector<unsigned char> value_commitment_out(ASSET_COMMITMENT_LEN);
      CHECK_WALLY(wally_asset_value_commitment(
          feeRemaining, feeChange_vbf.data(), feeChange_vbf.size(),
          generator.data(), generator.size(), value_commitment_out.data(),
          value_commitment_out.size()));

      auto eph_priv = WallyUtils::RandomEcPrivateKey();
      std::vector<unsigned char> eph_pub(EC_PUBLIC_KEY_LEN);
      CHECK_WALLY(wally_ec_public_key_from_private_key(
          eph_priv.data(), eph_priv.size(), eph_pub.data(), eph_pub.size()));

      std::vector<unsigned char> rangeproof(ASSET_RANGEPROOF_MAX_LEN);
      size_t rangeproof_len = 0;

      const auto& blinding_pubkey =
          WallyUtils::GetBlindingPubKeyFromConfidentialAddress(
              feeChangeConfAddr);
      const auto& script_pubkey =
          WallyUtils::GetScriptPubkeyFromConfidentialAddress(feeChangeConfAddr);

      CHECK_WALLY(wally_asset_rangeproof(
          feeRemaining, blinding_pubkey.data(), blinding_pubkey.size(),
          eph_priv.data(), eph_priv.size(),
          WallyUtils::C().LBTC_ASSET_ID.data(),
          WallyUtils::C().LBTC_ASSET_ID.size(), feeChange_abf.data(),
          feeChange_abf.size(), feeChange_vbf.data(), feeChange_vbf.size(),
          value_commitment_out.data(), value_commitment_out.size(),
          script_pubkey.data(), script_pubkey.size(), generator.data(),
          generator.size(), 1, 0, 36, rangeproof.data(), rangeproof.size(),
          &rangeproof_len));
      rangeproof.resize(rangeproof_len);

      std::vector<unsigned char> surj(ASSET_SURJECTIONPROOF_MAX_LEN);
      size_t surj_len = ASSET_SURJECTIONPROOF_MAX_LEN;
      auto surj_entropy = WallyUtils::RandomBytes(32);
      CHECK_WALLY(wally_asset_surjectionproof(
          WallyUtils::C().LBTC_ASSET_ID.data(),
          WallyUtils::C().LBTC_ASSET_ID.size(), feeChange_abf.data(),
          feeChange_abf.size(), generator.data(), generator.size(),
          surj_entropy.data(), surj_entropy.size(),
          combined_asset_ids_in_for_surj.data(),
          combined_asset_ids_in_for_surj.size(),
          combined_abfs_in_for_surj.data(), combined_abfs_in_for_surj.size(),
          combined_asset_generators_in_for_surj.data(),
          combined_asset_generators_in_for_surj.size(), surj.data(),
          surj.size(), &surj_len));
      surj.resize(surj_len);

      CHECK_WALLY(wally_tx_add_elements_raw_output(
          output_tx, script_pubkey.data(), script_pubkey.size(),
          generator.data(), generator.size(), value_commitment_out.data(),
          value_commitment_out.size(), eph_pub.data(), eph_pub.size(),
          surj.data(), surj.size(), rangeproof.data(), rangeproof.size(), 0));
    }

    // Inputs spending prevouts
    for (size_t vin = 0; vin < num_inputs_combined; vin++) {
      const auto& prev_tx_id = combined_input_prev_txid_for_vin[vin];
      CHECK_WALLY(wally_tx_add_elements_raw_input(
          output_tx, prev_tx_id.data(), prev_tx_id.size(),
          combined_vouts_in[vin], 0xffffffff, nullptr,
          0,           // script + script_len
          nullptr,     // witness
          nullptr, 0,  // nonce + nonce_len
          nullptr, 0,  // entropy + entropy_len
          nullptr, 0,  // issuance_amount + issuance_amount_len
          nullptr, 0,  // inflation_keys + inflation_keys_len
          nullptr,
          0,  // issuance_amount_rangeproof + issuance_amount_rangeproof_len
          nullptr,
          0,        // inflation_keys_rangeproof + inflation_keys_rangeproof_len
          nullptr,  // pegin_witness
          0));      // flags
    }

    // Serialize unsigned tx (witness stacks empty). Call SignTx(hex, inputs)
    // later to produce a broadcast-ready transaction.
    char* txhex = nullptr;
    CHECK_WALLY(wally_tx_to_hex(output_tx, tx_flags_, &txhex));
    std::string txHexOut(txhex);
    wally_free_string(txhex);
    wally_tx_free(output_tx);
    return txHexOut;
  }

  // Signs an unsigned Liquid hex transaction produced by CreateTx.
  //
  // Elements confidential sighash requires each input's previous confidential
  // value commitment; that data is not present in the spending tx hex, so we
  // rebuild script_pubkey + value_commitment by matching each vin's (txid,
  // vout) against `inputs` (the same LiquidUtxos vector passed to CreateTx).
  std::string SignTx(const std::string& tx_hex,
                     const std::vector<LiquidUtxos>& inputs) {
    std::map<std::string, PrevoutSpendData> prevouts =
        BuildPrevoutSpendDataMap(inputs);

    struct wally_tx* tx = nullptr;
    CHECK_WALLY(wally_tx_from_hex(tx_hex.c_str(), tx_flags_, &tx));

    size_t num_inputs = 0;
    CHECK_WALLY(wally_tx_get_num_inputs(tx, &num_inputs));

    std::vector<std::vector<unsigned char>> script_pubkeys_in;
    std::vector<std::vector<unsigned char>> value_commitments_in;
    script_pubkeys_in.reserve(num_inputs);
    value_commitments_in.reserve(num_inputs);

    for (size_t vin = 0; vin < num_inputs; ++vin) {
      std::vector<unsigned char> txhash(WALLY_TXHASH_LEN);
      CHECK_WALLY(
          wally_tx_get_input_txhash(tx, vin, txhash.data(), txhash.size()));
      size_t vout_index = 0;
      CHECK_WALLY(wally_tx_get_input_index(tx, vin, &vout_index));
      const auto vout_u32 = static_cast<uint32_t>(vout_index);

      const std::string key = MakePrevoutMapKey(txhash.data(), vout_u32);
      auto it = prevouts.find(key);
      if (it == prevouts.end()) {
        wally_tx_free(tx);
        throw std::runtime_error(
            "SignTx: no LiquidUtxos match for input vin=" +
            std::to_string(vin) +
            " (need same UTXO set used when building the unsigned tx)");
      }
      script_pubkeys_in.push_back(it->second.first);
      value_commitments_in.push_back(it->second.second);
    }

    SignTxInPlace(tx, script_pubkeys_in, value_commitments_in);

    char* out_hex = nullptr;
    CHECK_WALLY(wally_tx_to_hex(tx, tx_flags_, &out_hex));
    std::string signed_hex(out_hex);
    wally_free_string(out_hex);
    wally_tx_free(tx);
    return signed_hex;
  }
};
}  // namespace nunchuk::wally

#endif  // NUNCHUK_WALLY_SIGNER_HPP