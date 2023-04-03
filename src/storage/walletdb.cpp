/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2020 Enigmo.
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

#include "walletdb.h"

#include <descriptor.h>
#include <utils/bip32.hpp>
#include <utils/txutils.hpp>
#include <utils/json.hpp>
#include <utils/loguru.hpp>
#include <utils/bsms.hpp>
#include <utils/stringutils.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <sstream>
#include "storage/common.h"

#include <univalue.h>
#include <rpc/util.h>
#include <policy/policy.h>
#include <signingprovider.h>

#include <base58.h>
#include <util/strencodings.h>
#include <util/bip32.h>

using json = nlohmann::json;
namespace ba = boost::algorithm;

namespace nunchuk {

static const int ADDRESS_LOOK_AHEAD = 20;

std::map<std::string, std::map<std::string, AddressData>>
    NunchukWalletDb::addr_cache_;
std::map<std::string, std::vector<SingleSigner>> NunchukWalletDb::signer_cache_;

void NunchukWalletDb::InitWallet(const Wallet& wallet) {
  CreateTable();
  // Note: when we update VTX table model, all these functions: CreatePsbt,
  // UpdatePsbtTxId, GetTransactions, GetTransaction need to be updated to
  // reflect the new fields.
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS VTX("
                        "ID TEXT PRIMARY KEY     NOT NULL,"
                        "VALUE           TEXT    NOT NULL,"
                        "HEIGHT          INT     NOT NULL,"
                        "FEE             INT     NOT NULL,"
                        "MEMO            TEXT    NOT NULL,"
                        "CHANGEPOS       INT     NOT NULL,"
                        "BLOCKTIME       INT     NOT NULL,"
                        "EXTRA           TEXT    NOT NULL);",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS ADDRESS("
                        "ADDR TEXT PRIMARY KEY     NOT NULL,"
                        "IDX             INT     NOT NULL,"
                        "INTERNAL        INT     NOT NULL,"
                        "USED            INT     NOT NULL,"
                        "UTXO            TEXT);",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS SIGNER("
                        "KEY TEXT PRIMARY KEY     NOT NULL,"
                        "NAME             TEXT    NOT NULL,"
                        "MASTER_ID        TEXT    NOT NULL,"
                        "LAST_HEALTHCHECK INT     NOT NULL);",
                        NULL, 0, NULL));
  PutString(DbKeys::NAME, wallet.get_name());
  PutString(DbKeys::DESCRIPTION, wallet.get_description());

  json immutable_data = {{"m", wallet.get_m()},
                         {"n", wallet.get_n()},
                         {"address_type", wallet.get_address_type()},
                         {"is_escrow", wallet.is_escrow()},
                         {"create_date", wallet.get_create_date()}};
  PutString(DbKeys::IMMUTABLE_DATA, immutable_data.dump());
  for (auto&& signer : wallet.get_signers()) {
    AddSigner(signer);
  }
  CreateCoinControlTable();
}

void NunchukWalletDb::MaybeMigrate() {
  int64_t current_ver = GetInt(DbKeys::VERSION);
  if (current_ver == STORAGE_VER) return;
  if (current_ver < 1) {
    sqlite3_exec(db_, "ALTER TABLE VTX ADD COLUMN BLOCKTIME INT;", NULL, 0,
                 NULL);
  }
  if (current_ver < 2) {
    sqlite3_exec(db_, "ALTER TABLE VTX ADD COLUMN EXTRA TEXT;", NULL, 0, NULL);
  }
  if (current_ver < 4) {
    CreateCoinControlTable();
  }
  DLOG_F(INFO, "NunchukWalletDb migrate to version %d", STORAGE_VER);
  PutInt(DbKeys::VERSION, STORAGE_VER);
}

std::string NunchukWalletDb::GetSingleSignerKey(const SingleSigner& signer) {
  json basic_data = {{"xpub", signer.get_xpub()},
                     {"public_key", signer.get_public_key()},
                     {"derivation_path", signer.get_derivation_path()},
                     {"master_fingerprint",
                      ba::to_lower_copy(signer.get_master_fingerprint())}};
  return basic_data.dump();
}

bool NunchukWalletDb::AddSigner(const SingleSigner& signer) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO SIGNER(KEY, NAME, MASTER_ID, LAST_HEALTHCHECK)"
      "VALUES (?1, ?2, ?3, ?4);";
  std::string key = GetSingleSignerKey(signer);
  std::string name = signer.get_name();
  std::string master_id = ba::to_lower_copy(signer.get_master_signer_id());
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, key.c_str(), key.size(), NULL);
  sqlite3_bind_text(stmt, 2, name.c_str(), name.size(), NULL);
  sqlite3_bind_text(stmt, 3, master_id.c_str(), master_id.size(), NULL);
  sqlite3_bind_int64(stmt, 4, signer.get_last_health_check());
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

void NunchukWalletDb::DeleteWallet() {
  SQLCHECK(sqlite3_exec(db_, "DROP TABLE IF EXISTS SIGNER;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DROP TABLE IF EXISTS ADDRESS;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DROP TABLE IF EXISTS VTX;", NULL, 0, NULL));
  DropTable();
}

bool NunchukWalletDb::SetName(const std::string& value) {
  return PutString(DbKeys::NAME, value);
}

bool NunchukWalletDb::SetDescription(const std::string& value) {
  return PutString(DbKeys::DESCRIPTION, value);
}

bool NunchukWalletDb::SetLastUsed(time_t value) {
  return PutInt(DbKeys::LAST_USED, value);
}

Wallet NunchukWalletDb::GetWallet(bool skip_balance, bool skip_provider) const {
  json immutable_data = json::parse(GetString(DbKeys::IMMUTABLE_DATA));
  int m = immutable_data["m"];
  int n = immutable_data["n"];
  AddressType address_type = immutable_data["address_type"];
  bool is_escrow = immutable_data["is_escrow"];
  time_t create_date = immutable_data["create_date"];

  Wallet wallet(id_, m, n, GetSigners(), address_type, is_escrow, create_date);
  wallet.set_name(GetString(DbKeys::NAME));
  wallet.set_description(GetString(DbKeys::DESCRIPTION));
  wallet.set_last_used(GetInt(DbKeys::LAST_USED));
  if (!skip_balance) {
    wallet.set_balance(GetBalance(false));
    wallet.set_unconfirmed_balance(GetBalance(true));
  }
  if (!skip_provider) {
    GetAllAddressData();  // update range to max address index
    auto desc = GetDescriptorsImportString(wallet);
    SigningProviderCache::getInstance().PreCalculate(desc);
  }
  return wallet;
}

std::vector<SingleSigner> NunchukWalletDb::GetSigners() const {
  if (signer_cache_.count(db_file_name_)) {
    return signer_cache_[db_file_name_];
  }
  sqlite3_stmt* stmt;
  std::string sql =
      "SELECT KEY, NAME, MASTER_ID, LAST_HEALTHCHECK FROM SIGNER;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);
  std::vector<SingleSigner> signers;
  while (sqlite3_column_text(stmt, 0)) {
    std::string key = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string name = std::string((char*)sqlite3_column_text(stmt, 1));
    std::string master_id = std::string((char*)sqlite3_column_text(stmt, 2));

    json basic_info = json::parse(key);
    std::string xpub = basic_info["xpub"];
    std::string public_key = basic_info["public_key"];
    std::string derivation_path = basic_info["derivation_path"];
    std::string master_fingerprint = basic_info["master_fingerprint"];
    ba::to_lower(master_fingerprint);
    time_t last_health_check = sqlite3_column_int64(stmt, 3);
    SingleSigner signer(name, xpub, public_key, derivation_path,
                        master_fingerprint, last_health_check, master_id, false,
                        SignerType::UNKNOWN);
    signers.push_back(signer);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  signer_cache_[db_file_name_] = signers;
  return signers;
}

void NunchukWalletDb::SetAddress(const std::string& address, int index,
                                 bool internal, const std::string& utxos) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO ADDRESS(ADDR, IDX, INTERNAL, USED, UTXO)"
      "VALUES (?1, ?2, ?3, ?4, ?5)"
      "ON CONFLICT(ADDR) DO UPDATE SET USED=excluded.USED, UTXO=excluded.UTXO;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, address.c_str(), address.size(), NULL);
  sqlite3_bind_int(stmt, 2, index);
  sqlite3_bind_int(stmt, 3, internal ? 1 : 0);
  sqlite3_bind_int(stmt, 4, utxos.empty() ? 0 : 1);
  sqlite3_bind_text(stmt, 5, utxos.c_str(), utxos.size(), NULL);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
}

bool NunchukWalletDb::AddAddress(const std::string& address, int index,
                                 bool internal) {
  SetAddress(address, index, internal);
  if (!IsMyAddress(address)) {
    addr_cache_[db_file_name_][address] = {address, index, internal, false};
    SigningProviderCache::getInstance().SetMaxIndex(id_, index);
  }
  return true;
}

void NunchukWalletDb::UseAddress(const std::string& address) const {
  if (address.empty()) return;
  if (!addr_cache_.count(db_file_name_)) return;
  if (!addr_cache_[db_file_name_].count(address)) return;
  addr_cache_[db_file_name_][address].used = true;
}

bool NunchukWalletDb::IsMyAddress(const std::string& address) const {
  return GetAllAddressData().count(address);
}

bool NunchukWalletDb::IsMyChange(const std::string& address) const {
  auto all = GetAllAddressData();
  return all.count(address) && all.at(address).internal;
}

std::map<std::string, AddressData> NunchukWalletDb::GetAllAddressData() const {
  if (addr_cache_.count(db_file_name_)) {
    return addr_cache_[db_file_name_];
  }
  std::map<std::string, AddressData> addresses;
  auto wallet = GetWallet(true, true);
  if (wallet.is_escrow()) {
    auto addr = CoreUtils::getInstance().DeriveAddress(
        wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL));
    addresses[addr] = {addr, 0, false, false};
  } else {
    int index = 0;
    auto internal_addr = CoreUtils::getInstance().DeriveAddresses(
        wallet.get_descriptor(DescriptorPath::INTERNAL_ALL), index,
        GetCurrentAddressIndex(true) + ADDRESS_LOOK_AHEAD);
    for (auto&& addr : internal_addr) {
      addresses[addr] = {addr, index++, true, false};
    }
    SigningProviderCache::getInstance().SetMaxIndex(id_, index);
    index = 0;
    auto external_addr = CoreUtils::getInstance().DeriveAddresses(
        wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL), index,
        GetCurrentAddressIndex(false) + ADDRESS_LOOK_AHEAD);
    for (auto&& addr : external_addr) {
      addresses[addr] = {addr, index++, false, false};
    }
    SigningProviderCache::getInstance().SetMaxIndex(id_, index);
  }
  addr_cache_[db_file_name_] = addresses;
  auto txs = GetTransactions();
  for (auto&& tx : txs) {
    for (auto&& output : tx.get_outputs()) UseAddress(output.first);
  }
  return addresses;
}

std::vector<std::string> NunchukWalletDb::GetAddresses(bool used,
                                                       bool internal) const {
  auto all = GetAllAddressData();
  auto cur = GetCurrentAddressIndex(internal);
  std::vector<std::string> rs;
  for (auto&& item : all) {
    auto data = item.second;
    if (data.used == used && data.internal == internal && data.index <= cur)
      rs.push_back(data.address);
  }
  return rs;
}

int NunchukWalletDb::GetAddressIndex(const std::string& address) const {
  auto all = GetAllAddressData();
  if (all.count(address)) return all.at(address).index;
  return -1;
}

Amount NunchukWalletDb::GetAddressBalance(const std::string& address) const {
  auto coins = GetCoins();
  Amount balance = 0;
  for (auto&& coin : coins) {
    if (coin.get_status() == CoinStatus::SPENT ||
        coin.get_status() == CoinStatus::OUTGOING_PENDING_CONFIRMATION ||
        coin.get_status() == CoinStatus::INCOMING_PENDING_CONFIRMATION)
      continue;
    if (coin.get_address() != address) continue;
    balance += coin.get_amount();
  }
  return balance;
}

std::string NunchukWalletDb::GetAddressStatus(
    const std::string& address) const {
  sqlite3_stmt* stmt;
  std::string sql =
      "SELECT UTXO FROM ADDRESS WHERE ADDR = ? AND UTXO IS NOT NULL;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, address.c_str(), address.size(), NULL);
  std::string status = "";
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    auto utxo = split(std::string((char*)sqlite3_column_text(stmt, 0)), '|');
    if (utxo.size() > 1) status = utxo[1];
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return status;
}

std::vector<std::string> NunchukWalletDb::GetAllAddresses() const {
  auto all = GetAllAddressData();
  std::vector<std::string> rs;
  for (auto&& data : all) {
    rs.push_back(data.second.address);
  }
  return rs;
}

int NunchukWalletDb::GetCurrentAddressIndex(bool internal) const {
  sqlite3_stmt* stmt;
  std::string sql =
      "SELECT MAX(IDX) FROM ADDRESS WHERE INTERNAL = ? GROUP BY INTERNAL";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, internal ? 1 : 0);
  int current_index = -1;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    current_index = sqlite3_column_int(stmt, 0);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return current_index;
}

Transaction NunchukWalletDb::InsertTransaction(const std::string& raw_tx,
                                               int height, time_t blocktime,
                                               Amount fee,
                                               const std::string& memo,
                                               int change_pos) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO VTX(ID, VALUE, HEIGHT, FEE, MEMO, CHANGEPOS, BLOCKTIME, "
      "EXTRA)"
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '')"
      "ON CONFLICT(ID) DO UPDATE SET VALUE=excluded.VALUE, "
      "HEIGHT=excluded.HEIGHT;";
  CMutableTransaction mtx = DecodeRawTransaction(raw_tx);
  std::string tx_id = mtx.GetHash().GetHex();
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_bind_text(stmt, 2, raw_tx.c_str(), raw_tx.size(), NULL);
  sqlite3_bind_int64(stmt, 3, height);
  sqlite3_bind_int64(stmt, 4, fee);
  sqlite3_bind_text(stmt, 5, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_int(stmt, 6, change_pos);
  sqlite3_bind_int64(stmt, 7, blocktime);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
  return GetTransaction(tx_id);
}

void NunchukWalletDb::SetReplacedBy(const std::string& old_txid,
                                    const std::string& new_txid) {
  // Get replaced tx extra
  sqlite3_stmt* select_stmt;
  std::string select_sql = "SELECT EXTRA FROM VTX WHERE ID = ?;";
  sqlite3_prepare_v2(db_, select_sql.c_str(), -1, &select_stmt, NULL);
  sqlite3_bind_text(select_stmt, 1, old_txid.c_str(), old_txid.size(), NULL);
  sqlite3_step(select_stmt);
  if (sqlite3_column_text(select_stmt, 0)) {
    // Update replaced tx extra
    std::string extra = std::string((char*)sqlite3_column_text(select_stmt, 0));
    json extra_json = json::parse(extra);
    extra_json["replaced_by_txid"] = new_txid;
    extra = extra_json.dump();

    sqlite3_stmt* update_stmt;
    std::string update_sql = "UPDATE VTX SET EXTRA = ?1 WHERE ID = ?2;";
    sqlite3_prepare_v2(db_, update_sql.c_str(), -1, &update_stmt, NULL);
    sqlite3_bind_text(update_stmt, 1, extra.c_str(), extra.size(), NULL);
    sqlite3_bind_text(update_stmt, 2, old_txid.c_str(), old_txid.size(), NULL);
    sqlite3_step(update_stmt);
    SQLCHECK(sqlite3_finalize(update_stmt));
  }
  SQLCHECK(sqlite3_finalize(select_stmt));
}

bool NunchukWalletDb::UpdateTransaction(const std::string& raw_tx, int height,
                                        time_t blocktime,
                                        const std::string& reject_msg) {
  if (height == -1) {
    auto [tx, is_hex_tx] = GetTransactionFromStr(raw_tx, GetSigners(), 0, -1);
    std::string tx_id = tx.get_txid();

    sqlite3_stmt* stmt;
    std::string sql = "SELECT EXTRA FROM VTX WHERE ID = ? AND HEIGHT = -1;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
    sqlite3_step(stmt);

    std::string extra;
    if (sqlite3_column_text(stmt, 0)) {
      extra = std::string((char*)sqlite3_column_text(stmt, 0));
      json extra_json = json::parse(extra);
      extra_json["signers"] = tx.get_signers();
      extra = extra_json.dump();

      SQLCHECK(sqlite3_finalize(stmt));
    } else {
      SQLCHECK(sqlite3_finalize(stmt));
      throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
    }

    sql = extra.empty()
              ? "UPDATE VTX SET VALUE = ?1 WHERE ID = ?2;"
              : "UPDATE VTX SET VALUE = ?1, EXTRA = ?3 WHERE ID = ?2;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, raw_tx.c_str(), raw_tx.size(), NULL);
    sqlite3_bind_text(stmt, 2, tx_id.c_str(), tx_id.size(), NULL);
    if (!extra.empty()) {
      sqlite3_bind_text(stmt, 3, extra.c_str(), extra.size(), NULL);
    }

    sqlite3_step(stmt);
    bool updated = (sqlite3_changes(db_) == 1);
    SQLCHECK(sqlite3_finalize(stmt));
    if (updated) GetTransaction(tx_id);
    return updated;
  }

  CMutableTransaction mtx = DecodeRawTransaction(raw_tx);
  std::string tx_id = mtx.GetHash().GetHex();

  std::string extra = "";
  if (height <= 0) {
    // Persist signers to extra if the psbt existed
    sqlite3_stmt* stmt;
    std::string sql =
        "SELECT VALUE, EXTRA FROM VTX WHERE ID = ? AND HEIGHT = -1;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
    sqlite3_step(stmt);
    if (sqlite3_column_text(stmt, 1)) {
      std::string value = std::string((char*)sqlite3_column_text(stmt, 0));
      extra = std::string((char*)sqlite3_column_text(stmt, 1));
      auto [tx, is_hex_tx] = GetTransactionFromStr(value, GetSigners(), 0, -1);

      json extra_json = json::parse(extra);
      extra_json["signers"] = tx.get_signers();
      if (!reject_msg.empty()) {
        extra_json["reject_msg"] = reject_msg;
      }
      extra = extra_json.dump();
      if (extra_json["replace_txid"] != nullptr) {
        SetReplacedBy(extra_json["replace_txid"], tx_id);
      }
    }
    SQLCHECK(sqlite3_finalize(stmt));
  }

  sqlite3_stmt* stmt;
  std::string sql =
      extra.empty() ? "UPDATE VTX SET VALUE = ?1, HEIGHT = ?2, BLOCKTIME = ?3 "
                      "WHERE ID = ?4;"
                    : "UPDATE VTX SET VALUE = ?1, HEIGHT = ?2, BLOCKTIME = ?3, "
                      "EXTRA = ?5 WHERE ID = ?4;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, raw_tx.c_str(), raw_tx.size(), NULL);
  sqlite3_bind_int64(stmt, 2, height);
  sqlite3_bind_int64(stmt, 3, blocktime);
  sqlite3_bind_text(stmt, 4, tx_id.c_str(), tx_id.size(), NULL);
  if (!extra.empty()) {
    sqlite3_bind_text(stmt, 5, extra.c_str(), extra.size(), NULL);
  }
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) GetTransaction(tx_id);
  return updated;
}

bool NunchukWalletDb::UpdateTransactionMemo(const std::string& tx_id,
                                            const std::string& memo) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE VTX SET MEMO = ?1 WHERE ID = ?2;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_text(stmt, 2, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::UpdateTransactionSchedule(const std::string& tx_id,
                                                time_t value) {
  sqlite3_stmt* select_stmt;
  std::string select_sql = "SELECT EXTRA FROM VTX WHERE ID = ?;";
  sqlite3_prepare_v2(db_, select_sql.c_str(), -1, &select_stmt, NULL);
  sqlite3_bind_text(select_stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(select_stmt);
  bool updated = false;
  if (sqlite3_column_text(select_stmt, 0)) {
    std::string extra = std::string((char*)sqlite3_column_text(select_stmt, 0));
    json extra_json = extra.empty() ? json{} : json::parse(extra);
    extra_json["schedule_time"] = value;
    extra = extra_json.dump();

    sqlite3_stmt* update_stmt;
    std::string update_sql = "UPDATE VTX SET EXTRA = ?1 WHERE ID = ?2;";
    sqlite3_prepare_v2(db_, update_sql.c_str(), -1, &update_stmt, NULL);
    sqlite3_bind_text(update_stmt, 1, extra.c_str(), extra.size(), NULL);
    sqlite3_bind_text(update_stmt, 2, tx_id.c_str(), tx_id.size(), NULL);
    sqlite3_step(update_stmt);
    SQLCHECK(sqlite3_finalize(update_stmt));
    updated = true;
  }
  SQLCHECK(sqlite3_finalize(select_stmt));
  return updated;
}

Transaction NunchukWalletDb::CreatePsbt(
    const std::string& psbt, Amount fee, const std::string& memo,
    int change_pos, const std::map<std::string, Amount>& outputs,
    Amount fee_rate, bool subtract_fee_from_amount,
    const std::string& replace_tx) {
  PartiallySignedTransaction psbtx = DecodePsbt(psbt);
  std::string tx_id = psbtx.tx.value().GetHash().GetHex();

  json extra{};
  extra["outputs"] = outputs;
  extra["fee_rate"] = fee_rate;
  extra["subtract"] = subtract_fee_from_amount;
  if (!replace_tx.empty()) {
    extra["replace_txid"] = replace_tx;
  }

  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO "
      "VTX(ID, VALUE, HEIGHT, FEE, MEMO, CHANGEPOS, BLOCKTIME, EXTRA)"
      "VALUES (?1, ?2, -1, ?3, ?4, ?5, ?6, ?7)"
      "ON CONFLICT(ID) DO UPDATE SET VALUE=excluded.VALUE, "
      "HEIGHT=excluded.HEIGHT;";
  std::string extra_str = extra.dump();
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_bind_text(stmt, 2, psbt.c_str(), psbt.size(), NULL);
  sqlite3_bind_int64(stmt, 3, fee);
  sqlite3_bind_text(stmt, 4, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_int(stmt, 5, change_pos);
  sqlite3_bind_int64(stmt, 6, 0);
  sqlite3_bind_text(stmt, 7, extra_str.c_str(), extra_str.size(), NULL);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
  return GetTransaction(tx_id);
}

bool NunchukWalletDb::UpdatePsbt(const std::string& psbt) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE VTX SET VALUE = ?1 WHERE ID = ?2 AND HEIGHT = -1;";
  PartiallySignedTransaction psbtx = DecodePsbt(psbt);
  std::string tx_id = psbtx.tx.value().GetHash().GetHex();
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, psbt.c_str(), psbt.size(), NULL);
  sqlite3_bind_text(stmt, 2, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) GetTransaction(tx_id);
  return updated;
}

bool NunchukWalletDb::UpdatePsbtTxId(const std::string& old_id,
                                     const std::string& new_id) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM VTX WHERE ID = ? AND HEIGHT = -1;;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, old_id.c_str(), old_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    std::string value = std::string((char*)sqlite3_column_text(stmt, 1));
    int64_t fee = sqlite3_column_int64(stmt, 3);
    std::string memo = std::string((char*)sqlite3_column_text(stmt, 4));
    int change_pos = sqlite3_column_int(stmt, 5);
    std::string extra;
    if (sqlite3_column_text(stmt, 7)) {
      extra = std::string((char*)sqlite3_column_text(stmt, 7));
    }
    SQLCHECK(sqlite3_finalize(stmt));

    sqlite3_stmt* insert_stmt;
    std::string insert_sql =
        "INSERT INTO "
        "VTX(ID, VALUE, HEIGHT, FEE, MEMO, CHANGEPOS, BLOCKTIME, EXTRA)"
        "VALUES (?1, ?2, -1, ?3, ?4, ?5, ?6, ?7);";
    sqlite3_prepare_v2(db_, insert_sql.c_str(), -1, &insert_stmt, NULL);
    sqlite3_bind_text(insert_stmt, 1, new_id.c_str(), new_id.size(), NULL);
    sqlite3_bind_text(insert_stmt, 2, value.c_str(), value.size(), NULL);
    sqlite3_bind_int64(insert_stmt, 3, fee);
    sqlite3_bind_text(insert_stmt, 4, memo.c_str(), memo.size(), NULL);
    sqlite3_bind_int(insert_stmt, 5, change_pos);
    sqlite3_bind_int64(insert_stmt, 6, 0);
    sqlite3_bind_text(insert_stmt, 7, extra.c_str(), extra.size(), NULL);
    sqlite3_step(insert_stmt);
    SQLCHECK(sqlite3_finalize(insert_stmt));
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::TX_NOT_FOUND, "Old tx not found!");
  }
  return DeleteTransaction(old_id);
}

std::string NunchukWalletDb::GetPsbt(const std::string& tx_id) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT VALUE FROM VTX WHERE ID = ? AND HEIGHT = -1;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    std::string rs = std::string((char*)sqlite3_column_text(stmt, 0));
    SQLCHECK(sqlite3_finalize(stmt));
    return rs;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    return "";
  }
}

std::pair<std::string, bool> NunchukWalletDb::GetPsbtOrRawTx(
    const std::string& tx_id) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT VALUE FROM VTX WHERE ID = ? AND HEIGHT = -1;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    std::string rs = std::string((char*)sqlite3_column_text(stmt, 0));
    SQLCHECK(sqlite3_finalize(stmt));
    auto [tx, is_hex_tx] = GetTransactionFromStr(rs, {}, 0, -1);
    return {rs, is_hex_tx};
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    return {"", false};
  }
}

Transaction NunchukWalletDb::GetTransaction(const std::string& tx_id) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM VTX WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    std::string value = std::string((char*)sqlite3_column_text(stmt, 1));
    int height = sqlite3_column_int(stmt, 2);
    int64_t fee = sqlite3_column_int64(stmt, 3);
    std::string memo = std::string((char*)sqlite3_column_text(stmt, 4));
    int change_pos = sqlite3_column_int(stmt, 5);
    time_t blocktime = sqlite3_column_int64(stmt, 6);

    json immutable_data = json::parse(GetString(DbKeys::IMMUTABLE_DATA));
    int m = immutable_data["m"];

    auto signers = GetSigners();
    auto [tx, is_hex_tx] = GetTransactionFromStr(value, signers, m, height);
    tx.set_txid(tx_id);
    tx.set_m(m);
    tx.set_fee(Amount(fee));
    tx.set_fee_rate(0);
    tx.set_memo(memo);
    tx.set_change_index(change_pos);
    tx.set_blocktime(blocktime);
    tx.set_schedule_time(-1);
    // Default value, will set in FillSendReceiveData
    // TODO: Replace this asap. This code is fragile and potentially dangerous,
    // since it relies on external assumptions (flow of outside code) that might
    // become false
    tx.set_receive(false);
    tx.set_sub_amount(0);
    if (is_hex_tx) {
      tx.set_raw(value);
    } else {
      tx.set_psbt(value);
    }

    if (sqlite3_column_text(stmt, 7)) {
      std::string extra = std::string((char*)sqlite3_column_text(stmt, 7));
      FillExtra(extra, tx);
    }
    SQLCHECK(sqlite3_finalize(stmt));
    for (auto&& output : tx.get_outputs()) UseAddress(output.first);
    return tx;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
  }
}

bool NunchukWalletDb::DeleteTransaction(const std::string& tx_id) {
  sqlite3_stmt* stmt;
  std::string sql = "DELETE FROM VTX WHERE ID = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::SetUtxos(const std::string& address,
                               const std::string& utxo) {
  auto all = GetAllAddressData();
  if (!all.count(address)) return false;
  SetAddress(address, all[address].index, all[address].internal, utxo);
  return true;
}

Amount NunchukWalletDb::GetBalance(bool include_mempool) const {
  auto coins = GetCoins();
  Amount balance = 0;
  for (auto&& coin : coins) {
    if (coin.get_status() == CoinStatus::SPENT ||
        coin.get_status() == CoinStatus::OUTGOING_PENDING_CONFIRMATION)
      continue;
    if (!include_mempool && !coin.is_change() &&
        coin.get_status() == CoinStatus::INCOMING_PENDING_CONFIRMATION)
      continue;
    balance += coin.get_amount();
  }
  return balance;
}

std::vector<Transaction> NunchukWalletDb::GetTransactions(int count,
                                                          int skip) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM VTX;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  std::vector<Transaction> rs;
  while (sqlite3_column_text(stmt, 0)) {
    std::string tx_id = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string value = std::string((char*)sqlite3_column_text(stmt, 1));
    int height = sqlite3_column_int(stmt, 2);
    int64_t fee = sqlite3_column_int64(stmt, 3);
    std::string memo = std::string((char*)sqlite3_column_text(stmt, 4));
    int change_pos = sqlite3_column_int(stmt, 5);
    time_t blocktime = sqlite3_column_int64(stmt, 6);

    json immutable_data = json::parse(GetString(DbKeys::IMMUTABLE_DATA));
    int m = immutable_data["m"];

    auto signers = GetSigners();
    auto [tx, is_hex_tx] = GetTransactionFromStr(value, signers, m, height);
    tx.set_txid(tx_id);
    tx.set_m(m);
    tx.set_fee(Amount(fee));
    tx.set_fee_rate(0);
    tx.set_memo(memo);
    tx.set_change_index(change_pos);
    tx.set_blocktime(blocktime);
    tx.set_schedule_time(-1);
    tx.set_receive(false);
    tx.set_sub_amount(0);
    if (is_hex_tx) {
      tx.set_raw(value);
    } else {
      tx.set_psbt(value);
    }

    if (sqlite3_column_text(stmt, 7)) {
      std::string extra = std::string((char*)sqlite3_column_text(stmt, 7));
      FillExtra(extra, tx);
    }
    rs.push_back(tx);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

std::string NunchukWalletDb::FillPsbt(const std::string& base64_psbt) {
  auto psbt = DecodePsbt(base64_psbt);
  if (!psbt.tx.has_value()) return base64_psbt;

  auto wallet = GetWallet(true);
  auto desc = GetDescriptorsImportString(wallet);
  auto provider = SigningProviderCache::getInstance().GetProvider(desc);

  int nin = psbt.tx.value().vin.size();
  for (int i = 0; i < nin; i++) {
    std::string tx_id = psbt.tx.value().vin[i].prevout.hash.GetHex();
    sqlite3_stmt* stmt;
    std::string sql = "SELECT VALUE FROM VTX WHERE ID = ? AND HEIGHT > -1;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
    sqlite3_step(stmt);
    if (sqlite3_column_text(stmt, 0)) {
      std::string raw_tx = std::string((char*)sqlite3_column_text(stmt, 0));
      psbt.inputs[i].non_witness_utxo =
          MakeTransactionRef(DecodeRawTransaction(raw_tx));
      psbt.inputs[i].witness_utxo.SetNull();
    }
    SQLCHECK(sqlite3_finalize(stmt));
  }

  const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);
  for (int i = 0; i < nin; i++) {
    SignPSBTInput(provider, psbt, i, &txdata, 1);
  }

  // Update script/keypath information using descriptor data.
  for (unsigned int i = 0; i < psbt.tx.value().vout.size(); ++i) {
    UpdatePSBTOutput(provider, psbt, i);
  }

  for (auto&& signer : wallet.get_signers()) {
    std::vector<unsigned char> key;
    if (DecodeBase58Check(signer.get_xpub(), key, 78)) {
      auto value = ParseHex(signer.get_master_fingerprint());
      std::vector<uint32_t> keypath;
      std::string formalized = signer.get_derivation_path();
      std::replace(formalized.begin(), formalized.end(), 'h', '\'');
      if (ParseHDKeypath(formalized, keypath)) {
        for (uint32_t index : keypath) {
          value.push_back(index);
          value.push_back(index >> 8);
          value.push_back(index >> 16);
          value.push_back(index >> 24);
        }
      }
      key.insert(key.begin(), 1);
      psbt.unknown[key] = value;
    }
  }

  return EncodePsbt(psbt);
}

void NunchukWalletDb::FillExtra(const std::string& extra,
                                Transaction& tx) const {
  if (!extra.empty()) {
    json extra_json = json::parse(extra);
    if (extra_json["signers"] != nullptr &&
        (tx.get_height() >= 0 || !tx.get_raw().empty())) {
      for (auto&& signer : tx.get_signers()) {
        tx.set_signer(signer.first, extra_json["signers"][signer.first]);
      }
    }
    if (extra_json["outputs"] != nullptr) {
      for (auto&& output : tx.get_outputs()) {
        auto amount = extra_json["outputs"][output.first];
        if (amount != nullptr) {
          tx.add_user_output({output.first, Amount(amount)});
        }
      }
    }
    if (extra_json["fee_rate"] != nullptr) {
      tx.set_fee_rate(extra_json["fee_rate"]);
    }
    if (extra_json["subtract"] != nullptr) {
      tx.set_subtract_fee_from_amount(extra_json["subtract"]);
    }
    if (extra_json["replace_txid"] != nullptr) {
      tx.set_replace_txid(extra_json["replace_txid"]);
    }
    if (extra_json["schedule_time"] != nullptr) {
      tx.set_schedule_time(extra_json["schedule_time"]);
    }
    if (tx.get_status() == TransactionStatus::PENDING_CONFIRMATION &&
        extra_json["replaced_by_txid"] != nullptr) {
      tx.set_status(TransactionStatus::REPLACED);
      tx.set_replaced_by_txid(extra_json["replaced_by_txid"]);
    } else if (tx.get_status() == TransactionStatus::NETWORK_REJECTED &&
               extra_json["reject_msg"] != nullptr) {
      tx.set_reject_msg(extra_json["reject_msg"]);
    }
  }
}

// TODO (bakaoh): consider persisting these data
void NunchukWalletDb::FillSendReceiveData(Transaction& tx) {
  Amount total_amount = 0;
  bool is_send_tx = false;
  for (auto&& input : tx.get_inputs()) {
    TxOutput prev_out;
    try {
      prev_out = GetTransaction(input.first).get_outputs()[input.second];
    } catch (StorageException& se) {
      if (se.code() != StorageException::TX_NOT_FOUND) throw;
    }
    if (IsMyAddress(prev_out.first)) {
      total_amount += prev_out.second;
      is_send_tx = true;
    }
  }
  if (is_send_tx) {
    Amount send_amount{0};
    for (size_t i = 0; i < tx.get_outputs().size(); i++) {
      auto output = tx.get_outputs()[i];
      total_amount -= output.second;
      if (!IsMyAddress(output.first)) {
        send_amount += output.second;
      } else if (tx.get_change_index() < 0) {
        tx.set_change_index(i);
      }
    }
    tx.set_fee(total_amount);
    tx.set_receive(false);
    tx.set_sub_amount(send_amount);
    if (tx.get_fee_rate() == 0 && !tx.get_raw().empty()) {
      auto vsize = GetVirtualTransactionSize(
          CTransaction(DecodeRawTransaction(tx.get_raw())));
      tx.set_fee_rate(total_amount * 1000 / vsize);
    }
  } else {
    Amount receive_amount{0};
    for (auto&& output : tx.get_outputs()) {
      if (IsMyAddress(output.first)) {
        receive_amount += output.second;
        tx.add_receive_output(output);
      }
    }
    tx.set_receive(true);
    tx.set_sub_amount(receive_amount);
  }
}

void NunchukWalletDb::ForceRefresh() {
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM VTX;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM ADDRESS;", NULL, 0, NULL));
  addr_cache_.erase(db_file_name_);
}

void NunchukWalletDb::CreateCoinControlTable() {
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS TAGS("
                        "ID INTEGER PRIMARY KEY,"
                        "NAME            TEXT    NOT NULL UNIQUE,"
                        "COLOR           TEXT    NOT NULL);",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS COLLECTIONS("
                        "ID INTEGER PRIMARY KEY,"
                        "NAME            TEXT    NOT NULL UNIQUE,"
                        "SETTINGS        TEXT    NOT NULL);",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS COINTAGS("
                        "COIN            TEXT    NOT NULL,"
                        "TAGID           INT     NOT NULL,"
                        "PRIMARY KEY (COIN, TAGID));",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS COINCOLLECTIONS("
                        "COIN            TEXT    NOT NULL,"
                        "COLLECTIONID    INT     NOT NULL,"
                        "PRIMARY KEY (COIN, COLLECTIONID));",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS COININFO("
                        "COIN TEXT PRIMARY KEY   NOT NULL,"
                        "MEMO            TEXT    NOT NULL,"
                        "LOCKED          INT     NOT NULL);",
                        NULL, 0, NULL));
}

std::string NunchukWalletDb::CoinId(const std::string& tx_id, int vout) const {
  return strprintf("%s:%d", tx_id, vout);
}

bool NunchukWalletDb::UpdateCoinMemo(const std::string& tx_id, int vout,
                                     const std::string& memo) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO COININFO(COIN, MEMO, LOCKED) VALUES (?1, ?2, ?3) "
      "ON CONFLICT(COIN) DO UPDATE SET MEMO=excluded.MEMO;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_text(stmt, 2, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_int(stmt, 3, 0);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::LockCoin(const std::string& tx_id, int vout) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO COININFO(COIN, MEMO, LOCKED) VALUES (?1, ?2, ?3) "
      "ON CONFLICT(COIN) DO UPDATE SET LOCKED=excluded.LOCKED;";
  std::string coin = CoinId(tx_id, vout);
  std::string memo = "";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_text(stmt, 2, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_int(stmt, 3, 1);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::UnlockCoin(const std::string& tx_id, int vout) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO COININFO(COIN, MEMO, LOCKED) VALUES (?1, ?2, ?3) "
      "ON CONFLICT(COIN) DO UPDATE SET LOCKED=excluded.LOCKED;";
  std::string coin = CoinId(tx_id, vout);
  std::string memo = "";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_text(stmt, 2, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_int(stmt, 3, 0);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::IsLock(const std::string& tx_id, int vout) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM COININFO WHERE COIN = ?1;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_step(stmt);

  bool rs = false;
  while (sqlite3_column_text(stmt, 0)) {
    rs = sqlite3_column_int(stmt, 2) == 1;
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

int NunchukWalletDb::CreateCoinTag(const std::string& name,
                                   const std::string& color) {
  sqlite3_exec(db_, "BEGIN TRANSACTION;", NULL, NULL, NULL);
  sqlite3_stmt* stmt;
  std::string sql = "INSERT INTO TAGS(NAME, COLOR) VALUES (?1, ?2);";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, name.c_str(), name.size(), NULL);
  sqlite3_bind_text(stmt, 2, color.c_str(), color.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_changes(db_) != 1) {
    throw StorageException(StorageException::TAG_EXISTS, "Tag exists");
  }

  sql = "SELECT last_insert_rowid()";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  int id = -1;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    id = sqlite3_column_int(stmt, 0);
  }

  sqlite3_exec(db_, "COMMIT;", NULL, NULL, NULL);
  SQLCHECK(sqlite3_finalize(stmt));
  return id;
}

std::vector<CoinTag> NunchukWalletDb::GetCoinTags() {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM TAGS;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  std::vector<CoinTag> rs;
  while (sqlite3_column_text(stmt, 0)) {
    int id = sqlite3_column_int(stmt, 0);
    std::string name = std::string((char*)sqlite3_column_text(stmt, 1));
    std::string color = std::string((char*)sqlite3_column_text(stmt, 2));
    rs.push_back({id, name, color});
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

bool NunchukWalletDb::UpdateCoinTag(const CoinTag& tag) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE TAGS SET NAME = ?1, COLOR = ?2 WHERE ID = ?3;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  std::string name = tag.get_name();
  std::string color = tag.get_color();
  sqlite3_bind_text(stmt, 1, name.c_str(), name.size(), NULL);
  sqlite3_bind_text(stmt, 2, color.c_str(), color.size(), NULL);
  sqlite3_bind_int64(stmt, 3, tag.get_id());
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::DeleteCoinTag(int tag_id) {
  sqlite3_stmt* stmt;
  std::string sql = "DELETE FROM TAGS WHERE ID = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, tag_id);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));

  sql = "DELETE FROM COINTAGS WHERE TAGID = ?1;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, tag_id);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::AddToCoinTag(int tag_id, const std::string& tx_id,
                                   int vout) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT OR IGNORE INTO COINTAGS(COIN, TAGID) VALUES (?1, ?2);";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_int64(stmt, 2, tag_id);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::RemoveFromCoinTag(int tag_id, const std::string& tx_id,
                                        int vout) {
  sqlite3_stmt* stmt;
  std::string sql = "DELETE FROM COINTAGS WHERE COIN = ?1 AND TAGID = ?2;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_int64(stmt, 2, tag_id);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

std::vector<std::string> NunchukWalletDb::GetCoinByTag(int tag_id) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT COIN FROM COINTAGS WHERE TAGID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, tag_id);
  sqlite3_step(stmt);

  std::vector<std::string> rs;
  while (sqlite3_column_text(stmt, 0)) {
    std::string coin = std::string((char*)sqlite3_column_text(stmt, 0));
    rs.push_back(coin);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

std::vector<int> NunchukWalletDb::GetAddedTags(const std::string& tx_id,
                                               int vout) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT TAGID FROM COINTAGS WHERE COIN = ?;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_step(stmt);

  std::vector<int> rs;
  while (sqlite3_column_text(stmt, 0)) {
    int id = sqlite3_column_int(stmt, 0);
    rs.push_back(id);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

int NunchukWalletDb::CreateCoinCollection(const std::string& name) {
  json default_settings = {{"add_new_coin", false}, {"auto_lock", false}};
  std::string settings = default_settings.dump();

  sqlite3_exec(db_, "BEGIN TRANSACTION;", NULL, NULL, NULL);
  sqlite3_stmt* stmt;
  std::string sql = "INSERT INTO COLLECTIONS(NAME, SETTINGS) VALUES (?1, ?2);";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, name.c_str(), name.size(), NULL);
  sqlite3_bind_text(stmt, 2, settings.c_str(), settings.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_changes(db_) != 1) {
    throw StorageException(StorageException::COLLECTION_EXISTS,
                           "Collection exists");
  }

  sql = "SELECT last_insert_rowid()";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  int id = -1;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    id = sqlite3_column_int(stmt, 0);
  }

  sqlite3_exec(db_, "COMMIT;", NULL, NULL, NULL);
  SQLCHECK(sqlite3_finalize(stmt));
  return id;
}

std::vector<CoinCollection> NunchukWalletDb::GetCoinCollections() {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM COLLECTIONS;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  std::vector<CoinCollection> rs;
  while (sqlite3_column_text(stmt, 0)) {
    int id = sqlite3_column_int(stmt, 0);
    std::string name = std::string((char*)sqlite3_column_text(stmt, 1));
    std::string settings = std::string((char*)sqlite3_column_text(stmt, 2));
    CoinCollection collection{id, name};
    json parsed_settings = json::parse(settings);
    collection.set_add_new_coin(parsed_settings["add_new_coin"]);
    collection.set_auto_lock(parsed_settings["auto_lock"]);
    rs.push_back(collection);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

bool NunchukWalletDb::UpdateCoinCollection(const CoinCollection& collection) {
  sqlite3_stmt* stmt;
  std::string sql =
      "UPDATE COLLECTIONS SET NAME = ?1, SETTINGS = ?2 WHERE ID = ?3;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  std::string name = collection.get_name();
  json new_settings = {{"add_new_coin", collection.is_add_new_coin()},
                       {"auto_lock", collection.is_auto_lock()}};
  std::string settings = new_settings.dump();
  sqlite3_bind_text(stmt, 1, name.c_str(), name.size(), NULL);
  sqlite3_bind_text(stmt, 2, settings.c_str(), settings.size(), NULL);
  sqlite3_bind_int64(stmt, 3, collection.get_id());
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::DeleteCoinCollection(int collection_id) {
  sqlite3_stmt* stmt;
  std::string sql = "DELETE FROM COLLECTIONS WHERE ID = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, collection_id);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));

  sql = "DELETE FROM COINCOLLECTIONS WHERE COLLECTIONID = ?1;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, collection_id);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::AddToCoinCollection(int collection_id,
                                          const std::string& tx_id, int vout) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT OR IGNORE INTO COINCOLLECTIONS(COIN, COLLECTIONID) "
      "VALUES (?1, ?2);";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_int64(stmt, 2, collection_id);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::RemoveFromCoinCollection(int collection_id,
                                               const std::string& tx_id,
                                               int vout) {
  sqlite3_stmt* stmt;
  std::string sql =
      "DELETE FROM COINCOLLECTIONS WHERE COIN = ?1 AND COLLECTIONID = ?2;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_int64(stmt, 2, collection_id);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

std::vector<std::string> NunchukWalletDb::GetCoinInCollection(
    int collection_id) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT COIN FROM COINCOLLECTIONS WHERE COLLECTIONID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, collection_id);
  sqlite3_step(stmt);

  std::vector<std::string> rs;
  while (sqlite3_column_text(stmt, 0)) {
    std::string coin = std::string((char*)sqlite3_column_text(stmt, 0));
    rs.push_back(coin);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

std::vector<int> NunchukWalletDb::GetAddedCollections(const std::string& tx_id,
                                                      int vout) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT COLLECTIONID FROM COINCOLLECTIONS WHERE COIN = ?;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_step(stmt);

  std::vector<int> rs;
  while (sqlite3_column_text(stmt, 0)) {
    int id = sqlite3_column_int(stmt, 0);
    rs.push_back(id);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

std::string NunchukWalletDb::ExportCoinControlData() {
  json data;
  data["export_ts"] = std::time(0);
  // export tags
  data["tags"] = json::array();
  auto tags = GetCoinTags();
  for (auto&& i : tags) {
    json tag = {
        {"id", i.get_id()}, {"name", i.get_name()}, {"color", i.get_color()}};
    tag["coins"] = json::array();
    auto coins = GetCoinByTag(i.get_id());
    for (auto&& coin : coins) {
      tag["coins"].push_back(coin);
    }
    data["tags"].push_back(tag);
  }
  // export collections
  data["collections"] = json::array();
  auto collections = GetCoinCollections();
  for (auto&& i : collections) {
    json collection = {{"id", i.get_id()},
                       {"name", i.get_name()},
                       {"add_new_coin", i.is_add_new_coin()},
                       {"auto_lock", i.is_auto_lock()}};
    collection["coins"] = json::array();
    auto coins = GetCoinInCollection(i.get_id());
    for (auto&& coin : coins) {
      collection["coins"].push_back(coin);
    }
    data["collections"].push_back(collection);
  }
  // export coininfo
  data["coininfo"] = json::array();
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM COININFO;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  while (sqlite3_column_text(stmt, 0)) {
    std::string coin = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string memo = std::string((char*)sqlite3_column_text(stmt, 1));
    int locked = sqlite3_column_int(stmt, 2);
    data["coininfo"].push_back(
        {{"coin", coin}, {"memo", memo}, {"locked", locked}});
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));

  return data.dump();
}

void NunchukWalletDb::ClearCoinControlData() {
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM TAGS;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM COINTAGS;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM COLLECTIONS;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM COINCOLLECTIONS;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM COININFO;", NULL, 0, NULL));
}

void NunchukWalletDb::ImportCoinControlData(const std::string& dataStr) {
  json data = json::parse(dataStr);
  ClearCoinControlData();
  // import tags
  json tags = data["tags"];
  for (auto&& tag : tags) {
    int id = tag["id"];
    std::string name = tag["name"];
    std::string color = tag["color"];

    sqlite3_stmt* stmt;
    std::string sql =
        "INSERT INTO TAGS(ID, NAME, COLOR) VALUES (?1, ?2, ?3) "
        "ON CONFLICT(ID) DO UPDATE SET NAME=excluded.NAME, "
        "COLOR=excluded.COLOR;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, id);
    sqlite3_bind_text(stmt, 2, name.c_str(), name.size(), NULL);
    sqlite3_bind_text(stmt, 3, color.c_str(), color.size(), NULL);
    sqlite3_step(stmt);
    SQLCHECK(sqlite3_finalize(stmt));

    for (auto&& i : tag["coins"]) {
      sqlite3_stmt* stmt;
      std::string sql = "INSERT INTO COINTAGS(COIN, TAGID) VALUES (?1, ?2);";
      std::string coin = i.get<std::string>();
      sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
      sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
      sqlite3_bind_int64(stmt, 2, id);
      sqlite3_step(stmt);
      SQLCHECK(sqlite3_finalize(stmt));
    }
  }

  // import collections
  json collections = data["collections"];
  for (auto&& collection : collections) {
    int id = collection["id"];
    std::string name = collection["name"];

    sqlite3_stmt* stmt;
    std::string sql =
        "INSERT INTO COLLECTIONS(ID, NAME, SETTINGS) VALUES (?1, ?2, ?3) "
        "ON CONFLICT(ID) DO UPDATE SET NAME=excluded.NAME, "
        "SETTINGS=excluded.SETTINGS;";
    json collection_settings = {
        {"add_new_coin", collection["add_new_coin"].get<bool>()},
        {"auto_lock", collection["auto_lock"].get<bool>()}};
    std::string settings = collection_settings.dump();
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, id);
    sqlite3_bind_text(stmt, 2, name.c_str(), name.size(), NULL);
    sqlite3_bind_text(stmt, 3, settings.c_str(), settings.size(), NULL);
    sqlite3_step(stmt);
    SQLCHECK(sqlite3_finalize(stmt));

    for (auto&& i : collection["coins"]) {
      sqlite3_stmt* stmt;
      std::string sql =
          "INSERT INTO COINCOLLECTIONS(COIN, COLLECTIONID) VALUES (?1, ?2);";
      std::string coin = i.get<std::string>();
      sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
      sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
      sqlite3_bind_int64(stmt, 2, id);
      sqlite3_step(stmt);
      SQLCHECK(sqlite3_finalize(stmt));
    }
  }
  // import coininfo
  json coininfo = data["coininfo"];
  for (auto&& i : coininfo) {
    std::string coin = i["coin"];
    std::string memo = i["memo"];
    int locked = i["locked"];
    sqlite3_stmt* stmt;
    std::string sql =
        "INSERT INTO COININFO(COIN, MEMO, LOCKED) VALUES (?1, ?2, ?3) "
        "ON CONFLICT(COIN) DO UPDATE SET LOCKED=excluded.LOCKED, "
        "MEMO=excluded.MEMO;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
    sqlite3_bind_text(stmt, 2, memo.c_str(), memo.size(), NULL);
    sqlite3_bind_int(stmt, 3, locked);
    sqlite3_step(stmt);
    SQLCHECK(sqlite3_finalize(stmt));
  }
}

std::map<std::string, UnspentOutput> NunchukWalletDb::GetCoinsFromTransactions(
    const std::vector<Transaction>& transactions) const {
  std::map<std::string, Transaction> tx_map;
  std::map<std::string, std::string> used_by;
  for (auto&& tx : transactions) {
    tx_map.insert(std::make_pair(tx.get_txid(), tx));
    if (tx.get_height() <= 0) continue;
    for (auto&& input : tx.get_inputs()) {
      used_by[CoinId(input.first, input.second)] = tx.get_txid();
    }
  }

  std::map<std::string, UnspentOutput> coins;
  auto set_status = [&](const std::string& id, const CoinStatus& status) {
    if (coins[id].get_status() < status) coins[id].set_status(status);
  };

  for (auto&& tx : transactions) {
    if (tx.get_status() == TransactionStatus::REPLACED ||
        tx.get_status() == TransactionStatus::NETWORK_REJECTED)
      continue;

    bool invalid = false;
    for (auto&& input : tx.get_inputs()) {
      auto id = CoinId(input.first, input.second);
      if (used_by.count(id) && used_by[id] != tx.get_txid()) invalid = true;
    }
    if (invalid) continue;

    for (auto&& input : tx.get_inputs()) {
      if (tx_map.count(input.first) == 0) continue;
      auto prev_tx = tx_map[input.first];
      auto address = prev_tx.get_outputs()[input.second].first;
      if (!IsMyAddress(address)) continue;
      auto id = CoinId(input.first, input.second);
      coins[id].set_txid(input.first);
      coins[id].set_vout(input.second);
      coins[id].set_address(address);
      coins[id].set_amount(prev_tx.get_outputs()[input.second].second);
      coins[id].set_height(prev_tx.get_height());
      coins[id].set_blocktime(prev_tx.get_blocktime());
      coins[id].set_schedule_time(prev_tx.get_schedule_time());
      if (tx.get_status() == TransactionStatus::CONFIRMED) {
        set_status(id, CoinStatus::SPENT);
      } else if (tx.get_status() == TransactionStatus::PENDING_CONFIRMATION) {
        set_status(id, CoinStatus::OUTGOING_PENDING_CONFIRMATION);
      } else if (tx.get_status() == TransactionStatus::READY_TO_BROADCAST) {
        set_status(id, CoinStatus::OUTGOING_PENDING_BROADCAST);
      } else if (tx.get_status() == TransactionStatus::PENDING_SIGNATURES) {
        set_status(id, CoinStatus::OUTGOING_PENDING_SIGNATURES);
      }
      coins[id].set_memo(prev_tx.get_memo());
      coins[id].set_change(IsMyChange(address));
    }

    int nout = tx.get_outputs().size();
    for (int vout = 0; vout < nout; vout++) {
      auto output = tx.get_outputs()[vout];
      if (!IsMyAddress(output.first)) continue;
      auto id = CoinId(tx.get_txid(), vout);
      coins[id].set_txid(tx.get_txid());
      coins[id].set_vout(vout);
      coins[id].set_address(output.first);
      coins[id].set_amount(output.second);
      coins[id].set_height(tx.get_height());
      coins[id].set_blocktime(tx.get_blocktime());
      coins[id].set_schedule_time(tx.get_schedule_time());
      set_status(id, tx.get_height() > 0
                         ? CoinStatus::CONFIRMED
                         : CoinStatus::INCOMING_PENDING_CONFIRMATION);
      coins[id].set_memo(tx.get_memo());
      coins[id].set_change(IsMyChange(output.first));
    }
  }
  return coins;
}

std::vector<UnspentOutput> NunchukWalletDb::GetCoins() const {
  auto transactions = GetTransactions();
  auto coins = GetCoinsFromTransactions(transactions);
  std::vector<UnspentOutput> rs;
  for (auto&& coin : coins) {
    rs.push_back(coin.second);
  }
  return rs;
}

std::vector<std::vector<UnspentOutput>> NunchukWalletDb::GetAncestry(
    const std::string& tx_id, int vout) const {
  auto transactions = GetTransactions();
  auto coins = GetCoinsFromTransactions(transactions);
  std::map<std::string, Transaction> tx_map;
  for (auto&& tx : transactions) {
    tx_map.insert(std::make_pair(tx.get_txid(), tx));
  }

  std::vector<std::vector<UnspentOutput>> ancestry{};
  std::vector<UnspentOutput> parents{};
  parents.push_back(coins[CoinId(tx_id, vout)]);
  while (true) {
    std::vector<UnspentOutput> grandparents{};
    for (auto&& coin : parents) {
      if (tx_map.count(coin.get_txid()) == 0) continue;
      auto tx = tx_map[coin.get_txid()];
      for (auto&& input : tx.get_inputs()) {
        auto id = CoinId(input.first, input.second);
        if (coins.count(id)) grandparents.push_back(coins[id]);
      }
    }
    if (grandparents.empty()) {
      break;
    } else {
      ancestry.push_back(grandparents);
      parents = grandparents;
    }
  }

  return ancestry;
}

}  // namespace nunchuk
