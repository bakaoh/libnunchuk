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

#include <backend/electrum/synchronizer.h>
#include <algorithm>
#include <limits>
#include <numeric>
#include <utils/addressutils.hpp>
#include <utils/stringutils.hpp>
#include <utils/txutils.hpp>
#include <thread>

using namespace boost::asio;
using json = nlohmann::json;

namespace nunchuk {

static int RECONNECT_DELAY_SECOND = 3;
static long long SUBCRIBE_DELAY_MS = 50;

ElectrumSynchronizer::~ElectrumSynchronizer() {
  {
    std::lock_guard<std::mutex> guard(status_mutex_);
    status_ = Status::STOPPED;
    status_cv_.notify_all();
  }
  sync_worker_.reset();
  sync_thread_.join();
}

void ElectrumSynchronizer::WaitForReady() {
  std::unique_lock<std::mutex> lock_(status_mutex_);
  status_cv_.wait(lock_, [&]() {
    return status_ == Status::READY || status_ == Status::SYNCING;
  });
}

void ElectrumSynchronizer::Run() {
  {
    std::lock_guard<std::mutex> guard(status_mutex_);
    if (status_ == Status::STOPPED) return;
    status_ = Status::CONNECTING;
    status_cv_.notify_all();
  }
  // Clear cache
  chain_tip_ = 0;
  scripthash_to_wallet_address_.clear();

  io_service_.post([&]() {
    try {
      client_ = std::unique_ptr<ElectrumClient>(
          new ElectrumClient(app_settings_, [&]() {
            io_service_.post([&]() {
              std::this_thread::sleep_for(
                  std::chrono::seconds(RECONNECT_DELAY_SECOND));
              Run();
            });
          }));
    } catch (...) {
      std::lock_guard<std::mutex> guard(status_mutex_);
      status_ = Status::UNINITIALIZED;
      status_cv_.notify_all();
      return;
    }
    {
      std::lock_guard<std::mutex> guard(status_mutex_);
      if (status_ != Status::CONNECTING) return;
      status_ = Status::SYNCING;
      status_cv_.notify_all();
    }
    try {
      BlockchainSync(app_settings_.get_chain());
    } catch (...) {
      // TODO(Bakaoh): more elegant exeption handling
      // storage and CoreUtils chain-switch may cause exeption here
    }
    std::lock_guard<std::mutex> guard(status_mutex_);
    if (status_ != Status::SYNCING) return;
    status_ = Status::READY;
    status_cv_.notify_all();
  });
}

bool ElectrumSynchronizer::UpdateTransactions(Chain chain,
                                              const std::string& wallet_id,
                                              const json& history) {
  using TS = TransactionStatus;
  if (!history.is_array()) return false;
  bool isSynced = true;
  if (client_->support_batch_requests()) {
    std::vector<std::string> txs_hash{};
    std::vector<int> heights{};
    std::map<std::string, bool> founds;
    for (auto item : history) {
      std::string tx_id = item["tx_hash"];
      int height = item["height"];
      try {
        auto stx = storage_->GetTransaction(chain, wallet_id, tx_id);
        founds[tx_id] = true;
        if (stx.get_status() == TS::CONFIRMED) continue;
      } catch (StorageException& se) {
        if (se.code() != StorageException::TX_NOT_FOUND) continue;
        founds[tx_id] = false;
      }
      txs_hash.push_back(tx_id);
      if (height > 0) heights.push_back(height);
    }
    auto rawtx = client_->get_multi_rawtx(txs_hash);
    auto rawheader = client_->get_multi_rawheader(heights);
    for (auto item : history) {
      std::string tx_id = item["tx_hash"];
      int height = item["height"];
      std::string raw;
      if (std::find(txs_hash.begin(), txs_hash.end(), tx_id) ==
          txs_hash.end()) {
        continue;
      } else if (rawtx.count(tx_id) == 0) {
        try {
          raw = client_->blockchain_transaction_get(tx_id);
        } catch (...) {
          isSynced = false;
          continue;
        }
      } else {
        raw = rawtx[tx_id];
      }
      time_t time = height <= 0 ? 0 : GetBlockTime(rawheader[height]);
      Amount fee = item["fee"] == nullptr ? 0 : Amount(item["fee"]);
      auto status = height <= 0 ? TS::PENDING_CONFIRMATION : TS::CONFIRMED;
      if (height <= 0) height = 0;
      if (founds[tx_id]) {
        storage_->UpdateTransaction(chain, wallet_id, raw, height, time);
      } else {
        storage_->InsertTransaction(chain, wallet_id, raw, height, time, fee);
      }
      if (status_ == Status::READY) {
        transaction_listener_(tx_id, status, wallet_id);
      }
    }

    auto pending_receive_txs = storage_->GetTransactions(
        chain, wallet_id, TS::PENDING_CONFIRMATION, true);
    for (auto&& tx : pending_receive_txs) {
      auto txid = tx.get_txid();
      if (!rawtx.count(txid)) {
        storage_->DeleteTransaction(chain, wallet_id, txid);
        transaction_listener_(txid, TS::REPLACED, wallet_id);
      }
    }
    return isSynced;
  }

  std::vector<std::string> txs_hash;
  for (auto item : history) {
    std::string tx_id = item["tx_hash"];
    int height = item["height"];
    bool found = false;
    try {
      auto stx = storage_->GetTransaction(chain, wallet_id, tx_id);
      found = true;
      if (stx.get_status() == TS::CONFIRMED) continue;
    } catch (StorageException& se) {
      if (se.code() != StorageException::TX_NOT_FOUND) continue;
    }
    txs_hash.push_back(tx_id);
    std::string raw = client_->blockchain_transaction_get(tx_id);
    time_t time = height <= 0
                      ? 0
                      : GetBlockTime(client_->blockchain_block_header(height));
    Amount fee = item["fee"] == nullptr ? 0 : Amount(item["fee"]);
    auto status = height <= 0 ? TS::PENDING_CONFIRMATION : TS::CONFIRMED;
    if (height <= 0) height = 0;
    if (found) {
      storage_->UpdateTransaction(chain, wallet_id, raw, height, time);
    } else {
      storage_->InsertTransaction(chain, wallet_id, raw, height, time, fee);
    }
    if (status_ == Status::READY) {
      transaction_listener_(tx_id, status, wallet_id);
    }
  }
  std::sort(txs_hash.begin(), txs_hash.end());
  auto pending_receive_txs = storage_->GetTransactions(
      chain, wallet_id, TS::PENDING_CONFIRMATION, true);
  for (auto&& tx : pending_receive_txs) {
    auto txid = tx.get_txid();
    if (!std::binary_search(txs_hash.begin(), txs_hash.end(), txid)) {
      storage_->DeleteTransaction(chain, wallet_id, txid);
      transaction_listener_(txid, TS::REPLACED, wallet_id);
    }
  }
  return isSynced;
}

bool ElectrumSynchronizer::UpdateTransactions(
    Chain chain, const std::string& wallet_id, const json& history,
    const std::map<std::string, std::string>& rawtx,
    const std::map<int, std::string>& rawheader) {
  using TS = TransactionStatus;
  if (!history.is_array()) return false;
  bool isSynced = true;
  if (client_->support_batch_requests()) {
    std::vector<std::string> txs_hash{};
    std::map<std::string, bool> founds;
    for (auto item : history) {
      std::string tx_id = item["tx_hash"];
      try {
        auto stx = storage_->GetTransaction(chain, wallet_id, tx_id);
        founds[tx_id] = true;
        if (stx.get_status() == TS::CONFIRMED) continue;
      } catch (StorageException& se) {
        if (se.code() != StorageException::TX_NOT_FOUND) continue;
        founds[tx_id] = false;
      }
      txs_hash.push_back(tx_id);
    }
    for (auto item : history) {
      std::string tx_id = item["tx_hash"];
      int height = item["height"];
      std::string raw;
      if (std::find(txs_hash.begin(), txs_hash.end(), tx_id) ==
          txs_hash.end()) {
        continue;
      } else if (rawtx.count(tx_id) == 0) {
        try {
          raw = client_->blockchain_transaction_get(tx_id);
        } catch (...) {
          isSynced = false;
          continue;
        }
      } else {
        raw = rawtx.find(tx_id)->second;
      }
      time_t time =
          height <= 0 ? 0 : GetBlockTime(rawheader.find(height)->second);
      Amount fee = item["fee"] == nullptr ? 0 : Amount(item["fee"]);
      auto status = height <= 0 ? TS::PENDING_CONFIRMATION : TS::CONFIRMED;
      if (height <= 0) height = 0;
      if (founds[tx_id]) {
        storage_->UpdateTransaction(chain, wallet_id, raw, height, time);
      } else {
        storage_->InsertTransaction(chain, wallet_id, raw, height, time, fee);
      }
      if (status_ == Status::READY) {
        transaction_listener_(tx_id, status, wallet_id);
      }
    }
    auto pending_receive_txs = storage_->GetTransactions(
        chain, wallet_id, TS::PENDING_CONFIRMATION, true);
    for (auto&& tx : pending_receive_txs) {
      auto txid = tx.get_txid();
      if (!rawtx.count(txid)) {
        storage_->DeleteTransaction(chain, wallet_id, txid);
        transaction_listener_(txid, TS::REPLACED, wallet_id);
      }
    }
    return isSynced;
  }
  return UpdateTransactions(chain, wallet_id, history);
}

void ElectrumSynchronizer::OnScripthashStatusChange(Chain chain,
                                                    const json& notification) {
  UpdateScripthashStatus(chain, notification[0], notification[1]);
}

std::pair<std::string, std::string> ElectrumSynchronizer::SubscribeAddress(
    const std::string& wallet_id, const std::string& address) {
  std::string scripthash = AddressToScriptHash(address);
  scripthash_to_wallet_address_[scripthash] = {wallet_id, address};
  auto subscribe = client_->blockchain_scripthash_subscribe(scripthash);
  auto status = subscribe == nullptr ? "" : subscribe.get<std::string>();
  return {scripthash, status};
}

std::map<std::string, std::string> ElectrumSynchronizer::SubscribeAddresses(
    const std::string& wallet_id, const std::vector<std::string>& addresses) {
  std::vector<std::string> scripthashes{};
  for (auto&& address : addresses) {
    std::string scripthash = AddressToScriptHash(address);
    scripthash_to_wallet_address_[scripthash] = {wallet_id, address};
    scripthashes.push_back(scripthash);
  }
  return client_->subscribe_multi_scripthash(scripthashes);
}

void ElectrumSynchronizer::BlockchainSync(Chain chain) {
  connection_listener_(ConnectionStatus::OFFLINE, 0);
  {
    std::unique_lock<std::mutex> lock_(status_mutex_);
    if (status_ != Status::READY && status_ != Status::SYNCING) return;
    auto header = client_->blockchain_headers_subscribe([&](json rs) {
      chain_tip_ = rs[0]["height"];
      storage_->SetChainTip(app_settings_.get_chain(), chain_tip_);
      block_listener_(rs[0]["height"], rs[0]["hex"]);
    });
    connection_listener_(ConnectionStatus::SYNCING, 0);
    chain_tip_ = header["height"];
    storage_->SetChainTip(chain, header["height"]);
    block_listener_(header["height"], header["hex"]);
    client_->scripthash_add_listener([&](json notification) {
      OnScripthashStatusChange(app_settings_.get_chain(), notification);
    });
  }
  auto wallet_ids = storage_->ListRecentlyUsedWallets(chain);
  int process = 0;
  for (auto&& wallet_id : wallet_ids) {
    auto addresses = storage_->GetAllAddresses(chain, wallet_id);
    if (client_->support_batch_requests()) {
      auto multisub = SubscribeAddresses(wallet_id, addresses);
      std::vector<std::string> scripthashes;
      std::vector<std::string> status;
      for (auto& sub : multisub) {
        std::unique_lock<std::mutex> lock_(status_mutex_);
        if (status_ != Status::READY && status_ != Status::SYNCING) return;
        auto address = scripthash_to_wallet_address_[sub.first].second;
        auto prev_status =
            storage_->GetAddressStatus(chain, wallet_id, address);
        if (sub.second.empty() && prev_status.empty()) continue;
        if (sub.second != prev_status && !sub.second.empty()) {
          scripthashes.push_back(sub.first);
          status.push_back(sub.second);
        }
      }
      UpdateScripthashesStatus(chain, scripthashes, status);
    } else {
      for (auto a = addresses.rbegin(); a != addresses.rend(); ++a) {
        std::unique_lock<std::mutex> lock_(status_mutex_);
        if (status_ != Status::READY && status_ != Status::SYNCING) return;
        auto address = *a;
        auto sub = SubscribeAddress(wallet_id, address);
        auto prev_status =
            storage_->GetAddressStatus(chain, wallet_id, address);
        if (sub.second != prev_status) {
          UpdateScripthashStatus(chain, sub.first, sub.second, false);
        }
        std::this_thread::sleep_for(
            std::chrono::milliseconds(SUBCRIBE_DELAY_MS));
      }
    }
    Amount balance = storage_->GetBalance(chain, wallet_id);
    balance_listener_(wallet_id, balance);
    Amount unconfirmed_balance =
        storage_->GetUnconfirmedBalance(chain, wallet_id);
    balances_listener_(wallet_id, balance, unconfirmed_balance);
    connection_listener_(ConnectionStatus::SYNCING,
                         ++process * 100 / wallet_ids.size());
  }
  connection_listener_(ConnectionStatus::ONLINE, 100);
}

void ElectrumSynchronizer::Broadcast(const std::string& raw_tx) {
  std::unique_lock<std::mutex> lock_(status_mutex_);
  if (status_ != Status::READY && status_ != Status::SYNCING) {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Disconnected");
  }
  client_->blockchain_transaction_broadcast(raw_tx);
}

Amount ElectrumSynchronizer::EstimateFee(int conf_target) {
  std::unique_lock<std::mutex> lock_(status_mutex_);
  if (status_ != Status::READY && status_ != Status::SYNCING) {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Disconnected");
  }
  return Utils::AmountFromValue(
      client_->blockchain_estimatefee(conf_target).dump());
}

Amount ElectrumSynchronizer::RelayFee() {
  std::unique_lock<std::mutex> lock_(status_mutex_);
  if (status_ != Status::READY && status_ != Status::SYNCING) {
    return Amount(1000);
  }
  return Utils::AmountFromValue(client_->blockchain_relayfee().dump());
}

bool ElectrumSynchronizer::LookAhead(Chain chain, const std::string& wallet_id,
                                     const std::string& address, int index,
                                     bool internal) {
  std::unique_lock<std::mutex> lock_(status_mutex_);
  if (status_ != Status::READY && status_ != Status::SYNCING) return false;
  if (chain != app_settings_.get_chain()) return false;

  auto sub = SubscribeAddress(wallet_id, address);
  auto prev_status = storage_->GetAddressStatus(chain, wallet_id, address);
  if (sub.second.empty() && prev_status.empty()) return false;
  if (sub.second != prev_status) {
    storage_->AddAddress(chain, wallet_id, address, index, internal);
    UpdateScripthashStatus(chain, sub.first, sub.second);
  }
  return true;
}

bool ElectrumSynchronizer::SupportBatchLookAhead() {
  std::unique_lock<std::mutex> lock_(status_mutex_);
  if (status_ != Status::READY && status_ != Status::SYNCING) return false;
  return client_->support_batch_requests();
}

int ElectrumSynchronizer::BatchLookAhead(
    Chain chain, const std::string& wallet_id,
    const std::vector<std::string>& addresses, const std::vector<int>& indexes,
    bool internal) {
  std::unique_lock<std::mutex> lock_(status_mutex_);
  if (status_ != Status::READY && status_ != Status::SYNCING) return -1;
  if (chain != app_settings_.get_chain()) return -1;

  auto multisub = SubscribeAddresses(wallet_id, addresses);
  std::vector<std::string> scripthashes;
  std::vector<std::string> status;
  int lastUsedIdx = -1;
  for (auto& sub : multisub) {
    auto address = scripthash_to_wallet_address_[sub.first].second;
    auto it = std::find(addresses.begin(), addresses.end(), address);
    int i = it - addresses.begin();
    auto prev_status = storage_->GetAddressStatus(chain, wallet_id, address);
    if (sub.second.empty() && prev_status.empty()) continue;
    if (sub.second != prev_status) {
      storage_->AddAddress(chain, wallet_id, address, indexes[i], internal);
      if (!sub.second.empty()) {
        if (i > lastUsedIdx) lastUsedIdx = i;
        scripthashes.push_back(sub.first);
        status.push_back(sub.second);
      }
    }
  }

  UpdateScripthashesStatus(chain, scripthashes, status);
  Amount balance = storage_->GetBalance(chain, wallet_id);
  balance_listener_(wallet_id, balance);
  Amount unconfirmed_balance =
      storage_->GetUnconfirmedBalance(chain, wallet_id);
  balances_listener_(wallet_id, balance, unconfirmed_balance);
  return lastUsedIdx;
}

void ElectrumSynchronizer::UpdateScripthashStatus(Chain chain,
                                                  const std::string& scripthash,
                                                  const std::string& status,
                                                  bool check_balance) {
  if (status.empty()) return;
  if (scripthash_to_wallet_address_.count(scripthash) == 0) return;
  std::string wallet_id = scripthash_to_wallet_address_.at(scripthash).first;
  std::string address = scripthash_to_wallet_address_.at(scripthash).second;
  json history = client_->blockchain_scripthash_get_history(scripthash);
  if (UpdateTransactions(chain, wallet_id, history)) {
    json utxo;  // client_->blockchain_scripthash_listunspent(scripthash);
    std::string utxostatus = join(std::vector{utxo.dump(), status}, '|');
    storage_->SetUtxos(chain, wallet_id, address, utxostatus);
  }
  if (check_balance) {
    Amount balance = storage_->GetBalance(chain, wallet_id);
    balance_listener_(wallet_id, balance);
    Amount unconfirmed_balance =
        storage_->GetUnconfirmedBalance(chain, wallet_id);
    balances_listener_(wallet_id, balance, unconfirmed_balance);
  }
}

void ElectrumSynchronizer::UpdateScripthashesStatus(
    Chain chain, const std::vector<std::string>& scripthashes,
    const std::vector<std::string>& status) {
  if (scripthashes.empty()) return;
  auto multihistory = client_->get_multi_history(scripthashes);

  std::vector<std::string> txs_hash{};
  std::vector<int> heights{};
  std::map<std::string, bool> founds;
  for (auto [scripthash, history] : multihistory) {
    if (multihistory.count(scripthash) == 0) continue;
    std::string wallet_id = scripthash_to_wallet_address_.at(scripthash).first;
    for (auto item : history) {
      std::string tx_id = item["tx_hash"];
      int height = item["height"];
      try {
        auto stx = storage_->GetTransaction(chain, wallet_id, tx_id);
        if (stx.get_status() == TransactionStatus::CONFIRMED) continue;
      } catch (StorageException& se) {
        if (se.code() != StorageException::TX_NOT_FOUND) continue;
      }
      txs_hash.push_back(tx_id);
      if (height > 0) heights.push_back(height);
    }
  }
  auto rawtx = client_->get_multi_rawtx(txs_hash);
  auto rawheader = client_->get_multi_rawheader(heights);

  for (auto&& scripthash : scripthashes) {
    if (scripthash_to_wallet_address_.count(scripthash) == 0) continue;
    if (multihistory.count(scripthash) == 0) continue;
    std::string wallet_id = scripthash_to_wallet_address_.at(scripthash).first;
    std::string address = scripthash_to_wallet_address_.at(scripthash).second;
    json history = multihistory[scripthash];
    if (UpdateTransactions(chain, wallet_id, history, rawtx, rawheader)) {
      auto it = std::find(scripthashes.begin(), scripthashes.end(), scripthash);
      int i = it - scripthashes.begin();
      json utxo;  // client_->blockchain_scripthash_listunspent(scripthash);
      std::string utxostatus = join(std::vector{utxo.dump(), status[i]}, '|');
      storage_->SetUtxos(chain, wallet_id, address, utxostatus);
    }
  }
}

void ElectrumSynchronizer::RescanBlockchain(int start_height, int stop_height) {
}

std::vector<UnspentOutput> ElectrumSynchronizer::ListUnspent(
    const std::string& address) {
  std::unique_lock<std::mutex> lock_(status_mutex_);
  if (status_ != Status::READY && status_ != Status::SYNCING) {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Disconnected");
  }

  std::string scripthash = AddressToScriptHash(address);
  json utxos_json = client_->blockchain_scripthash_listunspent(scripthash);
  if (!utxos_json.is_array()) {
    return {};
  }
  std::vector<UnspentOutput> ret;
  ret.reserve(utxos_json.size());

  for (auto&& item : utxos_json) {
    UnspentOutput u;
    u.set_txid(item["tx_hash"]);
    u.set_vout(item["tx_pos"]);
    u.set_amount(Amount(item["value"]));
    u.set_height(item["height"]);
    ret.emplace_back(std::move(u));
  }
  return ret;
}

std::string ElectrumSynchronizer::GetRawTx(const std::string& tx_id) {
  if (raw_tx_.count(tx_id) > 0) return raw_tx_[tx_id];
  std::unique_lock<std::mutex> lock_(status_mutex_);
  if (status_ != Status::READY && status_ != Status::SYNCING) {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Disconnected");
  }
  raw_tx_[tx_id] = client_->blockchain_transaction_get(tx_id);
  return raw_tx_[tx_id];
}

Transaction ElectrumSynchronizer::GetTransaction(const std::string& tx_id) {
  std::unique_lock<std::mutex> lock_(status_mutex_);
  if (status_ != Status::READY && status_ != Status::SYNCING) {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Disconnected");
  }

  std::string raw = client_->blockchain_transaction_get(tx_id);
  auto cmutx = DecodeRawTransaction(raw);
  auto getHeight = [&]() {
    auto tx = GetTransactionFromCMutableTransaction(cmutx, {}, 0);
    std::string scripthash = AddressToScriptHash(tx.get_outputs()[0].first);
    json history = client_->blockchain_scripthash_get_history(scripthash);
    for (auto item : history) {
      std::string tx_hash = item["tx_hash"];
      int height = item["height"];
      if (tx_id == tx_hash) return height;
    }
    return 0;
  };
  int height = getHeight();
  time_t time =
      height <= 0 ? 0 : GetBlockTime(client_->blockchain_block_header(height));
  auto tx = GetTransactionFromCMutableTransaction(cmutx, {}, height);

  Amount total_input = 0;
  for (auto&& [txin_id, vout] : tx.get_inputs()) {
    auto txin_raw = client_->blockchain_transaction_get(txin_id);
    auto txin = DecodeRawTransaction(txin_raw);
    total_input += txin.vout[vout].nValue;
  }

  Amount total_output = std::accumulate(
      std::begin(tx.get_outputs()), std::end(tx.get_outputs()), Amount(0),
      [](Amount acc, const TxOutput& out) { return acc + out.second; });

  tx.set_fee(total_input - total_output);
  tx.set_sub_amount(total_output);
  tx.set_raw(raw);
  tx.set_receive(false);
  tx.set_blocktime(time);

  return tx;
}

}  // namespace nunchuk
