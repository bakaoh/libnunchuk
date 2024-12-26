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

#include <nunchukmatriximpl.h>
#include <iostream>
#include <sstream>
#include <set>
#include <random>
#include <mutex>

#include <utils/enumconverter.hpp>
#include <utils/json.hpp>
#include <utils/attachment.hpp>
#include <descriptor.h>
#include <coreutils.h>

using json = nlohmann::json;

namespace nunchuk {

static int CONTENT_MAX_LEN = 60000;

json GetInitBody(const json& body) {
  return body["io.nunchuk.relates_to"]["init_event"]["content"]["body"];
}

bool IsValidMembers(const json& members, const std::string& key) {
  if (!members.is_array() || members.empty()) return true;
  for (auto&& m : members) {
    if (m.get<std::string>() == key) return true;
  }
  return false;
}

json EventToJson(const NunchukMatrixEvent& event) {
  return {
      {"room_id", event.get_room_id()},
      {"type", event.get_type()},
      {"content", json::parse(event.get_content())},
      {"sender", event.get_sender()},
      {"ts", event.get_ts()},
      {"event_id", event.get_event_id()},
  };
}

NunchukMatrixEvent JsonToEvent(const json& j) {
  NunchukMatrixEvent event{};
  event.set_room_id(j["room_id"]);
  event.set_type(j["type"]);
  event.set_content(j["content"].dump());
  event.set_sender(j["sender"]);
  event.set_ts(j["ts"]);
  event.set_event_id(j["event_id"]);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::NewEvent(const std::string& room_id,
                                               const std::string& event_type,
                                               json& json_content,
                                               bool ignore_error) {
  json_content["v"] = NUNCHUK_EVENT_VER;
  json_content["device_id"] = device_id_;

  std::string content = json_content.dump();
  NunchukMatrixEvent event{};
  event.set_room_id(room_id);
  event.set_type(event_type);
  event.set_content(content);
  event.set_sender(sender_);
  event.set_ts(std::time(0));

  if (content.length() > CONTENT_MAX_LEN) {
    auto body = json_content["body"].dump();
    json_content.erase("body");
    event.set_content(json_content.dump());

    auto file = EncryptAttachment(uploadfunc_, body, EventToJson(event).dump());
    if (file.empty()) return event;

    json_content["file"] = json::parse(file);
    event.set_content(json_content.dump());
  }

  sendfunc_(room_id, event_type, event.get_content(), ignore_error);
  return event;
}

NunchukMatrixImpl::NunchukMatrixImpl(const AppSettings& appsettings,
                                     const std::string& access_token,
                                     const std::string& account,
                                     const std::string& device_id,
                                     SendEventFunc sendfunc)
    : access_token_(access_token),
      sender_(account),
      device_id_(device_id),
      chain_(appsettings.get_chain()),
      storage_(NunchukStorage::get(account)),
      sendfunc_(sendfunc) {
  uploadfunc_ = [this](const std::string&, const std::string&,
                       const std::string&, const char* body, size_t length) {
    auto rs = UploadAttachment(access_token_, body, length);
    return json::parse(rs)["content_uri"].get<std::string>();
  };
  downloadfunc_ = [](const std::string&, const std::string&, const std::string&,
                     const std::string& mxc_uri) {
    return DownloadAttachment(mxc_uri);
  };
}
NunchukMatrix::~NunchukMatrix() = default;
NunchukMatrixImpl::~NunchukMatrixImpl() { stopped = true; }

NunchukMatrixEvent NunchukMatrixImpl::SendErrorEvent(
    const std::string& room_id, const std::string& platform,
    const std::string& code, const std::string& message) {
  json content = {
      {"msgtype", "io.nunchuk.error"},
      {"body", {{"code", code}, {"message", message}, {"platform", platform}}}};
  return NewEvent(room_id, "io.nunchuk.error", content, true);
}

NunchukMatrixEvent NunchukMatrixImpl::InitWallet(
    const std::string& room_id, const std::string& name, int m, int n,
    AddressType address_type, bool is_escrow, const std::string& description,
    const std::vector<SingleSigner>& signers) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  if (db.HasActiveWallet(room_id)) {
    throw NunchukMatrixException(NunchukMatrixException::SHARED_WALLET_EXISTS,
                                 "Shared wallet exists");
  }

  json members = json::array();
  for (auto&& signer : signers) members.push_back(signer.get_descriptor());

  json content = {{"msgtype", "io.nunchuk.wallet.init"},
                  {"body",
                   {{"name", name},
                    {"description", description},
                    {"m", m},
                    {"n", n},
                    {"address_type", AddressTypeToStr(address_type)},
                    {"is_escrow", is_escrow},
                    {"members", members},
                    {"chain", ChainToStr(chain_)}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content);
}

NunchukMatrixEvent NunchukMatrixImpl::JoinWallet(const std::string& room_id,
                                                 const SingleSigner& signer) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);

  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json init_body = json::parse(init_event.get_content())["body"];
  auto chain = ChainFromStr(init_body["chain"]);
  if (chain_ != chain) {
    throw NunchukMatrixException(NunchukMatrixException::MISMATCHED_NETWORKS,
                                 "Mismatched networks");
  }
  bool is_escrow = init_body["is_escrow"];
  if (is_escrow && !signer.get_xpub().empty()) {
    throw NunchukMatrixException(NunchukMatrixException::MISMATCHED_KEY_TYPES,
                                 "Mismatched key types");
  }

  std::string key = signer.get_descriptor();
  if (!IsValidMembers(init_body["members"], key)) {
    throw NunchukMatrixException(NunchukMatrixException::INVALID_KEY,
                                 "Key can not be assigned");
  }

  std::set<std::string> leave_ids;
  for (auto&& leave_event_id : wallet.get_leave_event_ids()) {
    auto leave_event = db.GetEvent(leave_event_id);
    auto leave_body = json::parse(leave_event.get_content())["body"];
    std::string join_id = leave_body["io.nunchuk.relates_to"]["join_event_id"];
    leave_ids.insert(join_id);
  }

  for (auto&& join_event_id : wallet.get_join_event_ids()) {
    if (leave_ids.count(join_event_id)) continue;
    auto join_event = db.GetEvent(join_event_id);
    auto join_body = json::parse(join_event.get_content())["body"];
    std::string join_key = join_body["key"];
    if (key == join_key) {
      throw NunchukMatrixException(NunchukMatrixException::DUPLICATE_KEYS,
                                   "Duplicate keys");
    }
  }

  json content = {
      {"msgtype", "io.nunchuk.wallet.join"},
      {"body",
       {{"key", key},
        {"type", SignerTypeToStr(signer.get_type())},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content);
}

NunchukMatrixEvent NunchukMatrixImpl::LeaveWallet(
    const std::string& room_id, const std::string& join_event_id,
    const std::string& reason) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json content = {{"msgtype", "io.nunchuk.wallet.leave"},
                  {"body",
                   {{"reason", reason},
                    {"io.nunchuk.relates_to",
                     {{"init_event", EventToJson(init_event)},
                      {"join_event_id", join_event_id}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content);
}

NunchukMatrixEvent NunchukMatrixImpl::CancelWallet(const std::string& room_id,
                                                   const std::string& reason) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json content = {
      {"msgtype", "io.nunchuk.wallet.cancel"},
      {"body",
       {{"reason", reason},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content);
}

NunchukMatrixEvent NunchukMatrixImpl::DeleteWallet(
    const std::unique_ptr<Nunchuk>& nu, const std::string& room_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  nu->DeleteWallet(wallet.get_wallet_id());
  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json content = {
      {"msgtype", "io.nunchuk.wallet.delete"},
      {"body",
       {{"wallet_id", wallet.get_wallet_id()},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content);
}

NunchukMatrixEvent NunchukMatrixImpl::CreateWallet(
    const std::unique_ptr<Nunchuk>& /* nu */, const std::string& room_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);

  std::set<std::string> leave_ids;
  for (auto&& leave_event_id : wallet.get_leave_event_ids()) {
    auto leave_event = db.GetEvent(leave_event_id);
    auto leave_body = json::parse(leave_event.get_content())["body"];
    std::string join_id = leave_body["io.nunchuk.relates_to"]["join_event_id"];
    leave_ids.insert(join_id);
  }

  std::vector<std::string> join_event_ids;
  std::vector<SingleSigner> signers = {};
  for (auto&& join_event_id : wallet.get_join_event_ids()) {
    if (leave_ids.count(join_event_id)) continue;
    auto join_event = db.GetEvent(join_event_id);
    auto join_body = json::parse(join_event.get_content())["body"];
    join_event_ids.push_back(join_event_id);
    std::string key = join_body["key"];
    signers.push_back(ParseSignerString(key));
  }

  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json init_body = json::parse(init_event.get_content())["body"];
  std::string name = init_body["name"];
  int m = init_body["m"];
  int n = init_body["n"];
  std::string description = init_body["description"];
  bool is_escrow = init_body["is_escrow"];
  auto a = AddressTypeFromStr(init_body["address_type"]);

  Wallet w("", name, m, n, signers, a, is_escrow? WalletType::ESCROW : WalletType::MULTI_SIG, 0);
  std::string descriptor = w.get_descriptor(DescriptorPath::TEMPLATE);
  std::string first_address = CoreUtils::getInstance().DeriveAddress(
      w.get_descriptor(DescriptorPath::EXTERNAL_ALL), is_escrow ? -1 : 0);

  json content = {{"msgtype", "io.nunchuk.wallet.create"},
                  {"body",
                   {{"descriptor", descriptor},
                    {"path_restriction", "/0/*,/1/*"},
                    {"first_address", first_address},
                    {"io.nunchuk.relates_to",
                     {{"init_event", EventToJson(init_event)},
                      {"join_event_ids", join_event_ids}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content);
}

NunchukMatrixEvent NunchukMatrixImpl::InitTransaction(
    const std::unique_ptr<Nunchuk>& nu, const std::string& room_id,
    const std::map<std::string, Amount> outputs, const std::string& memo,
    const std::vector<UnspentOutput> inputs, Amount fee_rate,
    bool subtract_fee_from_amount) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  auto tx = nu->CreateTransaction(wallet.get_wallet_id(), outputs, memo, inputs,
                                  fee_rate, subtract_fee_from_amount);
  json content = {{"msgtype", "io.nunchuk.transaction.init"},
                  {"body",
                   {{"wallet_id", wallet.get_wallet_id()},
                    {"memo", tx.get_memo()},
                    {"psbt", tx.get_psbt()},
                    {"fee_rate", tx.get_fee_rate()},
                    {"subtract_fee_from_amount", tx.subtract_fee_from_amount()},
                    {"chain", ChainToStr(chain_)}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content);
}

NunchukMatrixEvent NunchukMatrixImpl::SignTransaction(
    const std::unique_ptr<Nunchuk>& nu, const std::string& init_event_id,
    const Device& device) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  auto rtx = db.GetTransaction(init_event_id);
  auto tx = nu->SignTransaction(rtx.get_wallet_id(), rtx.get_tx_id(), device);
  json content = {
      {"msgtype", "io.nunchuk.transaction.sign"},
      {"body",
       {{"psbt", tx.get_psbt()},
        {"master_fingerprint", device.get_master_fingerprint()},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content);
}

NunchukMatrixEvent NunchukMatrixImpl::SignAirgapTransaction(
    const std::unique_ptr<Nunchuk>& nu, const std::string& init_event_id,
    const std::string& master_fingerprint) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  auto rtx = db.GetTransaction(init_event_id);
  auto tx = nu->GetTransaction(rtx.get_wallet_id(), rtx.get_tx_id());
  json content = {
      {"msgtype", "io.nunchuk.transaction.sign"},
      {"body",
       {{"psbt", tx.get_psbt()},
        {"master_fingerprint", master_fingerprint},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content);
}

NunchukMatrixEvent NunchukMatrixImpl::SignTapsignerTransaction(
    const std::unique_ptr<Nunchuk>& nu, const std::string& init_event_id,
    tap_protocol::Tapsigner* tapsigner, const std::string& cvc) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  auto rtx = db.GetTransaction(init_event_id);
  auto st = nu->GetTapsignerStatus(tapsigner);
  auto tx = nu->SignTapsignerTransaction(tapsigner, cvc, rtx.get_wallet_id(),
                                         rtx.get_tx_id());
  json content = {
      {"msgtype", "io.nunchuk.transaction.sign"},
      {"body",
       {{"psbt", tx.get_psbt()},
        {"master_fingerprint", st.get_master_signer_id()},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content);
}

NunchukMatrixEvent NunchukMatrixImpl::RejectTransaction(
    const std::string& init_event_id, const std::string& reason) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  json content = {
      {"msgtype", "io.nunchuk.transaction.reject"},
      {"body",
       {{"reason", reason},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content);
}

NunchukMatrixEvent NunchukMatrixImpl::CancelTransaction(
    const std::string& init_event_id, const std::string& reason) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  json content = {
      {"msgtype", "io.nunchuk.transaction.cancel"},
      {"body",
       {{"reason", reason},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content);
}

NunchukMatrixEvent NunchukMatrixImpl::BroadcastTransaction(
    const std::unique_ptr<Nunchuk>& nu, const std::string& init_event_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  auto rtx = db.GetTransaction(init_event_id);
  auto tx = nu->BroadcastTransaction(rtx.get_wallet_id(), rtx.get_tx_id());
  json content = {{"msgtype", "io.nunchuk.transaction.broadcast"},
                  {"body",
                   {{"tx_id", tx.get_txid()},
                    {"raw_tx", tx.get_raw()},
                    {"io.nunchuk.relates_to",
                     {{"init_event", EventToJson(init_event)},
                      {"sign_event_ids", rtx.get_sign_event_ids()}}}}}};
  if (tx.get_status() == TransactionStatus::NETWORK_REJECTED) {
    content["body"]["reject_msg"] = tx.get_reject_msg();
  }
  rtx.set_tx_id(tx.get_txid());
  db.SetTransaction(rtx);
  return NewEvent(room_id, "io.nunchuk.transaction", content);
}

std::string NunchukMatrixImpl::GetTransactionId(const std::string& event_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);

  auto event = db.GetEvent(event_id);
  auto encrypted = json::parse(event.get_content())["body"]["encrypted_tx_id"];

  auto wallet = db.GetActiveWallet(event.get_room_id());
  if (wallet.get_finalize_event_id().empty()) {
    throw NunchukMatrixException(
        NunchukMatrixException::SHARED_WALLET_NOT_FOUND,
        "Shared wallet not finalized");
  }
  auto wallet_finalize_event = db.GetEvent(wallet.get_finalize_event_id());
  std::string desc =
      json::parse(wallet_finalize_event.get_content())["body"]["descriptor"];

  return DecryptTxId(desc, encrypted.dump());
}

void NunchukMatrixImpl::SendReceiveTransaction(const std::string& room_id,
                                               const std::string& tx_id) {
  // std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  if (db.HasTransactionNotify(tx_id)) return;
  auto wallet = db.GetActiveWallet(room_id);
  if (wallet.get_finalize_event_id().empty()) return;
  auto wallet_finalize_event = db.GetEvent(wallet.get_finalize_event_id());
  std::string desc =
      json::parse(wallet_finalize_event.get_content())["body"]["descriptor"];
  std::string encrypted_tx_id = EncryptTxId(desc, tx_id);
  json content = {
      {"msgtype", "io.nunchuk.transaction.receive"},
      {"body", {{"encrypted_tx_id", json::parse(encrypted_tx_id)}}}};
  NewEvent(room_id, "io.nunchuk.transaction", content);
}

void NunchukMatrixImpl::EnableGenerateReceiveEvent(
    const std::unique_ptr<Nunchuk>& nu) {
  auto wallets = GetAllRoomWallets();
  for (auto&& wallet : wallets) {
    if (!wallet.get_wallet_id().empty()) {
      wallet2room_[wallet.get_wallet_id()] = wallet.get_room_id();
    }
  }
  nu->AddTransactionListener(
      [&](std::string tx_id, TransactionStatus status, std::string wallet_id) {
        if (status != TransactionStatus::PENDING_CONFIRMATION &&
            status != TransactionStatus::CONFIRMED)
          return;
        if (wallet2room_.count(wallet_id) == 0) return;
        if (!nu->GetTransaction(wallet_id, tx_id).is_receive()) return;
        auto room_id{wallet2room_.at(wallet_id)};
        RandomDelay(
            [this, room_id, tx_id] { SendReceiveTransaction(room_id, tx_id); });
      });
}

NunchukMatrixEvent NunchukMatrixImpl::Backup(
    const std::unique_ptr<Nunchuk>& nu) {
  auto data = nu->ExportBackup();
  auto body = json::parse(data);
  body["matrix"] = json::parse(ExportBackup());
  json content = {{"msgtype", "io.nunchuk.sync.file"}, {"body", body}};
  return NewEvent(sync_room_id_, "io.nunchuk.sync", content);
}

void NunchukMatrixImpl::AsyncBackup(const std::unique_ptr<Nunchuk>& nu,
                                    int sec) {
  delay_.push_back(std::async(std::launch::async, [&, sec] {
    try {
      if (sec > 0) std::this_thread::sleep_for(std::chrono::seconds(sec));
      if (stopped) return;
      Backup(nu);
    } catch (...) {
      if (sec == 0 && !stopped) AsyncBackup(nu, 60);
    }
  }));
}

void NunchukMatrixImpl::RegisterAutoBackup(const std::unique_ptr<Nunchuk>& nu,
                                           const std::string& sync_room_id,
                                           const std::string& access_token) {
  sync_room_id_ = sync_room_id;
  access_token_ = access_token;
  if (sync_room_id_.empty() || access_token_.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid room_id or access_token");
  }
  nu->AddStorageUpdateListener([&]() {
    if (enable_auto_backup_) AsyncBackup(nu);
  });
}

void NunchukMatrixImpl::EnableAutoBackup(bool enable) {
  enable_auto_backup_ = enable;
}

void NunchukMatrixImpl::RegisterFileFunc(UploadFileFunc upload,
                                         DownloadFileFunc download) {
  uploadfunc_ = upload;
  downloadfunc_ = download;
}

NunchukMatrixEvent NunchukMatrixImpl::UploadFileCallback(
    const std::string& json_info, const std::string& file_url) {
  if (json_info.empty() || file_url.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "invalid params");
  }
  auto info = json::parse(json_info);
  auto event = JsonToEvent(info["event"]);
  auto file = info["file"];
  file["url"] = file_url;
  json new_content = json::parse(event.get_content());
  new_content["file"] = file;

  return NewEvent(event.get_room_id(), event.get_type(), new_content);
}

void NunchukMatrixImpl::DownloadFileCallback(
    const std::unique_ptr<Nunchuk>& nu, const std::string& json_info,
    const std::vector<unsigned char>& file_data,
    std::function<bool /* stop */ (int /* percent */)> progress) {
  auto event = JsonToEvent(json::parse(json_info));
  json content = json::parse(event.get_content());
  if (content["file"] == nullptr) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "invalid json_info");
  }
  auto data = DecryptAttachment(file_data, content["file"].dump());
  if (event.get_type().rfind("io.nunchuk.sync", 0) == 0) {
    if (nu->SyncWithBackup(data, progress)) {
      std::unique_lock<std::shared_mutex> lock(access_);
      SyncWithBackup(data);
    }
  } else {
    content["body"] = json::parse(data);
    event.set_content(content.dump());
    ConsumeEvent(nu, event);
    progress(100);
  }
}

void NunchukMatrixImpl::WriteFileCallback(
    const std::unique_ptr<Nunchuk>& nu, const std::string& json_info,
    const std::string& file_path,
    std::function<bool /* stop */ (int /* percent */)> progress) {
  auto file_data = LoadAttachmentFile(file_path);
  DownloadFileCallback(nu, json_info, file_data, progress);
}

std::vector<RoomWallet> NunchukMatrixImpl::GetAllRoomWallets() {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  return db.GetWallets();
}

bool NunchukMatrixImpl::HasRoomWallet(const std::string& room_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  return db.HasActiveWallet(room_id);
}

RoomWallet NunchukMatrixImpl::GetRoomWallet(const std::string& room_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  return db.GetActiveWallet(room_id);
}

std::vector<RoomTransaction> NunchukMatrixImpl::GetPendingTransactions(
    const std::string& room_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  return db.GetPendingTransactions(room_id);
}

RoomTransaction NunchukMatrixImpl::GetRoomTransaction(
    const std::string& init_event_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  return db.GetTransaction(init_event_id);
}

NunchukMatrixEvent NunchukMatrixImpl::GetEvent(const std::string& event_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto db = storage_->GetRoomDb(chain_);
  return db.GetEvent(event_id);
}

void NunchukMatrixImpl::ConsumeEvent(const std::unique_ptr<Nunchuk>& nu,
                                     const NunchukMatrixEvent& event) {
  std::unique_lock<std::shared_mutex> lock(access_);
  if (event.get_type().rfind("io.nunchuk.sync", 0) == 0) return;
  if (event.get_type().rfind("io.nunchuk", 0) != 0) return;
  if (event.get_event_id().empty()) return;
  if (event.get_event_id().rfind("$local", 0) == 0) return;

  auto db = storage_->GetRoomDb(chain_);
  if (db.HasEvent(event.get_event_id())) return;
  json content = json::parse(event.get_content());
  if (content["v"] == nullptr) return;

  json body;
  if (content["body"] != nullptr) {
    body = content["body"];
  } else if (content["file"] != nullptr) {
    auto data = DecryptAttachment(downloadfunc_, content["file"].dump(),
                                  EventToJson(event).dump());
    if (data.empty()) return;
    body = json::parse(data);
  }

  std::string init_event_id = "";
  if (body["io.nunchuk.relates_to"] != nullptr) {
    auto init_event = JsonToEvent(body["io.nunchuk.relates_to"]["init_event"]);
    if (!db.HasEvent(init_event.get_event_id())) db.SetEvent(init_event);
    init_event_id = init_event.get_event_id();
    json init_body = GetInitBody(body);
    if (ChainFromStr(init_body["chain"]) != chain_) return;
  }

  std::string msgtype = content["msgtype"];
  if (msgtype == "io.nunchuk.wallet.init") {
    auto wallet = db.GetWallet(event.get_event_id(), false);
    wallet.set_room_id(event.get_room_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.join") {
    auto wallet = db.GetWallet(init_event_id, false);
    wallet.set_room_id(event.get_room_id());
    wallet.add_join_event_id(event.get_event_id());
    db.SetWallet(wallet);
    db.SetEvent(event);
  } else if (msgtype == "io.nunchuk.wallet.leave") {
    auto wallet = db.GetWallet(init_event_id, false);
    wallet.set_room_id(event.get_room_id());
    wallet.add_leave_event_id(event.get_event_id());
    wallet.set_ready_event_id("");
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.cancel") {
    auto wallet = db.GetWallet(init_event_id, false);
    wallet.set_room_id(event.get_room_id());
    wallet.set_cancel_event_id(event.get_event_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.delete") {
    auto wallet = db.GetWallet(init_event_id, false);
    wallet.set_room_id(event.get_room_id());
    wallet.set_delete_event_id(event.get_event_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.create") {
    auto wallet = db.GetWallet(init_event_id, false);
    wallet.set_room_id(event.get_room_id());
    wallet.set_finalize_event_id(event.get_event_id());
    if (wallet.get_wallet_id().empty() &&
        wallet.get_delete_event_id().empty()) {
      std::string desc = body["descriptor"];
      Wallet w = Utils::ParseWalletDescriptor(desc);

      auto init_body = GetInitBody(body);
      w.set_name(init_body["name"]);
      w.set_description(init_body["description"]);

      wallet.set_wallet_id(w.get_id());
      wallet2room_[w.get_id()] = event.get_room_id();

      // Note: update db first to make sure sync file has the latest data
      db.SetWallet(wallet);
      NunchukMatrixEvent event_hasbody = JsonToEvent(EventToJson(event));
      content["body"] = body;
      event_hasbody.set_content(content.dump());
      db.SetEvent(event_hasbody);

      if (!nu->HasWallet(w.get_id())) nu->CreateWallet(w, true);
      return;
    }
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.transaction.receive") {
    if (db.HasActiveWallet(event.get_room_id())) {
      auto wallet = db.GetActiveWallet(event.get_room_id());
      if (!wallet.get_finalize_event_id().empty()) {
        nu->ScanWalletAddress(wallet.get_wallet_id());
        auto encrypted = body["encrypted_tx_id"];
        auto wallet_finalize_event =
            db.GetEvent(wallet.get_finalize_event_id());
        std::string desc = json::parse(
            wallet_finalize_event.get_content())["body"]["descriptor"];
        db.SetTransactionNotify(DecryptTxId(desc, encrypted.dump()),
                                event.get_event_id());
      }
    }
  } else if (msgtype.rfind("io.nunchuk.transaction", 0) == 0) {
    json init_body;
    if (msgtype == "io.nunchuk.transaction.init") {
      init_event_id = event.get_event_id();
      init_body = body;
    } else {
      init_body = GetInitBody(body);
    }

    auto tx = db.GetTransaction(init_event_id);
    tx.set_room_id(event.get_room_id());
    tx.set_wallet_id(init_body["wallet_id"]);
    nu->ScanWalletAddress(tx.get_wallet_id());
    if (tx.get_broadcast_event_id().empty()) {
      auto ntx = nu->ImportPsbt(tx.get_wallet_id(), init_body["psbt"], false);
      tx.set_tx_id(ntx.get_txid());
    }

    if (msgtype == "io.nunchuk.transaction.sign") {
      tx.add_sign_event_id(event.get_event_id());
      if (tx.get_broadcast_event_id().empty()) {
        nu->ImportPsbt(tx.get_wallet_id(), body["psbt"], false);
      }
    } else if (msgtype == "io.nunchuk.transaction.reject") {
      tx.add_reject_event_id(event.get_event_id());
      nu->DeleteTransaction(tx.get_wallet_id(), tx.get_tx_id());
    } else if (msgtype == "io.nunchuk.transaction.cancel") {
      tx.set_cancel_event_id(event.get_event_id());
      nu->DeleteTransaction(tx.get_wallet_id(), tx.get_tx_id());
    } else if (msgtype == "io.nunchuk.transaction.broadcast") {
      tx.set_broadcast_event_id(event.get_event_id());
      if (body["raw_tx"] != nullptr) {
        std::string reject_msg{};
        if (body["reject_msg"] != nullptr) reject_msg = body["reject_msg"];
        nu->UpdateTransaction(tx.get_wallet_id(), tx.get_tx_id(), body["tx_id"],
                              body["raw_tx"], reject_msg);
      }
      tx.set_tx_id(body["tx_id"]);
    }

    db.SetTransaction(tx);
  }
  NunchukMatrixEvent event_hasbody = JsonToEvent(EventToJson(event));
  content["body"] = body;
  event_hasbody.set_content(content.dump());
  db.SetEvent(event_hasbody);
}

void NunchukMatrixImpl::ConsumeSyncEvent(const std::unique_ptr<Nunchuk>& nu,
                                         const NunchukMatrixEvent& event,
                                         std::function<bool(int)> progress) {
  std::unique_lock<std::shared_mutex> lock(access_);
  if (event.get_type().rfind("io.nunchuk.sync", 0) != 0) return;
  if (event.get_event_id().empty()) return;
  if (event.get_event_id().rfind("$local", 0) == 0) return;

  auto db = storage_->GetRoomDb(chain_);
  if (db.HasEvent(event.get_event_id())) return;
  json content = json::parse(event.get_content());
  if (content["v"] == nullptr) return;
  std::string msgtype = content["msgtype"];
  if (msgtype == "io.nunchuk.sync.file") {
    db.SetSyncRoomId(event.get_room_id());
    if (content["device_id"] == nullptr || content["device_id"] != device_id_) {
      std::string data;
      if (content["body"] != nullptr) {
        data = content["body"].dump();
      } else if (content["file"] != nullptr) {
        data = DecryptAttachment(downloadfunc_, content["file"].dump(),
                                 EventToJson(event).dump());
      }
      if (!data.empty() && nu->SyncWithBackup(data, progress)) {
        SyncWithBackup(data);
      }
    }
  }
  db.SetEvent(event);
}

void NunchukMatrixImpl::SyncWithBackup(const std::string& dataStr) {
  json data = json::parse(dataStr);
  if (data["matrix"] == nullptr) return;

  auto importChain = [&](Chain chain, json& d) {
    if (d == nullptr) return;
    auto db = storage_->GetRoomDb(chain);
    json events = d["events"];
    for (auto&& e : events) db.SetEvent({e.dump()});
    json wallets = d["wallets"];
    for (auto&& w : wallets) {
      RoomWallet w1{w.dump()};
      if (db.HasActiveWallet(w1.get_room_id())) {
        auto w0 = db.GetActiveWallet(w1.get_room_id(), false);
        if (w0.get_init_event_id() == w1.get_init_event_id()) {
          w0.merge(w1);
          db.SetWallet(w0);
          continue;
        }
      }
      db.SetWallet(w1);
    }
  };

  importChain(Chain::TESTNET, data["matrix"]["testnet"]);
  importChain(Chain::MAIN, data["matrix"]["mainnet"]);
  importChain(Chain::SIGNET, data["matrix"]["signet"]);
}

std::string NunchukMatrixImpl::ExportBackup() {
  std::unique_lock<std::shared_mutex> lock(access_);

  auto exportChain = [&](Chain chain) {
    auto db = storage_->GetRoomDb(chain);
    json rs;
    rs["events"] = json::array();
    auto exportEvent = [&](const std::string& event_id) {
      if (event_id.empty()) return;
      try {
        rs["events"].push_back(json::parse(db.GetEvent(event_id).to_json()));
      } catch (...) {
      }
    };

    rs["wallets"] = json::array();
    auto wallets = db.GetWallets(false);
    for (auto&& wallet : wallets) {
      if (!wallet.get_cancel_event_id().empty() ||
          !wallet.get_delete_event_id().empty())
        continue;
      exportEvent(wallet.get_init_event_id());
      for (auto&& id : wallet.get_join_event_ids()) exportEvent(id);
      for (auto&& id : wallet.get_leave_event_ids()) exportEvent(id);
      exportEvent(wallet.get_finalize_event_id());
      exportEvent(wallet.get_cancel_event_id());
      exportEvent(wallet.get_delete_event_id());
      exportEvent(wallet.get_ready_event_id());
      rs["wallets"].push_back(json::parse(wallet.to_json()));
    }
    return rs;
  };

  json data = {{"testnet", exportChain(Chain::TESTNET)},
               {"mainnet", exportChain(Chain::MAIN)},
               {"signet", exportChain(Chain::SIGNET)}};
  return data.dump();
}

void NunchukMatrixImpl::RandomDelay(std::function<void()> exec) {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  static std::uniform_int_distribution<> distr(3, 15);

  delay_.push_back(std::async(std::launch::async, [exec] {
    std::this_thread::sleep_for(std::chrono::seconds(distr(gen)));
    exec();
  }));
}

std::unique_ptr<NunchukMatrix> MakeNunchukMatrixForAccount(
    const AppSettings& appsettings, const std::string& passphrase,
    const std::string& account, const std::string& device_id,
    SendEventFunc SendEventFunc) {
  return std::unique_ptr<NunchukMatrixImpl>(new NunchukMatrixImpl(
      appsettings, passphrase, account, device_id, SendEventFunc));
}

}  // namespace nunchuk
