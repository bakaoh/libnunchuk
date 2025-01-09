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

#include "nunchukimpl.h"

#include <groupservice.h>
#include <utils/json.hpp>
#include <utils/loguru.hpp>
#include <utils/rsa.hpp>

using json = nlohmann::json;

namespace nunchuk {

void ThrowIfNotEnable(bool value) {
  if (!value) {
    throw GroupException(GroupException::NOT_ENABLED, "Group is not enabled");
  }
}

void NunchukImpl::EnableGroupWallet(const std::string& osName,
                                    const std::string& osVersion,
                                    const std::string& appVersion,
                                    const std::string& deviceClass,
                                    const std::string& deviceId,
                                    const std::string& accessToken) {
  group_wallet_enable_ = true;
  group_service_.SetAccessToken(accessToken);
  auto keypair = storage_->GetGroupEphemeralKey(chain_);
  if (keypair.first.empty() || keypair.second.empty()) {
    keypair = rsa::GenerateKeypair();
    storage_->SetGroupEphemeralKey(chain_, keypair.first, keypair.second);
  }
  group_service_.SetEphemeralKey(keypair.first, keypair.second);
  auto deviceInfo = storage_->GetGroupDeviceInfo(chain_);
  if (deviceInfo.first.empty() || deviceInfo.second.empty()) {
    deviceInfo = group_service_.RegisterDevice(osName, osVersion, appVersion,
                                               deviceClass, deviceId);
    storage_->SetGroupDeviceInfo(chain_, deviceInfo.first, deviceInfo.second);
  } else {
    group_service_.SetDeviceInfo(deviceInfo.first, deviceInfo.second);
  }

  auto groups = GetGroups();
  for (auto&& group : groups) {
    if (group.need_broadcast() && group.get_m() > 0) {
      group_service_.UpdateGroup(group);
    }
  }
  auto walletIds = storage_->GetGroupWalletIds(chain_);
  for (auto&& walletId : walletIds) {
    auto wallet = GetWallet(walletId);
    group_service_.SetupKey(wallet);
  }
}

std::pair<std::string, std::string> NunchukImpl::ParseGroupUrl(
    const std::string& url) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.ParseUrl(url);
}

GroupConfig NunchukImpl::GetGroupConfig() {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.GetConfig();
}

void NunchukImpl::StartConsumeGroupEvent() {
  ThrowIfNotEnable(group_wallet_enable_);
  auto groupIds = storage_->GetGroupSandboxIds(chain_);
  auto walletIds = storage_->GetGroupWalletIds(chain_);
  group_service_.Subscribe(groupIds, walletIds);
  group_service_.StartListenEvents([&](const std::string& e) {
    json event = json::parse(e);
    time_t ts = event["timestamp_ms"].get<int64_t>() / 1000;
    std::string eid = event["id"];
    std::string uid = event["uid"];
    json payload = event["payload"];
    std::string type = payload["type"];
    json data = payload["data"];

    if (type == "init") {
      auto g = group_service_.ParseGroupData(payload["group_id"], false, data);
      if (g.need_broadcast() && g.get_m() > 0) {
        group_service_.UpdateGroup(g);
      }
      group_wallet_listener_(g);
    } else if (type == "finalize") {
      auto g = group_service_.ParseGroupData(payload["group_id"], true, data);
      if (!storage_->HasWallet(chain_, g.get_wallet_id())) {
        auto wallet =
            CreateWallet(g.get_name(), g.get_m(), g.get_n(), g.get_signers(),
                         g.get_address_type(), false, {}, true, {});
        group_service_.SetupKey(wallet);
        walletIds = storage_->AddGroupWalletId(chain_, wallet.get_id());
        groupIds = storage_->RemoveGroupSandboxId(chain_, payload["group_id"]);
        group_service_.Subscribe(groupIds, walletIds);
      }
      group_wallet_listener_(g);
    } else if (type == "chat") {
      auto m = group_service_.ParseMessageData(eid, payload["wallet_id"], data);
      m.set_ts(ts);
      m.set_sender(uid);
      group_message_listener_(m);
    } else if (type == "transaction_updated") {
      auto txGid = data["transaction_id"];
      auto walletId = group_service_.GetWalletIdFromGid(payload["wallet_id"]);
      auto txId = group_service_.GetTxIdFromGid(walletId, txGid);
      auto psbt = group_service_.GetTransaction(walletId, txId);
      ImportPsbt(walletId, psbt, false, false);
    } else if (type == "transaction_deleted") {
      auto txGid = data["transaction_id"];
      auto walletId = group_service_.GetWalletIdFromGid(payload["wallet_id"]);
      auto txId = group_service_.GetTxIdFromGid(walletId, txGid);
      DeleteTransaction(walletId, txId, false);
    }
    return true;
  });
}

void NunchukImpl::StopConsumeGroupEvent() {
  ThrowIfNotEnable(group_wallet_enable_);
  group_service_.StopListenEvents();
}

GroupSandbox NunchukImpl::CreateGroup(const std::string& name, int m, int n,
                                      AddressType addressType,
                                      const SingleSigner& signer) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto group = group_service_.CreateGroup(name, m, n, addressType, signer);
  storage_->AddGroupSandboxId(chain_, group.get_id());
  // BE auto subcribe new groupId for creator, don't need to call Subscribe here
  return group;
}

GroupSandbox NunchukImpl::GetGroup(const std::string& groupId) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.GetGroup(groupId);
}

std::vector<GroupSandbox> NunchukImpl::GetGroups() {
  ThrowIfNotEnable(group_wallet_enable_);
  auto groupIds = storage_->GetGroupSandboxIds(chain_);
  return group_service_.GetGroups(groupIds);
}

GroupSandbox NunchukImpl::JoinGroup(const std::string& groupId) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto groupIds = storage_->AddGroupSandboxId(chain_, groupId);
  auto walletIds = storage_->GetGroupWalletIds(chain_);
  group_service_.Subscribe(groupIds, walletIds);
  return group_service_.JoinGroup(groupId);
}

GroupSandbox NunchukImpl::AddSignerToGroup(const std::string& groupId,
                                           const SingleSigner& signer) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto group = group_service_.GetGroup(groupId);
  auto signers = group.get_signers();
  if (signers.size() == group.get_n()) {
    throw GroupException(GroupException::TOO_MANY_SIGNER, "Too many signer");
  }
  auto desc = signer.get_descriptor();
  for (auto&& s : signers) {
    if (s.get_descriptor() == desc) {
      throw GroupException(GroupException::SIGNER_EXISTS, "Signer exists");
    }
  }
  signers.push_back(signer);
  group.set_signers(signers);
  return group_service_.UpdateGroup(group);
}

GroupSandbox NunchukImpl::RemoveSignerFromGroup(const std::string& groupId,
                                                const SingleSigner& signer) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto group = group_service_.GetGroup(groupId);
  auto signers = group.get_signers();
  auto desc = signer.get_descriptor();
  signers.erase(std::remove_if(signers.begin(), signers.end(),
                               [&](const SingleSigner& s) {
                                 return s.get_descriptor() == desc;
                               }),
                signers.end());
  group.set_signers(signers);
  return group_service_.UpdateGroup(group);
}

GroupSandbox NunchukImpl::UpdateGroup(const std::string& groupId,
                                      const std::string& name, int m, int n,
                                      AddressType addressType,
                                      const SingleSigner& signer) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto group = group_service_.GetGroup(groupId);
  group.set_name(name);
  group.set_m(m);
  group.set_n(n);
  group.set_address_type(addressType);
  if (group.get_address_type() != addressType &&
      (group.get_address_type() == AddressType::TAPROOT ||
       addressType == AddressType::TAPROOT)) {
    group.set_signers({signer});
  }
  return group_service_.UpdateGroup(group);
}

GroupSandbox NunchukImpl::FinalizeGroup(const std::string& groupId) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto group = group_service_.GetGroup(groupId);
  if (group.get_m() <= 0 || group.get_n() <= 1 ||
      group.get_m() > group.get_n()) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid m/n");
  }
  auto signers = group.get_signers();
  if (signers.size() < group.get_n()) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid signers");
  }
  signers.resize(group.get_n());
  auto wallet =
      CreateWallet(group.get_name(), group.get_m(), group.get_n(), signers,
                   group.get_address_type(), false, {}, true, {});
  group.set_signers(signers);
  group.set_finalized(true);
  group.set_wallet_id(wallet.get_id());
  group.set_pubkey(group_service_.SetupKey(wallet));
  auto rs = group_service_.UpdateGroup(group);
  auto walletIds = storage_->AddGroupWalletId(chain_, wallet.get_id());
  auto groupIds = storage_->RemoveGroupSandboxId(chain_, groupId);
  group_service_.Subscribe(groupIds, walletIds);
  return rs;
}

std::vector<Wallet> NunchukImpl::GetGroupWallets() {
  auto walletIds = storage_->GetGroupWalletIds(chain_);
  std::vector<Wallet> rs{};
  for (auto&& walletId : walletIds) {
    auto wallet = GetWallet(walletId);
    rs.push_back(wallet);
  }
  return rs;
}

GroupWalletConfig NunchukImpl::GetGroupWalletConfig(
    const std::string& walletId) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.GetWalletConfig(walletId);
}

void NunchukImpl::SetGroupWalletConfig(const std::string& walletId,
                                       const GroupWalletConfig& config) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.SetWalletConfig(walletId, config);
}

bool NunchukImpl::CheckGroupWalletExists(const Wallet& wallet) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.CheckWalletExists(wallet);
}

void NunchukImpl::RecoverGroupWallet(const std::string& walletId) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto wallet = GetWallet(walletId);
  if (!group_service_.CheckWalletExists(wallet)) {
    throw GroupException(GroupException::WALLET_NOT_FOUND, "Wallet not found");
  }
  group_service_.SetupKey(wallet);
  auto groupIds = storage_->GetGroupSandboxIds(chain_);
  auto walletIds = storage_->AddGroupWalletId(chain_, walletId);
  group_service_.Subscribe(groupIds, walletIds);
}

void NunchukImpl::SendGroupMessage(const std::string& walletId,
                                   const std::string& msg,
                                   const SingleSigner& signer) {
  ThrowIfNotEnable(group_wallet_enable_);
  std::string signature = {};  // TODO: sign the msg with signature
  group_service_.SendMessage(walletId, msg, signer.get_master_fingerprint(),
                             signature);
}

std::vector<GroupMessage> NunchukImpl::GetGroupMessages(
    const std::string& walletId, int page, int pageSize, bool latest) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.GetMessages(walletId, page, pageSize, latest);
}

void NunchukImpl::AddGroupUpdateListener(
    std::function<void(const GroupSandbox& state)> listener) {
  group_wallet_listener_.connect(listener);
}

void NunchukImpl::AddGroupMessageListener(
    std::function<void(const GroupMessage& msg)> listener) {
  group_message_listener_.connect(listener);
}

}  // namespace nunchuk
