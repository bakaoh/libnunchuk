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

#ifndef NUNCHUK_DESCRIPTOR_H
#define NUNCHUK_DESCRIPTOR_H

#include <nunchuk.h>
#include <script/descriptor.h>

#include <string>
#include <vector>

namespace nunchuk {
const std::string H_POINT =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

std::string AddChecksum(const std::string& str);

std::string FormalizePath(const std::string& path);

std::string GetChildKeyPath(const std::pair<int, int>& external_internal,
                            DescriptorPath path, int index);

std::string GetDerivationPathView(std::string path);

std::string GetWalletId(const std::vector<SingleSigner>& signers, int m,
                        AddressType address_type, WalletType wallet_type,
                        WalletTemplate wallet_template);

/**
 * @param external External descriptor to import
 * @param internal Internal descriptor to import
 * @param range The end or the range (in the form [begin,end]) to import
 * @param timestamp UNIX epoch time from which to start rescanning the
 * blockchain for this descriptor, use -1 for "now"
 */
std::string GetDescriptorsImportString(const std::string& external,
                                       const std::string& internal = {},
                                       int range = 100, int64_t timestamp = -1);

std::string GetDescriptorsImportString(const Wallet& wallet);

std::string GetDescriptorForSigners(
    const std::vector<SingleSigner>& signers, int m,
    DescriptorPath path = DescriptorPath::EXTERNAL_ALL,
    AddressType address_type = AddressType::LEGACY,
    WalletType wallet_type = WalletType::MULTI_SIG,
    WalletTemplate wallet_template = WalletTemplate::DEFAULT, int index = -1,
    bool sorted = true);

std::string GetDescriptorForSigner(const SingleSigner& signer,
                                   DescriptorPath key_path, int index = -1);

std::string GetDescriptorForMiniscript(const std::string& miniscript,
                                       const std::string& keypath,
                                       AddressType address_type);

std::string GetPkhDescriptor(const std::string& address);

std::string GetDescriptor(const SingleSigner& signer, AddressType address_type);

SingleSigner ParseSignerString(const std::string& signer_str);

std::optional<Wallet> ParseDescriptors(const std::string& descs,
                                       std::string& error);

std::optional<Wallet> ParseJSONDescriptors(const std::string& json_str,
                                           std::string& error);

std::string GetSignerNameFromDerivationPath(const std::string& derivation_path,
                                            const std::string& prefix = {});

std::string GetUnspendableXpub(const std::vector<SingleSigner>& signers);

bool IsUnspendableXpub(const std::string& xpub);

}  // namespace nunchuk

#endif  // NUNCHUK_DESCRIPTOR_H
