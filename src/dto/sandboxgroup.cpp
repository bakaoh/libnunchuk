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

#include <nunchuk.h>
#include <vector>
#include <descriptor.h>

namespace nunchuk {

SandboxGroup::SandboxGroup(const std::string& id)
    : id_(id) {};

SandboxGroup::SandboxGroup(const std::string& id, int m, int n,
               AddressType address_type,
               const std::vector<SingleSigner>& signers,
               bool finalized,
               const std::vector<std::string>& keys,
               int state_id)
    : id_(id),
      m_(m),
      n_(n),
      address_type_(address_type),
      signers_(signers),
      finalized_(finalized),
      keys_(keys),
      state_id_(state_id) {};

std::string SandboxGroup::get_id() const { return id_; }
int SandboxGroup::get_m() const { return m_; }
int SandboxGroup::get_n() const { return n_; }
const std::vector<SingleSigner>& SandboxGroup::get_signers() const { return signers_; }
AddressType SandboxGroup::get_address_type() const { return address_type_; }
bool SandboxGroup::is_finalized() const { return finalized_; }
int SandboxGroup::get_state_id() const { return state_id_; }
const std::vector<std::string>& SandboxGroup::get_ephemeral_keys() const { return keys_; }

void SandboxGroup::set_n(int n) { n_ = n; }
void SandboxGroup::set_m(int m) { m_ = m; }
void SandboxGroup::set_signers(std::vector<SingleSigner> signers) { signers_ = std::move(signers); }
void SandboxGroup::set_address_type(AddressType value) { address_type_ = value; }
void SandboxGroup::set_finalized(bool value) { finalized_ = value; }
void SandboxGroup::set_ephemeral_keys(std::vector<std::string> keys) { keys_ = std::move(keys); }
void SandboxGroup::set_state_id(int value) { state_id_ = value; }

}  // namespace nunchuk
