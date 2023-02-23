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
#include <sstream>
#include <descriptor.h>

namespace nunchuk {

SingleSigner::SingleSigner() {}
SingleSigner::SingleSigner(const std::string& name, const std::string& xpub,
                           const std::string& public_key,
                           const std::string& derivation_path,
                           const std::string& master_fingerprint,
                           time_t last_health_check,
                           const std::string& master_signer_id, bool used,
                           SignerType signer_type, std::vector<SignerTag> tags)
    : name_(name),
      xpub_(xpub),
      public_key_(public_key),
      derivation_path_(GetDerivationPathView(derivation_path)),
      master_fingerprint_(master_fingerprint),
      master_signer_id_(master_signer_id),
      last_health_check_(last_health_check),
      used_(used),
      type_(signer_type) {
  set_tags(std::move(tags));
}

std::string SingleSigner::get_name() const { return name_; }
std::string SingleSigner::get_xpub() const { return xpub_; }
std::string SingleSigner::get_public_key() const { return public_key_; }
std::string SingleSigner::get_derivation_path() const {
  return derivation_path_;
}
std::string SingleSigner::get_master_fingerprint() const {
  return master_fingerprint_;
}
std::string SingleSigner::get_master_signer_id() const {
  return master_signer_id_;
}
SignerType SingleSigner::get_type() const { return type_; }
const std::vector<SignerTag>& SingleSigner::get_tags() const { return tags_; }
bool SingleSigner::is_used() const { return used_; }
bool SingleSigner::has_master_signer() const {
  return !master_signer_id_.empty();
}
time_t SingleSigner::get_last_health_check() const {
  return last_health_check_;
}
std::string SingleSigner::get_descriptor() const {
  std::stringstream key;
  key << "[" << master_fingerprint_ << FormalizePath(derivation_path_) << "]"
      << (xpub_.empty() ? public_key_ : xpub_);
  return key.str();
}
void SingleSigner::set_name(const std::string& value) { name_ = value; }
void SingleSigner::set_used(bool value) { used_ = value; }
void SingleSigner::set_type(SignerType value) { type_ = value; }
void SingleSigner::set_tags(std::vector<SignerTag> tags) {
  tags_ = std::move(tags);
  std::sort(tags_.begin(), tags_.end());
  tags_.erase(std::unique(tags_.begin(), tags_.end()), tags_.end());
}

}  // namespace nunchuk
