// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_SCRIPT_MINISCRIPT_COMPILER_H_
#define _BITCOIN_SCRIPT_MINISCRIPT_COMPILER_H_

#include <nunchuk.h>
#include <miniscript/miniscript.h>
#include <string>

namespace nunchuk {
struct Policy {
  enum class Type {
    NONE,

    PK_K,
    OLDER,
    AFTER,
    HASH160,
    HASH256,
    RIPEMD160,
    SHA256,
    AND,
    OR,
    THRESH
  };

  Type node_type = Type::NONE;
  std::vector<Policy> sub;
  std::vector<unsigned char> data;
  std::vector<std::string> keys;
  std::vector<uint32_t> prob;
  uint32_t k = 0;

  ~Policy() = default;
  Policy(const Policy& x) = delete;
  Policy& operator=(const Policy& x) = delete;
  Policy& operator=(Policy&& x) = default;
  Policy(Policy&& x) = default;

  Policy() {}
  Policy(Type nt) : node_type(nt) {}
  Policy(Type nt, uint32_t kv) : node_type(nt), k(kv) {}
  Policy(Type nt, std::vector<unsigned char>&& dat)
      : node_type(nt), data(std::move(dat)) {}
  Policy(Type nt, std::vector<unsigned char>&& dat, uint32_t kv)
      : node_type(nt), data(std::move(dat)), k(kv) {}
  Policy(Type nt, std::vector<Policy>&& subs)
      : node_type(nt), sub(std::move(subs)) {}
  Policy(Type nt, std::vector<std::string>&& key)
      : node_type(nt), keys(std::move(key)) {}
  Policy(Type nt, std::vector<Policy>&& subs, std::vector<uint32_t>&& probs)
      : node_type(nt), sub(std::move(subs)), prob(std::move(probs)) {}
  Policy(Type nt, std::vector<Policy>&& subs, uint32_t kv)
      : node_type(nt), sub(std::move(subs)), k(kv) {}
  Policy(Type nt, std::vector<std::string>&& key, uint32_t kv)
      : node_type(nt), keys(std::move(key)), k(kv) {}

  bool operator()() const { return node_type != Type::NONE; }

  Policy Clone() const {
    Policy result;
    result.node_type = node_type;
    result.k = k;

    // Deep copy vectors
    result.sub.reserve(sub.size());
    for (const auto& s : sub) {
      result.sub.push_back(s.Clone());
    }

    result.data = data;
    result.keys = keys;
    result.prob = prob;

    return result;
  }
};
}  // namespace nunchuk

struct CompilerContext {
  typedef std::string Key;

  std::optional<std::string> ToString(const Key& key) const { return key; }

  template <typename I>
  std::optional<Key> FromString(I first, I last) const {
    if (std::distance(first, last) == 0 || std::distance(first, last) > 17)
      return {};
    return std::string(first, last);
  }

  std::vector<unsigned char> ToPKBytes(const Key& key) const {
    std::vector<unsigned char> ret{2, 'P', 'K', 'b'};
    ret.resize(33, 0);
    std::copy(key.begin(), key.end(), ret.begin() + 4);
    return ret;
  }

  std::vector<unsigned char> ToPKHBytes(const Key& key) const {
    std::vector<unsigned char> ret{'P', 'K', 'h'};
    ret.resize(20, 0);
    std::copy(key.begin(), key.end(), ret.begin() + 3);
    return ret;
  }

  bool KeyCompare(const Key& a, const Key& b) const { return a < b; }
};

extern const CompilerContext COMPILER_CTX;

bool Compile(const std::string& policy,
             nunchuk::miniscript::NodeRef<CompilerContext::Key>& ret,
             double& avgcost);

std::string Expand(std::string str);
std::string Abbreviate(std::string str);
std::string Disassemble(const CScript& script);

nunchuk::Policy ParsePolicy(const std::string& policy);
bool CompilePolicy(const nunchuk::Policy& policy,
                   nunchuk::miniscript::NodeRef<CompilerContext::Key>& ret,
                   double& avgcost);

#endif
