/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2025 Enigmo.
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
#include <primitives/transaction.h>

namespace nunchuk {

Timelock::Timelock(Based based, Type type, int64_t value)
    : based_(based), type_(type), value_(value) {
  if (based_ == Based::TIME_LOCK && type_ == Type::LOCKTYPE_RELATIVE &&
      value_ < 512) {
    value_ = 512;
  }
  k();
}

Timelock::Based Timelock::based() const { return based_; }
Timelock::Type Timelock::type() const { return type_; }
int64_t Timelock::value() const { return value_; }

int64_t Timelock::k() const {
  if (type_ == Type::LOCKTYPE_ABSOLUTE) {
    if (value_ < LOCKTIME_THRESHOLD && based_ == Based::TIME_LOCK) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid time value");
    } else if (value_ >= LOCKTIME_THRESHOLD && based_ == Based::HEIGHT_LOCK) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid height value");
    }
    return value_;
  } else {
    if (based_ == Based::TIME_LOCK) {
      if (value_ < 0 || value_ >= 33554431) {
        throw NunchukException(NunchukException::INVALID_PARAMETER,
                               "Invalid time value");
      }
      return (value_ >> CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) |
             CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    } else if (based_ == Based::HEIGHT_LOCK) {
      if (value_ < 0 || value_ >= 65535) {
        throw NunchukException(NunchukException::INVALID_PARAMETER,
                               "Invalid height value");
      }
      return value_ & CTxIn::SEQUENCE_LOCKTIME_MASK;
    } else {
      return 0;
    }
  }
}

Timelock Timelock::FromK(bool is_absolute, int64_t k) {
  Based b;
  Type t;
  int64_t v;
  if (is_absolute) {
    t = Type::LOCKTYPE_ABSOLUTE;
    b = k >= LOCKTIME_THRESHOLD ? Timelock::Based::TIME_LOCK
                                : Timelock::Based::HEIGHT_LOCK;
    v = k;
  } else {
    t = Type::LOCKTYPE_RELATIVE;
    if (k & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
      b = Timelock::Based::TIME_LOCK;
      v = (int64_t)((k & CTxIn::SEQUENCE_LOCKTIME_MASK)
                    << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY);
    } else {
      b = Timelock::Based::HEIGHT_LOCK;
      v = (int)(k & CTxIn::SEQUENCE_LOCKTIME_MASK);
    }
  }
  if (v == 0) {
    b = Timelock::Based::NONE;
  }
  return Timelock(b, t, v);
}

std::string Timelock::to_miniscript() const {
  std::stringstream temp;
  if (type_ == Type::LOCKTYPE_ABSOLUTE) {
    temp << "after(" << k() << ")";
  } else {
    temp << "older(" << k() << ")";
  }
  return temp.str();
}

}  // namespace nunchuk