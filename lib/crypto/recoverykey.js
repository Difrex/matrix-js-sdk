"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.encodeRecoveryKey = encodeRecoveryKey;
exports.decodeRecoveryKey = decodeRecoveryKey;

var _bs = _interopRequireDefault(require("bs58"));

/*
Copyright 2018 New Vector Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// picked arbitrarily but to try & avoid clashing with any bitcoin ones
// (which are also base58 encoded, but bitcoin's involve a lot more hashing)
const OLM_RECOVERY_KEY_PREFIX = [0x8B, 0x01];

function encodeRecoveryKey(key) {
  const buf = new Buffer(OLM_RECOVERY_KEY_PREFIX.length + key.length + 1);
  buf.set(OLM_RECOVERY_KEY_PREFIX, 0);
  buf.set(key, OLM_RECOVERY_KEY_PREFIX.length);
  let parity = 0;

  for (let i = 0; i < buf.length - 1; ++i) {
    parity ^= buf[i];
  }

  buf[buf.length - 1] = parity;

  const base58key = _bs.default.encode(buf);

  return base58key.match(/.{1,4}/g).join(" ");
}

function decodeRecoveryKey(recoverykey) {
  const result = _bs.default.decode(recoverykey.replace(/ /g, ''));

  let parity = 0;

  for (const b of result) {
    parity ^= b;
  }

  if (parity !== 0) {
    throw new Error("Incorrect parity");
  }

  for (let i = 0; i < OLM_RECOVERY_KEY_PREFIX.length; ++i) {
    if (result[i] !== OLM_RECOVERY_KEY_PREFIX[i]) {
      throw new Error("Incorrect prefix");
    }
  }

  if (result.length !== OLM_RECOVERY_KEY_PREFIX.length + global.Olm.PRIVATE_KEY_LENGTH + 1) {
    throw new Error("Incorrect length");
  }

  return result.slice(OLM_RECOVERY_KEY_PREFIX.length, OLM_RECOVERY_KEY_PREFIX.length + global.Olm.PRIVATE_KEY_LENGTH);
}