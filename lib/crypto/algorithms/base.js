"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.registerAlgorithm = registerAlgorithm;
exports.UnknownDeviceError = exports.DecryptionError = exports.DecryptionAlgorithm = exports.EncryptionAlgorithm = exports.DECRYPTION_CLASSES = exports.ENCRYPTION_CLASSES = void 0;

/*
Copyright 2016 OpenMarket Ltd

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

/**
 * Internal module. Defines the base classes of the encryption implementations
 *
 * @module
 */

/**
 * map of registered encryption algorithm classes. A map from string to {@link
 * module:crypto/algorithms/base.EncryptionAlgorithm|EncryptionAlgorithm} class
 *
 * @type {Object.<string, function(new: module:crypto/algorithms/base.EncryptionAlgorithm)>}
 */
const ENCRYPTION_CLASSES = {};
/**
 * map of registered encryption algorithm classes. Map from string to {@link
 * module:crypto/algorithms/base.DecryptionAlgorithm|DecryptionAlgorithm} class
 *
 * @type {Object.<string, function(new: module:crypto/algorithms/base.DecryptionAlgorithm)>}
 */

exports.ENCRYPTION_CLASSES = ENCRYPTION_CLASSES;
const DECRYPTION_CLASSES = {};
/**
 * base type for encryption implementations
 *
 * @alias module:crypto/algorithms/base.EncryptionAlgorithm
 *
 * @param {object} params parameters
 * @param {string} params.userId  The UserID for the local user
 * @param {string} params.deviceId The identifier for this device.
 * @param {module:crypto} params.crypto crypto core
 * @param {module:crypto/OlmDevice} params.olmDevice olm.js wrapper
 * @param {module:base-apis~MatrixBaseApis} baseApis base matrix api interface
 * @param {string} params.roomId  The ID of the room we will be sending to
 * @param {object} params.config  The body of the m.room.encryption event
 */

exports.DECRYPTION_CLASSES = DECRYPTION_CLASSES;

class EncryptionAlgorithm {
  constructor(params) {
    this._userId = params.userId;
    this._deviceId = params.deviceId;
    this._crypto = params.crypto;
    this._olmDevice = params.olmDevice;
    this._baseApis = params.baseApis;
    this._roomId = params.roomId;
  }
  /**
   * Encrypt a message event
   *
   * @method module:crypto/algorithms/base.EncryptionAlgorithm.encryptMessage
   * @abstract
   *
   * @param {module:models/room} room
   * @param {string} eventType
   * @param {object} plaintext event content
   *
   * @return {Promise} Promise which resolves to the new event body
   */

  /**
   * Called when the membership of a member of the room changes.
   *
   * @param {module:models/event.MatrixEvent} event  event causing the change
   * @param {module:models/room-member} member  user whose membership changed
   * @param {string=} oldMembership  previous membership
   * @public
   */


  onRoomMembership(event, member, oldMembership) {}

}
/**
 * base type for decryption implementations
 *
 * @alias module:crypto/algorithms/base.DecryptionAlgorithm
 * @param {object} params parameters
 * @param {string} params.userId  The UserID for the local user
 * @param {module:crypto} params.crypto crypto core
 * @param {module:crypto/OlmDevice} params.olmDevice olm.js wrapper
 * @param {module:base-apis~MatrixBaseApis} baseApis base matrix api interface
 * @param {string=} params.roomId The ID of the room we will be receiving
 *     from. Null for to-device events.
 */


exports.EncryptionAlgorithm = EncryptionAlgorithm;

class DecryptionAlgorithm {
  constructor(params) {
    this._userId = params.userId;
    this._crypto = params.crypto;
    this._olmDevice = params.olmDevice;
    this._baseApis = params.baseApis;
    this._roomId = params.roomId;
  }
  /**
   * Decrypt an event
   *
   * @method module:crypto/algorithms/base.DecryptionAlgorithm#decryptEvent
   * @abstract
   *
   * @param {MatrixEvent} event undecrypted event
   *
   * @return {Promise<module:crypto~EventDecryptionResult>} promise which
   * resolves once we have finished decrypting. Rejects with an
   * `algorithms.DecryptionError` if there is a problem decrypting the event.
   */

  /**
   * Handle a key event
   *
   * @method module:crypto/algorithms/base.DecryptionAlgorithm#onRoomKeyEvent
   *
   * @param {module:models/event.MatrixEvent} params event key event
   */


  onRoomKeyEvent(params) {} // ignore by default

  /**
   * Import a room key
   *
   * @param {module:crypto/OlmDevice.MegolmSessionData} session
   */


  importRoomKey(session) {} // ignore by default

  /**
   * Determine if we have the keys necessary to respond to a room key request
   *
   * @param {module:crypto~IncomingRoomKeyRequest} keyRequest
   * @return {Promise<boolean>} true if we have the keys and could (theoretically) share
   *  them; else false.
   */


  hasKeysForKeyRequest(keyRequest) {
    return Promise.resolve(false);
  }
  /**
   * Send the response to a room key request
   *
   * @param {module:crypto~IncomingRoomKeyRequest} keyRequest
   */


  shareKeysWithDevice(keyRequest) {
    throw new Error("shareKeysWithDevice not supported for this DecryptionAlgorithm");
  }
  /**
   * Retry decrypting all the events from a sender that haven't been
   * decrypted yet.
   *
   * @param {string} senderKey the sender's key
   */


  async retryDecryptionFromSender(senderKey) {// ignore by default
  }

}
/**
 * Exception thrown when decryption fails
 *
 * @alias module:crypto/algorithms/base.DecryptionError
 * @param {string} msg user-visible message describing the problem
 *
 * @param {Object=} details key/value pairs reported in the logs but not shown
 *   to the user.
 *
 * @extends Error
 */


exports.DecryptionAlgorithm = DecryptionAlgorithm;

class DecryptionError extends Error {
  constructor(code, msg, details) {
    super(msg);
    this.code = code;
    this.name = 'DecryptionError';
    this.detailedString = _detailedStringForDecryptionError(this, details);
  }

}

exports.DecryptionError = DecryptionError;

function _detailedStringForDecryptionError(err, details) {
  let result = err.name + '[msg: ' + err.message;

  if (details) {
    result += ', ' + Object.keys(details).map(k => k + ': ' + details[k]).join(', ');
  }

  result += ']';
  return result;
}
/**
 * Exception thrown specifically when we want to warn the user to consider
 * the security of their conversation before continuing
 *
 * @param {string} msg message describing the problem
 * @param {Object} devices userId -> {deviceId -> object}
 *      set of unknown devices per user we're warning about
 * @extends Error
 */


class UnknownDeviceError extends Error {
  constructor(msg, devices) {
    super(msg);
    this.name = "UnknownDeviceError";
    this.devices = devices;
  }

}
/**
 * Registers an encryption/decryption class for a particular algorithm
 *
 * @param {string} algorithm algorithm tag to register for
 *
 * @param {class} encryptor {@link
 *     module:crypto/algorithms/base.EncryptionAlgorithm|EncryptionAlgorithm}
 *     implementation
 *
 * @param {class} decryptor {@link
 *     module:crypto/algorithms/base.DecryptionAlgorithm|DecryptionAlgorithm}
 *     implementation
 */


exports.UnknownDeviceError = UnknownDeviceError;

function registerAlgorithm(algorithm, encryptor, decryptor) {
  ENCRYPTION_CLASSES[algorithm] = encryptor;
  DECRYPTION_CLASSES[algorithm] = decryptor;
}