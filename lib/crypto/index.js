"use strict";

var _interopRequireWildcard = require("@babel/runtime/helpers/interopRequireWildcard");

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.isCryptoAvailable = isCryptoAvailable;
exports.Crypto = Crypto;
exports.verificationMethods = void 0;

var _anotherJson = _interopRequireDefault(require("another-json"));

var _events = require("events");

var _ReEmitter = require("../ReEmitter");

var _logger = require("../logger");

var utils = _interopRequireWildcard(require("../utils"));

var _OlmDevice = require("./OlmDevice");

var olmlib = _interopRequireWildcard(require("./olmlib"));

var _DeviceList = require("./DeviceList");

var _deviceinfo = require("./deviceinfo");

var algorithms = _interopRequireWildcard(require("./algorithms"));

var _CrossSigning = require("./CrossSigning");

var _SecretStorage = require("./SecretStorage");

var _OutgoingRoomKeyRequestManager = require("./OutgoingRoomKeyRequestManager");

var _indexeddbCryptoStore = require("./store/indexeddb-crypto-store");

var _QRCode = require("./verification/QRCode");

var _SAS = require("./verification/SAS");

var _key_passphrase = require("./key_passphrase");

var _recoverykey = require("./recoverykey");

var _VerificationRequest = require("./verification/request/VerificationRequest");

var _InRoomChannel = require("./verification/request/InRoomChannel");

var _ToDeviceChannel = require("./verification/request/ToDeviceChannel");

var httpApi = _interopRequireWildcard(require("../http-api"));

var _IllegalMethod = require("./verification/IllegalMethod");

/*
Copyright 2016 OpenMarket Ltd
Copyright 2017 Vector Creations Ltd
Copyright 2018-2019 New Vector Ltd
Copyright 2019-2020 The Matrix.org Foundation C.I.C.

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
 * @module crypto
 */
const DeviceVerification = _deviceinfo.DeviceInfo.DeviceVerification;
const defaultVerificationMethods = {
  [_QRCode.ReciprocateQRCode.NAME]: _QRCode.ReciprocateQRCode,
  [_SAS.SAS.NAME]: _SAS.SAS,
  // These two can't be used for actual verification, but we do
  // need to be able to define them here for the verification flows
  // to start.
  [_QRCode.SHOW_QR_CODE_METHOD]: _IllegalMethod.IllegalMethod,
  [_QRCode.SCAN_QR_CODE_METHOD]: _IllegalMethod.IllegalMethod
};
/**
 * verification method names
 */

const verificationMethods = {
  RECIPROCATE_QR_CODE: _QRCode.ReciprocateQRCode.NAME,
  SAS: _SAS.SAS.NAME
};
exports.verificationMethods = verificationMethods;

function isCryptoAvailable() {
  return Boolean(global.Olm);
}

const MIN_FORCE_SESSION_INTERVAL_MS = 60 * 60 * 1000;
const KEY_BACKUP_KEYS_PER_REQUEST = 200;
/**
 * Cryptography bits
 *
 * This module is internal to the js-sdk; the public API is via MatrixClient.
 *
 * @constructor
 * @alias module:crypto
 *
 * @internal
 *
 * @param {module:base-apis~MatrixBaseApis} baseApis base matrix api interface
 *
 * @param {module:store/session/webstorage~WebStorageSessionStore} sessionStore
 *    Store to be used for end-to-end crypto session data
 *
 * @param {string} userId The user ID for the local user
 *
 * @param {string} deviceId The identifier for this device.
 *
 * @param {Object} clientStore the MatrixClient data store.
 *
 * @param {module:crypto/store/base~CryptoStore} cryptoStore
 *    storage for the crypto layer.
 *
 * @param {RoomList} roomList An initialised RoomList object
 *
 * @param {Array} verificationMethods Array of verification methods to use.
 *    Each element can either be a string from MatrixClient.verificationMethods
 *    or a class that implements a verification method.
 */

function Crypto(baseApis, sessionStore, userId, deviceId, clientStore, cryptoStore, roomList, verificationMethods) {
  this._onDeviceListUserCrossSigningUpdated = this._onDeviceListUserCrossSigningUpdated.bind(this);
  this._reEmitter = new _ReEmitter.ReEmitter(this);
  this._baseApis = baseApis;
  this._sessionStore = sessionStore;
  this._userId = userId;
  this._deviceId = deviceId;
  this._clientStore = clientStore;
  this._cryptoStore = cryptoStore;
  this._roomList = roomList;

  if (verificationMethods) {
    this._verificationMethods = new Map();

    for (const method of verificationMethods) {
      if (typeof method === "string") {
        if (defaultVerificationMethods[method]) {
          this._verificationMethods.set(method, defaultVerificationMethods[method]);
        }
      } else if (method.NAME) {
        this._verificationMethods.set(method.NAME, method);
      } else {
        console.warn(`Excluding unknown verification method ${method}`);
      }
    }
  } else {
    this._verificationMethods = defaultVerificationMethods;
  } // track whether this device's megolm keys are being backed up incrementally
  // to the server or not.
  // XXX: this should probably have a single source of truth from OlmAccount


  this.backupInfo = null; // The info dict from /room_keys/version

  this.backupKey = null; // The encryption key object

  this._checkedForBackup = false; // Have we checked the server for a backup we can use?

  this._sendingBackups = false; // Are we currently sending backups?

  this._olmDevice = new _OlmDevice.OlmDevice(cryptoStore);
  this._deviceList = new _DeviceList.DeviceList(baseApis, cryptoStore, this._olmDevice); // XXX: This isn't removed at any point, but then none of the event listeners
  // this class sets seem to be removed at any point... :/

  this._deviceList.on('userCrossSigningUpdated', this._onDeviceListUserCrossSigningUpdated);

  this._reEmitter.reEmit(this._deviceList, ["crypto.devicesUpdated"]); // the last time we did a check for the number of one-time-keys on the
  // server.


  this._lastOneTimeKeyCheck = null;
  this._oneTimeKeyCheckInProgress = false; // EncryptionAlgorithm instance for each room

  this._roomEncryptors = {}; // map from algorithm to DecryptionAlgorithm instance, for each room

  this._roomDecryptors = {};
  this._supportedAlgorithms = utils.keys(algorithms.DECRYPTION_CLASSES);
  this._deviceKeys = {};
  this._globalBlacklistUnverifiedDevices = false;
  this._globalErrorOnUnknownDevices = true;
  this._outgoingRoomKeyRequestManager = new _OutgoingRoomKeyRequestManager.OutgoingRoomKeyRequestManager(baseApis, this._deviceId, this._cryptoStore); // list of IncomingRoomKeyRequests/IncomingRoomKeyRequestCancellations
  // we received in the current sync.

  this._receivedRoomKeyRequests = [];
  this._receivedRoomKeyRequestCancellations = []; // true if we are currently processing received room key requests

  this._processingRoomKeyRequests = false; // controls whether device tracking is delayed
  // until calling encryptEvent or trackRoomDevices,
  // or done immediately upon enabling room encryption.

  this._lazyLoadMembers = false; // in case _lazyLoadMembers is true,
  // track if an initial tracking of all the room members
  // has happened for a given room. This is delayed
  // to avoid loading room members as long as possible.

  this._roomDeviceTrackingState = {}; // The timestamp of the last time we forced establishment
  // of a new session for each device, in milliseconds.
  // {
  //     userId: {
  //         deviceId: 1234567890000,
  //     },
  // }

  this._lastNewSessionForced = {};
  this._toDeviceVerificationRequests = new _ToDeviceChannel.ToDeviceRequests();
  this._inRoomVerificationRequests = new _InRoomChannel.InRoomRequests();
  const cryptoCallbacks = this._baseApis._cryptoCallbacks || {};
  this._crossSigningInfo = new _CrossSigning.CrossSigningInfo(userId, cryptoCallbacks);
  this._secretStorage = new _SecretStorage.SecretStorage(baseApis, cryptoCallbacks, this._crossSigningInfo); // Assuming no app-supplied callback, default to getting from SSSS.

  if (!cryptoCallbacks.getCrossSigningKey && cryptoCallbacks.getSecretStorageKey) {
    cryptoCallbacks.getCrossSigningKey = async type => {
      return _CrossSigning.CrossSigningInfo.getFromSecretStorage(type, this._secretStorage);
    };
  }
}

utils.inherits(Crypto, _events.EventEmitter);
/**
 * Initialise the crypto module so that it is ready for use
 *
 * Returns a promise which resolves once the crypto module is ready for use.
 *
 * @param {Object} opts keyword arguments.
 * @param {string} opts.exportedOlmDevice (Optional) data from exported device
 *     that must be re-created.
 */

Crypto.prototype.init = async function (opts) {
  const {
    exportedOlmDevice
  } = opts || {};

  _logger.logger.log("Crypto: initialising Olm...");

  await global.Olm.init();

  _logger.logger.log(exportedOlmDevice ? "Crypto: initialising Olm device from exported device..." : "Crypto: initialising Olm device...");

  await this._olmDevice.init({
    fromExportedDevice: exportedOlmDevice
  });

  _logger.logger.log("Crypto: loading device list...");

  await this._deviceList.load(); // build our device keys: these will later be uploaded

  this._deviceKeys["ed25519:" + this._deviceId] = this._olmDevice.deviceEd25519Key;
  this._deviceKeys["curve25519:" + this._deviceId] = this._olmDevice.deviceCurve25519Key;

  _logger.logger.log("Crypto: fetching own devices...");

  let myDevices = this._deviceList.getRawStoredDevicesForUser(this._userId);

  if (!myDevices) {
    myDevices = {};
  }

  if (!myDevices[this._deviceId]) {
    // add our own deviceinfo to the cryptoStore
    _logger.logger.log("Crypto: adding this device to the store...");

    const deviceInfo = {
      keys: this._deviceKeys,
      algorithms: this._supportedAlgorithms,
      verified: DeviceVerification.VERIFIED,
      known: true
    };
    myDevices[this._deviceId] = deviceInfo;

    this._deviceList.storeDevicesForUser(this._userId, myDevices);

    this._deviceList.saveIfDirty();
  }

  await this._cryptoStore.doTxn('readonly', [_indexeddbCryptoStore.IndexedDBCryptoStore.STORE_ACCOUNT], txn => {
    this._cryptoStore.getCrossSigningKeys(txn, keys => {
      if (keys) {
        _logger.logger.log("Loaded cross-signing public keys from crypto store");

        this._crossSigningInfo.setKeys(keys);
      }
    });
  }); // make sure we are keeping track of our own devices
  // (this is important for key backups & things)

  this._deviceList.startTrackingDeviceList(this._userId);

  _logger.logger.log("Crypto: checking for key backup...");

  this._checkAndStartKeyBackup();
};
/**
 * Create a recovery key from a user-supplied passphrase.
 *
 * @param {string} password Passphrase string that can be entered by the user
 *     when restoring the backup as an alternative to entering the recovery key.
 *     Optional.
 * @returns {Promise<Array>} Array with public key metadata, encoded private
 *     recovery key which should be disposed of after displaying to the user,
 *     and raw private key to avoid round tripping if needed.
 */


Crypto.prototype.createRecoveryKeyFromPassphrase = async function (password) {
  const decryption = new global.Olm.PkDecryption();

  try {
    const keyInfo = {};

    if (password) {
      const derivation = await (0, _key_passphrase.keyFromPassphrase)(password);
      keyInfo.passphrase = {
        algorithm: "m.pbkdf2",
        iterations: derivation.iterations,
        salt: derivation.salt
      };
      keyInfo.pubkey = decryption.init_with_private_key(derivation.key);
    } else {
      keyInfo.pubkey = decryption.generate_key();
    }

    const privateKey = decryption.get_private_key();
    const encodedPrivateKey = (0, _recoverykey.encodeRecoveryKey)(privateKey);
    return [keyInfo, encodedPrivateKey, privateKey];
  } finally {
    if (decryption) decryption.free();
  }
};
/**
 * Bootstrap Secure Secret Storage if needed by creating a default key and
 * signing it with the cross-signing master key. If everything is already set
 * up, then no changes are made, so this is safe to run to ensure secret storage
 * is ready for use.
 *
 * @param {function} [opts.authUploadDeviceSigningKeys] Optional. Function
 * called to await an interactive auth flow when uploading device signing keys.
 * Args:
 *     {function} A function that makes the request requiring auth. Receives the
 *     auth data as an object.
 * @param {function} [opts.createSecretStorageKey] Optional. Function
 * called to await a secret storage key creation flow.
 * @param {object} [opts.keyBackupInfo] The current key backup object. If passed,
 * the passphrase and recovery key from this backup will be used.
 * @param {bool} [opts.setupNewKeyBackup] If true, a new key backup version will be
 * created and the private key stored in the new SSSS store. Ignored if keyBackupInfo
 * is supplied.
 * @param {bool} [opts.setupNewSecretStorage] Optional. Reset even if keys already exist.
 * Returns:
 *     {Promise} A promise which resolves to key creation data for
 *     SecretStorage#addKey: an object with `passphrase` and/or `pubkey` fields.
 */


Crypto.prototype.bootstrapSecretStorage = async function ({
  authUploadDeviceSigningKeys,
  createSecretStorageKey = async () => {},
  keyBackupInfo,
  setupNewKeyBackup,
  setupNewSecretStorage
} = {}) {
  _logger.logger.log("Bootstrapping Secure Secret Storage"); // Create cross-signing keys if they don't exist, as we want to sign the SSSS default
  // key with the cross-signing master key. The cross-signing master key is also used
  // to verify the signature on the SSSS default key when adding secrets, so we
  // effectively need it for both reading and writing secrets.


  const crossSigningPrivateKeys = {}; // If we happen to reset cross-signing keys here, then we want access to the
  // cross-signing private keys, but only for the scope of this method, so we
  // use temporary callbacks to weave them through the various APIs.

  const appCallbacks = Object.assign({}, this._baseApis._cryptoCallbacks);

  try {
    const inStorage = !setupNewSecretStorage && (await this._crossSigningInfo.isStoredInSecretStorage(this._secretStorage));

    if (!this._crossSigningInfo.getId() || !inStorage) {
      _logger.logger.log("Cross-signing public and/or private keys not found, " + "checking secret storage for private keys");

      if (inStorage) {
        _logger.logger.log("Cross-signing private keys found in secret storage");

        await this.checkOwnCrossSigningTrust();
      } else {
        _logger.logger.log("Cross-signing private keys not found in secret storage, " + "creating new keys");

        this._baseApis._cryptoCallbacks.saveCrossSigningKeys = keys => Object.assign(crossSigningPrivateKeys, keys);

        this._baseApis._cryptoCallbacks.getCrossSigningKey = name => crossSigningPrivateKeys[name];

        await this.resetCrossSigningKeys(_CrossSigning.CrossSigningLevel.MASTER, {
          authUploadDeviceSigningKeys
        });
      }
    } else {
      _logger.logger.log("Cross signing keys are present in secret storage");
    } // Check if Secure Secret Storage has a default key. If we don't have one, create
    // the default key (which will also be signed by the cross-signing master key).


    if (setupNewSecretStorage || !(await this.hasSecretStorageKey())) {
      let newKeyId;

      if (keyBackupInfo) {
        _logger.logger.log("Secret storage default key not found, using key backup key");

        const opts = {
          pubkey: keyBackupInfo.auth_data.public_key
        };

        if (keyBackupInfo.auth_data.private_key_salt && keyBackupInfo.auth_data.private_key_iterations) {
          opts.passphrase = {
            algorithm: "m.pbkdf2",
            iterations: keyBackupInfo.auth_data.private_key_iterations,
            salt: keyBackupInfo.auth_data.private_key_salt
          };
        }

        newKeyId = await this.addSecretStorageKey(_SecretStorage.SECRET_STORAGE_ALGORITHM_V1, opts); // Add an entry for the backup key in SSSS as a 'passthrough' key
        // (ie. the secret is the key itself).

        this._secretStorage.storePassthrough('m.megolm_backup.v1', newKeyId); // if this key backup is trusted, sign it with the cross signing key
        // so the key backup can be trusted via cross-signing.


        const backupSigStatus = await this.checkKeyBackup(keyBackupInfo);

        if (backupSigStatus.trustInfo.usable) {
          console.log("Adding cross signing signature to key backup");
          await this._crossSigningInfo.signObject(keyBackupInfo.auth_data, "master");
          await this._baseApis._http.authedRequest(undefined, "PUT", "/room_keys/version/" + keyBackupInfo.version, undefined, keyBackupInfo, {
            prefix: httpApi.PREFIX_UNSTABLE
          });
        } else {
          console.log("Key backup is NOT TRUSTED: NOT adding cross signing signature");
        }
      } else {
        _logger.logger.log("Secret storage default key not found, creating new key");

        const keyOptions = await createSecretStorageKey();
        newKeyId = await this.addSecretStorageKey(_SecretStorage.SECRET_STORAGE_ALGORITHM_V1, keyOptions);
      }

      await this.setDefaultSecretStorageKeyId(newKeyId);
    } else {
      _logger.logger.log("Have secret storage key");
    } // If cross-signing keys were reset, store them in Secure Secret Storage.
    // This is done in a separate step so we can ensure secret storage has its
    // own key first.
    // XXX: We need to think about how to re-do these steps if they fail.
    // See also https://github.com/vector-im/riot-web/issues/11635


    if (Object.keys(crossSigningPrivateKeys).length) {
      _logger.logger.log("Storing cross-signing private keys in secret storage"); // SSSS expects its keys to be signed by cross-signing master key.
      // Since we have just reset cross-signing keys, we need to re-sign the
      // SSSS default key with the new cross-signing master key so that the
      // following storage step can proceed.


      await this._secretStorage.signKey(); // Assuming no app-supplied callback, default to storing in SSSS.

      if (!appCallbacks.saveCrossSigningKeys) {
        await _CrossSigning.CrossSigningInfo.storeInSecretStorage(crossSigningPrivateKeys, this._secretStorage);
      }
    }

    if (setupNewKeyBackup && !keyBackupInfo) {
      const info = await this._baseApis.prepareKeyBackupVersion(null
      /* random key */
      , {
        secureSecretStorage: true
      });
      await this._baseApis.createKeyBackupVersion(info);
    }
  } finally {
    // Restore the original callbacks. NB. we must do this by manipulating
    // the same object since the CrossSigning class has a reference to the
    // object, so if we assign the object here then our callbacks will change
    // but the instances of the CrossSigning class will be left with our
    // random, otherwise dead closures.
    for (const cb of Object.keys(this._baseApis._cryptoCallbacks)) {
      delete this._baseApis._cryptoCallbacks[cb];
    }

    Object.assign(this._baseApis._cryptoCallbacks, appCallbacks);
  }

  _logger.logger.log("Secure Secret Storage ready");
};

Crypto.prototype.addSecretStorageKey = function (algorithm, opts, keyID) {
  return this._secretStorage.addKey(algorithm, opts, keyID);
};

Crypto.prototype.hasSecretStorageKey = function (keyID) {
  return this._secretStorage.hasKey(keyID);
};

Crypto.prototype.storeSecret = function (name, secret, keys) {
  return this._secretStorage.store(name, secret, keys);
};

Crypto.prototype.getSecret = function (name) {
  return this._secretStorage.get(name);
};

Crypto.prototype.isSecretStored = function (name, checkKey) {
  return this._secretStorage.isStored(name, checkKey);
};

Crypto.prototype.requestSecret = function (name, devices) {
  if (!devices) {
    devices = Object.keys(this._deviceList.getRawStoredDevicesForUser(this._userId));
  }

  return this._secretStorage.request(name, devices);
};

Crypto.prototype.getDefaultSecretStorageKeyId = function () {
  return this._secretStorage.getDefaultKeyId();
};

Crypto.prototype.setDefaultSecretStorageKeyId = function (k) {
  return this._secretStorage.setDefaultKeyId(k);
};
/**
 * Checks that a given secret storage private key matches a given public key.
 * This can be used by the getSecretStorageKey callback to verify that the
 * private key it is about to supply is the one that was requested.
 *
 * @param {Uint8Array} privateKey The private key
 * @param {string} expectedPublicKey The public key
 * @returns {boolean} true if the key matches, otherwise false
 */


Crypto.prototype.checkSecretStoragePrivateKey = function (privateKey, expectedPublicKey) {
  let decryption = null;

  try {
    decryption = new global.Olm.PkDecryption();
    const gotPubkey = decryption.init_with_private_key(privateKey); // make sure it agrees with the given pubkey

    return gotPubkey === expectedPublicKey;
  } finally {
    if (decryption) decryption.free();
  }
};
/**
 * Checks that a given cross-signing private key matches a given public key.
 * This can be used by the getCrossSigningKey callback to verify that the
 * private key it is about to supply is the one that was requested.
 *
 * @param {Uint8Array} privateKey The private key
 * @param {string} expectedPublicKey The public key
 * @returns {boolean} true if the key matches, otherwise false
 */


Crypto.prototype.checkCrossSigningPrivateKey = function (privateKey, expectedPublicKey) {
  let signing = null;

  try {
    signing = new global.Olm.PkSigning();
    const gotPubkey = signing.init_with_seed(privateKey); // make sure it agrees with the given pubkey

    return gotPubkey === expectedPublicKey;
  } finally {
    if (signing) signing.free();
  }
};
/**
 * Generate new cross-signing keys.
 *
 * @param {CrossSigningLevel} [level] the level of cross-signing to reset.  New
 * keys will be created for the given level and below.  Defaults to
 * regenerating all keys.
 * @param {function} [opts.authUploadDeviceSigningKeys] Optional. Function
 * called to await an interactive auth flow when uploading device signing keys.
 * Args:
 *     {function} A function that makes the request requiring auth. Receives the
 *     auth data as an object.
 */


Crypto.prototype.resetCrossSigningKeys = async function (level, {
  authUploadDeviceSigningKeys = async func => await func()
} = {}) {
  _logger.logger.info(`Resetting cross-signing keys at level ${level}`); // Copy old keys (usually empty) in case we need to revert


  const oldKeys = Object.assign({}, this._crossSigningInfo.keys);

  try {
    await this._crossSigningInfo.resetKeys(level);
    await this._signObject(this._crossSigningInfo.keys.master); // send keys to server first before storing as trusted locally
    // to ensure upload succeeds

    const keys = {};

    for (const [name, key] of Object.entries(this._crossSigningInfo.keys)) {
      keys[name + "_key"] = key;
    }

    await authUploadDeviceSigningKeys(async authDict => {
      await this._baseApis.uploadDeviceSigningKeys(authDict, keys);
    }); // write a copy locally so we know these are trusted keys

    await this._cryptoStore.doTxn('readwrite', [_indexeddbCryptoStore.IndexedDBCryptoStore.STORE_ACCOUNT], txn => {
      this._cryptoStore.storeCrossSigningKeys(txn, this._crossSigningInfo.keys);
    });
  } catch (e) {
    // If anything failed here, revert the keys so we know to try again from the start
    // next time.
    _logger.logger.error("Resetting cross-signing keys failed, revert to previous keys", e);

    this._crossSigningInfo.keys = oldKeys;
    throw e;
  }

  this._baseApis.emit("crossSigning.keysChanged", {});

  await this._afterCrossSigningLocalKeyChange();

  _logger.logger.info("Cross-signing key reset complete");
};
/**
 * Run various follow-up actions after cross-signing keys have changed locally
 * (either by resetting the keys for the account or by getting them from secret
 * storage), such as signing the current device, upgrading device
 * verifications, etc.
 */


Crypto.prototype._afterCrossSigningLocalKeyChange = async function () {
  // sign the current device with the new key, and upload to the server
  const device = this._deviceList.getStoredDevice(this._userId, this._deviceId);

  const signedDevice = await this._crossSigningInfo.signDevice(this._userId, device);
  await this._baseApis.uploadKeySignatures({
    [this._userId]: {
      [this._deviceId]: signedDevice
    }
  }); // check all users for signatures
  // FIXME: do this in batches

  const users = {};

  for (const [userId, crossSigningInfo] of Object.entries(this._deviceList._crossSigningInfo)) {
    const upgradeInfo = await this._checkForDeviceVerificationUpgrade(userId, _CrossSigning.CrossSigningInfo.fromStorage(crossSigningInfo, userId));

    if (upgradeInfo) {
      users[userId] = upgradeInfo;
    }
  }

  const shouldUpgradeCb = this._baseApis._cryptoCallbacks.shouldUpgradeDeviceVerifications;

  if (Object.keys(users).length > 0 && shouldUpgradeCb) {
    try {
      const usersToUpgrade = await shouldUpgradeCb({
        users: users
      });

      if (usersToUpgrade) {
        for (const userId of usersToUpgrade) {
          if (userId in users) {
            await this._baseApis.setDeviceVerified(userId, users[userId].crossSigningInfo.getId());
          }
        }
      }
    } catch (e) {
      _logger.logger.log("shouldUpgradeDeviceVerifications threw an error: not upgrading", e);
    }
  }
};
/**
 * Check if a user's cross-signing key is a candidate for upgrading from device
 * verification.
 *
 * @param {string} userId the user whose cross-signing information is to be checked
 * @param {object} crossSigningInfo the cross-signing information to check
 */


Crypto.prototype._checkForDeviceVerificationUpgrade = async function (userId, crossSigningInfo) {
  // only upgrade if this is the first cross-signing key that we've seen for
  // them, and if their cross-signing key isn't already verified
  const trustLevel = this._crossSigningInfo.checkUserTrust(crossSigningInfo);

  if (crossSigningInfo.firstUse && !trustLevel.verified) {
    const devices = this._deviceList.getRawStoredDevicesForUser(userId);

    const deviceIds = await this._checkForValidDeviceSignature(userId, crossSigningInfo.keys.master, devices);

    if (deviceIds.length) {
      return {
        devices: deviceIds.map(deviceId => _deviceinfo.DeviceInfo.fromStorage(devices[deviceId], deviceId)),
        crossSigningInfo
      };
    }
  }
};
/**
 * Check if the cross-signing key is signed by a verified device.
 *
 * @param {string} userId the user ID whose key is being checked
 * @param {object} key the key that is being checked
 * @param {object} devices the user's devices.  Should be a map from device ID
 *     to device info
 */


Crypto.prototype._checkForValidDeviceSignature = async function (userId, key, devices) {
  const deviceIds = [];

  if (devices && key.signatures && key.signatures[userId]) {
    for (const signame of Object.keys(key.signatures[userId])) {
      const [, deviceId] = signame.split(':', 2);

      if (deviceId in devices && devices[deviceId].verified === DeviceVerification.VERIFIED) {
        try {
          await olmlib.verifySignature(this._olmDevice, key, userId, deviceId, devices[deviceId].keys[signame]);
          deviceIds.push(deviceId);
        } catch (e) {}
      }
    }
  }

  return deviceIds;
};
/**
 * Get the user's cross-signing key ID.
 *
 * @param {string} [type=master] The type of key to get the ID of.  One of
 *     "master", "self_signing", or "user_signing".  Defaults to "master".
 *
 * @returns {string} the key ID
 */


Crypto.prototype.getCrossSigningId = function (type) {
  return this._crossSigningInfo.getId(type);
};
/**
 * Get the cross signing information for a given user.
 *
 * @param {string} userId the user ID to get the cross-signing info for.
 *
 * @returns {CrossSigningInfo} the cross signing informmation for the user.
 */


Crypto.prototype.getStoredCrossSigningForUser = function (userId) {
  return this._deviceList.getStoredCrossSigningForUser(userId);
};
/**
 * Check whether a given user is trusted.
 *
 * @param {string} userId The ID of the user to check.
 *
 * @returns {UserTrustLevel}
 */


Crypto.prototype.checkUserTrust = function (userId) {
  const userCrossSigning = this._deviceList.getStoredCrossSigningForUser(userId);

  if (!userCrossSigning) {
    return new _CrossSigning.UserTrustLevel(false, false);
  }

  return this._crossSigningInfo.checkUserTrust(userCrossSigning);
};
/**
 * Check whether a given device is trusted.
 *
 * @param {string} userId The ID of the user whose devices is to be checked.
 * @param {string} deviceId The ID of the device to check
 *
 * @returns {DeviceTrustLevel}
 */


Crypto.prototype.checkDeviceTrust = function (userId, deviceId) {
  const device = this._deviceList.getStoredDevice(userId, deviceId);

  const trustedLocally = device && device.isVerified();

  const userCrossSigning = this._deviceList.getStoredCrossSigningForUser(userId);

  if (device && userCrossSigning) {
    return this._crossSigningInfo.checkDeviceTrust(userCrossSigning, device, trustedLocally);
  } else {
    return new _CrossSigning.DeviceTrustLevel(false, false, trustedLocally);
  }
};
/*
 * Event handler for DeviceList's userNewDevices event
 */


Crypto.prototype._onDeviceListUserCrossSigningUpdated = async function (userId) {
  if (userId === this._userId) {
    // An update to our own cross-signing key.
    // Get the new key first:
    const newCrossSigning = this._deviceList.getStoredCrossSigningForUser(userId);

    const seenPubkey = newCrossSigning ? newCrossSigning.getId() : null;

    const currentPubkey = this._crossSigningInfo.getId();

    const changed = currentPubkey !== seenPubkey;

    if (currentPubkey && seenPubkey && !changed) {
      // If it's not changed, just make sure everything is up to date
      await this.checkOwnCrossSigningTrust();
    } else {
      this.emit("crossSigning.keysChanged", {}); // We'll now be in a state where cross-signing on the account is not trusted
      // because our locally stored cross-signing keys will not match the ones
      // on the server for our account. The app must call checkOwnCrossSigningTrust()
      // to fix this.
      // XXX: Do we need to do something to emit events saying every device has become
      // untrusted?
    }
  } else {
    await this._checkDeviceVerifications(userId);
    this.emit("userTrustStatusChanged", userId, this.checkUserTrust(userId));
  }
};
/**
 * Check the copy of our cross-signing key that we have in the device list and
 * see if we can get the private key. If so, mark it as trusted.
 */


Crypto.prototype.checkOwnCrossSigningTrust = async function () {
  const userId = this._userId; // Before proceeding, ensure our cross-signing public keys have been
  // downloaded via the device list.

  await this.downloadKeys([this._userId]); // If we see an update to our own master key, check it against the master
  // key we have and, if it matches, mark it as verified
  // First, get the new cross-signing info

  const newCrossSigning = this._deviceList.getStoredCrossSigningForUser(userId);

  if (!newCrossSigning) {
    _logger.logger.error("Got cross-signing update event for user " + userId + " but no new cross-signing information found!");

    return;
  }

  const seenPubkey = newCrossSigning.getId();
  const masterChanged = this._crossSigningInfo.getId() !== seenPubkey;

  if (masterChanged) {
    // try to get the private key if the master key changed
    _logger.logger.info("Got new master public key", seenPubkey);

    let signing = null;

    try {
      const ret = await this._crossSigningInfo.getCrossSigningKey('master', seenPubkey);
      signing = ret[1];

      if (!signing) {
        throw new Error("Cross-signing master private key not available");
      }
    } finally {
      if (signing) signing.free();
    }

    _logger.logger.info("Got matching private key from callback for new public master key");
  }

  const oldSelfSigningId = this._crossSigningInfo.getId("self_signing");

  const oldUserSigningId = this._crossSigningInfo.getId("user_signing"); // Update the version of our keys in our cross-signing object and the local store


  this._storeTrustedSelfKeys(newCrossSigning.keys);

  const keySignatures = {};

  if (oldSelfSigningId !== newCrossSigning.getId("self_signing")) {
    _logger.logger.info("Got new self-signing key", newCrossSigning.getId("self_signing"));

    const device = this._deviceList.getStoredDevice(this._userId, this._deviceId);

    const signedDevice = await this._crossSigningInfo.signDevice(this._userId, device);
    keySignatures[this._deviceId] = signedDevice;
  }

  if (oldUserSigningId !== newCrossSigning.getId("user_signing")) {
    _logger.logger.info("Got new user-signing key", newCrossSigning.getId("user_signing"));
  }

  if (masterChanged) {
    await this._signObject(this._crossSigningInfo.keys.master);
    keySignatures[this._crossSigningInfo.getId()] = this._crossSigningInfo.keys.master;
  }

  if (Object.keys(keySignatures).length) {
    await this._baseApis.uploadKeySignatures({
      [this._userId]: keySignatures
    });
  }

  this.emit("userTrustStatusChanged", userId, this.checkUserTrust(userId));

  if (masterChanged) {
    this._baseApis.emit("crossSigning.keysChanged", {});

    await this._afterCrossSigningLocalKeyChange();
  } // Now we may be able to trust our key backup


  await this.checkKeyBackup(); // FIXME: if we previously trusted the backup, should we automatically sign
  // the backup with the new key (if not already signed)?
};
/**
 * Store a set of keys as our own, trusted, cross-signing keys.
 *
 * @param {object} keys The new trusted set of keys
 */


Crypto.prototype._storeTrustedSelfKeys = async function (keys) {
  this._crossSigningInfo.setKeys(keys);

  await this._cryptoStore.doTxn('readwrite', [_indexeddbCryptoStore.IndexedDBCryptoStore.STORE_ACCOUNT], txn => {
    this._cryptoStore.storeCrossSigningKeys(txn, this._crossSigningInfo.keys);
  });
};
/**
 * Check if the master key is signed by a verified device, and if so, prompt
 * the application to mark it as verified.
 *
 * @param {string} userId the user ID whose key should be checked
 */


Crypto.prototype._checkDeviceVerifications = async function (userId) {
  if (this._crossSigningInfo.keys.user_signing) {
    const crossSigningInfo = this._deviceList.getStoredCrossSigningForUser(userId);

    if (crossSigningInfo) {
      const upgradeInfo = await this._checkForDeviceVerificationUpgrade(userId, crossSigningInfo);
      const shouldUpgradeCb = this._baseApis._cryptoCallbacks.shouldUpgradeDeviceVerifications;

      if (upgradeInfo && shouldUpgradeCb) {
        const usersToUpgrade = await shouldUpgradeCb({
          users: {
            [userId]: upgradeInfo
          }
        });

        if (usersToUpgrade.includes(userId)) {
          await this._baseApis.setDeviceVerified(userId, crossSigningInfo.getId());
        }
      }
    }
  }
};
/**
 * Check the server for an active key backup and
 * if one is present and has a valid signature from
 * one of the user's verified devices, start backing up
 * to it.
 */


Crypto.prototype._checkAndStartKeyBackup = async function () {
  _logger.logger.log("Checking key backup status...");

  if (this._baseApis.isGuest()) {
    _logger.logger.log("Skipping key backup check since user is guest");

    this._checkedForBackup = true;
    return null;
  }

  let backupInfo;

  try {
    backupInfo = await this._baseApis.getKeyBackupVersion();
  } catch (e) {
    _logger.logger.log("Error checking for active key backup", e);

    if (e.httpStatus / 100 === 4) {
      // well that's told us. we won't try again.
      this._checkedForBackup = true;
    }

    return null;
  }

  this._checkedForBackup = true;
  const trustInfo = await this.isKeyBackupTrusted(backupInfo);

  if (trustInfo.usable && !this.backupInfo) {
    _logger.logger.log("Found usable key backup v" + backupInfo.version + ": enabling key backups");

    this._baseApis.enableKeyBackup(backupInfo);
  } else if (!trustInfo.usable && this.backupInfo) {
    _logger.logger.log("No usable key backup: disabling key backup");

    this._baseApis.disableKeyBackup();
  } else if (!trustInfo.usable && !this.backupInfo) {
    _logger.logger.log("No usable key backup: not enabling key backup");
  } else if (trustInfo.usable && this.backupInfo) {
    // may not be the same version: if not, we should switch
    if (backupInfo.version !== this.backupInfo.version) {
      _logger.logger.log("On backup version " + this.backupInfo.version + " but found " + "version " + backupInfo.version + ": switching.");

      this._baseApis.disableKeyBackup();

      this._baseApis.enableKeyBackup(backupInfo);
    } else {
      _logger.logger.log("Backup version " + backupInfo.version + " still current");
    }
  }

  return {
    backupInfo,
    trustInfo
  };
};

Crypto.prototype.setTrustedBackupPubKey = async function (trustedPubKey) {
  // This should be redundant post cross-signing is a thing, so just
  // plonk it in localStorage for now.
  this._sessionStore.setLocalTrustedBackupPubKey(trustedPubKey);

  await this.checkKeyBackup();
};
/**
 * Forces a re-check of the key backup and enables/disables it
 * as appropriate.
 *
 * @return {Object} Object with backup info (as returned by
 *     getKeyBackupVersion) in backupInfo and
 *     trust information (as returned by isKeyBackupTrusted)
 *     in trustInfo.
 */


Crypto.prototype.checkKeyBackup = async function () {
  this._checkedForBackup = false;
  return this._checkAndStartKeyBackup();
};
/**
 * @param {object} backupInfo key backup info dict from /room_keys/version
 * @return {object} {
 *     usable: [bool], // is the backup trusted, true iff there is a sig that is valid & from a trusted device
 *     sigs: [
 *         valid: [bool || null], // true: valid, false: invalid, null: cannot attempt validation
 *         deviceId: [string],
 *         device: [DeviceInfo || null],
 *     ]
 * }
 */


Crypto.prototype.isKeyBackupTrusted = async function (backupInfo) {
  const ret = {
    usable: false,
    trusted_locally: false,
    sigs: []
  };

  if (!backupInfo || !backupInfo.algorithm || !backupInfo.auth_data || !backupInfo.auth_data.public_key || !backupInfo.auth_data.signatures) {
    _logger.logger.info("Key backup is absent or missing required data");

    return ret;
  }

  const trustedPubkey = this._sessionStore.getLocalTrustedBackupPubKey();

  if (backupInfo.auth_data.public_key === trustedPubkey) {
    _logger.logger.info("Backup public key " + trustedPubkey + " is trusted locally");

    ret.trusted_locally = true;
  }

  const mySigs = backupInfo.auth_data.signatures[this._userId] || [];

  for (const keyId of Object.keys(mySigs)) {
    const keyIdParts = keyId.split(':');

    if (keyIdParts[0] !== 'ed25519') {
      _logger.logger.log("Ignoring unknown signature type: " + keyIdParts[0]);

      continue;
    } // Could be a cross-signing master key, but just say this is the device
    // ID for backwards compat


    const sigInfo = {
      deviceId: keyIdParts[1]
    }; // first check to see if it's from our cross-signing key

    const crossSigningId = this._crossSigningInfo.getId();

    if (crossSigningId === sigInfo.deviceId) {
      sigInfo.crossSigningId = true;

      try {
        await olmlib.verifySignature(this._olmDevice, backupInfo.auth_data, this._userId, sigInfo.deviceId, crossSigningId);
        sigInfo.valid = true;
      } catch (e) {
        _logger.logger.warning("Bad signature from cross signing key " + crossSigningId, e);

        sigInfo.valid = false;
      }

      ret.sigs.push(sigInfo);
      continue;
    } // Now look for a sig from a device
    // At some point this can probably go away and we'll just support
    // it being signed by the cross-signing master key


    const device = this._deviceList.getStoredDevice(this._userId, sigInfo.deviceId);

    if (device) {
      sigInfo.device = device;
      sigInfo.deviceTrust = await this.checkDeviceTrust(this._userId, sigInfo.deviceId);

      try {
        await olmlib.verifySignature(this._olmDevice, backupInfo.auth_data, this._userId, device.deviceId, device.getFingerprint());
        sigInfo.valid = true;
      } catch (e) {
        _logger.logger.info("Bad signature from key ID " + keyId + " userID " + this._userId + " device ID " + device.deviceId + " fingerprint: " + device.getFingerprint(), backupInfo.auth_data, e);

        sigInfo.valid = false;
      }
    } else {
      sigInfo.valid = null; // Can't determine validity because we don't have the signing device

      _logger.logger.info("Ignoring signature from unknown key " + keyId);
    }

    ret.sigs.push(sigInfo);
  }

  ret.usable = ret.sigs.some(s => {
    return s.valid && (s.device && s.deviceTrust.isVerified() || s.crossSigningId);
  });
  ret.usable |= ret.trusted_locally;
  return ret;
};
/**
 */


Crypto.prototype.enableLazyLoading = function () {
  this._lazyLoadMembers = true;
};
/**
 * Tell the crypto module to register for MatrixClient events which it needs to
 * listen for
 *
 * @param {external:EventEmitter} eventEmitter event source where we can register
 *    for event notifications
 */


Crypto.prototype.registerEventHandlers = function (eventEmitter) {
  const crypto = this;
  eventEmitter.on("RoomMember.membership", function (event, member, oldMembership) {
    try {
      crypto._onRoomMembership(event, member, oldMembership);
    } catch (e) {
      _logger.logger.error("Error handling membership change:", e);
    }
  });
  eventEmitter.on("toDeviceEvent", crypto._onToDeviceEvent.bind(crypto));

  const timelineHandler = crypto._onTimelineEvent.bind(crypto);

  eventEmitter.on("Room.timeline", timelineHandler);
  eventEmitter.on("Event.decrypted", timelineHandler);
};
/** Start background processes related to crypto */


Crypto.prototype.start = function () {
  this._outgoingRoomKeyRequestManager.start();
};
/** Stop background processes related to crypto */


Crypto.prototype.stop = function () {
  this._outgoingRoomKeyRequestManager.stop();

  this._deviceList.stop();
};
/**
 * @return {string} The version of Olm.
 */


Crypto.getOlmVersion = function () {
  return _OlmDevice.OlmDevice.getOlmVersion();
};
/**
 * Get the Ed25519 key for this device
 *
 * @return {string} base64-encoded ed25519 key.
 */


Crypto.prototype.getDeviceEd25519Key = function () {
  return this._olmDevice.deviceEd25519Key;
};
/**
 * Get the Curve25519 key for this device
 *
 * @return {string} base64-encoded curve25519 key.
 */


Crypto.prototype.getDeviceCurve25519Key = function () {
  return this._olmDevice.deviceCurve25519Key;
};
/**
 * Set the global override for whether the client should ever send encrypted
 * messages to unverified devices.  This provides the default for rooms which
 * do not specify a value.
 *
 * @param {boolean} value whether to blacklist all unverified devices by default
 */


Crypto.prototype.setGlobalBlacklistUnverifiedDevices = function (value) {
  this._globalBlacklistUnverifiedDevices = value;
};
/**
 * @return {boolean} whether to blacklist all unverified devices by default
 */


Crypto.prototype.getGlobalBlacklistUnverifiedDevices = function () {
  return this._globalBlacklistUnverifiedDevices;
};
/**
 * Set whether sendMessage in a room with unknown and unverified devices
 * should throw an error and not send them message. This has 'Global' for
 * symmertry with setGlobalBlacklistUnverifiedDevices but there is currently
 * no room-level equivalent for this setting.
 *
 * This API is currently UNSTABLE and may change or be removed without notice.
 *
 * @param {boolean} value whether error on unknown devices
 */


Crypto.prototype.setGlobalErrorOnUnknownDevices = function (value) {
  this._globalErrorOnUnknownDevices = value;
};
/**
 * @return {boolean} whether to error on unknown devices
 *
 * This API is currently UNSTABLE and may change or be removed without notice.
 */


Crypto.prototype.getGlobalErrorOnUnknownDevices = function () {
  return this._globalErrorOnUnknownDevices;
};
/**
 * Upload the device keys to the homeserver.
 * @return {object} A promise that will resolve when the keys are uploaded.
 */


Crypto.prototype.uploadDeviceKeys = function () {
  const crypto = this;
  const userId = crypto._userId;
  const deviceId = crypto._deviceId;
  const deviceKeys = {
    algorithms: crypto._supportedAlgorithms,
    device_id: deviceId,
    keys: crypto._deviceKeys,
    user_id: userId
  };
  return crypto._signObject(deviceKeys).then(() => {
    return crypto._baseApis.uploadKeysRequest({
      device_keys: deviceKeys
    });
  });
};
/**
 * Stores the current one_time_key count which will be handled later (in a call of
 * onSyncCompleted). The count is e.g. coming from a /sync response.
 *
 * @param {Number} currentCount The current count of one_time_keys to be stored
 */


Crypto.prototype.updateOneTimeKeyCount = function (currentCount) {
  if (isFinite(currentCount)) {
    this._oneTimeKeyCount = currentCount;
  } else {
    throw new TypeError("Parameter for updateOneTimeKeyCount has to be a number");
  }
}; // check if it's time to upload one-time keys, and do so if so.


function _maybeUploadOneTimeKeys(crypto) {
  // frequency with which to check & upload one-time keys
  const uploadPeriod = 1000 * 60; // one minute
  // max number of keys to upload at once
  // Creating keys can be an expensive operation so we limit the
  // number we generate in one go to avoid blocking the application
  // for too long.

  const maxKeysPerCycle = 5;

  if (crypto._oneTimeKeyCheckInProgress) {
    return;
  }

  const now = Date.now();

  if (crypto._lastOneTimeKeyCheck !== null && now - crypto._lastOneTimeKeyCheck < uploadPeriod) {
    // we've done a key upload recently.
    return;
  }

  crypto._lastOneTimeKeyCheck = now; // We need to keep a pool of one time public keys on the server so that
  // other devices can start conversations with us. But we can only store
  // a finite number of private keys in the olm Account object.
  // To complicate things further then can be a delay between a device
  // claiming a public one time key from the server and it sending us a
  // message. We need to keep the corresponding private key locally until
  // we receive the message.
  // But that message might never arrive leaving us stuck with duff
  // private keys clogging up our local storage.
  // So we need some kind of enginering compromise to balance all of
  // these factors.
  // Check how many keys we can store in the Account object.

  const maxOneTimeKeys = crypto._olmDevice.maxNumberOfOneTimeKeys(); // Try to keep at most half that number on the server. This leaves the
  // rest of the slots free to hold keys that have been claimed from the
  // server but we haven't recevied a message for.
  // If we run out of slots when generating new keys then olm will
  // discard the oldest private keys first. This will eventually clean
  // out stale private keys that won't receive a message.


  const keyLimit = Math.floor(maxOneTimeKeys / 2);

  function uploadLoop(keyCount) {
    if (keyLimit <= keyCount) {
      // If we don't need to generate any more keys then we are done.
      return Promise.resolve();
    }

    const keysThisLoop = Math.min(keyLimit - keyCount, maxKeysPerCycle); // Ask olm to generate new one time keys, then upload them to synapse.

    return crypto._olmDevice.generateOneTimeKeys(keysThisLoop).then(() => {
      return _uploadOneTimeKeys(crypto);
    }).then(res => {
      if (res.one_time_key_counts && res.one_time_key_counts.signed_curve25519) {
        // if the response contains a more up to date value use this
        // for the next loop
        return uploadLoop(res.one_time_key_counts.signed_curve25519);
      } else {
        throw new Error("response for uploading keys does not contain " + "one_time_key_counts.signed_curve25519");
      }
    });
  }

  crypto._oneTimeKeyCheckInProgress = true;
  Promise.resolve().then(() => {
    if (crypto._oneTimeKeyCount !== undefined) {
      // We already have the current one_time_key count from a /sync response.
      // Use this value instead of asking the server for the current key count.
      return Promise.resolve(crypto._oneTimeKeyCount);
    } // ask the server how many keys we have


    return crypto._baseApis.uploadKeysRequest({}).then(res => {
      return res.one_time_key_counts.signed_curve25519 || 0;
    });
  }).then(keyCount => {
    // Start the uploadLoop with the current keyCount. The function checks if
    // we need to upload new keys or not.
    // If there are too many keys on the server then we don't need to
    // create any more keys.
    return uploadLoop(keyCount);
  }).catch(e => {
    _logger.logger.error("Error uploading one-time keys", e.stack || e);
  }).finally(() => {
    // reset _oneTimeKeyCount to prevent start uploading based on old data.
    // it will be set again on the next /sync-response
    crypto._oneTimeKeyCount = undefined;
    crypto._oneTimeKeyCheckInProgress = false;
  });
} // returns a promise which resolves to the response


async function _uploadOneTimeKeys(crypto) {
  const oneTimeKeys = await crypto._olmDevice.getOneTimeKeys();
  const oneTimeJson = {};
  const promises = [];

  for (const keyId in oneTimeKeys.curve25519) {
    if (oneTimeKeys.curve25519.hasOwnProperty(keyId)) {
      const k = {
        key: oneTimeKeys.curve25519[keyId]
      };
      oneTimeJson["signed_curve25519:" + keyId] = k;
      promises.push(crypto._signObject(k));
    }
  }

  await Promise.all(promises);
  const res = await crypto._baseApis.uploadKeysRequest({
    one_time_keys: oneTimeJson
  });
  await crypto._olmDevice.markKeysAsPublished();
  return res;
}
/**
 * Download the keys for a list of users and stores the keys in the session
 * store.
 * @param {Array} userIds The users to fetch.
 * @param {bool} forceDownload Always download the keys even if cached.
 *
 * @return {Promise} A promise which resolves to a map userId->deviceId->{@link
 * module:crypto/deviceinfo|DeviceInfo}.
 */


Crypto.prototype.downloadKeys = function (userIds, forceDownload) {
  return this._deviceList.downloadKeys(userIds, forceDownload);
};
/**
 * Get the stored device keys for a user id
 *
 * @param {string} userId the user to list keys for.
 *
 * @return {module:crypto/deviceinfo[]|null} list of devices, or null if we haven't
 * managed to get a list of devices for this user yet.
 */


Crypto.prototype.getStoredDevicesForUser = function (userId) {
  return this._deviceList.getStoredDevicesForUser(userId);
};
/**
 * Get the stored keys for a single device
 *
 * @param {string} userId
 * @param {string} deviceId
 *
 * @return {module:crypto/deviceinfo?} device, or undefined
 * if we don't know about this device
 */


Crypto.prototype.getStoredDevice = function (userId, deviceId) {
  return this._deviceList.getStoredDevice(userId, deviceId);
};
/**
 * Save the device list, if necessary
 *
 * @param {integer} delay Time in ms before which the save actually happens.
 *     By default, the save is delayed for a short period in order to batch
 *     multiple writes, but this behaviour can be disabled by passing 0.
 *
 * @return {Promise<bool>} true if the data was saved, false if
 *     it was not (eg. because no changes were pending). The promise
 *     will only resolve once the data is saved, so may take some time
 *     to resolve.
 */


Crypto.prototype.saveDeviceList = function (delay) {
  return this._deviceList.saveIfDirty(delay);
};
/**
 * Update the blocked/verified state of the given device
 *
 * @param {string} userId owner of the device
 * @param {string} deviceId unique identifier for the device or user's
 * cross-signing public key ID.
 *
 * @param {?boolean} verified whether to mark the device as verified. Null to
 *     leave unchanged.
 *
 * @param {?boolean} blocked whether to mark the device as blocked. Null to
 *      leave unchanged.
 *
 * @param {?boolean} known whether to mark that the user has been made aware of
 *      the existence of this device. Null to leave unchanged
 *
 * @return {Promise<module:crypto/deviceinfo>} updated DeviceInfo
 */


Crypto.prototype.setDeviceVerification = async function (userId, deviceId, verified, blocked, known) {
  // get rid of any `undefined`s here so we can just check
  // for null rather than null or undefined
  if (verified === undefined) verified = null;
  if (blocked === undefined) blocked = null;
  if (known === undefined) known = null; // Check if the 'device' is actually a cross signing key
  // The js-sdk's verification treats cross-signing keys as devices
  // and so uses this method to mark them verified.

  const xsk = this._deviceList.getStoredCrossSigningForUser(userId);

  if (xsk && xsk.getId() === deviceId) {
    if (blocked !== null || known !== null) {
      throw new Error("Cannot set blocked or known for a cross-signing key");
    }

    if (!verified) {
      throw new Error("Cannot set a cross-signing key as unverified");
    }

    if (!this._crossSigningInfo.getId() && userId === this._crossSigningInfo.userId) {
      this._storeTrustedSelfKeys(xsk.keys);
    } // Now sign the master key with our user signing key (unless it's ourself)


    if (userId !== this._userId) {
      _logger.logger.info("Master key " + xsk.getId() + " for " + userId + " marked verified. Signing...");

      const device = await this._crossSigningInfo.signUser(xsk);

      if (device) {
        _logger.logger.info("Uploading signature for " + userId + "...");

        await this._baseApis.uploadKeySignatures({
          [userId]: {
            [deviceId]: device
          }
        }); // This will emit events when it comes back down the sync
        // (we could do local echo to speed things up)
      }

      return device;
    } else {
      return xsk;
    }
  }

  const devices = this._deviceList.getRawStoredDevicesForUser(userId);

  if (!devices || !devices[deviceId]) {
    throw new Error("Unknown device " + userId + ":" + deviceId);
  }

  const dev = devices[deviceId];
  let verificationStatus = dev.verified;

  if (verified) {
    verificationStatus = DeviceVerification.VERIFIED;
  } else if (verified !== null && verificationStatus == DeviceVerification.VERIFIED) {
    verificationStatus = DeviceVerification.UNVERIFIED;
  }

  if (blocked) {
    verificationStatus = DeviceVerification.BLOCKED;
  } else if (blocked !== null && verificationStatus == DeviceVerification.BLOCKED) {
    verificationStatus = DeviceVerification.UNVERIFIED;
  }

  let knownStatus = dev.known;

  if (known !== null) {
    knownStatus = known;
  }

  if (dev.verified !== verificationStatus || dev.known !== knownStatus) {
    dev.verified = verificationStatus;
    dev.known = knownStatus;

    this._deviceList.storeDevicesForUser(userId, devices);

    this._deviceList.saveIfDirty();
  } // do cross-signing


  if (verified && userId === this._userId) {
    _logger.logger.info("Own device " + deviceId + " marked verified: signing");

    const device = await this._crossSigningInfo.signDevice(userId, _deviceinfo.DeviceInfo.fromStorage(dev, deviceId));

    if (device) {
      _logger.logger.info("Uploading signature for " + deviceId);

      await this._baseApis.uploadKeySignatures({
        [userId]: {
          [deviceId]: device
        }
      }); // XXX: we'll need to wait for the device list to be updated
    }
  }

  const deviceObj = _deviceinfo.DeviceInfo.fromStorage(dev, deviceId);

  this.emit("deviceVerificationChanged", userId, deviceId, deviceObj);
  return deviceObj;
};

Crypto.prototype.findVerificationRequestDMInProgress = function (roomId) {
  return this._inRoomVerificationRequests.findRequestInProgress(roomId);
};

Crypto.prototype.requestVerificationDM = function (userId, roomId) {
  const existingRequest = this._inRoomVerificationRequests.findRequestInProgress(roomId);

  if (existingRequest) {
    return Promise.resolve(existingRequest);
  }

  const channel = new _InRoomChannel.InRoomChannel(this._baseApis, roomId, userId);
  return this._requestVerificationWithChannel(userId, channel, this._inRoomVerificationRequests);
};

Crypto.prototype.requestVerification = function (userId, devices) {
  if (!devices) {
    devices = Object.keys(this._deviceList.getRawStoredDevicesForUser(userId));
  }

  const existingRequest = this._toDeviceVerificationRequests.findRequestInProgress(userId, devices);

  if (existingRequest) {
    return Promise.resolve(existingRequest);
  }

  const channel = new _ToDeviceChannel.ToDeviceChannel(this._baseApis, userId, devices);
  return this._requestVerificationWithChannel(userId, channel, this._toDeviceVerificationRequests);
};

Crypto.prototype._requestVerificationWithChannel = async function (userId, channel, requestsMap) {
  let request = new _VerificationRequest.VerificationRequest(channel, this._verificationMethods, this._baseApis);
  await request.sendRequest(); // don't replace the request created by a racing remote echo

  const racingRequest = requestsMap.getRequestByChannel(channel);

  if (racingRequest) {
    request = racingRequest;
  } else {
    _logger.logger.log(`Crypto: adding new request to ` + `requestsByTxnId with id ${channel.transactionId} ${channel.roomId}`);

    requestsMap.setRequestByChannel(channel, request);
  }

  return request;
};

Crypto.prototype.beginKeyVerification = function (method, userId, deviceId, transactionId = null) {
  let request;

  if (transactionId) {
    request = this._toDeviceVerificationRequests.getRequestBySenderAndTxnId(userId, transactionId);

    if (!request) {
      throw new Error(`No request found for user ${userId} with ` + `transactionId ${transactionId}`);
    }
  } else {
    transactionId = _ToDeviceChannel.ToDeviceChannel.makeTransactionId();
    const channel = new _ToDeviceChannel.ToDeviceChannel(this._baseApis, userId, [deviceId], transactionId, deviceId);
    request = new _VerificationRequest.VerificationRequest(channel, this._verificationMethods, this._baseApis);

    this._toDeviceVerificationRequests.setRequestBySenderAndTxnId(userId, transactionId, request);
  }

  return request.beginKeyVerification(method, {
    userId,
    deviceId
  });
};
/**
 * Get information on the active olm sessions with a user
 * <p>
 * Returns a map from device id to an object with keys 'deviceIdKey' (the
 * device's curve25519 identity key) and 'sessions' (an array of objects in the
 * same format as that returned by
 * {@link module:crypto/OlmDevice#getSessionInfoForDevice}).
 * <p>
 * This method is provided for debugging purposes.
 *
 * @param {string} userId id of user to inspect
 *
 * @return {Promise<Object.<string, {deviceIdKey: string, sessions: object[]}>>}
 */


Crypto.prototype.getOlmSessionsForUser = async function (userId) {
  const devices = this.getStoredDevicesForUser(userId) || [];
  const result = {};

  for (let j = 0; j < devices.length; ++j) {
    const device = devices[j];
    const deviceKey = device.getIdentityKey();
    const sessions = await this._olmDevice.getSessionInfoForDevice(deviceKey);
    result[device.deviceId] = {
      deviceIdKey: deviceKey,
      sessions: sessions
    };
  }

  return result;
};
/**
 * Get the device which sent an event
 *
 * @param {module:models/event.MatrixEvent} event event to be checked
 *
 * @return {module:crypto/deviceinfo?}
 */


Crypto.prototype.getEventSenderDeviceInfo = function (event) {
  const senderKey = event.getSenderKey();
  const algorithm = event.getWireContent().algorithm;

  if (!senderKey || !algorithm) {
    return null;
  }

  const forwardingChain = event.getForwardingCurve25519KeyChain();

  if (forwardingChain.length > 0) {
    // we got this event from somewhere else
    // TODO: check if we can trust the forwarders.
    return null;
  } // senderKey is the Curve25519 identity key of the device which the event
  // was sent from. In the case of Megolm, it's actually the Curve25519
  // identity key of the device which set up the Megolm session.


  const device = this._deviceList.getDeviceByIdentityKey(algorithm, senderKey);

  if (device === null) {
    // we haven't downloaded the details of this device yet.
    return null;
  } // so far so good, but now we need to check that the sender of this event
  // hadn't advertised someone else's Curve25519 key as their own. We do that
  // by checking the Ed25519 claimed by the event (or, in the case of megolm,
  // the event which set up the megolm session), to check that it matches the
  // fingerprint of the purported sending device.
  //
  // (see https://github.com/vector-im/vector-web/issues/2215)


  const claimedKey = event.getClaimedEd25519Key();

  if (!claimedKey) {
    _logger.logger.warn("Event " + event.getId() + " claims no ed25519 key: " + "cannot verify sending device");

    return null;
  }

  if (claimedKey !== device.getFingerprint()) {
    _logger.logger.warn("Event " + event.getId() + " claims ed25519 key " + claimedKey + "but sender device has key " + device.getFingerprint());

    return null;
  }

  return device;
};
/**
 * Forces the current outbound group session to be discarded such
 * that another one will be created next time an event is sent.
 *
 * @param {string} roomId The ID of the room to discard the session for
 *
 * This should not normally be necessary.
 */


Crypto.prototype.forceDiscardSession = function (roomId) {
  const alg = this._roomEncryptors[roomId];
  if (alg === undefined) throw new Error("Room not encrypted");

  if (alg.forceDiscardSession === undefined) {
    throw new Error("Room encryption algorithm doesn't support session discarding");
  }

  alg.forceDiscardSession();
};
/**
 * Configure a room to use encryption (ie, save a flag in the cryptoStore).
 *
 * @param {string} roomId The room ID to enable encryption in.
 *
 * @param {object} config The encryption config for the room.
 *
 * @param {boolean=} inhibitDeviceQuery true to suppress device list query for
 *   users in the room (for now). In case lazy loading is enabled,
 *   the device query is always inhibited as the members are not tracked.
 */


Crypto.prototype.setRoomEncryption = async function (roomId, config, inhibitDeviceQuery) {
  // ignore crypto events with no algorithm defined
  // This will happen if a crypto event is redacted before we fetch the room state
  // It would otherwise just throw later as an unknown algorithm would, but we may
  // as well catch this here
  if (!config.algorithm) {
    _logger.logger.log("Ignoring setRoomEncryption with no algorithm");

    return;
  } // if state is being replayed from storage, we might already have a configuration
  // for this room as they are persisted as well.
  // We just need to make sure the algorithm is initialized in this case.
  // However, if the new config is different,
  // we should bail out as room encryption can't be changed once set.


  const existingConfig = this._roomList.getRoomEncryption(roomId);

  if (existingConfig) {
    if (JSON.stringify(existingConfig) != JSON.stringify(config)) {
      _logger.logger.error("Ignoring m.room.encryption event which requests " + "a change of config in " + roomId);

      return;
    }
  } // if we already have encryption in this room, we should ignore this event,
  // as it would reset the encryption algorithm.
  // This is at least expected to be called twice, as sync calls onCryptoEvent
  // for both the timeline and state sections in the /sync response,
  // the encryption event would appear in both.
  // If it's called more than twice though,
  // it signals a bug on client or server.


  const existingAlg = this._roomEncryptors[roomId];

  if (existingAlg) {
    return;
  } // _roomList.getRoomEncryption will not race with _roomList.setRoomEncryption
  // because it first stores in memory. We should await the promise only
  // after all the in-memory state (_roomEncryptors and _roomList) has been updated
  // to avoid races when calling this method multiple times. Hence keep a hold of the promise.


  let storeConfigPromise = null;

  if (!existingConfig) {
    storeConfigPromise = this._roomList.setRoomEncryption(roomId, config);
  }

  const AlgClass = algorithms.ENCRYPTION_CLASSES[config.algorithm];

  if (!AlgClass) {
    throw new Error("Unable to encrypt with " + config.algorithm);
  }

  const alg = new AlgClass({
    userId: this._userId,
    deviceId: this._deviceId,
    crypto: this,
    olmDevice: this._olmDevice,
    baseApis: this._baseApis,
    roomId: roomId,
    config: config
  });
  this._roomEncryptors[roomId] = alg;

  if (storeConfigPromise) {
    await storeConfigPromise;
  }

  if (!this._lazyLoadMembers) {
    _logger.logger.log("Enabling encryption in " + roomId + "; " + "starting to track device lists for all users therein");

    await this.trackRoomDevices(roomId); // TODO: this flag is only not used from MatrixClient::setRoomEncryption
    // which is never used (inside riot at least)
    // but didn't want to remove it as it technically would
    // be a breaking change.

    if (!this.inhibitDeviceQuery) {
      this._deviceList.refreshOutdatedDeviceLists();
    }
  } else {
    _logger.logger.log("Enabling encryption in " + roomId);
  }
};
/**
 * Make sure we are tracking the device lists for all users in this room.
 *
 * @param {string} roomId The room ID to start tracking devices in.
 * @returns {Promise} when all devices for the room have been fetched and marked to track
 */


Crypto.prototype.trackRoomDevices = function (roomId) {
  const trackMembers = async () => {
    // not an encrypted room
    if (!this._roomEncryptors[roomId]) {
      return;
    }

    const room = this._clientStore.getRoom(roomId);

    if (!room) {
      throw new Error(`Unable to start tracking devices in unknown room ${roomId}`);
    }

    _logger.logger.log(`Starting to track devices for room ${roomId} ...`);

    const members = await room.getEncryptionTargetMembers();
    members.forEach(m => {
      this._deviceList.startTrackingDeviceList(m.userId);
    });
  };

  let promise = this._roomDeviceTrackingState[roomId];

  if (!promise) {
    promise = trackMembers();
    this._roomDeviceTrackingState[roomId] = promise;
  }

  return promise;
};
/**
 * @typedef {Object} module:crypto~OlmSessionResult
 * @property {module:crypto/deviceinfo} device  device info
 * @property {string?} sessionId base64 olm session id; null if no session
 *    could be established
 */

/**
 * Try to make sure we have established olm sessions for all known devices for
 * the given users.
 *
 * @param {string[]} users list of user ids
 *
 * @return {Promise} resolves once the sessions are complete, to
 *    an Object mapping from userId to deviceId to
 *    {@link module:crypto~OlmSessionResult}
 */


Crypto.prototype.ensureOlmSessionsForUsers = function (users) {
  const devicesByUser = {};

  for (let i = 0; i < users.length; ++i) {
    const userId = users[i];
    devicesByUser[userId] = [];
    const devices = this.getStoredDevicesForUser(userId) || [];

    for (let j = 0; j < devices.length; ++j) {
      const deviceInfo = devices[j];
      const key = deviceInfo.getIdentityKey();

      if (key == this._olmDevice.deviceCurve25519Key) {
        // don't bother setting up session to ourself
        continue;
      }

      if (deviceInfo.verified == DeviceVerification.BLOCKED) {
        // don't bother setting up sessions with blocked users
        continue;
      }

      devicesByUser[userId].push(deviceInfo);
    }
  }

  return olmlib.ensureOlmSessionsForDevices(this._olmDevice, this._baseApis, devicesByUser);
};
/**
 * Get a list containing all of the room keys
 *
 * @return {module:crypto/OlmDevice.MegolmSessionData[]} a list of session export objects
 */


Crypto.prototype.exportRoomKeys = async function () {
  const exportedSessions = [];
  await this._cryptoStore.doTxn('readonly', [_indexeddbCryptoStore.IndexedDBCryptoStore.STORE_INBOUND_GROUP_SESSIONS], txn => {
    this._cryptoStore.getAllEndToEndInboundGroupSessions(txn, s => {
      if (s === null) return;

      const sess = this._olmDevice.exportInboundGroupSession(s.senderKey, s.sessionId, s.sessionData);

      delete sess.first_known_index;
      sess.algorithm = olmlib.MEGOLM_ALGORITHM;
      exportedSessions.push(sess);
    });
  });
  return exportedSessions;
};
/**
 * Import a list of room keys previously exported by exportRoomKeys
 *
 * @param {Object[]} keys a list of session export objects
 * @return {Promise} a promise which resolves once the keys have been imported
 */


Crypto.prototype.importRoomKeys = function (keys) {
  return Promise.all(keys.map(key => {
    if (!key.room_id || !key.algorithm) {
      _logger.logger.warn("ignoring room key entry with missing fields", key);

      return null;
    }

    const alg = this._getRoomDecryptor(key.room_id, key.algorithm);

    return alg.importRoomKey(key);
  }));
};
/**
 * Schedules sending all keys waiting to be sent to the backup, if not already
 * scheduled. Retries if necessary.
 *
 * @param {number} maxDelay Maximum delay to wait in ms. 0 means no delay.
 */


Crypto.prototype.scheduleKeyBackupSend = async function (maxDelay = 10000) {
  if (this._sendingBackups) return;
  this._sendingBackups = true;

  try {
    // wait between 0 and `maxDelay` seconds, to avoid backup
    // requests from different clients hitting the server all at
    // the same time when a new key is sent
    const delay = Math.random() * maxDelay;
    await (0, utils.sleep)(delay);
    let numFailures = 0; // number of consecutive failures

    while (1) {
      if (!this.backupKey) {
        return;
      }

      try {
        const numBackedUp = await this._backupPendingKeys(KEY_BACKUP_KEYS_PER_REQUEST);

        if (numBackedUp === 0) {
          // no sessions left needing backup: we're done
          return;
        }

        numFailures = 0;
      } catch (err) {
        numFailures++;

        _logger.logger.log("Key backup request failed", err);

        if (err.data) {
          if (err.data.errcode == 'M_NOT_FOUND' || err.data.errcode == 'M_WRONG_ROOM_KEYS_VERSION') {
            // Re-check key backup status on error, so we can be
            // sure to present the current situation when asked.
            await this.checkKeyBackup(); // Backup version has changed or this backup version
            // has been deleted

            this.emit("crypto.keyBackupFailed", err.data.errcode);
            throw err;
          }
        }
      }

      if (numFailures) {
        // exponential backoff if we have failures
        await (0, utils.sleep)(1000 * Math.pow(2, Math.min(numFailures - 1, 4)));
      }
    }
  } finally {
    this._sendingBackups = false;
  }
};
/**
 * Take some e2e keys waiting to be backed up and send them
 * to the backup.
 *
 * @param {integer} limit Maximum number of keys to back up
 * @returns {integer} Number of sessions backed up
 */


Crypto.prototype._backupPendingKeys = async function (limit) {
  const sessions = await this._cryptoStore.getSessionsNeedingBackup(limit);

  if (!sessions.length) {
    return 0;
  }

  let remaining = await this._cryptoStore.countSessionsNeedingBackup();
  this.emit("crypto.keyBackupSessionsRemaining", remaining);
  const data = {};

  for (const session of sessions) {
    const roomId = session.sessionData.room_id;

    if (data[roomId] === undefined) {
      data[roomId] = {
        sessions: {}
      };
    }

    const sessionData = await this._olmDevice.exportInboundGroupSession(session.senderKey, session.sessionId, session.sessionData);
    sessionData.algorithm = olmlib.MEGOLM_ALGORITHM;
    delete sessionData.session_id;
    delete sessionData.room_id;
    const firstKnownIndex = sessionData.first_known_index;
    delete sessionData.first_known_index;
    const encrypted = this.backupKey.encrypt(JSON.stringify(sessionData));
    const forwardedCount = (sessionData.forwarding_curve25519_key_chain || []).length;

    const device = this._deviceList.getDeviceByIdentityKey(olmlib.MEGOLM_ALGORITHM, session.senderKey);

    data[roomId]['sessions'][session.sessionId] = {
      first_message_index: firstKnownIndex,
      forwarded_count: forwardedCount,
      is_verified: !!(device && device.isVerified()),
      session_data: encrypted
    };
  }

  await this._baseApis.sendKeyBackup(undefined, undefined, this.backupInfo.version, {
    rooms: data
  });
  await this._cryptoStore.unmarkSessionsNeedingBackup(sessions);
  remaining = await this._cryptoStore.countSessionsNeedingBackup();
  this.emit("crypto.keyBackupSessionsRemaining", remaining);
  return sessions.length;
};

Crypto.prototype.backupGroupSession = async function (roomId, senderKey, forwardingCurve25519KeyChain, sessionId, sessionKey, keysClaimed, exportFormat) {
  if (!this.backupInfo) {
    throw new Error("Key backups are not enabled");
  }

  await this._cryptoStore.markSessionsNeedingBackup([{
    senderKey: senderKey,
    sessionId: sessionId
  }]); // don't wait for this to complete: it will delay so
  // happens in the background

  this.scheduleKeyBackupSend();
};
/**
 * Marks all group sessions as needing to be backed up and schedules them to
 * upload in the background as soon as possible.
 */


Crypto.prototype.scheduleAllGroupSessionsForBackup = async function () {
  await this.flagAllGroupSessionsForBackup(); // Schedule keys to upload in the background as soon as possible.

  this.scheduleKeyBackupSend(0
  /* maxDelay */
  );
};
/**
 * Marks all group sessions as needing to be backed up without scheduling
 * them to upload in the background.
 * @returns {Promise<int>} Resolves to the number of sessions requiring a backup.
 */


Crypto.prototype.flagAllGroupSessionsForBackup = async function () {
  await this._cryptoStore.doTxn('readwrite', [_indexeddbCryptoStore.IndexedDBCryptoStore.STORE_INBOUND_GROUP_SESSIONS, _indexeddbCryptoStore.IndexedDBCryptoStore.STORE_BACKUP], txn => {
    this._cryptoStore.getAllEndToEndInboundGroupSessions(txn, session => {
      if (session !== null) {
        this._cryptoStore.markSessionsNeedingBackup([session], txn);
      }
    });
  });
  const remaining = await this._cryptoStore.countSessionsNeedingBackup();
  this.emit("crypto.keyBackupSessionsRemaining", remaining);
  return remaining;
};
/* eslint-disable valid-jsdoc */
//https://github.com/eslint/eslint/issues/7307

/**
 * Encrypt an event according to the configuration of the room.
 *
 * @param {module:models/event.MatrixEvent} event  event to be sent
 *
 * @param {module:models/room} room destination room.
 *
 * @return {Promise?} Promise which resolves when the event has been
 *     encrypted, or null if nothing was needed
 */

/* eslint-enable valid-jsdoc */


Crypto.prototype.encryptEvent = async function (event, room) {
  if (!room) {
    throw new Error("Cannot send encrypted messages in unknown rooms");
  }

  const roomId = event.getRoomId();
  const alg = this._roomEncryptors[roomId];

  if (!alg) {
    // MatrixClient has already checked that this room should be encrypted,
    // so this is an unexpected situation.
    throw new Error("Room was previously configured to use encryption, but is " + "no longer. Perhaps the homeserver is hiding the " + "configuration event.");
  }

  if (!this._roomDeviceTrackingState[roomId]) {
    this.trackRoomDevices(roomId);
  } // wait for all the room devices to be loaded


  await this._roomDeviceTrackingState[roomId];
  let content = event.getContent(); // If event has an m.relates_to then we need
  // to put this on the wrapping event instead

  const mRelatesTo = content['m.relates_to'];

  if (mRelatesTo) {
    // Clone content here so we don't remove `m.relates_to` from the local-echo
    content = Object.assign({}, content);
    delete content['m.relates_to'];
  }

  const encryptedContent = await alg.encryptMessage(room, event.getType(), content);

  if (mRelatesTo) {
    encryptedContent['m.relates_to'] = mRelatesTo;
  }

  event.makeEncrypted("m.room.encrypted", encryptedContent, this._olmDevice.deviceCurve25519Key, this._olmDevice.deviceEd25519Key);
};
/**
 * Decrypt a received event
 *
 * @param {MatrixEvent} event
 *
 * @return {Promise<module:crypto~EventDecryptionResult>} resolves once we have
 *  finished decrypting. Rejects with an `algorithms.DecryptionError` if there
 *  is a problem decrypting the event.
 */


Crypto.prototype.decryptEvent = function (event) {
  if (event.isRedacted()) {
    return Promise.resolve({
      clearEvent: {
        room_id: event.getRoomId(),
        type: "m.room.message",
        content: {}
      }
    });
  }

  const content = event.getWireContent();

  const alg = this._getRoomDecryptor(event.getRoomId(), content.algorithm);

  return alg.decryptEvent(event);
};
/**
 * Handle the notification from /sync or /keys/changes that device lists have
 * been changed.
 *
 * @param {Object} syncData Object containing sync tokens associated with this sync
 * @param {Object} syncDeviceLists device_lists field from /sync, or response from
 * /keys/changes
 */


Crypto.prototype.handleDeviceListChanges = async function (syncData, syncDeviceLists) {
  // Initial syncs don't have device change lists. We'll either get the complete list
  // of changes for the interval or will have invalidated everything in willProcessSync
  if (!syncData.oldSyncToken) return; // Here, we're relying on the fact that we only ever save the sync data after
  // sucessfully saving the device list data, so we're guaranteed that the device
  // list store is at least as fresh as the sync token from the sync store, ie.
  // any device changes received in sync tokens prior to the 'next' token here
  // have been processed and are reflected in the current device list.
  // If we didn't make this assumption, we'd have to use the /keys/changes API
  // to get key changes between the sync token in the device list and the 'old'
  // sync token used here to make sure we didn't miss any.

  await this._evalDeviceListChanges(syncDeviceLists);
};
/**
 * Send a request for some room keys, if we have not already done so
 *
 * @param {module:crypto~RoomKeyRequestBody} requestBody
 * @param {Array<{userId: string, deviceId: string}>} recipients
 * @param {boolean} resend whether to resend the key request if there is
 *    already one
 *
 * @return {Promise} a promise that resolves when the key request is queued
 */


Crypto.prototype.requestRoomKey = function (requestBody, recipients, resend = false) {
  return this._outgoingRoomKeyRequestManager.sendRoomKeyRequest(requestBody, recipients, resend).catch(e => {
    // this normally means we couldn't talk to the store
    _logger.logger.error('Error requesting key for event', e);
  });
};
/**
 * Cancel any earlier room key request
 *
 * @param {module:crypto~RoomKeyRequestBody} requestBody
 *    parameters to match for cancellation
 */


Crypto.prototype.cancelRoomKeyRequest = function (requestBody) {
  this._outgoingRoomKeyRequestManager.cancelRoomKeyRequest(requestBody).catch(e => {
    _logger.logger.warn("Error clearing pending room key requests", e);
  });
};
/**
 * handle an m.room.encryption event
 *
 * @param {module:models/event.MatrixEvent} event encryption event
 */


Crypto.prototype.onCryptoEvent = async function (event) {
  const roomId = event.getRoomId();
  const content = event.getContent();

  try {
    // inhibit the device list refresh for now - it will happen once we've
    // finished processing the sync, in onSyncCompleted.
    await this.setRoomEncryption(roomId, content, true);
  } catch (e) {
    _logger.logger.error("Error configuring encryption in room " + roomId + ":", e);
  }
};
/**
 * Called before the result of a sync is procesed
 *
 * @param {Object} syncData  the data from the 'MatrixClient.sync' event
 */


Crypto.prototype.onSyncWillProcess = async function (syncData) {
  if (!syncData.oldSyncToken) {
    // If there is no old sync token, we start all our tracking from
    // scratch, so mark everything as untracked. onCryptoEvent will
    // be called for all e2e rooms during the processing of the sync,
    // at which point we'll start tracking all the users of that room.
    _logger.logger.log("Initial sync performed - resetting device tracking state");

    this._deviceList.stopTrackingAllDeviceLists(); // we always track our own device list (for key backups etc)


    this._deviceList.startTrackingDeviceList(this._userId);

    this._roomDeviceTrackingState = {};
  }
};
/**
 * handle the completion of a /sync
 *
 * This is called after the processing of each successful /sync response.
 * It is an opportunity to do a batch process on the information received.
 *
 * @param {Object} syncData  the data from the 'MatrixClient.sync' event
 */


Crypto.prototype.onSyncCompleted = async function (syncData) {
  const nextSyncToken = syncData.nextSyncToken;

  this._deviceList.setSyncToken(syncData.nextSyncToken);

  this._deviceList.saveIfDirty(); // catch up on any new devices we got told about during the sync.


  this._deviceList.lastKnownSyncToken = nextSyncToken; // we always track our own device list (for key backups etc)

  this._deviceList.startTrackingDeviceList(this._userId);

  this._deviceList.refreshOutdatedDeviceLists(); // we don't start uploading one-time keys until we've caught up with
  // to-device messages, to help us avoid throwing away one-time-keys that we
  // are about to receive messages for
  // (https://github.com/vector-im/riot-web/issues/2782).


  if (!syncData.catchingUp) {
    _maybeUploadOneTimeKeys(this);

    this._processReceivedRoomKeyRequests();
  }
};
/**
 * Trigger the appropriate invalidations and removes for a given
 * device list
 *
 * @param {Object} deviceLists device_lists field from /sync, or response from
 * /keys/changes
 */


Crypto.prototype._evalDeviceListChanges = async function (deviceLists) {
  if (deviceLists.changed && Array.isArray(deviceLists.changed)) {
    deviceLists.changed.forEach(u => {
      this._deviceList.invalidateUserDeviceList(u);
    });
  }

  if (deviceLists.left && Array.isArray(deviceLists.left) && deviceLists.left.length) {
    // Check we really don't share any rooms with these users
    // any more: the server isn't required to give us the
    // exact correct set.
    const e2eUserIds = new Set((await this._getTrackedE2eUsers()));
    deviceLists.left.forEach(u => {
      if (!e2eUserIds.has(u)) {
        this._deviceList.stopTrackingDeviceList(u);
      }
    });
  }
};
/**
 * Get a list of all the IDs of users we share an e2e room with
 * for which we are tracking devices already
 *
 * @returns {string[]} List of user IDs
 */


Crypto.prototype._getTrackedE2eUsers = async function () {
  const e2eUserIds = [];

  for (const room of this._getTrackedE2eRooms()) {
    const members = await room.getEncryptionTargetMembers();

    for (const member of members) {
      e2eUserIds.push(member.userId);
    }
  }

  return e2eUserIds;
};
/**
 * Get a list of the e2e-enabled rooms we are members of,
 * and for which we are already tracking the devices
 *
 * @returns {module:models.Room[]}
 */


Crypto.prototype._getTrackedE2eRooms = function () {
  return this._clientStore.getRooms().filter(room => {
    // check for rooms with encryption enabled
    const alg = this._roomEncryptors[room.roomId];

    if (!alg) {
      return false;
    }

    if (!this._roomDeviceTrackingState[room.roomId]) {
      return false;
    } // ignore any rooms which we have left


    const myMembership = room.getMyMembership();
    return myMembership === "join" || myMembership === "invite";
  });
};

Crypto.prototype._onToDeviceEvent = function (event) {
  try {
    _logger.logger.log(`received to_device ${event.getType()} from: ` + `${event.getSender()} id: ${event.getId()}`);

    if (event.getType() == "m.room_key" || event.getType() == "m.forwarded_room_key") {
      this._onRoomKeyEvent(event);
    } else if (event.getType() == "m.room_key_request") {
      this._onRoomKeyRequestEvent(event);
    } else if (event.getType() === "m.secret.request") {
      this._secretStorage._onRequestReceived(event);
    } else if (event.getType() === "m.secret.send") {
      this._secretStorage._onSecretReceived(event);
    } else if (event.getType() === "org.matrix.room_key.withheld") {
      this._onRoomKeyWithheldEvent(event);
    } else if (event.getContent().transaction_id) {
      this._onKeyVerificationMessage(event);
    } else if (event.getContent().msgtype === "m.bad.encrypted") {
      this._onToDeviceBadEncrypted(event);
    } else if (event.isBeingDecrypted()) {
      // once the event has been decrypted, try again
      event.once('Event.decrypted', ev => {
        this._onToDeviceEvent(ev);
      });
    }
  } catch (e) {
    _logger.logger.error("Error handling toDeviceEvent:", e);
  }
};
/**
 * Handle a key event
 *
 * @private
 * @param {module:models/event.MatrixEvent} event key event
 */


Crypto.prototype._onRoomKeyEvent = function (event) {
  const content = event.getContent();

  if (!content.room_id || !content.algorithm) {
    _logger.logger.error("key event is missing fields");

    return;
  }

  if (!this._checkedForBackup) {
    // don't bother awaiting on this - the important thing is that we retry if we
    // haven't managed to check before
    this._checkAndStartKeyBackup();
  }

  const alg = this._getRoomDecryptor(content.room_id, content.algorithm);

  alg.onRoomKeyEvent(event);
};
/**
 * Handle a key withheld event
 *
 * @private
 * @param {module:models/event.MatrixEvent} event key withheld event
 */


Crypto.prototype._onRoomKeyWithheldEvent = function (event) {
  const content = event.getContent();

  if (content.code !== "m.no_olm" && (!content.room_id || !content.session_id) || !content.algorithm || !content.sender_key) {
    _logger.logger.error("key withheld event is missing fields");

    return;
  }

  _logger.logger.info(`Got room key withheld event from ${event.getSender()} (${content.sender_key}) ` + `for ${content.algorithm}/${content.room_id}/${content.session_id} ` + `with reason ${content.code} (${content.reason})`);

  const alg = this._getRoomDecryptor(content.room_id, content.algorithm);

  if (alg.onRoomKeyWithheldEvent) {
    alg.onRoomKeyWithheldEvent(event);
  }

  if (!content.room_id) {
    // retry decryption for all events sent by the sender_key.  This will
    // update the events to show a message indicating that the olm session was
    // wedged.
    const roomDecryptors = this._getRoomDecryptors(content.algorithm);

    for (const decryptor of roomDecryptors) {
      decryptor.retryDecryptionFromSender(content.sender_key);
    }
  }
};
/**
 * Handle a general key verification event.
 *
 * @private
 * @param {module:models/event.MatrixEvent} event verification start event
 */


Crypto.prototype._onKeyVerificationMessage = function (event) {
  if (!_ToDeviceChannel.ToDeviceChannel.validateEvent(event, this._baseApis)) {
    return;
  }

  const createRequest = event => {
    if (!_ToDeviceChannel.ToDeviceChannel.canCreateRequest(_ToDeviceChannel.ToDeviceChannel.getEventType(event))) {
      return;
    }

    const content = event.getContent();
    const deviceId = content && content.from_device;

    if (!deviceId) {
      return;
    }

    const userId = event.getSender();
    const channel = new _ToDeviceChannel.ToDeviceChannel(this._baseApis, userId, [deviceId]);
    return new _VerificationRequest.VerificationRequest(channel, this._verificationMethods, this._baseApis);
  };

  this._handleVerificationEvent(event, this._toDeviceVerificationRequests, createRequest);
};
/**
 * Handle key verification requests sent as timeline events
 *
 * @private
 * @param {module:models/event.MatrixEvent} event the timeline event
 * @param {module:models/Room} room not used
 * @param {bool} atStart not used
 * @param {bool} removed not used
 * @param {bool} data.liveEvent whether this is a live event
 */


Crypto.prototype._onTimelineEvent = function (event, room, atStart, removed, {
  liveEvent
} = {}) {
  if (!_InRoomChannel.InRoomChannel.validateEvent(event, this._baseApis)) {
    return;
  }

  const createRequest = event => {
    const channel = new _InRoomChannel.InRoomChannel(this._baseApis, event.getRoomId());
    return new _VerificationRequest.VerificationRequest(channel, this._verificationMethods, this._baseApis);
  };

  this._handleVerificationEvent(event, this._inRoomVerificationRequests, createRequest, liveEvent);
};

Crypto.prototype._handleVerificationEvent = async function (event, requestsMap, createRequest, isLiveEvent = true) {
  let request = requestsMap.getRequest(event);
  let isNewRequest = false;

  if (!request) {
    request = createRequest(event); // a request could not be made from this event, so ignore event

    if (!request) {
      _logger.logger.log(`Crypto: could not find VerificationRequest for ` + `${event.getType()}, and could not create one, so ignoring.`);

      return;
    }

    isNewRequest = true;
    requestsMap.setRequest(event, request);
  }

  event.setVerificationRequest(request);

  try {
    const hadVerifier = !!request.verifier;
    await request.channel.handleEvent(event, request, isLiveEvent); // emit start event when verifier got set

    if (!hadVerifier && request.verifier) {
      this._baseApis.emit("crypto.verification.start", request.verifier);
    }
  } catch (err) {
    _logger.logger.error("error while handling verification event: " + err.message);
  }

  const shouldEmit = isNewRequest && !request.initiatedByMe && !request.invalid && // check it has enough events to pass the UNSENT stage
  !request.observeOnly;

  if (shouldEmit) {
    this._baseApis.emit("crypto.verification.request", request);
  }
};
/**
 * Handle a toDevice event that couldn't be decrypted
 *
 * @private
 * @param {module:models/event.MatrixEvent} event undecryptable event
 */


Crypto.prototype._onToDeviceBadEncrypted = async function (event) {
  const content = event.getWireContent();
  const sender = event.getSender();
  const algorithm = content.algorithm;
  const deviceKey = content.sender_key; // retry decryption for all events sent by the sender_key.  This will
  // update the events to show a message indicating that the olm session was
  // wedged.

  const retryDecryption = () => {
    const roomDecryptors = this._getRoomDecryptors(olmlib.MEGOLM_ALGORITHM);

    for (const decryptor of roomDecryptors) {
      decryptor.retryDecryptionFromSender(deviceKey);
    }
  };

  if (sender === undefined || deviceKey === undefined || deviceKey === undefined) {
    return;
  } // check when we last forced a new session with this device: if we've already done so
  // recently, don't do it again.


  this._lastNewSessionForced[sender] = this._lastNewSessionForced[sender] || {};
  const lastNewSessionForced = this._lastNewSessionForced[sender][deviceKey] || 0;

  if (lastNewSessionForced + MIN_FORCE_SESSION_INTERVAL_MS > Date.now()) {
    _logger.logger.debug("New session already forced with device " + sender + ":" + deviceKey + " at " + lastNewSessionForced + ": not forcing another");

    await this._olmDevice.recordSessionProblem(deviceKey, "wedged", true);
    retryDecryption();
    return;
  } // establish a new olm session with this device since we're failing to decrypt messages
  // on a current session.
  // Note that an undecryptable message from another device could easily be spoofed -
  // is there anything we can do to mitigate this?


  let device = this._deviceList.getDeviceByIdentityKey(algorithm, deviceKey);

  if (!device) {
    // if we don't know about the device, fetch the user's devices again
    // and retry before giving up
    await this.downloadKeys([sender], false);
    device = this._deviceList.getDeviceByIdentityKey(algorithm, deviceKey);

    if (!device) {
      _logger.logger.info("Couldn't find device for identity key " + deviceKey + ": not re-establishing session");

      await this._olmDevice.recordSessionProblem(deviceKey, "wedged", false);
      retryDecryption();
      return;
    }
  }

  const devicesByUser = {};
  devicesByUser[sender] = [device];
  await olmlib.ensureOlmSessionsForDevices(this._olmDevice, this._baseApis, devicesByUser, true);
  this._lastNewSessionForced[sender][deviceKey] = Date.now(); // Now send a blank message on that session so the other side knows about it.
  // (The keyshare request is sent in the clear so that won't do)
  // We send this first such that, as long as the toDevice messages arrive in the
  // same order we sent them, the other end will get this first, set up the new session,
  // then get the keyshare request and send the key over this new session (because it
  // is the session it has most recently received a message on).

  const encryptedContent = {
    algorithm: olmlib.OLM_ALGORITHM,
    sender_key: this._olmDevice.deviceCurve25519Key,
    ciphertext: {}
  };
  await olmlib.encryptMessageForDevice(encryptedContent.ciphertext, this._userId, this._deviceId, this._olmDevice, sender, device, {
    type: "m.dummy"
  });
  await this._olmDevice.recordSessionProblem(deviceKey, "wedged", true);
  retryDecryption();
  await this._baseApis.sendToDevice("m.room.encrypted", {
    [sender]: {
      [device.deviceId]: encryptedContent
    }
  }); // Most of the time this probably won't be necessary since we'll have queued up a key request when
  // we failed to decrypt the message and will be waiting a bit for the key to arrive before sending
  // it. This won't always be the case though so we need to re-send any that have already been sent
  // to avoid races.

  const requestsToResend = await this._outgoingRoomKeyRequestManager.getOutgoingSentRoomKeyRequest(sender, device.deviceId);

  for (const keyReq of requestsToResend) {
    this.requestRoomKey(keyReq.requestBody, keyReq.recipients, true);
  }
};
/**
 * Handle a change in the membership state of a member of a room
 *
 * @private
 * @param {module:models/event.MatrixEvent} event  event causing the change
 * @param {module:models/room-member} member  user whose membership changed
 * @param {string=} oldMembership  previous membership
 */


Crypto.prototype._onRoomMembership = function (event, member, oldMembership) {
  // this event handler is registered on the *client* (as opposed to the room
  // member itself), which means it is only called on changes to the *live*
  // membership state (ie, it is not called when we back-paginate, nor when
  // we load the state in the initialsync).
  //
  // Further, it is automatically registered and called when new members
  // arrive in the room.
  const roomId = member.roomId;
  const alg = this._roomEncryptors[roomId];

  if (!alg) {
    // not encrypting in this room
    return;
  } // only mark users in this room as tracked if we already started tracking in this room
  // this way we don't start device queries after sync on behalf of this room which we won't use
  // the result of anyway, as we'll need to do a query again once all the members are fetched
  // by calling _trackRoomDevices


  if (this._roomDeviceTrackingState[roomId]) {
    if (member.membership == 'join') {
      _logger.logger.log('Join event for ' + member.userId + ' in ' + roomId); // make sure we are tracking the deviceList for this user


      this._deviceList.startTrackingDeviceList(member.userId);
    } else if (member.membership == 'invite' && this._clientStore.getRoom(roomId).shouldEncryptForInvitedMembers()) {
      _logger.logger.log('Invite event for ' + member.userId + ' in ' + roomId);

      this._deviceList.startTrackingDeviceList(member.userId);
    }
  }

  alg.onRoomMembership(event, member, oldMembership);
};
/**
 * Called when we get an m.room_key_request event.
 *
 * @private
 * @param {module:models/event.MatrixEvent} event key request event
 */


Crypto.prototype._onRoomKeyRequestEvent = function (event) {
  const content = event.getContent();

  if (content.action === "request") {
    // Queue it up for now, because they tend to arrive before the room state
    // events at initial sync, and we want to see if we know anything about the
    // room before passing them on to the app.
    const req = new IncomingRoomKeyRequest(event);

    this._receivedRoomKeyRequests.push(req);
  } else if (content.action === "request_cancellation") {
    const req = new IncomingRoomKeyRequestCancellation(event);

    this._receivedRoomKeyRequestCancellations.push(req);
  }
};
/**
 * Process any m.room_key_request events which were queued up during the
 * current sync.
 *
 * @private
 */


Crypto.prototype._processReceivedRoomKeyRequests = async function () {
  if (this._processingRoomKeyRequests) {
    // we're still processing last time's requests; keep queuing new ones
    // up for now.
    return;
  }

  this._processingRoomKeyRequests = true;

  try {
    // we need to grab and clear the queues in the synchronous bit of this method,
    // so that we don't end up racing with the next /sync.
    const requests = this._receivedRoomKeyRequests;
    this._receivedRoomKeyRequests = [];
    const cancellations = this._receivedRoomKeyRequestCancellations;
    this._receivedRoomKeyRequestCancellations = []; // Process all of the requests, *then* all of the cancellations.
    //
    // This makes sure that if we get a request and its cancellation in the
    // same /sync result, then we process the request before the
    // cancellation (and end up with a cancelled request), rather than the
    // cancellation before the request (and end up with an outstanding
    // request which should have been cancelled.)

    await Promise.all(requests.map(req => this._processReceivedRoomKeyRequest(req)));
    await Promise.all(cancellations.map(cancellation => this._processReceivedRoomKeyRequestCancellation(cancellation)));
  } catch (e) {
    _logger.logger.error(`Error processing room key requsts: ${e}`);
  } finally {
    this._processingRoomKeyRequests = false;
  }
};
/**
 * Helper for processReceivedRoomKeyRequests
 *
 * @param {IncomingRoomKeyRequest} req
 */


Crypto.prototype._processReceivedRoomKeyRequest = async function (req) {
  const userId = req.userId;
  const deviceId = req.deviceId;
  const body = req.requestBody;
  const roomId = body.room_id;
  const alg = body.algorithm;

  _logger.logger.log(`m.room_key_request from ${userId}:${deviceId}` + ` for ${roomId} / ${body.session_id} (id ${req.requestId})`);

  if (userId !== this._userId) {
    if (!this._roomEncryptors[roomId]) {
      _logger.logger.debug(`room key request for unencrypted room ${roomId}`);

      return;
    }

    const encryptor = this._roomEncryptors[roomId];

    const device = this._deviceList.getStoredDevice(userId, deviceId);

    if (!device) {
      _logger.logger.debug(`Ignoring keyshare for unknown device ${userId}:${deviceId}`);

      return;
    }

    try {
      await encryptor.reshareKeyWithDevice(body.sender_key, body.session_id, userId, device);
    } catch (e) {
      _logger.logger.warn("Failed to re-share keys for session " + body.session_id + " with device " + userId + ":" + device.deviceId, e);
    }

    return;
  } // todo: should we queue up requests we don't yet have keys for,
  // in case they turn up later?
  // if we don't have a decryptor for this room/alg, we don't have
  // the keys for the requested events, and can drop the requests.


  if (!this._roomDecryptors[roomId]) {
    _logger.logger.log(`room key request for unencrypted room ${roomId}`);

    return;
  }

  const decryptor = this._roomDecryptors[roomId][alg];

  if (!decryptor) {
    _logger.logger.log(`room key request for unknown alg ${alg} in room ${roomId}`);

    return;
  }

  if (!(await decryptor.hasKeysForKeyRequest(req))) {
    _logger.logger.log(`room key request for unknown session ${roomId} / ` + body.session_id);

    return;
  }

  req.share = () => {
    decryptor.shareKeysWithDevice(req);
  }; // if the device is is verified already, share the keys


  const device = this._deviceList.getStoredDevice(userId, deviceId);

  if (device && device.isVerified()) {
    _logger.logger.log('device is already verified: sharing keys');

    req.share();
    return;
  }

  this.emit("crypto.roomKeyRequest", req);
};
/**
 * Helper for processReceivedRoomKeyRequests
 *
 * @param {IncomingRoomKeyRequestCancellation} cancellation
 */


Crypto.prototype._processReceivedRoomKeyRequestCancellation = async function (cancellation) {
  _logger.logger.log(`m.room_key_request cancellation for ${cancellation.userId}:` + `${cancellation.deviceId} (id ${cancellation.requestId})`); // we should probably only notify the app of cancellations we told it
  // about, but we don't currently have a record of that, so we just pass
  // everything through.


  this.emit("crypto.roomKeyRequestCancellation", cancellation);
};
/**
 * Get a decryptor for a given room and algorithm.
 *
 * If we already have a decryptor for the given room and algorithm, return
 * it. Otherwise try to instantiate it.
 *
 * @private
 *
 * @param {string?} roomId   room id for decryptor. If undefined, a temporary
 * decryptor is instantiated.
 *
 * @param {string} algorithm  crypto algorithm
 *
 * @return {module:crypto.algorithms.base.DecryptionAlgorithm}
 *
 * @raises {module:crypto.algorithms.DecryptionError} if the algorithm is
 * unknown
 */


Crypto.prototype._getRoomDecryptor = function (roomId, algorithm) {
  let decryptors;
  let alg;
  roomId = roomId || null;

  if (roomId) {
    decryptors = this._roomDecryptors[roomId];

    if (!decryptors) {
      this._roomDecryptors[roomId] = decryptors = {};
    }

    alg = decryptors[algorithm];

    if (alg) {
      return alg;
    }
  }

  const AlgClass = algorithms.DECRYPTION_CLASSES[algorithm];

  if (!AlgClass) {
    throw new algorithms.DecryptionError('UNKNOWN_ENCRYPTION_ALGORITHM', 'Unknown encryption algorithm "' + algorithm + '".');
  }

  alg = new AlgClass({
    userId: this._userId,
    crypto: this,
    olmDevice: this._olmDevice,
    baseApis: this._baseApis,
    roomId: roomId
  });

  if (decryptors) {
    decryptors[algorithm] = alg;
  }

  return alg;
};
/**
 * Get all the room decryptors for a given encryption algorithm.
 *
 * @param {string} algorithm The encryption algorithm
 *
 * @return {array} An array of room decryptors
 */


Crypto.prototype._getRoomDecryptors = function (algorithm) {
  const decryptors = [];

  for (const d of Object.values(this._roomDecryptors)) {
    if (algorithm in d) {
      decryptors.push(d[algorithm]);
    }
  }

  return decryptors;
};
/**
 * sign the given object with our ed25519 key
 *
 * @param {Object} obj  Object to which we will add a 'signatures' property
 */


Crypto.prototype._signObject = async function (obj) {
  const sigs = obj.signatures || {};
  const unsigned = obj.unsigned;
  delete obj.signatures;
  delete obj.unsigned;
  sigs[this._userId] = sigs[this._userId] || {};
  sigs[this._userId]["ed25519:" + this._deviceId] = await this._olmDevice.sign(_anotherJson.default.stringify(obj));
  obj.signatures = sigs;
  if (unsigned !== undefined) obj.unsigned = unsigned;
};
/**
 * The parameters of a room key request. The details of the request may
 * vary with the crypto algorithm, but the management and storage layers for
 * outgoing requests expect it to have 'room_id' and 'session_id' properties.
 *
 * @typedef {Object} RoomKeyRequestBody
 */

/**
 * Represents a received m.room_key_request event
 *
 * @property {string} userId    user requesting the key
 * @property {string} deviceId  device requesting the key
 * @property {string} requestId unique id for the request
 * @property {module:crypto~RoomKeyRequestBody} requestBody
 * @property {function()} share  callback which, when called, will ask
 *    the relevant crypto algorithm implementation to share the keys for
 *    this request.
 */


class IncomingRoomKeyRequest {
  constructor(event) {
    const content = event.getContent();
    this.userId = event.getSender();
    this.deviceId = content.requesting_device_id;
    this.requestId = content.request_id;
    this.requestBody = content.body || {};

    this.share = () => {
      throw new Error("don't know how to share keys for this request yet");
    };
  }

}
/**
 * Represents a received m.room_key_request cancellation
 *
 * @property {string} userId    user requesting the cancellation
 * @property {string} deviceId  device requesting the cancellation
 * @property {string} requestId unique id for the request to be cancelled
 */


class IncomingRoomKeyRequestCancellation {
  constructor(event) {
    const content = event.getContent();
    this.userId = event.getSender();
    this.deviceId = content.requesting_device_id;
    this.requestId = content.request_id;
  }

}
/**
 * The result of a (successful) call to decryptEvent.
 *
 * @typedef {Object} EventDecryptionResult
 *
 * @property {Object} clearEvent The plaintext payload for the event
 *     (typically containing <tt>type</tt> and <tt>content</tt> fields).
 *
 * @property {?string} senderCurve25519Key Key owned by the sender of this
 *    event.  See {@link module:models/event.MatrixEvent#getSenderKey}.
 *
 * @property {?string} claimedEd25519Key ed25519 key claimed by the sender of
 *    this event. See
 *    {@link module:models/event.MatrixEvent#getClaimedEd25519Key}.
 *
 * @property {?Array<string>} forwardingCurve25519KeyChain list of curve25519
 *     keys involved in telling us about the senderCurve25519Key and
 *     claimedEd25519Key. See
 *     {@link module:models/event.MatrixEvent#getForwardingCurve25519KeyChain}.
 */

/**
 * Fires when we receive a room key request
 *
 * @event module:client~MatrixClient#"crypto.roomKeyRequest"
 * @param {module:crypto~IncomingRoomKeyRequest} req  request details
 */

/**
 * Fires when we receive a room key request cancellation
 *
 * @event module:client~MatrixClient#"crypto.roomKeyRequestCancellation"
 * @param {module:crypto~IncomingRoomKeyRequestCancellation} req
 */

/**
 * Fires when the app may wish to warn the user about something related
 * the end-to-end crypto.
 *
 * @event module:client~MatrixClient#"crypto.warning"
 * @param {string} type One of the strings listed above
 */