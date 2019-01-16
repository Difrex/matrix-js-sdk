/*
Copyright 2016 OpenMarket Ltd
Copyright 2017 Vector Creations Ltd
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
"use strict";

/**
 * @module crypto
 */

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _classCallCheck2 = require('babel-runtime/helpers/classCallCheck');

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _getIterator2 = require('babel-runtime/core-js/get-iterator');

var _getIterator3 = _interopRequireDefault(_getIterator2);

var _set = require('babel-runtime/core-js/set');

var _set2 = _interopRequireDefault(_set);

var _assign = require('babel-runtime/core-js/object/assign');

var _assign2 = _interopRequireDefault(_assign);

var _stringify = require('babel-runtime/core-js/json/stringify');

var _stringify2 = _interopRequireDefault(_stringify);

var _bluebird = require('bluebird');

var _bluebird2 = _interopRequireDefault(_bluebird);

var _regenerator = require('babel-runtime/regenerator');

var _regenerator2 = _interopRequireDefault(_regenerator);

// returns a promise which resolves to the response
var _uploadOneTimeKeys = function () {
    var _ref2 = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee2(crypto) {
        var oneTimeKeys, oneTimeJson, promises, keyId, k, res;
        return _regenerator2.default.wrap(function _callee2$(_context2) {
            while (1) {
                switch (_context2.prev = _context2.next) {
                    case 0:
                        _context2.next = 2;
                        return (0, _bluebird.resolve)(crypto._olmDevice.getOneTimeKeys());

                    case 2:
                        oneTimeKeys = _context2.sent;
                        oneTimeJson = {};
                        promises = [];


                        for (keyId in oneTimeKeys.curve25519) {
                            if (oneTimeKeys.curve25519.hasOwnProperty(keyId)) {
                                k = {
                                    key: oneTimeKeys.curve25519[keyId]
                                };

                                oneTimeJson["signed_curve25519:" + keyId] = k;
                                promises.push(crypto._signObject(k));
                            }
                        }

                        _context2.next = 8;
                        return (0, _bluebird.resolve)(_bluebird2.default.all(promises));

                    case 8:
                        _context2.next = 10;
                        return (0, _bluebird.resolve)(crypto._baseApis.uploadKeysRequest({
                            one_time_keys: oneTimeJson
                        }, {
                            // for now, we set the device id explicitly, as we may not be using the
                            // same one as used in login.
                            device_id: crypto._deviceId
                        }));

                    case 10:
                        res = _context2.sent;
                        _context2.next = 13;
                        return (0, _bluebird.resolve)(crypto._olmDevice.markKeysAsPublished());

                    case 13:
                        return _context2.abrupt('return', res);

                    case 14:
                    case 'end':
                        return _context2.stop();
                }
            }
        }, _callee2, this);
    }));

    return function _uploadOneTimeKeys(_x) {
        return _ref2.apply(this, arguments);
    };
}();

/**
 * Download the keys for a list of users and stores the keys in the session
 * store.
 * @param {Array} userIds The users to fetch.
 * @param {bool} forceDownload Always download the keys even if cached.
 *
 * @return {Promise} A promise which resolves to a map userId->deviceId->{@link
 * module:crypto/deviceinfo|DeviceInfo}.
 */


exports.isCryptoAvailable = isCryptoAvailable;
exports.default = Crypto;

var _events = require('events');

var _OutgoingRoomKeyRequestManager = require('./OutgoingRoomKeyRequestManager');

var _OutgoingRoomKeyRequestManager2 = _interopRequireDefault(_OutgoingRoomKeyRequestManager);

var _indexeddbCryptoStore = require('./store/indexeddb-crypto-store');

var _indexeddbCryptoStore2 = _interopRequireDefault(_indexeddbCryptoStore);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var anotherjson = require('another-json');


var logger = require("../logger");
var utils = require("../utils");
var OlmDevice = require("./OlmDevice");
var olmlib = require("./olmlib");
var algorithms = require("./algorithms");
var DeviceInfo = require("./deviceinfo");
var DeviceVerification = DeviceInfo.DeviceVerification;
var DeviceList = require('./DeviceList').default;

function isCryptoAvailable() {
    return Boolean(global.Olm);
}

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
 */
function Crypto(baseApis, sessionStore, userId, deviceId, clientStore, cryptoStore, roomList) {
    this._baseApis = baseApis;
    this._sessionStore = sessionStore;
    this._userId = userId;
    this._deviceId = deviceId;
    this._clientStore = clientStore;
    this._cryptoStore = cryptoStore;
    this._roomList = roomList;

    this._olmDevice = new OlmDevice(sessionStore, cryptoStore);
    this._deviceList = new DeviceList(baseApis, cryptoStore, sessionStore, this._olmDevice);

    // the last time we did a check for the number of one-time-keys on the
    // server.
    this._lastOneTimeKeyCheck = null;
    this._oneTimeKeyCheckInProgress = false;

    // EncryptionAlgorithm instance for each room
    this._roomEncryptors = {};

    // map from algorithm to DecryptionAlgorithm instance, for each room
    this._roomDecryptors = {};

    this._supportedAlgorithms = utils.keys(algorithms.DECRYPTION_CLASSES);

    this._deviceKeys = {};

    this._globalBlacklistUnverifiedDevices = false;

    this._outgoingRoomKeyRequestManager = new _OutgoingRoomKeyRequestManager2.default(baseApis, this._deviceId, this._cryptoStore);

    // list of IncomingRoomKeyRequests/IncomingRoomKeyRequestCancellations
    // we received in the current sync.
    this._receivedRoomKeyRequests = [];
    this._receivedRoomKeyRequestCancellations = [];
    // true if we are currently processing received room key requests
    this._processingRoomKeyRequests = false;
    // controls whether device tracking is delayed
    // until calling encryptEvent or trackRoomDevices,
    // or done immediately upon enabling room encryption.
    this._lazyLoadMembers = false;
    // in case _lazyLoadMembers is true,
    // track if an initial tracking of all the room members
    // has happened for a given room. This is delayed
    // to avoid loading room members as long as possible.
    this._roomDeviceTrackingState = {};
}
utils.inherits(Crypto, _events.EventEmitter);

/**
 * Initialise the crypto module so that it is ready for use
 *
 * Returns a promise which resolves once the crypto module is ready for use.
 */
Crypto.prototype.init = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee() {
    var _this = this;

    var sessionStoreHasAccount, cryptoStoreHasAccount, myDevices, deviceInfo;
    return _regenerator2.default.wrap(function _callee$(_context) {
        while (1) {
            switch (_context.prev = _context.next) {
                case 0:
                    _context.next = 2;
                    return (0, _bluebird.resolve)(global.Olm.init());

                case 2:
                    sessionStoreHasAccount = Boolean(this._sessionStore.getEndToEndAccount());
                    cryptoStoreHasAccount = void 0;
                    _context.next = 6;
                    return (0, _bluebird.resolve)(this._cryptoStore.doTxn('readonly', [_indexeddbCryptoStore2.default.STORE_ACCOUNT], function (txn) {
                        _this._cryptoStore.getAccount(txn, function (pickledAccount) {
                            cryptoStoreHasAccount = Boolean(pickledAccount);
                        });
                    }));

                case 6:
                    if (sessionStoreHasAccount && !cryptoStoreHasAccount) {
                        // we're about to migrate to the crypto store
                        this.emit("crypto.warning", 'CRYPTO_WARNING_ACCOUNT_MIGRATED');
                    } else if (sessionStoreHasAccount && cryptoStoreHasAccount) {
                        // There's an account in both stores: an old version of
                        // the code has been run against this store.
                        this.emit("crypto.warning", 'CRYPTO_WARNING_OLD_VERSION_DETECTED');
                    }

                    _context.next = 9;
                    return (0, _bluebird.resolve)(this._olmDevice.init());

                case 9:
                    _context.next = 11;
                    return (0, _bluebird.resolve)(this._deviceList.load());

                case 11:

                    // build our device keys: these will later be uploaded
                    this._deviceKeys["ed25519:" + this._deviceId] = this._olmDevice.deviceEd25519Key;
                    this._deviceKeys["curve25519:" + this._deviceId] = this._olmDevice.deviceCurve25519Key;

                    myDevices = this._deviceList.getRawStoredDevicesForUser(this._userId);


                    if (!myDevices) {
                        myDevices = {};
                    }

                    if (!myDevices[this._deviceId]) {
                        // add our own deviceinfo to the sessionstore
                        deviceInfo = {
                            keys: this._deviceKeys,
                            algorithms: this._supportedAlgorithms,
                            verified: DeviceVerification.VERIFIED,
                            known: true
                        };


                        myDevices[this._deviceId] = deviceInfo;
                        this._deviceList.storeDevicesForUser(this._userId, myDevices);
                        this._deviceList.saveIfDirty();
                    }

                case 16:
                case 'end':
                    return _context.stop();
            }
        }
    }, _callee, this);
}));

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
    var crypto = this;

    eventEmitter.on("RoomMember.membership", function (event, member, oldMembership) {
        try {
            crypto._onRoomMembership(event, member, oldMembership);
        } catch (e) {
            logger.error("Error handling membership change:", e);
        }
    });

    eventEmitter.on("toDeviceEvent", function (event) {
        crypto._onToDeviceEvent(event);
    });
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
    return OlmDevice.getOlmVersion();
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
 * Upload the device keys to the homeserver.
 * @return {object} A promise that will resolve when the keys are uploaded.
 */
Crypto.prototype.uploadDeviceKeys = function () {
    var crypto = this;
    var userId = crypto._userId;
    var deviceId = crypto._deviceId;

    var deviceKeys = {
        algorithms: crypto._supportedAlgorithms,
        device_id: deviceId,
        keys: crypto._deviceKeys,
        user_id: userId
    };

    return crypto._signObject(deviceKeys).then(function () {
        crypto._baseApis.uploadKeysRequest({
            device_keys: deviceKeys
        }, {
            // for now, we set the device id explicitly, as we may not be using the
            // same one as used in login.
            device_id: deviceId
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
};

// check if it's time to upload one-time keys, and do so if so.
function _maybeUploadOneTimeKeys(crypto) {
    // frequency with which to check & upload one-time keys
    var uploadPeriod = 1000 * 60; // one minute

    // max number of keys to upload at once
    // Creating keys can be an expensive operation so we limit the
    // number we generate in one go to avoid blocking the application
    // for too long.
    var maxKeysPerCycle = 5;

    if (crypto._oneTimeKeyCheckInProgress) {
        return;
    }

    var now = Date.now();
    if (crypto._lastOneTimeKeyCheck !== null && now - crypto._lastOneTimeKeyCheck < uploadPeriod) {
        // we've done a key upload recently.
        return;
    }

    crypto._lastOneTimeKeyCheck = now;

    // We need to keep a pool of one time public keys on the server so that
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
    var maxOneTimeKeys = crypto._olmDevice.maxNumberOfOneTimeKeys();
    // Try to keep at most half that number on the server. This leaves the
    // rest of the slots free to hold keys that have been claimed from the
    // server but we haven't recevied a message for.
    // If we run out of slots when generating new keys then olm will
    // discard the oldest private keys first. This will eventually clean
    // out stale private keys that won't receive a message.
    var keyLimit = Math.floor(maxOneTimeKeys / 2);

    function uploadLoop(keyCount) {
        if (keyLimit <= keyCount) {
            // If we don't need to generate any more keys then we are done.
            return _bluebird2.default.resolve();
        }

        var keysThisLoop = Math.min(keyLimit - keyCount, maxKeysPerCycle);

        // Ask olm to generate new one time keys, then upload them to synapse.
        return crypto._olmDevice.generateOneTimeKeys(keysThisLoop).then(function () {
            return _uploadOneTimeKeys(crypto);
        }).then(function (res) {
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
    _bluebird2.default.resolve().then(function () {
        if (crypto._oneTimeKeyCount !== undefined) {
            // We already have the current one_time_key count from a /sync response.
            // Use this value instead of asking the server for the current key count.
            return _bluebird2.default.resolve(crypto._oneTimeKeyCount);
        }
        // ask the server how many keys we have
        return crypto._baseApis.uploadKeysRequest({}, {
            device_id: crypto._deviceId
        }).then(function (res) {
            return res.one_time_key_counts.signed_curve25519 || 0;
        });
    }).then(function (keyCount) {
        // Start the uploadLoop with the current keyCount. The function checks if
        // we need to upload new keys or not.
        // If there are too many keys on the server then we don't need to
        // create any more keys.
        return uploadLoop(keyCount);
    }).catch(function (e) {
        logger.error("Error uploading one-time keys", e.stack || e);
    }).finally(function () {
        // reset _oneTimeKeyCount to prevent start uploading based on old data.
        // it will be set again on the next /sync-response
        crypto._oneTimeKeyCount = undefined;
        crypto._oneTimeKeyCheckInProgress = false;
    }).done();
}Crypto.prototype.downloadKeys = function (userIds, forceDownload) {
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
 * @param {string} deviceId unique identifier for the device
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
Crypto.prototype.setDeviceVerification = function () {
    var _ref3 = (0, _bluebird.method)(function (userId, deviceId, verified, blocked, known) {
        var devices = this._deviceList.getRawStoredDevicesForUser(userId);
        if (!devices || !devices[deviceId]) {
            throw new Error("Unknown device " + userId + ":" + deviceId);
        }

        var dev = devices[deviceId];
        var verificationStatus = dev.verified;

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

        var knownStatus = dev.known;
        if (known !== null && known !== undefined) {
            knownStatus = known;
        }

        if (dev.verified !== verificationStatus || dev.known !== knownStatus) {
            dev.verified = verificationStatus;
            dev.known = knownStatus;
            this._deviceList.storeDevicesForUser(userId, devices);
            this._deviceList.saveIfDirty();
        }
        return DeviceInfo.fromStorage(dev, deviceId);
    });

    return function (_x2, _x3, _x4, _x5, _x6) {
        return _ref3.apply(this, arguments);
    };
}();

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
Crypto.prototype.getOlmSessionsForUser = function () {
    var _ref4 = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee3(userId) {
        var devices, result, j, device, deviceKey, sessions;
        return _regenerator2.default.wrap(function _callee3$(_context3) {
            while (1) {
                switch (_context3.prev = _context3.next) {
                    case 0:
                        devices = this.getStoredDevicesForUser(userId) || [];
                        result = {};
                        j = 0;

                    case 3:
                        if (!(j < devices.length)) {
                            _context3.next = 13;
                            break;
                        }

                        device = devices[j];
                        deviceKey = device.getIdentityKey();
                        _context3.next = 8;
                        return (0, _bluebird.resolve)(this._olmDevice.getSessionInfoForDevice(deviceKey));

                    case 8:
                        sessions = _context3.sent;


                        result[device.deviceId] = {
                            deviceIdKey: deviceKey,
                            sessions: sessions
                        };

                    case 10:
                        ++j;
                        _context3.next = 3;
                        break;

                    case 13:
                        return _context3.abrupt('return', result);

                    case 14:
                    case 'end':
                        return _context3.stop();
                }
            }
        }, _callee3, this);
    }));

    return function (_x7) {
        return _ref4.apply(this, arguments);
    };
}();

/**
 * Get the device which sent an event
 *
 * @param {module:models/event.MatrixEvent} event event to be checked
 *
 * @return {module:crypto/deviceinfo?}
 */
Crypto.prototype.getEventSenderDeviceInfo = function (event) {
    var senderKey = event.getSenderKey();
    var algorithm = event.getWireContent().algorithm;

    if (!senderKey || !algorithm) {
        return null;
    }

    var forwardingChain = event.getForwardingCurve25519KeyChain();
    if (forwardingChain.length > 0) {
        // we got this event from somewhere else
        // TODO: check if we can trust the forwarders.
        return null;
    }

    // senderKey is the Curve25519 identity key of the device which the event
    // was sent from. In the case of Megolm, it's actually the Curve25519
    // identity key of the device which set up the Megolm session.

    var device = this._deviceList.getDeviceByIdentityKey(event.getSender(), algorithm, senderKey);

    if (device === null) {
        // we haven't downloaded the details of this device yet.
        return null;
    }

    // so far so good, but now we need to check that the sender of this event
    // hadn't advertised someone else's Curve25519 key as their own. We do that
    // by checking the Ed25519 claimed by the event (or, in the case of megolm,
    // the event which set up the megolm session), to check that it matches the
    // fingerprint of the purported sending device.
    //
    // (see https://github.com/vector-im/vector-web/issues/2215)

    var claimedKey = event.getClaimedEd25519Key();
    if (!claimedKey) {
        logger.warn("Event " + event.getId() + " claims no ed25519 key: " + "cannot verify sending device");
        return null;
    }

    if (claimedKey !== device.getFingerprint()) {
        logger.warn("Event " + event.getId() + " claims ed25519 key " + claimedKey + "but sender device has key " + device.getFingerprint());
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
    var alg = this._roomEncryptors[roomId];
    if (alg === undefined) throw new Error("Room not encrypted");
    if (alg.forceDiscardSession === undefined) {
        throw new Error("Room encryption algorithm doesn't support session discarding");
    }
    alg.forceDiscardSession();
};

/**
 * Configure a room to use encryption (ie, save a flag in the sessionstore).
 *
 * @param {string} roomId The room ID to enable encryption in.
 *
 * @param {object} config The encryption config for the room.
 *
 * @param {boolean=} inhibitDeviceQuery true to suppress device list query for
 *   users in the room (for now). In case lazy loading is enabled,
 *   the device query is always inhibited as the members are not tracked.
 */
Crypto.prototype.setRoomEncryption = function () {
    var _ref5 = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee4(roomId, config, inhibitDeviceQuery) {
        var existingConfig, existingAlg, storeConfigPromise, AlgClass, alg;
        return _regenerator2.default.wrap(function _callee4$(_context4) {
            while (1) {
                switch (_context4.prev = _context4.next) {
                    case 0:
                        // if state is being replayed from storage, we might already have a configuration
                        // for this room as they are persisted as well.
                        // We just need to make sure the algorithm is initialized in this case.
                        // However, if the new config is different,
                        // we should bail out as room encryption can't be changed once set.
                        existingConfig = this._roomList.getRoomEncryption(roomId);

                        if (!existingConfig) {
                            _context4.next = 5;
                            break;
                        }

                        if (!((0, _stringify2.default)(existingConfig) != (0, _stringify2.default)(config))) {
                            _context4.next = 5;
                            break;
                        }

                        logger.error("Ignoring m.room.encryption event which requests " + "a change of config in " + roomId);
                        return _context4.abrupt('return');

                    case 5:
                        // if we already have encryption in this room, we should ignore this event,
                        // as it would reset the encryption algorithm.
                        // This is at least expected to be called twice, as sync calls onCryptoEvent
                        // for both the timeline and state sections in the /sync response,
                        // the encryption event would appear in both.
                        // If it's called more than twice though,
                        // it signals a bug on client or server.
                        existingAlg = this._roomEncryptors[roomId];

                        if (!existingAlg) {
                            _context4.next = 8;
                            break;
                        }

                        return _context4.abrupt('return');

                    case 8:

                        // _roomList.getRoomEncryption will not race with _roomList.setRoomEncryption
                        // because it first stores in memory. We should await the promise only
                        // after all the in-memory state (_roomEncryptors and _roomList) has been updated
                        // to avoid races when calling this method multiple times. Hence keep a hold of the promise.
                        storeConfigPromise = null;

                        if (!existingConfig) {
                            storeConfigPromise = this._roomList.setRoomEncryption(roomId, config);
                        }

                        AlgClass = algorithms.ENCRYPTION_CLASSES[config.algorithm];

                        if (AlgClass) {
                            _context4.next = 13;
                            break;
                        }

                        throw new Error("Unable to encrypt with " + config.algorithm);

                    case 13:
                        alg = new AlgClass({
                            userId: this._userId,
                            deviceId: this._deviceId,
                            crypto: this,
                            olmDevice: this._olmDevice,
                            baseApis: this._baseApis,
                            roomId: roomId,
                            config: config
                        });

                        this._roomEncryptors[roomId] = alg;

                        if (!storeConfigPromise) {
                            _context4.next = 18;
                            break;
                        }

                        _context4.next = 18;
                        return (0, _bluebird.resolve)(storeConfigPromise);

                    case 18:
                        if (this._lazyLoadMembers) {
                            _context4.next = 25;
                            break;
                        }

                        logger.log("Enabling encryption in " + roomId + "; " + "starting to track device lists for all users therein");

                        _context4.next = 22;
                        return (0, _bluebird.resolve)(this.trackRoomDevices(roomId));

                    case 22:
                        // TODO: this flag is only not used from MatrixClient::setRoomEncryption
                        // which is never used (inside riot at least)
                        // but didn't want to remove it as it technically would
                        // be a breaking change.
                        if (!this.inhibitDeviceQuery) {
                            this._deviceList.refreshOutdatedDeviceLists();
                        }
                        _context4.next = 26;
                        break;

                    case 25:
                        logger.log("Enabling encryption in " + roomId);

                    case 26:
                    case 'end':
                        return _context4.stop();
                }
            }
        }, _callee4, this);
    }));

    return function (_x8, _x9, _x10) {
        return _ref5.apply(this, arguments);
    };
}();

/**
 * Make sure we are tracking the device lists for all users in this room.
 *
 * @param {string} roomId The room ID to start tracking devices in.
 * @returns {Promise} when all devices for the room have been fetched and marked to track
 */
Crypto.prototype.trackRoomDevices = function (roomId) {
    var _this2 = this;

    var trackMembers = function () {
        var _ref6 = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee5() {
            var room, members;
            return _regenerator2.default.wrap(function _callee5$(_context5) {
                while (1) {
                    switch (_context5.prev = _context5.next) {
                        case 0:
                            if (_this2._roomEncryptors[roomId]) {
                                _context5.next = 2;
                                break;
                            }

                            return _context5.abrupt('return');

                        case 2:
                            room = _this2._clientStore.getRoom(roomId);

                            if (room) {
                                _context5.next = 5;
                                break;
                            }

                            throw new Error('Unable to start tracking devices in unknown room ' + roomId);

                        case 5:
                            logger.log('Starting to track devices for room ' + roomId + ' ...');
                            _context5.next = 8;
                            return (0, _bluebird.resolve)(room.getEncryptionTargetMembers());

                        case 8:
                            members = _context5.sent;

                            members.forEach(function (m) {
                                _this2._deviceList.startTrackingDeviceList(m.userId);
                            });

                        case 10:
                        case 'end':
                            return _context5.stop();
                    }
                }
            }, _callee5, _this2);
        }));

        return function trackMembers() {
            return _ref6.apply(this, arguments);
        };
    }();

    var promise = this._roomDeviceTrackingState[roomId];
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
 * @return {module:client.Promise} resolves once the sessions are complete, to
 *    an Object mapping from userId to deviceId to
 *    {@link module:crypto~OlmSessionResult}
 */
Crypto.prototype.ensureOlmSessionsForUsers = function (users) {
    var devicesByUser = {};

    for (var i = 0; i < users.length; ++i) {
        var userId = users[i];
        devicesByUser[userId] = [];

        var devices = this.getStoredDevicesForUser(userId) || [];
        for (var j = 0; j < devices.length; ++j) {
            var deviceInfo = devices[j];

            var key = deviceInfo.getIdentityKey();
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
Crypto.prototype.exportRoomKeys = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee6() {
    var _this3 = this;

    var exportedSessions;
    return _regenerator2.default.wrap(function _callee6$(_context6) {
        while (1) {
            switch (_context6.prev = _context6.next) {
                case 0:
                    exportedSessions = [];
                    _context6.next = 3;
                    return (0, _bluebird.resolve)(this._cryptoStore.doTxn('readonly', [_indexeddbCryptoStore2.default.STORE_INBOUND_GROUP_SESSIONS], function (txn) {
                        _this3._cryptoStore.getAllEndToEndInboundGroupSessions(txn, function (s) {
                            if (s === null) return;

                            var sess = _this3._olmDevice.exportInboundGroupSession(s.senderKey, s.sessionId, s.sessionData);
                            sess.algorithm = olmlib.MEGOLM_ALGORITHM;
                            exportedSessions.push(sess);
                        });
                    }));

                case 3:
                    return _context6.abrupt('return', exportedSessions);

                case 4:
                case 'end':
                    return _context6.stop();
            }
        }
    }, _callee6, this);
}));

/**
 * Import a list of room keys previously exported by exportRoomKeys
 *
 * @param {Object[]} keys a list of session export objects
 * @return {module:client.Promise} a promise which resolves once the keys have been imported
 */
Crypto.prototype.importRoomKeys = function (keys) {
    var _this4 = this;

    return _bluebird2.default.map(keys, function (key) {
        if (!key.room_id || !key.algorithm) {
            logger.warn("ignoring room key entry with missing fields", key);
            return null;
        }

        var alg = _this4._getRoomDecryptor(key.room_id, key.algorithm);
        return alg.importRoomKey(key);
    });
};
/* eslint-disable valid-jsdoc */ //https://github.com/eslint/eslint/issues/7307
/**
 * Encrypt an event according to the configuration of the room.
 *
 * @param {module:models/event.MatrixEvent} event  event to be sent
 *
 * @param {module:models/room} room destination room.
 *
 * @return {module:client.Promise?} Promise which resolves when the event has been
 *     encrypted, or null if nothing was needed
 */
/* eslint-enable valid-jsdoc */
Crypto.prototype.encryptEvent = function () {
    var _ref8 = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee7(event, room) {
        var roomId, alg, content, mRelatesTo, encryptedContent;
        return _regenerator2.default.wrap(function _callee7$(_context7) {
            while (1) {
                switch (_context7.prev = _context7.next) {
                    case 0:
                        if (room) {
                            _context7.next = 2;
                            break;
                        }

                        throw new Error("Cannot send encrypted messages in unknown rooms");

                    case 2:
                        roomId = event.getRoomId();
                        alg = this._roomEncryptors[roomId];

                        if (alg) {
                            _context7.next = 6;
                            break;
                        }

                        throw new Error("Room was previously configured to use encryption, but is " + "no longer. Perhaps the homeserver is hiding the " + "configuration event.");

                    case 6:

                        if (!this._roomDeviceTrackingState[roomId]) {
                            this.trackRoomDevices(roomId);
                        }
                        // wait for all the room devices to be loaded
                        _context7.next = 9;
                        return (0, _bluebird.resolve)(this._roomDeviceTrackingState[roomId]);

                    case 9:
                        content = event.getContent();
                        // If event has an m.relates_to then we need
                        // to put this on the wrapping event instead

                        mRelatesTo = content['m.relates_to'];

                        if (mRelatesTo) {
                            // Clone content here so we don't remove `m.relates_to` from the local-echo
                            content = (0, _assign2.default)({}, content);
                            delete content['m.relates_to'];
                        }

                        _context7.next = 14;
                        return (0, _bluebird.resolve)(alg.encryptMessage(room, event.getType(), content));

                    case 14:
                        encryptedContent = _context7.sent;


                        if (mRelatesTo) {
                            encryptedContent['m.relates_to'] = mRelatesTo;
                        }

                        event.makeEncrypted("m.room.encrypted", encryptedContent, this._olmDevice.deviceCurve25519Key, this._olmDevice.deviceEd25519Key);

                    case 17:
                    case 'end':
                        return _context7.stop();
                }
            }
        }, _callee7, this);
    }));

    return function (_x11, _x12) {
        return _ref8.apply(this, arguments);
    };
}();

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
        return _bluebird2.default.resolve({
            clearEvent: {
                room_id: event.getRoomId(),
                type: "m.room.message",
                content: {}
            }
        });
    }
    var content = event.getWireContent();
    var alg = this._getRoomDecryptor(event.getRoomId(), content.algorithm);
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
Crypto.prototype.handleDeviceListChanges = function () {
    var _ref9 = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee8(syncData, syncDeviceLists) {
        return _regenerator2.default.wrap(function _callee8$(_context8) {
            while (1) {
                switch (_context8.prev = _context8.next) {
                    case 0:
                        if (syncData.oldSyncToken) {
                            _context8.next = 2;
                            break;
                        }

                        return _context8.abrupt('return');

                    case 2:
                        _context8.next = 4;
                        return (0, _bluebird.resolve)(this._evalDeviceListChanges(syncDeviceLists));

                    case 4:
                    case 'end':
                        return _context8.stop();
                }
            }
        }, _callee8, this);
    }));

    return function (_x13, _x14) {
        return _ref9.apply(this, arguments);
    };
}();

/**
 * Send a request for some room keys, if we have not already done so
 *
 * @param {module:crypto~RoomKeyRequestBody} requestBody
 * @param {Array<{userId: string, deviceId: string}>} recipients
 */
Crypto.prototype.requestRoomKey = function (requestBody, recipients) {
    this._outgoingRoomKeyRequestManager.sendRoomKeyRequest(requestBody, recipients).catch(function (e) {
        // this normally means we couldn't talk to the store
        logger.error('Error requesting key for event', e);
    }).done();
};

/**
 * Cancel any earlier room key request
 *
 * @param {module:crypto~RoomKeyRequestBody} requestBody
 *    parameters to match for cancellation
 * @param {boolean} andResend
 *    if true, resend the key request after cancelling.
 */
Crypto.prototype.cancelRoomKeyRequest = function (requestBody, andResend) {
    this._outgoingRoomKeyRequestManager.cancelRoomKeyRequest(requestBody, andResend).catch(function (e) {
        logger.warn("Error clearing pending room key requests", e);
    }).done();
};

/**
 * handle an m.room.encryption event
 *
 * @param {module:models/event.MatrixEvent} event encryption event
 */
Crypto.prototype.onCryptoEvent = function () {
    var _ref10 = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee9(event) {
        var roomId, content;
        return _regenerator2.default.wrap(function _callee9$(_context9) {
            while (1) {
                switch (_context9.prev = _context9.next) {
                    case 0:
                        roomId = event.getRoomId();
                        content = event.getContent();
                        _context9.prev = 2;
                        _context9.next = 5;
                        return (0, _bluebird.resolve)(this.setRoomEncryption(roomId, content, true));

                    case 5:
                        _context9.next = 10;
                        break;

                    case 7:
                        _context9.prev = 7;
                        _context9.t0 = _context9['catch'](2);

                        logger.error("Error configuring encryption in room " + roomId + ":", _context9.t0);

                    case 10:
                    case 'end':
                        return _context9.stop();
                }
            }
        }, _callee9, this, [[2, 7]]);
    }));

    return function (_x15) {
        return _ref10.apply(this, arguments);
    };
}();

/**
 * Called before the result of a sync is procesed
 *
 * @param {Object} syncData  the data from the 'MatrixClient.sync' event
 */
Crypto.prototype.onSyncWillProcess = function () {
    var _ref11 = (0, _bluebird.method)(function (syncData) {
        if (!syncData.oldSyncToken) {
            // If there is no old sync token, we start all our tracking from
            // scratch, so mark everything as untracked. onCryptoEvent will
            // be called for all e2e rooms during the processing of the sync,
            // at which point we'll start tracking all the users of that room.
            logger.log("Initial sync performed - resetting device tracking state");
            this._deviceList.stopTrackingAllDeviceLists();
            this._roomDeviceTrackingState = {};
        }
    });

    return function (_x16) {
        return _ref11.apply(this, arguments);
    };
}();

/**
 * handle the completion of a /sync
 *
 * This is called after the processing of each successful /sync response.
 * It is an opportunity to do a batch process on the information received.
 *
 * @param {Object} syncData  the data from the 'MatrixClient.sync' event
 */
Crypto.prototype.onSyncCompleted = function () {
    var _ref12 = (0, _bluebird.method)(function (syncData) {
        var nextSyncToken = syncData.nextSyncToken;

        this._deviceList.setSyncToken(syncData.nextSyncToken);
        this._deviceList.saveIfDirty();

        // catch up on any new devices we got told about during the sync.
        this._deviceList.lastKnownSyncToken = nextSyncToken;
        this._deviceList.refreshOutdatedDeviceLists();

        // we don't start uploading one-time keys until we've caught up with
        // to-device messages, to help us avoid throwing away one-time-keys that we
        // are about to receive messages for
        // (https://github.com/vector-im/riot-web/issues/2782).
        if (!syncData.catchingUp) {
            _maybeUploadOneTimeKeys(this);
            this._processReceivedRoomKeyRequests();
        }
    });

    return function (_x17) {
        return _ref12.apply(this, arguments);
    };
}();

/**
 * Trigger the appropriate invalidations and removes for a given
 * device list
 *
 * @param {Object} deviceLists device_lists field from /sync, or response from
 * /keys/changes
 */
Crypto.prototype._evalDeviceListChanges = function () {
    var _ref13 = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee10(deviceLists) {
        var _this5 = this;

        var e2eUserIds;
        return _regenerator2.default.wrap(function _callee10$(_context10) {
            while (1) {
                switch (_context10.prev = _context10.next) {
                    case 0:
                        if (deviceLists.changed && Array.isArray(deviceLists.changed)) {
                            deviceLists.changed.forEach(function (u) {
                                _this5._deviceList.invalidateUserDeviceList(u);
                            });
                        }

                        if (!(deviceLists.left && Array.isArray(deviceLists.left) && deviceLists.left.length)) {
                            _context10.next = 8;
                            break;
                        }

                        _context10.t0 = _set2.default;
                        _context10.next = 5;
                        return (0, _bluebird.resolve)(this._getTrackedE2eUsers());

                    case 5:
                        _context10.t1 = _context10.sent;
                        e2eUserIds = new _context10.t0(_context10.t1);


                        deviceLists.left.forEach(function (u) {
                            if (!e2eUserIds.has(u)) {
                                _this5._deviceList.stopTrackingDeviceList(u);
                            }
                        });

                    case 8:
                    case 'end':
                        return _context10.stop();
                }
            }
        }, _callee10, this);
    }));

    return function (_x18) {
        return _ref13.apply(this, arguments);
    };
}();

/**
 * Get a list of all the IDs of users we share an e2e room with
 * for which we are tracking devices already
 *
 * @returns {string[]} List of user IDs
 */
Crypto.prototype._getTrackedE2eUsers = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee11() {
    var e2eUserIds, _iteratorNormalCompletion, _didIteratorError, _iteratorError, _iterator, _step, room, members, _iteratorNormalCompletion2, _didIteratorError2, _iteratorError2, _iterator2, _step2, member;

    return _regenerator2.default.wrap(function _callee11$(_context11) {
        while (1) {
            switch (_context11.prev = _context11.next) {
                case 0:
                    e2eUserIds = [];
                    _iteratorNormalCompletion = true;
                    _didIteratorError = false;
                    _iteratorError = undefined;
                    _context11.prev = 4;
                    _iterator = (0, _getIterator3.default)(this._getTrackedE2eRooms());

                case 6:
                    if (_iteratorNormalCompletion = (_step = _iterator.next()).done) {
                        _context11.next = 33;
                        break;
                    }

                    room = _step.value;
                    _context11.next = 10;
                    return (0, _bluebird.resolve)(room.getEncryptionTargetMembers());

                case 10:
                    members = _context11.sent;
                    _iteratorNormalCompletion2 = true;
                    _didIteratorError2 = false;
                    _iteratorError2 = undefined;
                    _context11.prev = 14;

                    for (_iterator2 = (0, _getIterator3.default)(members); !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
                        member = _step2.value;

                        e2eUserIds.push(member.userId);
                    }
                    _context11.next = 22;
                    break;

                case 18:
                    _context11.prev = 18;
                    _context11.t0 = _context11['catch'](14);
                    _didIteratorError2 = true;
                    _iteratorError2 = _context11.t0;

                case 22:
                    _context11.prev = 22;
                    _context11.prev = 23;

                    if (!_iteratorNormalCompletion2 && _iterator2.return) {
                        _iterator2.return();
                    }

                case 25:
                    _context11.prev = 25;

                    if (!_didIteratorError2) {
                        _context11.next = 28;
                        break;
                    }

                    throw _iteratorError2;

                case 28:
                    return _context11.finish(25);

                case 29:
                    return _context11.finish(22);

                case 30:
                    _iteratorNormalCompletion = true;
                    _context11.next = 6;
                    break;

                case 33:
                    _context11.next = 39;
                    break;

                case 35:
                    _context11.prev = 35;
                    _context11.t1 = _context11['catch'](4);
                    _didIteratorError = true;
                    _iteratorError = _context11.t1;

                case 39:
                    _context11.prev = 39;
                    _context11.prev = 40;

                    if (!_iteratorNormalCompletion && _iterator.return) {
                        _iterator.return();
                    }

                case 42:
                    _context11.prev = 42;

                    if (!_didIteratorError) {
                        _context11.next = 45;
                        break;
                    }

                    throw _iteratorError;

                case 45:
                    return _context11.finish(42);

                case 46:
                    return _context11.finish(39);

                case 47:
                    return _context11.abrupt('return', e2eUserIds);

                case 48:
                case 'end':
                    return _context11.stop();
            }
        }
    }, _callee11, this, [[4, 35, 39, 47], [14, 18, 22, 30], [23,, 25, 29], [40,, 42, 46]]);
}));

/**
 * Get a list of the e2e-enabled rooms we are members of,
 * and for which we are already tracking the devices
 *
 * @returns {module:models.Room[]}
 */
Crypto.prototype._getTrackedE2eRooms = function () {
    var _this6 = this;

    return this._clientStore.getRooms().filter(function (room) {
        // check for rooms with encryption enabled
        var alg = _this6._roomEncryptors[room.roomId];
        if (!alg) {
            return false;
        }
        if (!_this6._roomDeviceTrackingState[room.roomId]) {
            return false;
        }

        // ignore any rooms which we have left
        var myMembership = room.getMyMembership();
        return myMembership === "join" || myMembership === "invite";
    });
};

Crypto.prototype._onToDeviceEvent = function (event) {
    var _this7 = this;

    try {
        if (event.getType() == "m.room_key" || event.getType() == "m.forwarded_room_key") {
            this._onRoomKeyEvent(event);
        } else if (event.getType() == "m.room_key_request") {
            this._onRoomKeyRequestEvent(event);
        } else if (event.isBeingDecrypted()) {
            // once the event has been decrypted, try again
            event.once('Event.decrypted', function (ev) {
                _this7._onToDeviceEvent(ev);
            });
        }
    } catch (e) {
        logger.error("Error handling toDeviceEvent:", e);
    }
};

/**
 * Handle a key event
 *
 * @private
 * @param {module:models/event.MatrixEvent} event key event
 */
Crypto.prototype._onRoomKeyEvent = function (event) {
    var content = event.getContent();

    if (!content.room_id || !content.algorithm) {
        logger.error("key event is missing fields");
        return;
    }

    var alg = this._getRoomDecryptor(content.room_id, content.algorithm);
    alg.onRoomKeyEvent(event);
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

    var roomId = member.roomId;

    var alg = this._roomEncryptors[roomId];
    if (!alg) {
        // not encrypting in this room
        return;
    }
    // only mark users in this room as tracked if we already started tracking in this room
    // this way we don't start device queries after sync on behalf of this room which we won't use
    // the result of anyway, as we'll need to do a query again once all the members are fetched
    // by calling _trackRoomDevices
    if (this._roomDeviceTrackingState[roomId]) {
        if (member.membership == 'join') {
            logger.log('Join event for ' + member.userId + ' in ' + roomId);
            // make sure we are tracking the deviceList for this user
            this._deviceList.startTrackingDeviceList(member.userId);
        } else if (member.membership == 'invite' && this._clientStore.getRoom(roomId).shouldEncryptForInvitedMembers()) {
            logger.log('Invite event for ' + member.userId + ' in ' + roomId);
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
    var content = event.getContent();
    if (content.action === "request") {
        // Queue it up for now, because they tend to arrive before the room state
        // events at initial sync, and we want to see if we know anything about the
        // room before passing them on to the app.
        var req = new IncomingRoomKeyRequest(event);
        this._receivedRoomKeyRequests.push(req);
    } else if (content.action === "request_cancellation") {
        var _req = new IncomingRoomKeyRequestCancellation(event);
        this._receivedRoomKeyRequestCancellations.push(_req);
    }
};

/**
 * Process any m.room_key_request events which were queued up during the
 * current sync.
 *
 * @private
 */
Crypto.prototype._processReceivedRoomKeyRequests = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee12() {
    var _this8 = this;

    var requests, cancellations;
    return _regenerator2.default.wrap(function _callee12$(_context12) {
        while (1) {
            switch (_context12.prev = _context12.next) {
                case 0:
                    if (!this._processingRoomKeyRequests) {
                        _context12.next = 2;
                        break;
                    }

                    return _context12.abrupt('return');

                case 2:
                    this._processingRoomKeyRequests = true;

                    _context12.prev = 3;

                    // we need to grab and clear the queues in the synchronous bit of this method,
                    // so that we don't end up racing with the next /sync.
                    requests = this._receivedRoomKeyRequests;

                    this._receivedRoomKeyRequests = [];
                    cancellations = this._receivedRoomKeyRequestCancellations;

                    this._receivedRoomKeyRequestCancellations = [];

                    // Process all of the requests, *then* all of the cancellations.
                    //
                    // This makes sure that if we get a request and its cancellation in the
                    // same /sync result, then we process the request before the
                    // cancellation (and end up with a cancelled request), rather than the
                    // cancellation before the request (and end up with an outstanding
                    // request which should have been cancelled.)
                    _context12.next = 10;
                    return (0, _bluebird.resolve)(_bluebird2.default.map(requests, function (req) {
                        return _this8._processReceivedRoomKeyRequest(req);
                    }));

                case 10:
                    _context12.next = 12;
                    return (0, _bluebird.resolve)(_bluebird2.default.map(cancellations, function (cancellation) {
                        return _this8._processReceivedRoomKeyRequestCancellation(cancellation);
                    }));

                case 12:
                    _context12.next = 17;
                    break;

                case 14:
                    _context12.prev = 14;
                    _context12.t0 = _context12['catch'](3);

                    logger.error('Error processing room key requsts: ' + _context12.t0);

                case 17:
                    _context12.prev = 17;

                    this._processingRoomKeyRequests = false;
                    return _context12.finish(17);

                case 20:
                case 'end':
                    return _context12.stop();
            }
        }
    }, _callee12, this, [[3, 14, 17, 20]]);
}));

/**
 * Helper for processReceivedRoomKeyRequests
 *
 * @param {IncomingRoomKeyRequest} req
 */
Crypto.prototype._processReceivedRoomKeyRequest = function () {
    var _ref16 = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee13(req) {
        var userId, deviceId, body, roomId, alg, decryptor, device;
        return _regenerator2.default.wrap(function _callee13$(_context13) {
            while (1) {
                switch (_context13.prev = _context13.next) {
                    case 0:
                        userId = req.userId;
                        deviceId = req.deviceId;
                        body = req.requestBody;
                        roomId = body.room_id;
                        alg = body.algorithm;


                        logger.log('m.room_key_request from ' + userId + ':' + deviceId + (' for ' + roomId + ' / ' + body.session_id + ' (id ' + req.requestId + ')'));

                        if (!(userId !== this._userId)) {
                            _context13.next = 9;
                            break;
                        }

                        // TODO: determine if we sent this device the keys already: in
                        // which case we can do so again.
                        logger.log("Ignoring room key request from other user for now");
                        return _context13.abrupt('return');

                    case 9:
                        if (this._roomDecryptors[roomId]) {
                            _context13.next = 12;
                            break;
                        }

                        logger.log('room key request for unencrypted room ' + roomId);
                        return _context13.abrupt('return');

                    case 12:
                        decryptor = this._roomDecryptors[roomId][alg];

                        if (decryptor) {
                            _context13.next = 16;
                            break;
                        }

                        logger.log('room key request for unknown alg ' + alg + ' in room ' + roomId);
                        return _context13.abrupt('return');

                    case 16:
                        _context13.next = 18;
                        return (0, _bluebird.resolve)(decryptor.hasKeysForKeyRequest(req));

                    case 18:
                        if (_context13.sent) {
                            _context13.next = 21;
                            break;
                        }

                        logger.log('room key request for unknown session ' + roomId + ' / ' + body.session_id);
                        return _context13.abrupt('return');

                    case 21:

                        req.share = function () {
                            decryptor.shareKeysWithDevice(req);
                        };

                        // if the device is is verified already, share the keys
                        device = this._deviceList.getStoredDevice(userId, deviceId);

                        if (!(device && device.isVerified())) {
                            _context13.next = 27;
                            break;
                        }

                        logger.log('device is already verified: sharing keys');
                        req.share();
                        return _context13.abrupt('return');

                    case 27:

                        this.emit("crypto.roomKeyRequest", req);

                    case 28:
                    case 'end':
                        return _context13.stop();
                }
            }
        }, _callee13, this);
    }));

    return function (_x19) {
        return _ref16.apply(this, arguments);
    };
}();

/**
 * Helper for processReceivedRoomKeyRequests
 *
 * @param {IncomingRoomKeyRequestCancellation} cancellation
 */
Crypto.prototype._processReceivedRoomKeyRequestCancellation = function () {
    var _ref17 = (0, _bluebird.method)(function (cancellation) {
        logger.log('m.room_key_request cancellation for ' + cancellation.userId + ':' + (cancellation.deviceId + ' (id ' + cancellation.requestId + ')'));

        // we should probably only notify the app of cancellations we told it
        // about, but we don't currently have a record of that, so we just pass
        // everything through.
        this.emit("crypto.roomKeyRequestCancellation", cancellation);
    });

    return function (_x20) {
        return _ref17.apply(this, arguments);
    };
}();

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
    var decryptors = void 0;
    var alg = void 0;

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

    var AlgClass = algorithms.DECRYPTION_CLASSES[algorithm];
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
 * sign the given object with our ed25519 key
 *
 * @param {Object} obj  Object to which we will add a 'signatures' property
 */
Crypto.prototype._signObject = function () {
    var _ref18 = (0, _bluebird.coroutine)( /*#__PURE__*/_regenerator2.default.mark(function _callee14(obj) {
        var sigs;
        return _regenerator2.default.wrap(function _callee14$(_context14) {
            while (1) {
                switch (_context14.prev = _context14.next) {
                    case 0:
                        sigs = {};

                        sigs[this._userId] = {};
                        _context14.next = 4;
                        return (0, _bluebird.resolve)(this._olmDevice.sign(anotherjson.stringify(obj)));

                    case 4:
                        sigs[this._userId]["ed25519:" + this._deviceId] = _context14.sent;

                        obj.signatures = sigs;

                    case 6:
                    case 'end':
                        return _context14.stop();
                }
            }
        }, _callee14, this);
    }));

    return function (_x21) {
        return _ref18.apply(this, arguments);
    };
}();

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

var IncomingRoomKeyRequest = function IncomingRoomKeyRequest(event) {
    (0, _classCallCheck3.default)(this, IncomingRoomKeyRequest);

    var content = event.getContent();

    this.userId = event.getSender();
    this.deviceId = content.requesting_device_id;
    this.requestId = content.request_id;
    this.requestBody = content.body || {};
    this.share = function () {
        throw new Error("don't know how to share keys for this request yet");
    };
};

/**
 * Represents a received m.room_key_request cancellation
 *
 * @property {string} userId    user requesting the cancellation
 * @property {string} deviceId  device requesting the cancellation
 * @property {string} requestId unique id for the request to be cancelled
 */


var IncomingRoomKeyRequestCancellation = function IncomingRoomKeyRequestCancellation(event) {
    (0, _classCallCheck3.default)(this, IncomingRoomKeyRequestCancellation);

    var content = event.getContent();

    this.userId = event.getSender();
    this.deviceId = content.requesting_device_id;
    this.requestId = content.request_id;
};

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
 * Comes with a type which is one of:
 * * CRYPTO_WARNING_ACCOUNT_MIGRATED: Account data has been migrated from an older
 *       version of the store in such a way that older clients will no longer be
 *       able to read it. The app may wish to warn the user against going back to
 *       an older version of the app.
 * * CRYPTO_WARNING_OLD_VERSION_DETECTED: js-sdk has detected that an older version
 *       of js-sdk has been run against the same store after a migration has been
 *       performed. This is likely have caused unexpected behaviour in the old
 *       version. For example, the old version and the new version may have two
 *       different identity keys.
 *
 * @event module:client~MatrixClient#"crypto.warning"
 * @param {string} type One of the strings listed above
 */
//# sourceMappingURL=index.js.map