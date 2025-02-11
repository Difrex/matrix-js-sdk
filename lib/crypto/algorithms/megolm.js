"use strict";

var _interopRequireWildcard = require("@babel/runtime/helpers/interopRequireWildcard");

var _logger = require("../../logger");

var utils = _interopRequireWildcard(require("../../utils"));

var olmlib = _interopRequireWildcard(require("../olmlib"));

var _base = require("./base");

var _OlmDevice = require("../OlmDevice");

/*
Copyright 2015, 2016 OpenMarket Ltd
Copyright 2018 New Vector Ltd
Copyright 2020 The Matrix.org Foundation C.I.C.

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
 * Defines m.olm encryption/decryption
 *
 * @module crypto/algorithms/megolm
 */

/**
 * @private
 * @constructor
 *
 * @param {string} sessionId
 *
 * @property {string} sessionId
 * @property {Number} useCount     number of times this session has been used
 * @property {Number} creationTime when the session was created (ms since the epoch)
 *
 * @property {object} sharedWithDevices
 *    devices with which we have shared the session key
 *        userId -> {deviceId -> msgindex}
 */
function OutboundSessionInfo(sessionId) {
  this.sessionId = sessionId;
  this.useCount = 0;
  this.creationTime = new Date().getTime();
  this.sharedWithDevices = {};
  this.blockedDevicesNotified = {};
}
/**
 * Check if it's time to rotate the session
 *
 * @param {Number} rotationPeriodMsgs
 * @param {Number} rotationPeriodMs
 * @return {Boolean}
 */


OutboundSessionInfo.prototype.needsRotation = function (rotationPeriodMsgs, rotationPeriodMs) {
  const sessionLifetime = new Date().getTime() - this.creationTime;

  if (this.useCount >= rotationPeriodMsgs || sessionLifetime >= rotationPeriodMs) {
    _logger.logger.log("Rotating megolm session after " + this.useCount + " messages, " + sessionLifetime + "ms");

    return true;
  }

  return false;
};

OutboundSessionInfo.prototype.markSharedWithDevice = function (userId, deviceId, chainIndex) {
  if (!this.sharedWithDevices[userId]) {
    this.sharedWithDevices[userId] = {};
  }

  this.sharedWithDevices[userId][deviceId] = chainIndex;
};

OutboundSessionInfo.prototype.markNotifiedBlockedDevice = function (userId, deviceId) {
  if (!this.blockedDevicesNotified[userId]) {
    this.blockedDevicesNotified[userId] = {};
  }

  this.blockedDevicesNotified[userId][deviceId] = true;
};
/**
 * Determine if this session has been shared with devices which it shouldn't
 * have been.
 *
 * @param {Object} devicesInRoom userId -> {deviceId -> object}
 *   devices we should shared the session with.
 *
 * @return {Boolean} true if we have shared the session with devices which aren't
 * in devicesInRoom.
 */


OutboundSessionInfo.prototype.sharedWithTooManyDevices = function (devicesInRoom) {
  for (const userId in this.sharedWithDevices) {
    if (!this.sharedWithDevices.hasOwnProperty(userId)) {
      continue;
    }

    if (!devicesInRoom.hasOwnProperty(userId)) {
      _logger.logger.log("Starting new megolm session because we shared with " + userId);

      return true;
    }

    for (const deviceId in this.sharedWithDevices[userId]) {
      if (!this.sharedWithDevices[userId].hasOwnProperty(deviceId)) {
        continue;
      }

      if (!devicesInRoom[userId].hasOwnProperty(deviceId)) {
        _logger.logger.log("Starting new megolm session because we shared with " + userId + ":" + deviceId);

        return true;
      }
    }
  }
};
/**
 * Megolm encryption implementation
 *
 * @constructor
 * @extends {module:crypto/algorithms/EncryptionAlgorithm}
 *
 * @param {object} params parameters, as per
 *     {@link module:crypto/algorithms/EncryptionAlgorithm}
 */


function MegolmEncryption(params) {
  (0, utils.polyfillSuper)(this, _base.EncryptionAlgorithm, params); // the most recent attempt to set up a session. This is used to serialise
  // the session setups, so that we have a race-free view of which session we
  // are using, and which devices we have shared the keys with. It resolves
  // with an OutboundSessionInfo (or undefined, for the first message in the
  // room).

  this._setupPromise = Promise.resolve(); // Map of outbound sessions by sessions ID. Used if we need a particular
  // session (the session we're currently using to send is always obtained
  // using _setupPromise).

  this._outboundSessions = {}; // default rotation periods

  this._sessionRotationPeriodMsgs = 100;
  this._sessionRotationPeriodMs = 7 * 24 * 3600 * 1000;

  if (params.config.rotation_period_ms !== undefined) {
    this._sessionRotationPeriodMs = params.config.rotation_period_ms;
  }

  if (params.config.rotation_period_msgs !== undefined) {
    this._sessionRotationPeriodMsgs = params.config.rotation_period_msgs;
  }
}

utils.inherits(MegolmEncryption, _base.EncryptionAlgorithm);
/**
 * @private
 *
 * @param {Object} devicesInRoom The devices in this room, indexed by user ID
 * @param {Object} blocked The devices that are blocked, indexed by user ID
 *
 * @return {Promise} Promise which resolves to the
 *    OutboundSessionInfo when setup is complete.
 */

MegolmEncryption.prototype._ensureOutboundSession = async function (devicesInRoom, blocked) {
  const self = this;
  let session; // takes the previous OutboundSessionInfo, and considers whether to create
  // a new one. Also shares the key with any (new) devices in the room.
  // Updates `session` to hold the final OutboundSessionInfo.
  //
  // returns a promise which resolves once the keyshare is successful.

  async function prepareSession(oldSession) {
    session = oldSession; // need to make a brand new session?

    if (session && session.needsRotation(self._sessionRotationPeriodMsgs, self._sessionRotationPeriodMs)) {
      _logger.logger.log("Starting new megolm session because we need to rotate.");

      session = null;
    } // determine if we have shared with anyone we shouldn't have


    if (session && session.sharedWithTooManyDevices(devicesInRoom)) {
      session = null;
    }

    if (!session) {
      _logger.logger.log(`Starting new megolm session for room ${self._roomId}`);

      session = await self._prepareNewSession();

      _logger.logger.log(`Started new megolm session ${session.sessionId} ` + `for room ${self._roomId}`);

      self._outboundSessions[session.sessionId] = session;
    } // now check if we need to share with any devices


    const shareMap = {};

    for (const userId in devicesInRoom) {
      if (!devicesInRoom.hasOwnProperty(userId)) {
        continue;
      }

      const userDevices = devicesInRoom[userId];

      for (const deviceId in userDevices) {
        if (!userDevices.hasOwnProperty(deviceId)) {
          continue;
        }

        const deviceInfo = userDevices[deviceId];
        const key = deviceInfo.getIdentityKey();

        if (key == self._olmDevice.deviceCurve25519Key) {
          // don't bother sending to ourself
          continue;
        }

        if (!session.sharedWithDevices[userId] || session.sharedWithDevices[userId][deviceId] === undefined) {
          shareMap[userId] = shareMap[userId] || [];
          shareMap[userId].push(deviceInfo);
        }
      }
    }

    const errorDevices = [];
    await self._shareKeyWithDevices(session, shareMap, errorDevices); // are there any new blocked devices that we need to notify?

    const blockedMap = {};

    for (const userId in blocked) {
      if (!blocked.hasOwnProperty(userId)) {
        continue;
      }

      const userBlockedDevices = blocked[userId];

      for (const deviceId in userBlockedDevices) {
        if (!userBlockedDevices.hasOwnProperty(deviceId)) {
          continue;
        }

        if (!session.blockedDevicesNotified[userId] || session.blockedDevicesNotified[userId][deviceId] === undefined) {
          blockedMap[userId] = blockedMap[userId] || [];
          blockedMap[userId].push(userBlockedDevices[deviceId]);
        }
      }
    }

    const filteredErrorDevices = await self._olmDevice.filterOutNotifiedErrorDevices(errorDevices);

    for (const {
      userId,
      deviceInfo
    } of filteredErrorDevices) {
      blockedMap[userId] = blockedMap[userId] || [];
      blockedMap[userId].push({
        code: "m.no_olm",
        reason: _OlmDevice.WITHHELD_MESSAGES["m.no_olm"],
        deviceInfo
      });
    } // notify blocked devices that they're blocked


    await self._notifyBlockedDevices(session, blockedMap);
  } // helper which returns the session prepared by prepareSession


  function returnSession() {
    return session;
  } // first wait for the previous share to complete


  const prom = this._setupPromise.then(prepareSession); // _setupPromise resolves to `session` whether or not the share succeeds


  this._setupPromise = prom.then(returnSession, returnSession); // but we return a promise which only resolves if the share was successful.

  return prom.then(returnSession);
};
/**
 * @private
 *
 * @return {module:crypto/algorithms/megolm.OutboundSessionInfo} session
 */


MegolmEncryption.prototype._prepareNewSession = async function () {
  const sessionId = this._olmDevice.createOutboundGroupSession();

  const key = this._olmDevice.getOutboundGroupSessionKey(sessionId);

  await this._olmDevice.addInboundGroupSession(this._roomId, this._olmDevice.deviceCurve25519Key, [], sessionId, key.key, {
    ed25519: this._olmDevice.deviceEd25519Key
  });

  if (this._crypto.backupInfo) {
    // don't wait for it to complete
    this._crypto.backupGroupSession(this._roomId, this._olmDevice.deviceCurve25519Key, [], sessionId, key.key).catch(e => {
      // This throws if the upload failed, but this is fine
      // since it will have written it to the db and will retry.
      _logger.logger.log("Failed to back up megolm session", e);
    });
  }

  return new OutboundSessionInfo(sessionId);
};
/**
 * Splits the user device map into multiple chunks to reduce the number of
 * devices we encrypt to per API call. Also filters out devices we don't have
 * a session with.
 *
 * @private
 *
 * @param {module:crypto/algorithms/megolm.OutboundSessionInfo} session
 *
 * @param {number} chainIndex current chain index
 *
 * @param {object<userId, deviceId>} devicemap
 *   mapping from userId to deviceId to {@link module:crypto~OlmSessionResult}
 *
 * @param {object<string, module:crypto/deviceinfo[]>} devicesByUser
 *    map from userid to list of devices
 *
 * @param {array<object>} errorDevices
 *    array that will be populated with the devices that can't get an
 *    olm session for
 *
 * @return {array<object<userid, deviceInfo>>}
 */


MegolmEncryption.prototype._splitUserDeviceMap = function (session, chainIndex, devicemap, devicesByUser, errorDevices) {
  const maxUsersPerRequest = 20; // use an array where the slices of a content map gets stored

  const mapSlices = [];
  let currentSliceId = 0; // start inserting in the first slice

  let entriesInCurrentSlice = 0;

  for (const userId of Object.keys(devicesByUser)) {
    const devicesToShareWith = devicesByUser[userId];
    const sessionResults = devicemap[userId];

    for (let i = 0; i < devicesToShareWith.length; i++) {
      const deviceInfo = devicesToShareWith[i];
      const deviceId = deviceInfo.deviceId;
      const sessionResult = sessionResults[deviceId];

      if (!sessionResult.sessionId) {
        // no session with this device, probably because there
        // were no one-time keys.
        // mark this device as "handled" because we don't want to try
        // to claim a one-time-key for dead devices on every message.
        session.markSharedWithDevice(userId, deviceId, chainIndex);
        errorDevices.push({
          userId,
          deviceInfo
        }); // ensureOlmSessionsForUsers has already done the logging,
        // so just skip it.

        continue;
      }

      _logger.logger.log("share keys with device " + userId + ":" + deviceId);

      if (!mapSlices[currentSliceId]) {
        mapSlices[currentSliceId] = [];
      }

      mapSlices[currentSliceId].push({
        userId: userId,
        deviceInfo: deviceInfo
      });
      entriesInCurrentSlice++;
    } // We do this in the per-user loop as we prefer that all messages to the
    // same user end up in the same API call to make it easier for the
    // server (e.g. only have to send one EDU if a remote user, etc). This
    // does mean that if a user has many devices we may go over the desired
    // limit, but its not a hard limit so that is fine.


    if (entriesInCurrentSlice > maxUsersPerRequest) {
      // the current slice is filled up. Start inserting into the next slice
      entriesInCurrentSlice = 0;
      currentSliceId++;
    }
  }

  return mapSlices;
};
/**
 * Splits the user device map into multiple chunks to reduce the number of
 * devices we encrypt to per API call.
 *
 * @private
 *
 * @param {object} devicesByUser map from userid to list of devices
 *
 * @return {array<array<object>>} the blocked devices, split into chunks
 */


MegolmEncryption.prototype._splitBlockedDevices = function (devicesByUser) {
  const maxUsersPerRequest = 20; // use an array where the slices of a content map gets stored

  let currentSlice = [];
  const mapSlices = [currentSlice];

  for (const userId of Object.keys(devicesByUser)) {
    const userBlockedDevicesToShareWith = devicesByUser[userId];

    for (const blockedInfo of userBlockedDevicesToShareWith) {
      currentSlice.push({
        userId: userId,
        blockedInfo: blockedInfo
      });
    } // We do this in the per-user loop as we prefer that all messages to the
    // same user end up in the same API call to make it easier for the
    // server (e.g. only have to send one EDU if a remote user, etc). This
    // does mean that if a user has many devices we may go over the desired
    // limit, but its not a hard limit so that is fine.


    if (currentSlice.length > maxUsersPerRequest) {
      // the current slice is filled up. Start inserting into the next slice
      currentSlice = [];
      mapSlices.push(currentSlice);
    }
  }

  if (currentSlice.length === 0) {
    mapSlices.pop();
  }

  return mapSlices;
};
/**
 * @private
 *
 * @param {module:crypto/algorithms/megolm.OutboundSessionInfo} session
 *
 * @param {number} chainIndex current chain index
 *
 * @param {object<userId, deviceInfo>} userDeviceMap
 *   mapping from userId to deviceInfo
 *
 * @param {object} payload fields to include in the encrypted payload
 *
 * @return {Promise} Promise which resolves once the key sharing
 *     for the given userDeviceMap is generated and has been sent.
 */


MegolmEncryption.prototype._encryptAndSendKeysToDevices = function (session, chainIndex, userDeviceMap, payload) {
  const contentMap = {};
  const promises = [];

  for (let i = 0; i < userDeviceMap.length; i++) {
    const encryptedContent = {
      algorithm: olmlib.OLM_ALGORITHM,
      sender_key: this._olmDevice.deviceCurve25519Key,
      ciphertext: {}
    };
    const val = userDeviceMap[i];
    const userId = val.userId;
    const deviceInfo = val.deviceInfo;
    const deviceId = deviceInfo.deviceId;

    if (!contentMap[userId]) {
      contentMap[userId] = {};
    }

    contentMap[userId][deviceId] = encryptedContent;
    promises.push(olmlib.encryptMessageForDevice(encryptedContent.ciphertext, this._userId, this._deviceId, this._olmDevice, userId, deviceInfo, payload));
  }

  return Promise.all(promises).then(() => {
    return this._baseApis.sendToDevice("m.room.encrypted", contentMap).then(() => {
      // store that we successfully uploaded the keys of the current slice
      for (const userId of Object.keys(contentMap)) {
        for (const deviceId of Object.keys(contentMap[userId])) {
          session.markSharedWithDevice(userId, deviceId, chainIndex);
        }
      }
    });
  });
};
/**
 * @private
 *
 * @param {module:crypto/algorithms/megolm.OutboundSessionInfo} session
 *
 * @param {array<object>} userDeviceMap list of blocked devices to notify
 *
 * @param {object} payload fields to include in the notification payload
 *
 * @return {Promise} Promise which resolves once the notifications
 *     for the given userDeviceMap is generated and has been sent.
 */


MegolmEncryption.prototype._sendBlockedNotificationsToDevices = async function (session, userDeviceMap, payload) {
  const contentMap = {};

  for (const val of userDeviceMap) {
    const userId = val.userId;
    const blockedInfo = val.blockedInfo;
    const deviceInfo = blockedInfo.deviceInfo;
    const deviceId = deviceInfo.deviceId;
    const message = Object.assign({}, payload);
    message.code = blockedInfo.code;
    message.reason = blockedInfo.reason;

    if (message.code === "m.no_olm") {
      delete message.room_id;
      delete message.session_id;
    }

    if (!contentMap[userId]) {
      contentMap[userId] = {};
    }

    contentMap[userId][deviceId] = message;
  }

  await this._baseApis.sendToDevice("org.matrix.room_key.withheld", contentMap); // store that we successfully uploaded the keys of the current slice

  for (const userId of Object.keys(contentMap)) {
    for (const deviceId of Object.keys(contentMap[userId])) {
      session.markNotifiedBlockedDevice(userId, deviceId);
    }
  }
};
/**
 * Re-shares a megolm session key with devices if the key has already been
 * sent to them.
 *
 * @param {string} senderKey The key of the originating device for the session
 * @param {string} sessionId ID of the outbound session to share
 * @param {string} userId ID of the user who owns the target device
 * @param {module:crypto/deviceinfo} device The target device
 */


MegolmEncryption.prototype.reshareKeyWithDevice = async function (senderKey, sessionId, userId, device) {
  const obSessionInfo = this._outboundSessions[sessionId];

  if (!obSessionInfo) {
    _logger.logger.debug(`megolm session ${sessionId} not found: not re-sharing keys`);

    return;
  } // The chain index of the key we previously sent this device


  if (obSessionInfo.sharedWithDevices[userId] === undefined) {
    _logger.logger.debug(`megolm session ${sessionId} never shared with user ${userId}`);

    return;
  }

  const sentChainIndex = obSessionInfo.sharedWithDevices[userId][device.deviceId];

  if (sentChainIndex === undefined) {
    _logger.logger.debug("megolm session ID " + sessionId + " never shared with device " + userId + ":" + device.deviceId);

    return;
  } // get the key from the inbound session: the outbound one will already
  // have been ratcheted to the next chain index.


  const key = await this._olmDevice.getInboundGroupSessionKey(this._roomId, senderKey, sessionId, sentChainIndex);

  if (!key) {
    _logger.logger.warn(`No inbound session key found for megolm ${sessionId}: not re-sharing keys`);

    return;
  }

  await olmlib.ensureOlmSessionsForDevices(this._olmDevice, this._baseApis, {
    [userId]: {
      [device.deviceId]: device
    }
  });
  const payload = {
    type: "m.forwarded_room_key",
    content: {
      algorithm: olmlib.MEGOLM_ALGORITHM,
      room_id: this._roomId,
      session_id: sessionId,
      session_key: key.key,
      chain_index: key.chain_index,
      sender_key: senderKey,
      sender_claimed_ed25519_key: key.sender_claimed_ed25519_key,
      forwarding_curve25519_key_chain: key.forwarding_curve25519_key_chain
    }
  };
  const encryptedContent = {
    algorithm: olmlib.OLM_ALGORITHM,
    sender_key: this._olmDevice.deviceCurve25519Key,
    ciphertext: {}
  };
  await olmlib.encryptMessageForDevice(encryptedContent.ciphertext, this._userId, this._deviceId, this._olmDevice, userId, device, payload);
  await this._baseApis.sendToDevice("m.room.encrypted", {
    [userId]: {
      [device.deviceId]: encryptedContent
    }
  });

  _logger.logger.debug(`Re-shared key for megolm session ${sessionId} ` + `with ${userId}:${device.deviceId}`);
};
/**
 * @param {module:crypto/algorithms/megolm.OutboundSessionInfo} session
 *
 * @param {object<string, module:crypto/deviceinfo[]>} devicesByUser
 *    map from userid to list of devices
 *
 * @param {array<object>} errorDevices
 *    array that will be populated with the devices that we can't get an
 *    olm session for
 */


MegolmEncryption.prototype._shareKeyWithDevices = async function (session, devicesByUser, errorDevices) {
  const key = this._olmDevice.getOutboundGroupSessionKey(session.sessionId);

  const payload = {
    type: "m.room_key",
    content: {
      algorithm: olmlib.MEGOLM_ALGORITHM,
      room_id: this._roomId,
      session_id: session.sessionId,
      session_key: key.key,
      chain_index: key.chain_index
    }
  };
  const devicemap = await olmlib.ensureOlmSessionsForDevices(this._olmDevice, this._baseApis, devicesByUser);

  const userDeviceMaps = this._splitUserDeviceMap(session, key.chain_index, devicemap, devicesByUser, errorDevices);

  for (let i = 0; i < userDeviceMaps.length; i++) {
    try {
      await this._encryptAndSendKeysToDevices(session, key.chain_index, userDeviceMaps[i], payload);

      _logger.logger.log(`Completed megolm keyshare for ${session.sessionId} ` + `in ${this._roomId} (slice ${i + 1}/${userDeviceMaps.length})`);
    } catch (e) {
      _logger.logger.log(`megolm keyshare for ${session.sessionId} in ${this._roomId} ` + `(slice ${i + 1}/${userDeviceMaps.length}) failed`);

      throw e;
    }
  }
};
/**
 * Notify blocked devices that they have been blocked.
 *
 * @param {module:crypto/algorithms/megolm.OutboundSessionInfo} session
 *
 * @param {object<string, object>} devicesByUser
 *    map from userid to device ID to blocked data
 */


MegolmEncryption.prototype._notifyBlockedDevices = async function (session, devicesByUser) {
  const payload = {
    room_id: this._roomId,
    session_id: session.sessionId,
    algorithm: olmlib.MEGOLM_ALGORITHM,
    sender_key: this._olmDevice.deviceCurve25519Key
  };

  const userDeviceMaps = this._splitBlockedDevices(devicesByUser);

  for (let i = 0; i < userDeviceMaps.length; i++) {
    try {
      await this._sendBlockedNotificationsToDevices(session, userDeviceMaps[i], payload);

      _logger.logger.log(`Completed blacklist notification for ${session.sessionId} ` + `in ${this._roomId} (slice ${i + 1}/${userDeviceMaps.length})`);
    } catch (e) {
      _logger.logger.log(`blacklist notification for ${session.sessionId} in ` + `${this._roomId} (slice ${i + 1}/${userDeviceMaps.length}) failed`);

      throw e;
    }
  }
};
/**
 * @inheritdoc
 *
 * @param {module:models/room} room
 * @param {string} eventType
 * @param {object} content plaintext event content
 *
 * @return {Promise} Promise which resolves to the new event body
 */


MegolmEncryption.prototype.encryptMessage = async function (room, eventType, content) {
  const self = this;

  _logger.logger.log(`Starting to encrypt event for ${this._roomId}`);

  const [devicesInRoom, blocked] = await this._getDevicesInRoom(room); // check if any of these devices are not yet known to the user.
  // if so, warn the user so they can verify or ignore.

  if (this._crypto.getGlobalErrorOnUnknownDevices()) {
    self._checkForUnknownDevices(devicesInRoom);
  }

  const session = await self._ensureOutboundSession(devicesInRoom, blocked);
  const payloadJson = {
    room_id: self._roomId,
    type: eventType,
    content: content
  };

  const ciphertext = self._olmDevice.encryptGroupMessage(session.sessionId, JSON.stringify(payloadJson));

  const encryptedContent = {
    algorithm: olmlib.MEGOLM_ALGORITHM,
    sender_key: self._olmDevice.deviceCurve25519Key,
    ciphertext: ciphertext,
    session_id: session.sessionId,
    // Include our device ID so that recipients can send us a
    // m.new_device message if they don't have our session key.
    // XXX: Do we still need this now that m.new_device messages
    // no longer exist since #483?
    device_id: self._deviceId
  };
  session.useCount++;
  return encryptedContent;
};
/**
 * Forces the current outbound group session to be discarded such
 * that another one will be created next time an event is sent.
 *
 * This should not normally be necessary.
 */


MegolmEncryption.prototype.forceDiscardSession = function () {
  this._setupPromise = this._setupPromise.then(() => null);
};
/**
 * Checks the devices we're about to send to and see if any are entirely
 * unknown to the user.  If so, warn the user, and mark them as known to
 * give the user a chance to go verify them before re-sending this message.
 *
 * @param {Object} devicesInRoom userId -> {deviceId -> object}
 *   devices we should shared the session with.
 */


MegolmEncryption.prototype._checkForUnknownDevices = function (devicesInRoom) {
  const unknownDevices = {};
  Object.keys(devicesInRoom).forEach(userId => {
    Object.keys(devicesInRoom[userId]).forEach(deviceId => {
      const device = devicesInRoom[userId][deviceId];

      if (device.isUnverified() && !device.isKnown()) {
        if (!unknownDevices[userId]) {
          unknownDevices[userId] = {};
        }

        unknownDevices[userId][deviceId] = device;
      }
    });
  });

  if (Object.keys(unknownDevices).length) {
    // it'd be kind to pass unknownDevices up to the user in this error
    throw new _base.UnknownDeviceError("This room contains unknown devices which have not been verified. " + "We strongly recommend you verify them before continuing.", unknownDevices);
  }
};
/**
 * Get the list of unblocked devices for all users in the room
 *
 * @param {module:models/room} room
 *
 * @return {Promise} Promise which resolves to an array whose
 *     first element is a map from userId to deviceId to deviceInfo indicating
 *     the devices that messages should be encrypted to, and whose second
 *     element is a map from userId to deviceId to data indicating the devices
 *     that are in the room but that have been blocked
 */


MegolmEncryption.prototype._getDevicesInRoom = async function (room) {
  const members = await room.getEncryptionTargetMembers();
  const roomMembers = utils.map(members, function (u) {
    return u.userId;
  }); // The global value is treated as a default for when rooms don't specify a value.

  let isBlacklisting = this._crypto.getGlobalBlacklistUnverifiedDevices();

  if (typeof room.getBlacklistUnverifiedDevices() === 'boolean') {
    isBlacklisting = room.getBlacklistUnverifiedDevices();
  } // We are happy to use a cached version here: we assume that if we already
  // have a list of the user's devices, then we already share an e2e room
  // with them, which means that they will have announced any new devices via
  // device_lists in their /sync response.  This cache should then be maintained
  // using all the device_lists changes and left fields.
  // See https://github.com/vector-im/riot-web/issues/2305 for details.


  const devices = await this._crypto.downloadKeys(roomMembers, false);
  const blocked = {}; // remove any blocked devices

  for (const userId in devices) {
    if (!devices.hasOwnProperty(userId)) {
      continue;
    }

    const userDevices = devices[userId];

    for (const deviceId in userDevices) {
      if (!userDevices.hasOwnProperty(deviceId)) {
        continue;
      }

      if (userDevices[deviceId].isBlocked() || userDevices[deviceId].isUnverified() && isBlacklisting) {
        if (!blocked[userId]) {
          blocked[userId] = {};
        }

        const blockedInfo = userDevices[deviceId].isBlocked() ? {
          code: "m.blacklisted",
          reason: _OlmDevice.WITHHELD_MESSAGES["m.blacklisted"]
        } : {
          code: "m.unverified",
          reason: _OlmDevice.WITHHELD_MESSAGES["m.unverified"]
        };
        blockedInfo.deviceInfo = userDevices[deviceId];
        blocked[userId][deviceId] = blockedInfo;
        delete userDevices[deviceId];
      }
    }
  }

  return [devices, blocked];
};
/**
 * Megolm decryption implementation
 *
 * @constructor
 * @extends {module:crypto/algorithms/DecryptionAlgorithm}
 *
 * @param {object} params parameters, as per
 *     {@link module:crypto/algorithms/DecryptionAlgorithm}
 */


function MegolmDecryption(params) {
  (0, utils.polyfillSuper)(this, _base.DecryptionAlgorithm, params); // events which we couldn't decrypt due to unknown sessions / indexes: map from
  // senderKey|sessionId to Set of MatrixEvents

  this._pendingEvents = {}; // this gets stubbed out by the unit tests.

  this.olmlib = olmlib;
}

utils.inherits(MegolmDecryption, _base.DecryptionAlgorithm);
const PROBLEM_DESCRIPTIONS = {
  no_olm: "The sender was unable to establish a secure channel.",
  unknown: "The secure channel with the sender was corrupted."
};
/**
 * @inheritdoc
 *
 * @param {MatrixEvent} event
 *
 * returns a promise which resolves to a
 * {@link module:crypto~EventDecryptionResult} once we have finished
 * decrypting, or rejects with an `algorithms.DecryptionError` if there is a
 * problem decrypting the event.
 */

MegolmDecryption.prototype.decryptEvent = async function (event) {
  const content = event.getWireContent();

  if (!content.sender_key || !content.session_id || !content.ciphertext) {
    throw new _base.DecryptionError("MEGOLM_MISSING_FIELDS", "Missing fields in input");
  } // we add the event to the pending list *before* we start decryption.
  //
  // then, if the key turns up while decryption is in progress (and
  // decryption fails), we will schedule a retry.
  // (fixes https://github.com/vector-im/riot-web/issues/5001)


  this._addEventToPendingList(event);

  let res;

  try {
    res = await this._olmDevice.decryptGroupMessage(event.getRoomId(), content.sender_key, content.session_id, content.ciphertext, event.getId(), event.getTs());
  } catch (e) {
    if (e.name === "DecryptionError") {
      // re-throw decryption errors as-is
      throw e;
    }

    let errorCode = "OLM_DECRYPT_GROUP_MESSAGE_ERROR";

    if (e && e.message === 'OLM.UNKNOWN_MESSAGE_INDEX') {
      this._requestKeysForEvent(event);

      errorCode = 'OLM_UNKNOWN_MESSAGE_INDEX';
    }

    throw new _base.DecryptionError(errorCode, e ? e.toString() : "Unknown Error: Error is undefined", {
      session: content.sender_key + '|' + content.session_id
    });
  }

  if (res === null) {
    // We've got a message for a session we don't have.
    //
    // (XXX: We might actually have received this key since we started
    // decrypting, in which case we'll have scheduled a retry, and this
    // request will be redundant. We could probably check to see if the
    // event is still in the pending list; if not, a retry will have been
    // scheduled, so we needn't send out the request here.)
    this._requestKeysForEvent(event); // See if there was a problem with the olm session at the time the
    // event was sent.  Use a fuzz factor of 2 minutes.


    const problem = await this._olmDevice.sessionMayHaveProblems(content.sender_key, event.getTs() - 120000);

    if (problem) {
      let problemDescription = PROBLEM_DESCRIPTIONS[problem.type] || PROBLEM_DESCRIPTIONS.unknown;

      if (problem.fixed) {
        problemDescription += " Trying to create a new secure channel and re-requesting the keys.";
      }

      throw new _base.DecryptionError("MEGOLM_UNKNOWN_INBOUND_SESSION_ID", problemDescription, {
        session: content.sender_key + '|' + content.session_id
      });
    }

    throw new _base.DecryptionError("MEGOLM_UNKNOWN_INBOUND_SESSION_ID", "The sender's device has not sent us the keys for this message.", {
      session: content.sender_key + '|' + content.session_id
    });
  } // success. We can remove the event from the pending list, if that hasn't
  // already happened.


  this._removeEventFromPendingList(event);

  const payload = JSON.parse(res.result); // belt-and-braces check that the room id matches that indicated by the HS
  // (this is somewhat redundant, since the megolm session is scoped to the
  // room, so neither the sender nor a MITM can lie about the room_id).

  if (payload.room_id !== event.getRoomId()) {
    throw new _base.DecryptionError("MEGOLM_BAD_ROOM", "Message intended for room " + payload.room_id);
  }

  return {
    clearEvent: payload,
    senderCurve25519Key: res.senderKey,
    claimedEd25519Key: res.keysClaimed.ed25519,
    forwardingCurve25519KeyChain: res.forwardingCurve25519KeyChain
  };
};

MegolmDecryption.prototype._requestKeysForEvent = function (event) {
  const wireContent = event.getWireContent();
  const recipients = event.getKeyRequestRecipients(this._userId);

  this._crypto.requestRoomKey({
    room_id: event.getRoomId(),
    algorithm: wireContent.algorithm,
    sender_key: wireContent.sender_key,
    session_id: wireContent.session_id
  }, recipients);
};
/**
 * Add an event to the list of those awaiting their session keys.
 *
 * @private
 *
 * @param {module:models/event.MatrixEvent} event
 */


MegolmDecryption.prototype._addEventToPendingList = function (event) {
  const content = event.getWireContent();
  const senderKey = content.sender_key;
  const sessionId = content.session_id;

  if (!this._pendingEvents[senderKey]) {
    this._pendingEvents[senderKey] = new Map();
  }

  const senderPendingEvents = this._pendingEvents[senderKey];

  if (!senderPendingEvents.has(sessionId)) {
    senderPendingEvents.set(sessionId, new Set());
  }

  senderPendingEvents.get(sessionId).add(event);
};
/**
 * Remove an event from the list of those awaiting their session keys.
 *
 * @private
 *
 * @param {module:models/event.MatrixEvent} event
 */


MegolmDecryption.prototype._removeEventFromPendingList = function (event) {
  const content = event.getWireContent();
  const senderKey = content.sender_key;
  const sessionId = content.session_id;
  const senderPendingEvents = this._pendingEvents[senderKey];
  const pendingEvents = senderPendingEvents && senderPendingEvents.get(sessionId);

  if (!pendingEvents) {
    return;
  }

  pendingEvents.delete(event);

  if (pendingEvents.size === 0) {
    senderPendingEvents.delete(senderKey);
  }

  if (senderPendingEvents.size === 0) {
    delete this._pendingEvents[senderKey];
  }
};
/**
 * @inheritdoc
 *
 * @param {module:models/event.MatrixEvent} event key event
 */


MegolmDecryption.prototype.onRoomKeyEvent = function (event) {
  const content = event.getContent();
  const sessionId = content.session_id;
  let senderKey = event.getSenderKey();
  let forwardingKeyChain = [];
  let exportFormat = false;
  let keysClaimed;

  if (!content.room_id || !sessionId || !content.session_key) {
    _logger.logger.error("key event is missing fields");

    return;
  }

  if (!senderKey) {
    _logger.logger.error("key event has no sender key (not encrypted?)");

    return;
  }

  if (event.getType() == "m.forwarded_room_key") {
    exportFormat = true;
    forwardingKeyChain = content.forwarding_curve25519_key_chain;

    if (!utils.isArray(forwardingKeyChain)) {
      forwardingKeyChain = [];
    } // copy content before we modify it


    forwardingKeyChain = forwardingKeyChain.slice();
    forwardingKeyChain.push(senderKey);
    senderKey = content.sender_key;

    if (!senderKey) {
      _logger.logger.error("forwarded_room_key event is missing sender_key field");

      return;
    }

    const ed25519Key = content.sender_claimed_ed25519_key;

    if (!ed25519Key) {
      _logger.logger.error(`forwarded_room_key_event is missing sender_claimed_ed25519_key field`);

      return;
    }

    keysClaimed = {
      ed25519: ed25519Key
    };
  } else {
    keysClaimed = event.getKeysClaimed();
  }

  _logger.logger.log(`Received and adding key for megolm session ${senderKey}|${sessionId}`);

  return this._olmDevice.addInboundGroupSession(content.room_id, senderKey, forwardingKeyChain, sessionId, content.session_key, keysClaimed, exportFormat).then(() => {
    // have another go at decrypting events sent with this session.
    this._retryDecryption(senderKey, sessionId).then(success => {
      // cancel any outstanding room key requests for this session.
      // Only do this if we managed to decrypt every message in the
      // session, because if we didn't, we leave the other key
      // requests in the hopes that someone sends us a key that
      // includes an earlier index.
      if (success) {
        this._crypto.cancelRoomKeyRequest({
          algorithm: content.algorithm,
          room_id: content.room_id,
          session_id: content.session_id,
          sender_key: senderKey
        });
      }
    });
  }).then(() => {
    if (this._crypto.backupInfo) {
      // don't wait for the keys to be backed up for the server
      this._crypto.backupGroupSession(content.room_id, senderKey, forwardingKeyChain, content.session_id, content.session_key, keysClaimed, exportFormat).catch(e => {
        // This throws if the upload failed, but this is fine
        // since it will have written it to the db and will retry.
        _logger.logger.log("Failed to back up megolm session", e);
      });
    }
  }).catch(e => {
    _logger.logger.error(`Error handling m.room_key_event: ${e}`);
  });
};
/**
 * @inheritdoc
 *
 * @param {module:models/event.MatrixEvent} event key event
 */


MegolmDecryption.prototype.onRoomKeyWithheldEvent = async function (event) {
  const content = event.getContent();
  const senderKey = content.sender_key;

  if (content.code === "m.no_olm") {
    const sender = event.getSender();

    _logger.logger.warn(`${sender}:${senderKey} was unable to establish an olm session with us`); // if the sender says that they haven't been able to establish an olm
    // session, let's proactively establish one
    // Note: after we record that the olm session has had a problem, we
    // trigger retrying decryption for all the messages from the sender's
    // key, so that we can update the error message to indicate the olm
    // session problem.


    if (await this._olmDevice.getSessionIdForDevice(senderKey)) {
      // a session has already been established, so we don't need to
      // create a new one.
      _logger.logger.debug("New session already created.  Not creating a new one.");

      await this._olmDevice.recordSessionProblem(senderKey, "no_olm", true);
      this.retryDecryptionFromSender(senderKey);
      return;
    }

    let device = this._crypto._deviceList.getDeviceByIdentityKey(content.algorithm, senderKey);

    if (!device) {
      // if we don't know about the device, fetch the user's devices again
      // and retry before giving up
      await this._crypto.downloadKeys([sender], false);
      device = this._crypto._deviceList.getDeviceByIdentityKey(content.algorithm, senderKey);

      if (!device) {
        _logger.logger.info("Couldn't find device for identity key " + senderKey + ": not establishing session");

        await this._olmDevice.recordSessionProblem(senderKey, "no_olm", false);
        this.retryDecryptionFromSender(senderKey);
        return;
      }
    }

    await olmlib.ensureOlmSessionsForDevices(this._olmDevice, this._baseApis, {
      [sender]: [device]
    }, false);
    const encryptedContent = {
      algorithm: olmlib.OLM_ALGORITHM,
      sender_key: this._olmDevice.deviceCurve25519Key,
      ciphertext: {}
    };
    await olmlib.encryptMessageForDevice(encryptedContent.ciphertext, this._userId, this._deviceId, this._olmDevice, sender, device, {
      type: "m.dummy"
    });
    await this._olmDevice.recordSessionProblem(senderKey, "no_olm", true);
    this.retryDecryptionFromSender(senderKey);
    await this._baseApis.sendToDevice("m.room.encrypted", {
      [sender]: {
        [device.deviceId]: encryptedContent
      }
    });
  } else {
    await this._olmDevice.addInboundGroupSessionWithheld(content.room_id, senderKey, content.session_id, content.code, content.reason);
  }
};
/**
 * @inheritdoc
 */


MegolmDecryption.prototype.hasKeysForKeyRequest = function (keyRequest) {
  const body = keyRequest.requestBody;
  return this._olmDevice.hasInboundSessionKeys(body.room_id, body.sender_key, body.session_id // TODO: ratchet index
  );
};
/**
 * @inheritdoc
 */


MegolmDecryption.prototype.shareKeysWithDevice = function (keyRequest) {
  const userId = keyRequest.userId;
  const deviceId = keyRequest.deviceId;

  const deviceInfo = this._crypto.getStoredDevice(userId, deviceId);

  const body = keyRequest.requestBody;
  this.olmlib.ensureOlmSessionsForDevices(this._olmDevice, this._baseApis, {
    [userId]: [deviceInfo]
  }).then(devicemap => {
    const olmSessionResult = devicemap[userId][deviceId];

    if (!olmSessionResult.sessionId) {
      // no session with this device, probably because there
      // were no one-time keys.
      //
      // ensureOlmSessionsForUsers has already done the logging,
      // so just skip it.
      return null;
    }

    _logger.logger.log("sharing keys for session " + body.sender_key + "|" + body.session_id + " with device " + userId + ":" + deviceId);

    return this._buildKeyForwardingMessage(body.room_id, body.sender_key, body.session_id);
  }).then(payload => {
    const encryptedContent = {
      algorithm: olmlib.OLM_ALGORITHM,
      sender_key: this._olmDevice.deviceCurve25519Key,
      ciphertext: {}
    };
    return this.olmlib.encryptMessageForDevice(encryptedContent.ciphertext, this._userId, this._deviceId, this._olmDevice, userId, deviceInfo, payload).then(() => {
      const contentMap = {
        [userId]: {
          [deviceId]: encryptedContent
        }
      }; // TODO: retries

      return this._baseApis.sendToDevice("m.room.encrypted", contentMap);
    });
  });
};

MegolmDecryption.prototype._buildKeyForwardingMessage = async function (roomId, senderKey, sessionId) {
  const key = await this._olmDevice.getInboundGroupSessionKey(roomId, senderKey, sessionId);
  return {
    type: "m.forwarded_room_key",
    content: {
      algorithm: olmlib.MEGOLM_ALGORITHM,
      room_id: roomId,
      sender_key: senderKey,
      sender_claimed_ed25519_key: key.sender_claimed_ed25519_key,
      session_id: sessionId,
      session_key: key.key,
      chain_index: key.chain_index,
      forwarding_curve25519_key_chain: key.forwarding_curve25519_key_chain
    }
  };
};
/**
 * @inheritdoc
 *
 * @param {module:crypto/OlmDevice.MegolmSessionData} session
 */


MegolmDecryption.prototype.importRoomKey = function (session) {
  return this._olmDevice.addInboundGroupSession(session.room_id, session.sender_key, session.forwarding_curve25519_key_chain, session.session_id, session.session_key, session.sender_claimed_keys, true).then(() => {
    if (this._crypto.backupInfo) {
      // don't wait for it to complete
      this._crypto.backupGroupSession(session.room_id, session.sender_key, session.forwarding_curve25519_key_chain, session.session_id, session.session_key, session.sender_claimed_keys, true).catch(e => {
        // This throws if the upload failed, but this is fine
        // since it will have written it to the db and will retry.
        _logger.logger.log("Failed to back up megolm session", e);
      });
    } // have another go at decrypting events sent with this session.


    this._retryDecryption(session.sender_key, session.session_id);
  });
};
/**
 * Have another go at decrypting events after we receive a key
 *
 * @private
 * @param {String} senderKey
 * @param {String} sessionId
 *
 * @return {Boolean} whether all messages were successfully decrypted
 */


MegolmDecryption.prototype._retryDecryption = async function (senderKey, sessionId) {
  const senderPendingEvents = this._pendingEvents[senderKey];

  if (!senderPendingEvents) {
    return true;
  }

  const pending = senderPendingEvents.get(sessionId);

  if (!pending) {
    return true;
  }

  pending.delete(sessionId);

  if (pending.size === 0) {
    this._pendingEvents[senderKey];
  }

  await Promise.all([...pending].map(async ev => {
    try {
      await ev.attemptDecryption(this._crypto);
    } catch (e) {// don't die if something goes wrong
    }
  })); // ev.attemptDecryption will re-add to this._pendingEvents if an event
  // couldn't be decrypted

  return !(this._pendingEvents[senderKey] || {})[sessionId];
};

MegolmDecryption.prototype.retryDecryptionFromSender = async function (senderKey) {
  const senderPendingEvents = this._pendingEvents[senderKey];

  if (!senderPendingEvents) {
    return true;
  }

  delete this._pendingEvents[senderKey];
  await Promise.all([...senderPendingEvents].map(async ([_sessionId, pending]) => {
    await Promise.all([...pending].map(async ev => {
      try {
        await ev.attemptDecryption(this._crypto);
      } catch (e) {// don't die if something goes wrong
      }
    }));
  }));
  return !this._pendingEvents[senderKey];
};

(0, _base.registerAlgorithm)(olmlib.MEGOLM_ALGORITHM, MegolmEncryption, MegolmDecryption);