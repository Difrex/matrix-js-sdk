"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.InvalidStoreError = InvalidStoreError;
exports.InvalidCryptoStoreError = InvalidCryptoStoreError;

// can't just do InvalidStoreError extends Error
// because of http://babeljs.io/docs/usage/caveats/#classes
function InvalidStoreError(reason, value) {
  const message = `Store is invalid because ${reason}, ` + `please stop the client, delete all data and start the client again`;
  const instance = Reflect.construct(Error, [message]);
  Reflect.setPrototypeOf(instance, Reflect.getPrototypeOf(this));
  instance.reason = reason;
  instance.value = value;
  return instance;
}

InvalidStoreError.TOGGLED_LAZY_LOADING = "TOGGLED_LAZY_LOADING";
InvalidStoreError.prototype = Object.create(Error.prototype, {
  constructor: {
    value: Error,
    enumerable: false,
    writable: true,
    configurable: true
  }
});
Reflect.setPrototypeOf(InvalidStoreError, Error);

function InvalidCryptoStoreError(reason) {
  const message = `Crypto store is invalid because ${reason}, ` + `please stop the client, delete all data and start the client again`;
  const instance = Reflect.construct(Error, [message]);
  Reflect.setPrototypeOf(instance, Reflect.getPrototypeOf(this));
  instance.reason = reason;
  instance.name = 'InvalidCryptoStoreError';
  return instance;
}

InvalidCryptoStoreError.TOO_NEW = "TOO_NEW";
InvalidCryptoStoreError.prototype = Object.create(Error.prototype, {
  constructor: {
    value: Error,
    enumerable: false,
    writable: true,
    configurable: true
  }
});
Reflect.setPrototypeOf(InvalidCryptoStoreError, Error);