'use strict';

const assert = require('minimalistic-assert');
const inherits = require('inherits');

const Cipher = require('./cipher');
const DES = require('./des');

class EDEState {
  constructor(type, key) {
    assert.equal(key.length, 24, 'Invalid key length');

    let k1 = key.slice(0, 8);
    let k2 = key.slice(8, 16);
    let k3 = key.slice(16, 24);

    if (type === 'encrypt') {
      this.ciphers = [
        DES.create({ type: 'encrypt', key: k1 }),
        DES.create({ type: 'decrypt', key: k2 }),
        DES.create({ type: 'encrypt', key: k3 })
      ];
    } else {
      this.ciphers = [
        DES.create({ type: 'decrypt', key: k3 }),
        DES.create({ type: 'encrypt', key: k2 }),
        DES.create({ type: 'decrypt', key: k1 })
      ];
    }
  }
}

class EDE extends Cipher {
  constructor(options) {
    super(options);
    let state = new EDEState(this.type, this.options.key);
    this._edeState = state;
  }

  create(options) {
    return new EDE(options);
  }

  _update(inp, inOff, out, outOff) {
    let state = this._edeState;

    state.ciphers[0]._update(inp, inOff, out, outOff);
    state.ciphers[1]._update(out, outOff, out, outOff);
    state.ciphers[2]._update(out, outOff, out, outOff);
  }

  _pad(...args) {
    return DES.prototype._pad.apply(this, args);
  }

  _unpad(...args) {
    return DES.prototype._unpad.apply(this, args);
  }
}

module.exports = EDE;
