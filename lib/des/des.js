'use strict';

const assert = require('minimalistic-assert');
const inherits = require('inherits');

const utils = require('./utils');
const Cipher = require('./cipher');

class DESState {
  constructor() {
    this.tmp = new Array(2);
    this.keys = null;
  }
}

const shiftTable = [
  1, 1, 2, 2, 2, 2, 2, 2,
  1, 2, 2, 2, 2, 2, 2, 1
];

class DES extends Cipher {
  constructor(options) {
    super(options);
    const state = new DESState();

    this._desState = state;
    this.deriveKeys(state, options.key);
  }

  static create(options) {
    return new DES(options);
  }

  deriveKeys(state, key) {
    state.keys = new Array(16 * 2);

    assert.equal(key.length, this.blockSize, 'Invalid key length');

    let kL = utils.readUInt32BE(key, 0);
    let kR = utils.readUInt32BE(key, 4);

    utils.pc1(kL, kR, state.tmp, 0);
    kL = state.tmp[0];
    kR = state.tmp[1];
    for (let i = 0; i < state.keys.length; i += 2) {
      let shift = shiftTable[i >>> 1];
      kL = utils.r28shl(kL, shift);
      kR = utils.r28shl(kR, shift);
      utils.pc2(kL, kR, state.keys, i);
    }
  }

  _update(inp, inOff, out, outOff) {
    let state = this._desState;

    let l = utils.readUInt32BE(inp, inOff);
    let r = utils.readUInt32BE(inp, inOff + 4);

    // Initial Permutation
    utils.ip(l, r, state.tmp, 0);
    l = state.tmp[0];
    r = state.tmp[1];

    if (this.type === 'encrypt')
      this._encrypt(state, l, r, state.tmp, 0);
    else
      this._decrypt(state, l, r, state.tmp, 0);

    l = state.tmp[0];
    r = state.tmp[1];

    utils.writeUInt32BE(out, l, outOff);
    utils.writeUInt32BE(out, r, outOff + 4);
  }

  _pad(buffer, off) {
    if (this.padding === false) {
      return false;
    }

    let value = buffer.length - off;
    for (let i = off; i < buffer.length; i++)
      buffer[i] = value;

    return true;
  }

  _unpad(buffer) {
    if (this.padding === false) {
      return buffer;
    }

    let pad = buffer[buffer.length - 1];
    for (let i = buffer.length - pad; i < buffer.length; i++)
      assert.equal(buffer[i], pad);

    return buffer.slice(0, buffer.length - pad);
  }

  _encrypt(state, lStart, rStart, out, off) {
    let l = lStart;
    let r = rStart;

    // Apply f() x16 times
    for (let i = 0; i < state.keys.length; i += 2) {
      let keyL = state.keys[i];
      let keyR = state.keys[i + 1];

      // f(r, k)
      utils.expand(r, state.tmp, 0);

      keyL ^= state.tmp[0];
      keyR ^= state.tmp[1];
      let s = utils.substitute(keyL, keyR);
      let f = utils.permute(s);

      let t = r;
      r = (l ^ f) >>> 0;
      l = t;
    }

    // Reverse Initial Permutation
    utils.rip(r, l, out, off);
  }

  _decrypt(state, lStart, rStart, out, off) {
    let l = rStart;
    let r = lStart;

    // Apply f() x16 times
    for (let i = state.keys.length - 2; i >= 0; i -= 2) {
      let keyL = state.keys[i];
      let keyR = state.keys[i + 1];

      // f(r, k)
      utils.expand(l, state.tmp, 0);

      keyL ^= state.tmp[0];
      keyR ^= state.tmp[1];
      let s = utils.substitute(keyL, keyR);
      let f = utils.permute(s);

      let t = l;
      l = (r ^ f) >>> 0;
      r = t;
    }

    // Reverse Initial Permutation
    utils.rip(l, r, out, off);
  }
}

module.exports = DES;
