'use strict';

const assert = require('minimalistic-assert');
const inherits = require('inherits');

class CBCState {
  constructor(iv) {
    assert.equal(iv.length, 8, 'Invalid IV length');

    this.iv = new Array(8);
    for (let i = 0; i < this.iv.length; i++)
      this.iv[i] = iv[i];
  }
}

function instantiate(Base) {
  class CBC extends Base {
    constructor(options) {
      super(options);
      this._cbcInit();
    }

    static create(options) {
      return new CBC(options);
    }

    _cbcInit() {
      let state = new CBCState(this.options.iv);
      this._cbcState = state;
    }

    _update(inp, inOff, out, outOff) {
      let state = this._cbcState;

      let iv = state.iv;
      if (this.type === 'encrypt') {
        for (let i = 0; i < this.blockSize; i++)
          iv[i] ^= inp[inOff + i];

        super._update(iv, 0, out, outOff);

        for (let i = 0; i < this.blockSize; i++)
          iv[i] = out[outOff + i];
      } else {
        super._update(inp, inOff, out, outOff);

        for (let i = 0; i < this.blockSize; i++)
          out[outOff + i] ^= iv[i];

        for (let i = 0; i < this.blockSize; i++)
          iv[i] = inp[inOff + i];
      }
    }
  }

  return CBC;
}

exports.instantiate = instantiate;
