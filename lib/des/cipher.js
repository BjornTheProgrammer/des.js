'use strict';

const assert = require('minimalistic-assert');

class Cipher {
  constructor (options) {
    this.options = options;

    this.type = this.options.type;
    this.blockSize = 8;
    this._init();

    this.buffer = new Array(this.blockSize);
    this.bufferOff = 0;
    this.padding = options.padding !== false
  }

  _init() {
    // Might be overrided
  }

  update(data) {
    if (data.length === 0)
      return [];

    if (this.type === 'decrypt')
      return this._updateDecrypt(data);
    else
      return this._updateEncrypt(data);
  }

  _buffer(data, off) {
    // Append data to buffer
    let min = Math.min(this.buffer.length - this.bufferOff, data.length - off);
    for (let i = 0; i < min; i++)
      this.buffer[this.bufferOff + i] = data[off + i];
    this.bufferOff += min;

    // Shift next
    return min;
  }

  _flushBuffer(out, off) {
    this._update(this.buffer, 0, out, off);
    this.bufferOff = 0;
    return this.blockSize;
  }

  _updateEncrypt(data) {
    let inputOff = 0;
    let outputOff = 0;

    let count = ((this.bufferOff + data.length) / this.blockSize) | 0;
    let out = new Array(count * this.blockSize);

    if (this.bufferOff !== 0) {
      inputOff += this._buffer(data, inputOff);

      if (this.bufferOff === this.buffer.length)
        outputOff += this._flushBuffer(out, outputOff);
    }

    // Write blocks
    let max = data.length - ((data.length - inputOff) % this.blockSize);
    for (; inputOff < max; inputOff += this.blockSize) {
      this._update(data, inputOff, out, outputOff);
      outputOff += this.blockSize;
    }

    // Queue rest
    for (; inputOff < data.length; inputOff++, this.bufferOff++)
      this.buffer[this.bufferOff] = data[inputOff];

    return out;
  }

  _updateDecrypt(data) {
    let inputOff = 0;
    let outputOff = 0;

    let count = Math.ceil((this.bufferOff + data.length) / this.blockSize) - 1;
    let out = new Array(count * this.blockSize);

    // TODO(indutny): optimize it, this is far from optimal
    for (; count > 0; count--) {
      inputOff += this._buffer(data, inputOff);
      outputOff += this._flushBuffer(out, outputOff);
    }

    // Buffer rest of the input
    inputOff += this._buffer(data, inputOff);

    return out;
  }

  final(buffer) {
    let first;
    if (buffer)
      first = this.update(buffer);

    let last;
    if (this.type === 'encrypt')
      last = this._finalEncrypt();
    else
      last = this._finalDecrypt();

    if (first)
      return first.concat(last);
    else
      return last;
  }

  _pad(buffer, off) {
    if (off === 0)
      return false;

    while (off < buffer.length)
      buffer[off++] = 0;

    return true;
  }

  _finalEncrypt() {
    if (!this._pad(this.buffer, this.bufferOff))
      return [];

    let out = new Array(this.blockSize);
    this._update(this.buffer, 0, out, 0);
    return out;
  }

  _unpad(buffer) {
    return buffer;
  }

  _finalDecrypt() {
    assert.equal(this.bufferOff, this.blockSize, 'Not enough data to decrypt');
    let out = new Array(this.blockSize);
    this._flushBuffer(out, 0);

    return this._unpad(out);
  }
}

module.exports = Cipher;
