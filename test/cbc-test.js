'use strict';

let assert = require('assert');
let crypto = require('crypto');
let Buffer = require('buffer').Buffer;

let des = require('../');

let fixtures = require('./fixtures');
let bin = fixtures.bin;

describe('DES-CBC', function() {
  let CBC = des.CBC.instantiate(des.DES);

  describe('encryption/decryption', function() {
    let vectors = [
      {
        key: '133457799bbcdff1',
        iv: '0102030405060708',
        input: '0123456789abcdef'
      },
      {
        key: '0000000000000000',
        iv: 'ffffffffffffffff',
        input: '0000000000000000'
      },
      {
        key: 'a3a3a3a3b3b3b3b3',
        iv: 'cdcdcdcdcdcdcdcd',
        input: 'cccccccccccccccc'
      },
      {
        key: 'deadbeefabbadead',
        iv: 'a0da0da0da0da0da',
        input: '0102030405060708090a'
      },
      {
        key: 'aabbccddeeff0011',
        iv: 'fefefefefefefefe',
        input: '0102030405060708090a0102030405060708090a0102030405060708090a' +
               '0102030405060708090a0102030405060607080a0102030405060708090a'
      }
    ];

    vectors.forEach(function(vec, i) {
      it('should encrypt vector ' + i, function() {
        let key = Buffer.from(vec.key, 'hex');
        let iv = Buffer.from(vec.iv, 'hex');
        let input = Buffer.from(vec.input, 'hex');

        let enc = CBC.create({
          type: 'encrypt',
          key: key,
          iv: iv
        });
        let out = Buffer.from(enc.update(input).concat(enc.final()));

        let cipher = crypto.createCipheriv('des-cbc', key, iv);
        let expected = Buffer.concat([ cipher.update(input), cipher.final() ]);

        assert.deepEqual(out, expected);

        let dec = CBC.create({
          type: 'decrypt',
          key: key,
          iv: iv
        });
        assert.deepEqual(Buffer.from(dec.update(out).concat(dec.final())),
                         input);
      });
    });
  });
});
