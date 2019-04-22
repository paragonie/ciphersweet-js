"use strict";

const crypto = require('crypto');
const sodium = require('sodium-native');
const arrayToBuffer = require('typedarray-to-buffer');
const SymmetricKey = require('./Backend/Key/SymmetricKey');
const CryptoOperationException = require('./Exception/CryptoOperationException');

/**
 * Class Util
 *
 * @package CipherSweet
 * @author  Paragon Initiative Enterprises
 */
module.exports = class Util
{
    /**
     *
     * @param {string|Buffer} input
     * @param {Number} bits
     * @param {boolean} bitwiseLeft
     */
    static andMask(input, bits, bitwiseLeft = false)
    {
        input = Util.toBuffer(input);
        let bytes = bits >>> 3;
        if (bytes >= input.length) {
            input = Buffer.concat([
                input,
                Buffer.alloc(bytes - input.length + 1, 0)
            ]);
        }
        let output = input.slice(0, bytes);
        let leftOver = bits - (bytes << 3);
        if (leftOver > 0) {
            let mask = (1 << leftOver) - 1;
            if (!bitwiseLeft) {
                mask = (mask & 0xF0) >>> 4 | (mask & 0x0F) << 4;
                mask = (mask & 0xCC) >>> 2 | (mask & 0x33) << 2;
                mask = (mask & 0xAA) >>> 1 | (mask & 0x55) << 1;
            }
            let chr = Buffer.alloc(1, 0);
            chr[0] = input[bytes] & mask;
            output = Buffer.concat([output, chr]);
        }
        return output;
    }

    /**
     * Gets the string representation of a Buffer.
     *
     * @param {Buffer} buffer
     * @returns {string}
     */
    static fromBuffer(buffer)
    {
        if (!Buffer.isBuffer(buffer)) {
            throw new TypeError('Invalid type; string or buffer expected');
        }
        return buffer.toString('binary');
    }

    /**
     * Get the digest size based on a hash function name.
     *
     * @param {string} algo
     * @return {Number}
     */
    static hashDigestLength(algo)
    {
        if (algo === 'sha256') {
            return 32;
        } else if (algo === 'sha384') {
            return 48;
        } else if (algo === 'sha512') {
            return 64;
        } else if (algo === 'sha224') {
            return 24;
        }
        let hasher = crypto.createHash(algo);
        hasher.update('');
        let digest = hasher.digest();
        return digest.length;
    }

    /**
     * Compare two strings without timing leaks.
     *
     * @param {string|Buffer} a
     * @param {string|Buffer} b
     * @returns {boolean}
     */
    static hashEquals(a, b)
    {
        let random = Buffer.alloc(32);
        sodium.randombytes_buf(random);
        let x = Buffer.alloc(32);
        let y = Buffer.alloc(32);
        sodium.crypto_generichash(x, Util.toBuffer(a), random);
        sodium.crypto_generichash(y, Util.toBuffer(b), random);
        sodium.sodium_memzero(random);
        return sodium.sodium_memcmp(x, y);
    }

    /**
     *
     * @param {string} hash
     * @param {string|Buffer} message
     * @param {string|Buffer} key
     * @param {boolean} binary
     * @returns {string|Buffer}
     */
    static hmac(hash, message, key, binary = false)
    {
        let auth = crypto.createHmac(hash, key);
        auth.update(message);
        if (binary) {
            return auth.digest();
        }
        return auth.digest('hex');
    }

    /**
     * HKDF - RFC 5869
     *
     * @param {SymmetricKey|Buffer} key
     * @param {string|Buffer} salt
     * @param {string|Buffer} info
     * @param {Number} length
     * @param {string} hash
     * @return {Buffer}
     * @constructor
     */
    static HKDF(key, salt, info = '', length = 32, hash = 'sha384')
    {
        let ikm;

        if (Buffer.isBuffer(key)) {
            ikm = key;
        } else if (SymmetricKey.isSymmetricKey(key)) {
            ikm = key.getRawKey();
        } else {
            throw new TypeError('Argument 1 must be a SymmetricKey');
        }
        if (!Buffer.isBuffer(info)) {
            info = Util.toBuffer(info);
        }
        let digestLength = Util.hashDigestLength(hash);

        if (length < 0 || length > (255 * digestLength)) {
            throw new CryptoOperationException('Bad output length requested of HKDF.')
        }
        if (salt) {
            salt = Util.toBuffer(salt);
        } else {
            salt = Buffer.alloc(digestLength, 0);
        }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        let prk = Util.hmac(
            hash,
            ikm,
            salt,
            true
        );

        // HKDF-Expand:
        // T(0) = ''
        let last_block = Buffer.alloc(0);
        let t = Buffer.alloc(0);
        let c = Buffer.alloc(1);
        for (let i = 1; t.length < length; i++) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            c[0] = i;
            last_block = Util.hmac(
                hash,
                Buffer.concat([
                    last_block,
                    info,
                    c
                ]),
                prk,
                true
            );
            t = Buffer.concat([t, last_block]);
        }
        return t.slice(0, length);
    }

    /**
     * Pack chunks together for feeding into HMAC.
     *
     * @param {Buffer[]} pieces
     * @return Buffer
     */
    static pack(pieces)
    {
        let output = Util.store32_le(pieces.length);
        let piece;
        let pieceLen;
        for (let i = 0; i < pieces.length; i++) {
            piece = pieces[i];
            pieceLen = Util.store64_le(piece.length);
            output = Buffer.concat([output, pieceLen, piece]);
        }
        return output;
    }

    /**
     * @param {Number} len
     * @return {Buffer}
     */
    static randomBytes(len)
    {
        let buf = Buffer.alloc(len, 0);
        sodium.randombytes_buf(buf);
        return buf;
    }

    /**
     * Store a 32-bit integer as a buffer of length 4
     *
     * @param {Number} num
     * @return {Buffer}
     */
    static store32_le(num)
    {
        let result = Buffer.alloc(4, 0);
        result[0] = num & 0xff;
        result[1] = (num >>>  8) & 0xff;
        result[2] = (num >>> 16) & 0xff;
        result[3] = (num >>> 24) & 0xff;
        return result;
    }

    /**
     * JavaScript only supports 32-bit integers, so we're going to
     * zero-fill the rightmost bytes.
     *
     * @param {Number} num
     * @return {Buffer}
     */
    static store64_le(num)
    {
        let result = Buffer.alloc(8, 0);
        result[0] = num & 0xff;
        result[1] = (num >>>  8) & 0xff;
        result[2] = (num >>> 16) & 0xff;
        result[3] = (num >>> 24) & 0xff;
        return result;
    }

    /**
     * Coerce input to a Buffer, throwing a TypeError if it cannot be coerced.
     *
     * @param {string|Buffer|Uint8Array} stringOrBuffer
     * @returns {Buffer}
     */
    static toBuffer(stringOrBuffer)
    {
        if (Buffer.isBuffer(stringOrBuffer)) {
            return stringOrBuffer;
        } else if (typeof(stringOrBuffer) === 'string') {
            return Buffer.from(stringOrBuffer, 'binary');
        } else if (stringOrBuffer instanceof Uint8Array) {
            return arrayToBuffer(stringOrBuffer);
        } else {
            throw new TypeError('Invalid type; string or buffer expected');
        }
    }
};
