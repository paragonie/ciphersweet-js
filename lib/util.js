"use strict";

const crypto = require('crypto');
const SodiumPlus = require('sodium-plus').SodiumPlus;
const arrayToBuffer = require('typedarray-to-buffer');
const SymmetricKey = require('./backend/key/symmetrickey');
const CryptoOperationException = require('./exception/cryptooperationexception');

let sodium;

/**
 * Class Util
 *
 * @package CipherSweet
 * @author  Paragon Initiative Enterprises
 */
module.exports = class Util
{
    /**
     * @param {boolean|null} bool
     * @returns {string}
     */
    static boolToChr(bool)
    {
        if (bool === true) {
            return "\x02";
        } else if (bool === false) {
            return "\x01";
        } else if (bool === null) {
            return "\x00";
        } else {
            throw new TypeError('Only TRUE, FALSE, or NULL allowed');
        }
    }

    /**
     * @param {string} chr
     * @returns {boolean|null}
     */
    static chrToBool(chr)
    {
        if (Util.hashEqualsSync(chr[0], "\x02")) {
            return true;
        } else if (Util.hashEqualsSync(chr[0], "\x01")) {
            return false;
        } else if (Util.hashEqualsSync(chr[0], "\x00")) {
            return null;
        } else {
            throw new TypeError('Internal integer is not 0, 1, or 2');
        }
    }

    /**
     *
     * @param {Number} num
     * @returns {Buffer}
     */
    static floatToBuffer(num)
    {
        return arrayToBuffer(new Float64Array([num]).buffer);
    }

    /**
     * @param {Buffer} buffer
     * @returns {Number}
     */
    static bufferToFloat(buffer)
    {
        return buffer.readDoubleLE(0);
    }
    /**
     *
     * @param {string|Buffer} input
     * @param {Number} bits
     * @param {boolean} bitwiseLeft
     */
    static async andMask(input, bits, bitwiseLeft = false)
    {
        input = await Util.toBuffer(input);
        const bytes = bits >>> 3;
        if (bytes >= input.length) {
            input = Buffer.concat([
                input,
                Buffer.alloc(bytes - input.length + 1, 0)
            ]);
        }
        const output = input.slice(0, bytes);
        const leftOver = bits - (bytes << 3);
        const chr = Buffer.alloc(1, 0);
        if (leftOver > 0) {
            let mask = (1 << leftOver) - 1;
            if (!bitwiseLeft) {
                mask = (mask & 0xF0) >>> 4 | (mask & 0x0F) << 4;
                mask = (mask & 0xCC) >>> 2 | (mask & 0x33) << 2;
                mask = (mask & 0xAA) >>> 1 | (mask & 0x55) << 1;
            }
            chr[0] = input[bytes] & mask;
            return Buffer.concat([output, chr]);
        }
        return output;
    }

    /**
     *
     * @param {string|Buffer} input
     * @param {Number} bits
     * @param {boolean} bitwiseLeft
     */
    static andMaskSync(input, bits, bitwiseLeft = false)
    {
        input = Util.toBufferSync(input);
        const bytes = bits >>> 3;
        if (bytes >= input.length) {
            input = Buffer.concat([
                input,
                Buffer.alloc(bytes - input.length + 1, 0)
            ]);
        }
        let output = input.slice(0, bytes);
        const leftOver = bits - (bytes << 3);
        const chr = Buffer.alloc(1, 0);
        if (leftOver > 0) {
            let mask = (1 << leftOver) - 1;
            if (!bitwiseLeft) {
                mask = (mask & 0xF0) >>> 4 | (mask & 0x0F) << 4;
                mask = (mask & 0xCC) >>> 2 | (mask & 0x33) << 2;
                mask = (mask & 0xAA) >>> 1 | (mask & 0x55) << 1;
            }
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
     * @returns {Number}
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
        const hasher = crypto.createHash(algo);
        hasher.update('');
        const digest = hasher.digest();
        return digest.length;
    }

    /**
     * Compare two strings without timing leaks.
     *
     * @param {string|Buffer} a
     * @param {string|Buffer} b
     * @returns {boolean}
     */
    static async hashEquals(a, b)
    {
        return crypto.timingSafeEqual(
            await Util.toBuffer(a),
            await Util.toBuffer(b)
        );
    }

    /**
     * Compare two strings without timing leaks.
     *
     * @param {string|Buffer} a
     * @param {string|Buffer} b
     * @returns {boolean}
     */
    static hashEqualsSync(a, b)
    {
        return crypto.timingSafeEqual(
            Util.toBufferSync(a),
            Util.toBufferSync(b)
        );
    }

    /**
     *
     * @param {string} hash
     * @param {string|Buffer} message
     * @param {string|Buffer} key
     * @param {boolean} binary
     * @returns {string|Buffer}
     */
    static async hmac(hash, message, key, binary = false)
    {
        const auth = crypto.createHmac(hash, key);
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
     * @returns {Buffer}
     * @constructor
     */
    static async HKDF(key, salt, info = '', length = 32, hash = 'sha384')
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
            info = await Util.toBuffer(info);
        }
        const digestLength = Util.hashDigestLength(hash);

        if (length < 0 || length > (255 * digestLength)) {
            throw new CryptoOperationException('Bad output length requested of HKDF.')
        }
        if (salt) {
            salt = await Util.toBuffer(salt);
        } else {
            salt = Buffer.alloc(digestLength, 0);
        }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        const prk = await Util.hmac(
            hash,
            ikm,
            salt,
            true
        );

        // HKDF-Expand:
        // T(0) = ''
        let last_block = Buffer.alloc(0);
        let t = Buffer.alloc(0);
        const c = Buffer.alloc(1);
        for (let i = 1; t.length < length; i++) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            c[0] = i;
            last_block = await Util.hmac(
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
     *
     * @param {Buffer} nonce
     * @param {number} amount
     * @returns {Promise<Buffer>}
     */
    static async increaseCtrNonce(nonce, amount = 1)
    {
        const outNonce = Buffer.alloc(16, 0);
        nonce.copy(outNonce, 0, 0, 16);
        let c = amount;
        let x;
        for (let i = 15; i >= 0; i--) {
            x = outNonce[i] + c;
            c = x >>> 8;
            outNonce[i] = x & 0xff;
        }
        return outNonce;
    }

    /**
     * Node.js only supports 32-bit numbers so we discard the top 4 bytes.
     *
     * @param {Buffer} buf
     * @returns {Number}
     */
    static load64_le(buf)
    {
        return buf.readInt32LE(0);
    }

    /**
     * Pack chunks together for feeding into HMAC.
     *
     * @param {Buffer[]} pieces
     * @returns Buffer
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
     * await-able PBKDF2 interface
     *
     * @param {Buffer} password
     * @param {Buffer} salt
     * @param {number} iterations
     * @param {number} keylen
     * @param {string} digest
     * @returns {Promise<Buffer>}
     */
    static pbkdf2(password, salt, iterations, keylen, digest)
    {
        return new Promise( (res, rej) => {
            crypto.pbkdf2(password, salt, iterations, keylen, digest, (err, key) => {
                err ? rej(err) : res(key);
            });
        });
    }

    /**
     * @param {Number} len
     * @returns {Buffer}
     */
    static async randomBytes(len)
    {
        if (!sodium) sodium = await SodiumPlus.auto();
        return sodium.randombytes_buf(len);
    }

    /**
     * Store a 32-bit integer as a buffer of length 4
     *
     * @param {Number} num
     * @returns {Buffer}
     */
    static store32_le(num)
    {
        const result = Buffer.alloc(4, 0);
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
     * @returns {Buffer}
     */
    static store64_le(num)
    {
        const result = Buffer.alloc(8, 0);
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
    static async toBuffer(stringOrBuffer)
    {
        if (stringOrBuffer === null) {
            return Buffer.alloc(0);
        }
        if (Buffer.isBuffer(stringOrBuffer)) {
            return stringOrBuffer;
        } else if (typeof(stringOrBuffer) === 'number') {
            return Buffer.from("" + stringOrBuffer, 'utf-8');
        } else if (typeof(stringOrBuffer) === 'string') {
            return Buffer.from(stringOrBuffer, 'binary');
        } else if (stringOrBuffer instanceof Uint8Array) {
            return arrayToBuffer(stringOrBuffer);
        } else if (stringOrBuffer instanceof Promise) {
            return await stringOrBuffer;
        } else {
            throw new TypeError('Invalid type; string or buffer expected');
        }
    }

    /**
     * Coerce input to a Buffer, throwing a TypeError if it cannot be coerced.
     *
     * @param {string|Buffer|Uint8Array} stringOrBuffer
     * @returns {Buffer}
     */
    static toBufferSync(stringOrBuffer)
    {
        if (Buffer.isBuffer(stringOrBuffer)) {
            return stringOrBuffer;
        } else if (typeof(stringOrBuffer) === 'string') {
            return Buffer.from(stringOrBuffer, 'binary');
        } else if (stringOrBuffer instanceof Uint8Array) {
            return arrayToBuffer(stringOrBuffer);
        } else if (stringOrBuffer instanceof Promise) {
            throw new TypeError('Promise passed instead of buffer. Please await your promises.');
        } else {
            throw new TypeError('Invalid type; string or buffer expected');
        }
    }
};
