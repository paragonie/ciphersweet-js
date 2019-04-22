"use strict";

const base32 = require('rfc4648').base32;
const base64url = require('rfc4648').base64url;
const Backend =  require('../Contract/Backend');
const crypto = require('crypto');
const sodium = require('sodium-native');
const Util = require('../Util');
const SymmetricKey = require('./Key/SymmetricKey');
const CryptoOperationException = require('../Exception/CryptoOperationException');

const MAGIC_HEADER = "fips:";
const MAC_SIZE = 48;
const SALT_SIZE = 32;
const NONCE_SIZE = 16;

/**
 * Class FIPSCrypto
 *
 * This only uses algorithms supported by FIPS-140-2.
 *
 * Please consult your FIPS compliance auditor before you claim that your use
 * of this library is FIPS 140-2 compliant.
 *
 * @ref https://csrc.nist.gov/CSRC/media//Publications/fips/140/2/final/documents/fips1402annexa.pdf
 * @ref https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 * @ref https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
 *
 * @package CipherSweet.Backend
 * @author  Paragon Initiative Enterprises
 */
module.exports = class FIPSCrypto extends Backend
{
    /**
     * AES-256-CTR encrypt
     *
     * @param {Buffer} plaintext
     * @param {Buffer} key
     * @param {Buffer} nonce
     * @return {Buffer}
     */
    aes256ctr(plaintext, key, nonce)
    {
        let ciphertext;
        let cipher = crypto.createCipheriv('aes-256-ctr', key, nonce);
        ciphertext = cipher.update(plaintext);
        cipher.final();
        return ciphertext;
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @param {SymmetricKey} key
     * @param {string|Buffer} aad
     */
    encrypt(plaintext, key, aad = '')
    {
        if (!Buffer.isBuffer(plaintext)) {
            plaintext = Util.toBuffer(plaintext);
        }
        let hkdfSalt = Buffer.alloc(SALT_SIZE);
        let ctrNonce = Buffer.alloc(NONCE_SIZE);
        sodium.randombytes_buf(hkdfSalt);
        sodium.randombytes_buf(ctrNonce);

        let encKey = Util.HKDF(key, hkdfSalt, 'AES-256-CTR');
        let macKey = Util.HKDF(key, hkdfSalt, 'HMAC-SHA-384');

        let ciphertext = this.aes256ctr(plaintext, encKey, ctrNonce);
        sodium.sodium_memzero(encKey);

        let mac;
        if (aad.length > 0) {
            mac = Util.hmac(
                'sha384',
                Buffer.concat([
                    Util.pack([
                        Buffer.from(MAGIC_HEADER, 'binary'),
                        hkdfSalt,
                        ctrNonce,
                        ciphertext
                    ]),
                    Buffer.from(aad)
                ]),
                macKey,
                true
            );
        } else {
            mac = Util.hmac(
                'sha384',
                Util.pack([
                    Buffer.from(MAGIC_HEADER, 'binary'),
                    hkdfSalt,
                    ctrNonce,
                    ciphertext
                ]),
                macKey,
                true
            );
        }
        sodium.sodium_memzero(macKey);

        return MAGIC_HEADER + base64url.stringify(
            Buffer.concat([
                hkdfSalt,
                ctrNonce,
                mac,
                ciphertext
            ])
        );
    }

    /**
     *
     * @param {string|Buffer} ciphertext
     * @param {SymmetricKey} key
     * @param {string|Buffer} aad
     * @return {string}
     */
    decrypt(ciphertext, key, aad = '')
    {
        let header = ciphertext.slice(0, 5);
        if (!Util.hashEquals(MAGIC_HEADER, header)) {
            throw new CryptoOperationException('Invalid ciphertext header.');
        }
        let decoded = Util.toBuffer(base64url.parse(ciphertext.slice(5)));
        let hkdfSalt = decoded.slice(0, SALT_SIZE);
        let ctrNonce = decoded.slice(
            SALT_SIZE,
            SALT_SIZE + NONCE_SIZE
        );
        let mac = decoded.slice(
            SALT_SIZE + NONCE_SIZE,
            SALT_SIZE + NONCE_SIZE + MAC_SIZE
        );
        let cipher = decoded.slice(SALT_SIZE + NONCE_SIZE + MAC_SIZE);

        let macKey = Util.HKDF(key, hkdfSalt, 'HMAC-SHA-384');
        let recalc;
        if (aad.length > 0) {
            recalc = Util.hmac(
                'sha384',
                Buffer.concat([
                    Util.pack([
                        Buffer.from(MAGIC_HEADER, 'binary'),
                        hkdfSalt,
                        ctrNonce,
                        cipher
                    ]),
                    Buffer.from(aad)
                ]),
                macKey,
                true
            );
        } else {
            recalc = Util.hmac(
                'sha384',
                Util.pack([
                    Buffer.from(MAGIC_HEADER, 'binary'),
                    hkdfSalt,
                    ctrNonce,
                    cipher
                ]),
                macKey,
                true
            );
        }
        if (!Util.hashEquals(recalc, mac)) {
            sodium.sodium_memzero(macKey);
            throw new CryptoOperationException('Invalid MAC');
        }
        let encKey = Util.HKDF(key, hkdfSalt, 'AES-256-CTR');

        let plaintext = this.aes256ctr(cipher, encKey, ctrNonce);
        sodium.sodium_memzero(encKey);
        return plaintext.toString('binary');
    }

    /**
     * Perform a fast blind index. Ideal for high-entropy inputs.
     * Algorithm: PBKDF2-SHA384 with only 1 iteration.
     *
     * @param {string|Buffer} plaintext
     * @param {SymmetricKey} key
     * @param {Number} length
     * @param {object} config
     * @return {Buffer}
     */
    blindIndexFast(plaintext, key, length = 256, config = [])
    {
        let ikm;
        if (Buffer.isBuffer(key)) {
            ikm = key;
        } else if (SymmetricKey.isSymmetricKey(key)) {
            ikm = key.getRawKey();
        } else {
            throw new TypeError('Argument 1 must be a SymmetricKey');
        }
        return Util.andMask(
            crypto.pbkdf2Sync(plaintext, ikm, 1, length >>> 3, 'sha384'),
            length
        );
    }

    /**
     * Perform a slower Blind Index calculation.
     * Algorithm: PBKDF2-SHA384 with at least 50,000 iterations.
     *
     * @param {string|Buffer} plaintext
     * @param {SymmetricKey} key
     * @param {Number} length
     * @param {object} config
     * @return {Buffer}
     */
    blindIndexSlow(plaintext, key, length = 256, config = [])
    {
        let ikm;
        if (Buffer.isBuffer(key)) {
            ikm = key;
        } else if (SymmetricKey.isSymmetricKey(key)) {
            ikm = key.getRawKey();
        } else {
            throw new TypeError('Argument 1 must be a SymmetricKey');
        }
        let iterations = 50000;
        if (typeof config['iterations'] !== 'undefined') {
            if (config['iterations'] > 50000) {
                iterations = config['iterations'];
            }
        }
        return Util.andMask(
            crypto.pbkdf2Sync(plaintext, ikm, iterations, length >>> 3, 'sha384'),
            length
        );
    }

    /**
     *
     * @param {string|Buffer} tableName
     * @param {string|Buffer} fieldName
     * @param {string|Buffer} indexName
     * @return {string}
     */
    getIndexTypeColumn(tableName, fieldName, indexName)
    {
        let hash = Util.hmac(
            'sha384',
            Util.pack([
                Buffer.from(fieldName, 'binary'),
                Buffer.from(indexName, 'binary')
            ]),
            tableName,
            true
        );
        return base32.stringify(hash.slice(0, 8))
            .toLowerCase()
            .replace(/=+$/, '');
    }

    /**
     * @returns {string}
     */
    getPrefix()
    {
        return MAGIC_HEADER;
    }
};
