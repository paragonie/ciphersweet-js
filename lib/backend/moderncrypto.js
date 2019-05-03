"use strict";

const base32 = require('rfc4648').base32;
const base64url = require('rfc4648').base64url;
const Backend =  require('../contract/backend');
const sodium = require('sodium-native');
const Util = require('../util');
const SymmetricKey = require('./key/symmetrickey');
const CryptoOperationException = require('../exception/cryptooperationexception');

const MAGIC_HEADER = "nacl:";
const NONCE_SIZE = 24;
const TAG_SIZE = 16;

/**
 * Class ModernCrypto
 *
 * Use modern cryptography (e.g. Curve25519, Chapoly)
 *
 * @package CipherSweet.backend
 * @author  Paragon Initiative Enterprises
 */
module.exports = class ModernCrypto extends Backend
{
    /**
     * Encrypt a message using XChaCha20-Poly1305
     *
     * @param {string|Buffer} plaintext
     * @param {SymmetricKey} key
     * @param {string|Buffer} aad
     * @return {string}
     */
    async encrypt(plaintext, key, aad = '') {
        if (!Buffer.isBuffer(plaintext)) {
            plaintext = await Util.toBuffer(plaintext);
        }
        let encKey = Buffer.alloc(32, 0);
        if (Buffer.isBuffer(key)) {
            key.copy(encKey, 0);
        } else if (SymmetricKey.isSymmetricKey(key)) {
            key.getRawKey().copy(encKey, 0);
        } else {
            console.log(arguments);
            throw new TypeError('Argument 1 must be a SymmetricKey');
        }

        let nonce = await Util.randomBytes(NONCE_SIZE);
        if (aad.length >= 0) {
            if (!Buffer.isBuffer(aad)) {
                aad = await Util.toBuffer(aad);
            }
            aad = Buffer.concat([nonce, aad]);
        } else {
            aad = nonce;
        }

        let ciphertext = Buffer.alloc(plaintext.length + TAG_SIZE, 0);
        sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext,
            plaintext,
            aad,
            null, // secret number, not used in this algorithm
            nonce,
            encKey
        );
        sodium.sodium_memzero(encKey);
        return MAGIC_HEADER + base64url.stringify(
            Buffer.concat([nonce, ciphertext])
        );
    }

    /**
     * Decrypt a message using XChaCha20-Poly1305
     *
     * @param {string|Buffer} ciphertext
     * @param {SymmetricKey} key
     * @param {string|Buffer} aad
     * @return {string}
     */
    async decrypt(ciphertext, key, aad = '')
    {
        let encKey = Buffer.alloc(32, 0);
        if (Buffer.isBuffer(key)) {
            key.copy(encKey, 0);
        } else if (SymmetricKey.isSymmetricKey(key)) {
            key.getRawKey().copy(encKey, 0);
        } else {
            throw new TypeError('Argument 1 must be a SymmetricKey');
        }

        let header = ciphertext.slice(0, 5);
        if (!await Util.hashEquals(MAGIC_HEADER, header)) {
            throw new CryptoOperationException('Invalid ciphertext header.');
        }
        let decoded = await Util.toBuffer(base64url.parse(ciphertext.slice(5)));
        let nonce = decoded.slice(0, NONCE_SIZE);
        let encrypted = decoded.slice(NONCE_SIZE);

        if (aad.length >= 0) {
            if (!Buffer.isBuffer(aad)) {
                aad = await Util.toBuffer(aad);
            }
            aad = Buffer.concat([nonce, aad]);
        } else {
            aad = nonce;
        }

        let decrypted = Buffer.alloc(encrypted.length - TAG_SIZE, 0);
        try {
            sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                decrypted,
                null, // secret number
                encrypted,
                aad,
                nonce,
                encKey
            );
        } catch (e) {
            sodium.sodium_memzero(encKey);
            throw new CryptoOperationException('Invalid MAC');
        }
        sodium.sodium_memzero(encKey);
        return decrypted.toString('binary');
    }

    /**
     *
     * @param {Buffer} plaintext
     * @param {SymmetricKey|Buffer} symmetricKey
     * @param {Number} bitLength
     * @returns {Buffer}
     */
    async blindIndexFast(plaintext, symmetricKey, bitLength = 256)
    {
        let idxKey = Buffer.alloc(32, 0);
        if (Buffer.isBuffer(symmetricKey)) {
            symmetricKey.copy(idxKey, 0);
        } else if (SymmetricKey.isSymmetricKey(symmetricKey)) {
            symmetricKey.getRawKey().copy(idxKey, 0);
        } else {
            throw new TypeError('Argument 1 must be a SymmetricKey');
        }
        plaintext = await Util.toBuffer(plaintext);
        let hashLength = 32;
        if (bitLength > 512) {
            throw new CryptoOperationException('Output length is too high');
        } else if (bitLength > 64) {
            hashLength = bitLength >>> 3;
        }
        let hash = Buffer.alloc(hashLength, 0);
        sodium.crypto_generichash(hash, plaintext, idxKey);
        return Util.andMask(hash, bitLength);
    }


    /**
     *
     * @param {Buffer} plaintext
     * @param {SymmetricKey|Buffer} symmetricKey
     * @param {Number} bitLength
     * @param {object} config
     * @returns {Buffer}
     */
    async blindIndexSlow(plaintext, symmetricKey, bitLength = 256, config = [])
    {
        let idxKey = Buffer.alloc(32, 0);
        if (Buffer.isBuffer(symmetricKey)) {
            symmetricKey.copy(idxKey, 0);
        } else if (SymmetricKey.isSymmetricKey(symmetricKey)) {
            symmetricKey.getRawKey().copy(idxKey, 0);
        } else {
            throw new TypeError('Argument 1 must be a SymmetricKey');
        }
        let hashLength = bitLength >>> 3;
        if (bitLength > 4294967295) {
            throw new CryptoOperationException('Output length is too high');
        }
        if (bitLength < 128) {
            hashLength = 16;
        }
        let opsLimit = 4;
        let memLimit = 33554432;
        if (typeof config['opslimit'] !== 'undefined') {
            if (config['opslimit'] > opsLimit) {
                opsLimit = config['opslimit'];
            }
        }
        if (typeof config['memlimit'] !== 'undefined') {
            if (config['memlimit'] > memLimit) {
                memLimit = config['memlimit'];
            }
        }

        let salt = Buffer.alloc(16, 0);
        sodium.crypto_generichash(salt, idxKey);
        sodium.sodium_memzero(idxKey);

        let hash = Buffer.alloc(hashLength, 0);
        sodium.crypto_pwhash(
            hash,
            await Util.toBuffer(plaintext),
            salt,
            opsLimit,
            memLimit,
            sodium.crypto_pwhash_ALG_ARGON2ID13
        );
        return Util.andMask(hash, bitLength);
    }

    /**
     *
     * @param {string|Buffer} tableName
     * @param {string|Buffer} fieldName
     * @param {string|Buffer} indexName
     * @return {string}
     */
    async getIndexTypeColumn(tableName, fieldName, indexName)
    {
        tableName = await Util.toBuffer(tableName);
        fieldName = await Util.toBuffer(fieldName);
        indexName = await Util.toBuffer(indexName);
        let hash = Buffer.alloc(16, 0);
        let shorthash = Buffer.alloc(8, 0);

        sodium.crypto_generichash(hash, tableName);
        sodium.crypto_shorthash(
            shorthash,
            Util.pack([fieldName, indexName]),
            hash
        );
        return base32.stringify(shorthash.slice(0, 8))
            .toLowerCase()
            .replace(/=+$/, '');
    }

    /**
     * @param {string|Buffer} password
     * @param {string|Buffer} salt
     */
    async deriveKeyFromPassword(password, salt)
    {
        let buf = Buffer.alloc(32, 0);
        sodium.crypto_pwhash(
            Util.toBuffer(password),
            Util.toBuffer(salt),
            4, // SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE
            33554432, // SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            sodium.crypto_pwhash_ALG_ARGON2ID13
        );
        return new SymmetricKey(buf);
    }

    /**
     *
     * @param {number} inputFP
     * @param {number} outputFP
     * @param {SymmetricKey} key
     * @param {number} chunkSize
     * @return {Promise<boolean>}
     */
    async doStreamDecrypt(
        inputFP,
        outputFP,
        key,
        chunkSize = 8192
    ) {

    }

    /**
     *
     * @param {number} inputFP
     * @param {number} outputFP
     * @param {SymmetricKey} key
     * @param {number} chunkSize
     * @param {Buffer} salt
     * @return {Promise<boolean>}
     */
    async doStreamEncrypt(
        inputFP,
        outputFP,
        key,
        chunkSize = 8192,
        salt = Constants.DUMMY_SALT
    ) {

    }

    /**
     * @return {number}
     */
    getFileEncryptionSaltOffset()
    {
        return 21;
    }
};
