"use strict";

const base32 = require('rfc4648').base32;
const base64url = require('rfc4648').base64url;
const ChaCha20 = require('xchacha20-js').ChaCha20;
const Constants = require('../constants');
const fs = require('fs-extra');
const Backend =  require('../contract/backend');
const HChaCha20 = require('xchacha20-js').HChaCha20;
const Poly1305 = require('poly1305-js');
const {SodiumPlus, CryptographyKey} = require('sodium-plus');
const Util = require('../util');
const SymmetricKey = require('./key/symmetrickey');
const CryptoOperationException = require('../exception/cryptooperationexception');

let sodium;
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
        if (!sodium) sodium = await SodiumPlus.auto();
        if (!Buffer.isBuffer(plaintext)) {
            plaintext = await Util.toBuffer(plaintext);
        }
        let encKey = Buffer.alloc(32, 0);
        if (Buffer.isBuffer(key)) {
            key.copy(encKey, 0);
        } else if (SymmetricKey.isSymmetricKey(key)) {
            key.getRawKey().copy(encKey, 0);
        } else {
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

        let ciphertext = await sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext,
            nonce,
            new CryptographyKey(encKey),
            aad
        );
        await sodium.sodium_memzero(encKey);
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
        if (!sodium) sodium = await SodiumPlus.auto();
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

        let decrypted;
        try {
            decrypted = await sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                encrypted,
                nonce,
                new CryptographyKey(encKey),
                aad
            );
        } catch (e) {
            await sodium.sodium_memzero(encKey);
            throw new CryptoOperationException('Invalid MAC');
        }
        await sodium.sodium_memzero(encKey);
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
        if (!sodium) sodium = await SodiumPlus.auto();
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
        let hash = await sodium.crypto_generichash(
            plaintext,
            new CryptographyKey(idxKey),
            hashLength
        );
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
        if (!sodium) sodium = await SodiumPlus.auto();
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

        let salt = await sodium.crypto_generichash(idxKey, null, 16);
        await sodium.sodium_memzero(idxKey);

        let hash = await sodium.crypto_pwhash(
            hashLength,
            await Util.toBuffer(plaintext),
            salt,
            opsLimit,
            memLimit
        );
        return Util.andMask(hash.getBuffer(), bitLength);
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
        if (!sodium) sodium = await SodiumPlus.auto();
        tableName = await Util.toBuffer(tableName);
        fieldName = await Util.toBuffer(fieldName);
        indexName = await Util.toBuffer(indexName);

        let hash = await sodium.crypto_generichash(tableName, null, 16);
        let shorthash = await sodium.crypto_shorthash(
            Util.pack([fieldName, indexName]),
            new CryptographyKey(hash)
        );
        return base32.stringify(shorthash)
            .toLowerCase()
            .replace(/=+$/, '');
    }

    /**
     * @param {string|Buffer} password
     * @param {string|Buffer} salt
     */
    async deriveKeyFromPassword(password, salt)
    {
        if (!sodium) sodium = await SodiumPlus.auto();
        let buf = await sodium.crypto_pwhash(
            32,
            await Util.toBuffer(password),
            await Util.toBuffer(salt),
            4, // SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE from PHP
            33554432 // SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE from PHP
        );
        return new SymmetricKey(buf.getBuffer());
    }

    /**
     * @returns {string}
     */
    getPrefix()
    {
        return MAGIC_HEADER;
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
        if (!sodium) sodium = await SodiumPlus.auto();
        let adlen = 45;
        let encKey = Buffer.alloc(32, 0);
        if (Buffer.isBuffer(key)) {
            key.copy(encKey, 0);
        } else if (SymmetricKey.isSymmetricKey(key)) {
            key.getRawKey().copy(encKey, 0);
        } else {
            throw new TypeError('Argument 3 must be a SymmetricKey');
        }

        let header = Buffer.alloc(5, 0);
        let storedMAC = Buffer.alloc(16, 0);
        let salt = Buffer.alloc(16, 0); // argon2id
        let nonce = Buffer.alloc(24, 0);

        let inputFileSize = (await fs.fstat(inputFP)).size;
        if (inputFileSize < 5) {
            throw new CryptoOperationException('Input file is empty');
        }
        await fs.read(inputFP, header, 0, 5);
        if (!await Util.hashEquals(MAGIC_HEADER, header)) {
            throw new CryptoOperationException('Invalid cipher backend for this file');
        }
        await fs.read(inputFP, storedMAC, 0, 16, 5);
        await fs.read(inputFP, salt, 0, 16, 21);
        await fs.read(inputFP, nonce, 0, 24, 37);

        let subkey = await (new HChaCha20()).hChaCha20Bytes(nonce.slice(0, 16), encKey);
        let nonceLast = Buffer.alloc(12, 0);
        nonce.copy(nonceLast, 4, 16, 24);

        let chacha = new ChaCha20();
        let poly = new Poly1305(await chacha.ietfStream(32, nonceLast, subkey));
        let chunkMacKey = new CryptographyKey(
            (await chacha.ietfStream(64, nonceLast, subkey)).slice(32)
        );
        await poly.update(Buffer.from(MAGIC_HEADER));
        await poly.update(salt);
        await poly.update(nonce);
        await poly.update(Buffer.alloc((0x10 - adlen) & 0xf, 0));

        let ciphertext = Buffer.alloc(chunkSize, 0);
        let plaintext;
        let inPos = 61;
        let outPos = 0;
        let toRead = chunkSize;
        let chunkMacs = [];
        let len = 0;

        // Validate the Poly1305 tag, storing MACs of each chunk in memory
        let hash = await sodium.crypto_generichash_init(chunkMacKey, 16);
        let thisChunkMac = Buffer.alloc(16, 0);
        do {
            toRead = (inPos + chunkSize > inputFileSize)
                ? (inputFileSize - inPos)
                : chunkSize;
            len += toRead;

            await fs.read(inputFP, ciphertext, 0, toRead, inPos);
            await poly.update(ciphertext.slice(0, toRead));

            // Chain chunk MACs based on the previous chunk's MAC
            await sodium.crypto_generichash_update(hash, ciphertext.slice(0, toRead));
            thisChunkMac = await sodium.crypto_generichash_final(hash, 16);
            chunkMacs.push(Buffer.concat([thisChunkMac]));
            hash = await sodium.crypto_generichash_init(chunkMacKey, 16);
            await sodium.crypto_generichash_update(hash, thisChunkMac);

            inPos += chunkSize;
            outPos += chunkSize;
        } while(inPos <= inputFileSize);
        thisChunkMac = await sodium.crypto_generichash_final(hash, 16);
        chunkMacs.push(Buffer.concat([thisChunkMac]));

        await poly.update(Buffer.alloc((0x10 - len) & 0xf, 0));
        await poly.update(Util.store64_le(adlen));
        await poly.update(Util.store64_le(len));

        let calcMAC = await poly.finish();
        if (!(await Util.hashEquals(calcMAC, storedMAC))) {
            throw new CryptoOperationException('Invalid authentication tag');
        }

        inPos = 61;
        outPos = 0;
        let block_counter = 1;
        let ctrIncrease = (chunkSize + 63) >>> 6;
        let storedChunkMac;
        hash = await sodium.crypto_generichash_init(chunkMacKey, 16);
        do {
            toRead = (inPos + chunkSize > inputFileSize)
                ? (inputFileSize - inPos)
                : chunkSize;

            await fs.read(inputFP, ciphertext, 0, toRead, inPos);

            // Chain chunk MACs based on the previous chunk's MAC
            await sodium.crypto_generichash_update(hash, ciphertext.slice(0, toRead));
            thisChunkMac = await sodium.crypto_generichash_final(hash, 16);
            storedChunkMac = chunkMacs.shift();
            if (typeof storedChunkMac === 'undefined') {
                throw new CryptoOperationException('Race condition');
            }
            if (!(await Util.hashEquals(storedChunkMac, thisChunkMac))) {
                throw new CryptoOperationException('Race condition');
            }

            hash = await sodium.crypto_generichash_init(chunkMacKey, 16);
            await sodium.crypto_generichash_update(hash, thisChunkMac);

            plaintext = await chacha.ietfStreamXorIc(
                ciphertext.slice(0, toRead),
                nonceLast,
                subkey,
                block_counter
            );

            await fs.write(outputFP, plaintext, 0, toRead, outPos);

            inPos += chunkSize;
            outPos += chunkSize;
            block_counter += ctrIncrease;

        } while(inPos <= inputFileSize);
        thisChunkMac = await sodium.crypto_generichash_final(hash, 16);
        storedChunkMac = chunkMacs.shift();
        if (typeof storedChunkMac === 'undefined') {
            throw new CryptoOperationException('Race condition');
        }
        if (!(await Util.hashEquals(storedChunkMac, thisChunkMac))) {
            throw new CryptoOperationException('Race condition');
        }
        if (chunkMacs.length > 0) {
            throw new CryptoOperationException('Race condition');
        }
        return true;
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
        if (!sodium) sodium = await SodiumPlus.auto();
        let adlen = 45;
        let encKey = Buffer.alloc(32, 0);
        if (Buffer.isBuffer(key)) {
            key.copy(encKey, 0);
        } else if (SymmetricKey.isSymmetricKey(key)) {
            key.getRawKey().copy(encKey, 0);
        } else {
            throw new TypeError('Argument 3 must be a SymmetricKey');
        }
        let inputFileSize = (await fs.fstat(inputFP)).size;
        let nonce = await Util.randomBytes(NONCE_SIZE);
        let subkey = await ((new HChaCha20()).hChaCha20Bytes(nonce.slice(0, 16), encKey));
        let nonceLast = Buffer.alloc(12, 0);
        nonce.copy(nonceLast, 4, 16, 24);

        await fs.write(outputFP, await Util.toBuffer(MAGIC_HEADER), 0, 5, 0);
        // Empty space for MAC
        await fs.write(outputFP, Buffer.alloc(16, 0), 0, 16, 5);
        await fs.write(outputFP, salt, 0, 16, 21);
        await fs.write(outputFP, nonce, 0, 24, 37);

        let chacha = new ChaCha20();
        let poly = new Poly1305(await chacha.ietfStream(32, nonceLast, subkey));
        await poly.update(Buffer.from(MAGIC_HEADER));
        await poly.update(salt);
        await poly.update(nonce);
        await poly.update(Buffer.alloc((0x10 - adlen) & 0xf, 0));

        let plaintext = Buffer.alloc(chunkSize, 0);
        let ciphertext;
        let block_counter = 1;
        let ctrIncrease = (chunkSize + 63) >>> 6;
        let inPos = 0;
        let outPos = 61;
        let toRead = chunkSize;
        let len = 0;
        do {
            toRead = (inPos + chunkSize > inputFileSize)
                ? (inputFileSize - inPos)
                : chunkSize;

            await fs.read(inputFP, plaintext, 0, toRead, inPos);
            ciphertext = await chacha.ietfStreamXorIc(
                plaintext.slice(0, toRead),
                nonceLast,
                subkey,
                block_counter
            );
            await poly.update(ciphertext);
            await fs.write(outputFP, ciphertext, 0, toRead, outPos);

            len += toRead;
            inPos += chunkSize;
            outPos += chunkSize;
            block_counter += ctrIncrease;
        } while (inPos < inputFileSize);

        await poly.update(Buffer.alloc((0x10 - len) & 0xf, 0));
        await poly.update(Util.store64_le(adlen));
        await poly.update(Util.store64_le(len));
        let authTag = await poly.finish();
        await fs.write(outputFP, authTag, 0, 16, 5);

        return true;
    }

    /**
     * @return {number}
     */
    getFileEncryptionSaltOffset()
    {
        return 21;
    }
};
