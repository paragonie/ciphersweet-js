"use strict";

const base32 = require('rfc4648').base32;
const base64url = require('rfc4648').base64url;
const Constants = require('../constants');
const fs = require('fs-extra');
const Backend =  require('../contract/backend');
const {ChaCha20, HChaCha20, XChaCha20} = require('xchacha20-js');
const {SodiumPlus, CryptographyKey} = require('sodium-plus');
const Util = require('../util');
const SymmetricKey = require('./key/symmetrickey');
const CryptoOperationException = require('../exception/cryptooperationexception');

let sodium;
const MAGIC_HEADER = "brng:";
const NONCE_SIZE = 24;
const TAG_SIZE = 32;

/**
 * Class BoringCrypto
 *
 * Newer alternative to ModernCrypto. Doesn't use Poly1305.
 *
 * @package CipherSweet.backend
 * @author  Paragon Initiative Enterprises
 */
module.exports = class BoringCrypto extends Backend {
    /**
     * @returns {boolean}
     */
    multiTenantSafe() {
        return true;
    }

    /**
     * @param {Buffer} key
     * @returns {Promise<SymmetricKey>}
     */
    async getEncryptionKey(key) {
        if (!sodium) sodium = await SodiumPlus.auto();
        return new SymmetricKey(
            await sodium.crypto_generichash(
                'message-encryption',
                new CryptographyKey(key),
                32
            )
        );
    }

    /**
     * @param {Buffer} key
     * @returns {Promise<SymmetricKey>}
     */
    async getIntegrityKey(key) {
        if (!sodium) sodium = await SodiumPlus.auto();
        return new SymmetricKey(
            await sodium.crypto_generichash(
                'message-integrity',
                new CryptographyKey(key),
                32
            )
        );
    }

    /**
     * Encrypt a message using XChaCha20-B2MAC
     *
     * @param {string|Buffer} plaintext
     * @param {SymmetricKey} key
     * @param {string|Buffer} aad
     * @returns {string}
     */
    async encrypt(plaintext, key, aad = '') {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (!Buffer.isBuffer(plaintext)) {
            plaintext = await Util.toBuffer(plaintext);
        }
        const encKey = Buffer.alloc(32, 0);
        if (Buffer.isBuffer(key)) {
            key.copy(encKey, 0);
        } else if (SymmetricKey.isSymmetricKey(key)) {
            key.getRawKey().copy(encKey, 0);
        } else {
            throw new TypeError('Argument 1 must be a SymmetricKey');
        }

        const nonce = await Util.randomBytes(NONCE_SIZE);
        if (aad.length >= 0) {
            if (!Buffer.isBuffer(aad)) {
                aad = await Util.toBuffer(aad);
            }
            aad = Buffer.concat([nonce, aad]);
        } else {
            aad = nonce;
        }
        const xchacha = new XChaCha20();
        const ciphertext = await xchacha.encrypt(
            plaintext,
            nonce,
            (await this.getEncryptionKey(encKey)).getRawKey()
        );

        const mac = await sodium.crypto_generichash(
            Buffer.concat([
                Buffer.from(MAGIC_HEADER, 'utf-8'),
                nonce,
                Buffer.from((aad.length) + '', 'utf-8'),
                aad,
                Buffer.from((ciphertext.length) + '', 'utf-8'),
                ciphertext
            ]),
            new CryptographyKey(
                (await this.getIntegrityKey(encKey)).getRawKey()
            ),
            TAG_SIZE
        );

        await sodium.sodium_memzero(encKey);
        return MAGIC_HEADER + base64url.stringify(
            Buffer.concat([nonce, mac, ciphertext])
        );
    }

    /**
     * Decrypt a message using XChaCha20-B2MAC
     *
     * @param {string} ciphertext
     * @param {string|Buffer} key
     * @param {string|Buffer} aad
     * @returns {Promise<string>}
     */
    async decrypt(ciphertext, key, aad = '')
    {
        if (!sodium) sodium = await SodiumPlus.auto();
        const encKey = Buffer.alloc(32, 0);
        if (Buffer.isBuffer(key)) {
            key.copy(encKey, 0);
        } else if (SymmetricKey.isSymmetricKey(key)) {
            key.getRawKey().copy(encKey, 0);
        } else {
            throw new TypeError('Argument 1 must be a SymmetricKey');
        }

        const header = ciphertext.slice(0, 5);
        if (!await Util.hashEquals(MAGIC_HEADER, header)) {
            throw new CryptoOperationException('Invalid ciphertext header.');
        }
        const decoded = await Util.toBuffer(base64url.parse(ciphertext.slice(5)));
        const nonce = decoded.slice(0, NONCE_SIZE);
        const tag = decoded.slice(NONCE_SIZE, NONCE_SIZE + TAG_SIZE);
        const encrypted = decoded.slice(NONCE_SIZE + TAG_SIZE);

        if (aad.length >= 0) {
            if (!Buffer.isBuffer(aad)) {
                aad = await Util.toBuffer(aad);
            }
            aad = Buffer.concat([nonce, aad]);
        } else {
            aad = nonce;
        }
        const calc = await sodium.crypto_generichash(
            Buffer.concat([
                Buffer.from(MAGIC_HEADER, 'utf-8'),
                nonce,
                Buffer.from((aad.length) + '', 'utf-8'),
                aad,
                Buffer.from((encrypted.length) + '', 'utf-8'),
                encrypted
            ]),
            new CryptographyKey(
                (await this.getIntegrityKey(encKey)).getRawKey()
            ),
            TAG_SIZE
        );

        if (!(await sodium.sodium_memcmp(calc, tag))) {
            await sodium.sodium_memzero(encKey);
            throw new CryptoOperationException('Invalid MAC');
        }
        const xchacha = new XChaCha20();
        const decrypted = await xchacha.decrypt(
            encrypted,
            nonce,
            (await this.getEncryptionKey(encKey)).getRawKey()
        );

        await sodium.sodium_memzero(encKey);
        return decrypted.toString('binary');
    }

    // NEW


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
        const idxKey = Buffer.alloc(32, 0);
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
        const hash = await sodium.crypto_generichash(
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
        const idxKey = Buffer.alloc(32, 0);
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

        const salt = await sodium.crypto_generichash(idxKey, null, 16);
        await sodium.sodium_memzero(idxKey);

        const hash = await sodium.crypto_pwhash(
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
     * @returns {string}
     */
    async getIndexTypeColumn(tableName, fieldName, indexName)
    {
        if (!sodium) sodium = await SodiumPlus.auto();
        tableName = await Util.toBuffer(tableName);
        fieldName = await Util.toBuffer(fieldName);
        indexName = await Util.toBuffer(indexName);

        const hash = await sodium.crypto_generichash(tableName, null, 16);
        const shorthash = await sodium.crypto_shorthash(
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
        const buf = await sodium.crypto_pwhash(
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
     * @returns {Promise<boolean>}
     */
    async doStreamDecrypt(
        inputFP,
        outputFP,
        key,
        chunkSize = 8192
    ) {
        if (!sodium) sodium = await SodiumPlus.auto();
        let adlen = 61;
        const encKey = Buffer.alloc(32, 0);
        if (Buffer.isBuffer(key)) {
            key.copy(encKey, 0);
        } else if (SymmetricKey.isSymmetricKey(key)) {
            key.getRawKey().copy(encKey, 0);
        } else {
            throw new TypeError('Argument 3 must be a SymmetricKey');
        }

        const header = Buffer.alloc(5, 0);
        const storedMAC = Buffer.alloc(32, 0);
        const salt = Buffer.alloc(16, 0); // argon2id
        const nonce = Buffer.alloc(24, 0);

        const inputFileSize = (await fs.fstat(inputFP)).size;
        if (inputFileSize < 5) {
            throw new CryptoOperationException('Input file is empty');
        }
        await fs.read(inputFP, header, 0, 5);
        if (!await Util.hashEquals(MAGIC_HEADER, header)) {
            throw new CryptoOperationException('Invalid cipher backend for this file');
        }
        await fs.read(inputFP, storedMAC, 0, TAG_SIZE, 5);
        await fs.read(inputFP, salt, 0, 16, 37);
        await fs.read(inputFP, nonce, 0, 24, 53);

        const subkey = await (new HChaCha20()).hChaCha20Bytes(
            nonce.slice(0, 16),
            (await this.getEncryptionKey(key.getRawKey())).getRawKey()
        );
        const nonceLast = Buffer.alloc(12, 0);
        nonce.copy(nonceLast, 4, 16, 24);

        const chacha = new ChaCha20();

        const b2mac = await sodium.crypto_generichash_init(
            new CryptographyKey((await this.getIntegrityKey(key.getRawKey())).getRawKey()),
            TAG_SIZE
        );
        await sodium.crypto_generichash_update(b2mac, Buffer.from(MAGIC_HEADER));
        await sodium.crypto_generichash_update(b2mac, salt);
        await sodium.crypto_generichash_update(b2mac, nonce);

        // $chunkMacKey = $this->getIntegrityKey($this->getIntegrityKey($key))->getRawKey();
        const chunkMacKey = new CryptographyKey((
            await this.getIntegrityKey(
                (await this.getIntegrityKey(key.getRawKey())).getRawKey()
            )
        ).getRawKey());

        const ciphertext = Buffer.alloc(chunkSize, 0);
        let plaintext;
        let inPos = 77; // 5 (header) + 24 (nonce) + 32 (authtag) + 16 (salt)
        let outPos = 0;
        let toRead = chunkSize;
        const chunkMacs = [];
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
            await sodium.crypto_generichash_update(b2mac, ciphertext.slice(0, toRead));
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

        await sodium.crypto_generichash_update(b2mac, Util.store64_le(adlen));
        await sodium.crypto_generichash_update(b2mac, Util.store64_le(len));

        const calcMAC = await sodium.crypto_generichash_final(b2mac);
        if (!(await Util.hashEquals(calcMAC, storedMAC))) {
            throw new CryptoOperationException('Invalid authentication tag');
        }

        inPos = 77; // 5 (header) + 24 (nonce) + 32 (authtag) + 16 (salt)
        outPos = 0;
        let block_counter = 1;
        const ctrIncrease = (chunkSize + 63) >>> 6;
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
     * @returns {Promise<boolean>}
     */
    async doStreamEncrypt(
        inputFP,
        outputFP,
        key,
        chunkSize = 8192,
        salt = Constants.DUMMY_SALT
    ) {
        if (!sodium) sodium = await SodiumPlus.auto();
        let adlen = 61;
        const encKey = Buffer.alloc(32, 0);
        if (Buffer.isBuffer(key)) {
            key.copy(encKey, 0);
        } else if (SymmetricKey.isSymmetricKey(key)) {
            key.getRawKey().copy(encKey, 0);
        } else {
            throw new TypeError('Argument 3 must be a SymmetricKey');
        }
        const inputFileSize = (await fs.fstat(inputFP)).size;
        const nonce = await Util.randomBytes(NONCE_SIZE);
        const subkey = await (new HChaCha20()).hChaCha20Bytes(
            nonce.slice(0, 16),
            (await this.getEncryptionKey(key.getRawKey())).getRawKey()
        );
        const nonceLast = Buffer.alloc(12, 0);
        nonce.copy(nonceLast, 4, 16, 24);

        await fs.write(outputFP, await Util.toBuffer(MAGIC_HEADER), 0, 5, 0);
        // Empty space for MAC
        await fs.write(outputFP, Buffer.alloc(32, 0), 0, 32, 5);
        await fs.write(outputFP, salt, 0, 16, 37);
        await fs.write(outputFP, nonce, 0, 24, 53);

        const chacha = new ChaCha20();
        const b2mac = await sodium.crypto_generichash_init(
            new CryptographyKey((await this.getIntegrityKey(key.getRawKey())).getRawKey()),
            TAG_SIZE
        );
        await sodium.crypto_generichash_update(b2mac, Buffer.from(MAGIC_HEADER));
        await sodium.crypto_generichash_update(b2mac, salt);
        await sodium.crypto_generichash_update(b2mac, nonce);

        const plaintext = Buffer.alloc(chunkSize, 0);
        let ciphertext;
        let block_counter = 1;
        const ctrIncrease = (chunkSize + 63) >>> 6;
        let inPos = 0;
        let outPos = 77;
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
            await sodium.crypto_generichash_update(b2mac, ciphertext.slice(0, toRead));
            await fs.write(outputFP, ciphertext, 0, toRead, outPos);

            len += toRead;
            inPos += chunkSize;
            outPos += chunkSize;
            block_counter += ctrIncrease;
        } while (inPos < inputFileSize);

        await sodium.crypto_generichash_update(b2mac, Util.store64_le(adlen));
        await sodium.crypto_generichash_update(b2mac, Util.store64_le(len));
        const authTag = await sodium.crypto_generichash_final(b2mac);
        await fs.write(outputFP, authTag, 0, TAG_SIZE, 5);

        return true;
    }

    /**
     * @returns {number}
     */
    getFileEncryptionSaltOffset()
    {
        return 37;
    }
}
