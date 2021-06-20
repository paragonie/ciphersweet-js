"use strict";

const base32 = require('rfc4648').base32;
const base64url = require('rfc4648').base64url;
const Backend =  require('../contract/backend');
const Constants = require('../constants');
const crypto = require('crypto');
const fs = require('fs-extra');
const SodiumPlus = require('sodium-plus').SodiumPlus;
const Util = require('../util');
const SymmetricKey = require('./key/symmetrickey');
const CryptoOperationException = require('../exception/cryptooperationexception');

let sodium;
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
 * @package CipherSweet.backend
 * @author  Paragon Initiative Enterprises
 */
module.exports = class FIPSCrypto extends Backend
{
    /**
     * @returns {boolean}
     */
    multiTenantSafe() {
        return true;
    }

    /**
     * AES-256-CTR encrypt
     *
     * @param {Buffer} plaintext
     * @param {Buffer} key
     * @param {Buffer} nonce
     * @returns {Buffer}
     */
    async aes256ctr(plaintext, key, nonce)
    {
        let ciphertext;
        const cipher = crypto.createCipheriv('aes-256-ctr', key, nonce);
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
    async encrypt(plaintext, key, aad = '')
    {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (!Buffer.isBuffer(plaintext)) {
            plaintext = await Util.toBuffer(plaintext);
        }
        const hkdfSalt = await Util.randomBytes(SALT_SIZE);
        const encKey = await Util.HKDF(key, hkdfSalt, 'AES-256-CTR');
        const macKey = await Util.HKDF(key, hkdfSalt, 'HMAC-SHA-384');
        const ctrNonce = await Util.randomBytes(NONCE_SIZE);

        const ciphertext = await this.aes256ctr(plaintext, encKey, ctrNonce);
        await sodium.sodium_memzero(encKey);

        let mac;
        if (aad.length > 0) {
            mac = await Util.hmac(
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
            mac = await Util.hmac(
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
        await sodium.sodium_memzero(macKey);

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
     * @returns {string}
     */
    async decrypt(ciphertext, key, aad = '')
    {
        if (!sodium) sodium = await SodiumPlus.auto();
        const header = ciphertext.slice(0, 5);
        if (!await Util.hashEquals(MAGIC_HEADER, header)) {
            throw new CryptoOperationException('Invalid ciphertext header.');
        }
        const decoded = await Util.toBuffer(base64url.parse(ciphertext.slice(5)));
        const hkdfSalt = decoded.slice(0, SALT_SIZE);
        const ctrNonce = decoded.slice(
            SALT_SIZE,
            SALT_SIZE + NONCE_SIZE
        );
        const mac = decoded.slice(
            SALT_SIZE + NONCE_SIZE,
            SALT_SIZE + NONCE_SIZE + MAC_SIZE
        );
        const cipher = decoded.slice(SALT_SIZE + NONCE_SIZE + MAC_SIZE);

        const macKey = await Util.HKDF(key, hkdfSalt, 'HMAC-SHA-384');
        let recalc;
        if (aad.length > 0) {
            recalc = await Util.hmac(
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
            recalc = await Util.hmac(
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
        if (!await Util.hashEquals(recalc, mac)) {
            await sodium.sodium_memzero(macKey);
            throw new CryptoOperationException('Invalid MAC');
        }
        const encKey = await Util.HKDF(key, hkdfSalt, 'AES-256-CTR');

        const plaintext = await this.aes256ctr(cipher, encKey, ctrNonce);
        await sodium.sodium_memzero(encKey);
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
     * @returns {Buffer}
     */
    async blindIndexFast(plaintext, key, length = 256, config = [])
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
     * @returns {Buffer}
     */
    async blindIndexSlow(plaintext, key, length = 256, config = [])
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
        plaintext = await Util.toBuffer(plaintext);
        return await Util.pbkdf2(plaintext, ikm, iterations, length >>> 3, 'sha384')
            .then((input) => {
                return Util.andMask(input, length);
            }
        );
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
        const hash = await Util.hmac(
            'sha384',
            Util.pack([
                await Util.toBuffer(fieldName),
                await Util.toBuffer(indexName)
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

    /**
     * @param {string|Buffer} password
     * @param {string|Buffer} salt
     */
    async deriveKeyFromPassword(password, salt)
    {
        return new SymmetricKey(
            await Util.pbkdf2(
                password,
                salt,
                100000,
                32,
                'sha384'
            )
        );
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
        const header = Buffer.alloc(5, 0);
        const storedMAC = Buffer.alloc(48, 0);
        const salt = Buffer.alloc(16, 0); // pbkdf2
        const hkdfSalt = Buffer.alloc(32, 0); // HKDF
        let ctrNonce = Buffer.alloc(16, 0);

        const inputFileSize = (await fs.fstat(inputFP)).size;
        if (inputFileSize < 5) {
            throw new CryptoOperationException('Input file is empty');
        }
        await fs.read(inputFP, header, 0, 5);
        if (!await Util.hashEquals(MAGIC_HEADER, header)) {
            throw new CryptoOperationException('Invalid cipher backend for this file');
        }
        await fs.read(inputFP, storedMAC, 0, 48, 5);
        await fs.read(inputFP, salt, 0, 16, 53);
        await fs.read(inputFP, hkdfSalt, 0, 32, 69);
        await fs.read(inputFP, ctrNonce, 0, 16, 101);

        const encKey = await Util.HKDF(key, hkdfSalt, 'AES-256-CTR');
        const macKey = await Util.HKDF(key, hkdfSalt, 'HMAC-SHA-384');
        const hmac = crypto.createHmac('sha384', macKey);
        hmac.update(MAGIC_HEADER);
        hmac.update(salt);
        hmac.update(hkdfSalt);
        hmac.update(ctrNonce);

        // Chunk HMAC
        let cHmac = crypto.createHmac('sha384', macKey);
        cHmac.update(MAGIC_HEADER);
        cHmac.update(salt);
        cHmac.update(hkdfSalt);
        cHmac.update(ctrNonce);

        const ctrIncrease = (chunkSize + 15) >>> 4;
        let outPos = 0;
        let inPos = 117;
        let toRead = chunkSize;
        let plaintext;
        const ciphertext = Buffer.alloc(chunkSize, 0);

        // First, validate the HMAC of the ciphertext. We're storing the MAC of each chunk
        // in memory, as well.
        let thisChunkMac;
        const chunkMacs = [];
        do {
            toRead = (inPos + chunkSize > inputFileSize)
                ? (inputFileSize - inPos)
                : chunkSize;

            await fs.read(inputFP, ciphertext, 0, toRead, inPos);
            hmac.update(ciphertext.slice(0, toRead));

            // Append chunk MAC for TOCTOU protection
            cHmac.update(ciphertext.slice(0, toRead));
            thisChunkMac = cHmac.digest();
            chunkMacs.push(thisChunkMac);
            cHmac = crypto.createHmac('sha384', macKey);
            cHmac.update(thisChunkMac);

            outPos += toRead;
            inPos += toRead;
        } while (inPos < inputFileSize);

        const calcMAC = hmac.digest();
        if (!await Util.hashEquals(calcMAC, storedMAC)) {
            throw new CryptoOperationException('Invalid authentication tag');
        }
        thisChunkMac = cHmac.digest();
        chunkMacs.push(thisChunkMac);

        cHmac = crypto.createHmac('sha384', macKey);
        cHmac.update(MAGIC_HEADER);
        cHmac.update(salt);
        cHmac.update(hkdfSalt);
        cHmac.update(ctrNonce);
        outPos = 0;
        inPos = 117;
        toRead = chunkSize;
        let shifted;
        do {
            toRead = (inPos + chunkSize > inputFileSize)
                ? (inputFileSize - inPos)
                : chunkSize;

            await fs.read(inputFP, ciphertext, 0, toRead, inPos);
            cHmac.update(ciphertext.slice(0, toRead));
            thisChunkMac = cHmac.digest();
            shifted = chunkMacs.shift();
            if (typeof (shifted) === 'undefined') {
                throw new CryptoOperationException('TOCTOU + truncation attack');
            }
            if (!await Util.hashEquals(thisChunkMac, shifted)) {
                throw new CryptoOperationException('TOCTOU + chosen ciphertext attack');
            }

            // Reinitialize
            cHmac = crypto.createHmac('sha384', macKey);
            cHmac.update(thisChunkMac);

            plaintext = await this.aes256ctr(
                ciphertext.slice(0, toRead),
                encKey,
                ctrNonce
            );
            await fs.write(outputFP, plaintext);
            ctrNonce = await Util.increaseCtrNonce(ctrNonce, ctrIncrease);
            outPos += toRead;
            inPos += toRead;
        } while (inPos < inputFileSize);

        await sodium.sodium_memzero(macKey);
        await sodium.sodium_memzero(encKey);
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
        const hkdfSalt = await Util.randomBytes(SALT_SIZE);
        let ctrNonce = await Util.randomBytes(NONCE_SIZE);

        const encKey = await Util.HKDF(key, hkdfSalt, 'AES-256-CTR');
        const macKey = await Util.HKDF(key, hkdfSalt, 'HMAC-SHA-384');

        await fs.write(outputFP, await Util.toBuffer(MAGIC_HEADER), 0, 5);
        // Empty space for MAC
        await fs.write(outputFP, Buffer.alloc(48, 0), 0, 48, 5);
        await fs.write(outputFP, salt, 0, 16, 53); // pwhash salt
        await fs.write(outputFP, hkdfSalt, 0, 32, 69); // hkdf salt
        await fs.write(outputFP, ctrNonce, 0, 16, 101);

        // Init MAC state
        const hmac = crypto.createHmac('sha384', macKey);
        await sodium.sodium_memzero(macKey);
        hmac.update(MAGIC_HEADER);
        hmac.update(salt);
        hmac.update(hkdfSalt);
        hmac.update(ctrNonce);

        // We want to increase our CTR value by the number of blocks we used previously
        const ctrIncrease = (chunkSize + 15) >>> 4;
        const inputFileSize = (await fs.fstat(inputFP)).size;
        let outPos = 117;
        let inPos = 0;
        let toRead = chunkSize;
        const plaintext = Buffer.alloc(chunkSize, 0);
        let ciphertext;

        do {
            toRead = (inPos + chunkSize > inputFileSize)
                ? (inputFileSize - inPos)
                : chunkSize;

            await fs.read(inputFP, plaintext, 0, toRead, inPos);
            ciphertext = await this.aes256ctr(
                plaintext.slice(0, toRead),
                encKey,
                ctrNonce
            );
            hmac.update(ciphertext);
            await fs.write(outputFP, ciphertext, 0, toRead, outPos);

            ctrNonce = await Util.increaseCtrNonce(ctrNonce, ctrIncrease);
            outPos += toRead;
            inPos += toRead;
        } while (inPos < inputFileSize);
        await sodium.sodium_memzero(encKey);

        const storedMAC = hmac.digest();

        // Write the MAC at the beginning of the file.
        await fs.write(outputFP, storedMAC, 0, 48, 5);

        return true;
    }

    /**
     * @returns {number}
     */
    getFileEncryptionSaltOffset()
    {
        return 53;
    }
};
