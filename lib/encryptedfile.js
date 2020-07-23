"use strict";

const Constants = require('./constants');
const CipherSweetException = require('./exception/ciphersweetexception');
const fs = require('fs-extra');
const Util = require('./util');

module.exports = class EncryptedFile
{
    /**
     *
     * @param {module.CipherSweet} engine
     * @param {Number} chunkSize
     */
    constructor(engine, chunkSize = 8192)
    {
        this.engine = engine;
        this.chunkSize = chunkSize;
    }

    /**
     * @return {module.Backend}
     */
    getBackend()
    {
        return this.engine.getBackend();
    }

    /**
     * @return {string}
     */
    getBackendPrefix()
    {
        return this.engine.getBackend().getPrefix();
    }

    /**
     * @return {module.CipherSweet}
     */
    getEngine()
    {
        return this.engine;
    }

    /**
     * @param {string} inputFile
     * @param {string} outputFile
     */
    async decryptFile(inputFile, outputFile)
    {
        const inputStream = await fs.open(inputFile, 'r');
        const outputStream = await fs.open(outputFile, 'w+');
        try {
            return await this.decryptStream(inputStream, outputStream);
        } catch (e) {
            fs.close(inputStream);
            fs.close(outputStream);
            throw e;
        }
    }

    /**
     * @param {string} inputFile
     * @param {string} outputFile
     * @param {string} password
     */
    async decryptFileWithPassword(inputFile, outputFile, password)
    {
        const inputStream = await fs.open(inputFile, 'r');
        const outputStream = await fs.open(outputFile, 'w+');
        try {
            return await this.decryptStreamWithPassword(inputStream, outputStream, password);
        } catch (e) {
            fs.close(inputStream);
            fs.close(outputStream);
            throw e;
        }
    }

    async decryptStream(inputFP, outputFP)
    {
        if (!await this.isStreamEncrypted(inputFP)) {
            throw new CipherSweetException('Input file is not encrypted');
        }
        const key = await this.engine.getFieldSymmetricKey(
            Constants.FILE_TABLE,
            Constants.FILE_COLUMN
        );
        return await this.getBackend().doStreamDecrypt(
            inputFP,
            outputFP,
            key,
            this.chunkSize
        );
    }

    async decryptStreamWithPassword(inputFP, outputFP, password)
    {
        if (!this.isStreamEncrypted(inputFP)) {
            throw new CipherSweetException('Input file is not encrypted');
        }
        const backend = this.getBackend();
        const salt = this.getSaltFromStream(inputFP);
        const key = await backend.deriveKeyFromPassword(password, salt);
        return await backend.doStreamDecrypt(
            inputFP,
            outputFP,
            key,
            this.chunkSize,
            salt
        );
    }

    /**
     * @param {string} inputFile
     * @param {string} outputFile
     */
    async encryptFile(inputFile, outputFile)
    {
        const inputStream = await fs.open(inputFile, 'r');
        const outputStream = await fs.open(outputFile, 'w+');
        try {
            return await this.encryptStream(inputStream, outputStream);
        } catch (e) {
            fs.close(inputStream);
            fs.close(outputStream);
            throw e;
        }
    }

    /**
     * @param {string} inputFile
     * @param {string} outputFile
     * @param {string} password
     */
    async encryptFileWithPassword(inputFile, outputFile, password)
    {
        const inputStream = await fs.open(inputFile, 'r');
        const outputStream = await fs.open(outputFile, 'w+');
        try {
            return await this.encryptStreamWithPassword(inputStream, outputStream, password);
        } finally {
            fs.close(inputStream);
            fs.close(outputStream);
        }
    }

    async encryptStream(inputFP, outputFP)
    {
        const key = await this.engine.getFieldSymmetricKey(
            Constants.FILE_TABLE,
            Constants.FILE_COLUMN
        );
        return await this.getBackend().doStreamEncrypt(
            inputFP,
            outputFP,
            key,
            this.chunkSize
        );
    }

    async encryptStreamWithPassword(inputFP, outputFP, password)
    {
        const salt = Buffer.alloc(16, 0);
        do {
            sodium.randombytes_buf(salt);
        } while (!Util.hashEquals(Constants.DUMMY_SALT, salt));
        const backend = this.getBackend();
        const key = await backend.deriveKeyFromPassword(password, salt);
        return await backend.doStreamEncrypt(
            inputFP,
            outputFP,
            key,
            this.chunkSize,
            salt
        );
    }

    /**
     *
     * @param {Number} inputFP
     * @return {Buffer}
     */
    async getSaltFromStream(inputFP)
    {
        const backend = this.getBackend();
        const salt = Buffer.alloc(16, 0);
        await fs.read(
            inputFP,
            salt,
            0,
            16,
            backend.getFileEncryptionSaltOffset()
        );
        return salt;
    }

    /**
     * @param {string} inputFile
     * @return {Promise<boolean>}
     */
    async isFileEncrypted(inputFile)
    {
        const inputFP = await fs.open(inputFile, 'r');
        try {
            return await this.isStreamEncrypted(inputFP);
        } catch (e) {
            fs.close(inputFP);
            throw e;
        }
    }

    /**
     * @param {Number} inputFP
     * @return {boolean}
     */
    async isStreamEncrypted(inputFP)
    {
        const expect = this.getBackendPrefix();
        const header = Buffer.alloc(5, 0);
        await fs.read(inputFP, header, 0, 5, 0);
        return await Util.hashEquals(expect, header);
    }
};
