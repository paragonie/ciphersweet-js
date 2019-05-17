"use strict";

const sodium = require('sodium-native');

const BlindIndexNotFoundException = require('./exception/blindindexnotfoundexception');
const BlindIndexNameCollisionException = require('./exception/blindindexnamecollisionexception');
const CipherSweet = require('./ciphersweet');
const SymmetricKey = require('./backend/key/symmetrickey');
const Util = require('./util');

/**
 * Class EncryptedField
 *
 * @package CipherSweet
 */
module.exports = class EncryptedField
{
    /**
     *
     * @param {CipherSweet} engine
     * @param {string} tableName
     * @param {string} fieldName
     * @param {boolean} usedTypedIndexes
     */
    constructor(engine, tableName = '', fieldName = '', usedTypedIndexes = false)
    {
        this.blindIndexes = [];
        this.engine = engine;
        this.key = null;
        this.tableName = tableName;
        this.fieldName = fieldName;
        this.typedIndexes = usedTypedIndexes;
    }
    /**
     *
     * @param {CipherSweet} engine
     * @param {string} tableName
     * @param {string} fieldName
     * @param {boolean} usedTypedIndexes
     */
    static async build(engine, tableName = '', fieldName = '', usedTypedIndexes = false)
    {
        return await new EncryptedField(engine, tableName, fieldName, usedTypedIndexes)
            .setFieldSymmetricKeyAndReturnSelf();
    }

    async setFieldSymmetricKeyAndReturnSelf()
    {
        this.key = await this.engine.getFieldSymmetricKey(
            this.tableName,
            this.fieldName
        );
        return this;
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @param {string|Buffer} aad
     * @return {Promise}
     */
    async prepareForStorage(plaintext, aad = '')
    {
        return [
            await this.encryptValue(plaintext, aad),
            await this.getAllBlindIndexes(plaintext)
        ];
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @param {string|Buffer} aad
     * @returns {Promise}
     */
    async encryptValue(plaintext, aad = '')
    {
        if (!this.key) {
            await this.setFieldSymmetricKeyAndReturnSelf();
        }
        return await this.getBackend().encrypt(plaintext, this.key, aad);
    }

    /**
     *
     * @param {string|Buffer} ciphertext
     * @param {string|Buffer} aad
     * @returns {string}
     */
    async decryptValue(ciphertext, aad = '')
    {
        if (!this.key) {
            await this.setFieldSymmetricKeyAndReturnSelf();
        }
        return await this.getBackend().decrypt(ciphertext, this.key, aad);
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @returns {string[]|string[][]}
     */
    async getAllBlindIndexes(plaintext)
    {
        let raw;
        let output = {};
        let key = await this.engine.getBlindIndexRootKey(this.tableName, this.fieldName);

        if (this.typedIndexes) {
            for (let name in this.blindIndexes) {
                /** @var {Buffer} raw */
                raw = await this.getBlindIndexRaw(plaintext, name, key);
                output[name] = {
                    "type": await this.engine.getIndexTypeColumn(this.tableName, this.fieldName, name),
                    "value": raw.toString('hex')
                };
            }
        } else {
            for (let name in this.blindIndexes) {
                raw = await this.getBlindIndexRaw(plaintext, name, key);
                output[name] = raw.toString('hex');
            }
        }
        return output;
    }

    /**
     * @param {string|Buffer} plaintext
     * @param {string} name
     * @return {string|object}
     */
    async getBlindIndex(plaintext, name)
    {
        let key = await this.engine.getBlindIndexRootKey(this.tableName, this.fieldName);
        if (this.typedIndexes) {
            let raw = await this.getBlindIndexRaw(plaintext, name, key);
            return {
                "type": await this.engine.getIndexTypeColumn(this.tableName, this.fieldName, name),
                "value": raw.toString('hex')
            };
        }
        return await this.getBlindIndexRaw(plaintext, name, key).toString('hex');
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @param {string} name
     * @param {SymmetricKey} key
     * @returns {Buffer}
     */
    async getBlindIndexRaw(plaintext, name, key = null)
    {
        if (typeof(this.blindIndexes[name]) === 'undefined') {
            throw new BlindIndexNotFoundException(`Blind index ${name} not found`);
        }
        if (!key) {
            key = await this.engine.getBlindIndexRootKey(this.tableName, this.fieldName);
        } else {
            if (!SymmetricKey.isSymmetricKey(key)) {
                throw new TypeError("Argument 3 passed to getBlindIndexRaw() must be an instance of SymmetricKey");
            }
        }
        /** @var {Buffer} subkey */
        let subkey = await Util.hmac(
            'sha256',
            Util.pack([
                await Util.toBuffer(this.tableName),
                await Util.toBuffer(this.fieldName),
                await Util.toBuffer(name)
            ]),
            key.getRawKey(),
            true
        );
        let result;
        let index = this.blindIndexes[name];
        if (index.getFastHash()) {
            result = await this.getBackend().blindIndexFast(
                await index.getTransformed(plaintext),
                subkey,
                index.getFilterBitLength()
            );
        } else {
            result = await this.getBackend().blindIndexSlow(
                await index.getTransformed(plaintext),
                subkey,
                index.getFilterBitLength(),
                index.getHashConfig()
            );
        }
        sodium.sodium_memzero(subkey);
        return result;
    }

    /**
     *
     * @returns {Array<string, BlindIndex>}
     */
    getBlindIndexObjects()
    {
        return this.blindIndexes;
    }

    /**
     *
     * @param {string} name
     * @returns {string}
     */
    async getBlindIndexType(name)
    {
        return await this.engine.getIndexTypeColumn(
            this.tableName,
            this.fieldName,
            name
        );
    }

    /**
     * @return {Array<string, string>}
     */
    async getBlindIndexTypes()
    {
        let result = {};
        for (let name in this.blindIndexes) {
            result[name] = await this.engine.getIndexTypeColumn(
                this.tableName,
                this.fieldName,
                name
            );
        }
        return result;
    }

    /**
     * @param {BlindIndex} index
     * @param {string|null} name
     * @return {module.EncryptedField}
     */
    addBlindIndex(index, name = null)
    {
        if (!name) {
            name = index.getName();
        }
        if (typeof this.blindIndexes[name] !== 'undefined') {
            throw new BlindIndexNameCollisionException(`Index ${name} is already defined`);
        }
        this.blindIndexes[name] = index;
        return this;
    }

    /**
     * @returns {boolean}
     */
    getFlatIndexes()
    {
        return !this.typedIndexes;
    }

    /**
     * @returns {boolean}
     */
    getTypedIndexes()
    {
        return this.typedIndexes;
    }

    /**
     * @returns {Backend}
     */
    getBackend()
    {
        return this.engine.getBackend();
    }

    /**
     * @returns {CipherSweet}
     */
    getEngine()
    {
        return this.engine;
    }

    /**
     *
     * @param {boolean} bool
     * @return {module.EncryptedField}
     */
    setFlatIndexes(bool)
    {
        this.typedIndexes = !bool;
        return this;
    }

    /**
     * @param {boolean} bool
     * @return {module.EncryptedField}
     */
    setTypedIndexes(bool)
    {
        this.typedIndexes = bool && true;
        return this;
    }
};
