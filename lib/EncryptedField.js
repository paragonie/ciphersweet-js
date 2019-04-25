"use strict";

const sodium = require('sodium-native');

const BlindIndexNotFoundException = require('./Exception/BlindIndexNotFoundException');
const BlindIndexNameCollisionException = require('./Exception/BlindIndexNameCollisionException');
const CipherSweet = require('./CipherSweet');
const SymmetricKey = require('./Backend/Key/SymmetricKey');
const Util = require('./Util');

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
        this.tableName = tableName;
        this.fieldName = fieldName;
        this.key = this.engine.getFieldSymmetricKey(
            this.tableName,
            this.fieldName
        );
        this.typedIndexes = usedTypedIndexes;
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @param {string|Buffer} aad
     * @return {Array<int, string|Array<string, string|Array<string, string>>>}
     */
    prepareForStorage(plaintext, aad = '')
    {
        return [
            this.encryptValue(plaintext, aad),
            this.getAllBlindIndexes(plaintext)
        ];
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @param {string|Buffer} aad
     * @returns {string}
     */
    encryptValue(plaintext, aad = '')
    {
        return this.getBackend().encrypt(plaintext, this.key, aad);
    }

    /**
     *
     * @param {string|Buffer} ciphertext
     * @param {string|Buffer} aad
     * @returns {string}
     */
    decryptValue(ciphertext, aad = '')
    {
        return this.getBackend().decrypt(ciphertext, this.key, aad);
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @returns {string[]|string[][]}
     */
    getAllBlindIndexes(plaintext)
    {
        let output = {};
        let key = this.engine.getBlindIndexRootKey(this.tableName, this.fieldName);

        if (this.typedIndexes) {
            for (let name in this.blindIndexes) {
                output[name] = {
                    "type": this.engine.getIndexTypeColumn(this.tableName, this.fieldName, name),
                    "value": this.getBlindIndexRaw(plaintext, name, key).toString('hex')
                };
            }
        } else {
            for (let name in this.blindIndexes) {
                output[name] = this.getBlindIndexRaw(plaintext, name, key).toString('hex');
            }
        }
        return output;
    }

    /**
     * @param {string|Buffer} plaintext
     * @param {string} name
     * @return {string|object}
     */
    getBlindIndex(plaintext, name)
    {
        let key = this.engine.getBlindIndexRootKey(this.tableName, this.fieldName);
        if (this.typedIndexes) {
            return {
                "type": this.engine.getIndexTypeColumn(this.tableName, this.fieldName, name),
                "value": this.getBlindIndexRaw(plaintext, name, key).toString('hex')
            };
        }
        return this.getBlindIndexRaw(plaintext, name, key).toString('hex');
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @param {string} name
     * @param {SymmetricKey} key
     * @returns {Buffer}
     */
    getBlindIndexRaw(plaintext, name, key = null)
    {
        if (typeof(this.blindIndexes[name]) === 'undefined') {
            throw new BlindIndexNotFoundException(`Blind index ${name} not found`);
        }
        if (!key) {
            key = this.engine.getBlindIndexRootKey(this.tableName, this.fieldName);
        } else {
            if (!SymmetricKey.isSymmetricKey(key)) {
                throw new TypeError("Argument 3 passed to getBlindIndexRaw() must be an instance of SymmetricKey");
            }
        }
        let subkey = Util.hmac(
            'sha256',
            Util.pack([
                Util.toBuffer(this.tableName),
                Util.toBuffer(this.fieldName),
                Util.toBuffer(name)
            ]),
            key.getRawKey(),
            true
        );
        let result;
        let index = this.blindIndexes[name];
        if (index.getFastHash()) {
            result = this.getBackend().blindIndexFast(
                index.getTransformed(plaintext),
                subkey,
                index.getFilterBitLength()
            );
        } else {
            result = this.getBackend().blindIndexSlow(
                index.getTransformed(plaintext),
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
    getBlindIndexType(name)
    {
        return this.engine.getIndexTypeColumn(
            this.tableName,
            this.fieldName,
            name
        );
    }

    /**
     * @return {Array<string, string>}
     */
    getBlindIndexTypes()
    {
        let result = {};
        for (let name in this.blindIndexes) {
            result[name] = this.engine.getIndexTypeColumn(
                this.tableName,
                this.fieldName,
                name
            );
        }
        return result;
    }

    /**
     * @param {BlindIndex} index
     * @param {string} name
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
