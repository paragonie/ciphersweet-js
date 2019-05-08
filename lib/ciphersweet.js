"use strict";

const Backend = require('./contract/backend');
const Constants = require('./constants');
const KeyProvider = require('./contract/keyprovider');
const ModernCrypto = require('./backend/moderncrypto');
const SymmetricKey = require('./backend/key/symmetrickey');
const Util = require('./util');
const sodium = require('sodium-native');

/**
 * Class CipherSweet
 *
 * @package CipherSweet
 * @author  Paragon Initiative Enterprises
 */
module.exports = class CipherSweet
{
    /**
     *
     * @param {module.KeyProvider} keyProvider
     * @param {module.Backend|null} backend
     */
    constructor(keyProvider, backend = null)
    {
        if (!(keyProvider instanceof KeyProvider)) {
            throw new TypeError("Argument 1 must be an instance of keyprovider");
        }
        if (!(backend instanceof Backend)) {
            throw new TypeError("Argument 2 must be an instance of backend");
        }
        this.keyProvider = keyProvider;
        if (!backend) {
            backend = new ModernCrypto();
        }
        this.backend = backend;
    }

    /**
     * @return {module.Backend}
     */
    getBackend()
    {
        return this.backend;
    }

    /**
     *
     * @param {string} tableName
     * @param {string} fieldName
     * @param {string} indexName
     * @returns string
     */
    async getIndexTypeColumn(tableName, fieldName, indexName)
    {
        return await this.backend.getIndexTypeColumn(tableName, fieldName, indexName);
    }

    /**
     * @param {string|Buffer} tableName
     * @param {string|Buffer} fieldName
     * @return {module.SymmetricKey}
     */
    async getBlindIndexRootKey(tableName, fieldName)
    {
        return new SymmetricKey(
            await Util.HKDF(
                this.keyProvider.getSymmetricKey(),
                tableName,
                Buffer.concat([
                    Constants.DS_BIDX,
                    await Util.toBuffer(fieldName)
                ])
            )
        )
    }

    /**
     * @param {string|Buffer} tableName
     * @param {string|Buffer} fieldName
     * @return {module.SymmetricKey}
     */
    async getFieldSymmetricKey(tableName, fieldName)
    {
        return new SymmetricKey(
            await Util.HKDF(
                this.keyProvider.getSymmetricKey(),
                tableName,
                Buffer.concat([
                    Constants.DS_FENC,
                    await Util.toBuffer(fieldName)
                ])
            )
        )
    }
};
