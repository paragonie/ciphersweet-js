"use strict";

const Backend = require('./Contract/Backend');
const Constants = require('./Constants');
const KeyProvider = require('./Contract/KeyProvider');
const ModernCrypto = require('./Backend/ModernCrypto');
const SymmetricKey = require('./Backend/Key/SymmetricKey');
const Util = require('./Util');

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
     * @param {KeyProvider} keyProvider
     * @param {Backend} backend
     */
    constructor(keyProvider, backend)
    {
        if (!(keyProvider instanceof KeyProvider)) {
            throw new TypeError("Argument 1 must be an instance of KeyProvider");
        }
        if (!(backend instanceof Backend)) {
            throw new TypeError("Argument 2 must be an instance of Backend");
        }
        this.keyProvider = keyProvider;
        if (!backend) {
            backend = new ModernCrypto();
        }
        this.backend = backend;
    }

    /**
     * @return {Backend}
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
    getIndexTypeColumn(tableName, fieldName, indexName)
    {
        return this.backend.getIndexTypeColumn(tableName, fieldName, indexName);
    }

    /**
     * @param {string|Buffer} tableName
     * @param {string|Buffer} fieldName
     * @return {module.SymmetricKey}
     */
    getBlindIndexRootKey(tableName, fieldName)
    {
       return new SymmetricKey(
           Util.HKDF(
               this.keyProvider.getSymmetricKey(),
               tableName,
               Buffer.concat([
                   Constants.DS_BIDX,
                   Util.toBuffer(fieldName)
               ])
           )
       )
    }

    /**
     * @param {string|Buffer} tableName
     * @param {string|Buffer} fieldName
     * @return {module.SymmetricKey}
     */
    getFieldSymmetricKey(tableName, fieldName)
    {
        return new SymmetricKey(
            Util.HKDF(
                this.keyProvider.getSymmetricKey(),
                tableName,
                Buffer.concat([
                    Constants.DS_FENC,
                    Util.toBuffer(fieldName)
                ])
            )
        )
    }
};
