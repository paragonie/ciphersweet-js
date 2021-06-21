"use strict";

const Backend = require('./contract/backend');
const Constants = require('./constants');
const KeyProvider = require('./contract/keyprovider');
const MultiTenantAwareProvider = require('./contract/multitenantawareprovider');
const BoringCrypto = require('./backend/boringcrypto');
const SymmetricKey = require('./backend/key/symmetrickey');
const Util = require('./util');
const CipherSweetException = require("./exception/ciphersweetexception");

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
     * @param {Backend|null} backend
     */
    constructor(keyProvider, backend = null)
    {
        if (!(keyProvider instanceof KeyProvider)) {
            throw new TypeError("Argument 1 must be an instance of keyprovider");
        }
        if (!backend) {
            backend = new BoringCrypto();
        }
        if (!(backend instanceof Backend)) {
            throw new TypeError("Argument 2 must be an instance of backend");
        }
        this.keyProvider = keyProvider;
        this.backend = backend;
    }

    /**
     * @returns {Backend}
     */
    getBackend()
    {
        return this.backend;
    }

    /**
     * Get the key provider for the active tenant
     *
     * @returns {KeyProvider}
     */
    getKeyProviderForActiveTenant() {
        if (!(this.keyProvider instanceof MultiTenantAwareProvider)) {
            throw new CipherSweetException('Your Key Provider is not multi-tenant aware');
        }
        return this.keyProvider.getActiveTenant();
    }

    /**
     * Get the key provider for a given tenant
     *
     * @param {string} name
     * @returns {KeyProvider}
     */
    getKeyProviderForTenant(name) {
        if (!(this.keyProvider instanceof MultiTenantAwareProvider)) {
            throw new CipherSweetException('Your Key Provider is not multi-tenant aware');
        }
        return this.keyProvider.getTenant(name);
    }

    /**
     * Get the tenant from a given row
     *
     * @param {object} row
     * @param {string} tableName
     * @returns {string}
     */
    getTenantFromRow(row, tableName = '') {
        if (!(this.keyProvider instanceof MultiTenantAwareProvider)) {
            throw new CipherSweetException('Your Key Provider is not multi-tenant aware');
        }
        return this.keyProvider.getTenantFromRow(row, tableName);
    }

    /**
     * @param {string} name
     * @returns {void}
     */
    setActiveTenant(name) {
        if (!(this.keyProvider instanceof MultiTenantAwareProvider)) {
            throw new CipherSweetException('Your Key Provider is not multi-tenant aware');
        }
        this.keyProvider.setActiveTenant(name);
    }

    /**
     * @param {object} row
     * @param {string} tableName
     * @returns {object}
     */
    injectTenantMetadata(row, tableName = '') {
        if (!(this.keyProvider instanceof MultiTenantAwareProvider)) {
            throw new CipherSweetException('Your Key Provider is not multi-tenant aware');
        }
        return this.keyProvider.injectTenantMetadata(row, tableName);
    }

    /**
     * Are we setup for multi-tenant data storage (each tenant gets a distinct key)?
     *
     * @returns {boolean}
     */
    isMultiTenantSupported() {
        if (!this.backend.multiTenantSafe()) {
            // Backend doesn't provide the cryptographic properties we need.
            return false;
        }
        return this.keyProvider instanceof MultiTenantAwareProvider;
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
        return this.backend.getIndexTypeColumn(tableName, fieldName, indexName);
    }

    /**
     * @param {string|Buffer} tableName
     * @param {string|Buffer} fieldName
     * @returns {SymmetricKey}
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
     * @returns {SymmetricKey}
     */
    async getFieldSymmetricKey(tableName, fieldName)
    {
        if (this.isMultiTenantSupported()) {
            return new SymmetricKey(
                await Util.HKDF(
                    this.getKeyProviderForActiveTenant().getSymmetricKey(),
                    tableName,
                    Buffer.concat([
                        Constants.DS_FENC,
                        await Util.toBuffer(fieldName)
                    ])
                )
            );

        }
        return new SymmetricKey(
            await Util.HKDF(
                this.keyProvider.getSymmetricKey(),
                tableName,
                Buffer.concat([
                    Constants.DS_FENC,
                    await Util.toBuffer(fieldName)
                ])
            )
        );
    }
};
