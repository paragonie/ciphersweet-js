const MultiTenantAwareProvider = require('../contract/multitenantawareprovider');
const CipherSweetException = require('../exception/ciphersweetexception');

module.exports = class MultiTenantProvider extends MultiTenantAwareProvider {
    /**
     * @param {Map<string, KeyProvider>} keyProviders
     * @param {string|null} active
     */
    constructor(keyProviders, active = null) {
        super();
        this.tenants = {};
        for (let name of keyProviders) {
            this.tenants[name] = keyProviders[name];
        }
        this.active = active;
    }

    /**
     * @param {string} index
     * @param {KeyProvider} provider
     * @returns {MultiTenantProvider}
     */
    addTenant(index, provider) {
        this.tenants[index] = provider;
        return this;
    }

    /**
     * @param {string|null} index
     * @returns {MultiTenantProvider}
     */
    setActiveTenant(index) {
        this.active = index;
        return this;
    }

    /**
     *
     * @param {string} index
     * @returns {KeyProvider}
     */
    getTenant(index) {
        if (!(index in this.tenants)) {
            throw new CipherSweetException('Tenant does not exist');
        }
        return this.tenants[index];
    }

    /**
     * @returns {KeyProvider}
     */
    getActiveTenant() {
        if (this.active === null) {
            throw new CipherSweetException('Active tenant not set');
        }
        if (!(this.active in this.tenants)) {
            throw new CipherSweetException('Tenant does not exist');
        }
        return this.tenants[this.active];
    }

    /**
     * @returns {SymmetricKey}
     */
    getSymmetricKey() {
        if (this.active === null) {
            throw new CipherSweetException('Active tenant not set');
        }
        return this.getActiveTenant().getSymmetricKey();
    }
    /**
     * OVERRIDE THIS in your own class!
     *
     * Given a row of data, determine which tenant should be selected.
     *
     * @param {object} row
     * @param {string} tableName
     * @returns {string}
     */
    getTenantFromRow(row, tableName) {
        if (this.active === null) {
            throw new CipherSweetException('This is not implemented. Please override in a child class.');
        }
        return this.active;
    }

    /**
     * OVERRIDE THIS in your own class!
     *
     * @param {object} row
     * @param {string} tableName
     * @returns {object}
     */
    injectTenantMetadata(row, tableName) {
        return row;
    }
}