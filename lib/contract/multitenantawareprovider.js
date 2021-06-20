const KeyProvider = require('./keyprovider');

module.exports = class MultiTenantAwareProvider extends KeyProvider
{
    /**
     * @returns {KeyProvider}
     */
    getActiveTenant() {
        throw new Error("Not implemented in the base class");
    }

    /**
     *
     * @param {string} name
     * @returns {KeyProvider}
     */
    getTenant(name) {
        throw new Error("Not implemented in the base class");
    }

    /**
     * @param {string} index
     * @returns {this}
     */
    setActiveTenant(index) {
        throw new Error("Not implemented in the base class");
    }

    /**
     * OVERRIDE THIS in your own class!
     *
     * Given a row of data, determine which tenant should be selected.
     *
     * @param {object} row
     * @param {string} tableName
     * @returns {string}
     *
     * @throws CipherSweetException
     */
    getTenantFromRow(row, tableName) {
        throw new Error("Not implemented in the base class");
    }

    /**
     * @param {object} row
     * @param {string} tableName
     * @returns {object}
     */
    injectTenantMetadata(row, tableName) {
        return row;
    }
}
