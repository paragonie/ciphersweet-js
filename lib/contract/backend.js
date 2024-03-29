"use strict";

/**
 *
 * @type {CipherSweet.Backend}
 */
module.exports = class Backend
{
    /**
     * Is this an instance of backend?
     *
     * @param {object} obj
     * @returns {boolean}
     */
    static isBackend(obj)
    {
        if (!obj) {
            return false;
        }
        if (typeof this.encrypt !== 'function') {
            return false;
        }
        if (typeof this.decrypt !== 'function') {
            return false;
        }
        if (typeof this.blindIndexSlow !== 'function') {
            return false;
        }
        return this.blindIndexFast === 'function';
    }

    /**
     * @returns {boolean}
     */
    multiTenantSafe() {
        return false;
    }

    getFileEncryptionSaltOffset()
    {
        return 0;
    }
};
