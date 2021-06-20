"use strict";

const SymmetricKey = require('../backend/key/symmetrickey');

module.exports = class KeyProvider
{
    /**
     * @returns {SymmetricKey}
     */
    getSymmetricKey() {
        throw new Error("Not implemented in the base class");
    }
};
