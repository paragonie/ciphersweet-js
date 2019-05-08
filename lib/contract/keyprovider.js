"use strict";

const SymmetricKey = require('../backend/key/symmetrickey');

module.exports = class KeyProvider
{
    /**
     * @return {SymmetricKey}
     */
    getSymmetricKey() {
        throw new Error("Not implemented in the base class");
    }
};
