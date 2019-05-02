"use strict";

const SymmetricKey = require('../backend/key/SymmetricKey');

module.exports = class KeyProvider
{
    /**
     * @return {SymmetricKey}
     */
    getSymmetricKey() {
        throw new Error("Not implemented in the base class");
    }
};
