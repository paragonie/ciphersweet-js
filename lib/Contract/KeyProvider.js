"use strict";

const SymmetricKey = require('../Backend/Key/SymmetricKey');

module.exports = class KeyProvider
{
    /**
     * @return {SymmetricKey}
     */
    getSymmetricKey() {
        throw new Error("Not implemented in the base class");
    }
};
