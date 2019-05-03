"use strict";

/**
 * @class   CipherSweet
 * @package CipherSweet.backend.key
 * @author  Paragon Initiative Enterprises
 */
module.exports = class SymmetricKey
{
    /**
     * @param {string|Buffer} rawKeyMaterial
     */
    constructor(rawKeyMaterial)
    {
        if (!Buffer.isBuffer(rawKeyMaterial)) {
            rawKeyMaterial = Buffer.from(rawKeyMaterial, 'binary');
        }
        this.rawKeyMaterial = rawKeyMaterial;
    }

    /**
     * @param {object} key
     * @return {boolean}
     */
    static isSymmetricKey(key)
    {
        return Buffer.isBuffer(key.rawKeyMaterial);
    }

    /**
     * @returns {Buffer}
     */
    getRawKey()
    {
        return this.rawKeyMaterial;
    }
};
