"use strict";

const CryptoOperationException = require('../Exception/CryptoOperationException');
const KeyProvider = require('../Contract/KeyProvider');
const SymmetricKey = require('../Backend/Key/SymmetricKey');
const Util = require('../Util');

module.exports = class StringProvider extends KeyProvider
{
    constructor(string)
    {
        let buf;
        super();
        if (Buffer.isBuffer(string)) {
            if (string.length !== 32) {
                throw new CryptoOperationException('Invalid key size');
            }
            buf = string;
        } else if (string.length === 64) {
            buf = Buffer.from(string, 'hex');
        } else if (string.length === 32) {
            buf = Util.toBuffer(string);
        }
        this.symmetricKey = Buffer.alloc(32, 0);
        buf.copy(this.symmetricKey, 0);
    }

    /**
     * @return {SymmetricKey}
     */
    getSymmetricKey()
    {
        return new SymmetricKey(this.symmetricKey);
    }
};
