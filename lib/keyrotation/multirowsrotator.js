"use strict";

const InvalidCiphertextException = require('../exception/invalidciphertextexception');

module.exports = class MultiRowsRotator
{
    /**
     *
     * @param {EncryptedMultiRows} oldMultiRows
     * @param {EncryptedMultiRows} newMultiRows
     */
    constructor(oldMultiRows, newMultiRows)
    {
        this.oldMultiRows = oldMultiRows;
        this.newMultiRows = newMultiRows;
    }

    /**
     *
     * @param {object<string, string>} ciphertext
     * @returns {Promise<boolean>}
     */
    async needsReEncrypt(ciphertext)
    {
        if (typeof ciphertext === 'string') {
            throw new InvalidCiphertextException('FieldRotator expects an array/object, not a string');
        }
        try {
            await this.newMultiRows.decryptManyRows(ciphertext);
            return false;
        } catch (e) {
            return true;
        }
    }

    /**
     *
     * @param {object<string, string>} values
     * @returns {Promise<object>}
     */
    async prepareForUpdate(values)
    {
        return await this.newMultiRows.prepareForStorage(
            await this.oldMultiRows.decryptManyRows(values)
        );
    }
};
