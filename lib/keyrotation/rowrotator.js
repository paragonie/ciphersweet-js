"use strict";

const InvalidCiphertextException = require('../exception/invalidciphertextexception');

module.exports = class RowRotator
{
    /**
     *
     * @param {EncryptedRow} oldRow
     * @param {EncryptedRow} newRow
     */
    constructor(oldRow, newRow)
    {
        this.oldRow = oldRow;
        this.newRow = newRow;
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
            await this.newRow.decryptRow(ciphertext);
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
        return await this.newRow.prepareRowForStorage(
            await this.oldRow.decryptRow(values)
        );
    }
};
