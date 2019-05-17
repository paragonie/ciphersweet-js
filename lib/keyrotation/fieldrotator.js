"use strict";

const InvalidCiphertextException = require('../exception/invalidciphertextexception');
const Util = require('../util');

module.exports = class FieldRotator
{
    /**
     *
     * @param {module.EncryptedField} oldField
     * @param {module.EncryptedField} newField
     */
    constructor(oldField, newField)
    {
        this.oldField = oldField;
        this.newField = newField;
    }

    /**
     *
     * @param {string} ciphertext
     * @param {string} aad
     * @return {Promise<boolean>}
     */
    async needsReEncrypt(ciphertext, aad)
    {
        if (!(typeof ciphertext === 'string')) {
            throw new InvalidCiphertextException('FieldRotator expects a string, not an array');
        }
        if (ciphertext.length < 5) {
            throw new InvalidCiphertextException('This message is not encrypted');
        }
        let pre = ciphertext.slice(0, 5);
        if (!await Util.hashEquals(pre, this.newField.getBackend().getPrefix())) {
            return true;
        }

        try {
            await this.newField.decryptValue(ciphertext, aad);
            return false;
        } catch (e) {
            return true;
        }
    }

    /**
     *
     * @param {object<string, *>} values
     * @param {string} oldAad
     * @param {string} newAad
     * @return {object<string, string>}
     */
    async prepareForUpdate(values, oldAad = '', newAad = '')
    {
        let plaintext = await this.oldField.decryptValue(values, oldAad);
        return await this.newField.prepareForStorage(plaintext, newAad);
    }
};
