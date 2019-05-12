"use strict";

const Transformation = require('../contract/transformation');

module.exports = class AlphaCharactersOnly extends Transformation
{
    /**
     * @param {string|Buffer} input
     * @returns {Buffer}
     */
    async invoke(input)
    {
        let str;
        if (Buffer.isBuffer(input)) {
            str = input.toString('binary');
        } else if (typeof input === 'string') {
            str = input;
        } else {
            throw new TypeError();
        }
        str = str.replace(/[^A-Za-z]/, '');
        return Buffer.from(str);
    }
};
