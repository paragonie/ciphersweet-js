"use strict";

const Transformation = require('../contract/transformation');

module.exports = class LastFourDigits extends Transformation
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
        const result = Buffer.alloc(4, 0);
        str = str.replace(/[^0-9]/g, '');
        if (str.length < 4) {
            Buffer.from(str).copy(result, 4 - str.length);
        } else {
            Buffer.from(str.slice(str.length - 4)).copy(result, 0);
        }
        return result;
    }
};
