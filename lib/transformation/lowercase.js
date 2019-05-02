"use strict";

const Transformation = require('../contract/transformation');

module.exports = class Lowercase extends Transformation
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
        let result = Buffer.alloc(str.length, 0);
        str = str.toLowerCase();
        Buffer.from(str).copy(result, 0);
        return result;
    }
};
