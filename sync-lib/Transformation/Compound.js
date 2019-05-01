"use strict";

const base64url = require('rfc4648').base64url;
const RowTransformation = require('../Contract/RowTransformation');
const Util = require('../Util');

module.exports = class Compound extends RowTransformation
{
    /**
     * @param {Array<string, string>} input
     * @return {string}
     */
    invoke(input)
    {
        let result = JSON.stringify(
            Compound.processArray(input, 0)
        );
        if (result === '{}') {
            return '[]';
        }
        return result;
    }

    /**
     * @param {Array<string, string>|Object<string, string>} input
     * @param {Number} layer
     * @return {Array}
     */
    static processArray(input, layer = 0)
    {
        if (layer > 255) {
            throw new Error('Too much recursion');
        }
        let value;
        let result = {};
        /** @var {string} key */
        for (let key in input) {
            value = input[key];
            if (Array.isArray(value)) {
                result[key] = this.processArray(value, layer + 1);
                continue;
            }
            if (typeof value === 'object' && value !== null) {
                result[key] = this.processArray(value, layer + 1);
                continue;
            }
            if (typeof value === 'number') {
                result[key] = value.toString();
                continue;
            }
            if (typeof value === 'string') {
                result[key] = Compound.packString(value);
                continue;
            }
            result[key] = value;
        }
        return result;
    }

    /**
     * @param {string} str
     * @return {string}
     */
    static packString(str)
    {
        return Util.store64_le(str.length).toString('hex') +
            base64url.stringify(Buffer.from(str));
    }
};
