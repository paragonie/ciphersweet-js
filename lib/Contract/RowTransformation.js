"use strict";

const Util = require('../Util');
const Transformation = require('./Transformation');

/**
 * Class RowTransformation
 *
 * @package CipherSweet.Contract
 */
module.exports = class RowTransformation extends Transformation
{
    /**
     * @param {Array<string, string>} input
     * @return {string}
     */
    invoke(input)
    {
        if (!Array.isArray(input)) {
            throw new TypeError('Compound Transformation expects an array');
        }
        return JSON.stringify(
            this.processArray(input, 0)
        );
    }

    /**
     * @param {Array<string, string>} input
     * @param {Number} layer
     * @returns {string|Array}
     */
    static processArray(input, layer = 0)
    {
        return input;
    }
};
