"use strict";

const Util = require('../util');
const Transformation = require('./transformation');

/**
 * Class RowTransformation
 *
 * @package CipherSweet.contract
 */
module.exports = class RowTransformation extends Transformation
{
    /**
     * @param {Array<string, string>} input
     * @return {string}
     */
    async invoke(input)
    {
        if (!Array.isArray(input)) {
            throw new TypeError('Compound transformation expects an array');
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
    static async processArray(input, layer = 0)
    {
        return input;
    }
};
