"use strict";

const Util = require('../Util');

/**
 * Class Transformation
 *
 * @package CipherSweet.Contract
 */
module.exports = class Transformation
{
    /**
     * @param {string|Buffer} input
     * @return {Buffer}
     */
    invoke(input)
    {
        return Util.toBuffer(input);
    }
};
