"use strict";

const Util = require('../util');

/**
 * Class transformation
 *
 * @package CipherSweet.contract
 */
module.exports = class Transformation
{
    /**
     * @param {string|Buffer} input
     * @return {Buffer}
     */
    async invoke(input)
    {
        return await Util.toBuffer(input);
    }
};
