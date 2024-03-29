"use strict";

const Util = require('../util');

/**
 * Class transformation
 *
 * @package CipherSweet.contract
 */
module.exports = class Transform
{
    /**
     * @param {string|Buffer} input
     * @returns {Buffer}
     */
    async invoke(input)
    {
        return await Util.toBuffer(input);
    }
};
