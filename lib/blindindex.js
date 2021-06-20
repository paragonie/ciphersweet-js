"use strict";

const Transformation = require('./contract/transformation');
const Util = require('./util');

/**
 * Class BlindIndex
 *
 * @package CipherSweet
 */
module.exports = class BlindIndex
{
    /**
     * @param {string} name
     * @param {Transformation[]} transformations
     * @param {Number} filterBits
     * @param {boolean} fastHash
     * @param {object|Array} hashConfig
     */
    constructor(name, transformations = [], filterBits = 256, fastHash = false, hashConfig = {})
    {
        this.name = name;
        this.transformations = transformations;
        this.filterBits = filterBits;
        this.fastHash = fastHash;
        this.hashConfig = hashConfig;
    }

    /**
     * @param {BlindIndex} tf
     * @returns {BlindIndex}
     */
    addTransformation(tf)
    {
        this.transformations.push(tf);
        return this;
    }

    /**
     * @returns {boolean}
     */
    getFastHash()
    {
        return this.fastHash;
    }

    /**
     * @returns {Number}
     */
    getFilterBitLength()
    {
        return this.filterBits;
    }

    /**
     * @returns {Object|Array|Object|Array}
     */
    getHashConfig()
    {
        return this.hashConfig;
    }

    /**
     * @returns {string}
     */
    getName()
    {
        return this.name;
    }

    /**
     * @param {string|Buffer} input
     * @returns {Buffer}
     */
    async getTransformed(input)
    {
        if (this.transformations.length < 1) {
            return await Util.toBuffer(input);
        }
        let tf;
        let output = await Util.toBuffer(input);
        for (let i = 0; i < this.transformations.length; i++) {
            /** @var {transformation} tf */
            tf = this.transformations[i];
            output = await tf.invoke(output);
        }
        return output;
    }
};
