"use strict";

const Transformation = require('./Contract/Transformation');
const Util = require('./Util');

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
    constructor(name, transformations = [], filterBits = 256, fastHash = false, hashConfig = [])
    {
        this.name = name;
        this.transformations = transformations;
        this.filterBits = filterBits;
        this.fastHash = fastHash;
        this.hashConfig = hashConfig;
    }

    /**
     * @param {BlindIndex} tf
     * @returns {module.BlindIndex}
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
     * @return {Buffer}
     */
    getTransformed(input)
    {
        if (this.transformations.length < 1) {
            return Util.toBuffer(input);
        }
        let tf;
        let output = Util.toBuffer(input);
        for (let i = 0; i < this.transformations.length; i++) {
            /** @var {Transformation} tf */
            tf = this.transformations[i];
            output = tf.invoke(output);
        }
        return output;
    }
};
