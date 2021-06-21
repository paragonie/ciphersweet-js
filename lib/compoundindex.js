"use strict";

const Compound = require('./transformation/compound');

/**
 * Class CompoundIndex
 *
 * @package CipherSweet
 */
module.exports = class CompoundIndex
{
    /**
     *
     * @param {string} name
     * @param {string[]} columns
     * @param {Number} filterBits
     * @param {boolean} fastHash
     * @param {Object<string, int>} hashConfig
     */
    constructor(name, columns = [], filterBits = 256, fastHash = false, hashConfig = {})
    {
        this.name = name;
        this.columns = columns;
        this.filterBits = filterBits;
        this.fastHash = fastHash;
        this.hashConfig = hashConfig;
        this.columnTransforms = {};
        this.rowTransforms = [];
    }

    /**
     * @param {string} column
     * @param {Transformation} tf
     * @returns {CompoundIndex}
     */
    addTransform(column, tf)
    {
        if (!this.columnTransforms[column]) {
            this.columnTransforms[column] = [];
        }
        this.columnTransforms[column].push(tf);
        return this;
    }

    /**
     * @param {RowTransformation} tf
     */
    addRowTransform(tf)
    {
        this.rowTransforms.push(tf);
    }

    /**
     * @returns {Array<int, string>}
     */
    getColumns()
    {
        return this.columns;
    }

    /**
     * @returns {string}
     */
    getName()
    {
        return this.name;
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
     * @returns {Object<string, int>}
     */
    getHashConfig()
    {
        return this.hashConfig;
    }

    /**
     * @returns {RowTransformation[]}
     */
    getRowTransforms()
    {
        return this.rowTransforms;
    }

    /**
     * @param {Array} row
     * @returns {string}
     */
    async getPacked(row)
    {
        let col;
        let piece;
        let pieces = {};
        let tf;
        for (let i = 0; i < this.columns.length; i++) {
            col = this.columns[i];
            if (typeof row[col] === 'undefined') {
                continue;
            }
            piece = row[col];
            if (this.columnTransforms[col]) {
                /** @var {string} t */
                for (let t = 0; t < this.columnTransforms[col].length; t++) {
                    tf = this.columnTransforms[col][t];
                    piece = await tf.invoke(piece);
                }
            }
            pieces[col] = piece;
        }

        if (this.rowTransforms.length > 0) {
            for (let t = 0; t < this.rowTransforms[col].length; t++) {
                tf = this.rowTransforms[t];
                pieces = await tf(pieces);
            }
        }

        if (typeof pieces === 'string') {
            return pieces;
        }
        return (new Compound()).invoke(pieces);
    }
};
