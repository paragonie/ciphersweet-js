"use strict";

const PlannerException = require('../exception/plannerexception');

/**
 * @class FieldIndexPlanner
 * @type {module.FieldIndexPlanner}
 */
module.exports = class FieldIndexPlanner
{
    constructor()
    {
        this.population = 0;
        this.indexes = {};
    }

    /**
     *
     * @param {module.EncryptedField} field
     * @return {module.FieldIndexPlanner}
     */
    static fromEncryptedField(field)
    {
        let self = new FieldIndexPlanner();
        let obj;
        let objects = field.getBlindIndexObjects();
        for (let name in objects) {
            obj = objects[name];
            self.addExistingIndex(name, obj.getFilterBitLength(), Number.MAX_SAFE_INTEGER);
        }
        return self;
    }

    /**
     *
     * @param {string} name
     * @param {number} L
     * @param {number} K
     * @return {module.FieldIndexPlanner}
     */
    addExistingIndex(name, L, K = Number.MAX_SAFE_INTEGER)
    {
        this.indexes[name] = {'L': L, 'K': K};
        return this;
    }

    /**
     * @return {float}
     */
    getCoincidenceCount()
    {
        return FieldIndexPlanner.coincidenceCounter(
            Object.values(this.indexes),
            this.population
        );
    }

    /**
     * @param extraFieldPopulationBits
     * @return {{min: number, max: number}}
     */
    recommend(extraFieldPopulationBits = Number.MAX_SAFE_INTEGER)
    {
        if (this.population < 1) {
            throw new PlannerException('An empty population is not useful for estimates');
        }
        let existing = Object.values(this.indexes);
        let recommend = {'min': null, 'max': null};
        let sqrtR = Math.sqrt(this.population);

        let tmp = Object.values(existing);
        tmp.push({'L': 257, 'K': extraFieldPopulationBits});

        let coincidences = 0;
        let boundary = Math.max(2, FieldIndexPlanner.coincidenceCounter(tmp, this.population));
        for (let l = 256; l >= 1; --l) {
            tmp = Object.values(existing);
            tmp.push({'L': l, 'K': extraFieldPopulationBits});
            coincidences = FieldIndexPlanner.coincidenceCounter(tmp, this.population);
            if (!recommend['max'] && coincidences > boundary) {
                recommend['max'] = l + 1;
            }
            if (coincidences >= 2 & coincidences <= sqrtR) {
                recommend['min'] = l;
            }
        }

        if (!recommend['min']) {
            recommend['min'] = 1;
        }

        if (!recommend['max']) {
            throw new PlannerException('There is no safe upper bound');
        }

        if (recommend['min'] > recommend['max']) {
            recommend['min'] = recommend['max'];
        }
        return recommend;
    }

    /**
     *
     * @param extraFieldPopulationBits
     * @return {number}
     */
    recommendLow(extraFieldPopulationBits = Number.MAX_SAFE_INTEGER)
    {
        return this.recommend(extraFieldPopulationBits).min;
    }

    /**
     *
     * @param extraFieldPopulationBits
     * @return {number}
     */
    recommendHigh(extraFieldPopulationBits = Number.MAX_SAFE_INTEGER)
    {
        return this.recommend(extraFieldPopulationBits).max;
    }

    /**
     * @param {number} num
     * @return {module.FieldIndexPlanner}
     */
    setEstimatedPopulation(num)
    {
        this.population = num;
        return this;
    }

    /**
     * @param {number} num
     * @return {module.FieldIndexPlanner}
     */
    withPopulation(num)
    {
        let self = new FieldIndexPlanner();
        for (let i in this.indexes) {
            self.indexes[i] = Object.assign({}, this.indexes[i]);
        }
        self.population = num;
        return self;
    }

    /**
     *
     * @param {array} indexes
     * @param {number} R
     */
    static coincidenceCounter(indexes, R)
    {
        let exponent = 0;
        let count = indexes.length;
        for (let i = 0; i < count; ++i) {
            let index = indexes[i];
            exponent += Math.min(index.L, index.K);
        }
        return Math.max(1, R) / Math.pow(2, exponent);
    }
};
