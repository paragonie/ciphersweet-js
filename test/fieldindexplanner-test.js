const assert = require('assert');
const expect = require('chai').expect;
const FieldIndexPlanner = require('../lib/planner/fieldindexplanner');

let planner;

describe('FieldIndexPlanner', function () {
    it('Coincidence counter', function () {
        planner = (new FieldIndexPlanner())
            .setEstimatedPopulation(1 << 16)
            .addExistingIndex('name', 8, Math.MAX_SAFE_INTEGER)
            .addExistingIndex('first_initial_last_name', 4, Math.MAX_SAFE_INTEGER);

        assert(planner.getCoincidenceCount() > 0);
        assert(planner.withPopulation(1 << 20).getCoincidenceCount() > 20);
        assert(planner.getCoincidenceCount() < 20);
    });

    it('Recommendations', function() {
        planner = (new FieldIndexPlanner())
            .setEstimatedPopulation(1 << 16)
            .addExistingIndex('name', 4, Math.MAX_SAFE_INTEGER)
            .addExistingIndex('first_initial_last_name', 4, Math.MAX_SAFE_INTEGER);

        console.log(planner.recommend());
        assert(planner.recommend().min === 1);
        assert(planner.recommend().max === 7);

        let plan2 = planner.withPopulation(2147483647);
        assert(plan2.recommend().min === 8);
        assert(plan2.recommend().max === 22);

        let plan3 = (new FieldIndexPlanner()).setEstimatedPopulation(1 << 16);
        assert(plan3.recommendLow() === 8);
        assert(plan3.recommendHigh() === 15);
        assert(plan3.recommendLow(14) === 8);
        assert(plan3.recommendHigh(14) === 14);
        assert(plan3.withPopulation(1 << 8).recommendLow() === 4);
        assert(plan3.withPopulation(1 << 8).recommendHigh() === 7);
        assert(plan3.withPopulation(1 << 8).recommendLow(7) === 4);
        assert(plan3.withPopulation(1 << 8).recommendHigh(7) === 7);
        assert(plan3.withPopulation(2147483647).recommendLow() === 16);
        assert(plan3.withPopulation(2147483647).recommendHigh() === 30);
        assert(plan3.withPopulation(2147483647).recommendLow(29) === 16);
        assert(plan3.withPopulation(2147483647).recommendHigh(29) === 29);
        assert(plan3.withPopulation(2147483647).recommendLow(24) === 16);
        assert(plan3.withPopulation(2147483647).recommendHigh(24) === 24);

        assert(plan3.withPopulation(2147483647).recommendLow(8) === 1);
        assert(plan3.withPopulation(2147483647).recommendHigh(8) === 8);
    });
});