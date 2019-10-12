"use strict";

const assert = require('assert');
const expect = require('chai').expect;
const {SodiumPlus} = require('sodium-plus');
let sodium;

const BlindIndex = require('../lib/blindindex');
const CipherSweet = require('../lib/ciphersweet');
const EncryptedMultiRows = require('../lib/encryptedmultirows');
const EncryptedRow = require('../lib/encryptedrow');
const FIPSCrypto = require('../lib/backend/fipsrypto');
const ModernCrypto = require('../lib/backend/moderncrypto');
const Lowercase = require('../lib/transformation/lowercase');
const StringProvider = require('../lib/keyprovider/stringprovider');
const Util = require('../lib/util');

let buf, fipsEngine, naclEngine, fipsRandom, naclRandom;
let initialized = false;

/**
 * @return {Promise<boolean>}
 */
async function initialize() {
    if (initialized) return true;
    if (!sodium) sodium = await SodiumPlus.auto();
    if (!buf) buf = await sodium.randombytes_buf(32);
    if (!fipsEngine) fipsEngine = new CipherSweet(
        new StringProvider('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'),
        new FIPSCrypto()
    );
    if (!naclEngine) naclEngine = new CipherSweet(
        new StringProvider('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'),
        new ModernCrypto()
    );
    if (!fipsRandom) fipsRandom = new CipherSweet(
        new StringProvider(buf.toString('hex')),
        new FIPSCrypto()
    );
    if (!naclRandom) naclRandom = new CipherSweet(
        new StringProvider(buf.toString('hex')),
        new ModernCrypto()
    );
    initialized = true;
    return false;
}

/**
 * @param {module.CipherSweet} engine
 */
function getExampleMultiRows(engine)
{
    return new EncryptedMultiRows(engine)
        .addTable('foo')
        .addTable('bar')
        .addIntegerField('foo', 'column1')
        .addTextField('foo', 'column2')
        .addBooleanField('foo', 'column3')
        .addIntegerField('bar', 'column1')
        .addIntegerField('baz', 'column1')
        .addBlindIndex(
            'foo',
            'column2',
            new BlindIndex('foo_column2_idx', [new Lowercase()], 32, true)
        );
}

describe('EncryptedMultiRows', function () {
    it('Sets up correctly when used correctly', async function () {
        if (!initialized) await initialize();
        let mr = new EncryptedMultiRows(naclRandom)
            .addTable('foo')
            .addTable('bar');
        expect('["foo","bar"]').to.be.equal(JSON.stringify(mr.listTables()));

        mr.addTextField('foo', 'column1')
            .addBooleanField('foo', 'column2');
        expect('["foo","bar"]').to.be.equal(JSON.stringify(mr.listTables()));

        mr.addTextField('baz', 'column1');
        expect('["foo","bar","baz"]').to.be.equal(JSON.stringify(mr.listTables()));


        expect('["column1","column2"]').to.be.equal(JSON.stringify(
            mr.getEncryptedRowObjectForTable('foo').listEncryptedFields()
        ));
        expect('[]').to.be.equal(JSON.stringify(
            mr.getEncryptedRowObjectForTable('bar').listEncryptedFields()
        ));
        expect('["column1"]').to.be.equal(JSON.stringify(
            mr.getEncryptedRowObjectForTable('baz').listEncryptedFields()
        ));
    });

    it('Encrypts / decrypts rows successfully', async function () {
        if (!initialized) await initialize();
        let mr = getExampleMultiRows(fipsEngine);

        let rows = {
            "foo": {
                "id": 123456,
                "column1": 654321,
                "column2": "paragonie",
                "column3": true,
                "extra": "text"
            },
            "bar": {
                "id": 554353,
                "foo_id": 123456,
                "column1": 654321
            },
            "baz": {
                "id": 3174521,
                "foo_id": 123456,
                "column1": 654322
            }
        };
        let outRow = await mr.encryptManyRows(rows);
        expect(JSON.stringify(outRow)).to.not.equal(JSON.stringify(rows));
        let decrypted = await mr.decryptManyRows(outRow);
        expect(JSON.stringify(decrypted)).to.be.equal(JSON.stringify(rows));
    });

    it('Handles blind indexes and compound indexes well', async function () {
        if (!initialized) await initialize();
        let mr = getExampleMultiRows(fipsEngine);
        let rows = {
            "foo": {
                "id": 123456,
                "column1": 654321,
                "column2": "paragonie",
                "column3": true,
                "extra": "text"
            },
            "bar": {
                "id": 554353,
                "foo_id": 123456,
                "column1": 654321
            },
            "baz": {
                "id": 3174521,
                "foo_id": 123456,
                "column1": 654322
            }
        };
        let indexes = await mr.getAllBlindIndexes(rows);
        expect('{"foo":{"foo_column2_idx":"65b71d96"},"bar":{},"baz":{}}').to.be.equal(JSON.stringify(indexes));
    });
});