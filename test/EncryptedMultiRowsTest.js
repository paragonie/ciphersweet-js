"use strict";

const assert = require('assert');
const expect = require('chai').expect;
const sodium = require('sodium-native');

const BlindIndex = require('../lib/BlindIndex');
const CipherSweet = require('../lib/CipherSweet');
const EncryptedMultiRows = require('../lib/EncryptedMultiRows');
const EncryptedRow = require('../lib/EncryptedRow');
const FIPSCrypto = require('../lib/Backend/FIPSCrypto');
const ModernCrypto = require('../lib/Backend/ModernCrypto');
const Lowercase = require('../lib/Transformation/Lowercase');
const StringProvider = require('../lib/KeyProvider/StringProvider');
const Util = require('../lib/Util');

let fipsEngine = new CipherSweet(
    new StringProvider('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'),
    new FIPSCrypto()
);
let naclEngine = new CipherSweet(
    new StringProvider('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'),
    new ModernCrypto()
);
let buf = Buffer.alloc(32,0);
sodium.randombytes_buf(buf);
let fipsRandom = new CipherSweet(
    new StringProvider(buf.toString('hex')),
    new FIPSCrypto()
);
let naclRandom = new CipherSweet(
    new StringProvider(buf.toString('hex')),
    new ModernCrypto()
);

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
    it('Sets up correctly when used correctly', function () {
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

    it('Encrypts / decrypts rows successfully', function () {
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
        let outRow = mr.encryptManyRows(rows);
        expect(JSON.stringify(outRow)).to.not.equal(JSON.stringify(rows));
        let decrypted = mr.decryptManyRows(outRow);
        expect(JSON.stringify(decrypted)).to.be.equal(JSON.stringify(rows));
    });

    it('Handles blind indexes and compound indexes well', function () {
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
        let indexes = mr.getAllBlindIndexes(rows);
        expect('{"foo":{"foo_column2_idx":"65b71d96"},"bar":{},"baz":{}}').to.be.equal(JSON.stringify(indexes));
    });
});