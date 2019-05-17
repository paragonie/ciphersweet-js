const assert = require('assert');
const expect = require('chai').expect;
const sodium = require('sodium-native');

const BlindIndex = require('../lib/blindindex');
const CipherSweet = require('../lib/ciphersweet');
const EncryptedField = require('../lib/encryptedfield');
const EncryptedMultiRows = require('../lib/encryptedmultirows');
const EncryptedRow = require('../lib/encryptedrow');
const FieldRotator = require('../lib/keyrotation/fieldrotator');
const MultiRowsRotator = require('../lib/keyrotation/multirowsrotator');
const RowRotator = require('../lib/keyrotation/rowrotator');
const FIPSCrypto = require('../lib/backend/fipsrypto');
const LastFourDigits = require('../lib/transformation/lastfourdigits');
const Lowercase = require('../lib/transformation/lowercase');
const ModernCrypto = require('../lib/backend/moderncrypto');
const StringProvider = require('../lib/keyprovider/stringprovider');
const Util = require('../lib/util');

function getExampleField(backend, longer = false, fast = false)
{
    return (new EncryptedField(backend, 'contacts', 'ssn'))
        .addBlindIndex(
            new BlindIndex(
                'contact_ssn_last_four',
                [new LastFourDigits()],
                longer ? 64 : 16,
                fast
            )
        )
        .addBlindIndex(
            new BlindIndex(
                'contact_ssn_last_4',
                [new LastFourDigits()],
                longer ? 64 : 16,
                fast
            )
        )
        .addBlindIndex(
            new BlindIndex(
                'contact_ssn',
                [],
                longer ? 128 : 32,
                fast
            )
        );
}

function getExampleRow(engine, longer = false, fast = false)
{
    let row = new EncryptedRow(engine, 'contacts')
        .addTextField('ssn')
        .addBooleanField('hivstatus');

    row.addBlindIndex('ssn', new BlindIndex(
        'contact_ssn_last_four',
        [new LastFourDigits()],
        longer ? 64 : 16,
        fast
    ));

    row.createCompoundIndex(
        'contact_ssnlast4_hivstatus',
        ['ssn', 'hivstatus'],
        longer ? 64 : 16,
        fast
    );
    return row;
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
let message = 'This is a test message';

describe('Key/Backend Rotation', function () {

    it('FieldRotator', async function () {
        let eF = getExampleField(fipsRandom);
        let eM = getExampleField(naclRandom);
        let fieldRotator = new FieldRotator(eF, eM);

        let fCipher = await eF.encryptValue(message);
        let mCipher = await eM.encryptValue(message);

        assert(true === await fieldRotator.needsReEncrypt(fCipher));
        assert(false === await fieldRotator.needsReEncrypt(mCipher));

        let cipher, indices;
        [cipher, indices] = await fieldRotator.prepareForUpdate(fCipher);
        expect(cipher.slice(0, 5)).to.be.equal(naclRandom.getBackend().getPrefix());
        eM.decryptValue(cipher).then(plaintext => {
            expect(plaintext).to.be.equal(message);
        });
    });

    it('RowRotator', async function () {
        let eFR = getExampleRow(fipsRandom);
        let eMR = getExampleRow(naclRandom);
        let rowRotator = new RowRotator(eFR, eMR);
        let plainRow = {
            "first_name": "test",
            "last_name": "test",
            "ssn": "123-45-6789",
            "hivstatus": false
        };
        let fipsRow = await eFR.encryptRow(plainRow);
        let naclRow = await eMR.encryptRow(plainRow);

        assert(true === await rowRotator.needsReEncrypt(fipsRow));
        assert(false === await rowRotator.needsReEncrypt(naclRow));

        let cipherRow, indices;
        [cipherRow, indices] = await rowRotator.prepareForUpdate(fipsRow);
        eMR.decryptRow(cipherRow).then(plaintext => {
            expect(plaintext.ssn).to.be.equal(plainRow.ssn);
        });
    });

    it('MultiRowsRotator', async function () {

        let eFMR = getExampleMultiRows(fipsRandom);
        let eMMR = getExampleMultiRows(naclRandom);
        let mutliRowsRotator = new MultiRowsRotator(eFMR, eMMR);
        let plainRows = {
            "foo": {
                "column1": 12345,
                "column2": message,
                "column3": false,
                "column4": "testing"
            },
            "bar": {
                "column1": 45,
                "extraneous": "test"
            },
            "baz": {
                "column1": 67,
                "extraneous": true
            }
        };
        let fipsRows = await eFMR.encryptManyRows(plainRows);
        let naclRows = await eMMR.encryptManyRows(plainRows);

        assert(true === await mutliRowsRotator.needsReEncrypt(fipsRows));
        assert(false === await mutliRowsRotator.needsReEncrypt(naclRows));

        let cipherRows, indices;
        [cipherRows, indices] = await mutliRowsRotator.prepareForUpdate(fipsRows);
        eMMR.decryptManyRows(cipherRows).then(plaintext => {
            expect(plaintext.foo.column2).to.be.equal(message);
        });
    });
});