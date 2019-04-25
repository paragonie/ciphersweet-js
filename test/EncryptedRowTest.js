const expect = require('chai').expect;
const sodium = require('sodium-native');

const BlindIndex = require('../lib/BlindIndex');
const CipherSweet = require('../lib/CipherSweet');
const EncryptedRow = require('../lib/EncryptedRow');
const FIPSCrypto = require('../lib/Backend/FIPSCrypto');
const ModernCrypto = require('../lib/Backend/ModernCrypto');
const LastFourDigits = require('../lib/Transformation/LastFourDigits');
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
 *
 * @param {module.CipherSweet} engine
 * @param {boolean} fast
 * @param {boolean} longer
 * @return {module.EncryptedRow}
 */
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

describe('EncryptedRow', function () {
    it('Encrypts / decrypts rows successfully', function () {
        let eF = new EncryptedRow(fipsEngine, 'contacts');
        let eM = new EncryptedRow(naclEngine, 'contacts');
        eF.addTextField('message');
        eM.addTextField('message');

        let message = 'This is a test message: ' + Util.randomBytes(16).toString('hex');

        let fCipher = eF.encryptRow({"message": message});
        let mCipher = eM.encryptRow({"message": message});

        let fDecrypt = eF.decryptRow(fCipher);
        expect(fDecrypt['message']).to.be.equal(message);
        let mDecrypt = eM.decryptRow(mCipher);
        expect(mDecrypt['message']).to.be.equal(message);

        let store;
        let indexes;
        let eRF = getExampleRow(fipsRandom, true);
        let eRM = getExampleRow(naclRandom, true);
        let rows = [
            {"ssn": "111-11-1111", "hivstatus": false},
            {"ssn": "123-45-6789", "hivstatus": false},
            {"ssn": "999-99-6789", "hivstatus": false},
            {"ssn": "123-45-1111", "hivstatus": true},
            {"ssn": "999-99-1111", "hivstatus": true},
            {"ssn": "123-45-6789", "hivstatus": true}
        ];
        for (let i = 0; i < rows.length; i++) {
            store = eRF.encryptRow(rows[i]);
            expect(typeof (store)).to.be.equal('object');
            expect(typeof (store.ssn)).to.be.equal('string');
            expect(typeof (store.hivstatus)).to.be.equal('string');
            expect(store.ssn).to.not.equal(rows[i].ssn);
            expect(store.hivstatus).to.not.equal(rows[i].hivstatus);
            expect(typeof (rows[i].ssn)).to.be.equal('string');
            expect(typeof (rows[i].hivstatus)).to.be.equal('boolean');

            store = eRM.encryptRow(rows[i]);
            expect(typeof (store)).to.be.equal('object');
            expect(typeof (store.ssn)).to.be.equal('string');
            expect(typeof (store.hivstatus)).to.be.equal('string');
            expect(store.ssn).to.not.equal(rows[i].ssn);
            expect(store.hivstatus).to.not.equal(rows[i].hivstatus);
            expect(typeof (rows[i].ssn)).to.be.equal('string');
            expect(typeof (rows[i].hivstatus)).to.be.equal('boolean');
        }
    });

    it('Handles blind indexes and compound indexes well', function () {
        this.timeout(5000);
        let indexes;
        let eRF = getExampleRow(fipsEngine, true);
        let eRM = getExampleRow(naclEngine, true);
        let plain = {
            "extraneous": "this is unencrypted",
            "ssn": "123-45-6789",
            "hivstatus": true
        };

        indexes = eRF.getAllBlindIndexes(plain);
        expect('a88e74ada916ab9b').to.be.equal(indexes['contact_ssn_last_four']);
        expect('9c3d53214ab71d7f').to.be.equal(indexes['contact_ssnlast4_hivstatus']);
        expect('a88e74ada916ab9b').to.be.equal(eRF.getBlindIndex('contact_ssn_last_four', plain));
        expect('9c3d53214ab71d7f').to.be.equal(eRF.getBlindIndex('contact_ssnlast4_hivstatus', plain));


        indexes = eRM.getAllBlindIndexes(plain);
        expect('2acbcd1c7c55c1db').to.be.equal(indexes['contact_ssn_last_four']);
        expect('1b8c1e1f8e122bd3').to.be.equal(indexes['contact_ssnlast4_hivstatus']);
        expect('2acbcd1c7c55c1db').to.be.equal(eRM.getBlindIndex('contact_ssn_last_four', plain));
        expect('1b8c1e1f8e122bd3').to.be.equal(eRM.getBlindIndex('contact_ssnlast4_hivstatus', plain));
    });
});
