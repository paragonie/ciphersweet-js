const expect = require('chai').expect;
const {SodiumPlus} = require('sodium-plus');
let sodium;

const BlindIndex = require('../lib/blindindex');
const CipherSweet = require('../lib/ciphersweet');
const EncryptedRow = require('../lib/encryptedrow');
const FIPSCrypto = require('../lib/backend/fipsrypto');
const ModernCrypto = require('../lib/backend/moderncrypto');
const LastFourDigits = require('../lib/transformation/lastfourdigits');
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
    it('Encrypts / decrypts rows successfully', async function () {
        if (!initialized) await initialize();
        let eF = new EncryptedRow(fipsEngine, 'contacts');
        let eM = new EncryptedRow(naclEngine, 'contacts');
        eF.addTextField('message');
        eM.addTextField('message');

        let message = 'This is a test message: ' + (await Util.randomBytes(16)).toString('hex');

        let fCipher = await eF.encryptRow({"message": message});
        let mCipher = await eM.encryptRow({"message": message});

        let fDecrypt = await eF.decryptRow(fCipher);
        expect(fDecrypt['message']).to.be.equal(message);
        let mDecrypt = await eM.decryptRow(mCipher);
        expect(mDecrypt['message']).to.be.equal(message);

        let store;
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
            store = await eRF.encryptRow(rows[i]);
            expect(typeof (store)).to.be.equal('object');
            expect(typeof (store.ssn)).to.be.equal('string');
            expect(typeof (store.hivstatus)).to.be.equal('string');
            expect(store.ssn).to.not.equal(rows[i].ssn);
            expect(store.hivstatus).to.not.equal(rows[i].hivstatus);
            expect(typeof (rows[i].ssn)).to.be.equal('string');
            expect(typeof (rows[i].hivstatus)).to.be.equal('boolean');

            store = await eRM.encryptRow(rows[i]);
            expect(typeof (store)).to.be.equal('object');
            expect(typeof (store.ssn)).to.be.equal('string');
            expect(typeof (store.hivstatus)).to.be.equal('string');
            expect(store.ssn).to.not.equal(rows[i].ssn);
            expect(store.hivstatus).to.not.equal(rows[i].hivstatus);
            expect(typeof (rows[i].ssn)).to.be.equal('string');
            expect(typeof (rows[i].hivstatus)).to.be.equal('boolean');
        }
    });

    it('Handles blind indexes and compound indexes well', async function () {
        if (!initialized) await initialize();
        this.timeout(5000);
        let indexes;
        let eRF = getExampleRow(fipsEngine, true);
        let eRM = getExampleRow(naclEngine, true);
        let plain = {
            "extraneous": "this is unencrypted",
            "ssn": "123-45-6789",
            "hivstatus": true
        };

        indexes = await eRF.getAllBlindIndexes(plain);
        expect('a88e74ada916ab9b').to.be.equal(indexes['contact_ssn_last_four']);
        expect('9c3d53214ab71d7f').to.be.equal(indexes['contact_ssnlast4_hivstatus']);
        expect('a88e74ada916ab9b').to.be.equal(await eRF.getBlindIndex('contact_ssn_last_four', plain));
        expect('9c3d53214ab71d7f').to.be.equal(await eRF.getBlindIndex('contact_ssnlast4_hivstatus', plain));


        indexes = await eRM.getAllBlindIndexes(plain);
        expect('2acbcd1c7c55c1db').to.be.equal(indexes['contact_ssn_last_four']);
        expect('1b8c1e1f8e122bd3').to.be.equal(indexes['contact_ssnlast4_hivstatus']);
        expect('2acbcd1c7c55c1db').to.be.equal(await eRM.getBlindIndex('contact_ssn_last_four', plain));
        expect('1b8c1e1f8e122bd3').to.be.equal(await eRM.getBlindIndex('contact_ssnlast4_hivstatus', plain));
    });
});
