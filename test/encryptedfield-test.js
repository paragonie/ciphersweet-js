const assert = require('assert');
const expect = require('chai').expect;
const {SodiumPlus} = require('sodium-plus');
let sodium;

const BlindIndex = require('../lib/blindindex');
const CipherSweet = require('../lib/ciphersweet');
const EncryptedField = require('../lib/encryptedfield');
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

// Testing utility function
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

describe('EncryptedField', function () {
    it('Encrypts / decrypts fields successfully', async function () {
        if (!initialized) await initialize();
        let eF = new EncryptedField(fipsEngine);
        let eM = new EncryptedField(naclEngine);

        let message = 'This is a test message: ' + (await Util.randomBytes(16)).toString('hex');
        let aad = 'Test AAD:' + (await Util.randomBytes(32)).toString('hex');

        eF.encryptValue(message).then((fCipher) => {
            eF.decryptValue(fCipher)
                .then((fDecrypt) => {
                    expect(fDecrypt).to.be.equal(message);
                });
            eF.decryptValue(fCipher, aad)
                .then(() => {
                    assert(false === true, 'exception thrown when AAD supplied erroneously')
                })
                .catch(() => {return false});
        });

        eM.encryptValue(message).then((mCipher) => {
            eM.decryptValue(mCipher).then((mDecrypt) => {
                expect(mDecrypt).to.be.equal(message);
            });
            eM.decryptValue(mCipher, aad)
                .then(() => {
                    assert(false === true, 'exception thrown when AAD supplied erroneously')
                })
                .catch(() => {return false});
        });
    });

    it('Blind Indexing (FIPSCrypto)', async function () {
        if (!initialized) await initialize();
        let ssn = getExampleField(fipsEngine).setTypedIndexes(true);
        ssn.getBlindIndex('111-11-1111', 'contact_ssn_last_four')
            .then((example) => {
                expect(example.type).to.be.equal("idlzpypmia6qu");
                expect(example.value).to.be.equal("334b");
            });

        ssn.getBlindIndex('111-11-2222', 'contact_ssn_last_four')
            .then((example) => {
                expect(example.type).to.be.equal("idlzpypmia6qu");
                expect(example.value).to.be.equal("7947");
            });

        ssn.getBlindIndex('123-45-6788', 'contact_ssn_last_four')
            .then((example) => {
                expect(example.type).to.be.equal("idlzpypmia6qu");
                expect(example.value).to.be.equal("d5ac");
            });
        ssn.getBlindIndex('123-45-6789', 'contact_ssn_last_four')
            .then((example) => {
                expect(example.type).to.be.equal("idlzpypmia6qu");
                expect(example.value).to.be.equal("a88e");
            });

        ssn.getBlindIndex('invalid guess 123', 'contact_ssn')
            .then((example) => {
                expect(example.type).to.be.equal("stfodrsbpd4ls");
                expect(example.value).to.be.equal("ee10e07b");
            });

        ssn.getBlindIndex('123-45-6789', 'contact_ssn')
            .then((example) => {
                expect(example.type).to.be.equal("stfodrsbpd4ls");
                expect(example.value).to.be.equal("9a15fe14");
            });

        let random = getExampleField(fipsRandom, true);
        random.getBlindIndex('123-45-6789', 'contact_ssn')
            .then((example) => {
                expect(example).to.not.equal("ee10e07b213a922075a6ada22514528c");
            });
    });

    it('Blind Indexing (ModernCrypto)', async function () {
        if (!initialized) await initialize();
        let ssn = getExampleField(naclEngine).setTypedIndexes(true);
        ssn.getBlindIndex('111-11-1111', 'contact_ssn_last_four')
            .then((example) => {
                expect(example.type).to.be.equal("3dywyifwujcu2");
                expect(example.value).to.be.equal("32ae");
            });
        ssn.getBlindIndex('111-11-2222', 'contact_ssn_last_four')
            .then((example) => {
                expect(example.type).to.be.equal("3dywyifwujcu2");
                expect(example.value).to.be.equal("e538");
            });

        ssn.getBlindIndex('123-45-6788', 'contact_ssn_last_four')
            .then((example) => {
                expect(example.type).to.be.equal("3dywyifwujcu2");
                expect(example.value).to.be.equal("8d1a");
            });
        ssn.getBlindIndex('123-45-6789', 'contact_ssn_last_four')
            .then((example) => {
                expect(example.type).to.be.equal("3dywyifwujcu2");
                expect(example.value).to.be.equal("2acb");
            });
        ssn.getBlindIndex('invalid guess 123', 'contact_ssn')
            .then((example) => {
                expect(example.type).to.be.equal("2iztg3wbd7j5a");
                expect(example.value).to.be.equal("499db508");
            });
        ssn.getBlindIndex('123-45-6789', 'contact_ssn')
            .then((example) => {
                expect(example.type).to.be.equal("2iztg3wbd7j5a");
                expect(example.value).to.be.equal("311314c1");
            });

        let random = getExampleField(naclRandom, true);
        random.getBlindIndex('123-45-6789', 'contact_ssn')
            .then((example) => {
                expect(example).to.not.equal("499db5085e715c2f167c1e2c02f1c80f");
            });
    });
});
