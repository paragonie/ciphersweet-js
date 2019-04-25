const assert = require('assert');
const expect = require('chai').expect;
const sodium = require('sodium-native');

const BlindIndex = require('../lib/BlindIndex');
const CipherSweet = require('../lib/CipherSweet');
const EncryptedField = require('../lib/EncryptedField');
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
    it('Encrypts / decrypts fields successfully', function () {
        let eF = new EncryptedField(fipsEngine);
        let eM = new EncryptedField(naclEngine);

        let message = 'This is a test message: ' + Util.randomBytes(16).toString('hex');
        let fCipher = eF.encryptValue(message);
        let mCipher = eM.encryptValue(message);

        expect(eF.decryptValue(fCipher)).to.be.equal(message);
        expect(eM.decryptValue(mCipher)).to.be.equal(message);

        let aad = 'Test AAD:' + Util.randomBytes(32).toString('hex');
        let passfail = true;
        try {
            expect(eF.decryptValue(fCipher, aad)).to.be.equal(message);
            passfail = false;
        } catch (e) {
        }
        assert(passfail === true, 'Exception thrown when AAD supplied erroneously');
        fCipher = eF.encryptValue(message, aad);
        try {
            expect(eF.decryptValue(fCipher)).to.be.equal(message);
            passfail = false;
        } catch (e) {
        }
        assert(passfail === true, 'Exception thrown when AAD omitted erroneously');
    });

    it('Blind Indexing (FIPSCrypto)', function () {
        let ssn = getExampleField(fipsEngine).setTypedIndexes(true);
        let example = ssn.getBlindIndex('111-11-1111', 'contact_ssn_last_four');
        expect(example.type).to.be.equal("idlzpypmia6qu");
        expect(example.value).to.be.equal("334b");

        example = ssn.getBlindIndex('111-11-2222', 'contact_ssn_last_four');
        expect(example.type).to.be.equal("idlzpypmia6qu");
        expect(example.value).to.be.equal("7947");

        example = ssn.getBlindIndex('123-45-6788', 'contact_ssn_last_four');
        expect(example.type).to.be.equal("idlzpypmia6qu");
        expect(example.value).to.be.equal("d5ac");

        example = ssn.getBlindIndex('123-45-6789', 'contact_ssn_last_four');
        expect(example.type).to.be.equal("idlzpypmia6qu");
        expect(example.value).to.be.equal("a88e");

        example = ssn.getBlindIndex('invalid guess 123', 'contact_ssn');
        expect(example.type).to.be.equal("stfodrsbpd4ls");
        expect(example.value).to.be.equal("ee10e07b");

        example = ssn.getBlindIndex('123-45-6789', 'contact_ssn');
        expect(example.type).to.be.equal("stfodrsbpd4ls");
        expect(example.value).to.be.equal("9a15fe14");

        let random = getExampleField(fipsRandom, true);
        example = random.getBlindIndex('123-45-6789', 'contact_ssn');
        expect(example).to.not.equal("ee10e07b213a922075a6ada22514528c");
    });

    it('Blind Indexing (ModernCrypto)', function () {
        let ssn = getExampleField(naclEngine).setTypedIndexes(true);
        let example = ssn.getBlindIndex('111-11-1111', 'contact_ssn_last_four');
        expect(example.type).to.be.equal("3dywyifwujcu2");
        expect(example.value).to.be.equal("32ae");

        example = ssn.getBlindIndex('111-11-2222', 'contact_ssn_last_four');
        expect(example.type).to.be.equal("3dywyifwujcu2");
        expect(example.value).to.be.equal("e538");

        example = ssn.getBlindIndex('123-45-6788', 'contact_ssn_last_four');
        expect(example.type).to.be.equal("3dywyifwujcu2");
        expect(example.value).to.be.equal("8d1a");

        example = ssn.getBlindIndex('123-45-6789', 'contact_ssn_last_four');
        expect(example.type).to.be.equal("3dywyifwujcu2");
        expect(example.value).to.be.equal("2acb");

        example = ssn.getBlindIndex('invalid guess 123', 'contact_ssn');
        expect(example.type).to.be.equal("2iztg3wbd7j5a");
        expect(example.value).to.be.equal("499db508");

        example = ssn.getBlindIndex('123-45-6789', 'contact_ssn');
        expect(example.type).to.be.equal("2iztg3wbd7j5a");
        expect(example.value).to.be.equal("311314c1");

        let random = getExampleField(naclRandom, true);
        example = random.getBlindIndex('123-45-6789', 'contact_ssn');
        expect(example).to.not.equal("499db5085e715c2f167c1e2c02f1c80f");
    });
});
