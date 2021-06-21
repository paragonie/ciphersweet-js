const assert = require('assert');
const expect = require('chai').expect;
const crypto = require('crypto');
const {SodiumPlus} = require('sodium-plus');
let sodium;

const CipherSweet = require('../lib/ciphersweet');
const BoringCrypto = require('../lib/backend/boringcrypto');
const FIPSCrypto = require('../lib/backend/fipsrypto');
const CompoundIndex = require('../lib/compoundindex');
const EncryptedField = require('../lib/encryptedfield');
const EncryptedRow = require('../lib/encryptedrow');
const EncryptedMultiRows = require('../lib/encryptedmultirows');
const TestMultiTenantKeyProvider = require('./multitenant/example-keyprovider');
const LastFourDigits = require('../lib/transformation/lastfourdigits');
const StringProvider = require('../lib/keyprovider/stringprovider');

let initialized = false;
let provider, csBoring, csFips;

/**
 * @return {Promise<boolean>}
 */
async function initialize() {
    if (initialized) return true;
    if (!sodium) sodium = await SodiumPlus.auto();

    provider = new TestMultiTenantKeyProvider({
        'foo': new StringProvider(crypto.randomBytes(32)),
        'bar': new StringProvider(crypto.randomBytes(32)),
        'baz': new StringProvider(crypto.randomBytes(32))
    })
    provider.setActiveTenant('foo');

    csBoring = new CipherSweet(provider, new BoringCrypto());
    csFips = new CipherSweet(provider, new FIPSCrypto());
    initialized = true;
    return false;
}

/**
 * @param {CipherSweet} cs
 * @return {EncryptedRow}
 */
function getERClass(cs) {
    const ER = new EncryptedRow(cs, 'customer');
    ER.addTextField('email', 'customerid');
    ER.addTextField('ssn', 'customerid');
    ER.addBooleanField('active', 'customerid');
    const cidx = (new CompoundIndex(
            'customer_ssnlast4_active',
            ['ssn', 'active'],
            15,
            true
        )).addTransform('ssn', new LastFourDigits());
    ER.addCompoundIndex(cidx);
    return ER;
}

/**
 * @param {CipherSweet} cs
 * @return {EncryptedMultiRows}
 */
function getMultiRows(cs) {
    const EMR = new EncryptedMultiRows(cs);
    EMR.addTable('meta');
    EMR.addTextField('meta', 'data');

    EMR.addTable('customer');
    EMR.addTextField('customer', 'email', 'customerid');
    EMR.addTextField('customer', 'ssn', 'customerid');
    EMR.addBooleanField('customer', 'active', 'customerid');
    const cidx = (new CompoundIndex(
        'customer_ssnlast4_active',
        ['ssn', 'active'],
        15,
        true
    )).addTransform('ssn', new LastFourDigits());
    EMR.addCompoundIndex('customer', cidx);

    EMR.addTable('customer_secret');
    EMR.addTextField('customer_secret', '2fa');
    EMR.addTextField('customer_secret', 'pwhash');

    return EMR;
}


describe('Multi-Tenant Test', function () {
    it('EncryptedField', async function () {
        await initialize();
        /** @var {CipherSweet} cs */
        for (let cs of [csBoring, csFips]) {
            const EF = new EncryptedField(cs, 'table', 'column');
            await EF.setActiveTenant('foo');
            let cipher = await EF.encryptValue('test plaintext', 'aad');
            let plain = (await EF.decryptValue(cipher, 'aad')).toString();
            expect(plain).to.be.equals('test plaintext');

            let decryptFailed = false;
            await EF.setActiveTenant('bar');
            try {
                await EF.decryptValue(cipher, 'aad');
            } catch (e) {
                decryptFailed = true;
            }
            expect(true).to.be.equals(decryptFailed);
        }
    });

    it('EncryptedRow', async function () {
        await initialize();
        /** @var {CipherSweet} cs */
        for (let cs of [csBoring, csFips]) {
            let ER = getERClass(cs);
            cs.setActiveTenant('foo');

            let row1 = await ER.encryptRow({
                'customerid': 1,
                'email': 'ciphersweet@paragonie.com',
                'ssn': '123-45-6789',
                'active': true
            });
            expect(row1.tenant).to.be.equals('foo');

            let plain1 = await ER.decryptRow(row1);
            expect(plain1.email).to.be.equals('ciphersweet@paragonie.com');
            expect('tenant-extra' in plain1).to.be.equals(true);

            cs.setActiveTenant('bar');
            let row2 = await ER.encryptRow({
                'customerid': 2,
                'email': 'security@paragonie.com',
                'ssn': '987-65-4321',
                'active': true
            });
            expect(row2.tenant).to.be.equals('bar');
            let plain2 = await ER.decryptRow(row2);
            expect(plain2.email).to.be.equals('security@paragonie.com');
            expect('tenant-extra' in plain2).to.be.equals(true);

            let decryptFailed = false;
            let row3 = row2;
            row3['tenant'] = 'foo';
            try {
                await ER.decryptRow(row3);
            } catch (e) {
                decryptFailed = true;
            }
            expect(decryptFailed).to.be.equals(true);
        }
    });

    it('EncryptedMultiRows', async function () {
        await initialize();
        /** @var {CipherSweet} cs */
        for (let cs of [csBoring, csFips]) {
            const EMR = getMultiRows(cs);

            cs.setActiveTenant('foo');
            let many1 = await EMR.encryptManyRows({
                'meta': {'data': 'foo'},
                'customer': {
                    'customerid': 1,
                    'email': 'ciphersweet@paragonie.com',
                    'ssn': '123-45-6789',
                    'active': true
                },
                'customer_secret': {
                    '2fa': 'jm2mes2ucvhck2kcw7er5l7ulwoyzfxa',
                    'pwhash': '$2y$10$s6gTREuS3dIOpiudUm6K/u0Wu3PoM1gZyr9sA9hAuu/hGiwO8agDa'
                }
            });
            expect('wrapped-key' in many1['meta']).to.be.equals(true);
            expect('tenant-extra' in many1['meta']).to.be.equals(false);
            expect('tenant-extra' in many1['customer']).to.be.equals(true);
            expect('tenant-extra' in many1['customer_secret']).to.be.equals(true);
            let decrypt1 = await EMR.decryptManyRows(many1);
            expect(decrypt1.customer.email).to.be.equals('ciphersweet@paragonie.com');

            cs.setActiveTenant('bar');
            let many2 = await EMR.encryptManyRows({
                'meta': {'data': 'foo'},
                'customer': {
                    'customerid': 2,
                    'email': 'security@paragonie.com',
                    'ssn': '987-65-4321',
                    'active': true
                },
                'customer_secret': {
                    '2fa': 'dyg27kjbe72hbiszv55lrxzmqs7zfn6o',
                    'pwhash': '$2y$10$Tvk8Uo338tK2AoqIwCnwiOV5tIKwGM/r93MzXbX.h/0iFYhpuRn3W'
                }
            });
            expect('wrapped-key' in many2['meta']).to.be.equals(true);
            expect('tenant-extra' in many2['meta']).to.be.equals(false);
            expect('tenant-extra' in many2['customer']).to.be.equals(true);
            expect('tenant-extra' in many2['customer_secret']).to.be.equals(true);
            let decrypt2 = await EMR.decryptManyRows(many2);
            expect(decrypt2.customer.email).to.be.equals('security@paragonie.com');

            let decryptFailed = false;
            let many3 = many2;
            for (let k in many3) {
                many3[k]['tenant'] = 'foo';
            }
            try {
                await EMR.decryptManyRows(many3);
            } catch (e) {
                decryptFailed = true;
            }
            expect(decryptFailed).to.be.equals(true);
        }
    });
});