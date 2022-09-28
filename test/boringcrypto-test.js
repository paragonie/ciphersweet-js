const assert = require('assert');
const expect = require('chai').expect;
const BoringCrypto = require('../lib/backend/boringcrypto');
const SymmetricKey = require('../lib/backend/key/symmetrickey');
const {SodiumPlus} = require('sodium-plus');
let sodium;

describe('BoringCrypto Tests', function () {
    it('Encrypts and decrypts successfully', async function () {
        if (!sodium) sodium = await SodiumPlus.auto();
        this.timeout(5000);
        let random_buf = await sodium.randombytes_buf(32);
        let brng = new BoringCrypto();
        let key = new SymmetricKey(random_buf);
        let plaintext, exampleKey, exampleCipher;

        // plaintext = 'This is a secret message';
        plaintext = 'This is just a test message';
        brng.encrypt(plaintext, key).then(
            (encrypted) => {
                brng.decrypt(encrypted, key).then(
                    (decrypted) => {
                        expect(decrypted).to.be.equal(plaintext);
                    }
                );
            }
        );
        brng.encrypt(plaintext, key, 'test aad')
            .then(encrypted => {
                let caught = false;
                brng.decrypt(encrypted, key)
                    .catch((e) => {
                        caught = true;
                        expect(e.message).to.be.equal('Invalid MAC');
                    })
                    .then(() => {
                        if (!caught) {
                            assert(null, 'AAD not being used in calculation');
                        }
                    });

                brng.decrypt(encrypted, key, 'test aad').then(
                    (decrypted) => {
                        expect(decrypted).to.be.equal(plaintext);
                    }
                );
            });

        let exampleDecrypt;
        exampleKey = Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'hex');
        exampleCipher = await brng.encrypt('This is just a test message', exampleKey);
        exampleDecrypt = await brng.decrypt(exampleCipher, exampleKey);
        expect(exampleDecrypt.toString('utf-8')).to.be.equal('This is just a test message');

        exampleCipher = 'brng:m3y71cMwhTB2e8YjPLzZ2mwBoMRP1BgqVs_He47bRT5DJbWVBwG_cNsn6xvsl4rT2Cu1QSOEFt_lRECl3w524LlzGwgZ30UDm1KfgaTi9scjmu4=';
        exampleDecrypt = await brng.decrypt(exampleCipher, exampleKey);
        expect(exampleDecrypt.toString('utf-8')).to.be.equal('This is just a test message');

        exampleKey = Buffer.from('0b036de5605144ea7aeed8bd3a191c08fe1b0ed69d9c8ba0dcbe82372451bb31', 'hex');

        exampleCipher = await brng.encrypt('This is just a test message', exampleKey);
        exampleDecrypt = await brng.decrypt(exampleCipher, exampleKey);
        expect(exampleDecrypt.toString('utf-8')).to.be.equal('This is just a test message');

        exampleCipher = 'brng:s0oCG2qoJMTWNreJ3AYQhTYSL423gsDYFKmSMDBzOUubIbiNPWSFZmD8uXMO5dmAhuCf5dvTCtfVvl8MADVL0dmub-znB7nEDYH2eMJBCmX-Qyc=';
        exampleDecrypt = await brng.decrypt(exampleCipher, exampleKey);
        expect(exampleDecrypt.toString('utf-8')).to.be.equal('This is just a test message');
    });
});
