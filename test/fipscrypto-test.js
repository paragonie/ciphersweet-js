const assert = require('assert');
const expect = require('chai').expect;
const FIPSCrypto = require('../lib/backend/fipsrypto');
const SymmetricKey = require('../lib/backend/key/symmetrickey');

const {SodiumPlus} = require('sodium-plus');
let sodium;

describe('FIPSCrypto Tests', function () {
    it('Encrypts and decrypts successfully', async function () {
        if (!sodium) sodium = await SodiumPlus.auto();
        this.timeout(5000);
        let random_buf = await sodium.randombytes_buf(32);
        let fips = new FIPSCrypto();
        let key = new SymmetricKey(random_buf);
        let plaintext, exampleKey, exampleCipher;

        plaintext = 'This is a secret message';
        fips.encrypt(plaintext, key).then(
            (encrypted) => {
                fips.decrypt(encrypted, key).then(
                    (decrypted) => {
                        expect(decrypted).to.be.equal(plaintext);
                    }
                );
            }
        );


        fips.encrypt(plaintext, key, 'test aad')
            .then(encrypted => {
                let caught = false;
                fips.decrypt(encrypted, key)
                    .catch((e) => {
                        caught = true;
                        expect(e.message).to.be.equal('Invalid MAC');
                    })
                    .then(() => {
                        if (!caught) {
                            assert(null, 'AAD not being used in calculation');
                        }
                    });

                fips.decrypt(encrypted, key, 'test aad').then(
                    (decrypted) => {
                        expect(decrypted).to.be.equal(plaintext);
                    }
                );
            });

        exampleKey = Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'hex');
        exampleCipher = 'fips:JkzlZgUUdwo6XDRYSKNTnuWMDVcIa7M4R0Xtg1c3aD14ZUiu5YGTiGu9PC2SAjRAZTTurWYa1KfrMJKSncc0llwcNeyEsWMytOir8oqskQtIF0XEkjTJEJSjxmkerxRfHNyBnOimLZ6fg31IjLWrzOW1UX3ARRwSjabK';
        fips.decrypt(exampleCipher, exampleKey).then(exampleDecrypt => {
            expect(exampleDecrypt.toString('utf-8')).to.be.equal('This is just a test message');
        });

    });
});
