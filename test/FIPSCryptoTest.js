const expect = require('chai').expect;
const FIPSCrypto = require('../lib/Backend/FIPSCrypto');
const SymmetricKey = require('../lib/Backend/Key/SymmetricKey');
const sodium = require('sodium-native');

describe('FIPSCrypto Tests', function () {
    it('Encrypts and decrypts successfully', function () {
        this.timeout(5000);
        let random_buf = Buffer.alloc(32, 0);
        sodium.randombytes_buf(random_buf);
        let fips = new FIPSCrypto();
        let key = new SymmetricKey(random_buf);

        let plaintext = 'This is a secret message';
        let encrypted = fips.encrypt(plaintext, key);
        let decrypted = fips.decrypt(encrypted, key);
        expect(decrypted).to.be.equal(plaintext);

        encrypted = fips.encrypt(plaintext, key, 'test aad');
        try {
            fips.decrypt(encrypted, key);
            assert(null, 'AAD not being used in calculation');
        } catch (e) {
            expect(e.message).to.be.equal('Invalid MAC');
        }
        decrypted = fips.decrypt(encrypted, key, 'test aad');
        expect(decrypted).to.be.equal(plaintext);

        // From the PHP version:
        let exampleKey = Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'hex');
        let exampleCipher = 'fips:JkzlZgUUdwo6XDRYSKNTnuWMDVcIa7M4R0Xtg1c3aD14ZUiu5YGTiGu9PC2SAjRAZTTurWYa1KfrMJKSncc0llwcNeyEsWMytOir8oqskQtIF0XEkjTJEJSjxmkerxRfHNyBnOimLZ6fg31IjLWrzOW1UX3ARRwSjabK';
        let exampleDecrypt = fips.decrypt(exampleCipher, exampleKey);
        expect(exampleDecrypt.toString('utf-8')).to.be.equal('This is just a test message');
    });
});
