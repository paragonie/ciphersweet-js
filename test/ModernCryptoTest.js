const expect = require('chai').expect;
const ModernCrypto = require('../lib/Backend/ModernCrypto');
const SymmetricKey = require('../lib/Backend/Key/SymmetricKey');
const sodium = require('sodium-native');

describe('ModernCrypto Tests', function () {
    it('Encrypts and decrypts successfully', function () {
        this.timeout(5000);
        let random_buf = Buffer.alloc(32, 0);
        sodium.randombytes_buf(random_buf);
        let nacl = new ModernCrypto();
        let key = new SymmetricKey(random_buf);

        let plaintext, encrypted, decrypted;
        let exampleKey, exampleCipher, exampleDecrypt;


        // plaintext = 'This is a secret message';
        plaintext = 'This is just a test message';
        encrypted = nacl.encrypt(plaintext, key);
        decrypted = nacl.decrypt(encrypted, key);
        expect(decrypted).to.be.equal(plaintext);

        encrypted = nacl.encrypt(plaintext, key, 'test aad');
        try {
            nacl.decrypt(encrypted, key);
            assert(null, 'AAD not being used in calculation');
        } catch (e) {
            expect(e.message).to.be.equal('Invalid MAC');
        }
        decrypted = nacl.decrypt(encrypted, key, 'test aad');
        expect(decrypted).to.be.equal(plaintext);

        // From the PHP version:
        exampleKey = Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'hex');
        exampleCipher = 'nacl:J-Dvk60qe6hv0hsMmRSRiqInQHxaumU8K8uP2hnchA59W6HBxBHJp_Ki3oD3jqmUBdJ8Vtyp7p4o81rpc_Ca4VKkNg==';
        exampleDecrypt = nacl.decrypt(exampleCipher, exampleKey);
        expect(exampleDecrypt.toString('utf-8')).to.be.equal('This is just a test message');

        exampleKey = Buffer.from('0b036de5605144ea7aeed8bd3a191c08fe1b0ed69d9c8ba0dcbe82372451bb31', 'hex');
        exampleCipher = 'nacl:cASARO-I3Twm5QqPB2kWSkNLnlrPiZ2hXy2btWUx_QGt5-t6KmvJFOLUswIU6TICquCRpU39sauVb_6j684CEyLidA==';
        exampleDecrypt = nacl.decrypt(exampleCipher, exampleKey);
        expect(exampleDecrypt.toString('utf-8')).to.be.equal('This is just a test message');

    });
});
