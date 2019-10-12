const assert = require('assert');
const expect = require('chai').expect;
const ModernCrypto = require('../lib/backend/moderncrypto');
const SymmetricKey = require('../lib/backend/key/symmetrickey');
const {SodiumPlus} = require('sodium-plus');
let sodium;

describe('ModernCrypto Tests', function () {
    it('Encrypts and decrypts successfully', async function () {
        if (!sodium) sodium = await SodiumPlus.auto();
        this.timeout(5000);
        let random_buf = await sodium.randombytes_buf(32);
        let nacl = new ModernCrypto();
        let key = new SymmetricKey(random_buf);
        let plaintext, exampleKey, exampleCipher;

        // plaintext = 'This is a secret message';
        plaintext = 'This is just a test message';
        nacl.encrypt(plaintext, key).then(
            (encrypted) => {
                nacl.decrypt(encrypted, key).then(
                    (decrypted) => {
                        expect(decrypted).to.be.equal(plaintext);
                    }
                );
            }
        );
        nacl.encrypt(plaintext, key, 'test aad')
            .then(encrypted => {
                let caught = false;
                nacl.decrypt(encrypted, key)
                    .catch((e) => {
                        caught = true;
                        expect(e.message).to.be.equal('Invalid MAC');
                    })
                    .then(() => {
                        if (!caught) {
                            assert(null, 'AAD not being used in calculation');
                        }
                    });

                nacl.decrypt(encrypted, key, 'test aad').then(
                    (decrypted) => {
                        expect(decrypted).to.be.equal(plaintext);
                    }
                );
            });

        exampleKey = Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'hex');
        exampleCipher = 'nacl:J-Dvk60qe6hv0hsMmRSRiqInQHxaumU8K8uP2hnchA59W6HBxBHJp_Ki3oD3jqmUBdJ8Vtyp7p4o81rpc_Ca4VKkNg==';
        nacl.decrypt(exampleCipher, exampleKey).then(exampleDecrypt => {
            expect(exampleDecrypt.toString('utf-8')).to.be.equal('This is just a test message');
        });
        exampleKey = Buffer.from('0b036de5605144ea7aeed8bd3a191c08fe1b0ed69d9c8ba0dcbe82372451bb31', 'hex');
        exampleCipher = 'nacl:cASARO-I3Twm5QqPB2kWSkNLnlrPiZ2hXy2btWUx_QGt5-t6KmvJFOLUswIU6TICquCRpU39sauVb_6j684CEyLidA==';

        nacl.decrypt(exampleCipher, exampleKey).then(exampleDecrypt => {
            expect(exampleDecrypt.toString('utf-8')).to.be.equal('This is just a test message');
        });
    });
});
