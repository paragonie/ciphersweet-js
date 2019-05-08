"use strict";

const expect = require('chai').expect;
const fs = require('fs-extra');

const CipherSweet = require('../lib/ciphersweet');
const EncryptedFile = require('../lib/encryptedfile');
const FIPSCrypto = require('../lib/backend/fipsrypto');
const ModernCrypto = require('../lib/backend/moderncrypto');
const StringProvider = require('../lib/keyprovider/stringprovider');

let fipsEngine = new CipherSweet(
    new StringProvider('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'),
    new FIPSCrypto()
);
let naclEngine = new CipherSweet(
    new StringProvider('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'),
    new ModernCrypto()
);

describe('EncryptedFile', function () {
    it('FIPS Backend', async function () {
        await fs.writeFile(__dirname+'/file-test-0001.txt', 'This is just a test file.\n\nNothing special.');
        let eF = new EncryptedFile(fipsEngine);
        await eF.encryptFile(__dirname+'/file-test-0001.txt', __dirname+'/file-test-0001.out');
        await eF.decryptFile(__dirname+'/file-test-0001.out', __dirname+'/file-test-0001.dec');

        let read0 = await fs.readFile(__dirname+'/file-test-0001.txt');
        let read1 = await fs.readFile(__dirname+'/file-test-0001.dec');
        expect(read0.toString('hex')).to.be.equals(read1.toString('hex'));
    });

    it('Modern Backend', async function () {
        this.timeout(10000);
        await fs.writeFile(__dirname+'/file-test-0001.txt', 'This is just a test file.\n\nNothing special.');
        let eF = new EncryptedFile(naclEngine);
        await eF.encryptFile(__dirname+'/file-test-0001.txt', __dirname+'/file-test-0001.sodium');
        await eF.decryptFile(__dirname+'/file-test-0001.sodium', __dirname+'/file-test-0001.sodium-dec');

        let read0 = await fs.readFile(__dirname+'/file-test-0001.txt');
        let read1 = await fs.readFile(__dirname+'/file-test-0001.sodium-dec');
        expect(read0.toString('hex')).to.be.equals(read1.toString('hex'));
    });

    it('PHP interop', async function () {
        let read;
        let eF = new EncryptedFile(fipsEngine);
        await eF.decryptFile(
            __dirname + '/fips-encrypted.txt',
            __dirname + '/fips-decrypted.txt'
        );

        read = await fs.readFile(__dirname+'/fips-decrypted.txt');
        expect(read.slice(0, 30).toString()).to.be.equal('Paragon Initiative Enterprises');

        let eN = new EncryptedFile(naclEngine);
        await eN.decryptFile(
            __dirname + '/nacl-encrypted.txt',
            __dirname + '/nacl-decrypted.txt'
        );
        read = await fs.readFile(__dirname+'/nacl-decrypted.txt');
        expect(read.slice(0, 30).toString()).to.be.equal('Paragon Initiative Enterprises');
    })
});
