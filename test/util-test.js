const expect = require('chai').expect;
const sodium = require('sodium-native');
const Util = require('../lib/util');

describe('Util', function () {
    it('Util.increaseCtrNonce()', async function () {
        let testCases = [
            [
                '00000000000000000000000000000001',
                '00000000000000000000000000000000'
            ],
            [
                '00000000000000000000000000000100',
                '000000000000000000000000000000ff'
            ],
            [
                '0000000000000000000000000000ff00',
                '0000000000000000000000000000feff'
            ],
            [
                '00000000000000000000000000000000',
                'ffffffffffffffffffffffffffffffff'
            ]
        ];
        let input, output, inBuf;
        for (let i = 0; i < testCases.length; i++) {
            [output, input] = testCases[i];
            inBuf = Buffer.from(input, 'hex');
            expect(output).to.be.equal(
                (await Util.increaseCtrNonce(inBuf)).toString('hex')
            );
        }

        output = '0000000000000000000000000000feff';
        inBuf = Buffer.from('0000000000000000000000000000fe00', 'hex');
        expect(output).to.be.equal(
            (await Util.increaseCtrNonce(inBuf, 255)).toString('hex')
        );
    });

    it('Util.andMask()', async function () {
        let input, size, output, outputRight, masked;
        let testCases = [
            ['ff', 4, 'f0', '0f'],
            ['ff', 9, 'ff00', 'ff00'],
            ['ffffffff', 16, 'ffff', 'ffff'],
            ['ffffffff', 17, 'ffff80', 'ffff01'],
            ['ffffffff', 18, 'ffffc0', 'ffff03'],
            ['ffffffff', 19, 'ffffe0', 'ffff07'],
            ['ffffffff', 20, 'fffff0', 'ffff0f'],
            ['ffffffff', 21, 'fffff8', 'ffff1f' ],
            ['ffffffff', 22, 'fffffc', 'ffff3f'],
            ['ffffffff', 23, 'fffffe', 'ffff7f'],
            ['ffffffff', 24, 'ffffff', 'ffffff'],
            ['ffffffff', 32, 'ffffffff', 'ffffffff'],
            ['ffffffff', 64, 'ffffffff00000000', 'ffffffff00000000'],
            ['55f6778c', 11, '55e0', '5506'],
            ['55f6778c', 12, '55f0', '5506'],
            ['55f6778c', 13, '55f0', '5516'],
            ['55f6778c', 14, '55f4', '5536'],
            ['55f6778c', 15, '55f6', '5576'],
            ['55f6778c', 16, '55f6', '55f6'],
            ['55f6778c', 17, '55f600', '55f601'],
            ['55f6778c', 32, '55f6778c', '55f6778c']
        ];
        for (let i = 0; i < testCases.length; i++) {
            [input, size, output, outputRight] = testCases[i];
            masked = await Util.andMask(Buffer.from(input, 'hex'), size);
            expect(output).to.be.equal(masked.toString('hex'));
            masked = await Util.andMask(Buffer.from(input, 'hex'), size, true);
            expect(outputRight).to.be.equal(masked.toString('hex'));
        }
    });

    it('Util.hmac()', function () {
        Util.hmac("sha256", "Paragon Initiative Enterprises", "Happy Pie Day!").then(out=>{
            expect(
                '6f3e128164ab6edb5e1d61fd4657f778665d3f0b4d3f3d6e8a29d27eb68e14c8'
            ).to.be.equal(
                out.toString('hex')
            )
        });
        Util.hmac(
            'sha256',
            Buffer.from('f0f1f2f3f4f5f6f7f8f901', 'hex'),
            Buffer.from('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5', 'hex')
        ).then(out => {
            expect('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf').to.be.equal(out);
        });
    });

    it('Util.HKDF() -- (RFC 5869) test vectors', function () {
        let ikm = Buffer.from('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex');
        let salt = Buffer.from('000102030405060708090a0b0c', 'hex');
        let info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');

        expect('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b').to.be.equal(ikm.toString('hex'));
        expect('000102030405060708090a0b0c').to.be.equal(salt.toString('hex'));
        expect('f0f1f2f3f4f5f6f7f8f9').to.be.equal(info.toString('hex'));

        Util.HKDF(ikm, salt, info, 42, 'sha256').then(out=>{
            expect(
                '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
            ).to.be.equal(
                out.toString('hex')
            );
        });
    });

    it('Util -- type conversions', function () {

        // BOOL
        expect(Util.chrToBool("\x02")).to.be.equal(true);
        expect(Util.chrToBool("\x01")).to.be.equal(false);
        expect(Util.chrToBool("\x00")).to.be.equal(null);
        expect(Util.boolToChr(true)).to.be.equal("\x02");
        expect(Util.boolToChr(false)).to.be.equal("\x01");
        expect(Util.boolToChr(null)).to.be.equal("\x00");

        // FLOAT
        let float = Math.PI;
        expect(
            Util.bufferToFloat(Util.floatToBuffer(float)).toFixed(9)
        ).to.be.equal(
            float.toFixed(9)
        );

        let a = sodium.randombytes_uniform(0x7ffffff) + 1;
        let b = sodium.randombytes_uniform(0x7fffffff) + 2;
        float = a/b;
        expect(
            Util.bufferToFloat(Util.floatToBuffer(float)).toFixed(9)
        ).to.be.equal(
            float.toFixed(9)
        );

        // INTEGER
        for (let i = 0; i < 100; i++) {
            b = sodium.randombytes_uniform(0x7fffffff);
            expect(b).to.be.equal(Util.load64_le(Util.store64_le(b)));
        }
    });
});
