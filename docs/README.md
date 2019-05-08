# CipherSweet (JavaScript)

## Setting up CipherSweet at Run-Time

### Select Your Backend

First, you'll need to decide if you have any strict operational requirements for
your encryption. This mostly boils down to whether or not you need all
encryption to be FIPS 140-2 compliant or not, in which case, you'll need to use
the `FIPSCrypto` backend.

If you aren't sure, the answer is that you probably don't, and feel free to use
`ModernCrypto` instead.

```javascript
const FIPSCrypto = require('ciphersweet-js').FIPSCrypto;
const ModernCrypto = require('ciphersweet-js').ModernCrypto;

let fips = new FIPSCrypto(); // Use only FIPS 140-2 algorithms
let nacl = new ModernCrypto(); // Uses libsodium
```

### Define your Key Provider

After you choose your backend, you'll need a KeyProvider. We provide a few
out-of-the-box, but we also provide an interface that can be used to integrate
with any key management service in your code.

The simplest example of this is the `StringProvider`, which accepts a
string containing your encryption key:

```javascript
const StringProvider = require('ciphersweet-js').StringProvider;

let provider = new StringProvider(
    // Example key, chosen randomly, hex-encoded:
    '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
);
```

You can pass a raw binary string, hex-encoded string, or
base64url-encoded string to the `StringProvider` constructor,
provided the decoded key is 256 bits.

Attempting to pass a key of an invalid size (i.e. not 256-bit) will
result in a `CryptoOperationException` being thrown. The recommended
way to generate a key is:

```javascript
const sodium = require('sodium-native');
let keyMaterial = Buffer.alloc(32, 0);
sodium.randombytes_buf(keyMaterial);

console.log(keyMaterial.toString('hex'));
```

### Start Your Engines

Once you have these two, you can actually start the engine (`CipherSweet`).
Building on the previous code example:

```javascript
const {StringProvider, CipherSweet} = require('ciphersweet-js');

let provider = new StringProvider(
    // Example key, chosen randomly, hex-encoded:
    '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
);
let engine = new CipherSweet(provider);
```

If you want to use FIPSCrypto instead of ModernCrypto, you just need to pass
it as the second argument of the `CipherSweet` constructor. The default is
`ModernCrypto`.

```javascript
const {FIPSCrypto, StringProvider, CipherSweet} = require('ciphersweet-js');

let provider = new StringProvider(
    // Example key, chosen randomly, hex-encoded:
    '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
);
let engine = new CipherSweet(provider, new FIPSCrypto());
```

## Basic CipherSweet Usage

The JavaScript API [mirrors the PHP API](https://github.com/paragonie/ciphersweet/tree/master/docs#basic-ciphersweet-usage),
except that many of our APIs are `async` functions and therefore return a `Promise` if you don't use `await`.

For example:

```javascript
const {
    BlindIndex,
    CipherSweet,
    CompoundIndex,
    EncryptedRow,
    LastFourDigits,
    StringProvider
} = require('ciphersweet-js');

let provider = new StringProvider(
    // Example key, chosen randomly, hex-encoded:
    '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
);
let engine = new CipherSweet(provider);

// Using the EncryptedRow abstraction:
let contactEncrypter = new EncryptedRow(engine, 'contacts')
    .addTextField('first_name')
    .addTextField('last_name')
    .addBooleanField('hiv_status')
    .addTextField('insurance_id')
    .addTextField('ssn')
    .addCompoundIndex(
        new CompoundIndex(
            'ssn_insurance_id_last4',
             ['insurance_id', 'ssn'],
             16
        )
    )
    .addBlindIndex('insurance_id', new BlindIndex('insurance_id_idx', [], 8))
    .addBlindIndex('ssn', new BlindIndex('ssn_last4_idx', [new LastFourDigits()], 8));

// An example row that we might want to store, encrypting some fields in the process...
let exampleRow = {
    "id": 12345,
    "first_name": "Harvey",
    "last_name": "Dent",
    "hiv_status": false,
    "insurance_id": "A1234-567-89012",
    "ssn": "123-45-6789"
};

// You can simply use the promisified API, like so:
contactEncrypter.prepareRowForStorage(exampleRow).then(
    function (encryptedRow, indexes) {
        console.log(encryptedRow, indexes);
    }
);

// Alternatively, if wrapped in an async function, use await instead:
(async function() {
    [encryptedRow, indexes] = await contactEncrypter.prepareRowForStorage(exampleRow); 
})();
```
