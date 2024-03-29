# CipherSweet.js

[![Build Status](https://github.com/paragonie/ciphersweet-js/actions/workflows/ci.yml/badge.svg)](https://github.com/paragonie/ciphersweet-js/actions)
[![npm version](https://img.shields.io/npm/v/ciphersweet-js.svg)](https://npm.im/ciphersweet-js)

A JavaScript port of [CipherSweet](https://github.com/paragonie/ciphersweet), which is a PHP library that implements
[searchable field-level encryption](https://paragonie.com/blog/2017/05/building-searchable-encrypted-databases-with-php-and-sql).

----

Before adding searchable encryption support to your project, make sure you understand
the [appropriate threat model](https://adamcaudill.com/2016/07/20/threat-modeling-for-applications/)
for your use case. At a minimum, you will want your application and database
server to be running on separate cloud instances / virtual machines.
(Even better: Separate bare-metal hardware.)

CipherSweet is available under the very permissive [ISC License](https://github.com/paragonie/ciphersweet/blob/master/LICENSE)
which allows you to use CipherSweet in any of your JavaScript projects, commercial
or noncommercial, open source or proprietary, at no cost to you.

## CipherSweet Features at a Glance

* Encryption that targets the 256-bit security level
  (using [AEAD](https://tonyarcieri.com/all-the-crypto-code-youve-ever-written-is-probably-broken) modes
  with extended nonces to minimize users' rekeying burden).
* **Compliance-Specific Protocol Support.** Multiple backends to satisfy a
  diverse range of compliance requirements. More can be added as needed:
  * `ModernCrypto` uses [libsodium](https://download.libsodium.org/doc/), the de
    facto standard encryption library for software developers.
    [Algorithm details](https://ciphersweet.paragonie.com/security#moderncrypto).
  * `FIPSCrypto` only uses the cryptographic algorithms covered by the
    FIPS 140-2 recommendations to avoid auditing complexity.
    [Algorithm details](https://ciphersweet.paragonie.com/security#fipscrypto).
* **Key separation.** Each column is encrypted with a different key, all of which are derived from
  your master encryption key using secure key-splitting algorithms.
* **Key management integration.** CipherSweet supports integration with Key
  Management solutions for storing and retrieving the master encryption key.
* **Searchable Encryption.** CipherSweet uses
  [blind indexing](https://paragonie.com/blog/2017/05/building-searchable-encrypted-databases-with-php-and-sql#solution-literal-search)
  with the fuzzier and Bloom filter strategies to allow fast ciphertext search
  with [minimal data leakage](https://ciphersweet.paragonie.com/node.js/blind-index-planning). 
  * Each blind index on each column uses a distinct key from your encryption key
    and each other blind index key.
  * This doesn't allow for `LIKE` operators or regular expression searching, but
    it does allow you to index transformations (e.g. substrings) of the plaintext,
    hashed under a distinct key.
* **Adaptability.** CipherSweet has a database- and product-agnostic design, so
  it should be easy to write an adapter to use CipherSweet in any PHP-based
  software.
* **File/stream encryption.** CipherSweet has an API for encrypting files (or
  other PHP streams) that provides authenticated encryption that defeats TOCTOU
  attacks with minimal overhead. [Learn more](https://ciphersweet.paragonie.com/internals/file-encryption).

## Install Instructions

```
npm install ciphersweet-js 
```

**Optional:**

CipherSweet uses [Sodium-Plus](https://github.com/paragonie/sodium-plus) internally.
The default Sodium-Plus backend is cross-platform, but you can obtain greater
performance by installing `sodium-native` too.

```terminal
npm install --save sodium-native
```

This isn't strictly necessary, and sodium-native doesn't work in browsers, but
if you're not targeting browsers, you can get a significant performance boost.

## Documentation

The [**CipherSweet.js documentation**](https://ciphersweet.paragonie.com/node.js) is
available online at `https://ciphersweet.paragonie.com`.

## Support Contracts

If your company uses this library in their products or services, you may be
interested in [purchasing a support contract from Paragon Initiative Enterprises](https://paragonie.com/enterprise).
