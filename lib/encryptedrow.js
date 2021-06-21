"use strict";

const ArrayKeyException = require('./exception/arraykeyexception');
const BlindIndexNotFoundException = require('./exception/blindindexnotfoundexception');
const BlindIndex = require('./blindindex');
const CompoundIndex = require('./compoundindex');
const Constants = require('./constants');
const SymmetricKey = require('./backend/key/symmetrickey');
const Util = require('./util');

module.exports = class EncryptedRow
{
    /**
     *
     * @param {CipherSweet} engine
     * @param {string} tableName
     * @param {boolean} usedTypedIndexes
     */
    constructor(engine, tableName = '', usedTypedIndexes = false)
    {
        this.blindIndexes = [];
        this.compoundIndexes = [];
        this.fieldsToEncrypt = {};
        this.aadSourceField = {};
        this.engine = engine;
        this.tableName = tableName;
        this.typedIndexes = usedTypedIndexes;
    }

    /**
     * @param {string} fieldName
     * @param {string} type
     * @param {string|null} aadSource
     * @returns {EncryptedRow}
     */
    addField(fieldName, type = Constants.TYPE_TEXT, aadSource = null)
    {
        this.fieldsToEncrypt[fieldName] = type;
        if (aadSource) {
            this.aadSourceField[fieldName] = aadSource;
        }
        return this;
    }

    /**
     * @param {string} fieldName
     * @param {string|null} aadSource
     * @returns {EncryptedRow}
     */
    addBooleanField(fieldName, aadSource = null)
    {
        return this.addField(fieldName, Constants.TYPE_BOOLEAN, aadSource);
    }

    /**
     * @param {string} fieldName
     * @param {string|null} aadSource
     * @returns {EncryptedRow}
     */
    addFloatField(fieldName, aadSource = null)
    {
        return this.addField(fieldName, Constants.TYPE_FLOAT, aadSource);
    }

    /**
     * @param {string} fieldName
     * @param {string|null} aadSource
     * @returns {EncryptedRow}
     */
    addIntegerField(fieldName, aadSource = null)
    {
        return this.addField(fieldName, Constants.TYPE_INT, aadSource);
    }

    /**
     * @param {string} fieldName
     * @param {string|null} aadSource
     * @returns {EncryptedRow}
     */
    addTextField(fieldName, aadSource = null)
    {
        return this.addField(fieldName, Constants.TYPE_TEXT, aadSource);
    }

    /**
     *
     * @param {string} column
     * @param {BlindIndex} index
     * @returns {EncryptedRow}
     */
    addBlindIndex(column, index)
    {
        if (!(index instanceof BlindIndex)) {
            throw new TypeError("Argument 2 must be an instance of BlindIndex");
        }
        if (typeof (this.blindIndexes[column]) === 'undefined') {
            this.blindIndexes[column] = {};
        }
        this.blindIndexes[column][index.getName()] = index;
        return this;
    }

    /**
     *
     * @param {CompoundIndex} index
     * @returns {EncryptedRow}
     */
    addCompoundIndex(index)
    {
        this.compoundIndexes[index.getName()] = index;
        return this;
    }

    /**
     *
     * @param {string} name
     * @param {string[]} columns
     * @param {Number} filterBits
     * @param {boolean} fastHash
     * @param {Object<string, int>} hashConfig
     * @returns {EncryptedRow}
     */
    createCompoundIndex(name, columns = [], filterBits = 256, fastHash = false, hashConfig = {})
    {
        this.compoundIndexes.push(
            new CompoundIndex(name, columns, filterBits, fastHash, hashConfig)
        );
        return this;
    }

    /**
     *
     * @param {string} indexName
     * @param {Object} row
     */
    async getBlindIndex(indexName, row)
    {
        let blindIndexes;
        for (let column in this.blindIndexes) {
            blindIndexes = this.blindIndexes[column];
            if (typeof blindIndexes[indexName] !== 'undefined') {
                return await this.calcBlindIndex(row, column, blindIndexes[indexName]);
            }
        }

        let compoundIndex;
        for (let idx in this.compoundIndexes) {
            if (typeof(this.compoundIndexes[idx]) !== 'undefined') {
                compoundIndex = this.compoundIndexes[idx];
                if (compoundIndex.getName() === indexName) {
                    return await this.calcCompoundIndex(row, compoundIndex);
                }
            }
        }
        throw new BlindIndexNotFoundException();
    }

    /**
     * @param {Object} row
     * @returns {Object}
     */
    async getAllBlindIndexes(row)
    {
        let blindIndexes, blindIndex;
        const ret = {};
        for (let column in this.blindIndexes) {
            blindIndexes = this.blindIndexes[column];
            for (let idx in blindIndexes) {
                blindIndex = blindIndexes[idx];
                ret[blindIndex.getName()] = await this.calcBlindIndex(row, column, blindIndex);
            }
        }

        let compoundIndex;
        for (let idx in this.compoundIndexes) {
            compoundIndex = this.compoundIndexes[idx];
            ret[compoundIndex.getName()] = await this.calcCompoundIndex(row, compoundIndex);
        }
        return ret;
    }

    /**
     * @param {string} column
     * @returns {Array<string, module.BlindIndex>}
     */
    getBlindIndexObjectsForColumn(column)
    {
        if (typeof this.blindIndexes[column] === 'undefined') {
            this.blindIndexes[column] = {};
        }
        return this.blindIndexes[column];
    }

    /**
     * @param {string} column
     * @param {string} name
     * @returns {string}
     */
    async getBlindIndexType(column, name)
    {
        return await this.engine.getIndexTypeColumn(
            this.tableName,
            column,
            name
        );
    }

    /**
     * @param {string} column
     * @param {string} name
     * @returns {string}
     */
    async getCompoundIndexType(name)
    {
        return await this.engine.getIndexTypeColumn(
            this.tableName,
            Constants.COMPOUND_SPECIAL,
            name
        );
    }

    /**
     * @returns {Array}
     */
    getCompoundIndexObjects()
    {
        return this.compoundIndexes;
    }

    /**
     *
     * @param {object<string, string>} row
     * @returns {object<string, *>}
     */
    async decryptRow(row)
    {
        let plaintext;
        let type;
        let key;
        const ret = Object.assign({}, row); // copy
        const backend = this.engine.getBackend();
        if (this.engine.isMultiTenantSupported()) {
            this.engine.setActiveTenant(
                this.engine.getTenantFromRow(row, this.tableName)
            );
        }
        for (let field in this.fieldsToEncrypt) {
            /** @var {string} field */
            type = this.fieldsToEncrypt[field];
            key = await this.engine.getFieldSymmetricKey(this.tableName, field);
            if (typeof (this.aadSourceField[field]) !== 'undefined' && typeof (row[field]) !== 'undefined') {
                plaintext = await backend.decrypt(
                        row[field],
                        key,
                        row[this.aadSourceField[field]]
                    );
            } else {
                plaintext = await backend.decrypt(row[field], key);
            }
            ret[field] = this.convertFromBuffer(plaintext, type);
        }
        return ret;
    }

    /**
     * @param {object<string, *>} row
     * @returns {object<string, string>}
     */
    async encryptRow(row)
    {
        let plaintext;
        let type;
        let key;
        const ret = Object.assign({}, row); // copy
        const backend = this.engine.getBackend();
        if (this.engine.isMultiTenantSupported()) {
            this.engine.setActiveTenant(
                this.engine.getTenantFromRow(row, this.tableName)
            );
        }
        for (let field in this.fieldsToEncrypt) {
            /** @var {string} field */
            type = this.fieldsToEncrypt[field];
            plaintext = await this.convertToBuffer(row[field], type);
            key = await this.engine.getFieldSymmetricKey(this.tableName, field);
            if (typeof (this.aadSourceField[field]) !== 'undefined' && typeof (row[field]) !== 'undefined') {
                ret[field] = await backend.encrypt(
                    plaintext,
                    key,
                    row[this.aadSourceField[field]]
                );
            } else {
                ret[field] = await backend.encrypt(plaintext, key);
            }
        }
        if (this.engine.isMultiTenantSupported()) {
            return this.engine.injectTenantMetadata(ret, this.tableName);
        }
        return ret;
    }

    /**
     *
     * @param {Array} row
     * @returns {Array}
     */
    async prepareRowForStorage(row)
    {
        return [
            await this.encryptRow(row),
            await this.getAllBlindIndexes(row)
        ];
    }

    /**
     * @returns {string[]}
     */
    listEncryptedFields()
    {
        return Object.keys(this.fieldsToEncrypt);
    }

    /**
     * @param {string} fieldName
     * @param {string} aadSource
     * @returns {EncryptedRow}
     */
    setAadSourceField(fieldName, aadSource)
    {
        this.aadSourceField[fieldName] = aadSource;
        return this;
    }

    /**
     *
     * @param {Array|Object} row
     * @param {string} column
     * @param {BlindIndex} index
     * @returns {string|Object<string, string>}
     */
    async calcBlindIndex(row, column, index)
    {
        const name = index.getName();
        const key = await this.engine.getBlindIndexRootKey(this.tableName, column);
        if (this.typedIndexes) {
            return {
                "type": await this.engine.getIndexTypeColumn(this.tableName, column, name),
                "value": (await this.calcBlindIndexRaw(row, column, index, key)).toString('hex')
            }
        }
        return (await this.calcBlindIndexRaw(row, column, index, key)).toString('hex');
    }

    /**
     *
     * @param {Array|Object} row
     * @param {CompoundIndex} index
     * @returns {string|Object<string, string>}
     */
    async calcCompoundIndex(row, index)
    {
        const name = index.getName();
        const key = await this.engine.getBlindIndexRootKey(this.tableName, Constants.COMPOUND_SPECIAL);
        if (this.typedIndexes) {
            return {
                "type": await this.engine.getIndexTypeColumn(this.tableName, Constants.COMPOUND_SPECIAL, name),
                "value": (await this.calcCompoundIndexRaw(row, index, key)).toString('hex')
            }
        }
        return (await this.calcCompoundIndexRaw(row, index, key)).toString('hex');
    }

    /**
     *
     * @param {Array|Object} row
     * @param {string} column
     * @param {BlindIndex} index
     * @param {SymmetricKey|null} key
     * @returns {Buffer}
     */
    async calcBlindIndexRaw(row, column, index, key = null)
    {
        if (!key) {
            key = await this.engine.getBlindIndexRootKey(
                this.tableName,
                column
            );
        }
        const backend = this.getBackend();
        const name = index.getName();
        const subKey = new SymmetricKey(
            await Util.hmac(
                'sha256',
                Util.pack([
                    Buffer.from(this.tableName),
                    Buffer.from(column),
                    Buffer.from(name)
                ]),
                key.getRawKey(),
                true
            )
        );
        if (typeof(this.fieldsToEncrypt[column]) === 'undefined') {
            throw new ArrayKeyException(
                `The field ${column} is not defined in this encrypted row.`
            );
        }
        const fieldType = this.fieldsToEncrypt[column];

        const plaintext = await index.getTransformed(
            await this.convertToBuffer(row[column], fieldType)
        );

        if (index.getFastHash()) {
            return backend.blindIndexFast(
                plaintext,
                subKey,
                index.getFilterBitLength()
            );
        }
        return backend.blindIndexSlow(
            plaintext,
            subKey,
            index.getFilterBitLength(),
            index.getHashConfig()
        );
    }

    /**
     *
     * @param {Array|Object} row
     * @param {CompoundIndex} index
     * @param {SymmetricKey|null} key
     * @returns {Buffer}
     */
    async calcCompoundIndexRaw(row, index, key = null)
    {
        if (!key) {
            key = this.engine.getBlindIndexRootKey(
                this.tableName,
                Constants.COMPOUND_SPECIAL
            );
        }
        const subKey = new SymmetricKey(
            await Util.hmac(
                'sha256',
                Util.pack([
                    Buffer.from(this.tableName),
                    Buffer.from(Constants.COMPOUND_SPECIAL),
                    Buffer.from(index.getName())
                ]),
                key.getRawKey(),
                true
            )
        );

        const backend = this.getBackend();

        const plaintext = await index.getPacked(row);

        if (index.getFastHash()) {
            return backend.blindIndexFast(
                plaintext,
                subKey,
                index.getFilterBitLength()
            );
        }
        return backend.blindIndexSlow(
            plaintext,
            subKey,
            index.getFilterBitLength(),
            index.getHashConfig()
        );

    }

    /**
     *
     * @param {Buffer} data
     * @param {string} type
     * @returns {*}
     */
    convertFromBuffer(data, type)
    {
        switch (type) {
            case Constants.TYPE_BOOLEAN:
                return Util.chrToBool(data.toString('binary'));
            case Constants.TYPE_FLOAT:
                return Util.bufferToFloat(data);
            case Constants.TYPE_INT:
                return Util.load64_le(data);
            case Constants.TYPE_TEXT:
                return Util.fromBuffer(data);
            default:
                return data;
        }
    }

    /**
     *
     * @param {*} data
     * @param {string} type
     * @returns {Buffer}
     */
    async convertToBuffer(data, type)
    {
        switch (type) {
            case Constants.TYPE_BOOLEAN:
                return Buffer.from(Util.boolToChr(data), 'binary');
            case Constants.TYPE_FLOAT:
                return Util.floatToBuffer(data);
            case Constants.TYPE_INT:
                return Util.store64_le(data);
            default:
                if (typeof data === 'undefined') {
                    return Buffer.from(Util.boolToChr(null), 'binary');
                }
                return Util.toBuffer(data);
        }
    }

    /**
     * @returns {Backend}
     */
    getBackend()
    {
        return this.engine.getBackend();
    }

    /**
     *
     * @returns {CipherSweet}
     */
    getEngine()
    {
        return this.engine;
    }

    /**
     * @returns {boolean}
     */
    getFlatIndexes()
    {
        return !this.typedIndexes;
    }

    /**
     * @returns {boolean}
     */
    getTypedIndexes()
    {
        return this.typedIndexes;
    }

    /**
     *
     * @param {boolean} bool
     * @returns {EncryptedRow}
     */
    setFlatIndexes(bool)
    {
        this.typedIndexes = !bool;
        return this;
    }

    /**
     * @param {boolean} bool
     * @returns {EncryptedRow}
     */
    setTypedIndexes(bool)
    {
        this.typedIndexes = bool;
        return this;
    }
};
