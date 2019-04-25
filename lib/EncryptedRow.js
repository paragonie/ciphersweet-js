"use strict";

const ArrayKeyException = require('./Exception/ArrayKeyException');
const BlindIndexNotFoundException = require('./Exception/BlindIndexNotFoundException');
const BlindIndex = require('./BlindIndex');
const CompoundIndex = require('./CompoundIndex');
const Constants = require('./Constants');
const SymmetricKey = require('./Backend/Key/SymmetricKey');
const Util = require('./Util');

module.exports = class EncryptedRow
{
    /**
     *
     * @param {module.CipherSweet} engine
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
     * @returns {module.EncryptedRow}
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
     * @returns {module.EncryptedRow}
     */
    addBooleanField(fieldName, aadSource = null)
    {
        return this.addField(fieldName, Constants.TYPE_BOOLEAN, aadSource);
    }

    /**
     * @param {string} fieldName
     * @param {string|null} aadSource
     * @returns {module.EncryptedRow}
     */
    addFloatField(fieldName, aadSource = null)
    {
        return this.addField(fieldName, Constants.TYPE_FLOAT, aadSource);
    }

    /**
     * @param {string} fieldName
     * @param {string|null} aadSource
     * @returns {module.EncryptedRow}
     */
    addIntegerField(fieldName, aadSource = null)
    {
        return this.addField(fieldName, Constants.TYPE_INT, aadSource);
    }

    /**
     * @param {string} fieldName
     * @param {string|null} aadSource
     * @returns {module.EncryptedRow}
     */
    addTextField(fieldName, aadSource = null)
    {
        return this.addField(fieldName, Constants.TYPE_TEXT, aadSource);
    }

    /**
     *
     * @param {string} column
     * @param {module.BlindIndex} index
     * @return {module.EncryptedRow}
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
     * @param {module.CompoundIndex} index
     * @return {module.EncryptedRow}
     */
    addCompoundIndex(index)
    {
        this.compoundIndexes[index.getName()] = index;
        return this;
    }

    /**
     *
     * @param {string} name
     * @param {Array<int, string>} columns
     * @param {Number} filterBits
     * @param {boolean} fastHash
     * @param {Object<string, int>} hashConfig
     * @return {module.EncryptedRow}
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
    getBlindIndex(indexName, row)
    {
        let blindIndexes;
        for (let column in this.blindIndexes) {
            blindIndexes = this.blindIndexes[column];
            if (typeof blindIndexes[indexName] !== 'undefined') {
                return this.calcBlindIndex(row, column, blindIndexes[indexName]);
            }
        }

        let compoundIndex;
        for (let idx in this.compoundIndexes) {
            if (typeof(this.compoundIndexes[idx]) !== 'undefined') {
                compoundIndex = this.compoundIndexes[idx];
                if (compoundIndex.getName() === indexName) {
                    return this.calcCompoundIndex(row, compoundIndex);
                }
            }
        }
        throw new BlindIndexNotFoundException();
    }

    /**
     * @param {Object} row
     * @return {Object}
     */
    getAllBlindIndexes(row)
    {
        let blindIndexes, blindIndex;
        let ret = {};
        for (let column in this.blindIndexes) {
            blindIndexes = this.blindIndexes[column];
            for (let idx in blindIndexes) {
                blindIndex = blindIndexes[idx];
                ret[blindIndex.getName()] = this.calcBlindIndex(row, column, blindIndex);
            }
        }

        let compoundIndex;
        for (let idx in this.compoundIndexes) {
            compoundIndex = this.compoundIndexes[idx];
            ret[compoundIndex.getName()] = this.calcCompoundIndex(row, compoundIndex);
        }
        return ret;
    }

    /**
     * @param {string} column
     * @return {Array<string, module.BlindIndex>}
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
     * @return {string}
     */
    getBlindIndexType(column, name)
    {
        return this.engine.getIndexTypeColumn(
            this.tableName,
            column,
            name
        );
    }

    /**
     * @param {string} column
     * @param {string} name
     * @return {string}
     */
    getCompoundIndexType(column, name)
    {
        return this.engine.getIndexTypeColumn(
            this.tableName,
            Constants.COMPOUND_SPECIAL,
            name
        );
    }

    /**
     * @return {Array}
     */
    getCompoundIndexObjects()
    {
        return this.compoundIndexes;
    }

    /**
     *
     * @param {Array} row
     * @return {Array}
     */
    decryptRow(row)
    {
        let plaintext;
        let type;
        let key;
        let ret = Object.assign({}, row); // copy
        let backend = this.engine.getBackend();
        for (let field in this.fieldsToEncrypt) {
            /** @var {string} field */
            type = this.fieldsToEncrypt[field];
            key = this.engine.getFieldSymmetricKey(this.tableName, field);
            if (typeof (this.aadSourceField[field]) !== 'undefined' && typeof (row[field]) !== 'undefined') {
                plaintext = Buffer.from(
                    backend.decrypt(
                        row[field],
                        key,
                        row[this.aadSourceField[field]]
                    ),
                    'binary'
                );
            } else {
                plaintext = Buffer.from(
                    backend.decrypt(row[field], key),
                    'binary'
                );
            }
            ret[field] = this.convertFromBuffer(plaintext, type);
        }
        return ret;
    }

    /**
     *
     * @param {Array} row
     * @return {Array}
     */
    encryptRow(row)
    {
        let plaintext;
        let type;
        let key;
        let ret = Object.assign({}, row); // copy
        let backend = this.engine.getBackend();
        for (let field in this.fieldsToEncrypt) {
            /** @var {string} field */
            type = this.fieldsToEncrypt[field];
            plaintext = this.convertToBuffer(row[field], type);
            key = this.engine.getFieldSymmetricKey(this.tableName, field);
            if (typeof (this.aadSourceField[field]) !== 'undefined' && typeof (row[field]) !== 'undefined') {
                ret[field] = backend.encrypt(
                    plaintext,
                    key,
                    row[this.aadSourceField[field]]
                );
            } else {
                ret[field] = backend.encrypt(plaintext, key);
            }
        }
        return ret;
    }

    /**
     *
     * @param {Array} row
     * @return {Array}
     */
    prepareRowForStorage(row)
    {
        return [
            this.encryptRow(row),
            this.getAllBlindIndexes(row)
        ];
    }

    /**
     * @return {string[]}
     */
    listEncryptedFields()
    {
        return Object.keys(this.fieldsToEncrypt);
    }

    /**
     * @param {string} fieldName
     * @param {string} aadSource
     * @return {module.EncryptedRow}
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
     * @param {module.BlindIndex} index
     * @return {string|Object<string, string>}
     */
    calcBlindIndex(row, column, index)
    {
        let name = index.getName();
        let key = this.engine.getBlindIndexRootKey(this.tableName, column);
        if (this.typedIndexes) {
            return {
                "type": this.engine.getIndexTypeColumn(this.tableName, column, name),
                "value": this.calcBlindIndexRaw(row, column, index, key).toString('hex')
            }
        }
        return this.calcBlindIndexRaw(row, column, index, key).toString('hex');
    }

    /**
     *
     * @param {Array|Object} row
     * @param {module.CompoundIndex} index
     * @return {string|Object<string, string>}
     */
    calcCompoundIndex(row, index)
    {
        let name = index.getName();
        let key = this.engine.getBlindIndexRootKey(this.tableName, Constants.COMPOUND_SPECIAL);
        if (this.typedIndexes) {
            return {
                "type": this.engine.getIndexTypeColumn(this.tableName, Constants.COMPOUND_SPECIAL, name),
                "value": this.calcCompoundIndexRaw(row, index, key).toString('hex')
            }
        }
        return this.calcCompoundIndexRaw(row, index, key).toString('hex');
    }

    /**
     *
     * @param {Array|Object} row
     * @param {string} column
     * @param {module.BlindIndex} index
     * @param {module.SymmetricKey|null} key
     * @return {Buffer}
     */
    calcBlindIndexRaw(row, column, index, key = null)
    {
        if (!key) {
            key = this.engine.getBlindIndexRootKey(
                this.tableName,
                column
            );
        }
        let backend = this.getBackend();
        let name = index.getName();
        let subKey = new SymmetricKey(
            Util.hmac(
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
        let fieldType = this.fieldsToEncrypt[column];

        let plaintext = index.getTransformed(
            this.convertToBuffer(row[column], fieldType)
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
     * @param {module.CompoundIndex} index
     * @param {module.SymmetricKey|null} key
     * @return {Buffer}
     */
    calcCompoundIndexRaw(row, index, key = null)
    {
        if (!key) {
            key = this.engine.getBlindIndexRootKey(
                this.tableName,
                Constants.COMPOUND_SPECIAL
            );
        }
        let subKey = new SymmetricKey(
            Util.hmac(
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

        let backend = this.getBackend();

        let plaintext = index.getPacked(row);

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
     * @return {*}
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
     * @return {Buffer}
     */
    convertToBuffer(data, type)
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
     * @return {Backend}
     */
    getBackend()
    {
        return this.engine.getBackend();
    }

    /**
     *
     * @return {CipherSweet}
     */
    getEngine()
    {
        return this.engine;
    }

    /**
     * @return {boolean}
     */
    getFlatIndexes()
    {
        return !this.typedIndexes;
    }

    /**
     * @return {boolean}
     */
    getTypedIndexes()
    {
        return this.typedIndexes;
    }

    /**
     *
     * @param {boolean} bool
     * @return {module.EncryptedRow}
     */
    setFlatIndexes(bool)
    {
        this.typedIndexes = !bool;
        return this;
    }

    /**
     * @param {boolean} bool
     * @return {module.EncryptedRow}
     */
    setTypedIndexes(bool)
    {
        this.typedIndexes = bool;
        return this;
    }
};
