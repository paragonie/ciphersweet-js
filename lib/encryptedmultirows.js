"use strict";

const CipherSweetException = require('./exception/ciphersweetexception');
const Constants = require('./constants');
const EncryptedRow = require('./encryptedrow');

module.exports = class EncryptedMultiRows
{
    /**
     *
     * @param {CipherSweet} engine
     * @param {boolean} useTypedIndexes
     */
    constructor(engine, useTypedIndexes = false)
    {
        this.engine = engine;
        this.typedIndexes = useTypedIndexes;
        this.tables = {};
    }

    /**
     * @param {string} tableName
     * @returns {EncryptedMultiRows}
     */
    addTable(tableName)
    {
        if (typeof this.tables[tableName] !== 'undefined') {
            throw new CipherSweetException('Table already exists');
        }
        this.tables[tableName] = new EncryptedRow(this.engine, tableName);
        return this;
    }

    /**
     *
     * @param {string} tableName
     * @param {string} fieldName
     * @param {string} type
     * @param {string} aadSource
     * @returns {EncryptedMultiRows}
     */
    addField(tableName, fieldName, type = Constants.TYPE_TEXT, aadSource = '')
    {
        this.getEncryptedRowObjectForTable(tableName).addField(fieldName, type, aadSource);
        return this;
    }

    /**
     *
     * @param {string} tableName
     * @param {string} fieldName
     * @param {string} aadSource
     * @returns {EncryptedMultiRows}
     */
    addBooleanField(tableName, fieldName, aadSource = '')
    {
        return this.addField(tableName, fieldName, Constants.TYPE_BOOLEAN, aadSource);
    }

    /**
     *
     * @param {string} tableName
     * @param {string} fieldName
     * @param {string} aadSource
     * @returns {EncryptedMultiRows}
     */
    addFloatField(tableName, fieldName, aadSource = '')
    {
        return this.addField(tableName, fieldName, Constants.TYPE_FLOAT, aadSource);
    }

    /**
     *
     * @param {string} tableName
     * @param {string} fieldName
     * @param {string} aadSource
     * @returns {EncryptedMultiRows}
     */
    addIntegerField(tableName, fieldName, aadSource = '')
    {
        return this.addField(tableName, fieldName, Constants.TYPE_INT, aadSource);
    }

    /**
     *
     * @param {string} tableName
     * @param {string} fieldName
     * @param {string} aadSource
     * @returns {EncryptedMultiRows}
     */
    addTextField(tableName, fieldName, aadSource = '')
    {
        return this.addField(tableName, fieldName, Constants.TYPE_TEXT, aadSource);
    }

    /**
     *
     * @param {string} tableName
     * @param {string} column
     * @param {BlindIndex} index
     * @returns {EncryptedMultiRows}
     */
    addBlindIndex(tableName, column, index)
    {
        this.getEncryptedRowObjectForTable(tableName)
            .addBlindIndex(column, index);
        return this;
    }

    /**
     *
     * @param {string} tableName
     * @param {CompoundIndex} index
     * @returns {EncryptedMultiRows}
     */
    addCompoundIndex(tableName, index)
    {
        this.getEncryptedRowObjectForTable(tableName)
            .addCompoundIndex(index);
        return this;
    }

    /**
     *
     * @param {string} tableName
     * @param {string} name
     * @param {string[]} columns
     * @param {Number} filterBits
     * @param {boolean} fastHash
     * @param {Object} hashConfig
     * @returns {EncryptedRow}
     */
    createCompoundIndex(
        tableName,
        name,
        columns = [],
        filterBits = 256,
        fastHash = false,
        hashConfig = {}
    ) {
        return this.getEncryptedRowObjectForTable(tableName)
            .createCompoundIndex(
                name,
                columns,
                filterBits,
                fastHash,
                hashConfig
            );
    }

    /**
     *
     * @param rows
     */
    async decryptManyRows(rows)
    {
        // Make a copy
        let row;
        rows = Object.assign({}, rows);
        for (let table in this.tables) {
            if (typeof (rows[table]) === 'undefined') {
                continue;
            }
            row = await this.getEncryptedRowObjectForTable(table)
                .decryptRow(rows[table]);
            rows[table] = row;
        }
        return rows;
    }

    /**
     *
     * @param {object} rows
     * @returns {object}
     */
    async encryptManyRows(rows)
    {
        // Make a copy
        rows = Object.assign({}, rows);
        for (let table in this.tables) {
            if (typeof (rows[table]) === 'undefined') {
                continue;
            }
            rows[table] = await this.getEncryptedRowObjectForTable(table)
                .encryptRow(rows[table]);
        }
        return rows;
    }

    /**
     * @param {string} tableName
     * @param {string} indexName
     * @param {object} row
     * @returns {string|Object<string, string>}
     */
    async getBlindIndex(tableName, indexName, row)
    {
        return await this.getEncryptedRowObjectForTable(tableName)
            .getBlindIndex(indexName, row);
    }

    /**
     * @param {string} tableName
     * @param {object} row
     * @returns {string|Object<string, string>}
     */
    async getBlindIndexesForTable(tableName, row)
    {
        return await this.getEncryptedRowObjectForTable(tableName)
            .getAllBlindIndexes(row);
    }

    /**
     * @param {object} rows
     * @returns {object}
     */
    async getAllBlindIndexes(rows)
    {
        const tables = {};
        for (let table in this.tables) {
            tables[table] = await this
                .getEncryptedRowObjectForTable(table)
                .getAllBlindIndexes(rows[table]);
        }
        return tables;
    }

    /**
     * @param {string} table
     * @param {string} column
     * @param {string} name
     * @returns {string}
     */
    getBlindIndexType(table, column, name)
    {
        return this
            .getEncryptedRowObjectForTable(table)
            .getBlindIndexType(column, name);
    }

    /**
     * @param {string} table
     * @param {string} name
     * @returns {string}
     */
    getCompoundIndexType(table, name)
    {
        return this
            .getEncryptedRowObjectForTable(table)
            .getCompoundIndexType(name);
    }

    /**
     *
     * @param {string} tableName
     * @returns {EncryptedRow}
     */
    getEncryptedRowObjectForTable(tableName = '')
    {
        if (typeof(this.tables[tableName]) === 'undefined') {
            this.addTable(tableName);
        }

        const encryptedRow = this.tables[tableName];
        encryptedRow.setTypedIndexes(this.typedIndexes);
        return encryptedRow;
    }

    /**
     * @returns {string[]}
     */
    listTables()
    {
        return Object.keys(this.tables);
    }

    /**
     * @param {string} tableName
     * @param {string} fieldName
     * @param {string} aadSource
     * @returns {EncryptedMultiRows}
     */
    setAadSourceField(tableName, fieldName, aadSource)
    {
        this.getEncryptedRowObjectForTable(tableName)
            .setAadSourceField(fieldName, aadSource);
        return this;
    }

    /**
     * @param {object} rows
     * @returns {Object[]}
     */
    async prepareForStorage(rows)
    {
        const indexes = {};
        const tables = {};

        for (let table in this.tables) {
            tables[table] = await this
                .getEncryptedRowObjectForTable(table)
                .encryptRow(rows[table]);
            indexes[table] = await this
                .getEncryptedRowObjectForTable(table)
                .getAllBlindIndexes(rows[table]);
        }
        return [tables, indexes];
    }

    /**
     * @returns {Backend}
     */
    getBackend()
    {
        return this.engine.getBackend();
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
     * @param bool
     * @returns {EncryptedMultiRows}
     */
    setFlatIndexes(bool)
    {
        this.typedIndexes = !bool;
        return this;
    }

    /**
     * @param bool
     * @returns {EncryptedMultiRows}
     */
    setTypedIndexes(bool)
    {
        this.typedIndexes = bool;
        return this;
    }
};
