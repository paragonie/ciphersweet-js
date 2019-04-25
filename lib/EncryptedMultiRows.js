"use strict";

const CipherSweetException = require('./Exception/CipherSweetException');
const Constants = require('./Constants');
const EncryptedRow = require('./EncryptedRow');

module.exports = class EncryptedMultiRows
{
    /**
     *
     * @param {module.CipherSweet} engine
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
     * @return {module.EncryptedMultiRows}
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
     * @return {module.EncryptedMultiRows}
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
     * @return {module.EncryptedMultiRows}
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
     * @return {module.EncryptedMultiRows}
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
     * @return {module.EncryptedMultiRows}
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
     * @return {module.EncryptedMultiRows}
     */
    addTextField(tableName, fieldName, aadSource = '')
    {
        return this.addField(tableName, fieldName, Constants.TYPE_TEXT, aadSource);
    }

    /**
     *
     * @param {string} tableName
     * @param {string} column
     * @param {module.BlindIndex} index
     * @return {module.EncryptedMultiRows}
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
     * @param {module.CompoundIndex} index
     * @return {module.EncryptedMultiRows}
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
     * @return {module.EncryptedRow}
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
    decryptManyRows(rows)
    {
        // Make a copy
        let row;
        rows = Object.assign({}, rows);
        for (let table in this.tables) {
            if (typeof (rows[table]) === 'undefined') {
                continue;
            }
            row = this.getEncryptedRowObjectForTable(table)
                .decryptRow(rows[table]);
            rows[table] = row;
        }
        return rows;
    }

    /**
     *
     * @param {object} rows
     * @return {object}
     */
    encryptManyRows(rows)
    {
        // Make a copy
        rows = Object.assign({}, rows);
        for (let table in this.tables) {
            if (typeof (rows[table]) === 'undefined') {
                continue;
            }
            rows[table] = this.getEncryptedRowObjectForTable(table)
                .encryptRow(rows[table]);
        }
        return rows;
    }

    /**
     * @param {string} tableName
     * @param {string} indexName
     * @param {object} row
     * @return {string|Object<string, string>}
     */
    getBlindIndex(tableName, indexName, row)
    {
        return this.getEncryptedRowObjectForTable(tableName)
            .getBlindIndex(indexName, row);
    }

    /**
     * @param {string} tableName
     * @param {object} row
     * @return {string|Object<string, string>}
     */
    getBlindIndexesForTable(tableName, row)
    {
        return this.getEncryptedRowObjectForTable(tableName)
            .getAllBlindIndexes(row);
    }

    /**
     * @param {object} rows
     * @return {object}
     */
    getAllBlindIndexes(rows)
    {
        let tables = {};
        for (let table in this.tables) {
            tables[table] = this
                .getEncryptedRowObjectForTable(table)
                .getAllBlindIndexes(rows[table]);
        }
        return tables;
    }

    /**
     * @param {string} table
     * @param {string} column
     * @param {string} name
     * @return {string}
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
     * @return {string}
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
     * @return {module.EncryptedRow}
     */
    getEncryptedRowObjectForTable(tableName = '')
    {
        if (typeof(this.tables[tableName]) === 'undefined') {
            this.addTable(tableName);
        }

        let encryptedRow = this.tables[tableName];
        encryptedRow.setTypedIndexes(this.typedIndexes);
        return encryptedRow;
    }

    /**
     * @return {string[]}
     */
    listTables()
    {
        return Object.keys(this.tables);
    }

    /**
     * @param {string} tableName
     * @param {string} fieldName
     * @param {string} aadSource
     * @return {module.EncryptedMultiRows}
     */
    setAadSourceField(tableName, fieldName, aadSource)
    {
        this.getEncryptedRowObjectForTable(tableName)
            .setAadSourceField(fieldName, aadSource);
        return this;
    }

    /**
     * @param {object} rows
     * @return {Object[]}
     */
    prepareForStorage(rows)
    {
        let indexes = {};
        let tables = {};

        for (let table in this.tables) {
            tables[table] = this
                .getEncryptedRowObjectForTable(table)
                .encryptRow(rows[table]);
            indexes[table] = this
                .getEncryptedRowObjectForTable(table)
                .getAllBlindIndexes(rows[table]);
        }
        return [tables, indexes];
    }

    /**
     * @return {module.Backend}
     */
    getBackend()
    {
        return this.engine.getBackend();
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
     * @param bool
     * @return {module.EncryptedMultiRows}
     */
    setFlatIndexes(bool)
    {
        this.typedIndexes = !bool;
        return this;
    }

    /**
     * @param bool
     * @return {module.EncryptedMultiRows}
     */
    setTypedIndexes(bool)
    {
        this.typedIndexes = bool;
        return this;
    }
};
