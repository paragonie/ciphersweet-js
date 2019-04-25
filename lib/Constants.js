"use strict";

const Constants = {
    DS_BIDX: Buffer.alloc(32, 126),
    DS_FENC: Buffer.alloc(32, 180),

    TYPE_BOOLEAN: 'bool',
    TYPE_TEXT: 'string',
    TYPE_INT: 'float',
    TYPE_FLOAT: 'float',

    COMPOUND_SPECIAL: 'special__compound__indexes',

    FILE_TABLE: "special__file__encryption",
    FILE_COLUMN: "special__file__ciphersweet",
    DUMMY_SALT: Buffer.alloc(16, 0)
};
module.exports = Constants;
