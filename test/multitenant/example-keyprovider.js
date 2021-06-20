const crypto = require('crypto');
const StringProvider = require('../../lib/keyprovider/stringprovider');
const MultiTenantProvider = require('../../lib/keyprovider/multitenantprovider');

module.exports = class TestMultiTenantKeyProvider extends MultiTenantProvider {
    /**
     * @param {object} row
     * @param {string} tableName
     * @return {string}
     */
    getTenantFromRow(row, tableName) {
        switch (row.tenant) {
            case 'foo':
            case 'bar':
            case 'baz':
                return row.tenant;
            default:
                return super.getTenantFromRow(row, tableName);
        }
    }

    injectTenantMetadata(row, tableName) {
        if (tableName !== 'meta') {
            row['tenant-extra'] = tableName;
        } else {
            row['wrapped-key'] = this.wrapKey(tableName);
        }
        row['tenant'] = this.active;
        return row;
    }

    getWrappingKey() {
        const hash = crypto.createHash('sha256');
        return hash.update('unit tests').digest();
    }

    /**
     * This is just a dummy key-wrapping example.
     * You'd really want to use KMS from AWS or GCP.
     *
     * @param {string} tableName
     * @return {string}
     */
    wrapKey(tableName) {
        const wrappingKey = this.getWrappingKey();
        const nonce = crypto.randomBytes(12);

        const cipher = crypto.createCipheriv('aes-256-gcm', wrappingKey, nonce);
        cipher.setAAD(Buffer.from(tableName));
        const wrapped = cipher.update(
            this.getActiveTenant().getSymmetricKey().getRawKey()
        );
        cipher.final();

        return Buffer.concat([nonce, wrapped]).toString('base64');
    }
}
