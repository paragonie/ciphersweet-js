declare module "ciphersweet-js" {
    export interface EncryptionBackend {
        multiTenantSafe(): boolean;
        getFileEncryptionSaltOffset(): number;
        decrypt(ciphertext: string, key: SymmetricKey, aad?: string): Promise<Buffer>;
        encrypt(plaintext: string|Buffer, key: SymmetricKey, aad?: string): Promise<string>;
    }
    export class BoringCrypto implements EncryptionBackend {
        public multiTenantSafe(): true;
        public getFileEncryptionSaltOffset(): number;
        public decrypt(ciphertext: string, key: SymmetricKey, aad?: string): Promise<Buffer>;
        public encrypt(plaintext: string|Buffer, key: SymmetricKey, aad?: string): Promise<string>;
    }
    export class FIPSCrypto implements EncryptionBackend {
        public multiTenantSafe(): true;
        public getFileEncryptionSaltOffset(): number;
        public decrypt(ciphertext: string, key: SymmetricKey, aad?: string): Promise<Buffer>;
        public encrypt(plaintext: string|Buffer, key: SymmetricKey, aad?: string): Promise<string>;
    }
    export class ModernCrypto implements EncryptionBackend {
        public multiTenantSafe(): false;
        public getFileEncryptionSaltOffset(): number;
        public decrypt(ciphertext: string, key: SymmetricKey, aad?: string): Promise<Buffer>;
        public encrypt(plaintext: string|Buffer, key: SymmetricKey, aad?: string): Promise<string>;
    }

    export interface CalculatedBlindIndex {
        type: string;
        value: string;
    }

    export class FieldIndexPlanner {
        public setEstimatedPopulation(population: number);
        public addExistingIndex(
            indexName: string,
            outputSizeInBits: number,
            bloomFilterSizeInBits: number
        );
        public recommend(
            inputDomainInBits?: number
        ): { min: number; max: number };
    }

    // Encrypted Field API
    export type FieldStorageTuple = [string, { [indexName: string]: string }];

    export class EncryptedField {
        constructor(
            engine: CipherSweet,
            tableName: string,
            fieldName: string,
            usedTypedIndexes?: boolean
        );
        public setTypedIndexes(enable: boolean);

        public addBlindIndex(
            blindIndex: BlindIndex,
            indexName?: string
        ): EncryptedField;

        public getBlindIndex(
            plaintext: string,
            indexName: string
        ): Promise<CalculatedBlindIndex>;
        public getAllBlindIndexes(
            plaintext: string
        ): Promise<{ [indexName: string]: CalculatedBlindIndex }>;

        public encryptValue(plaintext: string, aad?: string): Promise<string>;
        public decryptValue(ciphertext: string, aad?: string): Promise<Buffer>;

        // Returns [ciphertext, indexes]
        public prepareForStorage(
            plaintext: string,
            aad?: string
        ): Promise<FieldStorageTuple>;
    }

    export interface ModernCryptoHashConfig {
        opslimit: number;
        memlimit: number;
    }

    export interface BoringCryptoHashConfig {
        opslimit: number;
        memlimit: number;
    }
    
    export interface FIPSCryptoHashConfig {
        iterations: number;
    }

    export class BlindIndex {
        constructor(
            name: string,
            transforms: Transformation[],
            bloomFilterSizeInBits?: number,
            fastHash?: boolean,
            config?: ModernCryptoHashConfig | FIPSCryptoHashConfig | BoringCryptoHashConfig
        );
    }

    export class CompoundIndex {
        constructor(
            indexName: string,
            fieldNames: string[],
            bloomFilterSizeInBits?: number,
            fastHash?: boolean,
            config?: ModernCryptoHashConfig | FIPSCryptoHashConfig | BoringCryptoHashConfig
        );
        public addTransform(
            fieldName: string,
            transform: Transformation
        ): CompoundIndex;
        public addRowTransform(transform: RowTransformation): CompoundIndex;
    }

    // Encrypted Row API
    export type RowStorageTuple = [any, { [fieldName: string]: any }];

    export class EncryptedRow {
        constructor(engine: CipherSweet, tableName: string);
        public setTypedIndexes(boolean);
        public setFlatIndexes(boolean);
        public setAadSourceField(fieldName: string);

        public addTextField(fieldName: string, aad?: string): EncryptedRow;
        public addBooleanField(fieldName: string, aad?: string): EncryptedRow;
        public addFloatField(fieldName: string, aad?: string): EncryptedRow;

        public addBlindIndex(fieldName: string, index: BlindIndex);
        public addCompoundIndex(index: CompoundIndex);
        public createCompoundIndex(
            indexName: string,
            fieldNames: string[],
            bloomFilterSizeInBits?: number,
            fastHash?: boolean,
            config?: ModernCryptoHashConfig | FIPSCryptoHashConfig
        ): CompoundIndex;

        public decryptRow(row: Map<string, any>): Promise<Map<string, any>>;
        public encryptRow(row: Map<string, any>): Promise<Map<string, any>>;
        public prepareRowForStorage(row: any): Promise<RowStorageTuple>;
    }

    export class RowTransformation {
        /**
         * @param {Array<string, string>} input
         * @return {string}
         */
        public invoke(input: any): Promise<string>;

        /**
         * @param {Array<string, string>|Object<string, string>} input
         * @return {string}
         */
        public static processArray(input: any): Promise<string>;
    }

    // Encrypted Multi Rows
    export type MultiRowStorageTuple = [
        { [tableName: string]: { [fieldName: string]: any } },
        { [tableName: string]: { [indexName: string]: any } }
    ];

    export class EncryptedMultiRows {
        constructor(engine: CipherSweet);

        public setAadSourceField(
            tableName: string,
            indexName: string,
            aadFieldName: string
        );

        public addTextField(
            tableName: string,
            fieldName: string,
            aad?: string
        ): EncryptedMultiRows;
        public addBooleanField(
            tableName: string,
            fieldName: string,
            aad?: string
        ): EncryptedMultiRows;
        public addFloatField(
            tableName: string,
            fieldName: string,
            aad?: string
        ): EncryptedMultiRows;

        public addCompoundIndex(tableName: string, index: CompoundIndex);
        public createCompoundIndex(
            tableName: string,
            indexName: string,
            fieldNames: string[],
            bloomFilterSizeInBits?: number,
            fastHash?: boolean,
            config?: ModernCryptoHashConfig | FIPSCryptoHashConfig
        ): CompoundIndex;

        public prepareForStorage(input: any): Promise<MultiRowStorageTuple>;
    }

    // Encrypted Files
    export class EncryptedFile {
        constructor(engine: CipherSweet);

        public isFileEncrypted(inputPath: string): Promise<boolean>;
        public encryptFile(
            inputPath: string,
            outputPath: string
        ): Promise<void>;
        public decryptFile(
            inputPath: string,
            outputPath: string
        ): Promise<void>;
        public encryptFileWithPassword(
            inputPath: string,
            outputPath: string,
            password: string
        ): Promise<void>;
        public decryptFileWithPassword(
            inputPath: string,
            outputPath: string,
            password: string
        ): Promise<void>;
    }

    // Field Rotation
    export class FieldRotator {
        constructor(oldField: EncryptedField, newField: EncryptedField);

        public needsReEncrypt(ciphertext: string): boolean;
        public prepareForUpdate(
            ciphertext: string,
            oldAuthenticationTag?: string,
            newAuthenticationTag?: string
        ): FieldStorageTuple;
    }

    export class RowRotator {
        constructor(oldField: EncryptedRow, newField: EncryptedRow);

        public needsReEncrypt(ciphertext: string): boolean;
        public prepareForUpdate(ciphertext: string): RowStorageTuple;
    }

    export class MultiRowsRotator {
        constructor(oldField: EncryptedMultiRows, newField: EncryptedMultiRows);

        public needsReEncrypt(ciphertext: string): boolean;
        public prepareForUpdate(ciphertext: string): MultiRowStorageTuple;
    }

    // Transforms
    export class Transform {} // leaving in for backwards compat
    export class Transformation extends Transform {}
    export class LastFourDigits extends Transformation {}
    export class AlphaCharactersOnly extends Transformation {}
    export class FirstCharacter extends Transformation {}
    export class Lowercase extends Transformation {}

    // Key Providers
    export class SymmetricKey {
        constructor(rawKeyMaterial: string | Buffer);
        static isSymmetricKey(key: any): boolean;
        getRawKey(): Buffer;
    }

    export class KeyProvider {
        getSymmetricKey(): SymmetricKey;
    }
    export class StringProvider extends KeyProvider {
        constructor(hexEncodedKey: string);
    }
    export class MultiTenantAwareProvider extends KeyProvider {
        public getActiveTenant(): KeyProvider;
        public getTenant(name: string): KeyProvider;
        public setActiveTenant(index: string): MultiTenantAwareProvider;
        public getTenantFromRow(row: Map<string, any>, tableName: string): string;
        public injectTenantMetadata(row: Map<string, any>, tableName: string): Map<string, any>;
    }
    export class MultiTenantProvider extends MultiTenantAwareProvider {
        constructor(keyProviders: Map<string, KeyProvider>, active?: string);
    }

    // Main Engine
    export class CipherSweet {
        constructor(
            keyProvider: KeyProvider,
            encryptionBackend?: EncryptionBackend
        );

        public getBackend(): EncryptionBackend;
        public getKeyProviderForActiveTenant(): KeyProvider;
        public getKeyProviderForTenant(name: string): KeyProvider;
        public getTenantFromRow(row: Map<string, any>, tableName?: string): string;
        public setActiveTenant(tenant: string): void;
        public injectTenantMetadata(row: Map<string, any>, tableName: string): Map<string, any>;
        public isMultiTenantSupported(): boolean;

    }
}
