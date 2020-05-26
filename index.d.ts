declare module "ciphersweet-js" {
    export interface EncryptionBackend {}
    export class FIPSCrypto implements EncryptionBackend {}
    export class ModernCrypto implements EncryptionBackend {}

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

        public encryptValue(plaintext: string, aad?: string);
        public decryptValue(ciphertext: string, aad?: string);

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

    export interface FIPSCryptoHashConfig {
        iterations: number;
    }

    export class BlindIndex {
        constructor(
            name: string,
            transforms: Transform[],
            bloomFilterSizeInBits?: number,
            fastHash?: boolean,
            config?: ModernCryptoHashConfig | FIPSCryptoHashConfig
        );
    }

    export class CompoundIndex {
        constructor(
            indexName: string,
            fieldNames: string[],
            bloomFilterSizeInBits?: number,
            fastHash?: boolean,
            config?: ModernCryptoHashConfig | FIPSCryptoHashConfig
        );
        public addTransform(
            fieldName: string,
            transform: Transform
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
    export class Transform {}
    export class LastFourDigits extends Transform {}
    export class AlphaCharactersOnly extends Transform {}
    export class FirstCharacter extends Transform {}
    export class Lowercase extends Transform {}

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

    // Main Engine
    export class CipherSweet {
        constructor(
            keyProvider: KeyProvider,
            encryptionBackend?: EncryptionBackend
        );

        public getBackend(): EncryptionBackend;
    }
}
