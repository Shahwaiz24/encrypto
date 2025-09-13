/**
 * Data Security Service
 * Works in both Browser (Web Crypto) and Node.js (crypto)
 * Uses AES-256-GCM with HEX key - Accepts any data type (objects, arrays, strings, numbers, etc.)
 */

import { shouldShowSecurityWarning, markSecurityWarningAsShown } from '../shared/global-state.js';

// Type definitions
interface CryptoModule {
    randomBytes: (size: number) => Buffer;
    createCipheriv: (algorithm: string, key: Buffer, iv: Buffer) => any;
    createDecipheriv: (algorithm: string, key: Buffer, iv: Buffer) => any;
}

class DataSecurityService {
    private keyLength: number = 32;
    private ivLength: number = 12;
    private tagLength: number = 16;
    private secretKey: string;
    private isBrowser: boolean;
    private isNode: boolean;
    private algorithm: string;
    private keyPromise?: Promise<CryptoKey>;
    private nodeCrypto?: CryptoModule;
    private nodeKey?: Buffer;

    /**
     * 🔒 Security: Constant-time string comparison to prevent timing attacks
     */
    private static safeCompare(a: string, b: string): boolean {
        if (a.length !== b.length) return false;
        let result = 0;
        const maxLength = Math.max(a.length, b.length);
        for (let i = 0; i < maxLength; i++) {
            const aChar = i < a.length ? a.charCodeAt(i) : 0;
            const bChar = i < b.length ? b.charCodeAt(i) : 0;
            result |= aChar ^ bChar;
        }
        return result === 0;
    }

    constructor(secretKey: string) {
        // Enhanced validation with developer-friendly error messages
        if (!secretKey) {
            throw new Error("Secret key is required");
        }

        if (typeof secretKey !== 'string') {
            throw new Error("Secret key must be a string");
        }

        if (secretKey.length !== 64) {
            throw new Error("Secret key must be exactly 64 characters");
        }

        if (!/^[0-9a-f]+$/i.test(secretKey)) {
            throw new Error("Secret key must be a valid HEX string");
        }

        // Security reminder for development (only once per process - shared across all securex services)
        if (shouldShowSecurityWarning()) {
            console.warn(
                "🔐 SECURITY REMINDER:\n" +
                "• Rotate encryption keys regularly\n" +
                "• Never commit keys to version control\n" +
                "• Use environment variables for key storage\n" +
                "• Consider key management services for production"
            );
            markSecurityWarningAsShown();
        }

        this.secretKey = secretKey;

        // detect runtime
        this.isBrowser = (typeof window !== "undefined" && typeof window.crypto !== "undefined");
        this.isNode = !this.isBrowser;

        if (this.isBrowser) {
            this.algorithm = "AES-GCM"; // ✅ Web Crypto syntax
            this.keyPromise = this.importWebCryptoKey(this.secretKey);
        } else {
            this.algorithm = "aes-256-gcm"; // ✅ Node.js syntax
            // In Node.js, we'll dynamically import crypto when needed
            this.nodeKey = Buffer.from(this.secretKey, "hex");
        }
    }

    /**
     * Import key for browser (Web Crypto)
     */
    private async importWebCryptoKey(secret: string): Promise<CryptoKey> {
        const rawKey = Uint8Array.from(Buffer.from(secret, "hex"));
        return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    }

    /**
     * Generate a random secret key (HEX, save in .env)
     */
    static async generateSecretKey(): Promise<string> {
        if (typeof window !== "undefined") {
            const arr = new Uint8Array(32);
            window.crypto.getRandomValues(arr);
            return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
        } else {
            // Use dynamic import for Node.js crypto in ES modules
            const { randomBytes } = await import('node:crypto');
            return randomBytes(32).toString("hex");
        }
    }

    /**
     * Encrypt any data (converts to JSON string internally)
     */
    async encryptData(data: any): Promise<string> {
        // Enhanced validation - allow any data type except undefined
        if (data === undefined) {
            throw new Error("Cannot encrypt undefined data");
        }

        // Convert data to JSON string (supports unlimited data size)
        let dataString: string;
        try {
            dataString = JSON.stringify(data, null, 0);
            // No maximum length restriction - handle any size data
        } catch (error) {
            throw new Error("Failed to serialize data to JSON");
        }

        if (this.isBrowser) {
            const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));
            const key = await this.keyPromise!;

            const encrypted = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                key,
                new TextEncoder().encode(dataString)
            );

            const combined = new Uint8Array(iv.length + encrypted.byteLength);
            combined.set(iv, 0);
            combined.set(new Uint8Array(encrypted), iv.length);

            return this.toBase64(combined);
        } else {
            // Dynamic import for Node.js crypto
            const crypto = await import('node:crypto');
            const iv = crypto.randomBytes(this.ivLength);
            const cipher = crypto.createCipheriv(this.algorithm, this.nodeKey!, iv) as any;

            const encrypted = Buffer.concat([cipher.update(dataString, "utf8"), cipher.final()]);
            const tag = cipher.getAuthTag();

            const combined = Buffer.concat([iv, encrypted, tag]);
            // Using base64 for shorter output
            return combined.toString("base64url");
        }
    }

    /**
     * Decrypt data (returns original data type)
     */
    async decryptData(encryptedData: string): Promise<any> {
        // Enhanced input validation
        if (encryptedData === null || encryptedData === undefined) {
            throw new Error("Encrypted data cannot be null or undefined");
        }

        if (typeof encryptedData !== "string") {
            throw new Error("Encrypted data must be a string");
        }

        if (encryptedData.length === 0) {
            throw new Error("Encrypted data cannot be empty");
        }

        let decryptedString: string;

        if (this.isBrowser) {
            const combined = this.fromBase64(encryptedData);
            if (combined.length < this.ivLength + this.tagLength + 1) {
                throw new Error("Invalid encrypted data format");
            }

            const iv = combined.slice(0, this.ivLength);
            const encrypted = combined.slice(this.ivLength);

            const key = await this.keyPromise!;
            const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);

            decryptedString = new TextDecoder().decode(decrypted);
        } else {
            // Dynamic import for Node.js crypto
            const crypto = await import('node:crypto');
            // Decode from base64
            const combined = Buffer.from(encryptedData, "base64url");
            if (combined.length < this.ivLength + this.tagLength + 1) {
                throw new Error("Invalid encrypted data format");
            }

            const iv = combined.slice(0, this.ivLength);
            const data = combined.slice(this.ivLength, combined.length - this.tagLength);
            const tag = combined.slice(combined.length - this.tagLength);

            const decipher = crypto.createDecipheriv(this.algorithm, this.nodeKey!, iv) as any;
            decipher.setAuthTag(tag);

            const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
            decryptedString = decrypted.toString("utf8");
        }

        // Parse JSON back to original data type
        try {
            return JSON.parse(decryptedString);
        } catch (error) {
            throw new Error("Failed to parse decrypted data from JSON");
        }
    }


    /**
     * Check if a string is valid encrypted data
     */
    isValidEncryptedData(data: string): boolean {
        try {
            if (!data || typeof data !== "string") return false;
            let decoded: Uint8Array | Buffer;
            if (this.isBrowser) {
                decoded = this.fromBase64(data);
            } else {
                decoded = Buffer.from(data, "base64url");
            }
            return decoded.length >= this.ivLength + this.tagLength + 1;
        } catch {
            return false;
        }
    }

    /**
     * Base64 helpers (browser only) - Using standard base64 for shorter output
     */
    private toBase64(buffer: Uint8Array): string {
        let str = "";
        buffer.forEach((b) => {
            str += String.fromCharCode(b);
        });
        return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    private fromBase64(base64: string): Uint8Array {
        // Convert base64url back to base64
        const base64Standard = base64.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64Standard + '='.repeat((4 - base64Standard.length % 4) % 4);
        const binary = atob(padded);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
}

// No singleton - always create new instance with mandatory key
const getDataService = (secretKey: string): DataSecurityService => {
    return new DataSecurityService(secretKey);
};

// Exports - secretKey is mandatory
const encryptData = async (data: any, secretKey: string): Promise<string> => {
    if (!secretKey) {
        throw new Error("Secret key is required");
    }
    return getDataService(secretKey).encryptData(data);
};

const decryptData = async (encryptedData: string, secretKey: string): Promise<any> => {
    if (!secretKey) {
        throw new Error("Secret key is required");
    }
    return getDataService(secretKey).decryptData(encryptedData);
};

/**
 * ⚡ Batch encrypt multiple data items - short & sweet!
 */
const batchData = async (dataArray: any[], secretKey: string): Promise<string[]> => {
    if (!secretKey) {
        throw new Error("Secret key is required");
    }

    if (!Array.isArray(dataArray)) {
        throw new Error("Data must be an array of items to encrypt");
    }

    if (dataArray.length === 0) {
        throw new Error("Data array cannot be empty");
    }

    const service = getDataService(secretKey);

    // Process in parallel for better performance
    const promises = dataArray.map(async (data, index) => {
        try {
            if (data === undefined) {
                throw new Error(`Data at index ${index} cannot be undefined`);
            }
            return await service.encryptData(data);
        } catch (error) {
            throw new Error(`Failed to encrypt data at index ${index}`);
        }
    });

    return await Promise.all(promises);
};

/**
 * ⚡ Batch decrypt multiple data items - short & sweet!
 */
const batchDataDecrypt = async (encryptedDataArray: string[], secretKey: string): Promise<any[]> => {
    if (!secretKey) {
        throw new Error("Secret key is required");
    }

    if (!Array.isArray(encryptedDataArray)) {
        throw new Error("Encrypted data must be an array of strings");
    }

    if (encryptedDataArray.length === 0) {
        throw new Error("Encrypted data array cannot be empty");
    }

    const service = getDataService(secretKey);

    // Process in parallel for better performance
    const promises = encryptedDataArray.map(async (encryptedData, index) => {
        try {
            if (!encryptedData || typeof encryptedData !== "string") {
                throw new Error(`Encrypted data at index ${index} must be a non-empty string`);
            }
            return await service.decryptData(encryptedData);
        } catch (error) {
            throw new Error(`Failed to decrypt data at index ${index}`);
        }
    });

    return await Promise.all(promises);
};


export {
    DataSecurityService,
    getDataService,
    encryptData,
    decryptData,
    // Short & sweet batch operations!
    batchData,
    batchDataDecrypt
};
