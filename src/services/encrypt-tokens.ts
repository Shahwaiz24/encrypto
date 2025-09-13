/**
 * Token Security Service
 * Works in both Browser (Web Crypto) and Node.js (crypto)
 * Uses AES-256-GCM with HEX key
 */

import { shouldShowSecurityWarning, markSecurityWarningAsShown } from '../shared/global-state.js';

// Type definitions
interface CryptoModule {
    randomBytes: (size: number) => Buffer;
    createCipheriv: (algorithm: string, key: Buffer, iv: Buffer) => any;
    createDecipheriv: (algorithm: string, key: Buffer, iv: Buffer) => any;
}

class TokenSecurityService {
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
     * Encrypt token
     */
    async encryptToken(token: string): Promise<string> {
        // Enhanced input validation with helpful messages
        if (token === null || token === undefined) {
            throw new Error("Token cannot be null or undefined");
        }

        if (typeof token !== "string") {
            throw new Error("Token must be a string");
        }

        // Note: Empty strings are allowed - they are valid data to encrypt

        if (this.isBrowser) {
            const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));
            const key = await this.keyPromise!;

            const encrypted = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                key,
                new TextEncoder().encode(token)
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

            const encrypted = Buffer.concat([cipher.update(token, "utf8"), cipher.final()]);
            const tag = cipher.getAuthTag();

            const combined = Buffer.concat([iv, encrypted, tag]);
            // Using base64 instead of base64url for slightly shorter output
            return combined.toString("base64url");
        }
    }

    /**
     * Decrypt token
     */
    async decryptToken(encryptedToken: string): Promise<string> {
        // Enhanced input validation with helpful messages  
        if (encryptedToken === null || encryptedToken === undefined) {
            throw new Error("Encrypted token cannot be null or undefined");
        }

        if (typeof encryptedToken !== "string") {
            throw new Error("Encrypted token must be a string");
        }

        if (encryptedToken.length === 0) {
            throw new Error("Encrypted token cannot be empty");
        }

        if (this.isBrowser) {
            const combined = this.fromBase64(encryptedToken);
            if (combined.length < this.ivLength + this.tagLength) {
                throw new Error("Invalid encrypted token format");
            }

            const iv = combined.slice(0, this.ivLength);
            const encrypted = combined.slice(this.ivLength);

            const key = await this.keyPromise!;
            const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);

            return new TextDecoder().decode(decrypted);
        } else {
            // Dynamic import for Node.js crypto
            const crypto = await import('node:crypto');
            // Decode from base64
            const combined = Buffer.from(encryptedToken, "base64url");
            if (combined.length < this.ivLength + this.tagLength) {
                throw new Error("Invalid encrypted token format");
            }

            const iv = combined.slice(0, this.ivLength);
            const data = combined.slice(this.ivLength, combined.length - this.tagLength);
            const tag = combined.slice(combined.length - this.tagLength);

            const decipher = crypto.createDecipheriv(this.algorithm, this.nodeKey!, iv) as any;
            decipher.setAuthTag(tag);

            const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
            return decrypted.toString("utf8");
        }
    }

    /**
     * Batch helpers
     */
    isValidEncryptedToken(token: string): boolean {
        try {
            if (!token || typeof token !== "string") return false;
            let decoded: Uint8Array | Buffer;
            if (this.isBrowser) {
                decoded = this.fromBase64(token);
            } else {
                decoded = Buffer.from(token, "base64url");
            }
            return decoded.length >= this.ivLength + this.tagLength;
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
const getTokenService = (secretKey: string): TokenSecurityService => {
    return new TokenSecurityService(secretKey);
};

// Exports - secretKey is mandatory
const encryptToken = async (token: string, secretKey: string): Promise<string> => {
    if (!secretKey) {
        throw new Error("Secret key is required");
    }
    return getTokenService(secretKey).encryptToken(token);
};

const decryptToken = async (encryptedToken: string, secretKey: string): Promise<string> => {
    if (!secretKey) {
        throw new Error("Secret key is required");
    }
    return getTokenService(secretKey).decryptToken(encryptedToken);
};
const generateKey = async () => {
    return await TokenSecurityService.generateSecretKey();
};

/**
 * Sign data with expiry (JWT alternative) - like jwt.sign()
 */
const sign = async (data: any, secretKey: string, expiryMinutes: number = 60): Promise<string> => {
    if (!secretKey) {
        throw new Error("Secret key is required");
    }

    if (data === undefined) {
        throw new Error("Data cannot be undefined");
    }

    if (typeof expiryMinutes !== "number" || expiryMinutes <= 0) {
        throw new Error("Expiry must be a positive number (minutes)");
    }

    const tokenData = {
        data: data,
        exp: Date.now() + (expiryMinutes * 60 * 1000),
        iat: Date.now()
    };

    return getTokenService(secretKey).encryptToken(JSON.stringify(tokenData, null, 0));
};

/**
 * Verify signed data with expiry validation - like jwt.verify()
 */
const verify = async (signedToken: string, secretKey: string): Promise<any> => {
    if (!secretKey) {
        throw new Error("Secret key is required");
    }

    try {
        const decryptedString = await getTokenService(secretKey).decryptToken(signedToken);
        const tokenData = JSON.parse(decryptedString);

        // Validate token structure
        if (!tokenData.data || !tokenData.exp || !tokenData.iat) {
            throw new Error("Invalid token format");
        }

        // Check if token has expired
        if (Date.now() > tokenData.exp) {
            throw new Error("Token has expired");
        }

        return tokenData.data;
    } catch (error) {
        if (error instanceof Error && (error.message.includes('expired') || error.message.includes('Invalid'))) {
            throw error; // Re-throw our custom errors
        }
        throw new Error("Failed to verify token");
    }
};

/**
 * ⚡ Batch encrypt multiple tokens - like crypto.batchEncrypt()
 */
const batchEncrypt = async (tokens: string[], secretKey: string): Promise<string[]> => {
    if (!secretKey) {
        throw new Error("Secret key is required");
    }

    if (!Array.isArray(tokens)) {
        throw new Error("Tokens must be an array of strings");
    }

    if (tokens.length === 0) {
        throw new Error("Tokens array cannot be empty");
    }

    const service = getTokenService(secretKey);
    const results: string[] = [];

    // Process in parallel for better performance
    const promises = tokens.map(async (token, index) => {
        try {
            if (!token || typeof token !== "string") {
                throw new Error(`Token at index ${index} must be a non-empty string`);
            }
            return await service.encryptToken(token);
        } catch (error) {
            throw new Error(`Failed to encrypt token at index ${index}`);
        }
    });

    return await Promise.all(promises);
};

/**
 * ⚡ Batch decrypt multiple tokens - like crypto.batchDecrypt()
 */
const batchDecrypt = async (encryptedTokens: string[], secretKey: string): Promise<string[]> => {
    if (!secretKey) {
        throw new Error("Secret key is required");
    }

    if (!Array.isArray(encryptedTokens)) {
        throw new Error("Encrypted tokens must be an array of strings");
    }

    if (encryptedTokens.length === 0) {
        throw new Error("Encrypted tokens array cannot be empty");
    }

    const service = getTokenService(secretKey);

    // Process in parallel for better performance
    const promises = encryptedTokens.map(async (encryptedToken, index) => {
        try {
            if (!encryptedToken || typeof encryptedToken !== "string") {
                throw new Error(`Encrypted token at index ${index} must be a non-empty string`);
            }
            return await service.decryptToken(encryptedToken);
        } catch (error) {
            throw new Error(`Failed to decrypt token at index ${index}`);
        }
    });

    return await Promise.all(promises);
};

export {
    TokenSecurityService,
    getTokenService,
    encryptToken,
    decryptToken,
    // Short & sweet names - developer friendly!
    generateKey,
    sign,
    verify,
    batchEncrypt,
    batchDecrypt
};
