/**
 * Simple Direct Test
 */

import { unifiedCrypto } from './src/shared/unified-crypto-core.js';

async function simpleTest() {
    console.log('🚀 Simple Unified Crypto Test\n');

    try {
        // Test key generation
        const key = await unifiedCrypto.generateSecretKey();
        console.log(`✅ Key: ${key.substring(0, 16)}... (${key.length} chars)`);

        // Test basic encryption/decryption
        const data = "Hello World!";
        console.log(`📝 Original: ${data}`);

        const encrypted = await unifiedCrypto.encrypt(data, key);
        console.log(`🔐 Encrypted: ${encrypted.substring(0, 50)}...`);

        const decrypted = await unifiedCrypto.decrypt(encrypted, key);
        console.log(`🔓 Decrypted: ${decrypted}`);

        const match = JSON.parse(decrypted) === data;
        console.log(`🔍 Match: ${match ? '✅ YES' : '❌ NO'}`);

        if (match) {
            console.log('\n🎉 Basic test PASSED!');
        } else {
            console.log('\n❌ Basic test FAILED!');
        }

    } catch (error) {
        console.error('\n❌ Test failed:', error.message);
    }
}

simpleTest();
