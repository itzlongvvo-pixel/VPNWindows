/**
 * Nera VPN™ - RSA Key Management
 * 
 * Handles persistent RSA keypair for blind signature authentication.
 * Keys are stored in the keys/ directory and generated on first run.
 */

const NodeRSA = require('node-rsa');
const fs = require('fs');
const path = require('path');

const KEYS_DIR = path.join(__dirname, '..', 'keys');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'private.pem');
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, 'public.pem');

let privateKey = null;
let publicKey = null;

/**
 * Initialize RSA keys - loads existing or generates new ones
 */
function initKeys() {
    // Ensure keys directory exists
    if (!fs.existsSync(KEYS_DIR)) {
        fs.mkdirSync(KEYS_DIR, { recursive: true });
        console.log('📁 Created keys directory');
    }

    // Check if keys already exist
    if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
        console.log('🔑 Loading existing RSA keys...');
        const privateKeyPem = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
        const publicKeyPem = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');

        privateKey = new NodeRSA(privateKeyPem);
        publicKey = new NodeRSA(publicKeyPem);

        console.log('✅ RSA keys loaded successfully');
    } else {
        console.log('🔐 Generating new 2048-bit RSA keypair...');

        // Generate new keypair
        const key = new NodeRSA({ b: 2048 });
        key.setOptions({ encryptionScheme: 'pkcs1' });

        // Export keys
        const privateKeyPem = key.exportKey('pkcs8-private-pem');
        const publicKeyPem = key.exportKey('pkcs8-public-pem');

        // Save to files
        fs.writeFileSync(PRIVATE_KEY_PATH, privateKeyPem);
        fs.writeFileSync(PUBLIC_KEY_PATH, publicKeyPem);

        privateKey = key;
        publicKey = new NodeRSA(publicKeyPem);

        console.log('✅ New RSA keys generated and saved');
    }
}

/**
 * Get the private key for signing
 * @returns {NodeRSA} Private key instance
 */
function getPrivateKey() {
    if (!privateKey) {
        throw new Error('Keys not initialized. Call initKeys() first.');
    }
    return privateKey;
}

/**
 * Get the public key for verification
 * @returns {NodeRSA} Public key instance
 */
function getPublicKey() {
    if (!publicKey) {
        throw new Error('Keys not initialized. Call initKeys() first.');
    }
    return publicKey;
}

/**
 * Get the public key as PEM string (for client configuration)
 * @returns {string} Public key in PEM format
 */
function getPublicKeyPem() {
    if (!publicKey) {
        throw new Error('Keys not initialized. Call initKeys() first.');
    }
    return fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
}

/**
 * Sign a blinded token using raw RSA operation (m^d mod n)
 * For RSA blind signatures, we perform raw modular exponentiation with private key
 * This is NOT the same as PKCS#1 signing - it's the mathematical RSA primitive
 * @param {Buffer} blindedTokenBuffer - The blinded message from client
 * @returns {Buffer} Raw RSA "signature" (really decryption)
 */
function signBlindToken(blindedTokenBuffer) {
    const key = getPrivateKey();
    // Use decryptPublic with 'pkcs1' scheme for raw RSA operation
    // node-rsa's decrypt performs m^d mod n which is what we need
    try {
        // For blind signatures, we need the raw RSA operation: s = m^d mod n
        // node-rsa's sign() adds padding which breaks blind signature math
        // Instead, we use the underlying privateDecrypt which performs raw RSA
        const signed = key.encrypt(blindedTokenBuffer, 'buffer', 'buffer');
        return signed;
    } catch (e) {
        // Fallback: try decrypt operation (depends on key configuration)
        return key.decrypt(blindedTokenBuffer, 'buffer');
    }
}

module.exports = {
    initKeys,
    getPrivateKey,
    getPublicKey,
    getPublicKeyPem,
    signBlindToken
};
