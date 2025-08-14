# SecureBit.chat API Documentation

## 🏗️ Architecture Overview

SecureBit.chat is built as a client-side application with no backend servers. The "API" consists of JavaScript classes and methods that handle cryptography, P2P connections, and Lightning Network integration.

## 📚 Core Classes

### 🔐 EnhancedSecureCryptoUtils

Central cryptographic utilities class providing military-grade encryption.

#### Key Generation

##### `generateECDHKeyPair()`
``javascript
static async generateECDHKeyPair(): Promise<CryptoKeyPair>
Generates non-extractable ECDH P-384 key pair for secure key exchange.
Returns: CryptoKeyPair with P-384 keys
Throws: Error if key generation fails
Example:
javascriptconst keyPair = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
console.log(keyPair.privateKey.algorithm.namedCurve); // "P-384"
generateECDSAKeyPair()
javascriptstatic async generateECDSAKeyPair(): Promise<CryptoKeyPair>
Generates non-extractable ECDSA P-384 key pair for digital signatures.
Returns: CryptoKeyPair for signing and verification
Throws: Error if key generation fails
Encryption/Decryption
encryptMessage()
javascriptstatic async encryptMessage(
    message: string,
    encryptionKey: CryptoKey,
    macKey: CryptoKey,
    metadataKey: CryptoKey,
    messageId: string,
    sequenceNumber: number = 0
): Promise<EncryptedMessage>
Encrypts a message with metadata protection and sequence numbers.
Parameters:

message - Plaintext message (max 2000 chars)
encryptionKey - AES-GCM 256-bit key
macKey - HMAC key for authentication
metadataKey - Key for metadata encryption
messageId - Unique message identifier
sequenceNumber - Message sequence for replay protection

Returns:
typescriptinterface EncryptedMessage {
    messageIv: number[];
    messageData: number[];
    metadataIv: number[];
    metadataData: number[];
    mac: number[];
    version: string;
}
Example:
javascriptconst encrypted = await EnhancedSecureCryptoUtils.encryptMessage(
    "Hello, secure world!",
    encryptionKey,
    macKey,
    metadataKey,
    "msg_12345",
    42
);
decryptMessage()
javascriptstatic async decryptMessage(
    encryptedPayload: EncryptedMessage,
    encryptionKey: CryptoKey,
    macKey: CryptoKey,
    metadataKey: CryptoKey,
    expectedSequenceNumber?: number
): Promise<DecryptedMessage>
Decrypts and verifies an encrypted message.
Returns:
typescriptinterface DecryptedMessage {
    message: string;
    messageId: string;
    timestamp: number;
    sequenceNumber: number;
}
Key Exchange
deriveSharedKeys()
javascriptstatic async deriveSharedKeys(
    privateKey: CryptoKey,
    publicKey: CryptoKey,
    salt: Uint8Array
): Promise<SharedKeys>
Derives shared encryption keys using ECDH + HKDF.
Parameters:

privateKey - Local ECDH private key
publicKey - Remote ECDH public key
salt - 64-byte cryptographic salt

Returns:
typescriptinterface SharedKeys {
    encryptionKey: CryptoKey;
    macKey: CryptoKey;
    metadataKey: CryptoKey;
    fingerprint: string;
    timestamp: number;
    version: string;
}
Example:
javascriptconst salt = EnhancedSecureCryptoUtils.generateSalt();
const sharedKeys = await EnhancedSecureCryptoUtils.deriveSharedKeys(
    localPrivateKey,
    remotePublicKey,
    salt
);
console.log('Key fingerprint:', sharedKeys.fingerprint);
Digital Signatures
signData()
javascriptstatic async signData(
    privateKey: CryptoKey,
    data: string | Uint8Array
): Promise<number[]>
Signs data with ECDSA P-384.
Parameters:

privateKey - ECDSA private key
data - Data to sign

Returns: Signature as byte array
Example:
javascriptconst signature = await EnhancedSecureCryptoUtils.signData(
    ecdsaPrivateKey,
    "Important message"
);
verifySignature()
javascriptstatic async verifySignature(
    publicKey: CryptoKey,
    signature: number[],
    data: string | Uint8Array
): Promise<boolean>
Verifies ECDSA signature.
Returns: true if signature is valid
Authentication
generateMutualAuthChallenge()
javascriptstatic generateMutualAuthChallenge(): AuthChallenge
Generates cryptographic challenge for mutual authentication.
Returns:
typescriptinterface AuthChallenge {
    challenge: number[];
    timestamp: number;
    nonce: number[];
    version: string;
}
createAuthProof()
javascriptstatic async createAuthProof(
    challenge: AuthChallenge,
    privateKey: CryptoKey,
    publicKey: CryptoKey
): Promise<AuthProof>
Creates cryptographic proof for challenge response.
Returns:
typescriptinterface AuthProof {
    challenge: number[];
    timestamp: number;
    nonce: number[];
    responseTimestamp: number;
    publicKeyHash: string;
    signature: number[];
    version: string;
}
verifyAuthProof()
javascriptstatic async verifyAuthProof(
    proof: AuthProof,
    challenge: AuthChallenge,
    publicKey: CryptoKey
): Promise<boolean>
Verifies authentication proof against challenge.
Utility Functions
generateSalt()
javascriptstatic generateSalt(): number[]
Generates 64-byte cryptographically secure salt.
sanitizeMessage()
javascriptstatic sanitizeMessage(message: string): string
Sanitizes user input to prevent XSS attacks.
Example:
javascriptconst clean = EnhancedSecureCryptoUtils.sanitizeMessage("<script>alert('xss')</script>Hello");
// Returns: "Hello"
calculateSecurityLevel()
javascriptstatic async calculateSecurityLevel(securityManager: any): Promise<SecurityLevel>
Calculates real-time security level based on active protections.
Returns:
typescriptinterface SecurityLevel {
    level: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
    score: number; // 0-100
    color: 'green' | 'yellow' | 'red';
    verificationResults: Record<string, VerificationResult>;
    timestamp: number;
    details: string;
}

interface VerificationResult {
    passed: boolean;
    details: string;
}
generateVerificationCode()
javascriptstatic generateVerificationCode(): string
Generates 6-character verification code for out-of-band authentication.
Returns: Code in format "AB-CD-EF"
calculateKeyFingerprint()
javascriptstatic async calculateKeyFingerprint(keyData: number[]): Promise<string>
Calculates SHA-256 fingerprint of key data for MITM protection.
encryptData() / decryptData()
javascriptstatic async encryptData(data: any, password: string): Promise<string>
static async decryptData(encryptedData: string, password: string): Promise<any>
High-level encryption/decryption for offer/answer exchange.
Example:
javascriptconst password = EnhancedSecureCryptoUtils.generateSecurePassword();
const encrypted = await EnhancedSecureCryptoUtils.encryptData(
    { message: "secret data" },
    password
);
const decrypted = await EnhancedSecureCryptoUtils.decryptData(encrypted, password);
🌐 EnhancedSecureWebRTCManager
Manages P2P connections with enhanced security features.
Constructor
javascriptnew EnhancedSecureWebRTCManager(
    onMessage: (message: string, type: string) => void,
    onStatusChange: (status: string) => void,
    onKeyExchange: (fingerprint: string) => void,
    onVerificationRequired: (code: string) => void
)
Parameters:

onMessage - Callback for received messages
onStatusChange - Callback for connection state changes
onKeyExchange - Callback when keys are exchanged
onVerificationRequired - Callback when verification code is generated

Connection Management
createSecureOffer()
javascriptasync createSecureOffer(): Promise<SecureOffer>
Creates encrypted connection offer with ECDH keys and authentication.
Returns:
typescriptinterface SecureOffer {
    type: 'enhanced_secure_offer';
    sdp: string;
    ecdhPublicKey: SignedPublicKey;
    ecdsaPublicKey: SignedPublicKey;
    salt: number[];
    verificationCode: string;
    authChallenge: AuthChallenge;
    sessionId: string;
    timestamp: number;
    version: string;
    securityLevel: SecurityLevel;
}

interface SignedPublicKey {
    keyType: 'ECDH' | 'ECDSA';
    keyData: number[];
    timestamp: number;
    version: string;
    signature: number[];
}
Example:
javascriptconst webrtcManager = new EnhancedSecureWebRTCManager(/*...*/);
const offer = await webrtcManager.createSecureOffer();
console.log('Verification code:', offer.verificationCode);
createSecureAnswer()
javascriptasync createSecureAnswer(offerData: SecureOffer): Promise<SecureAnswer>
Creates encrypted response to connection offer.
Returns:
typescriptinterface SecureAnswer {
    type: 'enhanced_secure_answer';
    sdp: string;
    ecdhPublicKey: SignedPublicKey;
    ecdsaPublicKey: SignedPublicKey;
    authProof: AuthProof;
    timestamp: number;
    version: string;
    securityLevel: SecurityLevel;
}
handleSecureAnswer()
javascriptasync handleSecureAnswer(answerData: SecureAnswer): Promise<void>
Processes encrypted answer and establishes connection.
Throws: Error if answer is invalid or authentication fails
Message Handling
sendSecureMessage()
javascriptasync sendSecureMessage(message: string): Promise<void>
Sends encrypted message through secure channel.
Parameters:

message - Plaintext message (auto-sanitized)

Features:

Automatic encryption with metadata protection
Sequence number tracking
Rate limiting (60 messages/minute)
Perfect Forward Secrecy key rotation

Example:
javascriptawait webrtcManager.sendSecureMessage("Hello, secure world!");
Connection States
typescripttype ConnectionState = 
    | 'disconnected'      // No connection
    | 'connecting'        // Establishing connection
    | 'verifying'         // Verifying security codes
    | 'connected'         // Fully connected and verified
    | 'failed'           // Connection failed
    | 'reconnecting'     // Attempting to reconnect
    | 'peer_disconnected'; // Peer disconnected
Security Features
calculateSecurityLevel()
javascriptasync calculateSecurityLevel(): Promise<SecurityLevel>
Real-time security assessment with verification of:

✅ Encryption functionality
✅ ECDH key exchange
✅ ECDSA signatures
✅ Mutual authentication
✅ Metadata protection
✅ Replay protection
✅ Non-extractable keys
✅ Rate limiting
✅ Perfect Forward Secrecy

shouldRotateKeys()
javascriptshouldRotateKeys(): boolean
Determines if PFS key rotation is needed (every 5 minutes or 100 messages).
isConnected()
javascriptisConnected(): boolean
Returns true if WebRTC data channel is open and ready.
getConnectionInfo()
javascriptgetConnectionInfo(): ConnectionInfo
Returns:
typescriptinterface ConnectionInfo {
    fingerprint: string;
    isConnected: boolean;
    isVerified: boolean;
    connectionState: string;
    iceConnectionState: string;
    verificationCode: string;
}
Perfect Forward Secrecy
rotateKeys()
javascriptasync rotateKeys(): Promise<boolean>
Performs key rotation for Perfect Forward Secrecy.
Returns: true if rotation successful
getKeysForVersion()
javascriptgetKeysForVersion(version: number): KeySet | null
Retrieves keys for specific version (for decrypting old messages).
Returns:
typescriptinterface KeySet {
    encryptionKey: CryptoKey;
    macKey: CryptoKey;
    metadataKey: CryptoKey;
}
Connection Control
disconnect()
javascriptdisconnect(): void
Cleanly disconnects and cleans up all resources.
confirmVerification()
javascriptconfirmVerification(): void
Confirms that verification codes match (called after manual verification).
⚡ PayPerSessionManager
Handles Lightning Network payment integration.
Constructor
javascriptnew PayPerSessionManager()
Session Types
typescriptinterface SessionPricing {
    free: { sats: 0, hours: 1/60, usd: 0.00 };
    basic: { sats: 500, hours: 1, usd: 0.20 };
    premium: { sats: 1000, hours: 4, usd: 0.40 };
    extended: { sats: 2000, hours: 24, usd: 0.80 };
}
Payment Methods
createInvoice()
javascriptcreateInvoice(sessionType: string): LightningInvoice
Creates Lightning invoice for session payment.
Parameters:

sessionType - One of: 'free', 'basic', 'premium', 'extended'

Returns:
typescriptinterface LightningInvoice {
    amount: number; // satoshis
    memo: string;
    sessionType: string;
    timestamp: number;
    paymentHash: string;
    lightningAddress: string;
}
Example:
javascriptconst sessionManager = new PayPerSessionManager();
const invoice = sessionManager.createInvoice('premium');
console.log(`Pay ${invoice.amount} sats to ${invoice.lightningAddress}`);
verifyPayment()
javascriptasync verifyPayment(preimage: string, paymentHash: string): Promise<boolean>
Verifies Lightning payment preimage.
Parameters:

preimage - Payment preimage (64 hex characters)
paymentHash - Payment hash from invoice

Returns: true if payment is valid
activateSession()
javascriptactivateSession(sessionType: string, preimage: string): Session
Activates paid session.
Returns:
typescriptinterface Session {
    type: string;
    startTime: number;
    expiresAt: number;
    preimage: string;
}
Session Management
hasActiveSession()
javascripthasActiveSession(): boolean
Returns true if there's an active, non-expired session.
getTimeLeft()
javascriptgetTimeLeft(): number
Returns milliseconds remaining in current session.
Example:
javascriptconst timeLeft = sessionManager.getTimeLeft();
const hoursLeft = Math.floor(timeLeft / (1000 * 60 * 60));
console.log(`${hoursLeft} hours remaining`);
cleanup()
javascriptcleanup(): void
Cleans up session data and timers.
🔧 Integration Examples
Basic P2P Chat Setup
javascript// Initialize WebRTC manager
const webrtcManager = new EnhancedSecureWebRTCManager(
    (message, type) => {
        console.log(`${type}: ${message}`);
        addMessageToUI(message, type);
    },
    (status) => {
        console.log(`Status: ${status}`);
        updateStatusIndicator(status);
    },
    (fingerprint) => {
        console.log(`Key fingerprint: ${fingerprint}`);
        displayFingerprint(fingerprint);
    },
    (code) => {
        console.log(`Verification code: ${code}`);
        showVerificationModal(code);
    }
);

// Create secure offer
const offer = await webrtcManager.createSecureOffer();
console.log('Share this encrypted offer:', JSON.stringify(offer));

// Send message (after connection established)
await webrtcManager.sendSecureMessage('Hello, secure world!');
Lightning Payment Integration
javascript// Initialize session manager
const sessionManager = new PayPerSessionManager();

// Create invoice for premium session
const invoice = sessionManager.createInvoice('premium');
console.log(`Pay ${invoice.amount} sats to: ${invoice.lightningAddress}`);

// Handle payment (WebLN)
if (window.webln) {
    try {
        await window.webln.enable();
        const result = await window.webln.sendPayment({
            amount: invoice.amount,
            memo: invoice.memo
        });
        
        // Verify and activate session
        const isValid = await sessionManager.verifyPayment(
            result.preimage, 
            invoice.paymentHash
        );
        
        if (isValid) {
            const session = sessionManager.activateSession('premium', result.preimage);
            console.log(`Session active until: ${new Date(session.expiresAt)}`);
        }
    } catch (error) {
        console.error('WebLN payment failed:', error);
    }
}
Custom Cryptographic Operations
javascript// Generate fresh key pairs
const ecdhKeys = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
const ecdsaKeys = await EnhancedSecureCryptoUtils.generateECDSAKeyPair();

// Create and verify signature
const data = 'Important message to sign';
const signature = await EnhancedSecureCryptoUtils.signData(
    ecdsaKeys.privateKey, 
    data
);

const isValid = await EnhancedSecureCryptoUtils.verifySignature(
    ecdsaKeys.publicKey,
    signature,
    data
);
console.log('Signature valid:', isValid);

// Derive shared keys
const salt = EnhancedSecureCryptoUtils.generateSalt();
const sharedKeys = await EnhancedSecureCryptoUtils.deriveSharedKeys(
    ecdhKeys.privateKey,
    remotePublicKey,
    salt
);

// Encrypt message
const encrypted = await EnhancedSecureCryptoUtils.encryptMessage(
    "Secret message",
    sharedKeys.encryptionKey,
    sharedKeys.macKey,
    sharedKeys.metadataKey,
    "msg_001",
    1
);
Full Connection Flow
javascript// Complete initiator flow
async function initiatorFlow() {
    // 1. Create WebRTC manager
    const manager = new EnhancedSecureWebRTCManager(
        handleMessage,
        handleStatusChange,
        handleKeyExchange,
        handleVerification
    );
    
    // 2. Create offer
    const offer = await manager.createSecureOffer();
    
    // 3. Encrypt offer for sharing
    const password = EnhancedSecureCryptoUtils.generateSecurePassword();
    const encryptedOffer = await EnhancedSecureCryptoUtils.encryptData(offer, password);
    
    // 4. Share encrypted offer and password with peer
    console.log('Encrypted offer:', encryptedOffer);
    console.log('Password:', password);
    
    // 5. Wait for encrypted answer from peer
    const encryptedAnswer = await getAnswerFromPeer();
    const answerPassword = await getPasswordFromPeer();
    
    // 6. Decrypt and process answer
    const answer = await EnhancedSecureCryptoUtils.decryptData(
        encryptedAnswer, 
        answerPassword
    );
    await manager.handleSecureAnswer(answer);
    
    // 7. Verify out-of-band codes
    await verifySecurityCodes();
    
    // 8. Start secure communication
    await manager.sendSecureMessage("Hello from initiator!");
}
Responder Flow
javascriptasync function responderFlow() {
    // 1. Get encrypted offer from initiator
    const encryptedOffer = await getOfferFromPeer();
    const offerPassword = await getPasswordFromPeer();
    
    // 2. Decrypt offer
    const offer = await EnhancedSecureCryptoUtils.decryptData(
        encryptedOffer,
        offerPassword
    );
    
    // 3. Create WebRTC manager
    const manager = new EnhancedSecureWebRTCManager(
        handleMessage,
        handleStatusChange,
        handleKeyExchange,
        handleVerification
    );
    
    // 4. Create answer
    const answer = await manager.createSecureAnswer(offer);
    
    // 5. Encrypt answer for sharing
    const password = EnhancedSecureCryptoUtils.generateSecurePassword();
    const encryptedAnswer = await EnhancedSecureCryptoUtils.encryptData(answer, password);
    
    // 6. Share encrypted answer and password
    await sendAnswerToPeer(encryptedAnswer);
    await sendPasswordToPeer(password);
    
    // 7. Verify out-of-band codes
    await verifySecurityCodes();
    
    // 8. Start secure communication
    await manager.sendSecureMessage("Hello from responder!");
}
🔒 Security Considerations
Key Security

All keys are non-extractable - Cannot be exported from WebCrypto
Hardware security module - Keys protected by browser's HSM
Perfect Forward Secrecy - Old messages stay secure even if current keys compromised
Automatic key rotation - Keys change every 5 minutes

Message Security

Authenticated encryption - AES-GCM provides confidentiality + integrity
Metadata protection - Message metadata separately encrypted
Replay protection - Sequence numbers prevent message replay
Rate limiting - Prevents spam and DoS attacks

Connection Security

Out-of-band verification - Manual code verification prevents MITM
Mutual authentication - Both parties prove identity
Direct P2P - No intermediate servers to compromise
WebRTC encryption - DTLS transport layer security

Payment Security

Lightning Network - No credit card or banking data exposure
Preimage verification - Cryptographic proof of payment
No payment data stored - Payments verified and discarded

🐛 Error Handling
Common Error Types
typescript// Cryptographic errors
class CryptoError extends Error {
    constructor(message: string) {
        super(`Crypto Error: ${message}`);
        this.name = 'CryptoError';
    }
}

// Connection errors  
class ConnectionError extends Error {
    constructor(message: string) {
        super(`Connection Error: ${message}`);
        this.name = 'ConnectionError';
    }
}

// Payment errors
class PaymentError extends Error {
    constructor(message: string) {
        super(`Payment Error: ${message}`);
        this.name = 'PaymentError';
    }
}
Error Recovery Patterns
javascript// Robust message sending with retry
async function sendMessageWithRetry(manager, message, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            await manager.sendSecureMessage(message);
            return; // Success
        } catch (error) {
            console.warn(`Send attempt ${attempt} failed:`, error.message);
            
            if (error.message.includes('Session expired')) {
                throw new PaymentError('Session expired - payment required');
            }
            
            if (error.message.includes('Rate limit')) {
                // Wait before retry
                await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
                continue;
            }
            
            if (attempt === maxRetries) {
                throw error; // Final attempt failed
            }
        }
    }
}

// Connection error handling
function handleConnectionError(error) {
    if (error.message.includes('MITM')) {
        alert('⚠️ Security threat detected! Connection terminated.');
        return 'security_threat';
    }
    
    if (error.message.includes('timeout')) {
        return 'timeout';
    }
    
    if (error.message.includes('ice')) {
        return 'nat_traversal';
    }
    
    return 'unknown';
}

// Payment error handling
function handlePaymentError(error) {
    if (error.message.includes('preimage')) {
        return 'invalid_payment';
    }
    
    if (error.message.includes('expired')) {
        return 'session_expired';
    }
    
    if (error.message.includes('webln')) {
        return 'webln_failed';
    }
    
    return 'payment_failed';
}
🧪 Testing
Unit Testing Examples
javascript// Test encryption/decryption round-trip
async function testEncryptionRoundTrip() {
    const originalMessage = 'Test message for encryption';
    const keys = await generateTestKeys();
    
    const encrypted = await EnhancedSecureCryptoUtils.encryptMessage(
        originalMessage,
        keys.encryptionKey,
        keys.macKey,
        keys.metadataKey,
        'test-id',
        0
    );
    
    const decrypted = await EnhancedSecureCryptoUtils.decryptMessage(
        encrypted,
        keys.encryptionKey,
        keys.macKey,
        keys.metadataKey
    );
    
    assert.equal(decrypted.message, originalMessage);
    assert.equal(decrypted.messageId, 'test-id');
    assert.equal(decrypted.sequenceNumber, 0);
}

// Test key generation
async function testKeyGeneration() {
    const ecdhPair = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const ecdsaPair = await EnhancedSecureCryptoUtils.generateECDSAKeyPair();
    
    // Verify key properties
    assert.equal(ecdhPair.privateKey.algorithm.name, 'ECDH');
    assert.equal(ecdhPair.privateKey.algorithm.namedCurve, 'P-384');
    assert.equal(ecdhPair.privateKey.extractable, false);
    
    assert.equal(ecdsaPair.privateKey.algorithm.name, 'ECDSA');
    assert.equal(ecdsaPair.privateKey.algorithm.namedCurve, 'P-384');
    assert.equal(ecdsaPair.privateKey.extractable, false);
}

// Test signature verification
async function testSignatureVerification() {
    const keyPair = await EnhancedSecureCryptoUtils.generateECDSAKeyPair();
    const data = 'Test data to sign';
    
    const signature = await EnhancedSecureCryptoUtils.signData(
        keyPair.privateKey,
        data
    );
    
    const isValid = await EnhancedSecureCryptoUtils.verifySignature(
        keyPair.publicKey,
        signature,
        data
    );
    
    assert.equal(isValid, true);
    
    // Test with wrong data
    const invalidVerification = await EnhancedSecureCryptoUtils.verifySignature(
        keyPair.publicKey,
        signature,
        'Wrong data'
    );
    
    assert.equal(invalidVerification, false);
}

// Helper function for tests
async function generateTestKeys() {
    const ecdhPair = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    const salt = EnhancedSecureCryptoUtils.generateSalt();
    
    // For testing, we'll create a mock "remote" key pair
    const remotePair = await EnhancedSecureCryptoUtils.generateECDHKeyPair();
    
    const sharedKeys = await EnhancedSecureCryptoUtils.deriveSharedKeys(
        ecdhPair.privateKey,
        remotePair.publicKey,
        salt
    );
    
    return sharedKeys;
}
Integration Testing
javascript// Test full P2P connection flow
async function testP2PConnection() {
    let manager1Messages = [];
    let manager2Messages = [];
    
    const manager1 = new EnhancedSecureWebRTCManager(
        (msg, type) => manager1Messages.push({msg, type}),
        (status) => console.log('Manager1 status:', status),
        (fingerprint) => console.log('Manager1 fingerprint:', fingerprint),
        (code) => console.log('Manager1 verification:', code)
    );
    
    const manager2 = new EnhancedSecureWebRTCManager(
        (msg, type) => manager2Messages.push({msg, type}),
        (status) => console.log('Manager2 status:', status),
        (fingerprint) => console.log('Manager2 fingerprint:', fingerprint),
        (code) => console.log('Manager2 verification:', code)
    );
    
    // Create offer
    const offer = await manager1.createSecureOffer();
    
    // Create answer
    const answer = await manager2.createSecureAnswer(offer);
    
    // Handle answer
    await manager1.handleSecureAnswer(answer);
    
    // Wait for connection
    await waitForConnection(manager1, manager2);
    
    // Verify both are connected
    assert.equal(manager1.isConnected(), true);
    assert.equal(manager2.isConnected(), true);
    
    // Test message exchange
    await manager1.sendSecureMessage('Hello from manager1');
    await manager2.sendSecureMessage('Hello from manager2');
    
    // Wait for messages to arrive
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Verify messages were received
    assert.equal(manager2Messages.length > 0, true);
    assert.equal(manager1Messages.length > 0, true);
}

async function waitForConnection(manager1, manager2, timeout = 10000) {
    const start = Date.now();
    
    while (Date.now() - start < timeout) {
        if (manager1.isConnected() && manager2.isConnected()) {
            return;
        }
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    throw new Error('Connection timeout');
}
