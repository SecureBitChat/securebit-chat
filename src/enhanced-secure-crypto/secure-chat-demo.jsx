// secure-chat-demo.jsx
import React, { useState, useEffect, useCallback } from 'react';

// Импорт нашего модуля
import init, { EnhancedSecureCryptoUtils } from './pkg/enhanced_secure_crypto.js';

export function SecureChatDemo() {
    const [crypto, setCrypto] = useState(null);
    const [isReady, setIsReady] = useState(false);
    const [error, setError] = useState(null);
    const [status, setStatus] = useState('Initializing...');
    
    // Состояние для демонстрации
    const [message, setMessage] = useState('');
    const [password, setPassword] = useState('');
    const [encryptedMessage, setEncryptedMessage] = useState('');
    const [decryptedMessage, setDecryptedMessage] = useState('');
    const [keyPair, setKeyPair] = useState(null);
    const [signature, setSignature] = useState('');

    // Инициализация WASM модуля
    useEffect(() => {
        const initializeCrypto = async () => {
            try {
                setStatus('Loading WASM module...');
                await init();
                
                setStatus('Creating crypto instance...');
                const cryptoInstance = new EnhancedSecureCryptoUtils();
                setCrypto(cryptoInstance);
                
                setStatus('Generating secure password...');
                const generatedPassword = cryptoInstance.generate_secure_password();
                setPassword(generatedPassword);
                
                setStatus('Generating key pair...');
                const generatedKeyPair = cryptoInstance.generate_ecdsa_keypair();
                setKeyPair(generatedKeyPair);
                
                setIsReady(true);
                setStatus('✅ Rust crypto module ready!');
                setError(null);
                
            } catch (err) {
                console.error('Crypto initialization failed:', err);
                setError(err.message);
                setStatus('❌ Failed to initialize crypto module');
                setIsReady(false);
            }
        };

        initializeCrypto();
    }, []);

    // Функция шифрования
    const handleEncrypt = useCallback(async () => {
        if (!crypto || !message.trim()) {
            setStatus('❌ Please enter a message');
            return;
        }

        try {
            setStatus('🔒 Encrypting message...');
            const sanitized = crypto.sanitize_message(message);
            const encrypted = crypto.encrypt_data(sanitized, password);
            setEncryptedMessage(encrypted);
            setStatus('✅ Message encrypted successfully');
        } catch (err) {
            setStatus(`❌ Encryption failed: ${err.message}`);
            setError(err.message);
        }
    }, [crypto, message, password]);

    // Функция расшифровки
    const handleDecrypt = useCallback(async () => {
        if (!crypto || !encryptedMessage.trim()) {
            setStatus('❌ No encrypted message to decrypt');
            return;
        }

        try {
            setStatus('🔓 Decrypting message...');
            const decrypted = crypto.decrypt_data(encryptedMessage, password);
            setDecryptedMessage(decrypted);
            setStatus('✅ Message decrypted successfully');
        } catch (err) {
            setStatus(`❌ Decryption failed: ${err.message}`);
            setError(err.message);
        }
    }, [crypto, encryptedMessage, password]);

    // Функция подписи
    const handleSign = useCallback(async () => {
        if (!crypto || !message.trim() || !keyPair) {
            setStatus('❌ Need message and keys to sign');
            return;
        }

        try {
            setStatus('✍️ Signing message...');
            const signatureBytes = crypto.sign_data(keyPair.private_key, message);
            const signatureHex = Array.from(signatureBytes)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            setSignature(signatureHex);
            setStatus('✅ Message signed successfully');
        } catch (err) {
            setStatus(`❌ Signing failed: ${err.message}`);
            setError(err.message);
        }
    }, [crypto, message, keyPair]);

    // Функция верификации подписи
    const handleVerify = useCallback(async () => {
        if (!crypto || !message.trim() || !keyPair || !signature) {
            setStatus('❌ Need message, keys and signature to verify');
            return;
        }

        try {
            setStatus('🔍 Verifying signature...');
            const signatureBytes = signature.match(/.{1,2}/g).map(byte => parseInt(byte, 16));
            const isValid = crypto.verify_signature(keyPair.public_key, signatureBytes, message);
            setStatus(isValid ? '✅ Signature is valid' : '❌ Signature is invalid');
        } catch (err) {
            setStatus(`❌ Verification failed: ${err.message}`);
            setError(err.message);
        }
    }, [crypto, message, keyPair, signature]);

    // Генерация нового пароля
    const generateNewPassword = useCallback(() => {
        if (!crypto) return;
        const newPassword = crypto.generate_secure_password();
        setPassword(newPassword);
        setStatus('🔑 New password generated');
    }, [crypto]);

    // Генерация кода верификации
    const generateVerificationCode = useCallback(() => {
        if (!crypto) return;
        const code = crypto.generate_verification_code();
        setStatus(`🔢 Verification code: ${code}`);
    }, [crypto]);

    if (error) {
        return (
            <div style={{ 
                padding: '20px', 
                border: '2px solid #dc3545', 
                borderRadius: '8px', 
                backgroundColor: '#f8d7da' 
            }}>
                <h3>❌ Crypto Module Error</h3>
                <p>{error}</p>
                <p>Please check that your browser supports WebAssembly.</p>
            </div>
        );
    }

    return (
        <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
            <h1>🔐 Enhanced Secure Crypto Demo (Rust + WASM)</h1>
            
            {/* Status Panel */}
            <div style={{ 
                padding: '15px', 
                backgroundColor: isReady ? '#d4edda' : '#fff3cd',
                border: `1px solid ${isReady ? '#c3e6cb' : '#ffeaa7'}`,
                borderRadius: '5px',
                marginBottom: '20px'
            }}>
                <h3>Status</h3>
                <p><strong>Module Status:</strong> {status}</p>
                <p><strong>Crypto Ready:</strong> {isReady ? '✅ Yes' : '⏳ Loading...'}</p>
                <p><strong>Algorithm:</strong> AES-256-GCM + ECDSA P-384</p>
                {keyPair && (
                    <p><strong>Key Pair:</strong> ✅ Generated ({keyPair.curve})</p>
                )}
            </div>

            {isReady && (
                <>
                    {/* Password Section */}
                    <div style={{ marginBottom: '20px', padding: '15px', border: '1px solid #ddd', borderRadius: '5px' }}>
                        <h3>🔑 Password Management</h3>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
                            <input
                                type="text"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Encryption password"
                                style={{ flex: 1, padding: '8px' }}
                            />
                            <button onClick={generateNewPassword} style={buttonStyle}>
                                Generate New
                            </button>
                        </div>
                        <button onClick={generateVerificationCode} style={buttonStyle}>
                            Generate Verification Code
                        </button>
                    </div>

                    {/* Message Section */}
                    <div style={{ marginBottom: '20px', padding: '15px', border: '1px solid #ddd', borderRadius: '5px' }}>
                        <h3>💬 Message Operations</h3>
                        <textarea
                            value={message}
                            onChange={(e) => setMessage(e.target.value)}
                            placeholder="Enter your message here..."
                            rows={4}
                            style={{ width: '100%', padding: '8px', marginBottom: '10px' }}
                        />
                        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                            <button onClick={handleEncrypt} style={buttonStyle}>
                                🔒 Encrypt
                            </button>
                            <button onClick={handleSign} style={buttonStyle}>
                                ✍️ Sign
                            </button>
                            <button onClick={handleVerify} style={buttonStyle}>
                                🔍 Verify Signature
                            </button>
                        </div>
                    </div>

                    {/* Encrypted Message Section */}
                    {encryptedMessage && (
                        <div style={{ marginBottom: '20px', padding: '15px', border: '1px solid #ddd', borderRadius: '5px' }}>
                            <h3>🔐 Encrypted Message</h3>
                            <textarea
                                value={encryptedMessage}
                                readOnly
                                rows={4}
                                style={{ width: '100%', padding: '8px', backgroundColor: '#f8f9fa', marginBottom: '10px' }}
                            />
                            <button onClick={handleDecrypt} style={buttonStyle}>
                                🔓 Decrypt
                            </button>
                        </div>
                    )}

                    {/* Decrypted Message Section */}
                    {decryptedMessage && (
                        <div style={{ marginBottom: '20px', padding: '15px', border: '1px solid #d4edda', borderRadius: '5px', backgroundColor: '#d4edda' }}>
                            <h3>📄 Decrypted Message</h3>
                            <div style={{ padding: '10px', backgroundColor: 'white', borderRadius: '3px' }}>
                                {decryptedMessage}
                            </div>
                        </div>
                    )}

                    {/* Signature Section */}
                    {signature && (
                        <div style={{ marginBottom: '20px', padding: '15px', border: '1px solid #ddd', borderRadius: '5px' }}>
                            <h3>✍️ Digital Signature</h3>
                            <textarea
                                value={signature}
                                readOnly
                                rows={2}
                                style={{ width: '100%', padding: '8px', backgroundColor: '#f8f9fa', fontSize: '12px' }}
                            />
                        </div>
                    )}

                    {/* Security Info */}
                    <div style={{ padding: '15px', border: '1px solid #bee5eb', borderRadius: '5px', backgroundColor: '#d1ecf1' }}>
                        <h3>🛡️ Security Information</h3>
                        <ul>
                            <li><strong>Encryption:</strong> AES-256-GCM (256-bit key)</li>
                            <li><strong>Key Derivation:</strong> PBKDF2-HMAC-SHA256 (100,000 iterations)</li>
                            <li><strong>Digital Signatures:</strong> ECDSA P-384 with SHA-384</li>
                            <li><strong>Random Generation:</strong> Cryptographically secure PRNG</li>
                            <li><strong>Memory Safety:</strong> Rust + WebAssembly</li>
                            <li><strong>Performance:</strong> ~5-7x faster than pure JavaScript</li>
                        </ul>
                    </div>
                </>
            )}
        </div>
    );
}

const buttonStyle = {
    backgroundColor: '#007bff',
    color: 'white',
    border: 'none',
    padding: '10px 15px',
    borderRadius: '5px',
    cursor: 'pointer',
    fontSize: '14px'
};

export default SecureChatDemo;