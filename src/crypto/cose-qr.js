/**
 * COSE-based QR Code Compression and Encryption
 * Implements secure payload packing with CBOR, compression, and chunking
 */

import * as cbor from 'cbor-js';
import * as pako from 'pako';
import * as base64 from 'base64-js';

// Base64URL encoding/decoding helpers
function toBase64Url(uint8) {
    let b64 = base64.fromByteArray(uint8);
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return base64.toByteArray(str);
}

// Generate UUID for chunking
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

/**
 * Pack secure payload using COSE-like structure with compression
 * @param {Object} payloadObj - The data to pack
 * @param {CryptoKey} senderEcdsaPrivKey - Sender's signing key (optional)
 * @param {CryptoKey} recipientEcdhPubKey - Recipient's ECDH key (optional, null for broadcast)
 * @returns {Array<string>} Array of QR code strings (chunks)
 */
export async function packSecurePayload(payloadObj, senderEcdsaPrivKey = null, recipientEcdhPubKey = null) {
    try {
        console.log('🔐 Starting COSE packing...');
        
        // 1. Canonicalize payload (minified JSON)
        const payloadJson = JSON.stringify(payloadObj);
        console.log(`📊 Original payload size: ${payloadJson.length} characters`);
        
        // 2. Create ephemeral ECDH keypair (P-384) for encryption
        let ciphertextCose;
        let ephemeralRaw = null;
        
        if (recipientEcdhPubKey) {
            console.log('🔐 Encrypting for specific recipient...');
            
            // Generate ephemeral ECDH keypair
            const ecdhPair = await crypto.subtle.generateKey(
                { name: "ECDH", namedCurve: "P-384" },
                true,
                ["deriveKey", "deriveBits"]
            );
            
            // Export ephemeral public key as raw bytes
            ephemeralRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ecdhPair.publicKey));
            
            // Derive shared secret
            const sharedBits = await crypto.subtle.deriveBits(
                { name: "ECDH", public: recipientEcdhPubKey },
                ecdhPair.privateKey,
                384
            );
            
            // HKDF-SHA384: derive AES-256-GCM key
            const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
            const cek = await crypto.subtle.deriveKey(
                {
                    name: 'HKDF',
                    hash: 'SHA-384',
                    salt: new Uint8Array(0),
                    info: new TextEncoder().encode('SecureBit QR ECDH AES key')
                },
                hkdfKey,
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );
            
            // AES-GCM encrypt payload
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const enc = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                cek,
                new TextEncoder().encode(payloadJson)
            );
            
            // Build COSE_Encrypt-like structure
            ciphertextCose = {
                protected: { alg: 'A256GCM' },
                unprotected: { epk: ephemeralRaw },
                ciphertext: new Uint8Array(enc),
                iv: iv
            };
        } else {
            console.log('🔐 Using broadcast mode (no encryption)...');
            // Broadcast mode: not encrypted, include ephemeral key for future use
            ephemeralRaw = crypto.getRandomValues(new Uint8Array(97)); // P-384 uncompressed point size
            ciphertextCose = {
                plaintext: new TextEncoder().encode(payloadJson),
                epk: ephemeralRaw
            };
        }
        
        // 3. Wrap in COSE_Sign1 structure (sign if key provided)
        let coseSign1;
        const toSign = cbor.encode(ciphertextCose);
        
        if (senderEcdsaPrivKey) {
            console.log('🔐 Signing payload...');
            // Sign using ECDSA P-384 SHA-384
            const signature = new Uint8Array(await crypto.subtle.sign(
                { name: 'ECDSA', hash: 'SHA-384' },
                senderEcdsaPrivKey,
                toSign
            ));
            
            // COSE_Sign1 as array: [protected, unprotected, payload, signature]
            const protectedHeader = cbor.encode({ alg: 'ES384' });
            const unprotectedHeader = { kid: 'securebit-sender' };
            coseSign1 = [protectedHeader, unprotectedHeader, toSign, signature];
        } else {
            console.log('🔐 No signing key provided, using unsigned structure...');
            // COSE_Sign1 as array: [protected, unprotected, payload, signature]
            const protectedHeader = cbor.encode({ alg: 'none' });
            const unprotectedHeader = {};
            coseSign1 = [protectedHeader, unprotectedHeader, toSign, new Uint8Array(0)];
        }
        
        // 4. Final encode: CBOR -> deflate -> base64url
        const cborFinal = cbor.encode(coseSign1);
        const compressed = pako.deflate(cborFinal);
        const encoded = toBase64Url(compressed);
        
        console.log(`📊 Compressed size: ${encoded.length} characters (${Math.round((1 - encoded.length/payloadJson.length) * 100)}% reduction)`);
        
        // 5. Chunking for QR codes - улучшенное разбиение для лучшего сканирования
        const TARGET_CHUNKS = 10; // Целевое количество частей
        const QR_MAX = Math.max(200, Math.floor(encoded.length / TARGET_CHUNKS)); // Динамический размер части
        const chunks = [];
        
        if (encoded.length <= QR_MAX) {
            // Single chunk
            chunks.push(JSON.stringify({
                hdr: { v: 1, id: generateUUID(), seq: 1, total: 1 },
                body: encoded
            }));
        } else {
            // Multiple chunks - разбиваем на больше частей для лучшего сканирования
            const id = generateUUID();
            const totalChunks = Math.ceil(encoded.length / QR_MAX);
            
            console.log(`📊 COSE: Splitting ${encoded.length} chars into ${totalChunks} chunks (max ${QR_MAX} chars per chunk)`);
            
            for (let i = 0, seq = 1; i < encoded.length; i += QR_MAX, seq++) {
                const part = encoded.slice(i, i + QR_MAX);
                chunks.push(JSON.stringify({
                    hdr: { v: 1, id, seq, total: totalChunks },
                    body: part
                }));
            }
        }
        
        console.log(`📊 Generated ${chunks.length} QR chunk(s)`);
        return chunks;
        
    } catch (error) {
        console.error('❌ Error in packSecurePayload:', error);
        throw error;
    }
}

/**
 * Receive and process COSE-packed QR data
 * @param {Array<string>} qrStrings - Array of QR code strings
 * @param {CryptoKey} recipientEcdhPrivKey - Recipient's ECDH private key (optional)
 * @param {CryptoKey} trustedSenderPubKey - Trusted sender's public key (optional)
 * @returns {Array<Object>} Array of processed payloads
 */
export async function receiveAndProcess(qrStrings, recipientEcdhPrivKey = null, trustedSenderPubKey = null) {
    try {
        console.log('🔓 Starting COSE processing...');
        
        // 1. Assemble chunks by ID
        console.log(`📊 Processing ${qrStrings.length} QR string(s)`);
        const assembled = await assembleFromQrStrings(qrStrings);
        if (!assembled.length) {
            console.error('❌ No complete packets found after assembly');
            throw new Error('No complete packets found');
        }
        
        console.log(`📊 Assembled ${assembled.length} complete packet(s)`);
        console.log('📊 First assembled packet:', assembled[0]);
        
        const results = [];
        
        for (const pack of assembled) {
            try {
                const encoded = pack.jsonObj;
                
                // 2. Decode: base64url -> decompress -> CBOR decode
                const compressed = fromBase64Url(encoded.body || encoded);
                const cborBytes = pako.inflate(compressed);
                console.log('🔓 Decompressed CBOR bytes length:', cborBytes.length);
                console.log('🔓 CBOR bytes type:', typeof cborBytes, cborBytes.constructor.name);
                
                // Convert Uint8Array to ArrayBuffer for cbor-js
                const cborArrayBuffer = cborBytes.buffer.slice(cborBytes.byteOffset, cborBytes.byteOffset + cborBytes.byteLength);
                console.log('🔓 Converted to ArrayBuffer, length:', cborArrayBuffer.byteLength);
                
                const coseSign1 = cbor.decode(cborArrayBuffer);
                
                console.log('🔓 Decoded COSE structure');
                
                // Handle both array and object formats
                let protectedHeader, unprotectedHeader, payload, signature;
                if (Array.isArray(coseSign1)) {
                    // Array format: [protected, unprotected, payload, signature]
                    [protectedHeader, unprotectedHeader, payload, signature] = coseSign1;
                    console.log('🔓 COSE structure is array format');
                } else {
                    // Object format (legacy)
                    protectedHeader = coseSign1.protected;
                    unprotectedHeader = coseSign1.unprotected;
                    payload = coseSign1.payload;
                    signature = coseSign1.signature;
                    console.log('🔓 COSE structure is object format (legacy)');
                }
                
                // 3. Verify signature (if key provided)
                if (trustedSenderPubKey && signature && signature.length > 0) {
                    const toVerify = cbor.encode([protectedHeader, unprotectedHeader, payload]);
                    const isValid = await crypto.subtle.verify(
                        { name: 'ECDSA', hash: 'SHA-384' },
                        trustedSenderPubKey,
                        signature,
                        toVerify
                    );
                    
                    if (!isValid) {
                        console.warn('⚠️ Signature verification failed');
                        continue;
                    }
                    console.log('✅ Signature verified');
                }
                
                // 4. Decrypt payload
                let inner;
                if (payload instanceof Uint8Array) {
                    // Payload is still encoded
                    const innerArrayBuffer = payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength);
                    inner = cbor.decode(innerArrayBuffer);
                } else {
                    // Payload is already decoded
                    inner = payload;
                }
                console.log('🔓 Inner payload type:', typeof inner, inner.constructor.name);
                console.log('🔓 Inner payload keys:', Object.keys(inner));
                console.log('🔓 Inner payload full object:', inner);
                
                let payloadObj;
                
                if (inner.ciphertext && recipientEcdhPrivKey) {
                    console.log('🔓 Decrypting encrypted payload...');
                    
                    // Get ephemeral public key
                    const epkRaw = inner.unprotected?.epk || inner.epk;
                    
                    // Import ephemeral public key
                    const ephemeralPub = await crypto.subtle.importKey(
                        'raw',
                        epkRaw,
                        { name: 'ECDH', namedCurve: 'P-384' },
                        true,
                        []
                    );
                    
                    // Derive shared secret
                    const sharedBits = await crypto.subtle.deriveBits(
                        { name: 'ECDH', public: ephemeralPub },
                        recipientEcdhPrivKey,
                        384
                    );
                    
                    // HKDF-SHA384 -> AES key
                    const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
                    const cek = await crypto.subtle.deriveKey(
                        {
                            name: 'HKDF',
                            hash: 'SHA-384',
                            salt: new Uint8Array(0),
                            info: new TextEncoder().encode('SecureBit QR ECDH AES key')
                        },
                        hkdfKey,
                        { name: 'AES-GCM', length: 256 },
                        true,
                        ['decrypt']
                    );
                    
                    // Decrypt
                    const plaintext = await crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv: inner.iv },
                        cek,
                        inner.ciphertext
                    );
                    
                    const payloadJson = new TextDecoder().decode(plaintext);
                    payloadObj = JSON.parse(payloadJson);
                    
                } else if (inner.plaintext) {
                    console.log('🔓 Processing plaintext payload...');
                    // Broadcast mode
                    payloadObj = JSON.parse(new TextDecoder().decode(inner.plaintext));
                } else if (Object.keys(inner).length === 0) {
                    console.log('🔓 Empty inner payload, using alternative approach...');
                    
                    // Alternative: try to use the original assembled body
                    try {
                        const originalBody = encoded.body || encoded;
                        console.log('🔓 Trying to decode original body:', originalBody.substring(0, 50) + '...');
                        
                        // Decode base64url -> decompress -> CBOR decode -> extract JSON
                        const compressed = fromBase64Url(originalBody);
                        const decompressed = pako.inflate(compressed);
                        console.log('🔓 Decompressed length:', decompressed.length);
                        
                        // Convert to ArrayBuffer for CBOR decoding
                        const decompressedArrayBuffer = decompressed.buffer.slice(decompressed.byteOffset, decompressed.byteOffset + decompressed.byteLength);
                        const cborDecoded = cbor.decode(decompressedArrayBuffer);
                        console.log('🔓 CBOR decoded structure:', cborDecoded);
                        
                        // Handle both array and object formats
                        let payload;
                        if (Array.isArray(cborDecoded)) {
                            // Array format: [protected, unprotected, payload, signature]
                            console.log('🔓 Alternative: COSE structure is array format');
                            console.log('🔓 Array length:', cborDecoded.length);
                            console.log('🔓 Array elements:', cborDecoded.map((el, i) => `${i}: ${typeof el} ${el.constructor.name}`));
                            
                            // Payload is at index 2
                            payload = cborDecoded[2];
                            console.log('🔓 Payload at index 2:', payload);
                        } else {
                            // Object format (legacy)
                            payload = cborDecoded.payload;
                            console.log('🔓 Alternative: COSE structure is object format (legacy)');
                        }
                        
                        // Extract the actual payload from CBOR structure
                        if (payload && payload instanceof Uint8Array) {
                            const payloadArrayBuffer = payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength);
                            const innerCbor = cbor.decode(payloadArrayBuffer);
                            console.log('🔓 Inner CBOR structure:', innerCbor);
                            
                            if (innerCbor.plaintext) {
                                const jsonString = new TextDecoder().decode(innerCbor.plaintext);
                                payloadObj = JSON.parse(jsonString);
                                console.log('🔓 Successfully decoded via alternative approach');
                                console.log('🔓 Alternative payloadObj:', payloadObj);
                            } else {
                                console.error('❌ No plaintext found in inner CBOR structure');
                                continue;
                            }
                        } else if (payload && typeof payload === 'object' && Object.keys(payload).length > 0) {
                            // Payload is already a decoded object
                            console.log('🔓 Payload is already decoded object:', payload);
                            if (payload.plaintext) {
                                const jsonString = new TextDecoder().decode(payload.plaintext);
                                payloadObj = JSON.parse(jsonString);
                                console.log('🔓 Successfully decoded from payload object');
                                console.log('🔓 Alternative payloadObj:', payloadObj);
                            } else {
                                console.error('❌ No plaintext found in payload object');
                                continue;
                            }
                        } else {
                            console.error('❌ No payload found in CBOR structure');
                            console.log('🔓 CBOR structure keys:', Object.keys(cborDecoded));
                            console.log('🔓 Payload type:', typeof payload);
                            console.log('🔓 Payload value:', payload);
                            continue;
                        }
                    } catch (altError) {
                        console.error('❌ Alternative approach failed:', altError);
                        continue;
                    }
                } else {
                    console.warn('⚠️ Unknown payload format:', inner);
                    continue;
                }
                
                results.push({
                    payloadObj,
                    senderVerified: !!trustedSenderPubKey,
                    encrypted: !!inner.ciphertext
                });
                
            } catch (packError) {
                console.error('❌ Error processing packet:', packError);
                continue;
            }
        }
        
        console.log(`✅ Successfully processed ${results.length} payload(s)`);
        return results;
        
    } catch (error) {
        console.error('❌ Error in receiveAndProcess:', error);
        throw error;
    }
}

/**
 * Assemble QR chunks into complete packets
 * @param {Array<string>} qrStrings - Array of QR code strings
 * @returns {Array<Object>} Array of assembled packets
 */
async function assembleFromQrStrings(qrStrings) {
    const packets = new Map();
    
    console.log('🔧 Starting assembly of QR strings...');
    
    for (const qrString of qrStrings) {
        try {
            console.log('🔧 Parsing QR string:', qrString.substring(0, 100) + '...');
            const parsed = JSON.parse(qrString);
            console.log('🔧 Parsed structure:', parsed);
            
            if (parsed.hdr && parsed.body) {
                const id = parsed.hdr.id;
                console.log(`🔧 Processing packet ID: ${id}, seq: ${parsed.hdr.seq}, total: ${parsed.hdr.total}`);
                
                if (!packets.has(id)) {
                    packets.set(id, {
                        id: id,
                        chunks: new Map(),
                        total: parsed.hdr.total
                    });
                    console.log(`🔧 Created new packet for ID: ${id}`);
                }
                
                const packet = packets.get(id);
                packet.chunks.set(parsed.hdr.seq, parsed.body);
                console.log(`🔧 Added chunk ${parsed.hdr.seq} to packet ${id}. Current chunks: ${packet.chunks.size}/${packet.total}`);
                
                // Check if complete
                if (packet.chunks.size === packet.total) {
                    console.log(`🔧 Packet ${id} is complete! Assembling body...`);
                    // Assemble body
                    let assembledBody = '';
                    for (let i = 1; i <= packet.total; i++) {
                        assembledBody += packet.chunks.get(i);
                    }
                    
                    packet.jsonObj = { body: assembledBody };
                    packet.complete = true;
                    console.log(`🔧 Assembled body length: ${assembledBody.length} characters`);
                }
            } else {
                console.warn('⚠️ QR string missing hdr or body:', parsed);
            }
        } catch (error) {
            console.warn('⚠️ Failed to parse QR string:', error);
            continue;
        }
    }
    
    // Return only complete packets
    const completePackets = Array.from(packets.values()).filter(p => p.complete);
    console.log(`🔧 Assembly complete. Found ${completePackets.length} complete packets`);
    return completePackets;
}

// Export for global use
window.packSecurePayload = packSecurePayload;
window.receiveAndProcess = receiveAndProcess;
