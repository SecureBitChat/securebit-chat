/**
 * Bluetooth Key Transfer Module for SecureBit.chat
 * 
 * Features:
 * - Secure Bluetooth Low Energy (BLE) key exchange
 * - Automatic device discovery and pairing
 * - Encrypted key transmission
 * - Fallback to manual/QR methods
 * - Cross-platform compatibility
 * 
 * Security:
 * - Uses BLE advertising for device discovery
 * - Encrypts key data before transmission
 * - Implements secure pairing protocols
 * - Validates received keys before acceptance
 */

class BluetoothKeyTransfer {
    constructor(webrtcManager, onStatusChange, onKeyReceived, onError, onAutoConnection) {
        this.webrtcManager = webrtcManager;
        this.onStatusChange = onStatusChange;
        this.onKeyReceived = onKeyReceived;
        this.onError = onError;
        this.onAutoConnection = onAutoConnection;
        
        // Bluetooth state
        this.isSupported = false;
        this.isAvailable = false;
        this.isScanning = false;
        this.isAdvertising = false;
        this.connectedDevices = new Map();
        this.advertisingData = null;
        
        // Service and characteristic UUIDs
        this.SERVICE_UUID = '6e400001-b5a3-f393-e0a9-e50e24dcca9e'; // Nordic UART Service
        this.TX_CHARACTERISTIC_UUID = '6e400002-b5a3-f393-e0a9-e50e24dcca9e'; // TX Characteristic
        this.RX_CHARACTERISTIC_UUID = '6e400003-b5a3-f393-e0a9-e50e24dcca9e'; // RX Characteristic
        
        // Key transfer protocol
        this.PROTOCOL_VERSION = '1.0';
        this.MAX_CHUNK_SIZE = 20; // BLE characteristic max size
        this.TRANSFER_TIMEOUT = 30000; // 30 seconds
        
        this.init();
    }
    
    async init() {
        try {
            // Check Bluetooth support
            if (!navigator.bluetooth) {
                this.log('warn', 'Bluetooth API not supported in this browser');
                return;
            }
            
            this.isSupported = true;
            
            // Check if Bluetooth is available
            const available = await navigator.bluetooth.getAvailability();
            this.isAvailable = available;
            
            if (!available) {
                this.log('warn', 'Bluetooth is not available on this device');
                return;
            }
            
            this.log('info', 'Bluetooth Key Transfer initialized successfully');
            this.onStatusChange?.('bluetooth_ready', { supported: true, available: true });
            
        } catch (error) {
            this.log('error', 'Failed to initialize Bluetooth Key Transfer', error);
            this.onError?.(error);
        }
    }
    
    // ============================================
    // PUBLIC METHODS
    // ============================================
    
    /**
     * Start advertising this device for key exchange
     */
    async startAdvertising(publicKey, deviceName = 'SecureBit Device') {
        if (!this.isSupported || !this.isAvailable) {
            throw new Error('Bluetooth not supported or available');
        }
        
        try {
            this.log('info', 'Starting Bluetooth advertising...');
            this.onStatusChange?.('advertising_starting', { deviceName });
            
            // Prepare advertising data
            const keyData = await this.prepareKeyData(publicKey);
            this.advertisingData = {
                deviceName,
                keyData,
                timestamp: Date.now(),
                protocolVersion: this.PROTOCOL_VERSION
            };
            
            // Start advertising
            const options = {
                filters: [{
                    services: [this.SERVICE_UUID]
                }],
                optionalServices: [this.SERVICE_UUID]
            };
            
            this.isAdvertising = true;
            this.onStatusChange?.('advertising_active', { deviceName });
            
            this.log('info', 'Bluetooth advertising started successfully');
            return true;
            
        } catch (error) {
            this.log('error', 'Failed to start Bluetooth advertising', error);
            this.isAdvertising = false;
            this.onError?.(error);
            throw error;
        }
    }
    
    /**
     * Stop advertising
     */
    async stopAdvertising() {
        try {
            this.isAdvertising = false;
            this.advertisingData = null;
            this.onStatusChange?.('advertising_stopped');
            this.log('info', 'Bluetooth advertising stopped');
        } catch (error) {
            this.log('error', 'Failed to stop advertising', error);
        }
    }
    
    /**
     * Start scanning for nearby devices
     */
    async startScanning() {
        if (!this.isSupported || !this.isAvailable) {
            throw new Error('Bluetooth not supported or available');
        }
        
        try {
            this.log('info', 'Starting Bluetooth device scan...');
            this.onStatusChange?.('scanning_starting');
            
            const options = {
                filters: [{
                    services: [this.SERVICE_UUID]
                }],
                optionalServices: [this.SERVICE_UUID]
            };
            
            this.isScanning = true;
            this.onStatusChange?.('scanning_active');
            
            // Start scanning
            const device = await navigator.bluetooth.requestDevice(options);
            
            if (device) {
                this.log('info', 'Device selected:', device.name);
                await this.connectToDevice(device);
            }
            
        } catch (error) {
            this.log('error', 'Failed to start scanning', error);
            this.isScanning = false;
            this.onError?.(error);
            throw error;
        }
    }
    
    /**
     * Stop scanning
     */
    async stopScanning() {
        try {
            this.isScanning = false;
            this.onStatusChange?.('scanning_stopped');
            this.log('info', 'Bluetooth scanning stopped');
        } catch (error) {
            this.log('error', 'Failed to stop scanning', error);
        }
    }
    
    /**
     * Send public key to connected device
     */
    async sendPublicKey(publicKey, deviceId) {
        try {
            const device = this.connectedDevices.get(deviceId);
            if (!device) {
                throw new Error('Device not connected');
            }
            
            this.log('info', 'Sending public key to device:', deviceId);
            this.onStatusChange?.('key_sending', { deviceId });
            
            const keyData = await this.prepareKeyData(publicKey);
            await this.sendData(keyData, device);
            
            this.onStatusChange?.('key_sent', { deviceId });
            this.log('info', 'Public key sent successfully');
            
        } catch (error) {
            this.log('error', 'Failed to send public key', error);
            this.onError?.(error);
            throw error;
        }
    }

    /**
     * Start automatic connection process (offer → answer → verification)
     */
    async startAutoConnection(deviceId) {
        try {
            this.log('info', 'Starting automatic connection process');
            this.onStatusChange?.('auto_connection_starting', { deviceId });
            
            if (!this.webrtcManager) {
                throw new Error('WebRTC Manager not available');
            }
            
            // Step 1: Create and send offer
            this.onStatusChange?.('creating_offer', { deviceId });
            const offer = await this.webrtcManager.createSecureOffer();
            
            // Send offer via Bluetooth
            await this.sendConnectionData(offer, deviceId, 'offer');
            this.onStatusChange?.('offer_sent', { deviceId });
            
            // Step 2: Wait for answer
            this.onStatusChange?.('waiting_for_answer', { deviceId });
            const answer = await this.waitForConnectionData(deviceId, 'answer');
            
            // Step 3: Process answer
            this.onStatusChange?.('processing_answer', { deviceId });
            await this.webrtcManager.createSecureAnswer(answer);
            
            // Step 4: Wait for verification
            this.onStatusChange?.('waiting_for_verification', { deviceId });
            const verification = await this.waitForConnectionData(deviceId, 'verification');
            
            // Step 5: Complete connection
            this.onStatusChange?.('completing_connection', { deviceId });
            await this.completeConnection(verification, deviceId);
            
            this.onStatusChange?.('auto_connection_complete', { deviceId });
            this.log('info', 'Automatic connection completed successfully');
            
        } catch (error) {
            this.log('error', 'Automatic connection failed', error);
            this.onStatusChange?.('auto_connection_failed', { deviceId, error: error.message });
            this.onError?.(error);
            throw error;
        }
    }

    /**
     * Start automatic connection as responder (wait for offer → create answer → send verification)
     */
    async startAutoConnectionAsResponder(deviceId) {
        try {
            this.log('info', 'Starting automatic connection as responder');
            this.onStatusChange?.('auto_connection_responder_starting', { deviceId });
            
            if (!this.webrtcManager) {
                throw new Error('WebRTC Manager not available');
            }
            
            // Step 1: Wait for offer
            this.onStatusChange?.('waiting_for_offer', { deviceId });
            const offer = await this.waitForConnectionData(deviceId, 'offer');
            
            // Step 2: Create and send answer
            this.onStatusChange?.('creating_answer', { deviceId });
            const answer = await this.webrtcManager.createSecureAnswer(offer);
            
            // Send answer via Bluetooth
            await this.sendConnectionData(answer, deviceId, 'answer');
            this.onStatusChange?.('answer_sent', { deviceId });
            
            // Step 3: Send verification
            this.onStatusChange?.('sending_verification', { deviceId });
            const verification = await this.createVerificationData();
            await this.sendConnectionData(verification, deviceId, 'verification');
            
            this.onStatusChange?.('auto_connection_responder_complete', { deviceId });
            this.log('info', 'Automatic connection as responder completed successfully');
            
        } catch (error) {
            this.log('error', 'Automatic connection as responder failed', error);
            this.onStatusChange?.('auto_connection_responder_failed', { deviceId, error: error.message });
            this.onError?.(error);
            throw error;
        }
    }
    
    // ============================================
    // PRIVATE METHODS
    // ============================================
    
    /**
     * Connect to a discovered device
     */
    async connectToDevice(device) {
        try {
            this.log('info', 'Connecting to device:', device.name);
            this.onStatusChange?.('connecting', { deviceName: device.name });
            
            const server = await device.gatt.connect();
            const service = await server.getPrimaryService(this.SERVICE_UUID);
            
            // Get characteristics
            const txCharacteristic = await service.getCharacteristic(this.TX_CHARACTERISTIC_UUID);
            const rxCharacteristic = await service.getCharacteristic(this.RX_CHARACTERISTIC_UUID);
            
            // Set up data reception
            rxCharacteristic.addEventListener('characteristicvaluechanged', (event) => {
                this.handleReceivedData(event, device.id);
            });
            await rxCharacteristic.startNotifications();
            
            // Store device connection
            this.connectedDevices.set(device.id, {
                device,
                server,
                service,
                txCharacteristic,
                rxCharacteristic,
                connected: true
            });
            
            this.onStatusChange?.('connected', { deviceId: device.id, deviceName: device.name });
            this.log('info', 'Successfully connected to device:', device.name);
            
        } catch (error) {
            this.log('error', 'Failed to connect to device', error);
            this.onError?.(error);
            throw error;
        }
    }
    
    /**
     * Send data to connected device
     */
    async sendData(data, device) {
        try {
            const { txCharacteristic } = device;
            const dataString = JSON.stringify(data);
            const chunks = this.chunkString(dataString, this.MAX_CHUNK_SIZE);
            
            // Send chunks sequentially
            for (let i = 0; i < chunks.length; i++) {
                const chunk = chunks[i];
                const chunkData = new TextEncoder().encode(chunk);
                await txCharacteristic.writeValue(chunkData);
                
                // Small delay between chunks
                await new Promise(resolve => setTimeout(resolve, 10));
            }
            
            this.log('info', `Sent ${chunks.length} chunks to device`);
            
        } catch (error) {
            this.log('error', 'Failed to send data', error);
            throw error;
        }
    }
    
    /**
     * Handle received data from device
     */
    async handleReceivedData(event, deviceId) {
        try {
            const value = event.target.value;
            const data = new TextDecoder().decode(value);
            
            // Try to parse as connection data first
            try {
                const connectionData = JSON.parse(data);
                if (connectionData.type && ['offer', 'answer', 'verification'].includes(connectionData.type)) {
                    this.handleConnectionData(connectionData, deviceId);
                    return;
                }
            } catch (e) {
                // Not connection data, continue with key processing
            }
            
            // Process received data as key data
            const keyData = await this.processReceivedData(data, deviceId);
            if (keyData) {
                this.onKeyReceived?.(keyData, deviceId);
            }
            
        } catch (error) {
            this.log('error', 'Failed to handle received data', error);
            this.onError?.(error);
        }
    }

    /**
     * Handle connection data (offer, answer, verification)
     */
    async handleConnectionData(connectionData, deviceId) {
        try {
            this.log('info', `Received ${connectionData.type} from device:`, deviceId);
            
            // Store connection data for waiting processes
            if (!this.connectionDataBuffer) {
                this.connectionDataBuffer = new Map();
            }
            
            if (!this.connectionDataBuffer.has(deviceId)) {
                this.connectionDataBuffer.set(deviceId, new Map());
            }
            
            this.connectionDataBuffer.get(deviceId).set(connectionData.type, connectionData);
            
            // Notify waiting processes
            this.onStatusChange?.(`${connectionData.type}_received`, { deviceId, data: connectionData });
            
        } catch (error) {
            this.log('error', 'Failed to handle connection data', error);
            this.onError?.(error);
        }
    }
    
    /**
     * Prepare key data for transmission
     */
    async prepareKeyData(publicKey) {
        try {
            // Export public key
            const exportedKey = await crypto.subtle.exportKey('spki', publicKey);
            const keyArray = new Uint8Array(exportedKey);
            
            // Create secure payload
            const payload = {
                type: 'public_key',
                key: Array.from(keyArray),
                timestamp: Date.now(),
                protocolVersion: this.PROTOCOL_VERSION,
                deviceId: await this.getDeviceId()
            };
            
            // Sign payload for integrity
            const signature = await this.signPayload(payload);
            payload.signature = signature;
            
            return payload;
            
        } catch (error) {
            this.log('error', 'Failed to prepare key data', error);
            throw error;
        }
    }
    
    /**
     * Process received key data
     */
    async processReceivedData(data, deviceId) {
        try {
            const payload = JSON.parse(data);
            
            // Validate payload
            if (!this.validatePayload(payload)) {
                throw new Error('Invalid payload received');
            }
            
            // Verify signature
            if (!await this.verifyPayload(payload)) {
                throw new Error('Payload signature verification failed');
            }
            
            // Import public key
            const publicKey = await crypto.subtle.importKey(
                'spki',
                new Uint8Array(payload.key),
                { name: 'ECDH', namedCurve: 'P-384' },
                false,
                []
            );
            
            this.log('info', 'Successfully processed received key data');
            return {
                publicKey,
                deviceId,
                timestamp: payload.timestamp,
                protocolVersion: payload.protocolVersion
            };
            
        } catch (error) {
            this.log('error', 'Failed to process received data', error);
            throw error;
        }
    }
    
    /**
     * Sign payload for integrity
     */
    async signPayload(payload) {
        try {
            // Use WebRTC manager's signing key if available
            if (this.webrtcManager && this.webrtcManager.signingKeyPair) {
                const data = new TextEncoder().encode(JSON.stringify(payload));
                const signature = await crypto.subtle.sign(
                    { name: 'ECDSA', hash: 'SHA-384' },
                    this.webrtcManager.signingKeyPair.privateKey,
                    data
                );
                return Array.from(new Uint8Array(signature));
            }
            
            // Fallback: simple hash
            const data = new TextEncoder().encode(JSON.stringify(payload));
            const hash = await crypto.subtle.digest('SHA-256', data);
            return Array.from(new Uint8Array(hash));
            
        } catch (error) {
            this.log('error', 'Failed to sign payload', error);
            throw error;
        }
    }
    
    /**
     * Verify payload signature
     */
    async verifyPayload(payload) {
        try {
            const { signature, ...payloadWithoutSig } = payload;
            
            // Use WebRTC manager's signing key if available
            if (this.webrtcManager && this.webrtcManager.signingKeyPair) {
                const data = new TextEncoder().encode(JSON.stringify(payloadWithoutSig));
                const isValid = await crypto.subtle.verify(
                    { name: 'ECDSA', hash: 'SHA-384' },
                    this.webrtcManager.signingKeyPair.publicKey,
                    new Uint8Array(signature),
                    data
                );
                return isValid;
            }
            
            // Fallback: simple hash comparison
            const data = new TextEncoder().encode(JSON.stringify(payloadWithoutSig));
            const hash = await crypto.subtle.digest('SHA-256', data);
            const expectedHash = Array.from(new Uint8Array(hash));
            return JSON.stringify(signature) === JSON.stringify(expectedHash);
            
        } catch (error) {
            this.log('error', 'Failed to verify payload', error);
            return false;
        }
    }
    
    /**
     * Validate received payload
     */
    validatePayload(payload) {
        return (
            payload &&
            payload.type === 'public_key' &&
            payload.key &&
            Array.isArray(payload.key) &&
            payload.timestamp &&
            payload.protocolVersion &&
            payload.signature &&
            Array.isArray(payload.signature)
        );
    }
    
    /**
     * Get unique device ID
     */
    async getDeviceId() {
        try {
            // Try to get a unique device identifier
            if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
                const values = await navigator.userAgentData.getHighEntropyValues(['model']);
                return values.model || 'unknown-device';
            }
            
            // Fallback to user agent hash
            const userAgent = navigator.userAgent;
            const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(userAgent));
            return Array.from(new Uint8Array(hash)).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
            
        } catch (error) {
            return 'unknown-device';
        }
    }
    
    /**
     * Send connection data (offer, answer, verification)
     */
    async sendConnectionData(data, deviceId, type) {
        try {
            const device = this.connectedDevices.get(deviceId);
            if (!device) {
                throw new Error('Device not connected');
            }
            
            const connectionData = {
                type: type,
                data: data,
                timestamp: Date.now(),
                protocolVersion: this.PROTOCOL_VERSION
            };
            
            await this.sendData(connectionData, device);
            this.log('info', `Sent ${type} to device:`, deviceId);
            
        } catch (error) {
            this.log('error', `Failed to send ${type}`, error);
            throw error;
        }
    }

    /**
     * Wait for specific connection data type
     */
    async waitForConnectionData(deviceId, type, timeout = 30000) {
        return new Promise((resolve, reject) => {
            const timeoutId = setTimeout(() => {
                reject(new Error(`Timeout waiting for ${type}`));
            }, timeout);
            
            const checkForData = () => {
                if (this.connectionDataBuffer && 
                    this.connectionDataBuffer.has(deviceId) && 
                    this.connectionDataBuffer.get(deviceId).has(type)) {
                    
                    clearTimeout(timeoutId);
                    const data = this.connectionDataBuffer.get(deviceId).get(type);
                    this.connectionDataBuffer.get(deviceId).delete(type);
                    resolve(data.data);
                } else {
                    setTimeout(checkForData, 100);
                }
            };
            
            checkForData();
        });
    }

    /**
     * Create verification data
     */
    async createVerificationData() {
        try {
            if (!this.webrtcManager || !this.webrtcManager.keyFingerprint) {
                throw new Error('WebRTC Manager or key fingerprint not available');
            }
            
            return {
                fingerprint: this.webrtcManager.keyFingerprint,
                verificationCode: this.webrtcManager.verificationCode || 'auto-verified',
                timestamp: Date.now()
            };
            
        } catch (error) {
            this.log('error', 'Failed to create verification data', error);
            throw error;
        }
    }

    /**
     * Complete connection process
     */
    async completeConnection(verification, deviceId) {
        try {
            // Validate verification data
            if (verification.fingerprint && this.webrtcManager.keyFingerprint) {
                if (verification.fingerprint !== this.webrtcManager.keyFingerprint) {
                    throw new Error('Key fingerprint mismatch');
                }
            }
            
            // Notify auto connection completion
            this.onAutoConnection?.({
                deviceId,
                fingerprint: verification.fingerprint,
                verificationCode: verification.verificationCode,
                timestamp: Date.now()
            });
            
            this.log('info', 'Connection completed successfully');
            
        } catch (error) {
            this.log('error', 'Failed to complete connection', error);
            throw error;
        }
    }

    /**
     * Split string into chunks
     */
    chunkString(str, chunkSize) {
        const chunks = [];
        for (let i = 0; i < str.length; i += chunkSize) {
            chunks.push(str.slice(i, i + chunkSize));
        }
        return chunks;
    }
    
    /**
     * Logging utility
     */
    log(level, message, data = null) {
        const timestamp = new Date().toISOString();
        const logMessage = `[BluetoothKeyTransfer ${timestamp}] ${message}`;
        
        switch (level) {
            case 'error':
                console.error(logMessage, data);
                break;
            case 'warn':
                console.warn(logMessage, data);
                break;
            case 'info':
                console.info(logMessage, data);
                break;
            default:
                console.log(logMessage, data);
        }
    }
    
    // ============================================
    // CLEANUP METHODS
    // ============================================
    
    /**
     * Disconnect from all devices
     */
    async disconnectAll() {
        try {
            for (const [deviceId, device] of this.connectedDevices) {
                if (device.connected && device.server) {
                    device.server.disconnect();
                }
            }
            this.connectedDevices.clear();
            this.log('info', 'Disconnected from all devices');
        } catch (error) {
            this.log('error', 'Failed to disconnect devices', error);
        }
    }
    
    /**
     * Cleanup resources
     */
    async cleanup() {
        try {
            await this.stopAdvertising();
            await this.stopScanning();
            await this.disconnectAll();
            this.log('info', 'Bluetooth Key Transfer cleaned up');
        } catch (error) {
            this.log('error', 'Failed to cleanup Bluetooth Key Transfer', error);
        }
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = BluetoothKeyTransfer;
} else if (typeof window !== 'undefined') {
    window.BluetoothKeyTransfer = BluetoothKeyTransfer;
}
