import { useState, useEffect, useCallback, useRef } from 'react';
import { getCryptoBridge } from './crypto-bridge.js';

export function useCrypto() {
    const [isReady, setIsReady] = useState(false);
    const [error, setError] = useState(null);
    const cryptoBridge = useRef(getCryptoBridge());

    useEffect(() => {
        const initializeCrypto = async () => {
            try {
                const success = await cryptoBridge.current.initialize();
                if (success) {
                    setIsReady(true);
                    setError(null);
                } else {
                    setError('Failed to initialize crypto module');
                }
            } catch (err) {
                setError(err.message);
            }
        };

        initializeCrypto();
    }, []);

    const encryptData = useCallback(async (data, password) => {
        if (!isReady) throw new Error('Crypto not ready');
        return await cryptoBridge.current.encryptData(data, password);
    }, [isReady]);

    const decryptData = useCallback(async (encryptedData, password) => {
        if (!isReady) throw new Error('Crypto not ready');
        return await cryptoBridge.current.decryptData(encryptedData, password);
    }, [isReady]);

    const generateKeyPair = useCallback(async () => {
        if (!isReady) throw new Error('Crypto not ready');
        return await cryptoBridge.current.generateECDSAKeyPair();
    }, [isReady]);

    const generatePassword = useCallback(() => {
        if (!isReady) throw new Error('Crypto not ready');
        return cryptoBridge.current.generateSecurePassword();
    }, [isReady]);

    const sanitizeMessage = useCallback((message) => {
        if (!isReady) throw new Error('Crypto not ready');
        return cryptoBridge.current.sanitizeMessage(message);
    }, [isReady]);

    return {
        isReady,
        error,
        encryptData,
        decryptData,
        generateKeyPair,
        generatePassword,
        sanitizeMessage,
        cryptoBridge: cryptoBridge.current
    };
}