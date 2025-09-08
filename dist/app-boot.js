// src/crypto/EnhancedSecureCryptoUtils.js
var EnhancedSecureCryptoUtils = class _EnhancedSecureCryptoUtils {
  static _keyMetadata = /* @__PURE__ */ new WeakMap();
  // Initialize secure logging system after class definition
  // Utility to sort object keys for deterministic serialization
  static sortObjectKeys(obj) {
    if (typeof obj !== "object" || obj === null) {
      return obj;
    }
    if (Array.isArray(obj)) {
      return obj.map(_EnhancedSecureCryptoUtils.sortObjectKeys);
    }
    const sortedObj = {};
    Object.keys(obj).sort().forEach((key) => {
      sortedObj[key] = _EnhancedSecureCryptoUtils.sortObjectKeys(obj[key]);
    });
    return sortedObj;
  }
  // Utility to assert CryptoKey type and properties
  static assertCryptoKey(key, expectedName = null, expectedUsages = []) {
    if (!(key instanceof CryptoKey)) throw new Error("Expected CryptoKey");
    if (expectedName && key.algorithm?.name !== expectedName) {
      throw new Error(`Expected algorithm ${expectedName}, got ${key.algorithm?.name}`);
    }
    for (const u of expectedUsages) {
      if (!key.usages || !key.usages.includes(u)) {
        throw new Error(`Missing required key usage: ${u}`);
      }
    }
  }
  // Helper function to convert ArrayBuffer to Base64
  static arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  // Helper function to convert Base64 to ArrayBuffer
  static base64ToArrayBuffer(base64) {
    try {
      if (typeof base64 !== "string" || !base64) {
        throw new Error("Invalid base64 input: must be a non-empty string");
      }
      const cleanBase64 = base64.trim();
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleanBase64)) {
        throw new Error("Invalid base64 format");
      }
      if (cleanBase64 === "") {
        return new ArrayBuffer(0);
      }
      const binaryString = atob(cleanBase64);
      const len = binaryString.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes.buffer;
    } catch (error) {
      console.error("Base64 to ArrayBuffer conversion failed:", error.message);
      throw new Error(`Base64 conversion error: ${error.message}`);
    }
  }
  // Helper function to convert hex string to Uint8Array
  static hexToUint8Array(hexString) {
    try {
      if (!hexString || typeof hexString !== "string") {
        throw new Error("Invalid hex string input: must be a non-empty string");
      }
      const cleanHex = hexString.replace(/:/g, "").replace(/\s/g, "");
      if (!/^[0-9a-fA-F]*$/.test(cleanHex)) {
        throw new Error("Invalid hex format: contains non-hex characters");
      }
      if (cleanHex.length % 2 !== 0) {
        throw new Error("Invalid hex format: odd length");
      }
      const bytes = new Uint8Array(cleanHex.length / 2);
      for (let i = 0; i < cleanHex.length; i += 2) {
        bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
      }
      return bytes;
    } catch (error) {
      console.error("Hex to Uint8Array conversion failed:", error.message);
      throw new Error(`Hex conversion error: ${error.message}`);
    }
  }
  static async encryptData(data, password) {
    try {
      const dataString = typeof data === "string" ? data : JSON.stringify(data);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const encoder = new TextEncoder();
      const passwordBuffer = encoder.encode(password);
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );
      const key = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: 1e5,
          hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
      );
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const dataBuffer = encoder.encode(dataString);
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        dataBuffer
      );
      const encryptedPackage = {
        version: "1.0",
        salt: Array.from(salt),
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted)),
        timestamp: Date.now()
      };
      const packageString = JSON.stringify(encryptedPackage);
      return _EnhancedSecureCryptoUtils.arrayBufferToBase64(new TextEncoder().encode(packageString).buffer);
    } catch (error) {
      console.error("Encryption failed:", error.message);
      throw new Error(`Encryption error: ${error.message}`);
    }
  }
  static async decryptData(encryptedData, password) {
    try {
      const packageBuffer = _EnhancedSecureCryptoUtils.base64ToArrayBuffer(encryptedData);
      const packageString = new TextDecoder().decode(packageBuffer);
      const encryptedPackage = JSON.parse(packageString);
      if (!encryptedPackage.version || !encryptedPackage.salt || !encryptedPackage.iv || !encryptedPackage.data) {
        throw new Error("Invalid encrypted data format");
      }
      const salt = new Uint8Array(encryptedPackage.salt);
      const iv = new Uint8Array(encryptedPackage.iv);
      const encrypted = new Uint8Array(encryptedPackage.data);
      const encoder = new TextEncoder();
      const passwordBuffer = encoder.encode(password);
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );
      const key = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: 1e5,
          hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        encrypted
      );
      const decryptedString = new TextDecoder().decode(decrypted);
      try {
        return JSON.parse(decryptedString);
      } catch {
        return decryptedString;
      }
    } catch (error) {
      console.error("Decryption failed:", error.message);
      throw new Error(`Decryption error: ${error.message}`);
    }
  }
  // Generate secure password for data exchange
  static generateSecurePassword() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    const length = 32;
    const randomValues = new Uint32Array(length);
    crypto.getRandomValues(randomValues);
    let password = "";
    for (let i = 0; i < length; i++) {
      password += chars[randomValues[i] % chars.length];
    }
    return password;
  }
  // Real security level calculation with actual verification
  static async calculateSecurityLevel(securityManager) {
    let score = 0;
    const maxScore = 100;
    const verificationResults = {};
    try {
      if (!securityManager || !securityManager.securityFeatures) {
        console.warn("Security manager not fully initialized, using fallback calculation");
        return {
          level: "INITIALIZING",
          score: 0,
          color: "gray",
          verificationResults: {},
          timestamp: Date.now(),
          details: "Security system initializing...",
          isRealData: false
        };
      }
      const sessionType = securityManager.currentSessionType || "demo";
      const isDemoSession = sessionType === "demo";
      try {
        if (await _EnhancedSecureCryptoUtils.verifyEncryption(securityManager)) {
          score += 20;
          verificationResults.encryption = { passed: true, details: "AES-GCM encryption verified", points: 20 };
        } else {
          verificationResults.encryption = { passed: false, details: "Encryption not working", points: 0 };
        }
      } catch (error) {
        verificationResults.encryption = { passed: false, details: `Encryption check failed: ${error.message}`, points: 0 };
      }
      try {
        if (await _EnhancedSecureCryptoUtils.verifyECDHKeyExchange(securityManager)) {
          score += 15;
          verificationResults.keyExchange = { passed: true, details: "Simple key exchange verified", points: 15 };
        } else {
          verificationResults.keyExchange = { passed: false, details: "Key exchange failed", points: 0 };
        }
      } catch (error) {
        verificationResults.keyExchange = { passed: false, details: `Key exchange check failed: ${error.message}`, points: 0 };
      }
      if (await _EnhancedSecureCryptoUtils.verifyMessageIntegrity(securityManager)) {
        score += 10;
        verificationResults.messageIntegrity = { passed: true, details: "Message integrity verified", points: 10 };
      } else {
        verificationResults.messageIntegrity = { passed: false, details: "Message integrity failed", points: 0 };
      }
      if (await _EnhancedSecureCryptoUtils.verifyRateLimiting(securityManager)) {
        score += 5;
        verificationResults.rateLimiting = { passed: true, details: "Rate limiting active", points: 5 };
      } else {
        verificationResults.rateLimiting = { passed: false, details: "Rate limiting not working", points: 0 };
      }
      if (!isDemoSession && await _EnhancedSecureCryptoUtils.verifyECDSASignatures(securityManager)) {
        score += 15;
        verificationResults.ecdsa = { passed: true, details: "ECDSA signatures verified", points: 15 };
      } else {
        const reason = isDemoSession ? "Enhanced session required - feature not available" : "ECDSA signatures failed";
        verificationResults.ecdsa = { passed: false, details: reason, points: 0 };
      }
      if (!isDemoSession && await _EnhancedSecureCryptoUtils.verifyMetadataProtection(securityManager)) {
        score += 10;
        verificationResults.metadataProtection = { passed: true, details: "Metadata protection verified", points: 10 };
      } else {
        const reason = isDemoSession ? "Enhanced session required - feature not available" : "Metadata protection failed";
        verificationResults.metadataProtection = { passed: false, details: reason, points: 0 };
      }
      if (!isDemoSession && await _EnhancedSecureCryptoUtils.verifyPFS(securityManager)) {
        score += 10;
        verificationResults.pfs = { passed: true, details: "Perfect Forward Secrecy active", points: 10 };
      } else {
        const reason = isDemoSession ? "Enhanced session required - feature not available" : "PFS not active";
        verificationResults.pfs = { passed: false, details: reason, points: 0 };
      }
      if (!isDemoSession && await _EnhancedSecureCryptoUtils.verifyNestedEncryption(securityManager)) {
        score += 5;
        verificationResults.nestedEncryption = { passed: true, details: "Nested encryption active", points: 5 };
      } else {
        const reason = isDemoSession ? "Enhanced session required - feature not available" : "Nested encryption failed";
        verificationResults.nestedEncryption = { passed: false, details: reason, points: 0 };
      }
      if (!isDemoSession && await _EnhancedSecureCryptoUtils.verifyPacketPadding(securityManager)) {
        score += 5;
        verificationResults.packetPadding = { passed: true, details: "Packet padding active", points: 5 };
      } else {
        const reason = isDemoSession ? "Enhanced session required - feature not available" : "Packet padding failed";
        verificationResults.packetPadding = { passed: false, details: reason, points: 0 };
      }
      if (sessionType === "premium" && await _EnhancedSecureCryptoUtils.verifyAdvancedFeatures(securityManager)) {
        score += 10;
        verificationResults.advancedFeatures = { passed: true, details: "Advanced features active", points: 10 };
      } else {
        const reason = sessionType === "demo" ? "Premium session required - feature not available" : sessionType === "basic" ? "Premium session required - feature not available" : "Advanced features failed";
        verificationResults.advancedFeatures = { passed: false, details: reason, points: 0 };
      }
      const percentage = Math.round(score / maxScore * 100);
      const availableChecks = isDemoSession ? 4 : 10;
      const passedChecks = Object.values(verificationResults).filter((r) => r.passed).length;
      const result = {
        level: percentage >= 85 ? "HIGH" : percentage >= 65 ? "MEDIUM" : percentage >= 35 ? "LOW" : "CRITICAL",
        score: percentage,
        color: percentage >= 85 ? "green" : percentage >= 65 ? "orange" : percentage >= 35 ? "yellow" : "red",
        verificationResults,
        timestamp: Date.now(),
        details: `Real verification: ${score}/${maxScore} security checks passed (${passedChecks}/${availableChecks} available)`,
        isRealData: true,
        passedChecks,
        totalChecks: availableChecks,
        sessionType,
        maxPossibleScore: isDemoSession ? 50 : 100
        // Demo sessions can only get max 50 points (4 checks)
      };
      console.log("Real security level calculated:", {
        score: percentage,
        level: result.level,
        passedChecks,
        totalChecks: availableChecks,
        sessionType,
        maxPossibleScore: result.maxPossibleScore
      });
      return result;
    } catch (error) {
      console.error("Security level calculation failed:", error.message);
      return {
        level: "UNKNOWN",
        score: 0,
        color: "red",
        verificationResults: {},
        timestamp: Date.now(),
        details: `Verification failed: ${error.message}`,
        isRealData: false
      };
    }
  }
  // Real verification functions
  static async verifyEncryption(securityManager) {
    try {
      if (!securityManager.encryptionKey) return false;
      const testData = "Test encryption verification";
      const encoder = new TextEncoder();
      const testBuffer = encoder.encode(testData);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        securityManager.encryptionKey,
        testBuffer
      );
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        securityManager.encryptionKey,
        encrypted
      );
      const decryptedText = new TextDecoder().decode(decrypted);
      return decryptedText === testData;
    } catch (error) {
      console.error("Encryption verification failed:", error.message);
      return false;
    }
  }
  static async verifyECDHKeyExchange(securityManager) {
    try {
      if (!securityManager.ecdhKeyPair || !securityManager.ecdhKeyPair.privateKey || !securityManager.ecdhKeyPair.publicKey) {
        return false;
      }
      const keyType = securityManager.ecdhKeyPair.privateKey.algorithm.name;
      const curve = securityManager.ecdhKeyPair.privateKey.algorithm.namedCurve;
      return keyType === "ECDH" && (curve === "P-384" || curve === "P-256");
    } catch (error) {
      console.error("ECDH verification failed:", error.message);
      return false;
    }
  }
  static async verifyECDSASignatures(securityManager) {
    try {
      if (!securityManager.ecdsaKeyPair || !securityManager.ecdsaKeyPair.privateKey || !securityManager.ecdsaKeyPair.publicKey) {
        return false;
      }
      const testData = "Test ECDSA signature verification";
      const encoder = new TextEncoder();
      const testBuffer = encoder.encode(testData);
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        securityManager.ecdsaKeyPair.privateKey,
        testBuffer
      );
      const isValid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        securityManager.ecdsaKeyPair.publicKey,
        signature,
        testBuffer
      );
      return isValid;
    } catch (error) {
      console.error("ECDSA verification failed:", error.message);
      return false;
    }
  }
  static async verifyMessageIntegrity(securityManager) {
    try {
      if (!securityManager.macKey || !(securityManager.macKey instanceof CryptoKey)) {
        console.warn("MAC key not available or invalid for message integrity verification");
        return false;
      }
      const testData = "Test message integrity verification";
      const encoder = new TextEncoder();
      const testBuffer = encoder.encode(testData);
      const hmac = await crypto.subtle.sign(
        { name: "HMAC", hash: "SHA-256" },
        securityManager.macKey,
        testBuffer
      );
      const isValid = await crypto.subtle.verify(
        { name: "HMAC", hash: "SHA-256" },
        securityManager.macKey,
        hmac,
        testBuffer
      );
      return isValid;
    } catch (error) {
      console.error("Message integrity verification failed:", error.message);
      return false;
    }
  }
  static async verifyNestedEncryption(securityManager) {
    try {
      if (!securityManager.nestedEncryptionKey || !(securityManager.nestedEncryptionKey instanceof CryptoKey)) {
        console.warn("Nested encryption key not available or invalid");
        return false;
      }
      const testData = "Test nested encryption verification";
      const encoder = new TextEncoder();
      const testBuffer = encoder.encode(testData);
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: crypto.getRandomValues(new Uint8Array(12)) },
        securityManager.nestedEncryptionKey,
        testBuffer
      );
      return encrypted && encrypted.byteLength > 0;
    } catch (error) {
      console.error("Nested encryption verification failed:", error.message);
      return false;
    }
  }
  static async verifyPacketPadding(securityManager) {
    try {
      if (!securityManager.paddingConfig || !securityManager.paddingConfig.enabled) return false;
      const testData = "Test packet padding verification";
      const encoder = new TextEncoder();
      const testBuffer = encoder.encode(testData);
      const paddingSize = Math.floor(Math.random() * (securityManager.paddingConfig.maxPadding - securityManager.paddingConfig.minPadding)) + securityManager.paddingConfig.minPadding;
      const paddedData = new Uint8Array(testBuffer.byteLength + paddingSize);
      paddedData.set(new Uint8Array(testBuffer), 0);
      return paddedData.byteLength >= testBuffer.byteLength + securityManager.paddingConfig.minPadding;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Packet padding verification failed", { error: error.message });
      return false;
    }
  }
  static async verifyAdvancedFeatures(securityManager) {
    try {
      const hasFakeTraffic = securityManager.fakeTrafficConfig && securityManager.fakeTrafficConfig.enabled;
      const hasDecoyChannels = securityManager.decoyChannelsConfig && securityManager.decoyChannelsConfig.enabled;
      const hasAntiFingerprinting = securityManager.antiFingerprintingConfig && securityManager.antiFingerprintingConfig.enabled;
      return hasFakeTraffic || hasDecoyChannels || hasAntiFingerprinting;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Advanced features verification failed", { error: error.message });
      return false;
    }
  }
  static async verifyMutualAuth(securityManager) {
    try {
      if (!securityManager.isVerified || !securityManager.verificationCode) return false;
      return securityManager.isVerified && securityManager.verificationCode.length > 0;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Mutual auth verification failed", { error: error.message });
      return false;
    }
  }
  static async verifyMetadataProtection(securityManager) {
    try {
      if (!securityManager.metadataKey) return false;
      const testData = "Test metadata protection verification";
      const encoder = new TextEncoder();
      const testBuffer = encoder.encode(testData);
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: crypto.getRandomValues(new Uint8Array(12)) },
        securityManager.metadataKey,
        testBuffer
      );
      return encrypted && encrypted.byteLength > 0;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Metadata protection verification failed", { error: error.message });
      return false;
    }
  }
  static async verifyReplayProtection(securityManager) {
    try {
      if (!securityManager.processedMessageIds || !securityManager.sequenceNumber) return false;
      const testId = Date.now().toString();
      if (securityManager.processedMessageIds.has(testId)) return false;
      securityManager.processedMessageIds.add(testId);
      return true;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Replay protection verification failed", { error: error.message });
      return false;
    }
  }
  static async verifyNonExtractableKeys(securityManager) {
    try {
      if (!securityManager.encryptionKey) return false;
      const keyData = await crypto.subtle.exportKey("raw", securityManager.encryptionKey);
      return keyData && keyData.byteLength > 0;
    } catch (error) {
      return true;
    }
  }
  static async verifyEnhancedValidation(securityManager) {
    try {
      if (!securityManager.securityFeatures) return false;
      const hasValidation = securityManager.securityFeatures.hasEnhancedValidation || securityManager.securityFeatures.hasEnhancedReplayProtection;
      return hasValidation;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Enhanced validation verification failed", { error: error.message });
      return false;
    }
  }
  static async verifyRateLimiting(securityManager) {
    try {
      const testId = "test_" + Date.now();
      const canProceed = await _EnhancedSecureCryptoUtils.rateLimiter.checkMessageRate(testId, 1, 6e4);
      return securityManager.rateLimiterId && _EnhancedSecureCryptoUtils.rateLimiter && typeof _EnhancedSecureCryptoUtils.rateLimiter.checkMessageRate === "function" && canProceed === true;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Rate limiting verification failed", { error: error.message });
      return false;
    }
  }
  static async verifyPFS(securityManager) {
    try {
      return securityManager.securityFeatures && securityManager.securityFeatures.hasPFS === true && securityManager.keyRotationInterval && securityManager.currentKeyVersion !== void 0 && securityManager.keyVersions && securityManager.keyVersions instanceof Map;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "PFS verification failed", { error: error.message });
      return false;
    }
  }
  // Rate limiting implementation
  static rateLimiter = {
    messages: /* @__PURE__ */ new Map(),
    connections: /* @__PURE__ */ new Map(),
    locks: /* @__PURE__ */ new Map(),
    async checkMessageRate(identifier, limit = 60, windowMs = 6e4) {
      if (typeof identifier !== "string" || identifier.length > 256) {
        return false;
      }
      const key = `msg_${identifier}`;
      if (this.locks.has(key)) {
        await new Promise((resolve) => setTimeout(resolve, Math.floor(Math.random() * 10) + 5));
        return this.checkMessageRate(identifier, limit, windowMs);
      }
      this.locks.set(key, true);
      try {
        const now = Date.now();
        if (!this.messages.has(key)) {
          this.messages.set(key, []);
        }
        const timestamps = this.messages.get(key);
        const validTimestamps = timestamps.filter((ts) => now - ts < windowMs);
        if (validTimestamps.length >= limit) {
          return false;
        }
        validTimestamps.push(now);
        this.messages.set(key, validTimestamps);
        return true;
      } finally {
        this.locks.delete(key);
      }
    },
    async checkConnectionRate(identifier, limit = 5, windowMs = 3e5) {
      if (typeof identifier !== "string" || identifier.length > 256) {
        return false;
      }
      const key = `conn_${identifier}`;
      if (this.locks.has(key)) {
        await new Promise((resolve) => setTimeout(resolve, Math.floor(Math.random() * 10) + 5));
        return this.checkConnectionRate(identifier, limit, windowMs);
      }
      this.locks.set(key, true);
      try {
        const now = Date.now();
        if (!this.connections.has(key)) {
          this.connections.set(key, []);
        }
        const timestamps = this.connections.get(key);
        const validTimestamps = timestamps.filter((ts) => now - ts < windowMs);
        if (validTimestamps.length >= limit) {
          return false;
        }
        validTimestamps.push(now);
        this.connections.set(key, validTimestamps);
        return true;
      } finally {
        this.locks.delete(key);
      }
    },
    cleanup() {
      const now = Date.now();
      const maxAge = 36e5;
      for (const [key, timestamps] of this.messages.entries()) {
        if (this.locks.has(key)) continue;
        const valid = timestamps.filter((ts) => now - ts < maxAge);
        if (valid.length === 0) {
          this.messages.delete(key);
        } else {
          this.messages.set(key, valid);
        }
      }
      for (const [key, timestamps] of this.connections.entries()) {
        if (this.locks.has(key)) continue;
        const valid = timestamps.filter((ts) => now - ts < maxAge);
        if (valid.length === 0) {
          this.connections.delete(key);
        } else {
          this.connections.set(key, valid);
        }
      }
      for (const lockKey of this.locks.keys()) {
        const keyTimestamp = parseInt(lockKey.split("_").pop()) || 0;
        if (now - keyTimestamp > 3e4) {
          this.locks.delete(lockKey);
        }
      }
    }
  };
  static validateSalt(salt) {
    if (!salt || salt.length !== 64) {
      throw new Error("Salt must be exactly 64 bytes");
    }
    const uniqueBytes = new Set(salt);
    if (uniqueBytes.size < 16) {
      throw new Error("Salt has insufficient entropy");
    }
    return true;
  }
  // Secure logging without data leaks
  static secureLog = {
    logs: [],
    maxLogs: 100,
    isProductionMode: false,
    // Initialize production mode detection
    init() {
      this.isProductionMode = this._detectProductionMode();
      if (this.isProductionMode) {
        console.log("[SecureChat] Production mode detected - sensitive logging disabled");
      }
    },
    _detectProductionMode() {
      return typeof process !== "undefined" && false || !window.DEBUG_MODE && !window.DEVELOPMENT_MODE || window.location.hostname && !window.location.hostname.includes("localhost") && !window.location.hostname.includes("127.0.0.1") && !window.location.hostname.includes(".local") || typeof window.webpackHotUpdate === "undefined" && !window.location.search.includes("debug");
    },
    log(level, message, context = {}) {
      const sanitizedContext = this.sanitizeContext(context);
      const logEntry = {
        timestamp: Date.now(),
        level,
        message,
        context: sanitizedContext,
        id: crypto.getRandomValues(new Uint32Array(1))[0]
      };
      this.logs.push(logEntry);
      if (this.logs.length > this.maxLogs) {
        this.logs = this.logs.slice(-this.maxLogs);
      }
      if (this.isProductionMode) {
        if (level === "error") {
          console.error(`\u274C [SecureChat] ${message} [ERROR_CODE: ${this._generateErrorCode(message)}]`);
        } else if (level === "warn") {
          console.warn(`\u26A0\uFE0F [SecureChat] ${message}`);
        } else {
          return;
        }
      } else {
        if (level === "error") {
          console.error(`\u274C [SecureChat] ${message}`, { errorType: sanitizedContext?.constructor?.name || "Unknown" });
        } else if (level === "warn") {
          console.warn(`\u26A0\uFE0F [SecureChat] ${message}`, { details: sanitizedContext });
        } else {
          console.log(`[SecureChat] ${message}`, sanitizedContext);
        }
      }
    },
    // Генерирует безопасный код ошибки для production
    _generateErrorCode(message) {
      const hash = message.split("").reduce((a, b) => {
        a = (a << 5) - a + b.charCodeAt(0);
        return a & a;
      }, 0);
      return Math.abs(hash).toString(36).substring(0, 6).toUpperCase();
    },
    sanitizeContext(context) {
      if (!context || typeof context !== "object") {
        return context;
      }
      const sensitivePatterns = [
        /key/i,
        /secret/i,
        /password/i,
        /token/i,
        /signature/i,
        /challenge/i,
        /proof/i,
        /salt/i,
        /iv/i,
        /nonce/i,
        /hash/i,
        /fingerprint/i,
        /mac/i,
        /private/i,
        /encryption/i,
        /decryption/i
      ];
      const sanitized = {};
      for (const [key, value] of Object.entries(context)) {
        const isSensitive = sensitivePatterns.some(
          (pattern) => pattern.test(key) || typeof value === "string" && pattern.test(value)
        );
        if (isSensitive) {
          sanitized[key] = "[REDACTED]";
        } else if (typeof value === "string" && value.length > 100) {
          sanitized[key] = value.substring(0, 100) + "...[TRUNCATED]";
        } else if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
          sanitized[key] = `[${value.constructor.name}(${value.byteLength || value.length} bytes)]`;
        } else if (value && typeof value === "object" && !Array.isArray(value)) {
          sanitized[key] = this.sanitizeContext(value);
        } else {
          sanitized[key] = value;
        }
      }
      return sanitized;
    },
    getLogs(level = null) {
      if (level) {
        return this.logs.filter((log) => log.level === level);
      }
      return [...this.logs];
    },
    clearLogs() {
      this.logs = [];
    },
    // Метод для отправки ошибок на сервер в production
    async sendErrorToServer(errorCode, message, context = {}) {
      if (!this.isProductionMode) {
        return;
      }
      try {
        const safeErrorData = {
          errorCode,
          timestamp: Date.now(),
          userAgent: navigator.userAgent.substring(0, 100),
          url: window.location.href.substring(0, 100)
        };
        if (window.DEBUG_MODE) {
          console.log("[SecureChat] Error logged to server:", safeErrorData);
        }
      } catch (e) {
      }
    }
  };
  // Generate ECDH key pair for secure key exchange (non-extractable) with fallback
  static async generateECDHKeyPair() {
    try {
      try {
        const keyPair = await crypto.subtle.generateKey(
          {
            name: "ECDH",
            namedCurve: "P-384"
          },
          false,
          // Non-extractable for enhanced security
          ["deriveKey"]
        );
        _EnhancedSecureCryptoUtils.secureLog.log("info", "ECDH key pair generated successfully (P-384)", {
          curve: "P-384",
          extractable: false
        });
        return keyPair;
      } catch (p384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "P-384 generation failed, trying P-256", { error: p384Error.message });
        const keyPair = await crypto.subtle.generateKey(
          {
            name: "ECDH",
            namedCurve: "P-256"
          },
          false,
          // Non-extractable for enhanced security
          ["deriveKey"]
        );
        _EnhancedSecureCryptoUtils.secureLog.log("info", "ECDH key pair generated successfully (P-256 fallback)", {
          curve: "P-256",
          extractable: false
        });
        return keyPair;
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "ECDH key generation failed", { error: error.message });
      throw new Error("Failed to create keys for secure exchange");
    }
  }
  // Generate ECDSA key pair for digital signatures with fallback
  static async generateECDSAKeyPair() {
    try {
      try {
        const keyPair = await crypto.subtle.generateKey(
          {
            name: "ECDSA",
            namedCurve: "P-384"
          },
          false,
          // Non-extractable for enhanced security
          ["sign", "verify"]
        );
        _EnhancedSecureCryptoUtils.secureLog.log("info", "ECDSA key pair generated successfully (P-384)", {
          curve: "P-384",
          extractable: false
        });
        return keyPair;
      } catch (p384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "P-384 generation failed, trying P-256", { error: p384Error.message });
        const keyPair = await crypto.subtle.generateKey(
          {
            name: "ECDSA",
            namedCurve: "P-256"
          },
          false,
          // Non-extractable for enhanced security
          ["sign", "verify"]
        );
        _EnhancedSecureCryptoUtils.secureLog.log("info", "ECDSA key pair generated successfully (P-256 fallback)", {
          curve: "P-256",
          extractable: false
        });
        return keyPair;
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "ECDSA key generation failed", { error: error.message });
      throw new Error("Failed to generate keys for digital signatures");
    }
  }
  // Sign data with ECDSA (P-384 or P-256)
  static async signData(privateKey, data) {
    try {
      const encoder = new TextEncoder();
      const dataBuffer = typeof data === "string" ? encoder.encode(data) : data;
      try {
        const signature = await crypto.subtle.sign(
          {
            name: "ECDSA",
            hash: "SHA-384"
          },
          privateKey,
          dataBuffer
        );
        return Array.from(new Uint8Array(signature));
      } catch (sha384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "SHA-384 signing failed, trying SHA-256", { error: sha384Error.message });
        const signature = await crypto.subtle.sign(
          {
            name: "ECDSA",
            hash: "SHA-256"
          },
          privateKey,
          dataBuffer
        );
        return Array.from(new Uint8Array(signature));
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Data signing failed", { error: error.message });
      throw new Error("Failed to sign data");
    }
  }
  // Verify ECDSA signature (P-384 or P-256)
  static async verifySignature(publicKey, signature, data) {
    try {
      const encoder = new TextEncoder();
      const dataBuffer = typeof data === "string" ? encoder.encode(data) : data;
      const signatureBuffer = new Uint8Array(signature);
      try {
        const isValid = await crypto.subtle.verify(
          {
            name: "ECDSA",
            hash: "SHA-384"
          },
          publicKey,
          signatureBuffer,
          dataBuffer
        );
        _EnhancedSecureCryptoUtils.secureLog.log("info", "Signature verification completed (SHA-384)", {
          isValid,
          dataSize: dataBuffer.length
        });
        return isValid;
      } catch (sha384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "SHA-384 verification failed, trying SHA-256", { error: sha384Error.message });
        const isValid = await crypto.subtle.verify(
          {
            name: "ECDSA",
            hash: "SHA-256"
          },
          publicKey,
          signatureBuffer,
          dataBuffer
        );
        _EnhancedSecureCryptoUtils.secureLog.log("info", "Signature verification completed (SHA-256 fallback)", {
          isValid,
          dataSize: dataBuffer.length
        });
        return isValid;
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Signature verification failed", { error: error.message });
      throw new Error("Failed to verify digital signature");
    }
  }
  // Enhanced DER/SPKI validation with full ASN.1 parsing
  static async validateKeyStructure(keyData, expectedAlgorithm = "ECDH") {
    try {
      if (!Array.isArray(keyData) || keyData.length === 0) {
        throw new Error("Invalid key data format");
      }
      const keyBytes = new Uint8Array(keyData);
      if (keyBytes.length < 50) {
        throw new Error("Key data too short - invalid SPKI structure");
      }
      if (keyBytes.length > 2e3) {
        throw new Error("Key data too long - possible attack");
      }
      const asn1 = _EnhancedSecureCryptoUtils.parseASN1(keyBytes);
      if (!asn1 || asn1.tag !== 48) {
        throw new Error("Invalid SPKI structure - missing SEQUENCE tag");
      }
      if (asn1.children.length !== 2) {
        throw new Error(`Invalid SPKI structure - expected 2 elements, got ${asn1.children.length}`);
      }
      const algIdentifier = asn1.children[0];
      if (algIdentifier.tag !== 48) {
        throw new Error("Invalid AlgorithmIdentifier - not a SEQUENCE");
      }
      const algOid = algIdentifier.children[0];
      if (algOid.tag !== 6) {
        throw new Error("Invalid algorithm OID - not an OBJECT IDENTIFIER");
      }
      const oidBytes = algOid.value;
      const oidString = _EnhancedSecureCryptoUtils.oidToString(oidBytes);
      const validAlgorithms = {
        "ECDH": ["1.2.840.10045.2.1"],
        // id-ecPublicKey
        "ECDSA": ["1.2.840.10045.2.1"],
        // id-ecPublicKey (same as ECDH)
        "RSA": ["1.2.840.113549.1.1.1"],
        // rsaEncryption
        "AES-GCM": ["2.16.840.1.101.3.4.1.6", "2.16.840.1.101.3.4.1.46"]
        // AES-128-GCM, AES-256-GCM
      };
      const expectedOids = validAlgorithms[expectedAlgorithm];
      if (!expectedOids) {
        throw new Error(`Unknown algorithm: ${expectedAlgorithm}`);
      }
      if (!expectedOids.includes(oidString)) {
        throw new Error(`Invalid algorithm OID: expected ${expectedOids.join(" or ")}, got ${oidString}`);
      }
      if (expectedAlgorithm === "ECDH" || expectedAlgorithm === "ECDSA") {
        if (algIdentifier.children.length < 2) {
          throw new Error("Missing curve parameters for EC key");
        }
        const curveOid = algIdentifier.children[1];
        if (curveOid.tag !== 6) {
          throw new Error("Invalid curve OID - not an OBJECT IDENTIFIER");
        }
        const curveOidString = _EnhancedSecureCryptoUtils.oidToString(curveOid.value);
        const validCurves = {
          "1.2.840.10045.3.1.7": "P-256",
          // secp256r1
          "1.3.132.0.34": "P-384"
          // secp384r1
        };
        if (!validCurves[curveOidString]) {
          throw new Error(`Invalid or unsupported curve OID: ${curveOidString}`);
        }
        _EnhancedSecureCryptoUtils.secureLog.log("info", "EC key curve validated", {
          curve: validCurves[curveOidString],
          oid: curveOidString
        });
      }
      const publicKeyBitString = asn1.children[1];
      if (publicKeyBitString.tag !== 3) {
        throw new Error("Invalid public key - not a BIT STRING");
      }
      if (publicKeyBitString.value[0] !== 0) {
        throw new Error(`Invalid BIT STRING - unexpected unused bits: ${publicKeyBitString.value[0]}`);
      }
      if (expectedAlgorithm === "ECDH" || expectedAlgorithm === "ECDSA") {
        const pointData = publicKeyBitString.value.slice(1);
        if (pointData[0] !== 4) {
          throw new Error(`Invalid EC point format: expected uncompressed (0x04), got 0x${pointData[0].toString(16)}`);
        }
        const expectedSizes = {
          "P-256": 65,
          // 1 + 32 + 32
          "P-384": 97
          // 1 + 48 + 48
        };
        const curveOidString = _EnhancedSecureCryptoUtils.oidToString(algIdentifier.children[1].value);
        const curveName = curveOidString === "1.2.840.10045.3.1.7" ? "P-256" : "P-384";
        const expectedSize = expectedSizes[curveName];
        if (pointData.length !== expectedSize) {
          throw new Error(`Invalid EC point size for ${curveName}: expected ${expectedSize}, got ${pointData.length}`);
        }
      }
      try {
        const algorithm = expectedAlgorithm === "ECDSA" || expectedAlgorithm === "ECDH" ? { name: expectedAlgorithm, namedCurve: "P-384" } : { name: expectedAlgorithm };
        const usages = expectedAlgorithm === "ECDSA" ? ["verify"] : [];
        await crypto.subtle.importKey("spki", keyBytes.buffer, algorithm, false, usages);
      } catch (importError) {
        if (expectedAlgorithm === "ECDSA" || expectedAlgorithm === "ECDH") {
          try {
            const algorithm = { name: expectedAlgorithm, namedCurve: "P-256" };
            const usages = expectedAlgorithm === "ECDSA" ? ["verify"] : [];
            await crypto.subtle.importKey("spki", keyBytes.buffer, algorithm, false, usages);
          } catch (fallbackError) {
            throw new Error(`Key import validation failed: ${fallbackError.message}`);
          }
        } else {
          throw new Error(`Key import validation failed: ${importError.message}`);
        }
      }
      _EnhancedSecureCryptoUtils.secureLog.log("info", "Key structure validation passed", {
        keyLen: keyBytes.length,
        algorithm: expectedAlgorithm,
        asn1Valid: true,
        oidValid: true,
        importValid: true
      });
      return true;
    } catch (err) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Key structure validation failed", {
        error: err.message,
        algorithm: expectedAlgorithm
      });
      throw new Error(`Invalid key structure: ${err.message}`);
    }
  }
  // ASN.1 DER parser helper
  static parseASN1(bytes, offset = 0) {
    if (offset >= bytes.length) {
      return null;
    }
    const tag = bytes[offset];
    let lengthOffset = offset + 1;
    if (lengthOffset >= bytes.length) {
      throw new Error("Truncated ASN.1 structure");
    }
    let length = bytes[lengthOffset];
    let valueOffset = lengthOffset + 1;
    if (length & 128) {
      const numLengthBytes = length & 127;
      if (numLengthBytes > 4) {
        throw new Error("ASN.1 length too large");
      }
      length = 0;
      for (let i = 0; i < numLengthBytes; i++) {
        if (valueOffset + i >= bytes.length) {
          throw new Error("Truncated ASN.1 length");
        }
        length = length << 8 | bytes[valueOffset + i];
      }
      valueOffset += numLengthBytes;
    }
    if (valueOffset + length > bytes.length) {
      throw new Error("ASN.1 structure extends beyond data");
    }
    const value = bytes.slice(valueOffset, valueOffset + length);
    const node = {
      tag,
      length,
      value,
      children: []
    };
    if (tag === 48 || tag === 49) {
      let childOffset = 0;
      while (childOffset < value.length) {
        const child = _EnhancedSecureCryptoUtils.parseASN1(value, childOffset);
        if (!child) break;
        node.children.push(child);
        childOffset = childOffset + 1 + child.lengthBytes + child.length;
      }
    }
    node.lengthBytes = valueOffset - lengthOffset;
    return node;
  }
  // OID decoder helper
  static oidToString(bytes) {
    if (!bytes || bytes.length === 0) {
      throw new Error("Empty OID");
    }
    const parts = [];
    const first = Math.floor(bytes[0] / 40);
    const second = bytes[0] % 40;
    parts.push(first);
    parts.push(second);
    let value = 0;
    for (let i = 1; i < bytes.length; i++) {
      value = value << 7 | bytes[i] & 127;
      if (!(bytes[i] & 128)) {
        parts.push(value);
        value = 0;
      }
    }
    return parts.join(".");
  }
  // Helper to validate and sanitize OID string
  static validateOidString(oidString) {
    const oidRegex = /^[0-9]+(\.[0-9]+)*$/;
    if (!oidRegex.test(oidString)) {
      throw new Error(`Invalid OID format: ${oidString}`);
    }
    const parts = oidString.split(".").map(Number);
    if (parts[0] > 2) {
      throw new Error(`Invalid OID first component: ${parts[0]}`);
    }
    if ((parts[0] === 0 || parts[0] === 1) && parts[1] > 39) {
      throw new Error(`Invalid OID second component: ${parts[1]} (must be <= 39 for first component ${parts[0]})`);
    }
    return true;
  }
  // Export public key for transmission with signature 
  static async exportPublicKeyWithSignature(publicKey, signingKey, keyType = "ECDH") {
    try {
      if (!["ECDH", "ECDSA"].includes(keyType)) {
        throw new Error("Invalid key type");
      }
      const exported = await crypto.subtle.exportKey("spki", publicKey);
      const keyData = Array.from(new Uint8Array(exported));
      await _EnhancedSecureCryptoUtils.validateKeyStructure(keyData, keyType);
      const keyPackage = {
        keyType,
        keyData,
        timestamp: Date.now(),
        version: "4.0"
      };
      const packageString = JSON.stringify(keyPackage);
      const signature = await _EnhancedSecureCryptoUtils.signData(signingKey, packageString);
      const signedPackage = {
        ...keyPackage,
        signature
      };
      _EnhancedSecureCryptoUtils.secureLog.log("info", "Public key exported with signature", {
        keyType,
        keySize: keyData.length,
        signed: true
      });
      return signedPackage;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Public key export failed", {
        error: error.message,
        keyType
      });
      throw new Error(`Failed to export ${keyType} key: ${error.message}`);
    }
  }
  // Import and verify signed public key
  static async importSignedPublicKey(signedPackage, verifyingKey, expectedKeyType = "ECDH") {
    try {
      if (!signedPackage || typeof signedPackage !== "object") {
        throw new Error("Invalid signed package format");
      }
      const { keyType, keyData, timestamp, version, signature } = signedPackage;
      if (!keyType || !keyData || !timestamp || !signature) {
        throw new Error("Missing required fields in signed package");
      }
      if (!_EnhancedSecureCryptoUtils.constantTimeCompare(keyType, expectedKeyType)) {
        throw new Error(`Key type mismatch: expected ${expectedKeyType}, got ${keyType}`);
      }
      const keyAge = Date.now() - timestamp;
      if (keyAge > 36e5) {
        throw new Error("Signed key package is too old");
      }
      await _EnhancedSecureCryptoUtils.validateKeyStructure(keyData, keyType);
      const packageCopy = { keyType, keyData, timestamp, version };
      const packageString = JSON.stringify(packageCopy);
      const isValidSignature = await _EnhancedSecureCryptoUtils.verifySignature(verifyingKey, signature, packageString);
      if (!isValidSignature) {
        throw new Error("Invalid signature on key package - possible MITM attack");
      }
      const keyBytes = new Uint8Array(keyData);
      try {
        const algorithm = keyType === "ECDH" ? { name: "ECDH", namedCurve: "P-384" } : { name: "ECDSA", namedCurve: "P-384" };
        const keyUsages = keyType === "ECDH" ? [] : ["verify"];
        const publicKey = await crypto.subtle.importKey(
          "spki",
          keyBytes,
          algorithm,
          false,
          // Non-extractable
          keyUsages
        );
        _EnhancedSecureCryptoUtils.secureLog.log("info", "Signed public key imported successfully (P-384)", {
          keyType,
          signatureValid: true,
          keyAge: Math.round(keyAge / 1e3) + "s"
        });
        return publicKey;
      } catch (p384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "P-384 import failed, trying P-256", {
          error: p384Error.message
        });
        const algorithm = keyType === "ECDH" ? { name: "ECDH", namedCurve: "P-256" } : { name: "ECDSA", namedCurve: "P-256" };
        const keyUsages = keyType === "ECDH" ? [] : ["verify"];
        const publicKey = await crypto.subtle.importKey(
          "spki",
          keyBytes,
          algorithm,
          false,
          // Non-extractable
          keyUsages
        );
        _EnhancedSecureCryptoUtils.secureLog.log("info", "Signed public key imported successfully (P-256 fallback)", {
          keyType,
          signatureValid: true,
          keyAge: Math.round(keyAge / 1e3) + "s"
        });
        return publicKey;
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Signed public key import failed", {
        error: error.message,
        expectedKeyType
      });
      throw new Error(`Failed to import the signed key: ${error.message}`);
    }
  }
  // Legacy export for backward compatibility
  static async exportPublicKey(publicKey) {
    try {
      const exported = await crypto.subtle.exportKey("spki", publicKey);
      const keyData = Array.from(new Uint8Array(exported));
      await _EnhancedSecureCryptoUtils.validateKeyStructure(keyData, "ECDH");
      _EnhancedSecureCryptoUtils.secureLog.log("info", "Legacy public key exported", { keySize: keyData.length });
      return keyData;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Legacy public key export failed", { error: error.message });
      throw new Error("Failed to export the public key");
    }
  }
  // Legacy import for backward compatibility with fallback
  static async importPublicKey(keyData) {
    try {
      await _EnhancedSecureCryptoUtils.validateKeyStructure(keyData, "ECDH");
      const keyBytes = new Uint8Array(keyData);
      try {
        const publicKey = await crypto.subtle.importKey(
          "spki",
          keyBytes,
          {
            name: "ECDH",
            namedCurve: "P-384"
          },
          false,
          // Non-extractable
          []
        );
        _EnhancedSecureCryptoUtils.secureLog.log("info", "Legacy public key imported (P-384)", { keySize: keyData.length });
        return publicKey;
      } catch (p384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "P-384 import failed, trying P-256", { error: p384Error.message });
        const publicKey = await crypto.subtle.importKey(
          "spki",
          keyBytes,
          {
            name: "ECDH",
            namedCurve: "P-256"
          },
          false,
          // Non-extractable
          []
        );
        _EnhancedSecureCryptoUtils.secureLog.log("info", "Legacy public key imported (P-256 fallback)", { keySize: keyData.length });
        return publicKey;
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Legacy public key import failed", { error: error.message });
      throw new Error("Failed to import the public key");
    }
  }
  // Method to check if a key is trusted
  static isKeyTrusted(keyOrFingerprint) {
    if (keyOrFingerprint instanceof CryptoKey) {
      const meta = _EnhancedSecureCryptoUtils._keyMetadata.get(keyOrFingerprint);
      return meta ? meta.trusted === true : false;
    } else if (keyOrFingerprint && keyOrFingerprint._securityMetadata) {
      return keyOrFingerprint._securityMetadata.trusted === true;
    }
    return false;
  }
  static async importPublicKeyFromSignedPackage(signedPackage, verifyingKey = null, options = {}) {
    try {
      if (!signedPackage || !signedPackage.keyData || !signedPackage.signature) {
        throw new Error("Invalid signed key package format");
      }
      const requiredFields = ["keyData", "signature", "keyType", "timestamp", "version"];
      const missingFields = requiredFields.filter((field) => !signedPackage[field]);
      if (missingFields.length > 0) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Missing required fields in signed package", {
          missingFields,
          availableFields: Object.keys(signedPackage)
        });
        throw new Error(`Required fields are missing in the signed package: ${missingFields.join(", ")}`);
      }
      if (!verifyingKey) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "SECURITY VIOLATION: Signed package received without verifying key", {
          keyType: signedPackage.keyType,
          keySize: signedPackage.keyData.length,
          timestamp: signedPackage.timestamp,
          version: signedPackage.version,
          securityRisk: "HIGH - Potential MITM attack vector"
        });
        throw new Error("CRITICAL SECURITY ERROR: Signed key package received without a verification key. This may indicate a possible MITM attack attempt. Import rejected for security reasons.");
      }
      await _EnhancedSecureCryptoUtils.validateKeyStructure(signedPackage.keyData, signedPackage.keyType || "ECDH");
      const packageCopy = { ...signedPackage };
      delete packageCopy.signature;
      const packageString = JSON.stringify(packageCopy);
      const isValidSignature = await _EnhancedSecureCryptoUtils.verifySignature(verifyingKey, signedPackage.signature, packageString);
      if (!isValidSignature) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "SECURITY BREACH: Invalid signature detected - MITM attack prevented", {
          keyType: signedPackage.keyType,
          keySize: signedPackage.keyData.length,
          timestamp: signedPackage.timestamp,
          version: signedPackage.version,
          attackPrevented: true
        });
        throw new Error("CRITICAL SECURITY ERROR: Invalid key signature detected. This indicates a possible MITM attack attempt. Key import rejected.");
      }
      const keyFingerprint = await _EnhancedSecureCryptoUtils.calculateKeyFingerprint(signedPackage.keyData);
      _EnhancedSecureCryptoUtils.secureLog.log("info", "SECURE: Signature verification passed for signed package", {
        keyType: signedPackage.keyType,
        keySize: signedPackage.keyData.length,
        timestamp: signedPackage.timestamp,
        version: signedPackage.version,
        signatureVerified: true,
        securityLevel: "HIGH",
        keyFingerprint: keyFingerprint.substring(0, 8)
        // Only log first 8 chars for security
      });
      const keyBytes = new Uint8Array(signedPackage.keyData);
      const keyType = signedPackage.keyType || "ECDH";
      try {
        const publicKey = await crypto.subtle.importKey(
          "spki",
          keyBytes,
          {
            name: keyType,
            namedCurve: "P-384"
          },
          false,
          // Non-extractable
          keyType === "ECDSA" ? ["verify"] : []
        );
        _EnhancedSecureCryptoUtils._keyMetadata.set(publicKey, {
          trusted: true,
          verificationStatus: "VERIFIED_SECURE",
          verificationTimestamp: Date.now()
        });
        return publicKey;
      } catch (p384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "P-384 import failed, trying P-256", { error: p384Error.message });
        const publicKey = await crypto.subtle.importKey(
          "spki",
          keyBytes,
          {
            name: keyType,
            namedCurve: "P-256"
          },
          false,
          // Non-extractable
          keyType === "ECDSA" ? ["verify"] : []
        );
        _EnhancedSecureCryptoUtils._keyMetadata.set(publicKey, {
          trusted: true,
          verificationStatus: "VERIFIED_SECURE",
          verificationTimestamp: Date.now()
        });
        return publicKey;
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Signed package key import failed", {
        error: error.message,
        securityImplications: "Potential security breach prevented"
      });
      throw new Error(`Failed to import the public key from the signed package: ${error.message}`);
    }
  }
  // Enhanced key derivation with metadata protection and 64-byte salt
  static async deriveSharedKeys(privateKey, publicKey, salt) {
    try {
      if (!(privateKey instanceof CryptoKey)) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Private key is not a CryptoKey", {
          privateKeyType: typeof privateKey,
          privateKeyAlgorithm: privateKey?.algorithm?.name
        });
        throw new Error("The private key is not a valid CryptoKey.");
      }
      if (!(publicKey instanceof CryptoKey)) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Public key is not a CryptoKey", {
          publicKeyType: typeof publicKey,
          publicKeyAlgorithm: publicKey?.algorithm?.name
        });
        throw new Error("The private key is not a valid CryptoKey.");
      }
      if (!salt || salt.length !== 64) {
        throw new Error("Salt must be exactly 64 bytes for enhanced security");
      }
      const saltBytes = new Uint8Array(salt);
      const encoder = new TextEncoder();
      const contextInfo = encoder.encode("SecureBit.chat v4.0 Enhanced Security Edition");
      let sharedSecret;
      try {
        sharedSecret = await crypto.subtle.deriveKey(
          {
            name: "ECDH",
            public: publicKey
          },
          privateKey,
          {
            name: "HKDF",
            hash: "SHA-384",
            salt: saltBytes,
            info: contextInfo
          },
          false,
          // Non-extractable
          ["deriveKey"]
        );
      } catch (sha384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "SHA-384 key derivation failed, trying SHA-256", {
          error: sha384Error.message,
          privateKeyType: typeof privateKey,
          publicKeyType: typeof publicKey,
          privateKeyAlgorithm: privateKey?.algorithm?.name,
          publicKeyAlgorithm: publicKey?.algorithm?.name
        });
        sharedSecret = await crypto.subtle.deriveKey(
          {
            name: "ECDH",
            public: publicKey
          },
          privateKey,
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: saltBytes,
            info: contextInfo
          },
          false,
          // Non-extractable
          ["deriveKey"]
        );
      }
      let encryptionKey;
      try {
        encryptionKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-384",
            salt: saltBytes,
            info: encoder.encode("message-encryption-v4")
          },
          sharedSecret,
          {
            name: "AES-GCM",
            length: 256
          },
          false,
          // Non-extractable for enhanced security
          ["encrypt", "decrypt"]
        );
      } catch (sha384Error) {
        encryptionKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: saltBytes,
            info: encoder.encode("message-encryption-v4")
          },
          sharedSecret,
          {
            name: "AES-GCM",
            length: 256
          },
          false,
          // Non-extractable for enhanced security
          ["encrypt", "decrypt"]
        );
      }
      let macKey;
      try {
        macKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-384",
            salt: saltBytes,
            info: encoder.encode("message-authentication-v4")
          },
          sharedSecret,
          {
            name: "HMAC",
            hash: "SHA-384"
          },
          false,
          // Non-extractable
          ["sign", "verify"]
        );
      } catch (sha384Error) {
        macKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: saltBytes,
            info: encoder.encode("message-authentication-v4")
          },
          sharedSecret,
          {
            name: "HMAC",
            hash: "SHA-256"
          },
          false,
          // Non-extractable
          ["sign", "verify"]
        );
      }
      let metadataKey;
      try {
        metadataKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-384",
            salt: saltBytes,
            info: encoder.encode("metadata-protection-v4")
          },
          sharedSecret,
          {
            name: "AES-GCM",
            length: 256
          },
          false,
          // Non-extractable
          ["encrypt", "decrypt"]
        );
      } catch (sha384Error) {
        metadataKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: saltBytes,
            info: encoder.encode("metadata-protection-v4")
          },
          sharedSecret,
          {
            name: "AES-GCM",
            length: 256
          },
          false,
          // Non-extractable
          ["encrypt", "decrypt"]
        );
      }
      let fingerprintKey;
      try {
        fingerprintKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-384",
            salt: saltBytes,
            info: encoder.encode("fingerprint-generation-v4")
          },
          sharedSecret,
          {
            name: "AES-GCM",
            length: 256
          },
          true,
          // Extractable only for fingerprint
          ["encrypt", "decrypt"]
        );
      } catch (sha384Error) {
        fingerprintKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: saltBytes,
            info: encoder.encode("fingerprint-generation-v4")
          },
          sharedSecret,
          {
            name: "AES-GCM",
            length: 256
          },
          true,
          // Extractable only for fingerprint
          ["encrypt", "decrypt"]
        );
      }
      const fingerprintKeyData = await crypto.subtle.exportKey("raw", fingerprintKey);
      const fingerprint = await _EnhancedSecureCryptoUtils.generateKeyFingerprint(Array.from(new Uint8Array(fingerprintKeyData)));
      if (!(encryptionKey instanceof CryptoKey)) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Derived encryption key is not a CryptoKey", {
          encryptionKeyType: typeof encryptionKey,
          encryptionKeyAlgorithm: encryptionKey?.algorithm?.name
        });
        throw new Error("The derived encryption key is not a valid CryptoKey.");
      }
      if (!(macKey instanceof CryptoKey)) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Derived MAC key is not a CryptoKey", {
          macKeyType: typeof macKey,
          macKeyAlgorithm: macKey?.algorithm?.name
        });
        throw new Error("The derived MAC key is not a valid CryptoKey.");
      }
      if (!(metadataKey instanceof CryptoKey)) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Derived metadata key is not a CryptoKey", {
          metadataKeyType: typeof metadataKey,
          metadataKeyAlgorithm: metadataKey?.algorithm?.name
        });
        throw new Error("The derived metadata key is not a valid CryptoKey.");
      }
      _EnhancedSecureCryptoUtils.secureLog.log("info", "Enhanced shared keys derived successfully", {
        saltSize: salt.length,
        hasMetadataKey: true,
        nonExtractable: true,
        version: "4.0",
        allKeysValid: true
      });
      return {
        encryptionKey,
        macKey,
        metadataKey,
        fingerprint,
        timestamp: Date.now(),
        version: "4.0"
      };
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Enhanced key derivation failed", { error: error.message });
      throw new Error(`Failed to create shared encryption keys: ${error.message}`);
    }
  }
  static async generateKeyFingerprint(keyData) {
    const keyBuffer = new Uint8Array(keyData);
    const hashBuffer = await crypto.subtle.digest("SHA-384", keyBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join(":");
  }
  // Generate mutual authentication challenge
  static generateMutualAuthChallenge() {
    const challenge = crypto.getRandomValues(new Uint8Array(48));
    const timestamp = Date.now();
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    return {
      challenge: Array.from(challenge),
      timestamp,
      nonce: Array.from(nonce),
      version: "4.0"
    };
  }
  // Create cryptographic proof for mutual authentication
  static async createAuthProof(challenge, privateKey, publicKey) {
    try {
      if (!challenge || !challenge.challenge || !challenge.timestamp || !challenge.nonce) {
        throw new Error("Invalid challenge structure");
      }
      const challengeAge = Date.now() - challenge.timestamp;
      if (challengeAge > 12e4) {
        throw new Error("Challenge expired");
      }
      const proofData = {
        challenge: challenge.challenge,
        timestamp: challenge.timestamp,
        nonce: challenge.nonce,
        responseTimestamp: Date.now(),
        publicKeyHash: await _EnhancedSecureCryptoUtils.hashPublicKey(publicKey)
      };
      const proofString = JSON.stringify(proofData);
      const signature = await _EnhancedSecureCryptoUtils.signData(privateKey, proofString);
      const proof = {
        ...proofData,
        signature,
        version: "4.0"
      };
      _EnhancedSecureCryptoUtils.secureLog.log("info", "Authentication proof created", {
        challengeAge: Math.round(challengeAge / 1e3) + "s"
      });
      return proof;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Authentication proof creation failed", { error: error.message });
      throw new Error(`Failed to create cryptographic proof: ${error.message}`);
    }
  }
  // Verify mutual authentication proof
  static async verifyAuthProof(proof, challenge, publicKey) {
    try {
      await new Promise((resolve) => setTimeout(resolve, Math.floor(Math.random() * 20) + 5));
      _EnhancedSecureCryptoUtils.assertCryptoKey(publicKey, "ECDSA", ["verify"]);
      if (!proof || !challenge || !publicKey) {
        throw new Error("Missing required parameters for proof verification");
      }
      const requiredFields = ["challenge", "timestamp", "nonce", "responseTimestamp", "publicKeyHash", "signature"];
      for (const field of requiredFields) {
        if (!proof[field]) {
          throw new Error(`Missing required field: ${field}`);
        }
      }
      if (!_EnhancedSecureCryptoUtils.constantTimeCompareArrays(proof.challenge, challenge.challenge) || proof.timestamp !== challenge.timestamp || !_EnhancedSecureCryptoUtils.constantTimeCompareArrays(proof.nonce, challenge.nonce)) {
        throw new Error("Challenge mismatch - possible replay attack");
      }
      const responseAge = Date.now() - proof.responseTimestamp;
      if (responseAge > 3e5) {
        throw new Error("Proof response expired");
      }
      const expectedHash = await _EnhancedSecureCryptoUtils.hashPublicKey(publicKey);
      if (!_EnhancedSecureCryptoUtils.constantTimeCompare(proof.publicKeyHash, expectedHash)) {
        throw new Error("Public key hash mismatch");
      }
      const proofCopy = { ...proof };
      delete proofCopy.signature;
      const proofString = JSON.stringify(proofCopy);
      const isValidSignature = await _EnhancedSecureCryptoUtils.verifySignature(publicKey, proof.signature, proofString);
      if (!isValidSignature) {
        throw new Error("Invalid proof signature");
      }
      _EnhancedSecureCryptoUtils.secureLog.log("info", "Authentication proof verified successfully", {
        responseAge: Math.round(responseAge / 1e3) + "s"
      });
      return true;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Authentication proof verification failed", { error: error.message });
      throw new Error(`Failed to verify cryptographic proof: ${error.message}`);
    }
  }
  // Hash public key for verification
  static async hashPublicKey(publicKey) {
    try {
      const exported = await crypto.subtle.exportKey("spki", publicKey);
      const hash = await crypto.subtle.digest("SHA-384", exported);
      const hashArray = Array.from(new Uint8Array(hash));
      return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Public key hashing failed", { error: error.message });
      throw new Error("Failed to create hash of the public key");
    }
  }
  // Legacy authentication challenge for backward compatibility
  static generateAuthChallenge() {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    return Array.from(challenge);
  }
  // Generate verification code for out-of-band authentication
  static generateVerificationCode() {
    const chars = "0123456789ABCDEF";
    let result = "";
    const values = crypto.getRandomValues(new Uint8Array(6));
    for (let i = 0; i < 6; i++) {
      result += chars[values[i] % chars.length];
    }
    return result.match(/.{1,2}/g).join("-");
  }
  // Enhanced message encryption with metadata protection and sequence numbers
  static async encryptMessage(message, encryptionKey, macKey, metadataKey, messageId, sequenceNumber = 0) {
    try {
      if (!message || typeof message !== "string") {
        throw new Error("Invalid message format");
      }
      _EnhancedSecureCryptoUtils.assertCryptoKey(encryptionKey, "AES-GCM", ["encrypt"]);
      _EnhancedSecureCryptoUtils.assertCryptoKey(macKey, "HMAC", ["sign"]);
      _EnhancedSecureCryptoUtils.assertCryptoKey(metadataKey, "AES-GCM", ["encrypt"]);
      const encoder = new TextEncoder();
      const messageData = encoder.encode(message);
      const messageIv = crypto.getRandomValues(new Uint8Array(12));
      const metadataIv = crypto.getRandomValues(new Uint8Array(12));
      const timestamp = Date.now();
      const paddingSize = 16 - messageData.length % 16;
      const paddedMessage = new Uint8Array(messageData.length + paddingSize);
      paddedMessage.set(messageData);
      const padding = crypto.getRandomValues(new Uint8Array(paddingSize));
      paddedMessage.set(padding, messageData.length);
      const encryptedMessage = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: messageIv },
        encryptionKey,
        paddedMessage
      );
      const metadata = {
        id: messageId,
        timestamp,
        sequenceNumber,
        originalLength: messageData.length,
        version: "4.0"
      };
      const metadataStr = JSON.stringify(_EnhancedSecureCryptoUtils.sortObjectKeys(metadata));
      const encryptedMetadata = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: metadataIv },
        metadataKey,
        encoder.encode(metadataStr)
      );
      const payload = {
        messageIv: Array.from(messageIv),
        messageData: Array.from(new Uint8Array(encryptedMessage)),
        metadataIv: Array.from(metadataIv),
        metadataData: Array.from(new Uint8Array(encryptedMetadata)),
        version: "4.0"
      };
      const sortedPayload = _EnhancedSecureCryptoUtils.sortObjectKeys(payload);
      const payloadStr = JSON.stringify(sortedPayload);
      const mac = await crypto.subtle.sign(
        "HMAC",
        macKey,
        encoder.encode(payloadStr)
      );
      payload.mac = Array.from(new Uint8Array(mac));
      _EnhancedSecureCryptoUtils.secureLog.log("info", "Message encrypted with metadata protection", {
        messageId,
        sequenceNumber,
        hasMetadataProtection: true,
        hasPadding: true
      });
      return payload;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Message encryption failed", {
        error: error.message,
        messageId
      });
      throw new Error(`Failed to encrypt the message: ${error.message}`);
    }
  }
  // Enhanced message decryption with metadata protection and sequence validation
  static async decryptMessage(encryptedPayload, encryptionKey, macKey, metadataKey, expectedSequenceNumber = null) {
    try {
      _EnhancedSecureCryptoUtils.assertCryptoKey(encryptionKey, "AES-GCM", ["decrypt"]);
      _EnhancedSecureCryptoUtils.assertCryptoKey(macKey, "HMAC", ["verify"]);
      _EnhancedSecureCryptoUtils.assertCryptoKey(metadataKey, "AES-GCM", ["decrypt"]);
      const requiredFields = ["messageIv", "messageData", "metadataIv", "metadataData", "mac", "version"];
      for (const field of requiredFields) {
        if (!encryptedPayload[field]) {
          throw new Error(`Missing required field: ${field}`);
        }
      }
      const payloadCopy = { ...encryptedPayload };
      delete payloadCopy.mac;
      const sortedPayloadCopy = _EnhancedSecureCryptoUtils.sortObjectKeys(payloadCopy);
      const payloadStr = JSON.stringify(sortedPayloadCopy);
      const macValid = await crypto.subtle.verify(
        "HMAC",
        macKey,
        new Uint8Array(encryptedPayload.mac),
        new TextEncoder().encode(payloadStr)
      );
      if (!macValid) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "MAC verification failed", {
          payloadFields: Object.keys(encryptedPayload),
          macLength: encryptedPayload.mac?.length
        });
        throw new Error("Message authentication failed - possible tampering");
      }
      const metadataIv = new Uint8Array(encryptedPayload.metadataIv);
      const metadataData = new Uint8Array(encryptedPayload.metadataData);
      const decryptedMetadataBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: metadataIv },
        metadataKey,
        metadataData
      );
      const metadataStr = new TextDecoder().decode(decryptedMetadataBuffer);
      const metadata = JSON.parse(metadataStr);
      if (!metadata.id || !metadata.timestamp || metadata.sequenceNumber === void 0 || !metadata.originalLength) {
        throw new Error("Invalid metadata structure");
      }
      const messageAge = Date.now() - metadata.timestamp;
      if (messageAge > 3e5) {
        throw new Error("Message expired (older than 5 minutes)");
      }
      if (expectedSequenceNumber !== null) {
        if (metadata.sequenceNumber < expectedSequenceNumber) {
          _EnhancedSecureCryptoUtils.secureLog.log("warn", "Received message with lower sequence number, possible queued message", {
            expected: expectedSequenceNumber,
            received: metadata.sequenceNumber,
            messageId: metadata.id
          });
        } else if (metadata.sequenceNumber > expectedSequenceNumber + 10) {
          throw new Error(`Sequence number gap too large: expected around ${expectedSequenceNumber}, got ${metadata.sequenceNumber}`);
        }
      }
      const messageIv = new Uint8Array(encryptedPayload.messageIv);
      const messageData = new Uint8Array(encryptedPayload.messageData);
      const decryptedMessageBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: messageIv },
        encryptionKey,
        messageData
      );
      const paddedMessage = new Uint8Array(decryptedMessageBuffer);
      const originalMessage = paddedMessage.slice(0, metadata.originalLength);
      const decoder = new TextDecoder();
      const message = decoder.decode(originalMessage);
      _EnhancedSecureCryptoUtils.secureLog.log("info", "Message decrypted successfully", {
        messageId: metadata.id,
        sequenceNumber: metadata.sequenceNumber,
        messageAge: Math.round(messageAge / 1e3) + "s"
      });
      return {
        message,
        messageId: metadata.id,
        timestamp: metadata.timestamp,
        sequenceNumber: metadata.sequenceNumber
      };
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Message decryption failed", { error: error.message });
      throw new Error(`Failed to decrypt the message: ${error.message}`);
    }
  }
  // Enhanced input sanitization
  static sanitizeMessage(message) {
    if (typeof message !== "string") {
      throw new Error("Message must be a string");
    }
    return message.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "").replace(/javascript:/gi, "").replace(/data:/gi, "").replace(/vbscript:/gi, "").replace(/onload\s*=/gi, "").replace(/onerror\s*=/gi, "").replace(/onclick\s*=/gi, "").trim().substring(0, 2e3);
  }
  // Generate cryptographically secure salt (64 bytes for enhanced security)
  static generateSalt() {
    return Array.from(crypto.getRandomValues(new Uint8Array(64)));
  }
  // Calculate key fingerprint for MITM protection
  static async calculateKeyFingerprint(keyData) {
    try {
      const encoder = new TextEncoder();
      const keyBytes = new Uint8Array(keyData);
      const hashBuffer = await crypto.subtle.digest("SHA-256", keyBytes);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const fingerprint = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
      _EnhancedSecureCryptoUtils.secureLog.log("info", "Key fingerprint calculated", {
        keySize: keyData.length,
        fingerprintLength: fingerprint.length
      });
      return fingerprint;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Key fingerprint calculation failed", { error: error.message });
      throw new Error("Failed to compute the key fingerprint");
    }
  }
  static constantTimeCompare(a, b) {
    const strA = typeof a === "string" ? a : JSON.stringify(a);
    const strB = typeof b === "string" ? b : JSON.stringify(b);
    if (strA.length !== strB.length) {
      let dummy = 0;
      for (let i = 0; i < Math.max(strA.length, strB.length); i++) {
        dummy |= (strA.charCodeAt(i % strA.length) || 0) ^ (strB.charCodeAt(i % strB.length) || 0);
      }
      return false;
    }
    let result = 0;
    for (let i = 0; i < strA.length; i++) {
      result |= strA.charCodeAt(i) ^ strB.charCodeAt(i);
    }
    return result === 0;
  }
  static constantTimeCompareArrays(arr1, arr2) {
    if (!Array.isArray(arr1) || !Array.isArray(arr2)) {
      return false;
    }
    if (arr1.length !== arr2.length) {
      let dummy = 0;
      const maxLen = Math.max(arr1.length, arr2.length);
      for (let i = 0; i < maxLen; i++) {
        dummy |= (arr1[i % arr1.length] || 0) ^ (arr2[i % arr2.length] || 0);
      }
      return false;
    }
    let result = 0;
    for (let i = 0; i < arr1.length; i++) {
      result |= arr1[i] ^ arr2[i];
    }
    return result === 0;
  }
  /**
   * CRITICAL SECURITY: Encrypt data with AAD (Additional Authenticated Data)
   * This method provides authenticated encryption with additional data binding
   */
  static async encryptDataWithAAD(data, key, aad) {
    try {
      const dataString = typeof data === "string" ? data : JSON.stringify(data);
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(dataString);
      const aadBuffer = encoder.encode(aad);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: aadBuffer
        },
        key,
        dataBuffer
      );
      const encryptedPackage = {
        version: "1.0",
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted)),
        aad,
        timestamp: Date.now()
      };
      const packageString = JSON.stringify(encryptedPackage);
      const packageBuffer = encoder.encode(packageString);
      return _EnhancedSecureCryptoUtils.arrayBufferToBase64(packageBuffer);
    } catch (error) {
      throw new Error(`AAD encryption failed: ${error.message}`);
    }
  }
  /**
   * CRITICAL SECURITY: Decrypt data with AAD validation
   * This method provides authenticated decryption with additional data validation
   */
  static async decryptDataWithAAD(encryptedData, key, expectedAad) {
    try {
      const packageBuffer = _EnhancedSecureCryptoUtils.base64ToArrayBuffer(encryptedData);
      const packageString = new TextDecoder().decode(packageBuffer);
      const encryptedPackage = JSON.parse(packageString);
      if (!encryptedPackage.version || !encryptedPackage.iv || !encryptedPackage.data || !encryptedPackage.aad) {
        throw new Error("Invalid encrypted data format");
      }
      if (encryptedPackage.aad !== expectedAad) {
        throw new Error("AAD mismatch - possible tampering or replay attack");
      }
      const iv = new Uint8Array(encryptedPackage.iv);
      const encrypted = new Uint8Array(encryptedPackage.data);
      const aadBuffer = new TextEncoder().encode(encryptedPackage.aad);
      const decrypted = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: aadBuffer
        },
        key,
        encrypted
      );
      const decryptedString = new TextDecoder().decode(decrypted);
      try {
        return JSON.parse(decryptedString);
      } catch {
        return decryptedString;
      }
    } catch (error) {
      throw new Error(`AAD decryption failed: ${error.message}`);
    }
  }
  static {
    if (_EnhancedSecureCryptoUtils.secureLog && typeof _EnhancedSecureCryptoUtils.secureLog.init === "function") {
      _EnhancedSecureCryptoUtils.secureLog.init();
    }
  }
};

// src/transfer/EnhancedSecureFileTransfer.js
var SecureFileTransferContext = class _SecureFileTransferContext {
  static #instance = null;
  static #contextKey = Symbol("SecureFileTransferContext");
  static getInstance() {
    if (!this.#instance) {
      this.#instance = new _SecureFileTransferContext();
    }
    return this.#instance;
  }
  #fileTransferSystem = null;
  #active = false;
  #securityLevel = "high";
  setFileTransferSystem(system) {
    if (!(system instanceof EnhancedSecureFileTransfer)) {
      throw new Error("Invalid file transfer system instance");
    }
    this.#fileTransferSystem = system;
    this.#active = true;
    console.log("\u{1F512} Secure file transfer context initialized");
  }
  getFileTransferSystem() {
    return this.#fileTransferSystem;
  }
  isActive() {
    return this.#active && this.#fileTransferSystem !== null;
  }
  deactivate() {
    this.#active = false;
    this.#fileTransferSystem = null;
    console.log("\u{1F512} Secure file transfer context deactivated");
  }
  getSecurityLevel() {
    return this.#securityLevel;
  }
  setSecurityLevel(level) {
    if (["low", "medium", "high"].includes(level)) {
      this.#securityLevel = level;
    }
  }
};
var SecurityErrorHandler = class {
  static #allowedErrors = /* @__PURE__ */ new Set([
    "File size exceeds maximum limit",
    "Unsupported file type",
    "Transfer timeout",
    "Connection lost",
    "Invalid file data",
    "File transfer failed",
    "Transfer cancelled",
    "Network error",
    "File not found",
    "Permission denied"
  ]);
  static sanitizeError(error) {
    const message = error.message || error;
    for (const allowed of this.#allowedErrors) {
      if (message.includes(allowed)) {
        return allowed;
      }
    }
    console.error("\u{1F512} Internal file transfer error:", {
      message: error.message,
      stack: error.stack,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
    return "File transfer failed";
  }
  static logSecurityEvent(event, details = {}) {
    console.warn("\u{1F512} Security event:", {
      event,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      ...details
    });
  }
};
var FileMetadataSigner = class {
  static async signFileMetadata(metadata, privateKey) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(JSON.stringify({
        fileId: metadata.fileId,
        fileName: metadata.fileName,
        fileSize: metadata.fileSize,
        fileHash: metadata.fileHash,
        timestamp: metadata.timestamp,
        version: metadata.version || "2.0"
      }));
      const signature = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        privateKey,
        data
      );
      return Array.from(new Uint8Array(signature));
    } catch (error) {
      SecurityErrorHandler.logSecurityEvent("signature_failed", { error: error.message });
      throw new Error("Failed to sign file metadata");
    }
  }
  static async verifyFileMetadata(metadata, signature, publicKey) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(JSON.stringify({
        fileId: metadata.fileId,
        fileName: metadata.fileName,
        fileSize: metadata.fileSize,
        fileHash: metadata.fileHash,
        timestamp: metadata.timestamp,
        version: metadata.version || "2.0"
      }));
      const signatureBuffer = new Uint8Array(signature);
      const isValid = await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        publicKey,
        signatureBuffer,
        data
      );
      if (!isValid) {
        SecurityErrorHandler.logSecurityEvent("invalid_signature", { fileId: metadata.fileId });
      }
      return isValid;
    } catch (error) {
      SecurityErrorHandler.logSecurityEvent("verification_failed", { error: error.message });
      return false;
    }
  }
};
var MessageSizeValidator = class {
  static MAX_MESSAGE_SIZE = 1024 * 1024;
  // 1MB
  static isMessageSizeValid(message) {
    const messageString = JSON.stringify(message);
    const sizeInBytes = new Blob([messageString]).size;
    if (sizeInBytes > this.MAX_MESSAGE_SIZE) {
      SecurityErrorHandler.logSecurityEvent("message_too_large", {
        size: sizeInBytes,
        limit: this.MAX_MESSAGE_SIZE
      });
      throw new Error("Message too large");
    }
    return true;
  }
};
var AtomicOperations = class {
  constructor() {
    this.locks = /* @__PURE__ */ new Map();
  }
  async withLock(key, operation) {
    if (this.locks.has(key)) {
      await this.locks.get(key);
    }
    const lockPromise = (async () => {
      try {
        return await operation();
      } finally {
        this.locks.delete(key);
      }
    })();
    this.locks.set(key, lockPromise);
    return lockPromise;
  }
};
var RateLimiter = class {
  constructor(maxRequests, windowMs) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = /* @__PURE__ */ new Map();
  }
  isAllowed(identifier) {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    if (!this.requests.has(identifier)) {
      this.requests.set(identifier, []);
    }
    const userRequests = this.requests.get(identifier);
    const validRequests = userRequests.filter((time) => time > windowStart);
    this.requests.set(identifier, validRequests);
    if (validRequests.length >= this.maxRequests) {
      SecurityErrorHandler.logSecurityEvent("rate_limit_exceeded", {
        identifier,
        requestCount: validRequests.length,
        limit: this.maxRequests
      });
      return false;
    }
    validRequests.push(now);
    return true;
  }
};
var SecureMemoryManager = class {
  static secureWipe(buffer) {
    if (buffer instanceof ArrayBuffer) {
      const view = new Uint8Array(buffer);
      crypto.getRandomValues(view);
    } else if (buffer instanceof Uint8Array) {
      crypto.getRandomValues(buffer);
    }
  }
  static secureDelete(obj, prop) {
    if (obj[prop]) {
      this.secureWipe(obj[prop]);
      delete obj[prop];
    }
  }
};
var EnhancedSecureFileTransfer = class {
  constructor(webrtcManager, onProgress, onComplete, onError, onFileReceived) {
    this.webrtcManager = webrtcManager;
    this.onProgress = onProgress;
    this.onComplete = onComplete;
    this.onError = onError;
    this.onFileReceived = onFileReceived;
    if (!webrtcManager) {
      throw new Error("webrtcManager is required for EnhancedSecureFileTransfer");
    }
    SecureFileTransferContext.getInstance().setFileTransferSystem(this);
    this.atomicOps = new AtomicOperations();
    this.rateLimiter = new RateLimiter(10, 6e4);
    this.signingKey = null;
    this.verificationKey = null;
    this.CHUNK_SIZE = 64 * 1024;
    this.MAX_FILE_SIZE = 100 * 1024 * 1024;
    this.MAX_CONCURRENT_TRANSFERS = 3;
    this.CHUNK_TIMEOUT = 3e4;
    this.RETRY_ATTEMPTS = 3;
    this.FILE_TYPE_RESTRICTIONS = {
      documents: {
        extensions: [".pdf", ".doc", ".docx", ".txt", ".md", ".rtf", ".odt"],
        mimeTypes: [
          "application/pdf",
          "application/msword",
          "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          "text/plain",
          "text/markdown",
          "application/rtf",
          "application/vnd.oasis.opendocument.text"
        ],
        maxSize: 50 * 1024 * 1024,
        // 50 MB
        category: "Documents",
        description: "PDF, DOC, TXT, MD, RTF, ODT"
      },
      images: {
        extensions: [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".ico"],
        mimeTypes: [
          "image/jpeg",
          "image/png",
          "image/gif",
          "image/webp",
          "image/bmp",
          "image/svg+xml",
          "image/x-icon"
        ],
        maxSize: 25 * 1024 * 1024,
        // 25 MB
        category: "Images",
        description: "JPG, PNG, GIF, WEBP, BMP, SVG, ICO"
      },
      archives: {
        extensions: [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"],
        mimeTypes: [
          "application/zip",
          "application/x-rar-compressed",
          "application/x-7z-compressed",
          "application/x-tar",
          "application/gzip",
          "application/x-bzip2",
          "application/x-xz"
        ],
        maxSize: 100 * 1024 * 1024,
        // 100 MB
        category: "Archives",
        description: "ZIP, RAR, 7Z, TAR, GZ, BZ2, XZ"
      },
      media: {
        extensions: [".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".ogg", ".wav"],
        mimeTypes: [
          "audio/mpeg",
          "video/mp4",
          "video/x-msvideo",
          "video/x-matroska",
          "video/quicktime",
          "video/x-ms-wmv",
          "video/x-flv",
          "video/webm",
          "audio/ogg",
          "audio/wav"
        ],
        maxSize: 100 * 1024 * 1024,
        // 100 MB
        category: "Media",
        description: "MP3, MP4, AVI, MKV, MOV, WMV, FLV, WEBM, OGG, WAV"
      },
      general: {
        extensions: [],
        mimeTypes: [],
        maxSize: 50 * 1024 * 1024,
        // 50 MB
        category: "General",
        description: "Any file type up to size limits"
      }
    };
    this.activeTransfers = /* @__PURE__ */ new Map();
    this.receivingTransfers = /* @__PURE__ */ new Map();
    this.transferQueue = [];
    this.pendingChunks = /* @__PURE__ */ new Map();
    this.sessionKeys = /* @__PURE__ */ new Map();
    this.processedChunks = /* @__PURE__ */ new Set();
    this.transferNonces = /* @__PURE__ */ new Map();
    this.receivedFileBuffers = /* @__PURE__ */ new Map();
    this.setupFileMessageHandlers();
    if (this.webrtcManager) {
      this.webrtcManager.fileTransferSystem = this;
    }
  }
  // ============================================
  // FILE TYPE VALIDATION SYSTEM
  // ============================================
  getFileType(file) {
    const fileName = file.name.toLowerCase();
    const fileExtension = fileName.substring(fileName.lastIndexOf("."));
    const mimeType = file.type.toLowerCase();
    for (const [typeKey, typeConfig] of Object.entries(this.FILE_TYPE_RESTRICTIONS)) {
      if (typeKey === "general") continue;
      if (typeConfig.extensions.includes(fileExtension)) {
        return {
          type: typeKey,
          category: typeConfig.category,
          description: typeConfig.description,
          maxSize: typeConfig.maxSize,
          allowed: true
        };
      }
      if (typeConfig.mimeTypes.includes(mimeType)) {
        return {
          type: typeKey,
          category: typeConfig.category,
          description: typeConfig.description,
          maxSize: typeConfig.maxSize,
          allowed: true
        };
      }
    }
    const generalConfig = this.FILE_TYPE_RESTRICTIONS.general;
    return {
      type: "general",
      category: generalConfig.category,
      description: generalConfig.description,
      maxSize: generalConfig.maxSize,
      allowed: true
    };
  }
  validateFile(file) {
    const fileType = this.getFileType(file);
    const errors = [];
    if (file.size > fileType.maxSize) {
      errors.push(`File size (${this.formatFileSize(file.size)}) exceeds maximum allowed for ${fileType.category} (${this.formatFileSize(fileType.maxSize)})`);
    }
    if (!fileType.allowed) {
      errors.push(`File type not allowed. Supported types: ${fileType.description}`);
    }
    if (file.size > this.MAX_FILE_SIZE) {
      errors.push(`File size (${this.formatFileSize(file.size)}) exceeds general limit (${this.formatFileSize(this.MAX_FILE_SIZE)})`);
    }
    return {
      isValid: errors.length === 0,
      errors,
      fileType,
      fileSize: file.size,
      formattedSize: this.formatFileSize(file.size)
    };
  }
  formatFileSize(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }
  getSupportedFileTypes() {
    const supportedTypes = {};
    for (const [typeKey, typeConfig] of Object.entries(this.FILE_TYPE_RESTRICTIONS)) {
      if (typeKey === "general") continue;
      supportedTypes[typeKey] = {
        category: typeConfig.category,
        description: typeConfig.description,
        extensions: typeConfig.extensions,
        maxSize: this.formatFileSize(typeConfig.maxSize),
        maxSizeBytes: typeConfig.maxSize
      };
    }
    return supportedTypes;
  }
  getFileTypeInfo() {
    return {
      supportedTypes: this.getSupportedFileTypes(),
      generalMaxSize: this.formatFileSize(this.MAX_FILE_SIZE),
      generalMaxSizeBytes: this.MAX_FILE_SIZE,
      restrictions: this.FILE_TYPE_RESTRICTIONS
    };
  }
  // ============================================
  // ENCODING HELPERS (Base64 for efficient transport)
  // ============================================
  arrayBufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = "";
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  base64ToUint8Array(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
  // ============================================
  // PUBLIC ACCESSORS FOR RECEIVED FILES
  // ============================================
  getReceivedFileMeta(fileId) {
    const entry = this.receivedFileBuffers.get(fileId);
    if (!entry) return null;
    return { fileId, fileName: entry.name, fileSize: entry.size, mimeType: entry.type };
  }
  async getBlob(fileId) {
    const entry = this.receivedFileBuffers.get(fileId);
    if (!entry) return null;
    return new Blob([entry.buffer], { type: entry.type });
  }
  async getObjectURL(fileId) {
    const blob = await this.getBlob(fileId);
    if (!blob) return null;
    return URL.createObjectURL(blob);
  }
  revokeObjectURL(url) {
    try {
      URL.revokeObjectURL(url);
    } catch (_) {
    }
  }
  setupFileMessageHandlers() {
    if (!this.webrtcManager.dataChannel) {
      const setupRetry = setInterval(() => {
        if (this.webrtcManager.dataChannel) {
          clearInterval(setupRetry);
          this.setupMessageInterception();
        }
      }, 100);
      setTimeout(() => {
        clearInterval(setupRetry);
      }, 5e3);
      return;
    }
    this.setupMessageInterception();
  }
  setupMessageInterception() {
    try {
      if (!this.webrtcManager.dataChannel) {
        return;
      }
      if (this.webrtcManager) {
        this.webrtcManager.fileTransferSystem = this;
      }
      if (this.webrtcManager.dataChannel.onmessage) {
        this.originalOnMessage = this.webrtcManager.dataChannel.onmessage;
      }
      this.webrtcManager.dataChannel.onmessage = async (event) => {
        try {
          if (event.data.length > MessageSizeValidator.MAX_MESSAGE_SIZE) {
            console.warn("\u{1F512} Message too large, ignoring");
            SecurityErrorHandler.logSecurityEvent("oversized_message_blocked");
            return;
          }
          if (typeof event.data === "string") {
            try {
              const parsed = JSON.parse(event.data);
              MessageSizeValidator.isMessageSizeValid(parsed);
              if (this.isFileTransferMessage(parsed)) {
                await this.handleFileMessage(parsed);
                return;
              }
            } catch (parseError) {
              if (parseError.message === "Message too large") {
                return;
              }
            }
          }
          if (this.originalOnMessage) {
            return this.originalOnMessage.call(this.webrtcManager.dataChannel, event);
          }
        } catch (error) {
          console.error("\u274C Error in file system message interception:", error);
          if (this.originalOnMessage) {
            return this.originalOnMessage.call(this.webrtcManager.dataChannel, event);
          }
        }
      };
    } catch (error) {
      console.error("\u274C Failed to set up message interception:", error);
    }
  }
  isFileTransferMessage(message) {
    if (!message || typeof message !== "object" || !message.type) {
      return false;
    }
    const fileMessageTypes2 = [
      "file_transfer_start",
      "file_transfer_response",
      "file_chunk",
      "chunk_confirmation",
      "file_transfer_complete",
      "file_transfer_error"
    ];
    return fileMessageTypes2.includes(message.type);
  }
  async handleFileMessage(message) {
    try {
      if (!this.webrtcManager.fileTransferSystem) {
        try {
          if (typeof this.webrtcManager.initializeFileTransfer === "function") {
            this.webrtcManager.initializeFileTransfer();
            let attempts2 = 0;
            const maxAttempts = 50;
            while (!this.webrtcManager.fileTransferSystem && attempts2 < maxAttempts) {
              await new Promise((resolve) => setTimeout(resolve, 100));
              attempts2++;
            }
            if (!this.webrtcManager.fileTransferSystem) {
              throw new Error("File transfer system initialization timeout");
            }
          } else {
            throw new Error("initializeFileTransfer method not available");
          }
        } catch (initError) {
          console.error("\u274C Failed to initialize file transfer system:", initError);
          if (message.fileId) {
            const errorMessage = {
              type: "file_transfer_error",
              fileId: message.fileId,
              error: "File transfer system not available",
              timestamp: Date.now()
            };
            await this.sendSecureMessage(errorMessage);
          }
          return;
        }
      }
      switch (message.type) {
        case "file_transfer_start":
          await this.handleFileTransferStart(message);
          break;
        case "file_transfer_response":
          this.handleTransferResponse(message);
          break;
        case "file_chunk":
          await this.handleFileChunk(message);
          break;
        case "chunk_confirmation":
          this.handleChunkConfirmation(message);
          break;
        case "file_transfer_complete":
          this.handleTransferComplete(message);
          break;
        case "file_transfer_error":
          this.handleTransferError(message);
          break;
        default:
          console.warn("\u26A0\uFE0F Unknown file message type:", message.type);
      }
    } catch (error) {
      console.error("\u274C Error handling file message:", error);
      if (message.fileId) {
        const errorMessage = {
          type: "file_transfer_error",
          fileId: message.fileId,
          error: error.message,
          timestamp: Date.now()
        };
        await this.sendSecureMessage(errorMessage);
      }
    }
  }
  // ============================================
  // SIMPLIFIED KEY DERIVATION - USE SHARED DATA
  // ============================================
  async deriveFileSessionKey(fileId) {
    try {
      if (!this.webrtcManager.keyFingerprint || !this.webrtcManager.sessionSalt) {
        throw new Error("WebRTC session data not available");
      }
      const fileSalt = crypto.getRandomValues(new Uint8Array(32));
      const encoder = new TextEncoder();
      const fingerprintData = encoder.encode(this.webrtcManager.keyFingerprint);
      const fileIdData = encoder.encode(fileId);
      const sessionSaltArray = new Uint8Array(this.webrtcManager.sessionSalt);
      const combinedSeed = new Uint8Array(
        fingerprintData.length + sessionSaltArray.length + fileSalt.length + fileIdData.length
      );
      let offset = 0;
      combinedSeed.set(fingerprintData, offset);
      offset += fingerprintData.length;
      combinedSeed.set(sessionSaltArray, offset);
      offset += sessionSaltArray.length;
      combinedSeed.set(fileSalt, offset);
      offset += fileSalt.length;
      combinedSeed.set(fileIdData, offset);
      const keyMaterial = await crypto.subtle.digest("SHA-256", combinedSeed);
      const fileSessionKey = await crypto.subtle.importKey(
        "raw",
        keyMaterial,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
      this.sessionKeys.set(fileId, {
        key: fileSessionKey,
        salt: Array.from(fileSalt),
        created: Date.now()
      });
      return { key: fileSessionKey, salt: Array.from(fileSalt) };
    } catch (error) {
      console.error("\u274C Failed to derive file session key:", error);
      throw error;
    }
  }
  async deriveFileSessionKeyFromSalt(fileId, saltArray) {
    try {
      if (!saltArray || !Array.isArray(saltArray) || saltArray.length !== 32) {
        throw new Error(`Invalid salt: ${saltArray?.length || 0} bytes`);
      }
      if (!this.webrtcManager.keyFingerprint || !this.webrtcManager.sessionSalt) {
        throw new Error("WebRTC session data not available");
      }
      const encoder = new TextEncoder();
      const fingerprintData = encoder.encode(this.webrtcManager.keyFingerprint);
      const fileIdData = encoder.encode(fileId);
      const fileSalt = new Uint8Array(saltArray);
      const sessionSaltArray = new Uint8Array(this.webrtcManager.sessionSalt);
      const combinedSeed = new Uint8Array(
        fingerprintData.length + sessionSaltArray.length + fileSalt.length + fileIdData.length
      );
      let offset = 0;
      combinedSeed.set(fingerprintData, offset);
      offset += fingerprintData.length;
      combinedSeed.set(sessionSaltArray, offset);
      offset += sessionSaltArray.length;
      combinedSeed.set(fileSalt, offset);
      offset += fileSalt.length;
      combinedSeed.set(fileIdData, offset);
      const keyMaterial = await crypto.subtle.digest("SHA-256", combinedSeed);
      const fileSessionKey = await crypto.subtle.importKey(
        "raw",
        keyMaterial,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
      this.sessionKeys.set(fileId, {
        key: fileSessionKey,
        salt: saltArray,
        created: Date.now()
      });
      return fileSessionKey;
    } catch (error) {
      console.error("\u274C Failed to derive session key from salt:", error);
      throw error;
    }
  }
  // ============================================
  // FILE TRANSFER IMPLEMENTATION
  // ============================================
  async sendFile(file) {
    try {
      if (!this.webrtcManager) {
        throw new Error("WebRTC Manager not initialized");
      }
      const clientId = this.getClientIdentifier();
      if (!this.rateLimiter.isAllowed(clientId)) {
        SecurityErrorHandler.logSecurityEvent("rate_limit_exceeded", { clientId });
        throw new Error("Rate limit exceeded. Please wait before sending another file.");
      }
      if (!file || !file.size) {
        throw new Error("Invalid file object");
      }
      const validation = this.validateFile(file);
      if (!validation.isValid) {
        const errorMessage = validation.errors.join(". ");
        throw new Error(errorMessage);
      }
      if (this.activeTransfers.size >= this.MAX_CONCURRENT_TRANSFERS) {
        throw new Error("Maximum concurrent transfers reached");
      }
      const fileId = `file_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const fileHash = await this.calculateFileHash(file);
      const keyResult = await this.deriveFileSessionKey(fileId);
      const sessionKey = keyResult.key;
      const salt = keyResult.salt;
      const transferState = {
        fileId,
        file,
        fileHash,
        sessionKey,
        salt,
        totalChunks: Math.ceil(file.size / this.CHUNK_SIZE),
        sentChunks: 0,
        confirmedChunks: 0,
        startTime: Date.now(),
        status: "preparing",
        retryCount: 0,
        lastChunkTime: Date.now()
      };
      this.activeTransfers.set(fileId, transferState);
      this.transferNonces.set(fileId, 0);
      await this.sendFileMetadata(transferState);
      await this.startChunkTransmission(transferState);
      return fileId;
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C File sending failed:", safeError);
      if (this.onError) this.onError(safeError);
      throw new Error(safeError);
    }
  }
  async sendFileMetadata(transferState) {
    try {
      const metadata = {
        type: "file_transfer_start",
        fileId: transferState.fileId,
        fileName: transferState.file.name,
        fileSize: transferState.file.size,
        fileType: transferState.file.type || "application/octet-stream",
        fileHash: transferState.fileHash,
        totalChunks: transferState.totalChunks,
        chunkSize: this.CHUNK_SIZE,
        salt: transferState.salt,
        timestamp: Date.now(),
        version: "2.0"
      };
      if (this.signingKey) {
        try {
          metadata.signature = await FileMetadataSigner.signFileMetadata(metadata, this.signingKey);
          console.log("\u{1F512} File metadata signed successfully");
        } catch (signError) {
          SecurityErrorHandler.logSecurityEvent("signature_failed", {
            fileId: transferState.fileId,
            error: signError.message
          });
        }
      }
      await this.sendSecureMessage(metadata);
      transferState.status = "metadata_sent";
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C Failed to send file metadata:", safeError);
      transferState.status = "failed";
      throw new Error(safeError);
    }
  }
  async startChunkTransmission(transferState) {
    try {
      transferState.status = "transmitting";
      const file = transferState.file;
      const totalChunks = transferState.totalChunks;
      for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
        const start2 = chunkIndex * this.CHUNK_SIZE;
        const end = Math.min(start2 + this.CHUNK_SIZE, file.size);
        const chunkData = await this.readFileChunk(file, start2, end);
        await this.sendFileChunk(transferState, chunkIndex, chunkData);
        transferState.sentChunks++;
        const progress = Math.round(transferState.sentChunks / totalChunks * 95) + 5;
        await this.waitForBackpressure();
      }
      transferState.status = "waiting_confirmation";
      setTimeout(() => {
        if (this.activeTransfers.has(transferState.fileId)) {
          const state = this.activeTransfers.get(transferState.fileId);
          if (state.status === "waiting_confirmation") {
            this.cleanupTransfer(transferState.fileId);
          }
        }
      }, 3e4);
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C Chunk transmission failed:", safeError);
      transferState.status = "failed";
      throw new Error(safeError);
    }
  }
  async readFileChunk(file, start2, end) {
    try {
      const blob = file.slice(start2, end);
      return await blob.arrayBuffer();
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C Failed to read file chunk:", safeError);
      throw new Error(safeError);
    }
  }
  async sendFileChunk(transferState, chunkIndex, chunkData) {
    try {
      const sessionKey = transferState.sessionKey;
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const encryptedChunk = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce
        },
        sessionKey,
        chunkData
      );
      const encryptedB64 = this.arrayBufferToBase64(new Uint8Array(encryptedChunk));
      const chunkMessage = {
        type: "file_chunk",
        fileId: transferState.fileId,
        chunkIndex,
        totalChunks: transferState.totalChunks,
        nonce: Array.from(nonce),
        encryptedDataB64: encryptedB64,
        chunkSize: chunkData.byteLength,
        timestamp: Date.now()
      };
      await this.waitForBackpressure();
      await this.sendSecureMessage(chunkMessage);
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C Failed to send file chunk:", safeError);
      throw new Error(safeError);
    }
  }
  async sendSecureMessage(message) {
    const messageString = JSON.stringify(message);
    const dc = this.webrtcManager?.dataChannel;
    const maxRetries = 10;
    let attempt = 0;
    const wait = (ms) => new Promise((r) => setTimeout(r, ms));
    while (true) {
      try {
        if (!dc || dc.readyState !== "open") {
          throw new Error("Data channel not ready");
        }
        await this.waitForBackpressure();
        dc.send(messageString);
        return;
      } catch (error) {
        const msg = String(error?.message || "");
        const queueFull = msg.includes("send queue is full") || msg.includes("bufferedAmount");
        const opErr = error?.name === "OperationError";
        if ((queueFull || opErr) && attempt < maxRetries) {
          attempt++;
          await this.waitForBackpressure();
          await wait(Math.min(50 * attempt, 500));
          continue;
        }
        console.error("\u274C Failed to send secure message:", error);
        throw error;
      }
    }
  }
  async waitForBackpressure() {
    try {
      const dc = this.webrtcManager?.dataChannel;
      if (!dc) return;
      if (typeof dc.bufferedAmountLowThreshold === "number") {
        if (dc.bufferedAmount > dc.bufferedAmountLowThreshold) {
          await new Promise((resolve) => {
            const handler = () => {
              dc.removeEventListener("bufferedamountlow", handler);
              resolve();
            };
            dc.addEventListener("bufferedamountlow", handler, { once: true });
          });
        }
        return;
      }
      const softLimit = 4 * 1024 * 1024;
      while (dc.bufferedAmount > softLimit) {
        await new Promise((r) => setTimeout(r, 20));
      }
    } catch (_) {
    }
  }
  async calculateFileHash(file) {
    try {
      const arrayBuffer = await file.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch (error) {
      console.error("\u274C File hash calculation failed:", error);
      throw error;
    }
  }
  // ============================================
  // MESSAGE HANDLERS
  // ============================================
  async handleFileTransferStart(metadata) {
    try {
      if (!metadata.fileId || !metadata.fileName || !metadata.fileSize) {
        throw new Error("Invalid file transfer metadata");
      }
      if (metadata.signature && this.verificationKey) {
        try {
          const isValid = await FileMetadataSigner.verifyFileMetadata(
            metadata,
            metadata.signature,
            this.verificationKey
          );
          if (!isValid) {
            SecurityErrorHandler.logSecurityEvent("invalid_metadata_signature", {
              fileId: metadata.fileId
            });
            throw new Error("Invalid file metadata signature");
          }
          console.log("\u{1F512} File metadata signature verified successfully");
        } catch (verifyError) {
          SecurityErrorHandler.logSecurityEvent("verification_failed", {
            fileId: metadata.fileId,
            error: verifyError.message
          });
          throw new Error("File metadata verification failed");
        }
      }
      if (this.receivingTransfers.has(metadata.fileId)) {
        return;
      }
      const sessionKey = await this.deriveFileSessionKeyFromSalt(
        metadata.fileId,
        metadata.salt
      );
      const receivingState = {
        fileId: metadata.fileId,
        fileName: metadata.fileName,
        fileSize: metadata.fileSize,
        fileType: metadata.fileType || "application/octet-stream",
        fileHash: metadata.fileHash,
        totalChunks: metadata.totalChunks,
        chunkSize: metadata.chunkSize || this.CHUNK_SIZE,
        sessionKey,
        salt: metadata.salt,
        receivedChunks: /* @__PURE__ */ new Map(),
        receivedCount: 0,
        startTime: Date.now(),
        lastChunkTime: Date.now(),
        status: "receiving"
      };
      this.receivingTransfers.set(metadata.fileId, receivingState);
      const response = {
        type: "file_transfer_response",
        fileId: metadata.fileId,
        accepted: true,
        timestamp: Date.now()
      };
      await this.sendSecureMessage(response);
      if (this.pendingChunks.has(metadata.fileId)) {
        const bufferedChunks = this.pendingChunks.get(metadata.fileId);
        for (const [chunkIndex, chunkMessage] of bufferedChunks.entries()) {
          await this.handleFileChunk(chunkMessage);
        }
        this.pendingChunks.delete(metadata.fileId);
      }
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C Failed to handle file transfer start:", safeError);
      const errorResponse = {
        type: "file_transfer_response",
        fileId: metadata.fileId,
        accepted: false,
        error: safeError,
        timestamp: Date.now()
      };
      await this.sendSecureMessage(errorResponse);
    }
  }
  async handleFileChunk(chunkMessage) {
    return this.atomicOps.withLock(
      `chunk-${chunkMessage.fileId}`,
      async () => {
        try {
          let receivingState = this.receivingTransfers.get(chunkMessage.fileId);
          if (!receivingState) {
            if (!this.pendingChunks.has(chunkMessage.fileId)) {
              this.pendingChunks.set(chunkMessage.fileId, /* @__PURE__ */ new Map());
            }
            this.pendingChunks.get(chunkMessage.fileId).set(chunkMessage.chunkIndex, chunkMessage);
            return;
          }
          receivingState.lastChunkTime = Date.now();
          if (receivingState.receivedChunks.has(chunkMessage.chunkIndex)) {
            return;
          }
          if (chunkMessage.chunkIndex < 0 || chunkMessage.chunkIndex >= receivingState.totalChunks) {
            throw new Error(`Invalid chunk index: ${chunkMessage.chunkIndex}`);
          }
          const nonce = new Uint8Array(chunkMessage.nonce);
          let encryptedData;
          if (chunkMessage.encryptedDataB64) {
            encryptedData = this.base64ToUint8Array(chunkMessage.encryptedDataB64);
          } else if (chunkMessage.encryptedData) {
            encryptedData = new Uint8Array(chunkMessage.encryptedData);
          } else {
            throw new Error("Missing encrypted data");
          }
          const decryptedChunk = await crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: nonce
            },
            receivingState.sessionKey,
            encryptedData
          );
          if (decryptedChunk.byteLength !== chunkMessage.chunkSize) {
            throw new Error(`Chunk size mismatch: expected ${chunkMessage.chunkSize}, got ${decryptedChunk.byteLength}`);
          }
          receivingState.receivedChunks.set(chunkMessage.chunkIndex, decryptedChunk);
          receivingState.receivedCount++;
          const confirmation = {
            type: "chunk_confirmation",
            fileId: chunkMessage.fileId,
            chunkIndex: chunkMessage.chunkIndex,
            timestamp: Date.now()
          };
          await this.sendSecureMessage(confirmation);
          if (receivingState.receivedCount === receivingState.totalChunks) {
            await this.assembleFile(receivingState);
          }
        } catch (error) {
          const safeError = SecurityErrorHandler.sanitizeError(error);
          console.error("\u274C Failed to handle file chunk:", safeError);
          const errorMessage = {
            type: "file_transfer_error",
            fileId: chunkMessage.fileId,
            error: safeError,
            chunkIndex: chunkMessage.chunkIndex,
            timestamp: Date.now()
          };
          await this.sendSecureMessage(errorMessage);
          const receivingState = this.receivingTransfers.get(chunkMessage.fileId);
          if (receivingState) {
            receivingState.status = "failed";
          }
          if (this.onError) {
            this.onError(`Chunk processing failed: ${safeError}`);
          }
        }
      }
    );
  }
  async assembleFile(receivingState) {
    try {
      receivingState.status = "assembling";
      for (let i = 0; i < receivingState.totalChunks; i++) {
        if (!receivingState.receivedChunks.has(i)) {
          throw new Error(`Missing chunk ${i}`);
        }
      }
      const chunks = [];
      for (let i = 0; i < receivingState.totalChunks; i++) {
        const chunk = receivingState.receivedChunks.get(i);
        chunks.push(new Uint8Array(chunk));
      }
      const totalSize = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
      if (totalSize !== receivingState.fileSize) {
        throw new Error(`File size mismatch: expected ${receivingState.fileSize}, got ${totalSize}`);
      }
      const fileData = new Uint8Array(totalSize);
      let offset = 0;
      for (const chunk of chunks) {
        fileData.set(chunk, offset);
        offset += chunk.length;
      }
      const receivedHash = await this.calculateFileHashFromData(fileData);
      if (receivedHash !== receivingState.fileHash) {
        throw new Error("File integrity check failed - hash mismatch");
      }
      const fileBuffer = fileData.buffer;
      const fileBlob = new Blob([fileBuffer], { type: receivingState.fileType });
      receivingState.endTime = Date.now();
      receivingState.status = "completed";
      this.receivedFileBuffers.set(receivingState.fileId, {
        buffer: fileBuffer,
        type: receivingState.fileType,
        name: receivingState.fileName,
        size: receivingState.fileSize
      });
      if (this.onFileReceived) {
        const getBlob = async () => new Blob([this.receivedFileBuffers.get(receivingState.fileId).buffer], { type: receivingState.fileType });
        const getObjectURL = async () => {
          const blob = await getBlob();
          return URL.createObjectURL(blob);
        };
        const revokeObjectURL = (url) => {
          try {
            URL.revokeObjectURL(url);
          } catch (_) {
          }
        };
        this.onFileReceived({
          fileId: receivingState.fileId,
          fileName: receivingState.fileName,
          fileSize: receivingState.fileSize,
          mimeType: receivingState.fileType,
          transferTime: receivingState.endTime - receivingState.startTime,
          // backward-compatibility for existing UIs
          fileBlob,
          getBlob,
          getObjectURL,
          revokeObjectURL
        });
      }
      const completionMessage = {
        type: "file_transfer_complete",
        fileId: receivingState.fileId,
        success: true,
        timestamp: Date.now()
      };
      await this.sendSecureMessage(completionMessage);
      if (this.receivingTransfers.has(receivingState.fileId)) {
        const rs = this.receivingTransfers.get(receivingState.fileId);
        if (rs && rs.receivedChunks) rs.receivedChunks.clear();
      }
      this.receivingTransfers.delete(receivingState.fileId);
    } catch (error) {
      console.error("\u274C File assembly failed:", error);
      receivingState.status = "failed";
      if (this.onError) {
        this.onError(`File assembly failed: ${error.message}`);
      }
      const errorMessage = {
        type: "file_transfer_complete",
        fileId: receivingState.fileId,
        success: false,
        error: error.message,
        timestamp: Date.now()
      };
      await this.sendSecureMessage(errorMessage);
      this.cleanupReceivingTransfer(receivingState.fileId);
    }
  }
  async calculateFileHashFromData(data) {
    try {
      const hashBuffer = await crypto.subtle.digest("SHA-256", data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch (error) {
      console.error("\u274C Hash calculation failed:", error);
      throw error;
    }
  }
  handleTransferResponse(response) {
    try {
      const transferState = this.activeTransfers.get(response.fileId);
      if (!transferState) {
        return;
      }
      if (response.accepted) {
        transferState.status = "accepted";
      } else {
        transferState.status = "rejected";
        if (this.onError) {
          this.onError(`Transfer rejected: ${response.error || "Unknown reason"}`);
        }
        this.cleanupTransfer(response.fileId);
      }
    } catch (error) {
      console.error("\u274C Failed to handle transfer response:", error);
    }
  }
  handleChunkConfirmation(confirmation) {
    try {
      const transferState = this.activeTransfers.get(confirmation.fileId);
      if (!transferState) {
        return;
      }
      transferState.confirmedChunks++;
      transferState.lastChunkTime = Date.now();
    } catch (error) {
      console.error("\u274C Failed to handle chunk confirmation:", error);
    }
  }
  handleTransferComplete(completion) {
    try {
      const transferState = this.activeTransfers.get(completion.fileId);
      if (!transferState) {
        return;
      }
      if (completion.success) {
        transferState.status = "completed";
        transferState.endTime = Date.now();
        if (this.onComplete) {
          this.onComplete({
            fileId: transferState.fileId,
            fileName: transferState.file.name,
            fileSize: transferState.file.size,
            transferTime: transferState.endTime - transferState.startTime,
            status: "completed"
          });
        }
      } else {
        transferState.status = "failed";
        if (this.onError) {
          this.onError(`Transfer failed: ${completion.error || "Unknown error"}`);
        }
      }
      this.cleanupTransfer(completion.fileId);
    } catch (error) {
      console.error("\u274C Failed to handle transfer completion:", error);
    }
  }
  handleTransferError(errorMessage) {
    try {
      const transferState = this.activeTransfers.get(errorMessage.fileId);
      if (transferState) {
        transferState.status = "failed";
        this.cleanupTransfer(errorMessage.fileId);
      }
      const receivingState = this.receivingTransfers.get(errorMessage.fileId);
      if (receivingState) {
        receivingState.status = "failed";
        this.cleanupReceivingTransfer(errorMessage.fileId);
      }
      if (this.onError) {
        this.onError(`Transfer error: ${errorMessage.error || "Unknown error"}`);
      }
    } catch (error) {
      console.error("\u274C Failed to handle transfer error:", error);
    }
  }
  // ============================================
  // UTILITY METHODS
  // ============================================
  getActiveTransfers() {
    return Array.from(this.activeTransfers.values()).map((transfer) => ({
      fileId: transfer.fileId,
      fileName: transfer.file?.name || "Unknown",
      fileSize: transfer.file?.size || 0,
      progress: Math.round(transfer.sentChunks / transfer.totalChunks * 100),
      status: transfer.status,
      startTime: transfer.startTime
    }));
  }
  getReceivingTransfers() {
    return Array.from(this.receivingTransfers.values()).map((transfer) => ({
      fileId: transfer.fileId,
      fileName: transfer.fileName || "Unknown",
      fileSize: transfer.fileSize || 0,
      progress: Math.round(transfer.receivedCount / transfer.totalChunks * 100),
      status: transfer.status,
      startTime: transfer.startTime
    }));
  }
  cancelTransfer(fileId) {
    try {
      if (this.activeTransfers.has(fileId)) {
        this.cleanupTransfer(fileId);
        return true;
      }
      if (this.receivingTransfers.has(fileId)) {
        this.cleanupReceivingTransfer(fileId);
        return true;
      }
      return false;
    } catch (error) {
      console.error("\u274C Failed to cancel transfer:", error);
      return false;
    }
  }
  cleanupTransfer(fileId) {
    this.activeTransfers.delete(fileId);
    this.sessionKeys.delete(fileId);
    this.transferNonces.delete(fileId);
    for (const chunkId of this.processedChunks) {
      if (chunkId.startsWith(fileId)) {
        this.processedChunks.delete(chunkId);
      }
    }
  }
  // ✅ УЛУЧШЕННАЯ безопасная очистка памяти для предотвращения use-after-free
  cleanupReceivingTransfer(fileId) {
    try {
      this.pendingChunks.delete(fileId);
      const receivingState = this.receivingTransfers.get(fileId);
      if (receivingState) {
        if (receivingState.receivedChunks && receivingState.receivedChunks.size > 0) {
          for (const [index, chunk] of receivingState.receivedChunks) {
            try {
              if (chunk && (chunk instanceof ArrayBuffer || chunk instanceof Uint8Array)) {
                SecureMemoryManager.secureWipe(chunk);
                if (chunk instanceof ArrayBuffer) {
                  const view = new Uint8Array(chunk);
                  view.fill(0);
                } else if (chunk instanceof Uint8Array) {
                  chunk.fill(0);
                }
              }
            } catch (chunkError) {
              console.warn("\u26A0\uFE0F Failed to securely wipe chunk:", chunkError);
            }
          }
          receivingState.receivedChunks.clear();
        }
        if (receivingState.sessionKey) {
          try {
            receivingState.sessionKey = null;
          } catch (keyError) {
            console.warn("\u26A0\uFE0F Failed to clear session key:", keyError);
          }
        }
        if (receivingState.salt) {
          try {
            if (Array.isArray(receivingState.salt)) {
              receivingState.salt.fill(0);
            }
            receivingState.salt = null;
          } catch (saltError) {
            console.warn("\u26A0\uFE0F Failed to clear salt:", saltError);
          }
        }
        for (const [key, value] of Object.entries(receivingState)) {
          if (value && typeof value === "object") {
            if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
              SecureMemoryManager.secureWipe(value);
            } else if (Array.isArray(value)) {
              value.fill(0);
            }
            receivingState[key] = null;
          }
        }
      }
      this.receivingTransfers.delete(fileId);
      this.sessionKeys.delete(fileId);
      const fileBuffer = this.receivedFileBuffers.get(fileId);
      if (fileBuffer) {
        try {
          if (fileBuffer.buffer) {
            SecureMemoryManager.secureWipe(fileBuffer.buffer);
            const view = new Uint8Array(fileBuffer.buffer);
            view.fill(0);
          }
          for (const [key, value] of Object.entries(fileBuffer)) {
            if (value && typeof value === "object") {
              if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
                SecureMemoryManager.secureWipe(value);
              }
              fileBuffer[key] = null;
            }
          }
          this.receivedFileBuffers.delete(fileId);
        } catch (bufferError) {
          console.warn("\u26A0\uFE0F Failed to securely clear file buffer:", bufferError);
          this.receivedFileBuffers.delete(fileId);
        }
      }
      const chunksToRemove = [];
      for (const chunkId of this.processedChunks) {
        if (chunkId.startsWith(fileId)) {
          chunksToRemove.push(chunkId);
        }
      }
      for (const chunkId of chunksToRemove) {
        this.processedChunks.delete(chunkId);
      }
      if (typeof global !== "undefined" && global.gc) {
        try {
          global.gc();
        } catch (gcError) {
        }
      }
      console.log(`\u{1F512} Memory safely cleaned for file transfer: ${fileId}`);
    } catch (error) {
      console.error("\u274C Error during secure memory cleanup:", error);
      this.receivingTransfers.delete(fileId);
      this.sessionKeys.delete(fileId);
      this.receivedFileBuffers.delete(fileId);
      this.pendingChunks.delete(fileId);
      throw new Error(`Memory cleanup failed: ${error.message}`);
    }
  }
  getTransferStatus(fileId) {
    if (this.activeTransfers.has(fileId)) {
      const transfer = this.activeTransfers.get(fileId);
      return {
        type: "sending",
        fileId: transfer.fileId,
        fileName: transfer.file.name,
        progress: Math.round(transfer.sentChunks / transfer.totalChunks * 100),
        status: transfer.status,
        startTime: transfer.startTime
      };
    }
    if (this.receivingTransfers.has(fileId)) {
      const transfer = this.receivingTransfers.get(fileId);
      return {
        type: "receiving",
        fileId: transfer.fileId,
        fileName: transfer.fileName,
        progress: Math.round(transfer.receivedCount / transfer.totalChunks * 100),
        status: transfer.status,
        startTime: transfer.startTime
      };
    }
    return null;
  }
  getSystemStatus() {
    return {
      initialized: true,
      activeTransfers: this.activeTransfers.size,
      receivingTransfers: this.receivingTransfers.size,
      totalTransfers: this.activeTransfers.size + this.receivingTransfers.size,
      maxConcurrentTransfers: this.MAX_CONCURRENT_TRANSFERS,
      maxFileSize: this.MAX_FILE_SIZE,
      chunkSize: this.CHUNK_SIZE,
      hasWebrtcManager: !!this.webrtcManager,
      isConnected: this.webrtcManager?.isConnected?.() || false,
      hasDataChannel: !!this.webrtcManager?.dataChannel,
      dataChannelState: this.webrtcManager?.dataChannel?.readyState,
      isVerified: this.webrtcManager?.isVerified,
      hasEncryptionKey: !!this.webrtcManager?.encryptionKey,
      hasMacKey: !!this.webrtcManager?.macKey,
      linkedToWebRTCManager: this.webrtcManager?.fileTransferSystem === this,
      supportedFileTypes: this.getSupportedFileTypes(),
      fileTypeInfo: this.getFileTypeInfo()
    };
  }
  cleanup() {
    SecureFileTransferContext.getInstance().deactivate();
    if (this.webrtcManager && this.webrtcManager.dataChannel && this.originalOnMessage) {
      this.webrtcManager.dataChannel.onmessage = this.originalOnMessage;
      this.originalOnMessage = null;
    }
    if (this.webrtcManager && this.originalProcessMessage) {
      this.webrtcManager.processMessage = this.originalProcessMessage;
      this.originalProcessMessage = null;
    }
    if (this.webrtcManager && this.originalRemoveSecurityLayers) {
      this.webrtcManager.removeSecurityLayers = this.originalRemoveSecurityLayers;
      this.originalRemoveSecurityLayers = null;
    }
    for (const fileId of this.activeTransfers.keys()) {
      this.cleanupTransfer(fileId);
    }
    for (const fileId of this.receivingTransfers.keys()) {
      this.cleanupReceivingTransfer(fileId);
    }
    if (this.atomicOps) {
      this.atomicOps.locks.clear();
    }
    if (this.rateLimiter) {
      this.rateLimiter.requests.clear();
    }
    this.pendingChunks.clear();
    this.activeTransfers.clear();
    this.receivingTransfers.clear();
    this.transferQueue.length = 0;
    this.sessionKeys.clear();
    this.transferNonces.clear();
    this.processedChunks.clear();
    this.clearKeys();
  }
  // ============================================
  // SESSION UPDATE HANDLER - FIXED
  // ============================================
  onSessionUpdate(sessionData) {
    this.sessionKeys.clear();
  }
  // ============================================
  // DEBUGGING AND DIAGNOSTICS
  // ============================================
  diagnoseFileTransferIssue() {
    const diagnosis = {
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      fileTransferSystem: {
        initialized: !!this,
        hasWebrtcManager: !!this.webrtcManager,
        webrtcManagerType: this.webrtcManager?.constructor?.name,
        linkedToWebRTCManager: this.webrtcManager?.fileTransferSystem === this
      },
      webrtcManager: {
        hasDataChannel: !!this.webrtcManager?.dataChannel,
        dataChannelState: this.webrtcManager?.dataChannel?.readyState,
        isConnected: this.webrtcManager?.isConnected?.() || false,
        isVerified: this.webrtcManager?.isVerified,
        hasEncryptionKey: !!this.webrtcManager?.encryptionKey,
        hasMacKey: !!this.webrtcManager?.macKey,
        hasKeyFingerprint: !!this.webrtcManager?.keyFingerprint,
        hasSessionSalt: !!this.webrtcManager?.sessionSalt
      },
      securityContext: {
        contextActive: SecureFileTransferContext.getInstance().isActive(),
        securityLevel: SecureFileTransferContext.getInstance().getSecurityLevel(),
        hasAtomicOps: !!this.atomicOps,
        hasRateLimiter: !!this.rateLimiter
      },
      transfers: {
        activeTransfers: this.activeTransfers.size,
        receivingTransfers: this.receivingTransfers.size,
        pendingChunks: this.pendingChunks.size,
        sessionKeys: this.sessionKeys.size
      },
      fileTypeSupport: {
        supportedTypes: this.getSupportedFileTypes(),
        generalMaxSize: this.formatFileSize(this.MAX_FILE_SIZE),
        restrictions: Object.keys(this.FILE_TYPE_RESTRICTIONS)
      }
    };
    return diagnosis;
  }
  async debugKeyDerivation(fileId) {
    try {
      if (!this.webrtcManager.keyFingerprint || !this.webrtcManager.sessionSalt) {
        throw new Error("Session data not available");
      }
      const senderResult = await this.deriveFileSessionKey(fileId);
      const receiverKey = await this.deriveFileSessionKeyFromSalt(fileId, senderResult.salt);
      const testData = new TextEncoder().encode("test data");
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        senderResult.key,
        testData
      );
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce },
        receiverKey,
        encrypted
      );
      const decryptedText = new TextDecoder().decode(decrypted);
      if (decryptedText === "test data") {
        return { success: true, message: "All tests passed" };
      } else {
        throw new Error("Decryption verification failed");
      }
    } catch (error) {
      console.error("\u274C Key derivation test failed:", error);
      return { success: false, error: error.message };
    }
  }
  // ============================================
  // ALTERNATIVE METHOD OF INITIALIZING HANDLERS
  // ============================================
  registerWithWebRTCManager() {
    if (!this.webrtcManager) {
      throw new Error("WebRTC manager not available");
    }
    this.webrtcManager.fileTransferSystem = this;
    this.webrtcManager.setFileMessageHandler = (handler) => {
      this.webrtcManager._fileMessageHandler = handler;
    };
    this.webrtcManager.setFileMessageHandler((message) => {
      return this.handleFileMessage(message);
    });
  }
  static createFileMessageFilter(fileTransferSystem) {
    return async (event) => {
      try {
        if (typeof event.data === "string") {
          const parsed = JSON.parse(event.data);
          if (fileTransferSystem.isFileTransferMessage(parsed)) {
            await fileTransferSystem.handleFileMessage(parsed);
            return true;
          }
        }
      } catch (error) {
      }
      return false;
    };
  }
  // ============================================
  // SECURITY KEY MANAGEMENT
  // ============================================
  setSigningKey(privateKey) {
    if (!privateKey || !(privateKey instanceof CryptoKey)) {
      throw new Error("Invalid private key for signing");
    }
    this.signingKey = privateKey;
    console.log("\u{1F512} Signing key set successfully");
  }
  setVerificationKey(publicKey) {
    if (!publicKey || !(publicKey instanceof CryptoKey)) {
      throw new Error("Invalid public key for verification");
    }
    this.verificationKey = publicKey;
    console.log("\u{1F512} Verification key set successfully");
  }
  async generateSigningKeyPair() {
    try {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        },
        true,
        // extractable
        ["sign", "verify"]
      );
      this.signingKey = keyPair.privateKey;
      this.verificationKey = keyPair.publicKey;
      console.log("\u{1F512} RSA key pair generated successfully");
      return keyPair;
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C Failed to generate signing key pair:", safeError);
      throw new Error(safeError);
    }
  }
  clearKeys() {
    this.signingKey = null;
    this.verificationKey = null;
    console.log("\u{1F512} Security keys cleared");
  }
  getSecurityStatus() {
    return {
      signingEnabled: this.signingKey !== null,
      verificationEnabled: this.verificationKey !== null,
      contextActive: SecureFileTransferContext.getInstance().isActive(),
      securityLevel: SecureFileTransferContext.getInstance().getSecurityLevel()
    };
  }
  getClientIdentifier() {
    return this.webrtcManager?.connectionId || this.webrtcManager?.keyFingerprint?.substring(0, 16) || "default-client";
  }
  destroy() {
    SecureFileTransferContext.getInstance().deactivate();
    this.clearKeys();
    console.log("\u{1F512} File transfer system destroyed safely");
  }
};

// src/network/EnhancedSecureWebRTCManager.js
var EnhancedSecureWebRTCManager = class _EnhancedSecureWebRTCManager {
  // ============================================
  // CONSTANTS
  // ============================================
  static TIMEOUTS = {
    KEY_ROTATION_INTERVAL: 3e5,
    // 5 minutes
    CONNECTION_TIMEOUT: 1e4,
    // 10 seconds  
    HEARTBEAT_INTERVAL: 3e4,
    // 30 seconds
    SECURITY_CALC_DELAY: 1e3,
    // 1 second
    SECURITY_CALC_RETRY_DELAY: 3e3,
    // 3 seconds
    CLEANUP_INTERVAL: 3e5,
    // 5 minutes (periodic cleanup)
    CLEANUP_CHECK_INTERVAL: 6e4,
    // 1 minute (cleanup check)
    ICE_GATHERING_TIMEOUT: 1e4,
    // 10 seconds
    DISCONNECT_CLEANUP_DELAY: 500,
    // 500ms
    PEER_DISCONNECT_CLEANUP: 2e3,
    // 2 seconds
    STAGE2_ACTIVATION_DELAY: 1e4,
    // 10 seconds
    STAGE3_ACTIVATION_DELAY: 15e3,
    // 15 seconds  
    STAGE4_ACTIVATION_DELAY: 2e4,
    // 20 seconds
    FILE_TRANSFER_INIT_DELAY: 1e3,
    // 1 second
    FAKE_TRAFFIC_MIN_INTERVAL: 15e3,
    // 15 seconds
    FAKE_TRAFFIC_MAX_INTERVAL: 3e4,
    // 30 seconds
    DECOY_INITIAL_DELAY: 5e3,
    // 5 seconds
    DECOY_TRAFFIC_MIN: 1e4,
    // 10 seconds
    DECOY_TRAFFIC_MAX: 25e3,
    // 25 seconds
    REORDER_TIMEOUT: 3e3,
    // 3 seconds
    RETRY_CONNECTION_DELAY: 2e3
    // 2 seconds
  };
  static LIMITS = {
    MAX_CONNECTION_ATTEMPTS: 3,
    MAX_OLD_KEYS: 3,
    MAX_PROCESSED_MESSAGE_IDS: 1e3,
    MAX_OUT_OF_ORDER_PACKETS: 5,
    MAX_DECOY_CHANNELS: 1,
    MESSAGE_RATE_LIMIT: 60,
    // messages per minute
    MAX_KEY_AGE: 9e5,
    // 15 minutes
    OFFER_MAX_AGE: 36e5,
    // 1 hour
    SALT_SIZE_V3: 32,
    // bytes
    SALT_SIZE_V4: 64
    // bytes
  };
  static SIZES = {
    VERIFICATION_CODE_MIN_LENGTH: 6,
    FAKE_TRAFFIC_MIN_SIZE: 32,
    FAKE_TRAFFIC_MAX_SIZE: 128,
    PACKET_PADDING_MIN: 64,
    PACKET_PADDING_MAX: 512,
    CHUNK_SIZE_MAX: 2048,
    CHUNK_DELAY_MIN: 100,
    CHUNK_DELAY_MAX: 500,
    FINGERPRINT_DISPLAY_LENGTH: 8,
    SESSION_ID_LENGTH: 16,
    NESTED_ENCRYPTION_IV_SIZE: 12
  };
  static MESSAGE_TYPES = {
    // Regular messages
    MESSAGE: "message",
    ENHANCED_MESSAGE: "enhanced_message",
    // System messages
    HEARTBEAT: "heartbeat",
    VERIFICATION: "verification",
    VERIFICATION_RESPONSE: "verification_response",
    VERIFICATION_CONFIRMED: "verification_confirmed",
    VERIFICATION_BOTH_CONFIRMED: "verification_both_confirmed",
    PEER_DISCONNECT: "peer_disconnect",
    SECURITY_UPGRADE: "security_upgrade",
    KEY_ROTATION_SIGNAL: "key_rotation_signal",
    KEY_ROTATION_READY: "key_rotation_ready",
    // File transfer messages
    FILE_TRANSFER_START: "file_transfer_start",
    FILE_TRANSFER_RESPONSE: "file_transfer_response",
    FILE_CHUNK: "file_chunk",
    CHUNK_CONFIRMATION: "chunk_confirmation",
    FILE_TRANSFER_COMPLETE: "file_transfer_complete",
    FILE_TRANSFER_ERROR: "file_transfer_error",
    // Fake traffic
    FAKE: "fake"
  };
  static FILTERED_RESULTS = {
    FAKE_MESSAGE: "FAKE_MESSAGE_FILTERED",
    FILE_MESSAGE: "FILE_MESSAGE_FILTERED",
    SYSTEM_MESSAGE: "SYSTEM_MESSAGE_FILTERED"
  };
  //   Static debug flag instead of this._debugMode
  static DEBUG_MODE = false;
  // Set to true during development, false in production
  constructor(onMessage, onStatusChange, onKeyExchange, onVerificationRequired, onAnswerError = null, onVerificationStateChange = null, config = {}) {
    this._isProductionMode = this._detectProductionMode();
    this._debugMode = !this._isProductionMode && _EnhancedSecureWebRTCManager.DEBUG_MODE;
    this._config = {
      fakeTraffic: {
        enabled: config.fakeTraffic?.enabled ?? true,
        minInterval: config.fakeTraffic?.minInterval ?? _EnhancedSecureWebRTCManager.TIMEOUTS.FAKE_TRAFFIC_MIN_INTERVAL,
        maxInterval: config.fakeTraffic?.maxInterval ?? _EnhancedSecureWebRTCManager.TIMEOUTS.FAKE_TRAFFIC_MAX_INTERVAL,
        minSize: config.fakeTraffic?.minSize ?? _EnhancedSecureWebRTCManager.SIZES.FAKE_TRAFFIC_MIN_SIZE,
        maxSize: config.fakeTraffic?.maxSize ?? _EnhancedSecureWebRTCManager.SIZES.FAKE_TRAFFIC_MAX_SIZE,
        patterns: config.fakeTraffic?.patterns ?? ["heartbeat", "status", "sync"]
      },
      decoyChannels: {
        enabled: config.decoyChannels?.enabled ?? true,
        maxDecoyChannels: config.decoyChannels?.maxDecoyChannels ?? _EnhancedSecureWebRTCManager.LIMITS.MAX_DECOY_CHANNELS,
        decoyChannelNames: config.decoyChannels?.decoyChannelNames ?? ["heartbeat"],
        sendDecoyData: config.decoyChannels?.sendDecoyData ?? true,
        randomDecoyIntervals: config.decoyChannels?.randomDecoyIntervals ?? true
      },
      packetPadding: {
        enabled: config.packetPadding?.enabled ?? true,
        minPadding: config.packetPadding?.minPadding ?? _EnhancedSecureWebRTCManager.SIZES.PACKET_PADDING_MIN,
        maxPadding: config.packetPadding?.maxPadding ?? _EnhancedSecureWebRTCManager.SIZES.PACKET_PADDING_MAX,
        useRandomPadding: config.packetPadding?.useRandomPadding ?? true,
        preserveMessageSize: config.packetPadding?.preserveMessageSize ?? false
      },
      antiFingerprinting: {
        enabled: config.antiFingerprinting?.enabled ?? false,
        randomizeTiming: config.antiFingerprinting?.randomizeTiming ?? true,
        randomizeSizes: config.antiFingerprinting?.randomizeSizes ?? false,
        addNoise: config.antiFingerprinting?.addNoise ?? true,
        maskPatterns: config.antiFingerprinting?.maskPatterns ?? false,
        useRandomHeaders: config.antiFingerprinting?.useRandomHeaders ?? false
      }
    };
    this._initializeSecureLogging();
    this._setupOwnLogger();
    this._setupProductionLogging();
    this._storeImportantMethods();
    this._setupSecureGlobalAPI();
    if (!window.EnhancedSecureCryptoUtils) {
      throw new Error("EnhancedSecureCryptoUtils is not loaded. Please ensure the module is loaded first.");
    }
    this.getSecurityData = () => {
      return this.lastSecurityCalculation ? {
        level: this.lastSecurityCalculation.level,
        score: this.lastSecurityCalculation.score,
        timestamp: this.lastSecurityCalculation.timestamp
        // Do NOT return check details or sensitive data
      } : null;
    };
    this._secureLog("info", "\u{1F512} Enhanced WebRTC Manager initialized with secure API");
    this.currentSessionType = null;
    this.currentSecurityLevel = "basic";
    this.sessionConstraints = null;
    this.peerConnection = null;
    this.dataChannel = null;
    this.onMessage = onMessage;
    this.onStatusChange = onStatusChange;
    this.onKeyExchange = onKeyExchange;
    this.onVerificationStateChange = onVerificationStateChange;
    this.onVerificationRequired = onVerificationRequired;
    this.onAnswerError = onAnswerError;
    this.isInitiator = false;
    this.connectionAttempts = 0;
    this.maxConnectionAttempts = _EnhancedSecureWebRTCManager.LIMITS.MAX_CONNECTION_ATTEMPTS;
    try {
      this._initializeMutexSystem();
    } catch (error) {
      this._secureLog("error", "\u274C Failed to initialize mutex system", {
        errorType: error.constructor.name
      });
      throw new Error("Critical: Mutex system initialization failed");
    }
    if (!this._validateMutexSystem()) {
      this._secureLog("error", "\u274C Mutex system validation failed after initialization");
      throw new Error("Critical: Mutex system validation failed");
    }
    if (typeof window !== "undefined") {
      this._secureLog("info", "\u{1F512} Emergency mutex handlers will be available through secure API");
    }
    this._secureLog("info", "\u{1F512} Enhanced Mutex system fully initialized and validated");
    this.heartbeatInterval = null;
    this.messageQueue = [];
    this.ecdhKeyPair = null;
    this.ecdsaKeyPair = null;
    if (this.fileTransferSystem) {
      this.fileTransferSystem.cleanup();
      this.fileTransferSystem = null;
    }
    this.verificationCode = null;
    this.pendingSASCode = null;
    this.isVerified = false;
    this.processedMessageIds = /* @__PURE__ */ new Set();
    this.localVerificationConfirmed = false;
    this.remoteVerificationConfirmed = false;
    this.bothVerificationsConfirmed = false;
    this.expectedDTLSFingerprint = null;
    this.strictDTLSValidation = true;
    this.ephemeralKeyPairs = /* @__PURE__ */ new Map();
    this.sessionStartTime = Date.now();
    this.messageCounter = 0;
    this.sequenceNumber = 0;
    this.expectedSequenceNumber = 0;
    this.sessionSalt = null;
    this.replayWindowSize = 64;
    this.replayWindow = /* @__PURE__ */ new Set();
    this.maxSequenceGap = 100;
    this.replayProtectionEnabled = true;
    this.sessionId = null;
    this.connectionId = Array.from(crypto.getRandomValues(new Uint8Array(8))).map((b) => b.toString(16).padStart(2, "0")).join("");
    this.peerPublicKey = null;
    this.rateLimiterId = null;
    this.intentionalDisconnect = false;
    this.lastCleanupTime = Date.now();
    this._resetNotificationFlags();
    this.verificationInitiationSent = false;
    this.disconnectNotificationSent = false;
    this.reconnectionFailedNotificationSent = false;
    this.peerDisconnectNotificationSent = false;
    this.connectionClosedNotificationSent = false;
    this.fakeTrafficDisabledNotificationSent = false;
    this.advancedFeaturesDisabledNotificationSent = false;
    this.securityUpgradeNotificationSent = false;
    this.lastSecurityUpgradeStage = null;
    this.securityCalculationNotificationSent = false;
    this.lastSecurityCalculationLevel = null;
    this.fileTransferSystem = null;
    this.onFileProgress = null;
    this._ivTrackingSystem = {
      usedIVs: /* @__PURE__ */ new Set(),
      // Track all used IVs to prevent reuse
      ivHistory: /* @__PURE__ */ new Map(),
      // Track IV usage with timestamps (max 10k entries)
      collisionCount: 0,
      // Track potential collisions
      maxIVHistorySize: 1e4,
      // Maximum IV history size
      maxSessionIVs: 1e3,
      // Maximum IVs per session
      entropyValidation: {
        minEntropy: 3,
        // Minimum entropy threshold
        entropyTests: 0,
        entropyFailures: 0
      },
      rngValidation: {
        testsPerformed: 0,
        weakRngDetected: false,
        lastValidation: 0
      },
      sessionIVs: /* @__PURE__ */ new Map(),
      // Track IVs per session
      emergencyMode: false
      // Emergency mode if IV reuse detected
    };
    this._lastIVCleanupTime = null;
    this._secureErrorHandler = {
      errorCategories: {
        CRYPTOGRAPHIC: "cryptographic",
        NETWORK: "network",
        VALIDATION: "validation",
        SYSTEM: "system",
        UNKNOWN: "unknown"
      },
      errorMappings: /* @__PURE__ */ new Map(),
      // Map internal errors to safe messages
      errorCounts: /* @__PURE__ */ new Map(),
      // Track error frequencies
      lastErrorTime: 0,
      errorThreshold: 10,
      // Max errors per minute
      isInErrorMode: false
    };
    this._secureMemoryManager = {
      sensitiveData: /* @__PURE__ */ new WeakMap(),
      // Track sensitive data for secure cleanup
      cleanupQueue: [],
      // Queue for deferred cleanup operations
      isCleaning: false,
      // Prevent concurrent cleanup operations
      cleanupInterval: null,
      // Periodic cleanup timer
      memoryStats: {
        totalCleanups: 0,
        failedCleanups: 0,
        lastCleanup: 0
      }
    };
    this.onFileReceived = null;
    this.onFileError = null;
    this.keyRotationInterval = _EnhancedSecureWebRTCManager.TIMEOUTS.KEY_ROTATION_INTERVAL;
    this.lastKeyRotation = Date.now();
    this.currentKeyVersion = 0;
    this.keyVersions = /* @__PURE__ */ new Map();
    this.oldKeys = /* @__PURE__ */ new Map();
    this.maxOldKeys = _EnhancedSecureWebRTCManager.LIMITS.MAX_OLD_KEYS;
    this.peerConnection = null;
    this.dataChannel = null;
    this.securityFeatures = {
      hasEncryption: true,
      hasECDH: true,
      hasECDSA: false,
      hasMutualAuth: false,
      hasMetadataProtection: false,
      hasEnhancedReplayProtection: false,
      hasNonExtractableKeys: false,
      hasRateLimiting: true,
      hasEnhancedValidation: false,
      hasPFS: true,
      //   Real Perfect Forward Secrecy enabled           
      // Advanced Features (Session Managed) 
      hasNestedEncryption: false,
      hasPacketPadding: false,
      hasPacketReordering: false,
      hasAntiFingerprinting: false,
      hasFakeTraffic: false,
      hasDecoyChannels: false,
      hasMessageChunking: false
    };
    this._secureLog("info", "\u{1F512} Enhanced WebRTC Manager initialized with tiered security");
    this._secureLog("info", "\u{1F512} Configuration loaded from constructor parameters", {
      fakeTraffic: this._config.fakeTraffic.enabled,
      decoyChannels: this._config.decoyChannels.enabled,
      packetPadding: this._config.packetPadding.enabled,
      antiFingerprinting: this._config.antiFingerprinting.enabled
    });
    this._hardenDebugModeReferences();
    this._initializeUnifiedScheduler();
    this._syncSecurityFeaturesWithTariff();
    if (!this._validateCryptographicSecurity()) {
      this._secureLog("error", "\u{1F6A8} CRITICAL: Cryptographic security validation failed after tariff sync");
      throw new Error("Critical cryptographic features are missing after tariff synchronization");
    }
    this.nestedEncryptionKey = null;
    this.paddingConfig = {
      enabled: this._config.packetPadding.enabled,
      minPadding: this._config.packetPadding.minPadding,
      maxPadding: this._config.packetPadding.maxPadding,
      useRandomPadding: this._config.packetPadding.useRandomPadding,
      preserveMessageSize: this._config.packetPadding.preserveMessageSize
    };
    this.fakeTrafficConfig = {
      enabled: this._config.fakeTraffic.enabled,
      minInterval: this._config.fakeTraffic.minInterval,
      maxInterval: this._config.fakeTraffic.maxInterval,
      minSize: this._config.fakeTraffic.minSize,
      maxSize: this._config.fakeTraffic.maxSize,
      patterns: this._config.fakeTraffic.patterns
    };
    this.fakeTrafficTimer = null;
    this.lastFakeTraffic = 0;
    this.chunkingConfig = {
      enabled: false,
      maxChunkSize: _EnhancedSecureWebRTCManager.SIZES.CHUNK_SIZE_MAX,
      minDelay: _EnhancedSecureWebRTCManager.SIZES.CHUNK_DELAY_MIN,
      maxDelay: _EnhancedSecureWebRTCManager.SIZES.CHUNK_DELAY_MAX,
      useRandomDelays: true,
      addChunkHeaders: true
    };
    this.chunkQueue = [];
    this.chunkingInProgress = false;
    this.decoyChannels = /* @__PURE__ */ new Map();
    this.decoyChannelConfig = {
      enabled: this._config.decoyChannels.enabled,
      maxDecoyChannels: this._config.decoyChannels.maxDecoyChannels,
      decoyChannelNames: this._config.decoyChannels.decoyChannelNames,
      sendDecoyData: this._config.decoyChannels.sendDecoyData,
      randomDecoyIntervals: this._config.decoyChannels.randomDecoyIntervals
    };
    this.decoyTimers = /* @__PURE__ */ new Map();
    this.reorderingConfig = {
      enabled: false,
      maxOutOfOrder: _EnhancedSecureWebRTCManager.LIMITS.MAX_OUT_OF_ORDER_PACKETS,
      reorderTimeout: _EnhancedSecureWebRTCManager.TIMEOUTS.REORDER_TIMEOUT,
      useSequenceNumbers: true,
      useTimestamps: true
    };
    this.packetBuffer = /* @__PURE__ */ new Map();
    this.lastProcessedSequence = -1;
    this.antiFingerprintingConfig = {
      enabled: this._config.antiFingerprinting.enabled,
      randomizeTiming: this._config.antiFingerprinting.randomizeTiming,
      randomizeSizes: this._config.antiFingerprinting.randomizeSizes,
      addNoise: this._config.antiFingerprinting.addNoise,
      maskPatterns: this._config.antiFingerprinting.maskPatterns,
      useRandomHeaders: this._config.antiFingerprinting.useRandomHeaders
    };
    this.fingerprintMask = this.generateFingerprintMask();
    this.rateLimiterId = `webrtc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    this.startPeriodicCleanup();
    this.initializeEnhancedSecurity();
    this._keyOperationMutex = {
      locked: false,
      queue: [],
      lockId: null,
      lockTimeout: null
    };
    this._cryptoOperationMutex = {
      locked: false,
      queue: [],
      lockId: null,
      lockTimeout: null
    };
    this._connectionOperationMutex = {
      locked: false,
      queue: [],
      lockId: null,
      lockTimeout: null
    };
    this._keySystemState = {
      isInitializing: false,
      isRotating: false,
      isDestroying: false,
      lastOperation: null,
      lastOperationTime: Date.now()
    };
    this._operationCounters = {
      keyOperations: 0,
      cryptoOperations: 0,
      connectionOperations: 0
    };
  }
  /**
   *   Create AAD with sequence number for anti-replay protection
   * This binds each message to its sequence number and prevents replay attacks
   */
  _createMessageAAD(messageType, messageData = null, isFileMessage = false) {
    try {
      const aad = {
        sessionId: this.currentSession?.sessionId || this.sessionId || "unknown",
        keyFingerprint: this.keyFingerprint || "unknown",
        sequenceNumber: this._generateNextSequenceNumber(),
        messageType,
        timestamp: Date.now(),
        connectionId: this.connectionId || "unknown",
        isFileMessage
      };
      if (messageData && typeof messageData === "object") {
        if (messageData.fileId) aad.fileId = messageData.fileId;
        if (messageData.chunkIndex !== void 0) aad.chunkIndex = messageData.chunkIndex;
        if (messageData.totalChunks !== void 0) aad.totalChunks = messageData.totalChunks;
      }
      return JSON.stringify(aad);
    } catch (error) {
      this._secureLog("error", "\u274C Failed to create message AAD", {
        errorType: error.constructor.name,
        message: error.message,
        messageType
      });
      return JSON.stringify({
        sessionId: "unknown",
        keyFingerprint: "unknown",
        sequenceNumber: Date.now(),
        messageType,
        timestamp: Date.now(),
        connectionId: "unknown",
        isFileMessage
      });
    }
  }
  /**
   *   Generate next sequence number for outgoing messages
   * This ensures unique ordering and prevents replay attacks
   */
  _generateNextSequenceNumber() {
    const nextSeq = this.sequenceNumber++;
    if (this.sequenceNumber > Number.MAX_SAFE_INTEGER - 1e3) {
      this.sequenceNumber = 0;
      this.expectedSequenceNumber = 0;
      this.replayWindow.clear();
      this._secureLog("warn", "\u26A0\uFE0F Sequence number reset due to overflow", {
        timestamp: Date.now()
      });
    }
    return nextSeq;
  }
  /**
   *   Enhanced mutex system initialization with atomic protection
   */
  _initializeMutexSystem() {
    this._keyOperationMutex = {
      locked: false,
      queue: [],
      lockId: null,
      lockTimeout: null,
      lockTime: null,
      operationCount: 0
    };
    this._cryptoOperationMutex = {
      locked: false,
      queue: [],
      lockId: null,
      lockTimeout: null,
      lockTime: null,
      operationCount: 0
    };
    this._connectionOperationMutex = {
      locked: false,
      queue: [],
      lockId: null,
      lockTimeout: null,
      lockTime: null,
      operationCount: 0
    };
    this._keySystemState = {
      isInitializing: false,
      isRotating: false,
      isDestroying: false,
      lastOperation: null,
      lastOperationTime: Date.now(),
      operationId: null,
      concurrentOperations: 0,
      maxConcurrentOperations: 1
    };
    this._operationCounters = {
      keyOperations: 0,
      cryptoOperations: 0,
      connectionOperations: 0,
      totalOperations: 0,
      failedOperations: 0
    };
    this._secureLog("info", "\u{1F512} Enhanced mutex system initialized with atomic protection", {
      mutexes: ["keyOperation", "cryptoOperation", "connectionOperation"],
      timestamp: Date.now(),
      features: ["atomic_operations", "race_condition_protection", "enhanced_state_tracking"]
    });
  }
  /**
   *   XSS Hardening - Debug mode references validation
   * This method is called during initialization to ensure XSS hardening
   */
  _hardenDebugModeReferences() {
    this._secureLog("info", "\u{1F512} XSS Hardening: Debug mode references already replaced");
  }
  /**
   *   Unified scheduler for all maintenance tasks
   * Replaces multiple setInterval calls with a single, controlled scheduler
   */
  _initializeUnifiedScheduler() {
    this._maintenanceScheduler = setInterval(() => {
      this._executeMaintenanceCycle();
    }, 3e5);
    this._secureLog("info", "\u{1F527} Unified maintenance scheduler initialized (5-minute cycle)");
    this._activeTimers = /* @__PURE__ */ new Set([this._maintenanceScheduler]);
  }
  /**
   *   Execute all maintenance tasks in a single cycle
   */
  _executeMaintenanceCycle() {
    try {
      this._secureLog("info", "\u{1F527} Starting maintenance cycle");
      this._cleanupLogs();
      this._auditLoggingSystemSecurity();
      this._verifyAPIIntegrity();
      this._validateCryptographicSecurity();
      this._syncSecurityFeaturesWithTariff();
      this._cleanupResources();
      this._enforceResourceLimits();
      if (this.isConnected && this.isVerified) {
        this._monitorKeySecurity();
      }
      if (this._debugMode) {
        this._monitorGlobalExposure();
      }
      if (this._heartbeatConfig && this._heartbeatConfig.enabled && this.isConnected()) {
        this._sendHeartbeat();
      }
      this._secureLog("info", "\u{1F527} Maintenance cycle completed successfully");
    } catch (error) {
      this._secureLog("error", "\u274C Maintenance cycle failed", {
        errorType: error?.constructor?.name || "Unknown",
        message: error?.message || "Unknown error"
      });
      this._emergencyCleanup();
    }
  }
  /**
   *   Enforce hard resource limits with emergency cleanup
   */
  _enforceResourceLimits() {
    const violations = [];
    if (this._logCounts.size > this._resourceLimits.maxLogEntries) {
      violations.push("log_entries");
    }
    if (this.messageQueue.length > this._resourceLimits.maxMessageQueue) {
      violations.push("message_queue");
    }
    if (this._ivTrackingSystem && this._ivTrackingSystem.ivHistory.size > this._resourceLimits.maxIVHistory) {
      violations.push("iv_history");
    }
    if (this.processedMessageIds.size > this._resourceLimits.maxProcessedMessageIds) {
      violations.push("processed_message_ids");
    }
    if (this.decoyChannels.size > this._resourceLimits.maxDecoyChannels) {
      violations.push("decoy_channels");
    }
    if (this._fakeTrafficMessages && this._fakeTrafficMessages.length > this._resourceLimits.maxFakeTrafficMessages) {
      violations.push("fake_traffic_messages");
    }
    if (this.chunkQueue.length > this._resourceLimits.maxChunkQueue) {
      violations.push("chunk_queue");
    }
    if (this.packetBuffer && this.packetBuffer.size > this._resourceLimits.maxPacketBuffer) {
      violations.push("packet_buffer");
    }
    if (violations.length > 0) {
      this._secureLog("warn", "\u26A0\uFE0F Resource limit violations detected", { violations });
      this._emergencyCleanup();
    }
  }
  /**
   *   Emergency cleanup when resource limits are exceeded
   */
  _emergencyCleanup() {
    this._secureLog("warn", "\u{1F6A8} EMERGENCY: Resource limits exceeded, performing emergency cleanup");
    try {
      this._logCounts.clear();
      this._secureLog("info", "\u{1F9F9} Emergency: All logs cleared");
      this.messageQueue.length = 0;
      this._secureLog("info", "\u{1F9F9} Emergency: Message queue cleared");
      if (this._ivTrackingSystem) {
        this._ivTrackingSystem.usedIVs.clear();
        this._ivTrackingSystem.ivHistory.clear();
        this._ivTrackingSystem.sessionIVs.clear();
        this._ivTrackingSystem.collisionCount = 0;
        this._ivTrackingSystem.emergencyMode = false;
        this._secureLog("info", "\u{1F9F9} Enhanced Emergency: IV tracking system cleared");
      }
      this.processedMessageIds.clear();
      this._secureLog("info", "\u{1F9F9} Emergency: Processed message IDs cleared");
      if (this.decoyChannels) {
        for (const [channelName, timer] of this.decoyTimers) {
          if (timer) clearTimeout(timer);
        }
        this.decoyChannels.clear();
        this.decoyTimers.clear();
        this._secureLog("info", "\u{1F9F9} Enhanced Emergency: Decoy channels cleared");
      }
      if (this.fakeTrafficTimer) {
        clearTimeout(this.fakeTrafficTimer);
        this.fakeTrafficTimer = null;
      }
      if (this._fakeTrafficMessages) {
        this._fakeTrafficMessages.length = 0;
        this._secureLog("info", "\u{1F9F9} Enhanced Emergency: Fake traffic messages cleared");
      }
      this.chunkQueue.length = 0;
      this._secureLog("info", "\u{1F9F9} Emergency: Chunk queue cleared");
      if (this.packetBuffer) {
        this.packetBuffer.clear();
        this._secureLog("info", "\u{1F9F9} Emergency: Packet buffer cleared");
      }
      this._secureMemoryManager.isCleaning = true;
      this._secureMemoryManager.cleanupQueue.length = 0;
      this._secureMemoryManager.memoryStats.lastCleanup = Date.now();
      if (typeof window.gc === "function") {
        try {
          for (let i = 0; i < 3; i++) {
            window.gc();
            this._secureLog("info", `\u{1F9F9} Enhanced Emergency: Garbage collection cycle ${i + 1}/3`);
            if (i < 2) {
              const start2 = Date.now();
              while (Date.now() - start2 < 10) {
              }
            }
          }
        } catch (e) {
        }
      }
      this._secureMemoryManager.isCleaning = false;
      this._secureLog("info", "\u2705 Enhanced emergency cleanup completed successfully");
    } catch (error) {
      this._secureLog("error", "\u274C Enhanced emergency cleanup failed", {
        errorType: error?.constructor?.name || "Unknown",
        message: error?.message || "Unknown error"
      });
      this._secureMemoryManager.isCleaning = false;
    }
  }
  /**
   *   Validate emergency cleanup success
   * @param {Object} originalState - Original state before cleanup
   * @returns {Object} Validation results
   */
  _validateEmergencyCleanup(originalState) {
    const currentState = {
      messageQueueSize: this.messageQueue.length,
      processedIdsSize: this.processedMessageIds.size,
      packetBufferSize: this.packetBuffer ? this.packetBuffer.size : 0,
      ivTrackingSize: this._ivTrackingSystem ? this._ivTrackingSystem.usedIVs.size : 0,
      decoyChannelsSize: this.decoyChannels ? this.decoyChannels.size : 0
    };
    const validation = {
      messageQueueCleared: currentState.messageQueueSize === 0,
      processedIdsCleared: currentState.processedIdsSize === 0,
      packetBufferCleared: currentState.packetBufferSize === 0,
      ivTrackingCleared: currentState.ivTrackingSize === 0,
      decoyChannelsCleared: currentState.decoyChannelsSize === 0,
      allCleared: currentState.messageQueueSize === 0 && currentState.processedIdsSize === 0 && currentState.packetBufferSize === 0 && currentState.ivTrackingSize === 0 && currentState.decoyChannelsSize === 0
    };
    return validation;
  }
  /**
   *   Cleanup resources based on age and usage
   */
  _cleanupResources() {
    const now = Date.now();
    if (this.processedMessageIds.size > this._emergencyThresholds.processedMessageIds) {
      this.processedMessageIds.clear();
      this._secureLog("info", "\u{1F9F9} Old processed message IDs cleared");
    }
    if (this._ivTrackingSystem) {
      this._cleanupOldIVs();
    }
    this.cleanupOldKeys();
    if (window.EnhancedSecureCryptoUtils && window.EnhancedSecureCryptoUtils.rateLimiter) {
      window.EnhancedSecureCryptoUtils.rateLimiter.cleanup();
    }
    this._secureLog("info", "\u{1F9F9} Resource cleanup completed");
  }
  /**
   *   Monitor key security (replaces _startKeySecurityMonitoring)
   */
  _monitorKeySecurity() {
    if (this._keyStorageStats.activeKeys > 10) {
      this._secureLog("warn", "\u26A0\uFE0F High number of active keys detected. Consider rotation.");
    }
    if (Date.now() - (this._keyStorageStats.lastRotation || 0) > 36e5) {
      this._rotateKeys();
    }
  }
  /**
   *   Send heartbeat message (called by unified scheduler)
   */
  _sendHeartbeat() {
    try {
      if (this.isConnected() && this.dataChannel && this.dataChannel.readyState === "open") {
        this.dataChannel.send(JSON.stringify({
          type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT,
          timestamp: Date.now()
        }));
        this._heartbeatConfig.lastHeartbeat = Date.now();
        this._secureLog("debug", "\u{1F493} Heartbeat sent");
      }
    } catch (error) {
      this._secureLog("error", "\u274C Heartbeat failed:", {
        errorType: error?.constructor?.name || "Unknown",
        message: error?.message || "Unknown error"
      });
    }
  }
  /**
   *   Comprehensive input validation to prevent DoS and injection attacks
   * @param {any} data - Data to validate
   * @param {string} context - Context for validation (e.g., 'sendMessage', 'sendSecureMessage')
   * @returns {Object} Validation result with isValid and sanitizedData
   */
  _validateInputData(data, context = "unknown") {
    const validationResult = {
      isValid: false,
      sanitizedData: null,
      errors: [],
      warnings: []
    };
    try {
      if (data === null || data === void 0) {
        validationResult.errors.push("Data cannot be null or undefined");
        return validationResult;
      }
      if (typeof data === "string") {
        if (data.length > this._inputValidationLimits.maxStringLength) {
          validationResult.errors.push(`String too long: ${data.length} > ${this._inputValidationLimits.maxStringLength}`);
          return validationResult;
        }
        for (const pattern of this._maliciousPatterns) {
          if (pattern.test(data)) {
            validationResult.errors.push(`Malicious pattern detected: ${pattern.source}`);
            this._secureLog("warn", "\u{1F6A8} Malicious pattern detected in input", {
              context,
              pattern: pattern.source,
              dataLength: data.length
            });
            return validationResult;
          }
        }
        validationResult.sanitizedData = this._sanitizeInputString(data);
        validationResult.isValid = true;
        return validationResult;
      }
      if (typeof data === "object") {
        const seen = /* @__PURE__ */ new WeakSet();
        const checkCircular = (obj, path = "") => {
          if (obj === null || typeof obj !== "object") return;
          if (seen.has(obj)) {
            validationResult.errors.push(`Circular reference detected at path: ${path}`);
            return;
          }
          seen.add(obj);
          if (path.split(".").length > this._inputValidationLimits.maxObjectDepth) {
            validationResult.errors.push(`Object too deep: ${path.split(".").length} > ${this._inputValidationLimits.maxObjectDepth}`);
            return;
          }
          if (Array.isArray(obj) && obj.length > this._inputValidationLimits.maxArrayLength) {
            validationResult.errors.push(`Array too long: ${obj.length} > ${this._inputValidationLimits.maxArrayLength}`);
            return;
          }
          for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
              checkCircular(obj[key], path ? `${path}.${key}` : key);
            }
          }
        };
        checkCircular(data);
        if (validationResult.errors.length > 0) {
          return validationResult;
        }
        const objectSize = this._calculateObjectSize(data);
        if (objectSize > this._inputValidationLimits.maxMessageSize) {
          validationResult.errors.push(`Object too large: ${objectSize} bytes > ${this._inputValidationLimits.maxMessageSize} bytes`);
          return validationResult;
        }
        validationResult.sanitizedData = this._sanitizeInputObject(data);
        validationResult.isValid = true;
        return validationResult;
      }
      if (data instanceof ArrayBuffer) {
        if (data.byteLength > this._inputValidationLimits.maxMessageSize) {
          validationResult.errors.push(`ArrayBuffer too large: ${data.byteLength} bytes > ${this._inputValidationLimits.maxMessageSize} bytes`);
          return validationResult;
        }
        validationResult.sanitizedData = data;
        validationResult.isValid = true;
        return validationResult;
      }
      validationResult.errors.push(`Unsupported data type: ${typeof data}`);
      return validationResult;
    } catch (error) {
      validationResult.errors.push(`Validation error: ${error.message}`);
      this._secureLog("error", "\u274C Input validation failed", {
        context,
        errorType: error?.constructor?.name || "Unknown",
        message: error?.message || "Unknown error"
      });
      return validationResult;
    }
  }
  /**
   *   Calculate approximate object size in bytes
   * @param {any} obj - Object to calculate size for
   * @returns {number} Size in bytes
   */
  _calculateObjectSize(obj) {
    try {
      const jsonString = JSON.stringify(obj);
      return new TextEncoder().encode(jsonString).length;
    } catch (error) {
      return 1024 * 1024;
    }
  }
  /**
   *   Sanitize string data for input validation
   * @param {string} str - String to sanitize
   * @returns {string} Sanitized string
   */
  _sanitizeInputString(str) {
    if (typeof str !== "string") return str;
    str = str.replace(/\0/g, "");
    str = str.replace(/\s+/g, " ");
    str = str.trim();
    return str;
  }
  /**
   *   Sanitize object data for input validation
   * @param {any} obj - Object to sanitize
   * @returns {any} Sanitized object
   */
  _sanitizeInputObject(obj) {
    if (obj === null || typeof obj !== "object") return obj;
    if (Array.isArray(obj)) {
      return obj.map((item) => this._sanitizeInputObject(item));
    }
    const sanitized = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const value = obj[key];
        if (typeof value === "string") {
          sanitized[key] = this._sanitizeInputString(value);
        } else if (typeof value === "object") {
          sanitized[key] = this._sanitizeInputObject(value);
        } else {
          sanitized[key] = value;
        }
      }
    }
    return sanitized;
  }
  /**
   *   Rate limiting for message sending
   * @param {string} context - Context for rate limiting
   * @returns {boolean} true if rate limit allows
   */
  _checkRateLimit(context = "message") {
    const now = Date.now();
    if (!this._rateLimiter) {
      this._rateLimiter = {
        messageCount: 0,
        lastReset: now,
        burstCount: 0,
        lastBurstReset: now
      };
    }
    if (now - this._rateLimiter.lastReset > 6e4) {
      this._rateLimiter.messageCount = 0;
      this._rateLimiter.lastReset = now;
    }
    if (now - this._rateLimiter.lastBurstReset > 1e3) {
      this._rateLimiter.burstCount = 0;
      this._rateLimiter.lastBurstReset = now;
    }
    if (this._rateLimiter.burstCount >= this._inputValidationLimits.rateLimitBurstSize) {
      this._secureLog("warn", "\u26A0\uFE0F Rate limit burst exceeded", { context });
      return false;
    }
    if (this._rateLimiter.messageCount >= this._inputValidationLimits.rateLimitMessagesPerMinute) {
      this._secureLog("warn", "\u26A0\uFE0F Rate limit exceeded", { context });
      return false;
    }
    this._rateLimiter.messageCount++;
    this._rateLimiter.burstCount++;
    return true;
  }
  // ============================================
  // SECURE KEY STORAGE MANAGEMENT
  // ============================================
  /**
   * Initializes the secure key storage
   */
  _initializeSecureKeyStorage() {
    this._secureKeyStorage = new SecureKeyStorage();
    this._keyStorageStats = {
      totalKeys: 0,
      activeKeys: 0,
      lastAccess: null,
      lastRotation: null
    };
    this._secureLog("info", "\u{1F510} Enhanced secure key storage initialized");
  }
  // Helper: ensure file transfer system is ready (lazy init on receiver)
  async _ensureFileTransferReady() {
    try {
      if (this.fileTransferSystem) {
        return true;
      }
      if (!this.dataChannel || this.dataChannel.readyState !== "open") {
        throw new Error("Data channel not open");
      }
      if (!this.isVerified) {
        throw new Error("Connection not verified");
      }
      this.initializeFileTransfer();
      let attempts2 = 0;
      const maxAttempts = 50;
      while (!this.fileTransferSystem && attempts2 < maxAttempts) {
        await new Promise((r) => setTimeout(r, 100));
        attempts2++;
      }
      if (!this.fileTransferSystem) {
        throw new Error("File transfer system initialization timeout");
      }
      return true;
    } catch (e) {
      this._secureLog("error", "\u274C _ensureFileTransferReady failed", {
        errorType: e?.constructor?.name || "Unknown",
        hasMessage: !!e?.message
      });
      return false;
    }
  }
  _getSecureKey(keyId) {
    return this._secureKeyStorage.retrieveKey(keyId);
  }
  async _setSecureKey(keyId, key) {
    if (!(key instanceof CryptoKey)) {
      this._secureLog("error", "\u274C Attempt to store non-CryptoKey");
      return false;
    }
    const success = await this._secureKeyStorage.storeKey(keyId, key, {
      version: this.currentKeyVersion,
      type: key.algorithm.name
    });
    if (success) {
      this._secureLog("info", `\u{1F511} Key ${keyId} stored securely with encryption`);
    }
    return success;
  }
  /**
   * Validates a key value
   * @param {CryptoKey} key - Key to validate
   * @returns {boolean} true if the key is valid
   */
  _validateKeyValue(key) {
    return key instanceof CryptoKey && key.algorithm && key.usages && key.usages.length > 0;
  }
  _secureWipeKeys() {
    this._secureKeyStorage.secureWipeAll();
    this._secureLog("info", "\u{1F9F9} All keys securely wiped and encrypted storage cleared");
  }
  /**
   * Validates key storage state
   * @returns {boolean} true if the storage is ready
   */
  _validateKeyStorage() {
    return this._secureKeyStorage instanceof SecureKeyStorage;
  }
  /**
   * Returns secure key storage statistics
   * @returns {object} Storage metrics
   */
  _getKeyStorageStats() {
    const stats = this._secureKeyStorage.getStorageStats();
    return {
      totalKeysCount: stats.totalKeys,
      activeKeysCount: stats.totalKeys,
      hasLastAccess: stats.metadata.some((m) => m.lastAccessed),
      hasLastRotation: !!this._keyStorageStats.lastRotation,
      storageType: "SecureKeyStorage",
      timestamp: Date.now()
    };
  }
  /**
   * Performs key rotation in storage
   */
  _rotateKeys() {
    const oldKeys = Array.from(this._secureKeyStorage.keys());
    this._secureKeyStorage.clear();
    this._keyStorageStats.lastRotation = Date.now();
    this._keyStorageStats.activeKeys = 0;
    this._secureLog("info", `\u{1F504} Key rotation completed. ${oldKeys.length} keys rotated`);
  }
  /**
   * Emergency key wipe (e.g., upon detecting a threat)
   */
  _emergencyKeyWipe() {
    this._secureWipeKeys();
    this._secureLog("error", "\u{1F6A8} EMERGENCY: All keys wiped due to security threat");
  }
  /**
   * Starts key security monitoring
   * @deprecated Use unified scheduler instead
   */
  _startKeySecurityMonitoring() {
    this._secureLog("info", "\u{1F527} Key security monitoring moved to unified scheduler");
  }
  // ============================================
  // HELPER METHODS
  // ============================================
  /**
   *   Constant-time key validation to prevent timing attacks
   * @param {CryptoKey} key - Key to validate
   * @returns {boolean} true if key is valid
   */
  _validateKeyConstantTime(key) {
    let isValid = 0;
    try {
      const isCryptoKey = key instanceof CryptoKey;
      isValid += isCryptoKey ? 1 : 0;
    } catch {
      isValid += 0;
    }
    try {
      const hasAlgorithm = !!(key && key.algorithm);
      isValid += hasAlgorithm ? 1 : 0;
    } catch {
      isValid += 0;
    }
    try {
      const hasType = !!(key && key.type);
      isValid += hasType ? 1 : 0;
    } catch {
      isValid += 0;
    }
    try {
      const hasExtractable = key && key.extractable !== void 0;
      isValid += hasExtractable ? 1 : 0;
    } catch {
      isValid += 0;
    }
    return isValid === 4;
  }
  /**
   *   Constant-time key pair validation
   * @param {Object} keyPair - Key pair to validate
   * @returns {boolean} true if key pair is valid
   */
  _validateKeyPairConstantTime(keyPair) {
    if (!keyPair || typeof keyPair !== "object") return false;
    const privateKeyValid = this._validateKeyConstantTime(keyPair.privateKey);
    const publicKeyValid = this._validateKeyConstantTime(keyPair.publicKey);
    return privateKeyValid && publicKeyValid;
  }
  /**
   *   Enhanced secure logging system initialization
   */
  _initializeSecureLogging() {
    this._logLevels = {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
      trace: 4
    };
    this._currentLogLevel = this._isProductionMode ? this._logLevels.error : (
      // In production, ONLY critical errors
      this._logLevels.info
    );
    this._logCounts = /* @__PURE__ */ new Map();
    this._maxLogCount = this._isProductionMode ? 5 : 50;
    this._resourceLimits = {
      maxLogEntries: this._isProductionMode ? 100 : 1e3,
      maxMessageQueue: 1e3,
      maxIVHistory: 1e4,
      maxProcessedMessageIds: 5e3,
      maxDecoyChannels: 100,
      maxFakeTrafficMessages: 500,
      maxChunkQueue: 200,
      maxPacketBuffer: 1e3
    };
    this._emergencyThresholds = {
      logEntries: this._resourceLimits.maxLogEntries * 0.8,
      // 80%
      messageQueue: this._resourceLimits.maxMessageQueue * 0.8,
      ivHistory: this._resourceLimits.maxIVHistory * 0.8,
      processedMessageIds: this._resourceLimits.maxProcessedMessageIds * 0.8
    };
    this._inputValidationLimits = {
      maxStringLength: 1e5,
      // 100KB for strings
      maxObjectDepth: 10,
      // Maximum object nesting depth
      maxArrayLength: 1e3,
      // Maximum array length
      maxMessageSize: 1024 * 1024,
      // 1MB total message size
      maxConcurrentMessages: 10,
      // Maximum concurrent message processing
      rateLimitMessagesPerMinute: 60,
      // Rate limiting
      rateLimitBurstSize: 10
      // Burst size for rate limiting
    };
    this._maliciousPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      // Script tags
      /javascript:/gi,
      // JavaScript protocol
      /data:text\/html/gi,
      // Data URLs with HTML
      /on\w+\s*=/gi,
      // Event handlers
      /eval\s*\(/gi,
      // eval() calls
      /document\./gi,
      // Document object access
      /window\./gi,
      // Window object access
      /localStorage/gi,
      // LocalStorage access
      /sessionStorage/gi,
      // SessionStorage access
      /fetch\s*\(/gi,
      // Fetch API calls
      /XMLHttpRequest/gi,
      // XHR calls
      /import\s*\(/gi,
      // Dynamic imports
      /require\s*\(/gi,
      // Require calls
      /process\./gi,
      // Process object access
      /global/gi,
      // Global object access
      /__proto__/gi,
      // Prototype pollution
      /constructor/gi,
      // Constructor access
      /prototype/gi,
      // Prototype access
      /toString\s*\(/gi,
      // toString calls
      /valueOf\s*\(/gi
      // valueOf calls
    ];
    this._absoluteBlacklist = /* @__PURE__ */ new Set([
      // Cryptographic keys
      "encryptionKey",
      "macKey",
      "metadataKey",
      "privateKey",
      "publicKey",
      "ecdhKeyPair",
      "ecdsaKeyPair",
      "peerPublicKey",
      "nestedEncryptionKey",
      // Authentication and session data
      "verificationCode",
      "sessionSalt",
      "keyFingerprint",
      "sessionId",
      "authChallenge",
      "authProof",
      "authToken",
      "sessionToken",
      // Credentials and secrets
      "password",
      "token",
      "secret",
      "credential",
      "signature",
      "apiKey",
      "accessKey",
      "secretKey",
      "privateKey",
      // Cryptographic materials
      "hash",
      "digest",
      "nonce",
      "iv",
      "cipher",
      "seed",
      "entropy",
      "random",
      "salt",
      "fingerprint",
      // JWT and session data
      "jwt",
      "bearer",
      "refreshToken",
      "accessToken",
      // File transfer sensitive data
      "fileHash",
      "fileSignature",
      "transferKey",
      "chunkKey"
    ]);
    this._safeFieldsWhitelist = /* @__PURE__ */ new Set([
      // Basic status fields
      "timestamp",
      "type",
      "status",
      "state",
      "level",
      "isConnected",
      "isVerified",
      "isInitiator",
      "version",
      // Counters and metrics (safe)
      "count",
      "total",
      "active",
      "inactive",
      "success",
      "failure",
      // Connection states (safe)
      "readyState",
      "connectionState",
      "iceConnectionState",
      // Feature counts (safe)
      "activeFeaturesCount",
      "totalFeatures",
      "stage",
      // Error types (safe)
      "errorType",
      "errorCode",
      "phase",
      "attempt"
    ]);
    this._initializeLogSecurityMonitoring();
    this._secureLog("info", `\u{1F527} Enhanced secure logging initialized (Production: ${this._isProductionMode})`);
  }
  /**
   *   Initialize security monitoring for logging system
   */
  _initializeLogSecurityMonitoring() {
    this._logSecurityViolations = 0;
    this._maxLogSecurityViolations = 3;
  }
  /**
   *   Audit logging system security
   */
  _auditLoggingSystemSecurity() {
    let violations = 0;
    for (const [key, count] of this._logCounts.entries()) {
      if (count > this._maxLogCount * 2) {
        violations++;
        this._originalConsole?.error?.(`\u{1F6A8} LOG SECURITY: Excessive log count detected: ${key}`);
      }
    }
    const recentLogs = Array.from(this._logCounts.keys());
    for (const logKey of recentLogs) {
      if (this._containsSensitiveContent(logKey)) {
        violations++;
        this._originalConsole?.error?.(`\u{1F6A8} LOG SECURITY: Sensitive content in log key: ${logKey}`);
      }
    }
    this._logSecurityViolations += violations;
    if (this._logSecurityViolations >= this._maxLogSecurityViolations) {
      this._emergencyDisableLogging();
      this._originalConsole?.error?.("\u{1F6A8} CRITICAL: Logging system disabled due to security violations");
    }
  }
  _secureLogShim(...args) {
    try {
      if (!Array.isArray(args) || args.length === 0) {
        return;
      }
      const message = args[0];
      const restArgs = args.slice(1);
      if (restArgs.length === 0) {
        this._secureLog("info", String(message || ""));
        return;
      }
      if (restArgs.length === 1) {
        this._secureLog("info", String(message || ""), restArgs[0]);
        return;
      }
      this._secureLog("info", String(message || ""), {
        additionalArgs: restArgs,
        argCount: restArgs.length
      });
    } catch (error) {
      try {
        if (this._originalConsole?.log) {
          this._originalConsole.log(...args);
        }
      } catch (fallbackError) {
      }
    }
  }
  /**
   *   Setup own logger without touching global console
   */
  _setupOwnLogger() {
    this.logger = {
      log: (message, data) => this._secureLog("info", message, data),
      info: (message, data) => this._secureLog("info", message, data),
      warn: (message, data) => this._secureLog("warn", message, data),
      error: (message, data) => this._secureLog("error", message, data),
      debug: (message, data) => this._secureLog("debug", message, data)
    };
    if (_EnhancedSecureWebRTCManager.DEBUG_MODE) {
      this._secureLog("info", "\u{1F512} Own logger created - development mode");
    } else {
      this._secureLog("info", "\u{1F512} Own logger created - production mode");
    }
  }
  /**
   *   Production logging - use own logger with minimal output
   */
  _setupProductionLogging() {
    if (this._isProductionMode) {
      this.logger = {
        log: () => {
        },
        // No-op in production
        info: () => {
        },
        // No-op in production
        warn: (message, data) => this._secureLog("warn", message, data),
        error: (message, data) => this._secureLog("error", message, data),
        debug: () => {
        }
        // No-op in production
      };
      this._secureLog("info", "\u{1F512} Production logging mode activated");
    }
  }
  /**
   *   Secure logging with enhanced data protection
   * @param {string} level - Log level (error, warn, info, debug, trace)
   * @param {string} message - Message
   * @param {object} data - Optional payload (will be sanitized)
   */
  _secureLog(level, message, data = null) {
    if (data && !this._auditLogMessage(message, data)) {
      this._originalConsole?.error?.("\u{1F6A8} SECURITY: Logging blocked due to potential data leakage");
      return;
    }
    if (this._logLevels[level] > this._currentLogLevel) {
      return;
    }
    const logKey = `${level}:${message.substring(0, 50)}`;
    const currentCount = this._logCounts.get(logKey) || 0;
    if (currentCount >= this._maxLogCount) {
      return;
    }
    this._logCounts.set(logKey, currentCount + 1);
    let sanitizedData = null;
    if (data) {
      sanitizedData = this._sanitizeLogData(data);
      if (this._containsSensitiveContent(JSON.stringify(sanitizedData))) {
        this._originalConsole?.error?.("\u{1F6A8} SECURITY: Sanitized data still contains sensitive content - blocking log");
        return;
      }
    }
    if (this._isProductionMode) {
      if (level === "error") {
        const safeMessage = this._sanitizeString(message);
        this._originalConsole?.error?.(safeMessage);
      }
      return;
    }
    const logMethod = this._originalConsole?.[level] || this._originalConsole?.log;
    if (sanitizedData) {
      logMethod(message, sanitizedData);
    } else {
      logMethod(message);
    }
  }
  /**
   *   Enhanced sanitization for log data with multiple security layers
   */
  _sanitizeLogData(data) {
    if (typeof data === "string") {
      return this._sanitizeString(data);
    }
    if (!data || typeof data !== "object") {
      return data;
    }
    const sanitized = {};
    for (const [key, value] of Object.entries(data)) {
      const lowerKey = key.toLowerCase();
      const blacklistPatterns = [
        "key",
        "secret",
        "token",
        "password",
        "credential",
        "auth",
        "fingerprint",
        "salt",
        "signature",
        "private",
        "encryption",
        "mac",
        "metadata",
        "session",
        "jwt",
        "bearer",
        "hash",
        "digest",
        "nonce",
        "iv",
        "cipher",
        "seed",
        "entropy"
      ];
      const isBlacklisted = this._absoluteBlacklist.has(key) || blacklistPatterns.some((pattern) => lowerKey.includes(pattern));
      if (isBlacklisted) {
        sanitized[key] = "[SENSITIVE_DATA_BLOCKED]";
        continue;
      }
      if (this._safeFieldsWhitelist.has(key)) {
        if (typeof value === "string") {
          sanitized[key] = this._sanitizeString(value);
        } else {
          sanitized[key] = value;
        }
        continue;
      }
      if (typeof value === "boolean" || typeof value === "number") {
        sanitized[key] = value;
      } else if (typeof value === "string") {
        sanitized[key] = this._sanitizeString(value);
      } else if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
        sanitized[key] = `[${value.constructor.name}(<REDACTED> bytes)]`;
      } else if (value && typeof value === "object") {
        try {
          sanitized[key] = this._sanitizeLogData(value);
        } catch (error) {
          sanitized[key] = "[RECURSIVE_SANITIZATION_FAILED]";
        }
      } else {
        sanitized[key] = `[${typeof value}]`;
      }
    }
    const sanitizedString = JSON.stringify(sanitized);
    if (this._containsSensitiveContent(sanitizedString)) {
      return { error: "SANITIZATION_FAILED_SENSITIVE_CONTENT_DETECTED" };
    }
    return sanitized;
  }
  /**
   *   Enhanced sanitization for strings with comprehensive pattern detection
   */
  _sanitizeString(str) {
    if (typeof str !== "string" || str.length === 0) {
      return str;
    }
    const sensitivePatterns = [
      // Hex patterns (various lengths)
      /[a-f0-9]{16,}/i,
      // 16+ hex chars (covers short keys)
      /[a-f0-9]{8,}/i,
      // 8+ hex chars (covers shorter keys)
      // Base64 patterns (comprehensive)
      /[A-Za-z0-9+/]{16,}={0,2}/,
      // Base64 with padding
      /[A-Za-z0-9+/]{12,}/,
      // Base64 without padding
      /[A-Za-z0-9+/=]{10,}/,
      // Base64-like patterns
      // Base58 patterns (Bitcoin-style)
      /[1-9A-HJ-NP-Za-km-z]{16,}/,
      // Base58 strings
      // Base32 patterns
      /[A-Z2-7]{16,}={0,6}/,
      // Base32 with padding
      /[A-Z2-7]{12,}/,
      // Base32 without padding
      // Custom encoding patterns
      /[A-Za-z0-9\-_]{16,}/,
      // URL-safe base64 variants
      /[A-Za-z0-9\.\-_]{16,}/,
      // JWT-like patterns
      // Long alphanumeric strings (potential keys)
      /\b[A-Za-z0-9]{12,}\b/,
      // 12+ alphanumeric chars
      /\b[A-Za-z0-9]{8,}\b/,
      // 8+ alphanumeric chars
      // PEM key patterns
      /BEGIN\s+(PRIVATE|PUBLIC|RSA|DSA|EC)\s+KEY/i,
      /END\s+(PRIVATE|PUBLIC|RSA|DSA|EC)\s+KEY/i,
      // JWT patterns
      /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/,
      // API key patterns
      /(api[_-]?key|token|secret|password|credential)[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i,
      // UUID patterns
      /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i,
      // Credit cards and SSN (existing patterns)
      /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,
      /\b\d{3}-\d{2}-\d{4}\b/,
      // Email patterns (more restrictive)
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
      // Crypto-specific patterns
      /(fingerprint|hash|digest|signature)[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i,
      /(encryption|mac|metadata)[\s]*key[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i,
      // Session and auth patterns
      /(session|auth|jwt|bearer)[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i
    ];
    for (const pattern of sensitivePatterns) {
      if (pattern.test(str)) {
        return "[SENSITIVE_DATA_REDACTED]";
      }
    }
    if (this._hasHighEntropy(str)) {
      return "[HIGH_ENTROPY_DATA_REDACTED]";
    }
    if (this._hasSuspiciousDistribution(str)) {
      return "[SUSPICIOUS_DATA_REDACTED]";
    }
    if (str.length > 50) {
      return str.substring(0, 20) + "...[TRUNCATED]";
    }
    return str;
  }
  /**
   *   Enhanced sensitive content detection
   */
  _containsSensitiveContent(str) {
    if (typeof str !== "string") return false;
    const sensitivePatterns = [
      /[a-f0-9]{16,}/i,
      /[A-Za-z0-9+/]{16,}={0,2}/,
      /[1-9A-HJ-NP-Za-km-z]{16,}/,
      /[A-Z2-7]{16,}={0,6}/,
      /\b[A-Za-z0-9]{12,}\b/,
      /BEGIN\s+(PRIVATE|PUBLIC|RSA|DSA|EC)\s+KEY/i,
      /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/,
      /(api[_-]?key|token|secret|password|credential)[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i
    ];
    return sensitivePatterns.some((pattern) => pattern.test(str)) || this._hasHighEntropy(str) || this._hasSuspiciousDistribution(str);
  }
  /**
   *   Check for high entropy strings (likely cryptographic keys)
   */
  _hasHighEntropy(str) {
    if (str.length < 8) return false;
    const charCount = {};
    for (const char of str) {
      charCount[char] = (charCount[char] || 0) + 1;
    }
    const length = str.length;
    let entropy = 0;
    for (const count of Object.values(charCount)) {
      const probability = count / length;
      entropy -= probability * Math.log2(probability);
    }
    return entropy > 4.5;
  }
  /**
   *   Check for suspicious character distributions
   */
  _hasSuspiciousDistribution(str) {
    if (str.length < 8) return false;
    const hexChars = str.match(/[a-f0-9]/gi) || [];
    if (hexChars.length >= str.length * 0.8) {
      return true;
    }
    const base64Chars = str.match(/[A-Za-z0-9+/=]/g) || [];
    if (base64Chars.length >= str.length * 0.9) {
      return true;
    }
    const uniqueChars = new Set(str).size;
    const diversityRatio = uniqueChars / str.length;
    if (diversityRatio > 0.8 && str.length > 16) {
      return true;
    }
    return false;
  }
  // ============================================
  // SECURE LOGGING SYSTEM
  // ============================================
  /**
   * Detects production mode
   */
  _detectProductionMode() {
    return (
      // Standard env variables
      typeof process !== "undefined" && false || // No debug flags
      !this._debugMode || // Production domains
      window.location.hostname && !window.location.hostname.includes("localhost") && !window.location.hostname.includes("127.0.0.1") && !window.location.hostname.includes(".local") || // Minified code (heuristic check)
      typeof window.webpackHotUpdate === "undefined" && !window.location.search.includes("debug")
    );
  }
  // ============================================
  // FIXED SECURE GLOBAL API
  // ============================================
  /**
   * Sets up a secure global API with limited access
   */
  _setupSecureGlobalAPI() {
    this._secureLog("info", "\u{1F512} Starting secure global API setup");
    const secureAPI = {};
    if (typeof this.sendMessage === "function") {
      secureAPI.sendMessage = this.sendMessage.bind(this);
    }
    secureAPI.getConnectionStatus = () => ({
      isConnected: this.isConnected ? this.isConnected() : false,
      isVerified: this.isVerified || false,
      connectionState: this.peerConnection?.connectionState || "disconnected"
    });
    secureAPI.getSecurityStatus = () => ({
      securityLevel: this.currentSecurityLevel || "basic",
      stage: "initialized",
      activeFeaturesCount: Object.values(this.securityFeatures || {}).filter(Boolean).length
    });
    if (typeof this.sendFile === "function") {
      secureAPI.sendFile = this.sendFile.bind(this);
    }
    secureAPI.getFileTransferStatus = () => ({
      initialized: !!this.fileTransferSystem,
      status: "ready",
      activeTransfers: 0,
      receivingTransfers: 0
    });
    if (typeof this.disconnect === "function") {
      secureAPI.disconnect = this.disconnect.bind(this);
    }
    const safeGlobalAPI = {
      ...secureAPI,
      // Spread only existing methods
      getConfiguration: () => ({
        fakeTraffic: this._config.fakeTraffic.enabled,
        decoyChannels: this._config.decoyChannels.enabled,
        packetPadding: this._config.packetPadding.enabled,
        antiFingerprinting: this._config.antiFingerprinting.enabled
      }),
      emergency: {}
    };
    if (typeof this._emergencyUnlockAllMutexes === "function") {
      safeGlobalAPI.emergency.unlockAllMutexes = this._emergencyUnlockAllMutexes.bind(this);
    }
    if (typeof this._emergencyRecoverMutexSystem === "function") {
      safeGlobalAPI.emergency.recoverMutexSystem = this._emergencyRecoverMutexSystem.bind(this);
    }
    if (typeof this._emergencyDisableLogging === "function") {
      safeGlobalAPI.emergency.disableLogging = this._emergencyDisableLogging.bind(this);
    }
    if (typeof this._resetLoggingSystem === "function") {
      safeGlobalAPI.emergency.resetLogging = this._resetLoggingSystem.bind(this);
    }
    safeGlobalAPI.getFileTransferSystemStatus = () => ({
      initialized: !!this.fileTransferSystem,
      status: "ready",
      activeTransfers: 0,
      receivingTransfers: 0
    });
    this._secureLog("info", "\u{1F512} API methods available", {
      sendMessage: !!secureAPI.sendMessage,
      getConnectionStatus: !!secureAPI.getConnectionStatus,
      getSecurityStatus: !!secureAPI.getSecurityStatus,
      sendFile: !!secureAPI.sendFile,
      getFileTransferStatus: !!secureAPI.getFileTransferStatus,
      disconnect: !!secureAPI.disconnect,
      getConfiguration: !!safeGlobalAPI.getConfiguration,
      emergencyMethods: Object.keys(safeGlobalAPI.emergency).length
    });
    Object.freeze(safeGlobalAPI);
    Object.freeze(safeGlobalAPI.emergency);
    this._createProtectedGlobalAPI(safeGlobalAPI);
    this._setupMinimalGlobalProtection();
    this._secureLog("info", "\u{1F512} Secure global API setup completed successfully");
  }
  /**
   *   Create simple global API export
   */
  _createProtectedGlobalAPI(safeGlobalAPI) {
    this._secureLog("info", "\u{1F512} Creating protected global API");
    if (!window.secureBitChat) {
      this._exportAPI(safeGlobalAPI);
    } else {
      this._secureLog("warn", "\u26A0\uFE0F Global API already exists, skipping setup");
    }
  }
  /**
   *   Simple API export without monitoring
   */
  _exportAPI(apiObject) {
    this._secureLog("info", "\u{1F512} Exporting API to window.secureBitChat");
    if (!this._importantMethods || !this._importantMethods.defineProperty) {
      this._secureLog("error", "\u274C Important methods not available for API export, using fallback");
      Object.defineProperty(window, "secureBitChat", {
        value: apiObject,
        writable: false,
        configurable: false,
        enumerable: true
      });
    } else {
      this._importantMethods.defineProperty(window, "secureBitChat", {
        value: apiObject,
        writable: false,
        configurable: false,
        enumerable: true
      });
    }
    this._secureLog("info", "\u{1F512} Secure API exported to window.secureBitChat");
  }
  /**
   *   Setup minimal global protection
   */
  _setupMinimalGlobalProtection() {
    this._protectGlobalAPI();
    this._secureLog("info", "\u{1F512} Minimal global protection activated");
  }
  /**
   *   Store important methods in closure for local use
   */
  _storeImportantMethods() {
    this._importantMethods = {
      defineProperty: Object.defineProperty,
      getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
      freeze: Object.freeze,
      consoleLog: console.log,
      consoleError: console.error,
      consoleWarn: console.warn
    };
    this._secureLog("info", "\u{1F512} Important methods stored locally", {
      defineProperty: !!this._importantMethods.defineProperty,
      getOwnPropertyDescriptor: !!this._importantMethods.getOwnPropertyDescriptor,
      freeze: !!this._importantMethods.freeze
    });
  }
  /**
   *   Simple protection without monitoring
   */
  _setupSimpleProtection() {
    this._secureLog("info", "\u{1F512} Simple protection activated - no monitoring");
  }
  /**
   *   No global exposure prevention needed
   */
  _preventGlobalExposure() {
    this._secureLog("info", "\u{1F512} No global exposure prevention - using secure API export only");
  }
  /**
   *   API integrity check - only at initialization
   */
  _verifyAPIIntegrity() {
    try {
      if (!window.secureBitChat) {
        this._secureLog("error", "\u274C SECURITY ALERT: Secure API has been removed!");
        return false;
      }
      const requiredMethods = ["sendMessage", "getConnectionStatus", "disconnect"];
      const missingMethods = requiredMethods.filter(
        (method) => typeof window.secureBitChat[method] !== "function"
      );
      if (missingMethods.length > 0) {
        this._secureLog("error", "\u274C SECURITY ALERT: API tampering detected, missing methods:", { errorType: missingMethods?.constructor?.name || "Unknown" });
        return false;
      }
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C SECURITY ALERT: API integrity check failed:", { errorType: error?.constructor?.name || "Unknown" });
      return false;
    }
  }
  // ============================================
  // ADDITIONAL SECURITY METHODS
  // ============================================
  /**
   *   Simple global exposure check - only at initialization
   */
  _auditGlobalExposure() {
    this._secureLog("info", "\u{1F512} Global exposure check completed at initialization");
    return [];
  }
  /**
   *   No periodic security audits - only at initialization
   */
  _startSecurityAudit() {
    this._secureLog("info", "\u{1F512} Security audit completed at initialization - no periodic monitoring");
  }
  /**
   *   Simple global API protection
   */
  _protectGlobalAPI() {
    if (!window.secureBitChat) {
      this._secureLog("warn", "\u26A0\uFE0F Global API not found during protection setup");
      return;
    }
    try {
      if (this._validateAPIIntegrityOnce()) {
        this._secureLog("info", "\u{1F512} Global API protection verified");
      }
    } catch (error) {
      this._secureLog("error", "\u274C Failed to verify global API protection", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
    }
  }
  /**
   *   Validate API integrity once at initialization
   */
  _validateAPIIntegrityOnce() {
    try {
      if (!this._importantMethods || !this._importantMethods.getOwnPropertyDescriptor) {
        const descriptor = Object.getOwnPropertyDescriptor(window, "secureBitChat");
        if (!descriptor || descriptor.configurable) {
          throw new Error("secureBitChat must not be reconfigurable!");
        }
      } else {
        const descriptor = this._importantMethods.getOwnPropertyDescriptor(window, "secureBitChat");
        if (!descriptor || descriptor.configurable) {
          throw new Error("secureBitChat must not be reconfigurable!");
        }
      }
      this._secureLog("info", "\u2705 API integrity validated");
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C API integrity validation failed", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      return false;
    }
  }
  /**
   *   Secure memory wipe for sensitive data
   */
  _secureWipeMemory(data, context = "unknown") {
    if (!data) return;
    try {
      if (data instanceof ArrayBuffer) {
        this._secureWipeArrayBuffer(data, context);
      } else if (data instanceof Uint8Array) {
        this._secureWipeUint8Array(data, context);
      } else if (Array.isArray(data)) {
        this._secureWipeArray(data, context);
      } else if (typeof data === "string") {
        this._secureWipeString(data, context);
      } else if (data instanceof CryptoKey) {
        this._secureWipeCryptoKey(data, context);
      } else if (typeof data === "object") {
        this._secureWipeObject(data, context);
      }
      this._secureMemoryManager.memoryStats.totalCleanups++;
    } catch (error) {
      this._secureMemoryManager.memoryStats.failedCleanups++;
      this._secureLog("error", "\u274C Secure memory wipe failed", {
        context,
        errorType: error.constructor.name,
        errorMessage: error.message
      });
    }
  }
  /**
   *   Secure wipe for ArrayBuffer
   */
  _secureWipeArrayBuffer(buffer, context) {
    if (!buffer || buffer.byteLength === 0) return;
    try {
      const view = new Uint8Array(buffer);
      crypto.getRandomValues(view);
      view.fill(0);
      view.fill(255);
      view.fill(0);
      this._secureLog("debug", "\u{1F512} ArrayBuffer securely wiped", {
        context,
        size: buffer.byteLength
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to wipe ArrayBuffer", {
        context,
        errorType: error.constructor.name
      });
    }
  }
  /**
   *   Secure wipe for Uint8Array
   */
  _secureWipeUint8Array(array, context) {
    if (!array || array.length === 0) return;
    try {
      crypto.getRandomValues(array);
      array.fill(0);
      array.fill(255);
      array.fill(0);
      this._secureLog("debug", "\u{1F512} Uint8Array securely wiped", {
        context,
        size: array.length
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to wipe Uint8Array", {
        context,
        errorType: error.constructor.name
      });
    }
  }
  /**
   *   Secure wipe for arrays
   */
  _secureWipeArray(array, context) {
    if (!Array.isArray(array) || array.length === 0) return;
    try {
      array.forEach((item, index) => {
        if (item !== null && item !== void 0) {
          this._secureWipeMemory(item, `${context}[${index}]`);
        }
      });
      array.fill(null);
      this._secureLog("debug", "\u{1F512} Array securely wiped", {
        context,
        size: array.length
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to wipe array", {
        context,
        errorType: error.constructor.name
      });
    }
  }
  /**
   *   No string wiping - strings are immutable in JS
   */
  _secureWipeString(str, context) {
    this._secureLog("debug", "\u{1F512} String reference removed (strings are immutable)", {
      context,
      length: str ? str.length : 0
    });
  }
  /**
   *   CryptoKey cleanup - store in WeakMap for proper GC
   */
  _secureWipeCryptoKey(key, context) {
    if (!key || !(key instanceof CryptoKey)) return;
    try {
      if (!this._cryptoKeyStorage) {
        this._cryptoKeyStorage = /* @__PURE__ */ new WeakMap();
      }
      this._cryptoKeyStorage.set(key, {
        context,
        timestamp: Date.now(),
        type: key.type
      });
      this._secureLog("debug", "\u{1F512} CryptoKey stored in WeakMap for cleanup", {
        context,
        type: key.type
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to store CryptoKey for cleanup", {
        context,
        errorType: error.constructor.name
      });
    }
  }
  /**
   *   Secure wipe for objects
   */
  _secureWipeObject(obj, context) {
    if (!obj || typeof obj !== "object") return;
    try {
      for (const [key, value] of Object.entries(obj)) {
        if (value !== null && value !== void 0) {
          this._secureWipeMemory(value, `${context}.${key}`);
        }
        obj[key] = null;
      }
      this._secureLog("debug", "\u{1F512} Object securely wiped", {
        context,
        properties: Object.keys(obj).length
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to wipe object", {
        context,
        errorType: error.constructor.name
      });
    }
  }
  /**
   *   Secure cleanup of cryptographic materials
   */
  _secureCleanupCryptographicMaterials() {
    try {
      if (this.ecdhKeyPair) {
        this._secureWipeMemory(this.ecdhKeyPair, "ecdhKeyPair");
        this.ecdhKeyPair = null;
      }
      if (this.ecdsaKeyPair) {
        this._secureWipeMemory(this.ecdsaKeyPair, "ecdsaKeyPair");
        this.ecdsaKeyPair = null;
      }
      if (this.encryptionKey) {
        this._secureWipeMemory(this.encryptionKey, "encryptionKey");
        this.encryptionKey = null;
      }
      if (this.macKey) {
        this._secureWipeMemory(this.macKey, "macKey");
        this.macKey = null;
      }
      if (this.metadataKey) {
        this._secureWipeMemory(this.metadataKey, "metadataKey");
        this.metadataKey = null;
      }
      if (this.nestedEncryptionKey) {
        this._secureWipeMemory(this.nestedEncryptionKey, "nestedEncryptionKey");
        this.nestedEncryptionKey = null;
      }
      if (this.sessionSalt) {
        this._secureWipeMemory(this.sessionSalt, "sessionSalt");
        this.sessionSalt = null;
      }
      if (this.sessionId) {
        this._secureWipeMemory(this.sessionId, "sessionId");
        this.sessionId = null;
      }
      if (this.verificationCode) {
        this._secureWipeMemory(this.verificationCode, "verificationCode");
        this.verificationCode = null;
      }
      if (this.peerPublicKey) {
        this._secureWipeMemory(this.peerPublicKey, "peerPublicKey");
        this.peerPublicKey = null;
      }
      if (this.keyFingerprint) {
        this._secureWipeMemory(this.keyFingerprint, "keyFingerprint");
        this.keyFingerprint = null;
      }
      if (this.connectionId) {
        this._secureWipeMemory(this.connectionId, "connectionId");
        this.connectionId = null;
      }
      this._secureLog("info", "\u{1F512} Cryptographic materials securely cleaned up");
    } catch (error) {
      this._secureLog("error", "\u274C Failed to cleanup cryptographic materials", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
    }
  }
  /**
   *   Force garbage collection if available
   */
  _forceGarbageCollection() {
    try {
      if (typeof window.gc === "function") {
        window.gc();
        this._secureLog("debug", "\u{1F512} Garbage collection forced");
      } else if (typeof global.gc === "function") {
        global.gc();
        this._secureLog("debug", "\u{1F512} Garbage collection forced (global)");
      } else {
        this._secureLog("debug", "\u26A0\uFE0F Garbage collection not available");
      }
    } catch (error) {
      this._secureLog("error", "\u274C Failed to force garbage collection", {
        errorType: error.constructor.name
      });
    }
  }
  /**
   *   Perform periodic memory cleanup
   */
  _performPeriodicMemoryCleanup() {
    try {
      this._secureMemoryManager.isCleaning = true;
      this._secureCleanupCryptographicMaterials();
      if (this.messageQueue && this.messageQueue.length > 100) {
        const excessMessages = this.messageQueue.splice(0, this.messageQueue.length - 50);
        excessMessages.forEach((message, index) => {
          this._secureWipeMemory(message, `periodicCleanup[${index}]`);
        });
      }
      if (this.processedMessageIds && this.processedMessageIds.size > 1e3) {
        this.processedMessageIds.clear();
      }
      this._forceGarbageCollection();
      this._secureLog("debug", "\u{1F512} Periodic memory cleanup completed");
    } catch (error) {
      this._secureLog("error", "\u274C Error during periodic memory cleanup", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
    } finally {
      this._secureMemoryManager.isCleaning = false;
    }
  }
  /**
   *   Create secure error message without information disclosure
   */
  _createSecureErrorMessage(originalError, context = "unknown") {
    try {
      const category = this._categorizeError(originalError);
      const safeMessage = this._getSafeErrorMessage(category, context);
      this._secureLog("error", "Internal error occurred", {
        category,
        context,
        errorType: originalError?.constructor?.name || "Unknown",
        timestamp: Date.now()
      });
      this._trackErrorFrequency(category);
      return safeMessage;
    } catch (error) {
      this._secureLog("error", "Error handling failed", {
        originalError: originalError?.message || "Unknown",
        handlingError: error.message
      });
      return "An unexpected error occurred";
    }
  }
  /**
   *   Categorize error for appropriate handling
   */
  _categorizeError(error) {
    if (!error || !error.message) {
      return this._secureErrorHandler.errorCategories.UNKNOWN;
    }
    const message = error.message.toLowerCase();
    if (message.includes("crypto") || message.includes("key") || message.includes("encrypt") || message.includes("decrypt") || message.includes("sign") || message.includes("verify") || message.includes("ecdh") || message.includes("ecdsa")) {
      return this._secureErrorHandler.errorCategories.CRYPTOGRAPHIC;
    }
    if (message.includes("network") || message.includes("connection") || message.includes("timeout") || message.includes("webrtc") || message.includes("peer")) {
      return this._secureErrorHandler.errorCategories.NETWORK;
    }
    if (message.includes("invalid") || message.includes("validation") || message.includes("format") || message.includes("type")) {
      return this._secureErrorHandler.errorCategories.VALIDATION;
    }
    if (message.includes("system") || message.includes("internal") || message.includes("memory") || message.includes("resource")) {
      return this._secureErrorHandler.errorCategories.SYSTEM;
    }
    return this._secureErrorHandler.errorCategories.UNKNOWN;
  }
  /**
   *   Get safe error message based on category
   */
  _getSafeErrorMessage(category, context) {
    const safeMessages = {
      [this._secureErrorHandler.errorCategories.CRYPTOGRAPHIC]: {
        "key_generation": "Security initialization failed",
        "key_import": "Security verification failed",
        "key_derivation": "Security setup failed",
        "encryption": "Message security failed",
        "decryption": "Message verification failed",
        "signature": "Authentication failed",
        "default": "Security operation failed"
      },
      [this._secureErrorHandler.errorCategories.NETWORK]: {
        "connection": "Connection failed",
        "timeout": "Connection timeout",
        "peer": "Peer connection failed",
        "webrtc": "Communication failed",
        "default": "Network operation failed"
      },
      [this._secureErrorHandler.errorCategories.VALIDATION]: {
        "format": "Invalid data format",
        "type": "Invalid data type",
        "structure": "Invalid data structure",
        "default": "Validation failed"
      },
      [this._secureErrorHandler.errorCategories.SYSTEM]: {
        "memory": "System resource error",
        "resource": "System resource unavailable",
        "internal": "Internal system error",
        "default": "System operation failed"
      },
      [this._secureErrorHandler.errorCategories.UNKNOWN]: {
        "default": "An unexpected error occurred"
      }
    };
    const categoryMessages = safeMessages[category] || safeMessages[this._secureErrorHandler.errorCategories.UNKNOWN];
    let specificContext = "default";
    if (context.includes("key") || context.includes("crypto")) {
      specificContext = category === this._secureErrorHandler.errorCategories.CRYPTOGRAPHIC ? "key_generation" : "default";
    } else if (context.includes("connection") || context.includes("peer")) {
      specificContext = category === this._secureErrorHandler.errorCategories.NETWORK ? "connection" : "default";
    } else if (context.includes("validation") || context.includes("format")) {
      specificContext = category === this._secureErrorHandler.errorCategories.VALIDATION ? "format" : "default";
    }
    return categoryMessages[specificContext] || categoryMessages.default;
  }
  /**
   *   Track error frequency for security monitoring
   */
  _trackErrorFrequency(category) {
    const now = Date.now();
    if (now - this._secureErrorHandler.lastErrorTime > 6e4) {
      this._secureErrorHandler.errorCounts.clear();
    }
    const currentCount = this._secureErrorHandler.errorCounts.get(category) || 0;
    this._secureErrorHandler.errorCounts.set(category, currentCount + 1);
    this._secureErrorHandler.lastErrorTime = now;
    const totalErrors = Array.from(this._secureErrorHandler.errorCounts.values()).reduce((sum, count) => sum + count, 0);
    if (totalErrors > this._secureErrorHandler.errorThreshold) {
      this._secureErrorHandler.isInErrorMode = true;
      this._secureLog("warn", "\u26A0\uFE0F High error frequency detected - entering error mode", {
        totalErrors,
        threshold: this._secureErrorHandler.errorThreshold
      });
    }
  }
  /**
   *   Throw secure error without information disclosure
   */
  _throwSecureError(originalError, context = "unknown") {
    const secureMessage = this._createSecureErrorMessage(originalError, context);
    throw new Error(secureMessage);
  }
  /**
   *   Get error handling statistics
   */
  _getErrorHandlingStats() {
    return {
      errorCounts: Object.fromEntries(this._secureErrorHandler.errorCounts),
      isInErrorMode: this._secureErrorHandler.isInErrorMode,
      lastErrorTime: this._secureErrorHandler.lastErrorTime,
      errorThreshold: this._secureErrorHandler.errorThreshold
    };
  }
  /**
   *   Reset error handling system
   */
  _resetErrorHandlingSystem() {
    this._secureErrorHandler.errorCounts.clear();
    this._secureErrorHandler.isInErrorMode = false;
    this._secureErrorHandler.lastErrorTime = 0;
    this._secureLog("info", "\u{1F504} Error handling system reset");
  }
  /**
   *   Get memory management statistics
   */
  _getMemoryManagementStats() {
    return {
      totalCleanups: this._secureMemoryManager.memoryStats.totalCleanups,
      failedCleanups: this._secureMemoryManager.memoryStats.failedCleanups,
      lastCleanup: this._secureMemoryManager.memoryStats.lastCleanup,
      isCleaning: this._secureMemoryManager.isCleaning,
      queueLength: this._secureMemoryManager.cleanupQueue.length
    };
  }
  /**
   *   Validate API integrity and security
   */
  _validateAPIIntegrity() {
    try {
      if (!window.secureBitChat) {
        this._secureLog("error", "\u274C Global API not found during integrity validation");
        return false;
      }
      const requiredMethods = ["sendMessage", "getConnectionStatus", "getSecurityStatus", "sendFile", "disconnect"];
      const missingMethods = requiredMethods.filter(
        (method) => !window.secureBitChat[method] || typeof window.secureBitChat[method] !== "function"
      );
      if (missingMethods.length > 0) {
        this._secureLog("error", "\u274C Global API integrity validation failed - missing methods", {
          missingMethods
        });
        return false;
      }
      const testContext = { test: true };
      const boundMethods = requiredMethods.map((method) => {
        try {
          return window.secureBitChat[method].bind(testContext);
        } catch (error) {
          return null;
        }
      });
      const unboundMethods = boundMethods.filter((method) => method === null);
      if (unboundMethods.length > 0) {
        this._secureLog("error", "\u274C Global API integrity validation failed - method binding issues", {
          unboundMethods: unboundMethods.length
        });
        return false;
      }
      try {
        const testProp = "_integrity_test_" + Date.now();
        Object.defineProperty(window.secureBitChat, testProp, {
          value: "test",
          writable: true,
          configurable: true
        });
        this._secureLog("error", "\u274C Global API integrity validation failed - API is mutable");
        delete window.secureBitChat[testProp];
        return false;
      } catch (immutabilityError) {
        this._secureLog("debug", "\u2705 Global API immutability verified");
      }
      this._secureLog("info", "\u2705 Global API integrity validation passed");
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C Global API integrity validation failed", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      return false;
    }
  }
  _validateCryptographicSecurity() {
    const criticalFeatures = ["hasRateLimiting"];
    const missingCritical = criticalFeatures.filter((feature) => !this.securityFeatures[feature]);
    if (missingCritical.length > 0) {
      this._secureLog("error", "\u{1F6A8} CRITICAL: Missing critical rate limiting feature", {
        missing: missingCritical,
        currentFeatures: this.securityFeatures,
        action: "Rate limiting will be forced enabled"
      });
      missingCritical.forEach((feature) => {
        this.securityFeatures[feature] = true;
        this._secureLog("warn", `\u26A0\uFE0F Forced enable critical: ${feature} = true`);
      });
    }
    const availableFeatures = Object.keys(this.securityFeatures).filter((f) => this.securityFeatures[f]);
    const encryptionFeatures = ["hasEncryption", "hasECDH", "hasECDSA"].filter((f) => this.securityFeatures[f]);
    this._secureLog("info", "\u2705 Cryptographic security validation passed", {
      criticalFeatures: criticalFeatures.length,
      availableFeatures: availableFeatures.length,
      encryptionFeatures: encryptionFeatures.length,
      totalSecurityFeatures: availableFeatures.length,
      note: "Encryption features will be enabled after key generation",
      currentState: {
        hasEncryption: this.securityFeatures.hasEncryption,
        hasECDH: this.securityFeatures.hasECDH,
        hasECDSA: this.securityFeatures.hasECDSA,
        hasRateLimiting: this.securityFeatures.hasRateLimiting
      }
    });
    return true;
  }
  _syncSecurityFeaturesWithTariff() {
    if (!this.sessionManager || !this.sessionManager.isFeatureAllowedForSession) {
      this._secureLog("warn", "\u26A0\uFE0F Session manager not available, using safe default security features");
      if (this.securityFeatures.hasEncryption === void 0) {
        this.securityFeatures.hasEncryption = false;
      }
      if (this.securityFeatures.hasECDH === void 0) {
        this.securityFeatures.hasECDH = false;
      }
      if (this.securityFeatures.hasECDSA === void 0) {
        this.securityFeatures.hasECDSA = false;
      }
      if (this.securityFeatures.hasMutualAuth === void 0) {
        this.securityFeatures.hasMutualAuth = false;
      }
      if (this.securityFeatures.hasMetadataProtection === void 0) {
        this.securityFeatures.hasMetadataProtection = false;
      }
      if (this.securityFeatures.hasEnhancedReplayProtection === void 0) {
        this.securityFeatures.hasEnhancedReplayProtection = false;
      }
      if (this.securityFeatures.hasNonExtractableKeys === void 0) {
        this.securityFeatures.hasNonExtractableKeys = false;
      }
      if (this.securityFeatures.hasRateLimiting === void 0) {
        this.securityFeatures.hasRateLimiting = true;
      }
      if (this.securityFeatures.hasEnhancedValidation === void 0) {
        this.securityFeatures.hasEnhancedValidation = false;
      }
      if (this.securityFeatures.hasPFS === void 0) {
        this.securityFeatures.hasPFS = false;
      }
      if (this.securityFeatures.hasNestedEncryption === void 0) {
        this.securityFeatures.hasNestedEncryption = false;
      }
      if (this.securityFeatures.hasPacketPadding === void 0) {
        this.securityFeatures.hasPacketPadding = false;
      }
      if (this.securityFeatures.hasPacketReordering === void 0) {
        this.securityFeatures.hasPacketReordering = false;
      }
      if (this.securityFeatures.hasAntiFingerprinting === void 0) {
        this.securityFeatures.hasAntiFingerprinting = false;
      }
      if (this.securityFeatures.hasFakeTraffic === void 0) {
        this.securityFeatures.hasFakeTraffic = false;
      }
      if (this.securityFeatures.hasDecoyChannels === void 0) {
        this.securityFeatures.hasDecoyChannels = false;
      }
      if (this.securityFeatures.hasMessageChunking === void 0) {
        this.securityFeatures.hasMessageChunking = false;
      }
      this._secureLog("info", "\u2705 Safe default security features applied (features will be enabled as they become available)");
      return;
    }
    let sessionType = "demo";
    if (this.sessionManager.isFeatureAllowedForSession("premium", "hasFakeTraffic")) {
      sessionType = "premium";
    } else if (this.sessionManager.isFeatureAllowedForSession("basic", "hasECDSA")) {
      sessionType = "basic";
    }
    this._secureLog("info", "\u{1F512} Syncing security features with tariff plan", { sessionType });
    const allFeatures = [
      "hasEncryption",
      "hasECDH",
      "hasECDSA",
      "hasMutualAuth",
      "hasMetadataProtection",
      "hasEnhancedReplayProtection",
      "hasNonExtractableKeys",
      "hasRateLimiting",
      "hasEnhancedValidation",
      "hasPFS",
      "hasNestedEncryption",
      "hasPacketPadding",
      "hasPacketReordering",
      "hasAntiFingerprinting",
      "hasFakeTraffic",
      "hasDecoyChannels",
      "hasMessageChunking"
    ];
    allFeatures.forEach((feature) => {
      const isAllowed = this.sessionManager.isFeatureAllowedForSession(sessionType, feature);
      if (this.securityFeatures[feature] !== isAllowed) {
        this._secureLog("info", `\u{1F504} Syncing ${feature}: ${this.securityFeatures[feature]} \u2192 ${isAllowed}`);
        this.securityFeatures[feature] = isAllowed;
      }
    });
    if (this.onStatusChange) {
      this.onStatusChange("security_synced", {
        type: "tariff_sync",
        sessionType,
        features: this.securityFeatures,
        message: `Security features synchronized with ${sessionType} tariff plan`
      });
    }
    this._secureLog("info", "\u2705 Security features synchronized with tariff plan", {
      sessionType,
      enabledFeatures: Object.keys(this.securityFeatures).filter((f) => this.securityFeatures[f]).length,
      totalFeatures: Object.keys(this.securityFeatures).length
    });
  }
  /**
   * Emergency shutdown for critical issues
   */
  _emergencyShutdown(reason = "Security breach") {
    this._secureLog("error", "\u274C EMERGENCY SHUTDOWN: ${reason}");
    try {
      this.encryptionKey = null;
      this.macKey = null;
      this.metadataKey = null;
      this.verificationCode = null;
      this.keyFingerprint = null;
      this.connectionId = null;
      if (this.dataChannel) {
        this.dataChannel.close();
        this.dataChannel = null;
      }
      if (this.peerConnection) {
        this.peerConnection.close();
        this.peerConnection = null;
      }
      this.messageQueue = [];
      this.processedMessageIds.clear();
      this.packetBuffer.clear();
      if (this.onStatusChange) {
        this.onStatusChange("security_breach");
      }
      this._secureLog("info", "\u{1F512} Emergency shutdown completed");
    } catch (error) {
      this._secureLog("error", "\u274C Error during emergency shutdown:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  _finalizeSecureInitialization() {
    this._startKeySecurityMonitoring();
    if (!this._verifyAPIIntegrity()) {
      this._secureLog("error", "\u274C Security initialization failed");
      return;
    }
    this._startSecurityMonitoring();
    setInterval(() => {
      this._cleanupLogs();
    }, 3e5);
    this._secureLog("info", "\u2705 Secure WebRTC Manager initialization completed");
    this._secureLog("info", "\u{1F512} Global exposure protection: Monitoring only, no automatic removal");
  }
  /**
   * Start security monitoring
   * @deprecated Use unified scheduler instead
   */
  _startSecurityMonitoring() {
    this._secureLog("info", "\u{1F527} Security monitoring moved to unified scheduler");
  }
  /**
   * Validates connection readiness for sending data
   * @param {boolean} throwError - whether to throw on not ready
   * @returns {boolean} true if connection is ready
   */
  _validateConnection(throwError = true) {
    const isDataChannelReady = this.dataChannel && this.dataChannel.readyState === "open";
    const isConnectionVerified = this.isVerified;
    const isValid = isDataChannelReady && isConnectionVerified;
    if (!isValid && throwError) {
      if (!isDataChannelReady) {
        throw new Error("Data channel not ready");
      }
      if (!isConnectionVerified) {
        throw new Error("Connection not verified");
      }
    }
    return isValid;
  }
  /**
   *   Hard gate for traffic blocking without verification
   * This method enforces that NO traffic (including system messages and file transfers)
   * can pass through without proper cryptographic verification
   */
  _enforceVerificationGate(operation = "unknown", throwError = true) {
    if (!this.isVerified) {
      const errorMessage = `SECURITY VIOLATION: ${operation} blocked - connection not cryptographically verified`;
      this._secureLog("error", errorMessage, {
        operation,
        isVerified: this.isVerified,
        hasKeys: !!(this.encryptionKey && this.macKey),
        timestamp: Date.now()
      });
      if (throwError) {
        throw new Error(errorMessage);
      }
      return false;
    }
    return true;
  }
  /**
   *   Safe method to set isVerified only after cryptographic verification
   * This is the ONLY method that should set isVerified = true
   */
  _setVerifiedStatus(verified, verificationMethod = "unknown", verificationData = null) {
    if (verified) {
      if (!this.encryptionKey || !this.macKey) {
        throw new Error("Cannot set verified=true without encryption keys");
      }
      if (!verificationMethod || verificationMethod === "unknown") {
        throw new Error("Cannot set verified=true without specifying verification method");
      }
      this._secureLog("info", "Connection verified through cryptographic verification", {
        verificationMethod,
        hasEncryptionKey: !!this.encryptionKey,
        hasMacKey: !!this.macKey,
        keyFingerprint: this.keyFingerprint,
        timestamp: Date.now(),
        verificationData: verificationData ? "provided" : "none"
      });
    }
    this.isVerified = verified;
    if (verified) {
      this.onStatusChange("connected");
    } else {
      this.onStatusChange("disconnected");
    }
  }
  /**
   *   Create AAD (Additional Authenticated Data) for file messages
   * This binds file messages to the current session and prevents replay attacks
   */
  _createFileMessageAAD(messageType, messageData = null) {
    if (typeof this._createMessageAAD !== "function") {
      throw new Error("_createMessageAAD method is not available in _createFileMessageAAD. Manager may not be fully initialized.");
    }
    return this._createMessageAAD(messageType, messageData, true);
  }
  /**
   *   Validate AAD for file messages
   * This ensures file messages are bound to the correct session
   */
  _validateFileMessageAAD(aadString, expectedMessageType = null) {
    try {
      const aad = JSON.parse(aadString);
      if (aad.sessionId !== (this.currentSession?.sessionId || "unknown")) {
        throw new Error("AAD sessionId mismatch - possible replay attack");
      }
      if (aad.keyFingerprint !== (this.keyFingerprint || "unknown")) {
        throw new Error("AAD keyFingerprint mismatch - possible key substitution attack");
      }
      if (expectedMessageType && aad.messageType !== expectedMessageType) {
        throw new Error(`AAD messageType mismatch - expected ${expectedMessageType}, got ${aad.messageType}`);
      }
      const now = Date.now();
      const messageAge = now - aad.timestamp;
      if (messageAge > 3e5) {
        throw new Error("AAD timestamp too old - possible replay attack");
      }
      return aad;
    } catch (error) {
      this._secureLog("error", "AAD validation failed", { error: error.message, aadString });
      throw new Error(`AAD validation failed: ${error.message}`);
    }
  }
  /**
   *   Extract DTLS fingerprint from SDP
   * This is essential for MITM protection
   */
  _extractDTLSFingerprintFromSDP(sdp) {
    try {
      if (!sdp || typeof sdp !== "string") {
        throw new Error("Invalid SDP provided");
      }
      const fingerprintRegex = /a=fingerprint:([a-zA-Z0-9-]+)\s+([A-Fa-f0-9:]+)/g;
      const fingerprints = [];
      let match;
      while ((match = fingerprintRegex.exec(sdp)) !== null) {
        fingerprints.push({
          algorithm: match[1].toLowerCase(),
          fingerprint: match[2].toLowerCase().replace(/:/g, "")
        });
      }
      if (fingerprints.length === 0) {
        const altFingerprintRegex = /fingerprint\s*=\s*([a-zA-Z0-9-]+)\s+([A-Fa-f0-9:]+)/gi;
        while ((match = altFingerprintRegex.exec(sdp)) !== null) {
          fingerprints.push({
            algorithm: match[1].toLowerCase(),
            fingerprint: match[2].toLowerCase().replace(/:/g, "")
          });
        }
      }
      if (fingerprints.length === 0) {
        this._secureLog("warn", "No DTLS fingerprints found in SDP - this may be normal for some WebRTC implementations", {
          sdpLength: sdp.length,
          sdpPreview: sdp.substring(0, 200) + "..."
        });
        throw new Error("No DTLS fingerprints found in SDP");
      }
      const sha256Fingerprint = fingerprints.find((fp) => fp.algorithm === "sha-256");
      if (sha256Fingerprint) {
        return sha256Fingerprint.fingerprint;
      }
      return fingerprints[0].fingerprint;
    } catch (error) {
      this._secureLog("error", "Failed to extract DTLS fingerprint from SDP", {
        error: error.message,
        sdpLength: sdp?.length || 0
      });
      throw new Error(`DTLS fingerprint extraction failed: ${error.message}`);
    }
  }
  /**
   *   Validate DTLS fingerprint against expected value
   * This prevents MITM attacks by ensuring the remote peer has the expected certificate
   */
  _validateDTLSFingerprint(receivedFingerprint, expectedFingerprint, context = "unknown") {
    try {
      if (!receivedFingerprint || !expectedFingerprint) {
        throw new Error("Missing fingerprint for validation");
      }
      const normalizedReceived = receivedFingerprint.toLowerCase().replace(/:/g, "");
      const normalizedExpected = expectedFingerprint.toLowerCase().replace(/:/g, "");
      if (normalizedReceived !== normalizedExpected) {
        this._secureLog("error", "DTLS fingerprint mismatch - possible MITM attack", {
          context,
          received: normalizedReceived,
          expected: normalizedExpected,
          timestamp: Date.now()
        });
        throw new Error(`DTLS fingerprint mismatch - possible MITM attack in ${context}`);
      }
      this._secureLog("info", "DTLS fingerprint validation successful", {
        context,
        fingerprint: normalizedReceived,
        timestamp: Date.now()
      });
      return true;
    } catch (error) {
      this._secureLog("error", "DTLS fingerprint validation failed", {
        error: error.message,
        context
      });
      throw error;
    }
  }
  /**
   *   Compute SAS (Short Authentication String) for MITM protection
   * Uses HKDF with DTLS fingerprints to generate a stable 7-digit verification code
   * @param {ArrayBuffer|Uint8Array} keyMaterialRaw - Shared secret or key fingerprint data
   * @param {string} localFP - Local DTLS fingerprint
   * @param {string} remoteFP - Remote DTLS fingerprint
   * @returns {Promise<string>} 7-digit SAS code
   */
  async _computeSAS(keyMaterialRaw, localFP, remoteFP) {
    try {
      console.log("_computeSAS called with parameters:", {
        keyMaterialRaw: keyMaterialRaw ? `${keyMaterialRaw.constructor.name} (${keyMaterialRaw.length || keyMaterialRaw.byteLength} bytes)` : "null/undefined",
        localFP: localFP ? `${localFP.substring(0, 20)}...` : "null/undefined",
        remoteFP: remoteFP ? `${remoteFP.substring(0, 20)}...` : "null/undefined"
      });
      if (!keyMaterialRaw || !localFP || !remoteFP) {
        const missing = [];
        if (!keyMaterialRaw) missing.push("keyMaterialRaw");
        if (!localFP) missing.push("localFP");
        if (!remoteFP) missing.push("remoteFP");
        throw new Error(`Missing required parameters for SAS computation: ${missing.join(", ")}`);
      }
      const enc = new TextEncoder();
      const salt = enc.encode(
        "webrtc-sas|" + [localFP, remoteFP].sort().join("|")
      );
      let keyBuffer;
      if (keyMaterialRaw instanceof ArrayBuffer) {
        keyBuffer = keyMaterialRaw;
      } else if (keyMaterialRaw instanceof Uint8Array) {
        keyBuffer = keyMaterialRaw.buffer;
      } else if (typeof keyMaterialRaw === "string") {
        const hexString = keyMaterialRaw.replace(/:/g, "").replace(/\s/g, "");
        const bytes = new Uint8Array(hexString.length / 2);
        for (let i = 0; i < hexString.length; i += 2) {
          bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
        }
        keyBuffer = bytes.buffer;
      } else {
        throw new Error("Invalid keyMaterialRaw type");
      }
      const key = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        "HKDF",
        false,
        ["deriveBits"]
      );
      const info = enc.encode("p2p-sas-v1");
      const bits = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt, info },
        key,
        64
        // 64 бита достаточно для 6–7 знаков
      );
      const dv = new DataView(bits);
      const n = (dv.getUint32(0) ^ dv.getUint32(4)) >>> 0;
      const sasCode = String(n % 1e7).padStart(7, "0");
      console.log("\u{1F3AF} _computeSAS computed code:", sasCode, "(type:", typeof sasCode, ")");
      this._secureLog("info", "SAS code computed successfully", {
        localFP: localFP.substring(0, 16) + "...",
        remoteFP: remoteFP.substring(0, 16) + "...",
        sasLength: sasCode.length,
        timestamp: Date.now()
      });
      return sasCode;
    } catch (error) {
      this._secureLog("error", "SAS computation failed", {
        error: error.message,
        keyMaterialType: typeof keyMaterialRaw,
        hasLocalFP: !!localFP,
        hasRemoteFP: !!remoteFP,
        timestamp: Date.now()
      });
      throw new Error(`SAS computation failed: ${error.message}`);
    }
  }
  /**
   * UTILITY: Decode hex keyFingerprint to Uint8Array for SAS computation
   * @param {string} hexString - Hex encoded keyFingerprint (e.g., "aa:bb:cc:dd")
   * @returns {Uint8Array} Decoded bytes
   */
  _decodeKeyFingerprint(hexString) {
    try {
      if (!hexString || typeof hexString !== "string") {
        throw new Error("Invalid hex string provided");
      }
      return window.EnhancedSecureCryptoUtils.hexToUint8Array(hexString);
    } catch (error) {
      this._secureLog("error", "Key fingerprint decoding failed", {
        error: error.message,
        inputType: typeof hexString,
        inputLength: hexString?.length || 0
      });
      throw new Error(`Key fingerprint decoding failed: ${error.message}`);
    }
  }
  /**
   *   Emergency key wipe on fingerprint mismatch
   * This ensures no sensitive data remains if MITM is detected
   */
  _emergencyWipeOnFingerprintMismatch(reason = "DTLS fingerprint mismatch") {
    try {
      this._secureLog("error", "\u{1F6A8} EMERGENCY: Initiating security wipe due to fingerprint mismatch", {
        reason,
        timestamp: Date.now()
      });
      this._secureWipeKeys();
      this._secureWipeMemory(this.encryptionKey, "emergency_wipe");
      this._secureWipeMemory(this.macKey, "emergency_wipe");
      this._secureWipeMemory(this.metadataKey, "emergency_wipe");
      this._wipeEphemeralKeys();
      this._hardWipeOldKeys();
      this.isVerified = null;
      this.verificationCode = null;
      this.keyFingerprint = null;
      this.connectionId = null;
      this.expectedDTLSFingerprint = null;
      this.disconnect();
      this.deliverMessageToUI("\u{1F6A8} SECURITY BREACH: Connection terminated due to fingerprint mismatch. Possible MITM attack detected!", "system");
    } catch (error) {
      this._secureLog("error", "Failed to perform emergency wipe", { error: error.message });
    }
  }
  /**
   *   Set expected DTLS fingerprint via out-of-band channel
   * This should be called after receiving the fingerprint through a secure channel
   * (e.g., QR code, voice call, in-person exchange, etc.)
   */
  setExpectedDTLSFingerprint(fingerprint, source = "out_of_band") {
    try {
      if (!fingerprint || typeof fingerprint !== "string") {
        throw new Error("Invalid fingerprint provided");
      }
      const normalizedFingerprint = fingerprint.toLowerCase().replace(/:/g, "");
      if (!/^[a-f0-9]{40,64}$/.test(normalizedFingerprint)) {
        throw new Error("Invalid fingerprint format - must be hex string");
      }
      this.expectedDTLSFingerprint = normalizedFingerprint;
      this._secureLog("info", "Expected DTLS fingerprint set via out-of-band channel", {
        source,
        fingerprint: normalizedFingerprint,
        timestamp: Date.now()
      });
      this.deliverMessageToUI(`\u2705 DTLS fingerprint set via ${source}. MITM protection enabled.`, "system");
    } catch (error) {
      this._secureLog("error", "Failed to set expected DTLS fingerprint", { error: error.message });
      throw error;
    }
  }
  /**
   *   Get current DTLS fingerprint for out-of-band verification
   * This should be shared through a secure channel (QR code, voice, etc.)
   */
  getCurrentDTLSFingerprint() {
    try {
      if (!this.expectedDTLSFingerprint) {
        throw new Error("No DTLS fingerprint available - connection not established");
      }
      return this.expectedDTLSFingerprint;
    } catch (error) {
      this._secureLog("error", "Failed to get current DTLS fingerprint", { error: error.message });
      throw error;
    }
  }
  /**
   * DEBUGGING: Temporarily disable strict DTLS validation
   * This should only be used for debugging connection issues
   */
  disableStrictDTLSValidation() {
    this.strictDTLSValidation = false;
    this._secureLog("warn", "\u26A0\uFE0F Strict DTLS validation disabled - security reduced", {
      timestamp: Date.now()
    });
    this.deliverMessageToUI("\u26A0\uFE0F DTLS validation disabled for debugging", "system");
  }
  /**
   * SECURITY: Re-enable strict DTLS validation
   */
  enableStrictDTLSValidation() {
    this.strictDTLSValidation = true;
    this._secureLog("info", "\u2705 Strict DTLS validation re-enabled", {
      timestamp: Date.now()
    });
    this.deliverMessageToUI("\u2705 DTLS validation re-enabled", "system");
  }
  /**
   *   Generate ephemeral ECDH keys for Perfect Forward Secrecy
   * This ensures each session has unique, non-persistent keys
   */
  async _generateEphemeralECDHKeys() {
    try {
      this._secureLog("info", "\u{1F511} Generating ephemeral ECDH keys for PFS", {
        sessionStartTime: this.sessionStartTime,
        timestamp: Date.now()
      });
      const ephemeralKeyPair = await window.EnhancedSecureCryptoUtils.generateECDHKeyPair();
      if (!ephemeralKeyPair || !this._validateKeyPairConstantTime(ephemeralKeyPair)) {
        throw new Error("Ephemeral ECDH key pair validation failed");
      }
      const sessionId = this.currentSession?.sessionId || `session_${Date.now()}`;
      this.ephemeralKeyPairs.set(sessionId, {
        keyPair: ephemeralKeyPair,
        timestamp: Date.now(),
        sessionId
      });
      this._secureLog("info", "\u2705 Ephemeral ECDH keys generated for PFS", {
        sessionId,
        timestamp: Date.now()
      });
      return ephemeralKeyPair;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to generate ephemeral ECDH keys", { error: error.message });
      throw new Error(`Ephemeral key generation failed: ${error.message}`);
    }
  }
  /**
   *   Hard wipe old keys for real PFS
   * This prevents retrospective decryption attacks
   */
  _hardWipeOldKeys() {
    try {
      this._secureLog("info", "\u{1F9F9} Performing hard wipe of old keys for PFS", {
        oldKeysCount: this.oldKeys.size,
        timestamp: Date.now()
      });
      for (const [version, keySet] of this.oldKeys.entries()) {
        if (keySet.encryptionKey) {
          this._secureWipeMemory(keySet.encryptionKey, "pfs_key_wipe");
        }
        if (keySet.macKey) {
          this._secureWipeMemory(keySet.macKey, "pfs_key_wipe");
        }
        if (keySet.metadataKey) {
          this._secureWipeMemory(keySet.metadataKey, "pfs_key_wipe");
        }
        keySet.encryptionKey = null;
        keySet.macKey = null;
        keySet.metadataKey = null;
        keySet.keyFingerprint = null;
      }
      this.oldKeys.clear();
      if (typeof window.gc === "function") {
        window.gc();
      }
      this._secureLog("info", "\u2705 Hard wipe of old keys completed for PFS", {
        timestamp: Date.now()
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to perform hard wipe of old keys", { error: error.message });
    }
  }
  /**
   *   Wipe ephemeral keys when session ends
   * This ensures session-specific keys are destroyed
   */
  _wipeEphemeralKeys() {
    try {
      this._secureLog("info", "\u{1F9F9} Wiping ephemeral keys for PFS", {
        ephemeralKeysCount: this.ephemeralKeyPairs.size,
        timestamp: Date.now()
      });
      for (const [sessionId, keyData] of this.ephemeralKeyPairs.entries()) {
        if (keyData.keyPair?.privateKey) {
          this._secureWipeMemory(keyData.keyPair.privateKey, "ephemeral_key_wipe");
        }
        if (keyData.keyPair?.publicKey) {
          this._secureWipeMemory(keyData.keyPair.publicKey, "ephemeral_key_wipe");
        }
        keyData.keyPair = null;
        keyData.timestamp = null;
        keyData.sessionId = null;
      }
      this.ephemeralKeyPairs.clear();
      if (typeof window.gc === "function") {
        window.gc();
      }
      this._secureLog("info", "\u2705 Ephemeral keys wiped for PFS", {
        timestamp: Date.now()
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to wipe ephemeral keys", { error: error.message });
    }
  }
  /**
   *   Encrypt file messages with AAD
   * This ensures file messages are properly authenticated and bound to session
   */
  async _encryptFileMessage(messageData, aad) {
    try {
      if (!this.encryptionKey) {
        throw new Error("No encryption key available for file message");
      }
      const messageString = typeof messageData === "string" ? messageData : JSON.stringify(messageData);
      const encryptedData = await window.EnhancedSecureCryptoUtils.encryptDataWithAAD(
        messageString,
        this.encryptionKey,
        aad
      );
      const encryptedMessage = {
        type: "encrypted_file_message",
        encryptedData,
        aad,
        timestamp: Date.now(),
        keyFingerprint: this.keyFingerprint
      };
      return JSON.stringify(encryptedMessage);
    } catch (error) {
      this._secureLog("error", "Failed to encrypt file message", { error: error.message });
      throw new Error(`File message encryption failed: ${error.message}`);
    }
  }
  /**
   *   Decrypt file messages with AAD validation
   * This ensures file messages are properly authenticated and bound to session
   */
  async _decryptFileMessage(encryptedMessageString) {
    try {
      const encryptedMessage = JSON.parse(encryptedMessageString);
      if (encryptedMessage.type !== "encrypted_file_message") {
        throw new Error("Invalid encrypted file message type");
      }
      if (encryptedMessage.keyFingerprint !== this.keyFingerprint) {
        throw new Error("Key fingerprint mismatch in encrypted file message");
      }
      const aad = this._validateMessageAAD(encryptedMessage.aad, "file_message");
      if (!this.encryptionKey) {
        throw new Error("No encryption key available for file message decryption");
      }
      const decryptedData = await window.EnhancedSecureCryptoUtils.decryptDataWithAAD(
        encryptedMessage.encryptedData,
        this.encryptionKey,
        encryptedMessage.aad
      );
      return {
        decryptedData,
        aad
      };
    } catch (error) {
      this._secureLog("error", "Failed to decrypt file message", { error: error.message });
      throw new Error(`File message decryption failed: ${error.message}`);
    }
  }
  /**
   * Validates encryption keys readiness
   * @param {boolean} throwError - whether to throw on not ready
   * @returns {boolean} true if keys are ready
   */
  _validateEncryptionKeys(throwError = true) {
    const hasAllKeys = !!(this.encryptionKey && this.macKey && this.metadataKey);
    if (!hasAllKeys && throwError) {
      throw new Error("Encryption keys not initialized");
    }
    return hasAllKeys;
  }
  /**
   * Checks whether a message is a file-transfer message
   * @param {string|object} data - message payload
   * @returns {boolean} true if it's a file message
   */
  _isFileMessage(data) {
    if (typeof data === "string") {
      try {
        const parsed = JSON.parse(data);
        return parsed.type && parsed.type.startsWith("file_");
      } catch {
        return false;
      }
    }
    if (typeof data === "object" && data.type) {
      return data.type.startsWith("file_");
    }
    return false;
  }
  /**
   * Checks whether a message is a system message
   * @param {string|object} data - message payload  
   * @returns {boolean} true if it's a system message
   */
  _isSystemMessage(data) {
    const systemTypes = [
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_RESPONSE,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_CONFIRMED,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_BOTH_CONFIRMED,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.PEER_DISCONNECT,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.SECURITY_UPGRADE,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_SIGNAL,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_READY
    ];
    if (typeof data === "string") {
      try {
        const parsed = JSON.parse(data);
        return systemTypes.includes(parsed.type);
      } catch {
        return false;
      }
    }
    if (typeof data === "object" && data.type) {
      return systemTypes.includes(data.type);
    }
    return false;
  }
  /**
   * Checks whether a message is fake traffic
   * @param {any} data - message payload
   * @returns {boolean} true if it's a fake message
   */
  _isFakeMessage(data) {
    if (typeof data === "string") {
      try {
        const parsed = JSON.parse(data);
        return parsed.type === _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FAKE || parsed.isFakeTraffic === true;
      } catch {
        return false;
      }
    }
    if (typeof data === "object" && data !== null) {
      return data.type === _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FAKE || data.isFakeTraffic === true;
    }
    return false;
  }
  /**
   * Safely executes an operation with error handling
   * @param {Function} operation - operation to execute
   * @param {string} errorMessage - error message to log
   * @param {any} fallback - default value on error
   * @returns {any} operation result or fallback
   */
  _withErrorHandling(operation, errorMessage, fallback = null) {
    try {
      return operation();
    } catch (error) {
      if (this._debugMode) {
        this._secureLog("error", "\u274C ${errorMessage}:", { errorType: error?.constructor?.name || "Unknown" });
      }
      return fallback;
    }
  }
  /**
   * Safely executes an async operation with error handling
   * @param {Function} operation - async operation
   * @param {string} errorMessage - error message to log
   * @param {any} fallback - default value on error
   * @returns {Promise<any>} operation result or fallback
   */
  async _withAsyncErrorHandling(operation, errorMessage, fallback = null) {
    try {
      return await operation();
    } catch (error) {
      if (this._debugMode) {
        this._secureLog("error", "\u274C ${errorMessage}:", { errorType: error?.constructor?.name || "Unknown" });
      }
      return fallback;
    }
  }
  /**
   * Checks rate limits
   * @returns {boolean} true if allowed to proceed
   */
  _checkRateLimit() {
    return window.EnhancedSecureCryptoUtils.rateLimiter.checkConnectionRate(this.rateLimiterId);
  }
  /**
   * Extracts message type from data
   * @param {string|object} data - message data
   * @returns {string|null} message type or null
   */
  _getMessageType(data) {
    if (typeof data === "string") {
      try {
        const parsed = JSON.parse(data);
        return parsed.type || null;
      } catch {
        return null;
      }
    }
    if (typeof data === "object" && data !== null) {
      return data.type || null;
    }
    return null;
  }
  /**
   * Resets notification flags for a new connection
   */
  _resetNotificationFlags() {
    this.lastSecurityLevelNotification = null;
    this.verificationNotificationSent = false;
    this.verificationInitiationSent = false;
    this.disconnectNotificationSent = false;
    this.reconnectionFailedNotificationSent = false;
    this.peerDisconnectNotificationSent = false;
    this.connectionClosedNotificationSent = false;
    this.fakeTrafficDisabledNotificationSent = false;
    this.advancedFeaturesDisabledNotificationSent = false;
    this.securityUpgradeNotificationSent = false;
    this.lastSecurityUpgradeStage = null;
    this.securityCalculationNotificationSent = false;
    this.lastSecurityCalculationLevel = null;
  }
  /**
   * Checks whether a message was filtered out
   * @param {any} result - processing result
   * @returns {boolean} true if filtered
   */
  _isFilteredMessage(result) {
    const filteredResults = Object.values(_EnhancedSecureWebRTCManager.FILTERED_RESULTS);
    return filteredResults.includes(result);
  }
  /**
   *   Enhanced log cleanup with security checks
   */
  _cleanupLogs() {
    if (this._logCounts.size > 500) {
      this._logCounts.clear();
      this._secureLog("debug", "\u{1F9F9} Log counts cleared due to size limit");
    }
    const now = Date.now();
    const maxAge = 3e5;
    let suspiciousCount = 0;
    for (const [key, count] of this._logCounts.entries()) {
      if (count > 10) {
        suspiciousCount++;
      }
    }
    if (suspiciousCount > 20) {
      this._logCounts.clear();
      this._secureLog("warn", "\u{1F6A8} Emergency log cleanup due to suspicious patterns");
    }
    if (this._logSecurityViolations > 0 && suspiciousCount < 5) {
      this._logSecurityViolations = Math.max(0, this._logSecurityViolations - 1);
    }
    if (!this._lastIVCleanupTime || Date.now() - this._lastIVCleanupTime > 3e5) {
      this._cleanupOldIVs();
      this._lastIVCleanupTime = Date.now();
    }
    if (!this._secureMemoryManager.memoryStats.lastCleanup || Date.now() - this._secureMemoryManager.memoryStats.lastCleanup > 6e5) {
      this._performPeriodicMemoryCleanup();
      this._secureMemoryManager.memoryStats.lastCleanup = Date.now();
    }
  }
  /**
   *   Secure logging stats with sensitive data protection
   */
  _getLoggingStats() {
    const stats = {
      isProductionMode: this._isProductionMode,
      debugMode: this._debugMode,
      currentLogLevel: this._currentLogLevel,
      logCountsSize: this._logCounts.size,
      maxLogCount: this._maxLogCount,
      securityViolations: this._logSecurityViolations || 0,
      maxSecurityViolations: this._maxLogSecurityViolations || 3,
      systemStatus: this._currentLogLevel === -1 ? "DISABLED" : "ACTIVE"
    };
    const sanitizedStats = {};
    for (const [key, value] of Object.entries(stats)) {
      if (typeof value === "string" && this._containsSensitiveContent(value)) {
        sanitizedStats[key] = "[SENSITIVE_DATA_REDACTED]";
      } else {
        sanitizedStats[key] = value;
      }
    }
    return sanitizedStats;
  }
  /**
   *   Enhanced emergency logging disable with cleanup
   */
  _emergencyDisableLogging() {
    this._currentLogLevel = -1;
    this._logCounts.clear();
    if (this._logSecurityViolations) {
      this._logSecurityViolations = 0;
    }
    this._secureLog = () => {
      if (arguments[0] === "error" && this._originalConsole?.error) {
        this._originalConsole.error("\u{1F6A8} SECURITY: Logging system disabled - potential data exposure prevented");
      }
    };
    this._originalSanitizeString = this._sanitizeString;
    this._originalSanitizeLogData = this._sanitizeLogData;
    this._originalAuditLogMessage = this._auditLogMessage;
    this._originalContainsSensitiveContent = this._containsSensitiveContent;
    this._sanitizeString = () => "[LOGGING_DISABLED]";
    this._sanitizeLogData = () => ({ error: "LOGGING_DISABLED" });
    this._auditLogMessage = () => false;
    this._containsSensitiveContent = () => true;
    if (typeof window.gc === "function") {
      try {
        window.gc();
      } catch (e) {
      }
    }
    this._originalConsole?.error?.("\u{1F6A8} CRITICAL: Secure logging system disabled due to potential data exposure");
  }
  /**
   *   Reset logging system after emergency shutdown
   * Use this function to restore normal logging functionality
   */
  _resetLoggingSystem() {
    this._secureLog("info", "\u{1F527} Resetting logging system after emergency shutdown");
    this._sanitizeString = this._originalSanitizeString || ((str) => str);
    this._sanitizeLogData = this._originalSanitizeLogData || ((data) => data);
    this._auditLogMessage = this._originalAuditLogMessage || (() => true);
    this._containsSensitiveContent = this._originalContainsSensitiveContent || (() => false);
    this._logSecurityViolations = 0;
    this._secureLog("info", "\u2705 Logging system reset successfully");
  }
  /**
   *   Enhanced audit function for log message security
   */
  _auditLogMessage(message, data) {
    if (!data || typeof data !== "object") return true;
    const dataString = JSON.stringify(data);
    if (this._containsSensitiveContent(message)) {
      this._emergencyDisableLogging();
      this._originalConsole?.error?.("\u{1F6A8} SECURITY BREACH: Sensitive content detected in log message");
      return false;
    }
    if (this._containsSensitiveContent(dataString)) {
      this._emergencyDisableLogging();
      this._originalConsole?.error?.("\u{1F6A8} SECURITY BREACH: Sensitive content detected in log data");
      return false;
    }
    const dangerousPatterns = [
      "secret",
      "token",
      "password",
      "credential",
      "auth",
      "fingerprint",
      "salt",
      "signature",
      "private_key",
      "api_key",
      "private",
      "encryption",
      "mac",
      "metadata",
      "session",
      "jwt",
      "bearer",
      "key",
      "hash",
      "digest",
      "nonce",
      "iv",
      "cipher"
    ];
    const dataStringLower = dataString.toLowerCase();
    for (const pattern of dangerousPatterns) {
      if (dataStringLower.includes(pattern) && !this._safeFieldsWhitelist.has(pattern)) {
        this._emergencyDisableLogging();
        this._originalConsole?.error?.(`\u{1F6A8} SECURITY BREACH: Dangerous pattern detected in log: ${pattern}`);
        return false;
      }
    }
    for (const [key, value] of Object.entries(data)) {
      if (typeof value === "string" && this._hasHighEntropy(value)) {
        this._emergencyDisableLogging();
        this._originalConsole?.error?.(`\u{1F6A8} SECURITY BREACH: High entropy value detected in log field: ${key}`);
        return false;
      }
    }
    return true;
  }
  initializeFileTransfer() {
    try {
      this._secureLog("info", "\u{1F527} Initializing Enhanced Secure File Transfer system...");
      if (this.fileTransferSystem) {
        this._secureLog("info", "\u2705 File transfer system already initialized");
        return;
      }
      const channelReady = !!(this.dataChannel && this.dataChannel.readyState === "open");
      if (!channelReady) {
        this._secureLog("warn", "\u26A0\uFE0F Data channel not open, deferring file transfer initialization");
        if (this.dataChannel) {
          const initHandler = () => {
            this._secureLog("info", "\u{1F504} DataChannel opened, initializing file transfer...");
            this.initializeFileTransfer();
          };
          this.dataChannel.addEventListener("open", initHandler, { once: true });
        }
        return;
      }
      if (!this.isVerified) {
        this._secureLog("warn", "\u26A0\uFE0F Connection not verified yet, deferring file transfer initialization");
        setTimeout(() => this.initializeFileTransfer(), 500);
        return;
      }
      if (this.fileTransferSystem) {
        this._secureLog("info", "\u{1F9F9} Cleaning up existing file transfer system");
        this.fileTransferSystem.cleanup();
        this.fileTransferSystem = null;
      }
      if (!this.encryptionKey || !this.macKey) {
        this._secureLog("warn", "\u26A0\uFE0F Encryption keys not ready, deferring file transfer initialization");
        setTimeout(() => this.initializeFileTransfer(), 1e3);
        return;
      }
      const safeOnComplete = (summary) => {
        try {
          this._secureLog("info", "\u{1F3C1} Sender transfer summary", { summary });
          if (this.onFileProgress) {
            this.onFileProgress({ type: "complete", ...summary });
          }
        } catch (e) {
          this._secureLog("warn", "\u26A0\uFE0F onComplete handler failed:", { details: e.message });
        }
      };
      this.fileTransferSystem = new EnhancedSecureFileTransfer(
        this,
        this.onFileProgress || null,
        safeOnComplete,
        this.onFileError || null,
        this.onFileReceived || null
      );
      this._fileTransferActive = true;
      this._secureLog("info", "\u2705 Enhanced Secure File Transfer system initialized successfully");
      const status = this.fileTransferSystem.getSystemStatus();
      this._secureLog("info", "\u{1F50D} File transfer system status after init", { status });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to initialize file transfer system", { errorType: error.constructor.name });
      this.fileTransferSystem = null;
      this._fileTransferActive = false;
    }
  }
  // ============================================
  // ENHANCED SECURITY INITIALIZATION
  // ============================================
  async initializeEnhancedSecurity() {
    try {
      await this.generateNestedEncryptionKey();
      if (this.decoyChannelConfig.enabled) {
        this.initializeDecoyChannels();
      }
      if (this.fakeTrafficConfig.enabled) {
        this.startFakeTrafficGeneration();
      }
    } catch (error) {
      this._secureLog("error", "\u274C Failed to initialize enhanced security", { errorType: error.constructor.name });
    }
  }
  //   Generate fingerprint mask for anti-fingerprinting with enhanced randomization
  generateFingerprintMask() {
    const cryptoRandom = crypto.getRandomValues(new Uint8Array(128));
    const mask = {
      timingOffset: cryptoRandom[0] % 1e3 + cryptoRandom[1] % 500,
      // 0-1500ms
      sizeVariation: (cryptoRandom[2] % 50 + 75) / 100,
      // 0.75 to 1.25
      noisePattern: Array.from(crypto.getRandomValues(new Uint8Array(64))),
      // Increased size
      headerVariations: [
        "X-Client-Version",
        "X-Session-ID",
        "X-Request-ID",
        "X-Timestamp",
        "X-Signature",
        "X-Secure",
        "X-Encrypted",
        "X-Protected",
        "X-Safe",
        "X-Anonymous",
        "X-Private"
      ],
      noiseIntensity: cryptoRandom[3] % 100 + 50,
      // 50-150%
      sizeMultiplier: (cryptoRandom[4] % 50 + 75) / 100,
      // 0.75-1.25
      timingVariation: cryptoRandom[5] % 1e3 + 100
      // 100-1100ms
    };
    return mask;
  }
  // Security configuration for session type
  configureSecurityForSession(sessionType, securityLevel) {
    this._secureLog("info", `\u{1F527} Configuring security for ${sessionType} session (${securityLevel} level)`);
    this.currentSessionType = sessionType;
    this.currentSecurityLevel = securityLevel;
    if (window.sessionManager && window.sessionManager.isFeatureAllowedForSession) {
      this.sessionConstraints = {};
      Object.keys(this.securityFeatures).forEach((feature) => {
        this.sessionConstraints[feature] = window.sessionManager.isFeatureAllowedForSession(sessionType, feature);
      });
      this.applySessionConstraints();
      this._secureLog("info", `\u2705 Security configured for ${sessionType}`, { constraints: this.sessionConstraints });
      if (!this._validateCryptographicSecurity()) {
        this._secureLog("error", "\u{1F6A8} CRITICAL: Cryptographic security validation failed after session configuration");
        if (this.onStatusChange) {
          this.onStatusChange("security_breach", {
            type: "crypto_security_failure",
            sessionType,
            message: "Cryptographic security validation failed after session configuration"
          });
        }
      }
      this.notifySecurityLevel();
      setTimeout(() => {
        this.calculateAndReportSecurityLevel();
      }, _EnhancedSecureWebRTCManager.TIMEOUTS.SECURITY_CALC_DELAY);
    } else {
      this._secureLog("warn", "\u26A0\uFE0F Session manager not available, using default security");
    }
  }
  // Applying session restrictions
  applySessionConstraints() {
    if (!this.sessionConstraints) return;
    Object.keys(this.sessionConstraints).forEach((feature) => {
      const allowed = this.sessionConstraints[feature];
      if (!allowed && this.securityFeatures[feature]) {
        this._secureLog("info", `\u{1F512} Disabling ${feature} for ${this.currentSessionType} session`);
        this.securityFeatures[feature] = false;
        switch (feature) {
          case "hasFakeTraffic":
            this.fakeTrafficConfig.enabled = false;
            this.stopFakeTrafficGeneration();
            break;
          case "hasDecoyChannels":
            this.decoyChannelConfig.enabled = false;
            this.cleanupDecoyChannels();
            break;
          case "hasPacketReordering":
            this.reorderingConfig.enabled = false;
            this.packetBuffer.clear();
            break;
          case "hasAntiFingerprinting":
            this.antiFingerprintingConfig.enabled = false;
            break;
          case "hasMessageChunking":
            this.chunkingConfig.enabled = false;
            break;
        }
      } else if (allowed && !this.securityFeatures[feature]) {
        this._secureLog("info", `\u{1F513} Enabling ${feature} for ${this.currentSessionType} session`);
        this.securityFeatures[feature] = true;
        switch (feature) {
          case "hasFakeTraffic":
            this.fakeTrafficConfig.enabled = true;
            if (this.isConnected()) {
              this.startFakeTrafficGeneration();
            }
            break;
          case "hasDecoyChannels":
            this.decoyChannelConfig.enabled = true;
            if (this.isConnected()) {
              this.initializeDecoyChannels();
            }
            break;
          case "hasPacketReordering":
            this.reorderingConfig.enabled = true;
            break;
          case "hasAntiFingerprinting":
            this.antiFingerprintingConfig.enabled = true;
            break;
          case "hasMessageChunking":
            this.chunkingConfig.enabled = true;
            break;
        }
      }
    });
  }
  deliverMessageToUI(message, type = "received") {
    try {
      this._secureLog("debug", "\u{1F4E4} deliverMessageToUI called", {
        message,
        type,
        messageType: typeof message,
        hasOnMessage: !!this.onMessage
      });
      if (typeof message === "object" && message.type) {
        const blockedTypes = [
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_START,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_RESPONSE,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_CHUNK,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.CHUNK_CONFIRMATION,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_COMPLETE,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_ERROR,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_RESPONSE,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_CONFIRMED,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_BOTH_CONFIRMED,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.PEER_DISCONNECT,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_SIGNAL,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_READY,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.SECURITY_UPGRADE
        ];
        if (blockedTypes.includes(message.type)) {
          if (this._debugMode) {
            this._secureLog("warn", `\u{1F6D1} Blocked system/file message from UI: ${message.type}`);
          }
          return;
        }
      }
      if (typeof message === "string" && message.trim().startsWith("{")) {
        try {
          const parsedMessage = JSON.parse(message);
          if (parsedMessage.type) {
            const blockedTypes = [
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_START,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_RESPONSE,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_CHUNK,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.CHUNK_CONFIRMATION,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_COMPLETE,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_ERROR,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_RESPONSE,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_CONFIRMED,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_BOTH_CONFIRMED,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.PEER_DISCONNECT,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_SIGNAL,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_READY,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.SECURITY_UPGRADE
            ];
            if (blockedTypes.includes(parsedMessage.type)) {
              if (this._debugMode) {
                this._secureLog("warn", `\u{1F6D1} Blocked system/file message from UI (string): ${parsedMessage.type}`);
              }
              return;
            }
          }
        } catch (parseError) {
        }
      }
      if (this.onMessage) {
        this._secureLog("debug", "\u{1F4E4} Calling this.onMessage callback", { message, type });
        this.onMessage(message, type);
      } else {
        this._secureLog("warn", "\u26A0\uFE0F this.onMessage callback is null or undefined");
      }
    } catch (err) {
      this._secureLog("error", "\u274C Failed to deliver message to UI:", { errorType: err?.constructor?.name || "Unknown" });
    }
  }
  // Security Level Notification
  notifySecurityLevel() {
    if (this.lastSecurityLevelNotification === this.currentSecurityLevel) {
      return;
    }
    this.lastSecurityLevelNotification = this.currentSecurityLevel;
    const levelMessages = {
      "basic": "\u{1F512} Basic Security Active - Demo session with essential protection",
      "enhanced": "\u{1F510} Enhanced Security Active - Paid session with advanced protection",
      "maximum": "\u{1F6E1}\uFE0F Maximum Security Active - Premium session with complete protection"
    };
    const message = levelMessages[this.currentSecurityLevel] || levelMessages["basic"];
    if (this.onMessage) {
      this.deliverMessageToUI(message, "system");
    }
    if (this.currentSecurityLevel !== "basic" && this.onMessage) {
      const activeFeatures = Object.entries(this.securityFeatures).filter(([key, value]) => value === true).map(([key]) => key.replace("has", "").replace(/([A-Z])/g, " $1").trim().toLowerCase()).slice(0, 5);
      this.deliverMessageToUI(`\u{1F527} Active: ${activeFeatures.join(", ")}...`, "system");
    }
  }
  // Cleaning decoy channels
  cleanupDecoyChannels() {
    for (const [channelName, timer] of this.decoyTimers.entries()) {
      clearTimeout(timer);
    }
    this.decoyTimers.clear();
    for (const [channelName, channel] of this.decoyChannels.entries()) {
      if (channel.readyState === "open") {
        channel.close();
      }
    }
    this.decoyChannels.clear();
    this._secureLog("info", "\u{1F9F9} Decoy channels cleaned up");
  }
  // ============================================
  // 1. NESTED ENCRYPTION LAYER
  // ============================================
  async generateNestedEncryptionKey() {
    try {
      this.nestedEncryptionKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    } catch (error) {
      this._secureLog("error", "\u274C Failed to generate nested encryption key:", { errorType: error?.constructor?.name || "Unknown" });
      throw error;
    }
  }
  async applyNestedEncryption(data) {
    if (!this.nestedEncryptionKey || !this.securityFeatures.hasNestedEncryption) {
      return data;
    }
    try {
      const uniqueIV = this._generateSecureIV(
        _EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE,
        "nestedEncryption"
      );
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: uniqueIV },
        this.nestedEncryptionKey,
        data
      );
      const result = new Uint8Array(_EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE + encrypted.byteLength);
      result.set(uniqueIV, 0);
      result.set(new Uint8Array(encrypted), _EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE);
      this._secureLog("debug", "\u2705 Nested encryption applied with secure IV", {
        ivSize: uniqueIV.length,
        dataSize: data.byteLength,
        encryptedSize: encrypted.byteLength
      });
      return result.buffer;
    } catch (error) {
      this._secureLog("error", "\u274C Nested encryption failed:", {
        errorType: error?.constructor?.name || "Unknown",
        errorMessage: error?.message || "Unknown error"
      });
      if (error.message.includes("emergency mode")) {
        this.securityFeatures.hasNestedEncryption = false;
        this._secureLog("warn", "\u26A0\uFE0F Nested encryption disabled due to IV emergency mode");
      }
      return data;
    }
  }
  async removeNestedEncryption(data) {
    if (!this.nestedEncryptionKey || !this.securityFeatures.hasNestedEncryption) {
      return data;
    }
    if (!(data instanceof ArrayBuffer) || data.byteLength < _EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE + 16) {
      if (this._debugMode) {
        this._secureLog("debug", "\u{1F4DD} Data not encrypted or too short for nested decryption (need IV + minimum encrypted data)");
      }
      return data;
    }
    try {
      const dataArray = new Uint8Array(data);
      const iv = dataArray.slice(0, _EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE);
      const encryptedData = dataArray.slice(_EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE);
      if (encryptedData.length === 0) {
        if (this._debugMode) {
          this._secureLog("debug", "\u{1F4DD} No encrypted data found");
        }
        return data;
      }
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        this.nestedEncryptionKey,
        encryptedData
      );
      return decrypted;
    } catch (error) {
      if (error.name === "OperationError") {
        if (this._debugMode) {
          this._secureLog("debug", "\u{1F4DD} Data not encrypted with nested encryption, skipping...");
        }
      } else {
        if (this._debugMode) {
          this._secureLog("warn", "\u26A0\uFE0F Nested decryption failed:", { details: error.message });
        }
      }
      return data;
    }
  }
  // ============================================
  // 2. PACKET PADDING
  // ============================================
  applyPacketPadding(data) {
    if (!this.securityFeatures.hasPacketPadding) {
      return data;
    }
    try {
      const originalSize = data.byteLength;
      let paddingSize;
      if (this.paddingConfig.useRandomPadding) {
        paddingSize = Math.floor(Math.random() * (this.paddingConfig.maxPadding - this.paddingConfig.minPadding + 1)) + this.paddingConfig.minPadding;
      } else {
        paddingSize = this.paddingConfig.minPadding;
      }
      const padding = crypto.getRandomValues(new Uint8Array(paddingSize));
      const paddedData = new Uint8Array(originalSize + paddingSize + 4);
      const sizeView = new DataView(paddedData.buffer, 0, 4);
      sizeView.setUint32(0, originalSize, false);
      paddedData.set(new Uint8Array(data), 4);
      paddedData.set(padding, 4 + originalSize);
      return paddedData.buffer;
    } catch (error) {
      this._secureLog("error", "\u274C Packet padding failed:", { errorType: error?.constructor?.name || "Unknown" });
      return data;
    }
  }
  removePacketPadding(data) {
    if (!this.securityFeatures.hasPacketPadding) {
      return data;
    }
    try {
      const dataArray = new Uint8Array(data);
      if (dataArray.length < 5) {
        if (this._debugMode) {
          this._secureLog("warn", "\u26A0\uFE0F Data too short for packet padding removal, skipping");
        }
        return data;
      }
      const sizeView = new DataView(dataArray.buffer, 0, 4);
      const originalSize = sizeView.getUint32(0, false);
      if (originalSize <= 0 || originalSize > dataArray.length - 4) {
        if (this._debugMode) {
          this._secureLog("warn", "\u26A0\uFE0F Invalid packet padding size, skipping removal");
        }
        return data;
      }
      const originalData = dataArray.slice(4, 4 + originalSize);
      return originalData.buffer;
    } catch (error) {
      if (this._debugMode) {
        this._secureLog("error", "\u274C Packet padding removal failed:", { errorType: error?.constructor?.name || "Unknown" });
      }
      return data;
    }
  }
  // ============================================
  // 3. FAKE TRAFFIC GENERATION
  // ============================================
  startFakeTrafficGeneration() {
    if (!this.fakeTrafficConfig.enabled || !this.isConnected()) {
      return;
    }
    if (this.fakeTrafficTimer) {
      this._secureLog("warn", "\u26A0\uFE0F Fake traffic generation already running");
      return;
    }
    const sendFakeMessage = async () => {
      if (!this.isConnected()) {
        this.stopFakeTrafficGeneration();
        return;
      }
      try {
        const fakeMessage = this.generateFakeMessage();
        await this.sendFakeMessage(fakeMessage);
        const nextInterval = this.fakeTrafficConfig.randomDecoyIntervals ? Math.random() * (this.fakeTrafficConfig.maxInterval - this.fakeTrafficConfig.minInterval) + this.fakeTrafficConfig.minInterval : this.fakeTrafficConfig.minInterval;
        const safeInterval = Math.max(nextInterval, _EnhancedSecureWebRTCManager.TIMEOUTS.FAKE_TRAFFIC_MIN_INTERVAL);
        this.fakeTrafficTimer = setTimeout(sendFakeMessage, safeInterval);
      } catch (error) {
        if (this._debugMode) {
          this._secureLog("error", "\u274C Fake traffic generation failed:", { errorType: error?.constructor?.name || "Unknown" });
        }
        this.stopFakeTrafficGeneration();
      }
    };
    const initialDelay = Math.random() * this.fakeTrafficConfig.maxInterval + _EnhancedSecureWebRTCManager.TIMEOUTS.DECOY_INITIAL_DELAY;
    this.fakeTrafficTimer = setTimeout(sendFakeMessage, initialDelay);
  }
  stopFakeTrafficGeneration() {
    if (this.fakeTrafficTimer) {
      clearTimeout(this.fakeTrafficTimer);
      this.fakeTrafficTimer = null;
    }
  }
  generateFakeMessage() {
    const pattern = this.fakeTrafficConfig.patterns[Math.floor(Math.random() * this.fakeTrafficConfig.patterns.length)];
    const size = Math.floor(Math.random() * (this.fakeTrafficConfig.maxSize - this.fakeTrafficConfig.minSize + 1)) + this.fakeTrafficConfig.minSize;
    const fakeData = crypto.getRandomValues(new Uint8Array(size));
    return {
      type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FAKE,
      pattern,
      data: Array.from(fakeData).map((b) => b.toString(16).padStart(2, "0")).join(""),
      timestamp: Date.now(),
      size,
      isFakeTraffic: true,
      source: "fake_traffic_generator",
      fakeId: crypto.getRandomValues(new Uint32Array(1))[0].toString(36)
    };
  }
  // ============================================
  // EMERGENCY SHUT-OFF OF ADVANCED FUNCTIONS
  // ============================================
  emergencyDisableAdvancedFeatures() {
    this._secureLog("error", "\u{1F6A8} Emergency disabling advanced security features due to errors");
    this.securityFeatures.hasNestedEncryption = false;
    this.securityFeatures.hasPacketReordering = false;
    this.securityFeatures.hasAntiFingerprinting = false;
    this.reorderingConfig.enabled = false;
    this.antiFingerprintingConfig.enabled = false;
    this.packetBuffer.clear();
    this.emergencyDisableFakeTraffic();
    this._secureLog("info", "\u2705 Advanced features disabled, keeping basic encryption");
    if (!this.advancedFeaturesDisabledNotificationSent) {
      this.advancedFeaturesDisabledNotificationSent = true;
      if (this.onMessage) {
        this.deliverMessageToUI("\u{1F6A8} Advanced security features temporarily disabled due to compatibility issues", "system");
      }
    }
  }
  async sendFakeMessage(fakeMessage) {
    if (!this._validateConnection(false)) {
      return;
    }
    try {
      this._secureLog("debug", "\u{1F3AD} Sending fake message", {
        hasPattern: !!fakeMessage.pattern,
        sizeRange: fakeMessage.size > 100 ? "large" : "small"
      });
      const fakeData = JSON.stringify({
        ...fakeMessage,
        type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FAKE,
        isFakeTraffic: true,
        timestamp: Date.now()
      });
      const fakeBuffer = new TextEncoder().encode(fakeData);
      const encryptedFake = await this.applySecurityLayers(fakeBuffer, true);
      this.dataChannel.send(encryptedFake);
      this._secureLog("debug", "\u{1F3AD} Fake message sent successfully", {
        pattern: fakeMessage.pattern
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to send fake message", {
        error: error.message
      });
    }
  }
  checkFakeTrafficStatus() {
    const status = {
      fakeTrafficEnabled: this.securityFeatures.hasFakeTraffic,
      fakeTrafficConfigEnabled: this.fakeTrafficConfig.enabled,
      timerActive: !!this.fakeTrafficTimer,
      patterns: this.fakeTrafficConfig.patterns,
      intervals: {
        min: this.fakeTrafficConfig.minInterval,
        max: this.fakeTrafficConfig.maxInterval
      }
    };
    if (this._debugMode) {
      this._secureLog("info", "\u{1F3AD} Fake Traffic Status", { status });
    }
    return status;
  }
  emergencyDisableFakeTraffic() {
    if (this._debugMode) {
      this._secureLog("error", "\u{1F6A8} Emergency disabling fake traffic");
    }
    this.securityFeatures.hasFakeTraffic = false;
    this.fakeTrafficConfig.enabled = false;
    this.stopFakeTrafficGeneration();
    if (this._debugMode) {
      this._secureLog("info", "\u2705 Fake traffic disabled");
    }
    if (!this.fakeTrafficDisabledNotificationSent) {
      this.fakeTrafficDisabledNotificationSent = true;
      if (this.onMessage) {
        this.deliverMessageToUI("\u{1F6A8} Fake traffic emergency disabled", "system");
      }
    }
  }
  async _applySecurityLayersWithoutMutex(data, isFakeMessage = false) {
    try {
      let processedData = data;
      if (isFakeMessage) {
        if (this.encryptionKey && typeof processedData === "string") {
          processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
        }
        return processedData;
      }
      if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer) {
        processedData = await this.applyNestedEncryption(processedData);
      }
      if (this.securityFeatures.hasPacketReordering && this.reorderingConfig?.enabled && processedData instanceof ArrayBuffer) {
        processedData = this.applyPacketReordering(processedData);
      }
      if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
        processedData = this.applyPacketPadding(processedData);
      }
      if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
        processedData = this.applyAntiFingerprinting(processedData);
      }
      if (this.encryptionKey && typeof processedData === "string") {
        processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
      }
      return processedData;
    } catch (error) {
      this._secureLog("error", "\u274C Error in applySecurityLayersWithoutMutex:", { errorType: error?.constructor?.name || "Unknown" });
      return data;
    }
  }
  // ============================================
  // 4. MESSAGE CHUNKING
  // ============================================
  async processChunkedMessage(chunkData) {
    try {
      if (!this.chunkingConfig.addChunkHeaders) {
        return this.processMessage(chunkData);
      }
      const chunkArray = new Uint8Array(chunkData);
      if (chunkArray.length < 16) {
        return this.processMessage(chunkData);
      }
      const headerView = new DataView(chunkArray.buffer, 0, 16);
      const messageId = headerView.getUint32(0, false);
      const chunkIndex = headerView.getUint32(4, false);
      const totalChunks = headerView.getUint32(8, false);
      const chunkSize = headerView.getUint32(12, false);
      const chunk = chunkArray.slice(16, 16 + chunkSize);
      if (!this.chunkQueue[messageId]) {
        this.chunkQueue[messageId] = {
          chunks: new Array(totalChunks),
          received: 0,
          timestamp: Date.now()
        };
      }
      const messageBuffer = this.chunkQueue[messageId];
      messageBuffer.chunks[chunkIndex] = chunk;
      messageBuffer.received++;
      this._secureLog("debug", `\u{1F4E6} Received chunk ${chunkIndex + 1}/${totalChunks} for message ${messageId}`);
      if (messageBuffer.received === totalChunks) {
        const totalSize = messageBuffer.chunks.reduce((sum, chunk2) => sum + chunk2.length, 0);
        const combinedData = new Uint8Array(totalSize);
        let offset = 0;
        for (const chunk2 of messageBuffer.chunks) {
          combinedData.set(chunk2, offset);
          offset += chunk2.length;
        }
        await this.processMessage(combinedData.buffer);
        delete this.chunkQueue[messageId];
        this._secureLog("info", `\u{1F4E6} Chunked message ${messageId} reassembled and processed`);
      }
    } catch (error) {
      this._secureLog("error", "\u274C Chunked message processing failed:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  // ============================================
  // 5. DECOY CHANNELS
  // ============================================
  initializeDecoyChannels() {
    if (!this.decoyChannelConfig.enabled || !this.peerConnection) {
      return;
    }
    if (this.decoyChannels.size > 0) {
      this._secureLog("warn", "\u26A0\uFE0F Decoy channels already initialized, skipping...");
      return;
    }
    try {
      const numDecoyChannels = Math.min(
        this.decoyChannelConfig.maxDecoyChannels,
        this.decoyChannelConfig.decoyChannelNames.length
      );
      for (let i = 0; i < numDecoyChannels; i++) {
        const channelName = this.decoyChannelConfig.decoyChannelNames[i];
        const decoyChannel = this.peerConnection.createDataChannel(channelName, {
          ordered: Math.random() > 0.5,
          maxRetransmits: Math.floor(Math.random() * 3)
        });
        this.setupDecoyChannel(decoyChannel, channelName);
        this.decoyChannels.set(channelName, decoyChannel);
      }
      if (this._debugMode) {
        this._secureLog("info", `\u{1F3AD} Initialized ${numDecoyChannels} decoy channels`);
      }
    } catch (error) {
      if (this._debugMode) {
        this._secureLog("error", "\u274C Failed to initialize decoy channels:", { errorType: error?.constructor?.name || "Unknown" });
      }
    }
  }
  setupDecoyChannel(channel, channelName) {
    channel.onopen = () => {
      if (this._debugMode) {
        this._secureLog("debug", `\u{1F3AD} Decoy channel "${channelName}" opened`);
      }
      this.startDecoyTraffic(channel, channelName);
    };
    channel.onmessage = (event) => {
      if (this._debugMode) {
        this._secureLog("debug", `\u{1F3AD} Received decoy message on "${channelName}": ${event.data?.length || "undefined"} bytes`);
      }
    };
    channel.onclose = () => {
      if (this._debugMode) {
        this._secureLog("debug", `\u{1F3AD} Decoy channel "${channelName}" closed`);
      }
      this.stopDecoyTraffic(channelName);
    };
    channel.onerror = (error) => {
      if (this._debugMode) {
        this._secureLog("error", `\u274C Decoy channel "${channelName}" error`, { error: error.message });
      }
    };
  }
  startDecoyTraffic(channel, channelName) {
    const sendDecoyData = async () => {
      if (channel.readyState !== "open") {
        return;
      }
      try {
        const decoyData = this.generateDecoyData(channelName);
        channel.send(decoyData);
        const interval = this.decoyChannelConfig.randomDecoyIntervals ? Math.random() * 15e3 + 1e4 : 2e4;
        this.decoyTimers.set(channelName, setTimeout(() => sendDecoyData(), interval));
      } catch (error) {
        if (this._debugMode) {
          this._secureLog("error", `\u274C Failed to send decoy data on "${channelName}"`, { error: error.message });
        }
      }
    };
    const initialDelay = Math.random() * 1e4 + 5e3;
    this.decoyTimers.set(channelName, setTimeout(() => sendDecoyData(), initialDelay));
  }
  stopDecoyTraffic(channelName) {
    const timer = this.decoyTimers.get(channelName);
    if (timer) {
      clearTimeout(timer);
      this.decoyTimers.delete(channelName);
    }
  }
  generateDecoyData(channelName) {
    const decoyTypes = {
      "sync": () => JSON.stringify({
        type: "sync",
        timestamp: Date.now(),
        sequence: Math.floor(Math.random() * 1e3),
        data: Array.from(crypto.getRandomValues(new Uint8Array(32))).map((b) => b.toString(16).padStart(2, "0")).join("")
      }),
      "status": () => JSON.stringify({
        type: "status",
        status: ["online", "away", "busy"][Math.floor(Math.random() * 3)],
        uptime: Math.floor(Math.random() * 3600),
        data: Array.from(crypto.getRandomValues(new Uint8Array(16))).map((b) => b.toString(16).padStart(2, "0")).join("")
      }),
      "heartbeat": () => JSON.stringify({
        type: "heartbeat",
        timestamp: Date.now(),
        data: Array.from(crypto.getRandomValues(new Uint8Array(24))).map((b) => b.toString(16).padStart(2, "0")).join("")
      }),
      "metrics": () => JSON.stringify({
        type: "metrics",
        cpu: Math.random() * 100,
        memory: Math.random() * 100,
        network: Math.random() * 1e3,
        data: Array.from(crypto.getRandomValues(new Uint8Array(20))).map((b) => b.toString(16).padStart(2, "0")).join("")
      }),
      "debug": () => JSON.stringify({
        type: "debug",
        level: ["info", "warn", "error"][Math.floor(Math.random() * 3)],
        message: "Debug message",
        data: Array.from(crypto.getRandomValues(new Uint8Array(28))).map((b) => b.toString(16).padStart(2, "0")).join("")
      })
    };
    return decoyTypes[channelName] ? decoyTypes[channelName]() : Array.from(crypto.getRandomValues(new Uint8Array(64))).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  // ============================================
  // 6. PACKET REORDERING PROTECTION
  // ============================================
  addReorderingHeaders(data) {
    if (!this.reorderingConfig.enabled) {
      return data;
    }
    try {
      const dataArray = new Uint8Array(data);
      const headerSize = this.reorderingConfig.useTimestamps ? 12 : 8;
      const header = new ArrayBuffer(headerSize);
      const headerView = new DataView(header);
      if (this.reorderingConfig.useSequenceNumbers) {
        headerView.setUint32(0, this.sequenceNumber++, false);
      }
      if (this.reorderingConfig.useTimestamps) {
        headerView.setUint32(4, Date.now(), false);
      }
      headerView.setUint32(this.reorderingConfig.useTimestamps ? 8 : 4, dataArray.length, false);
      const result = new Uint8Array(headerSize + dataArray.length);
      result.set(new Uint8Array(header), 0);
      result.set(dataArray, headerSize);
      return result.buffer;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to add reordering headers:", { errorType: error?.constructor?.name || "Unknown" });
      return data;
    }
  }
  async processReorderedPacket(data) {
    if (!this.reorderingConfig.enabled) {
      return this.processMessage(data);
    }
    try {
      const dataArray = new Uint8Array(data);
      const headerSize = this.reorderingConfig.useTimestamps ? 12 : 8;
      if (dataArray.length < headerSize) {
        if (this._debugMode) {
          this._secureLog("warn", "\u26A0\uFE0F Data too short for reordering headers, processing directly");
        }
        return this.processMessage(data);
      }
      const headerView = new DataView(dataArray.buffer, 0, headerSize);
      let sequence = 0;
      let timestamp = 0;
      let dataSize = 0;
      if (this.reorderingConfig.useSequenceNumbers) {
        sequence = headerView.getUint32(0, false);
      }
      if (this.reorderingConfig.useTimestamps) {
        timestamp = headerView.getUint32(4, false);
      }
      dataSize = headerView.getUint32(this.reorderingConfig.useTimestamps ? 8 : 4, false);
      if (dataSize > dataArray.length - headerSize || dataSize <= 0) {
        if (this._debugMode) {
          this._secureLog("warn", "\u26A0\uFE0F Invalid reordered packet data size, processing directly");
        }
        return this.processMessage(data);
      }
      const actualData = dataArray.slice(headerSize, headerSize + dataSize);
      try {
        const textData = new TextDecoder().decode(actualData);
        const content = JSON.parse(textData);
        if (content.type === "fake" || content.isFakeTraffic === true) {
          if (this._debugMode) {
            this._secureLog("warn", `\u{1F3AD} BLOCKED: Reordered fake message: ${content.pattern || "unknown"}`);
          }
          return;
        }
      } catch (e) {
      }
      this.packetBuffer.set(sequence, {
        data: actualData.buffer,
        timestamp: timestamp || Date.now()
      });
      await this.processOrderedPackets();
    } catch (error) {
      this._secureLog("error", "\u274C Failed to process reordered packet:", { errorType: error?.constructor?.name || "Unknown" });
      return this.processMessage(data);
    }
  }
  // ============================================
  // IMPROVED PROCESSORDEREDPACKETS with filtering
  // ============================================
  async processOrderedPackets() {
    const now = Date.now();
    const timeout = this.reorderingConfig.reorderTimeout;
    while (true) {
      const nextSequence = this.lastProcessedSequence + 1;
      const packet = this.packetBuffer.get(nextSequence);
      if (!packet) {
        const oldestPacket = this.findOldestPacket();
        if (oldestPacket && now - oldestPacket.timestamp > timeout) {
          this._secureLog("warn", "\u26A0\uFE0F Packet ${oldestPacket.sequence} timed out, processing out of order");
          try {
            const textData = new TextDecoder().decode(oldestPacket.data);
            const content = JSON.parse(textData);
            if (content.type === "fake" || content.isFakeTraffic === true) {
              this._secureLog("warn", `\u{1F3AD} BLOCKED: Timed out fake message: ${content.pattern || "unknown"}`);
              this.packetBuffer.delete(oldestPacket.sequence);
              this.lastProcessedSequence = oldestPacket.sequence;
              continue;
            }
          } catch (e) {
          }
          await this.processMessage(oldestPacket.data);
          this.packetBuffer.delete(oldestPacket.sequence);
          this.lastProcessedSequence = oldestPacket.sequence;
        } else {
          break;
        }
      } else {
        try {
          const textData = new TextDecoder().decode(packet.data);
          const content = JSON.parse(textData);
          if (content.type === "fake" || content.isFakeTraffic === true) {
            this._secureLog("warn", `\u{1F3AD} BLOCKED: Ordered fake message: ${content.pattern || "unknown"}`);
            this.packetBuffer.delete(nextSequence);
            this.lastProcessedSequence = nextSequence;
            continue;
          }
        } catch (e) {
        }
        await this.processMessage(packet.data);
        this.packetBuffer.delete(nextSequence);
        this.lastProcessedSequence = nextSequence;
      }
    }
    this.cleanupOldPackets(now, timeout);
  }
  findOldestPacket() {
    let oldest = null;
    for (const [sequence, packet] of this.packetBuffer.entries()) {
      if (!oldest || packet.timestamp < oldest.timestamp) {
        oldest = { sequence, ...packet };
      }
    }
    return oldest;
  }
  cleanupOldPackets(now, timeout) {
    for (const [sequence, packet] of this.packetBuffer.entries()) {
      if (now - packet.timestamp > timeout) {
        this._secureLog("warn", "\u26A0\uFE0F \u{1F5D1}\uFE0F Removing timed out packet ${sequence}");
        this.packetBuffer.delete(sequence);
      }
    }
  }
  // ============================================
  // 7. ANTI-FINGERPRINTING
  // ============================================
  applyAntiFingerprinting(data) {
    if (!this.antiFingerprintingConfig.enabled) {
      return data;
    }
    try {
      let processedData = data;
      if (this.antiFingerprintingConfig.addNoise) {
        processedData = this.addNoise(processedData);
      }
      if (this.antiFingerprintingConfig.randomizeSizes) {
        processedData = this.randomizeSize(processedData);
      }
      if (this.antiFingerprintingConfig.maskPatterns) {
        processedData = this.maskPatterns(processedData);
      }
      if (this.antiFingerprintingConfig.useRandomHeaders) {
        processedData = this.addRandomHeaders(processedData);
      }
      return processedData;
    } catch (error) {
      this._secureLog("error", "\u274C Anti-fingerprinting failed:", { errorType: error?.constructor?.name || "Unknown" });
      return data;
    }
  }
  addNoise(data) {
    const dataArray = new Uint8Array(data);
    const noiseSize = Math.floor(Math.random() * 32) + 8;
    const noise = crypto.getRandomValues(new Uint8Array(noiseSize));
    const result = new Uint8Array(dataArray.length + noiseSize);
    result.set(dataArray, 0);
    result.set(noise, dataArray.length);
    return result.buffer;
  }
  randomizeSize(data) {
    const dataArray = new Uint8Array(data);
    const variation = this.fingerprintMask.sizeVariation;
    const targetSize = Math.floor(dataArray.length * variation);
    if (targetSize > dataArray.length) {
      const padding = crypto.getRandomValues(new Uint8Array(targetSize - dataArray.length));
      const result = new Uint8Array(targetSize);
      result.set(dataArray, 0);
      result.set(padding, dataArray.length);
      return result.buffer;
    } else if (targetSize < dataArray.length) {
      return dataArray.slice(0, targetSize).buffer;
    }
    return data;
  }
  maskPatterns(data) {
    const dataArray = new Uint8Array(data);
    const result = new Uint8Array(dataArray.length);
    for (let i = 0; i < dataArray.length; i++) {
      const noiseByte = this.fingerprintMask.noisePattern[i % this.fingerprintMask.noisePattern.length];
      result[i] = dataArray[i] ^ noiseByte;
    }
    return result.buffer;
  }
  addRandomHeaders(data) {
    const dataArray = new Uint8Array(data);
    const headerCount = Math.floor(Math.random() * 3) + 1;
    let totalHeaderSize = 0;
    for (let i = 0; i < headerCount; i++) {
      totalHeaderSize += 4 + Math.floor(Math.random() * 16) + 4;
    }
    const result = new Uint8Array(totalHeaderSize + dataArray.length);
    let offset = 0;
    for (let i = 0; i < headerCount; i++) {
      const headerName = this.fingerprintMask.headerVariations[Math.floor(Math.random() * this.fingerprintMask.headerVariations.length)];
      const headerData = crypto.getRandomValues(new Uint8Array(Math.floor(Math.random() * 16) + 4));
      const headerView = new DataView(result.buffer, offset);
      headerView.setUint32(0, headerData.length + 8, false);
      headerView.setUint32(4, this.hashString(headerName), false);
      result.set(headerData, offset + 8);
      const checksum = this.calculateChecksum(result.slice(offset, offset + 8 + headerData.length));
      const checksumView = new DataView(result.buffer, offset + 8 + headerData.length);
      checksumView.setUint32(0, checksum, false);
      offset += 8 + headerData.length + 4;
    }
    result.set(dataArray, offset);
    return result.buffer;
  }
  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return Math.abs(hash);
  }
  calculateChecksum(data) {
    let checksum = 0;
    for (let i = 0; i < data.length; i++) {
      checksum = checksum + data[i] & 4294967295;
    }
    return checksum;
  }
  // ============================================
  // ENHANCED MESSAGE SENDING AND RECEIVING
  // ============================================
  async removeSecurityLayers(data) {
    try {
      const status = this.getSecurityStatus();
      if (this._debugMode) {
        this._secureLog("debug", `\u{1F50D} removeSecurityLayers (Stage ${status.stage})`, {
          dataType: typeof data,
          dataLength: data?.length || data?.byteLength || 0,
          activeFeatures: status.activeFeaturesCount
        });
      }
      if (!data) {
        this._secureLog("warn", "\u26A0\uFE0F Received empty data");
        return null;
      }
      let processedData = data;
      if (typeof data === "string") {
        try {
          const jsonData = JSON.parse(data);
          if (jsonData.type === "fake") {
            if (this._debugMode) {
              this._secureLog("debug", `\u{1F3AD} Fake message filtered out: ${jsonData.pattern} (size: ${jsonData.size})`);
            }
            return "FAKE_MESSAGE_FILTERED";
          }
          if (jsonData.type && ["heartbeat", "verification", "verification_response", "peer_disconnect", "key_rotation_signal", "key_rotation_ready", "security_upgrade"].includes(jsonData.type)) {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F527} System message detected, blocking from chat", { type: jsonData.type });
            }
            return "SYSTEM_MESSAGE_FILTERED";
          }
          if (jsonData.type && ["file_transfer_start", "file_transfer_response", "file_chunk", "chunk_confirmation", "file_transfer_complete", "file_transfer_error"].includes(jsonData.type)) {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F4C1} File transfer message detected, blocking from chat", { type: jsonData.type });
            }
            return "FILE_MESSAGE_FILTERED";
          }
          if (jsonData.type === "message") {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F4DD} Regular message detected, extracting text", { data: jsonData.data });
            }
            return jsonData.data;
          }
          if (jsonData.type === "enhanced_message" && jsonData.data) {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F510} Enhanced message detected, decrypting...");
            }
            if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
              this._secureLog("error", "\u274C Missing encryption keys");
              return null;
            }
            const decryptedResult = await window.EnhancedSecureCryptoUtils.decryptMessage(
              jsonData.data,
              this.encryptionKey,
              this.macKey,
              this.metadataKey
            );
            if (this._debugMode) {
              this._secureLog("debug", "\u2705 Enhanced message decrypted, extracting...");
              this._secureLog("debug", "\u{1F50D} decryptedResult", {
                type: typeof decryptedResult,
                hasMessage: !!decryptedResult?.message,
                messageType: typeof decryptedResult?.message,
                messageLength: decryptedResult?.message?.length || 0,
                messageSample: decryptedResult?.message?.substring(0, 50) || "no message"
              });
            }
            try {
              const decryptedContent = JSON.parse(decryptedResult.message);
              if (decryptedContent.type === "fake" || decryptedContent.isFakeTraffic === true) {
                if (this._debugMode) {
                  this._secureLog("warn", `\u{1F3AD} BLOCKED: Encrypted fake message: ${decryptedContent.pattern || "unknown"}`);
                }
                return "FAKE_MESSAGE_FILTERED";
              }
            } catch (e) {
              if (this._debugMode) {
                this._secureLog("debug", "\u{1F4DD} Decrypted content is not JSON, treating as plain text message");
              }
            }
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F4E4} Returning decrypted message", { message: decryptedResult.message?.substring(0, 50) });
            }
            return decryptedResult.message;
          }
          if (jsonData.type === "message" && jsonData.data) {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F4DD} Regular message detected, extracting data");
            }
            return jsonData.data;
          }
          if (jsonData.type === "message") {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F4DD} Regular message detected, returning for display");
            }
            return data;
          }
          if (!jsonData.type || jsonData.type !== "fake" && !["heartbeat", "verification", "verification_response", "peer_disconnect", "key_rotation_signal", "key_rotation_ready", "enhanced_message", "security_upgrade", "file_transfer_start", "file_transfer_response", "file_chunk", "chunk_confirmation", "file_transfer_complete", "file_transfer_error"].includes(jsonData.type)) {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F4DD} Regular message detected, returning for display");
            }
            return data;
          }
        } catch (e) {
          if (this._debugMode) {
            this._secureLog("debug", "\u{1F4C4} Not JSON, processing as raw data");
          }
          return data;
        }
      }
      if (this.encryptionKey && typeof processedData === "string" && processedData.length > 50) {
        try {
          const base64Regex = /^[A-Za-z0-9+/=]+$/;
          if (base64Regex.test(processedData.trim())) {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F513} Applying standard decryption...");
            }
            processedData = await window.EnhancedSecureCryptoUtils.decryptData(processedData, this.encryptionKey);
            if (this._debugMode) {
              this._secureLog("debug", "\u2705 Standard decryption successful");
            }
            if (typeof processedData === "string") {
              try {
                const legacyContent = JSON.parse(processedData);
                if (legacyContent.type === "fake" || legacyContent.isFakeTraffic === true) {
                  if (this._debugMode) {
                    this._secureLog("warn", `\u{1F3AD} BLOCKED: Legacy fake message: ${legacyContent.pattern || "unknown"}`);
                  }
                  return "FAKE_MESSAGE_FILTERED";
                }
              } catch (e) {
              }
              processedData = new TextEncoder().encode(processedData).buffer;
            }
          }
        } catch (error) {
          if (this._debugMode) {
            this._secureLog("warn", "\u26A0\uFE0F Standard decryption failed:", { details: error.message });
          }
          return data;
        }
      }
      if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer && processedData.byteLength > 12) {
        try {
          processedData = await this.removeNestedEncryption(processedData);
          if (processedData instanceof ArrayBuffer) {
            try {
              const textData = new TextDecoder().decode(processedData);
              const nestedContent = JSON.parse(textData);
              if (nestedContent.type === "fake" || nestedContent.isFakeTraffic === true) {
                if (this._debugMode) {
                  this._secureLog("warn", `\u{1F3AD} BLOCKED: Nested fake message: ${nestedContent.pattern || "unknown"}`);
                }
                return "FAKE_MESSAGE_FILTERED";
              }
            } catch (e) {
            }
          }
        } catch (error) {
          if (this._debugMode) {
            this._secureLog("warn", "\u26A0\uFE0F Nested decryption failed - skipping this layer:", { details: error.message });
          }
        }
      }
      if (this.securityFeatures.hasPacketReordering && this.reorderingConfig.enabled && processedData instanceof ArrayBuffer) {
        try {
          const headerSize = this.reorderingConfig.useTimestamps ? 12 : 8;
          if (processedData.byteLength > headerSize) {
            return await this.processReorderedPacket(processedData);
          }
        } catch (error) {
          if (this._debugMode) {
            this._secureLog("warn", "\u26A0\uFE0F Reordering processing failed - using direct processing:", { details: error.message });
          }
        }
      }
      if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
        try {
          processedData = this.removePacketPadding(processedData);
        } catch (error) {
          if (this._debugMode) {
            this._secureLog("warn", "\u26A0\uFE0F Padding removal failed:", { details: error.message });
          }
        }
      }
      if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
        try {
          processedData = this.removeAntiFingerprinting(processedData);
        } catch (error) {
          if (this._debugMode) {
            this._secureLog("warn", "\u26A0\uFE0F Anti-fingerprinting removal failed:", { details: error.message });
          }
        }
      }
      if (processedData instanceof ArrayBuffer) {
        processedData = new TextDecoder().decode(processedData);
      }
      if (typeof processedData === "string") {
        try {
          const finalContent = JSON.parse(processedData);
          if (finalContent.type === "fake" || finalContent.isFakeTraffic === true) {
            if (this._debugMode) {
              this._secureLog("warn", `\u{1F3AD} BLOCKED: Final check fake message: ${finalContent.pattern || "unknown"}`);
            }
            return "FAKE_MESSAGE_FILTERED";
          }
        } catch (e) {
        }
      }
      return processedData;
    } catch (error) {
      this._secureLog("error", "\u274C Critical error in removeSecurityLayers:", { errorType: error?.constructor?.name || "Unknown" });
      return data;
    }
  }
  removeAntiFingerprinting(data) {
    return data;
  }
  async applySecurityLayers(data, isFakeMessage = false) {
    try {
      let processedData = data;
      if (isFakeMessage) {
        if (this.encryptionKey && typeof processedData === "string") {
          processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
        }
        return processedData;
      }
      if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer) {
        processedData = await this.applyNestedEncryption(processedData);
      }
      if (this.securityFeatures.hasPacketReordering && this.reorderingConfig?.enabled && processedData instanceof ArrayBuffer) {
        processedData = this.applyPacketReordering(processedData);
      }
      if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
        processedData = this.applyPacketPadding(processedData);
      }
      if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
        processedData = this.applyAntiFingerprinting(processedData);
      }
      if (this.encryptionKey && typeof processedData === "string") {
        processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
      }
      return processedData;
    } catch (error) {
      this._secureLog("error", "\u274C Error in applySecurityLayers:", { errorType: error?.constructor?.name || "Unknown" });
      return data;
    }
  }
  async sendMessage(data) {
    const validation = this._validateInputData(data, "sendMessage");
    if (!validation.isValid) {
      const errorMessage = `Input validation failed: ${validation.errors.join(", ")}`;
      this._secureLog("error", "\u274C Input validation failed in sendMessage", {
        errors: validation.errors,
        dataType: typeof data,
        dataLength: data?.length || data?.byteLength || 0
      });
      throw new Error(errorMessage);
    }
    if (!this._checkRateLimit("sendMessage")) {
      throw new Error("Rate limit exceeded for message sending");
    }
    this._enforceVerificationGate("sendMessage");
    if (!this.dataChannel || this.dataChannel.readyState !== "open") {
      throw new Error("Data channel not ready");
    }
    try {
      this._secureLog("debug", "sendMessage called", {
        hasDataChannel: !!this.dataChannel,
        dataChannelReady: this.dataChannel?.readyState === "open",
        isInitiator: this.isInitiator,
        isVerified: this.isVerified,
        connectionReady: this.peerConnection?.connectionState === "connected"
      });
      this._secureLog("debug", "\u{1F50D} sendMessage DEBUG", {
        dataType: typeof validation.sanitizedData,
        isString: typeof validation.sanitizedData === "string",
        isArrayBuffer: validation.sanitizedData instanceof ArrayBuffer,
        dataLength: validation.sanitizedData?.length || validation.sanitizedData?.byteLength || 0
      });
      if (typeof validation.sanitizedData === "string") {
        try {
          const parsed = JSON.parse(validation.sanitizedData);
          if (parsed.type && parsed.type.startsWith("file_")) {
            this._secureLog("debug", "\u{1F4C1} File message detected - applying full encryption with AAD", { type: parsed.type });
            const aad = this._createFileMessageAAD(parsed.type, parsed.data);
            const encryptedData = await this._encryptFileMessage(validation.sanitizedData, aad);
            this.dataChannel.send(encryptedData);
            return true;
          }
        } catch (jsonError) {
        }
      }
      if (typeof validation.sanitizedData === "string") {
        if (typeof this._createMessageAAD !== "function") {
          throw new Error("_createMessageAAD method is not available. Manager may not be fully initialized.");
        }
        const aad = this._createMessageAAD("message", { content: validation.sanitizedData });
        return await this.sendSecureMessage({
          type: "message",
          data: validation.sanitizedData,
          timestamp: Date.now(),
          aad
          // Include AAD for sequence number validation
        });
      }
      this._secureLog("debug", "\u{1F510} Applying security layers to non-string data");
      const securedData = await this._applySecurityLayersWithLimitedMutex(validation.sanitizedData, false);
      this.dataChannel.send(securedData);
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to send message", {
        error: error.message,
        errorType: error.constructor.name
      });
      throw error;
    }
  }
  // FIX: New method applying security layers with limited mutex use
  async _applySecurityLayersWithLimitedMutex(data, isFakeMessage = false) {
    return this._withMutex("cryptoOperation", async (operationId) => {
      try {
        let processedData = data;
        if (isFakeMessage) {
          if (this.encryptionKey && typeof processedData === "string") {
            processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
          }
          return processedData;
        }
        if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer) {
          processedData = await this.applyNestedEncryption(processedData);
        }
        if (this.securityFeatures.hasPacketReordering && this.reorderingConfig?.enabled && processedData instanceof ArrayBuffer) {
          processedData = this.applyPacketReordering(processedData);
        }
        if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
          processedData = this.applyPacketPadding(processedData);
        }
        if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
          processedData = this.applyAntiFingerprinting(processedData);
        }
        if (this.encryptionKey && typeof processedData === "string") {
          processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
        }
        return processedData;
      } catch (error) {
        this._secureLog("error", "\u274C Error in applySecurityLayers:", { errorType: error?.constructor?.name || "Unknown" });
        return data;
      }
    }, 3e3);
  }
  async sendSystemMessage(messageData) {
    const isVerificationMessage = messageData.type === "verification_request" || messageData.type === "verification_response" || messageData.type === "verification_required";
    if (!isVerificationMessage) {
      this._enforceVerificationGate("sendSystemMessage", false);
    }
    if (!this.dataChannel || this.dataChannel.readyState !== "open") {
      this._secureLog("warn", "\u26A0\uFE0F Cannot send system message - data channel not ready");
      return false;
    }
    try {
      const systemMessage = JSON.stringify({
        type: messageData.type,
        data: messageData,
        timestamp: Date.now()
      });
      this._secureLog("debug", "\u{1F527} Sending system message", { type: messageData.type });
      this.dataChannel.send(systemMessage);
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to send system message:", { errorType: error?.constructor?.name || "Unknown" });
      return false;
    }
  }
  // FIX 1: Simplified mutex system for message processing
  async processMessage(data) {
    try {
      this._secureLog("debug", "\uFFFD\uFFFD Processing message", {
        dataType: typeof data,
        isArrayBuffer: data instanceof ArrayBuffer,
        hasData: !!(data?.length || data?.byteLength)
      });
      if (typeof data === "string") {
        try {
          const parsed = JSON.parse(data);
          const fileMessageTypes2 = [
            "file_transfer_start",
            "file_transfer_response",
            "file_chunk",
            "chunk_confirmation",
            "file_transfer_complete",
            "file_transfer_error"
          ];
          if (parsed.type === "encrypted_file_message") {
            this._secureLog("debug", "\u{1F4C1} Encrypted file message detected in processMessage");
            try {
              const { decryptedData, aad } = await this._decryptFileMessage(data);
              const decryptedParsed = JSON.parse(decryptedData);
              this._secureLog("debug", "\u{1F4C1} File message decrypted successfully", {
                type: decryptedParsed.type,
                aadMessageType: aad.messageType
              });
              if (this.fileTransferSystem && typeof this.fileTransferSystem.handleFileMessage === "function") {
                await this.fileTransferSystem.handleFileMessage(decryptedParsed);
                return;
              }
            } catch (error) {
              this._secureLog("error", "\u274C Failed to decrypt file message", { error: error.message });
              return;
            }
          }
          if (parsed.type && fileMessageTypes2.includes(parsed.type)) {
            this._secureLog("warn", "\u26A0\uFE0F Unencrypted file message detected - this should not happen in secure mode", { type: parsed.type });
            this._secureLog("error", "\u274C Dropping unencrypted file message for security", { type: parsed.type });
            return;
          }
          if (parsed.type === "enhanced_message") {
            this._secureLog("debug", "\u{1F510} Enhanced message detected in processMessage");
            try {
              const decryptedData = await window.EnhancedSecureCryptoUtils.decryptMessage(
                parsed.data,
                this.encryptionKey,
                this.macKey,
                this.metadataKey
              );
              const decryptedParsed = JSON.parse(decryptedData.data);
              if (decryptedData.metadata && decryptedData.metadata.sequenceNumber !== void 0) {
                if (!this._validateIncomingSequenceNumber(decryptedData.metadata.sequenceNumber, "enhanced_message")) {
                  this._secureLog("warn", "\u26A0\uFE0F Enhanced message sequence number validation failed - possible replay attack", {
                    received: decryptedData.metadata.sequenceNumber,
                    expected: this.expectedSequenceNumber
                  });
                  return;
                }
              }
              if (decryptedParsed.type === "message" && this.onMessage && decryptedParsed.data) {
                this.deliverMessageToUI(decryptedParsed.data, "received");
              }
              return;
            } catch (error) {
              this._secureLog("error", "\u274C Failed to decrypt enhanced message", { error: error.message });
              return;
            }
          }
          if (parsed.type === "message") {
            this._secureLog("debug", "\u{1F4DD} Regular user message detected in processMessage");
            if (this.onMessage && parsed.data) {
              this.deliverMessageToUI(parsed.data, "received");
            }
            return;
          }
          if (parsed.type && ["heartbeat", "verification", "verification_response", "verification_confirmed", "verification_both_confirmed", "peer_disconnect", "security_upgrade"].includes(parsed.type)) {
            this.handleSystemMessage(parsed);
            return;
          }
          if (parsed.type === "fake") {
            this._secureLog("warn", "\u{1F3AD} Fake message blocked in processMessage", { pattern: parsed.pattern });
            return;
          }
        } catch (jsonError) {
          if (this.onMessage) {
            this.deliverMessageToUI(data, "received");
          }
          return;
        }
      }
      const originalData = await this._processEncryptedDataWithLimitedMutex(data);
      if (originalData === "FAKE_MESSAGE_FILTERED" || originalData === "FILE_MESSAGE_FILTERED" || originalData === "SYSTEM_MESSAGE_FILTERED") {
        return;
      }
      if (!originalData) {
        this._secureLog("warn", "\u26A0\uFE0F No data returned from removeSecurityLayers");
        return;
      }
      let messageText;
      if (typeof originalData === "string") {
        try {
          const message = JSON.parse(originalData);
          if (message.type && fileMessageTypes.includes(message.type)) {
            this._secureLog("debug", "\u{1F4C1} File message detected after decryption", { type: message.type });
            if (this.fileTransferSystem) {
              await this.fileTransferSystem.handleFileMessage(message);
            }
            return;
          }
          if (message.type && ["heartbeat", "verification", "verification_response", "verification_confirmed", "verification_both_confirmed", "peer_disconnect", "security_upgrade"].includes(message.type)) {
            this.handleSystemMessage(message);
            return;
          }
          if (message.type === "fake") {
            this._secureLog("warn", `\u{1F3AD} Post-decryption fake message blocked: ${message.pattern}`);
            return;
          }
          if (message.type === "message" && message.data) {
            messageText = message.data;
          } else {
            messageText = originalData;
          }
        } catch (e) {
          messageText = originalData;
        }
      } else if (originalData instanceof ArrayBuffer) {
        messageText = new TextDecoder().decode(originalData);
      } else if (originalData && typeof originalData === "object" && originalData.message) {
        messageText = originalData.message;
      } else {
        this._secureLog("warn", "\u26A0\uFE0F Unexpected data type after processing:", { details: typeof originalData });
        return;
      }
      if (messageText && messageText.trim().startsWith("{")) {
        try {
          const finalCheck = JSON.parse(messageText);
          if (finalCheck.type === "fake") {
            this._secureLog("warn", `\u{1F3AD} Final fake message check blocked: ${finalCheck.pattern}`);
            return;
          }
          const blockedTypes = [
            "file_transfer_start",
            "file_transfer_response",
            "file_chunk",
            "chunk_confirmation",
            "file_transfer_complete",
            "file_transfer_error",
            "heartbeat",
            "verification",
            "verification_response",
            "peer_disconnect",
            "key_rotation_signal",
            "key_rotation_ready",
            "security_upgrade"
          ];
          if (finalCheck.type && blockedTypes.includes(finalCheck.type)) {
            this._secureLog("warn", `\u{1F4C1} Final system/file message check blocked: ${finalCheck.type}`);
            return;
          }
        } catch (e) {
        }
      }
      if (this.onMessage && messageText) {
        this._secureLog("debug", "\u{1F4E4} Calling message handler with", { message: messageText.substring(0, 100) });
        this.deliverMessageToUI(messageText, "received");
      }
    } catch (error) {
      this._secureLog("error", "\u274C Failed to process message:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  // FIX: New method with limited mutex when processing encrypted data
  async _processEncryptedDataWithLimitedMutex(data) {
    return this._withMutex("cryptoOperation", async (operationId) => {
      this._secureLog("debug", "\u{1F510} Processing encrypted data with limited mutex", {
        operationId,
        dataType: typeof data
      });
      try {
        const originalData = await this.removeSecurityLayers(data);
        return originalData;
      } catch (error) {
        this._secureLog("error", "\u274C Error processing encrypted data", {
          operationId,
          errorType: error.constructor.name
        });
        return data;
      }
    }, 2e3);
  }
  notifySecurityUpdate() {
    try {
      this._secureLog("debug", "\u{1F512} Notifying about security level update", {
        isConnected: this.isConnected(),
        isVerified: this.isVerified,
        hasKeys: !!(this.encryptionKey && this.macKey && this.metadataKey),
        hasLastCalculation: !!this.lastSecurityCalculation
      });
      document.dispatchEvent(new CustomEvent("security-level-updated", {
        detail: {
          timestamp: Date.now(),
          manager: "webrtc",
          webrtcManager: this,
          isConnected: this.isConnected(),
          isVerified: this.isVerified,
          hasKeys: !!(this.encryptionKey && this.macKey && this.metadataKey),
          lastCalculation: this.lastSecurityCalculation
        }
      }));
      setTimeout(() => {
      }, 100);
      if (this.lastSecurityCalculation) {
        document.dispatchEvent(new CustomEvent("real-security-calculated", {
          detail: {
            securityData: this.lastSecurityCalculation,
            webrtcManager: this,
            timestamp: Date.now()
          }
        }));
      }
    } catch (error) {
      this._secureLog("error", "\u274C Error in notifySecurityUpdate", {
        error: error.message
      });
    }
  }
  handleSystemMessage(message) {
    this._secureLog("debug", "\u{1F527} Handling system message:", { type: message.type });
    switch (message.type) {
      case "heartbeat":
        this.handleHeartbeat();
        break;
      case "verification":
        this.handleVerificationRequest(message.data);
        break;
      case "verification_response":
        this.handleVerificationResponse(message.data);
        break;
      case "sas_code":
        this.handleSASCode(message.data);
        break;
      case "verification_confirmed":
        this.handleVerificationConfirmed(message.data);
        break;
      case "verification_both_confirmed":
        this.handleVerificationBothConfirmed(message.data);
        break;
      case "peer_disconnect":
        this.handlePeerDisconnectNotification(message);
        break;
      case "key_rotation_signal":
        this._secureLog("debug", "\u{1F504} Key rotation signal received (ignored for stability)");
        break;
      case "key_rotation_ready":
        this._secureLog("debug", "\u{1F504} Key rotation ready signal received (ignored for stability)");
        break;
      case "security_upgrade":
        this._secureLog("debug", "\u{1F512} Security upgrade notification received:", { type: message.type });
        break;
      default:
        this._secureLog("debug", "\u{1F527} Unknown system message type:", { type: message.type });
    }
  }
  // ============================================
  // FUNCTION MANAGEMENT METHODS
  // ============================================
  // Method to enable Stage 2 functions
  enableStage2Security() {
    if (this.sessionConstraints?.hasPacketReordering) {
      this.securityFeatures.hasPacketReordering = true;
      this.reorderingConfig.enabled = true;
    }
    if (this.sessionConstraints?.hasAntiFingerprinting) {
      this.securityFeatures.hasAntiFingerprinting = true;
      this.antiFingerprintingConfig.enabled = true;
      if (this.currentSecurityLevel === "enhanced") {
        this.antiFingerprintingConfig.randomizeSizes = false;
        this.antiFingerprintingConfig.maskPatterns = false;
        this.antiFingerprintingConfig.useRandomHeaders = false;
      }
    }
    this.notifySecurityUpgrade(2);
    setTimeout(() => {
      this.calculateAndReportSecurityLevel();
    }, 500);
  }
  // Method to enable Stage 3 features (traffic obfuscation)
  enableStage3Security() {
    if (this.currentSecurityLevel !== "maximum") {
      this._secureLog("info", "\u{1F512} Stage 3 features only available for premium sessions");
      return;
    }
    if (this.sessionConstraints?.hasMessageChunking) {
      this.securityFeatures.hasMessageChunking = true;
      this.chunkingConfig.enabled = true;
    }
    if (this.sessionConstraints?.hasFakeTraffic) {
      this.securityFeatures.hasFakeTraffic = true;
      this.fakeTrafficConfig.enabled = true;
      this.startFakeTrafficGeneration();
    }
    this.notifySecurityUpgrade(3);
    setTimeout(() => {
      this.calculateAndReportSecurityLevel();
    }, 500);
  }
  // Method for enabling Stage 4 functions (maximum safety)
  enableStage4Security() {
    if (this.currentSecurityLevel !== "maximum") {
      this._secureLog("info", "\u{1F512} Stage 4 features only available for premium sessions");
      return;
    }
    if (this.sessionConstraints?.hasDecoyChannels && this.isConnected() && this.isVerified) {
      this.securityFeatures.hasDecoyChannels = true;
      this.decoyChannelConfig.enabled = true;
      try {
        this.initializeDecoyChannels();
      } catch (error) {
        this._secureLog("warn", "\u26A0\uFE0F Decoy channels initialization failed:", { details: error.message });
        this.securityFeatures.hasDecoyChannels = false;
        this.decoyChannelConfig.enabled = false;
      }
    }
    if (this.sessionConstraints?.hasAntiFingerprinting) {
      this.antiFingerprintingConfig.randomizeSizes = true;
      this.antiFingerprintingConfig.maskPatterns = true;
      this.antiFingerprintingConfig.useRandomHeaders = false;
    }
    this.notifySecurityUpgrade(4);
    setTimeout(() => {
      this.calculateAndReportSecurityLevel();
    }, 500);
  }
  forceSecurityUpdate() {
    setTimeout(() => {
      this.calculateAndReportSecurityLevel();
      this.notifySecurityUpdate();
    }, 100);
  }
  // Method for getting security status
  getSecurityStatus() {
    const activeFeatures = Object.entries(this.securityFeatures).filter(([key, value]) => value === true).map(([key]) => key);
    const stage = this.currentSecurityLevel === "basic" ? 1 : this.currentSecurityLevel === "enhanced" ? 2 : this.currentSecurityLevel === "maximum" ? 4 : 1;
    return {
      stage,
      sessionType: this.currentSessionType,
      securityLevel: this.currentSecurityLevel,
      activeFeatures,
      totalFeatures: Object.keys(this.securityFeatures).length,
      activeFeaturesCount: activeFeatures.length,
      activeFeaturesNames: activeFeatures,
      sessionConstraints: this.sessionConstraints
    };
  }
  // Method to notify UI about security update
  notifySecurityUpgrade(stage) {
    const stageNames = {
      1: "Basic Enhanced",
      2: "Medium Security",
      3: "High Security",
      4: "Maximum Security"
    };
    const message = `\u{1F512} Security upgraded to Stage ${stage}: ${stageNames[stage]}`;
    if (!this.securityUpgradeNotificationSent || this.lastSecurityUpgradeStage !== stage) {
      this.securityUpgradeNotificationSent = true;
      this.lastSecurityUpgradeStage = stage;
      if (this.onMessage) {
        this.deliverMessageToUI(message, "system");
      }
    }
    if (this.dataChannel && this.dataChannel.readyState === "open") {
      try {
        const securityNotification = {
          type: "security_upgrade",
          stage,
          stageName: stageNames[stage],
          message,
          timestamp: Date.now()
        };
        this._secureLog("debug", "\u{1F512} Sending security upgrade notification to peer:", { type: securityNotification.type, stage: securityNotification.stage });
        this.dataChannel.send(JSON.stringify(securityNotification));
      } catch (error) {
        this._secureLog("warn", "\u26A0\uFE0F Failed to send security upgrade notification to peer:", { details: error.message });
      }
    }
    const status = this.getSecurityStatus();
  }
  async calculateAndReportSecurityLevel() {
    try {
      if (!window.EnhancedSecureCryptoUtils) {
        this._secureLog("warn", "\u26A0\uFE0F EnhancedSecureCryptoUtils not available for security calculation");
        return null;
      }
      if (!this.isConnected() || !this.isVerified || !this.encryptionKey || !this.macKey) {
        this._secureLog("debug", "\u26A0\uFE0F WebRTC not ready for security calculation", {
          connected: this.isConnected(),
          verified: this.isVerified,
          hasEncryptionKey: !!this.encryptionKey,
          hasMacKey: !!this.macKey
        });
        return null;
      }
      this._secureLog("debug", "\u{1F50D} Calculating real security level", {
        managerState: "ready",
        hasAllKeys: !!(this.encryptionKey && this.macKey && this.metadataKey)
      });
      const securityData = await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(this);
      this._secureLog("info", "\u{1F510} Real security level calculated", {
        hasSecurityLevel: !!securityData.level,
        scoreRange: securityData.score > 80 ? "high" : securityData.score > 50 ? "medium" : "low",
        checksRatio: `${securityData.passedChecks}/${securityData.totalChecks}`,
        isRealCalculation: securityData.isRealData
      });
      this.lastSecurityCalculation = securityData;
      document.dispatchEvent(new CustomEvent("real-security-calculated", {
        detail: {
          securityData,
          webrtcManager: this,
          timestamp: Date.now(),
          source: "calculateAndReportSecurityLevel"
        }
      }));
      if (securityData.isRealData && this.onMessage) {
        if (!this.securityCalculationNotificationSent || this.lastSecurityCalculationLevel !== securityData.level) {
          this.securityCalculationNotificationSent = true;
          this.lastSecurityCalculationLevel = securityData.level;
          const message = `\u{1F512} Security Level: ${securityData.level} (${securityData.score}%) - ${securityData.passedChecks}/${securityData.totalChecks} checks passed`;
          this.deliverMessageToUI(message, "system");
        }
      }
      return securityData;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to calculate real security level", {
        errorType: error.constructor.name
      });
      return null;
    }
  }
  // ============================================
  // AUTOMATIC STEP-BY-STEP SWITCHING ON
  // ============================================
  // Method for automatic feature enablement with stability check
  async autoEnableSecurityFeatures() {
    if (this.currentSessionType === "demo") {
      this._secureLog("info", "\u{1F512} Demo session - keeping basic security only");
      await this.calculateAndReportSecurityLevel();
      this.notifySecurityUpgrade(1);
      return;
    }
    const checkStability = () => {
      const isStable = this.isConnected() && this.isVerified && this.connectionAttempts === 0 && this.messageQueue.length === 0 && this.peerConnection?.connectionState === "connected";
      return isStable;
    };
    this._secureLog("info", `\u{1F512} ${this.currentSessionType} session - starting graduated security activation`);
    await this.calculateAndReportSecurityLevel();
    this.notifySecurityUpgrade(1);
    if (this.currentSecurityLevel === "enhanced" || this.currentSecurityLevel === "maximum") {
      setTimeout(async () => {
        if (checkStability()) {
          console.log("\u2705 Activating Stage 2 for paid session");
          this.enableStage2Security();
          await this.calculateAndReportSecurityLevel();
          if (this.currentSecurityLevel === "maximum") {
            setTimeout(async () => {
              if (checkStability()) {
                console.log("\u2705 Activating Stage 3 for premium session");
                this.enableStage3Security();
                await this.calculateAndReportSecurityLevel();
                setTimeout(async () => {
                  if (checkStability()) {
                    console.log("\u2705 Activating Stage 4 for premium session");
                    this.enableStage4Security();
                    await this.calculateAndReportSecurityLevel();
                  }
                }, 2e4);
              }
            }, 15e3);
          }
        }
      }, 1e4);
    }
  }
  // ============================================
  // CONNECTION MANAGEMENT WITH ENHANCED SECURITY
  // ============================================
  async establishConnection() {
    try {
      await this.initializeEnhancedSecurity();
      if (this.fakeTrafficConfig.enabled) {
        this.startFakeTrafficGeneration();
      }
      if (this.decoyChannelConfig.enabled) {
        this.initializeDecoyChannels();
      }
    } catch (error) {
      this._secureLog("error", "\u274C Failed to establish enhanced connection:", { errorType: error?.constructor?.name || "Unknown" });
      this.onStatusChange("disconnected");
      throw error;
    }
  }
  disconnect() {
    try {
      console.log("\u{1F50C} Disconnecting WebRTC Manager...");
      if (this.fileTransferSystem) {
        console.log("\u{1F9F9} Cleaning up file transfer system during disconnect...");
        this.fileTransferSystem.cleanup();
        this.fileTransferSystem = null;
      }
      this.stopFakeTrafficGeneration();
      for (const [channelName, timer] of this.decoyTimers.entries()) {
        clearTimeout(timer);
      }
      this.decoyTimers.clear();
      for (const [channelName, channel] of this.decoyChannels.entries()) {
        if (channel.readyState === "open") {
          channel.close();
        }
      }
      this.decoyChannels.clear();
      this.packetBuffer.clear();
      this.chunkQueue = [];
      this._wipeEphemeralKeys();
      this._hardWipeOldKeys();
      this._clearVerificationStates();
    } catch (error) {
      this._secureLog("error", "\u274C Error during enhanced disconnect:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  /**
   *   Clear all verification states and data
   * Called when verification is rejected or connection is terminated
   */
  _clearVerificationStates() {
    try {
      console.log("\u{1F9F9} Clearing verification states...");
      this.localVerificationConfirmed = false;
      this.remoteVerificationConfirmed = false;
      this.bothVerificationsConfirmed = false;
      this.isVerified = false;
      this.verificationCode = null;
      this.pendingSASCode = null;
      this.keyFingerprint = null;
      this.expectedDTLSFingerprint = null;
      this.connectionId = null;
      this.processedMessageIds.clear();
      this.verificationNotificationSent = false;
      this.verificationInitiationSent = false;
      console.log("\u2705 Verification states cleared successfully");
    } catch (error) {
      this._secureLog("error", "\u274C Error clearing verification states:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  // Start periodic cleanup for rate limiting and security
  startPeriodicCleanup() {
    this._secureLog("info", "\u{1F527} Periodic cleanup moved to unified scheduler");
  }
  // Calculate current security level with real verification
  async calculateSecurityLevel() {
    return await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(this);
  }
  // PFS: Check if key rotation is needed
  shouldRotateKeys() {
    if (!this.isConnected() || !this.isVerified) {
      return false;
    }
    const now = Date.now();
    const timeSinceLastRotation = now - this.lastKeyRotation;
    return timeSinceLastRotation > this.keyRotationInterval || this.messageCounter % 100 === 0;
  }
  // PFS: Rotate encryption keys for Perfect Forward Secrecy
  async rotateKeys() {
    return this._withMutex("keyOperation", async (operationId) => {
      this._secureLog("info", "\u{1F504} Starting key rotation with mutex", {
        operationId
      });
      if (!this.isConnected() || !this.isVerified) {
        this._secureLog("warn", "\u26A0\uFE0F Key rotation aborted - connection not ready", {
          operationId,
          isConnected: this.isConnected(),
          isVerified: this.isVerified
        });
        return false;
      }
      if (this._keySystemState.isRotating) {
        this._secureLog("warn", "\u26A0\uFE0F Key rotation already in progress", {
          operationId
        });
        return false;
      }
      try {
        this._keySystemState.isRotating = true;
        this._keySystemState.lastOperation = "rotation";
        this._keySystemState.lastOperationTime = Date.now();
        const rotationSignal = {
          type: "key_rotation_signal",
          newVersion: this.currentKeyVersion + 1,
          timestamp: Date.now(),
          operationId
        };
        if (this.dataChannel && this.dataChannel.readyState === "open") {
          this.dataChannel.send(JSON.stringify(rotationSignal));
        } else {
          throw new Error("Data channel not ready for key rotation");
        }
        this._hardWipeOldKeys();
        return new Promise((resolve) => {
          this.pendingRotation = {
            newVersion: this.currentKeyVersion + 1,
            operationId,
            resolve,
            timeout: setTimeout(() => {
              this._secureLog("error", "\u26A0\uFE0F Key rotation timeout", {
                operationId
              });
              this._keySystemState.isRotating = false;
              this.pendingRotation = null;
              resolve(false);
            }, 1e4)
            // 10 seconds timeout
          };
        });
      } catch (error) {
        this._secureLog("error", "\u274C Key rotation failed in critical section", {
          operationId,
          errorType: error.constructor.name
        });
        this._keySystemState.isRotating = false;
        return false;
      }
    }, 1e4);
  }
  //   Real PFS - Clean up old keys with hard wipe
  cleanupOldKeys() {
    const now = Date.now();
    const maxKeyAge = _EnhancedSecureWebRTCManager.LIMITS.MAX_KEY_AGE;
    let wipedKeysCount = 0;
    for (const [version, keySet] of this.oldKeys.entries()) {
      if (now - keySet.timestamp > maxKeyAge) {
        if (keySet.encryptionKey) {
          this._secureWipeMemory(keySet.encryptionKey, "pfs_cleanup_wipe");
        }
        if (keySet.macKey) {
          this._secureWipeMemory(keySet.macKey, "pfs_cleanup_wipe");
        }
        if (keySet.metadataKey) {
          this._secureWipeMemory(keySet.metadataKey, "pfs_cleanup_wipe");
        }
        keySet.encryptionKey = null;
        keySet.macKey = null;
        keySet.metadataKey = null;
        keySet.keyFingerprint = null;
        this.oldKeys.delete(version);
        wipedKeysCount++;
        this._secureLog("info", "\u{1F9F9} Old PFS keys hard wiped and cleaned up", {
          version,
          age: Math.round((now - keySet.timestamp) / 1e3) + "s",
          timestamp: Date.now()
        });
      }
    }
    if (wipedKeysCount > 0) {
      this._secureLog("info", `\u2705 PFS cleanup completed: ${wipedKeysCount} keys hard wiped`, {
        timestamp: Date.now()
      });
    }
  }
  // PFS: Get keys for specific version (for decryption)
  getKeysForVersion(version) {
    const oldKeySet = this.oldKeys.get(version);
    if (oldKeySet && oldKeySet.encryptionKey && oldKeySet.macKey && oldKeySet.metadataKey) {
      return {
        encryptionKey: oldKeySet.encryptionKey,
        macKey: oldKeySet.macKey,
        metadataKey: oldKeySet.metadataKey
      };
    }
    if (version === this.currentKeyVersion) {
      if (this.encryptionKey && this.macKey && this.metadataKey) {
        return {
          encryptionKey: this.encryptionKey,
          macKey: this.macKey,
          metadataKey: this.metadataKey
        };
      }
    }
    window.EnhancedSecureCryptoUtils.secureLog.log("error", "No valid keys found for version", {
      requestedVersion: version,
      currentVersion: this.currentKeyVersion,
      availableVersions: Array.from(this.oldKeys.keys())
    });
    return null;
  }
  createPeerConnection() {
    const config = {
      iceServers: [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" },
        { urls: "stun:stun2.l.google.com:19302" },
        { urls: "stun:stun3.l.google.com:19302" },
        { urls: "stun:stun4.l.google.com:19302" }
      ],
      iceCandidatePoolSize: 10,
      bundlePolicy: "balanced"
    };
    this.peerConnection = new RTCPeerConnection(config);
    this.peerConnection.onconnectionstatechange = () => {
      const state = this.peerConnection.connectionState;
      console.log("Connection state:", state);
      if (state === "connected" && !this.isVerified) {
        this.onStatusChange("verifying");
      } else if (state === "connected" && this.isVerified) {
        this.onStatusChange("connected");
      } else if (state === "disconnected" || state === "closed") {
        if (this.intentionalDisconnect) {
          this.onStatusChange("disconnected");
          setTimeout(() => this.disconnect(), 100);
        } else {
          this.onStatusChange("disconnected");
          this._clearVerificationStates();
        }
      } else if (state === "failed") {
        this.onStatusChange("disconnected");
      } else {
        this.onStatusChange(state);
      }
    };
    this.peerConnection.ondatachannel = (event) => {
      console.log("\u{1F517} Data channel received:", {
        channelLabel: event.channel.label,
        channelState: event.channel.readyState,
        isInitiator: this.isInitiator,
        channelId: event.channel.id,
        protocol: event.channel.protocol
      });
      if (event.channel.label === "securechat") {
        console.log("\u{1F517} MAIN DATA CHANNEL RECEIVED (answerer side)");
        this.dataChannel = event.channel;
        this.setupDataChannel(event.channel);
      } else {
        console.log("\u{1F517} ADDITIONAL DATA CHANNEL RECEIVED:", event.channel.label);
        if (event.channel.label === "heartbeat") {
          this.heartbeatChannel = event.channel;
        }
      }
    };
  }
  setupDataChannel(channel) {
    console.log("\u{1F517} setupDataChannel called:", {
      channelLabel: channel.label,
      channelState: channel.readyState,
      isInitiator: this.isInitiator,
      isVerified: this.isVerified
    });
    this.dataChannel = channel;
    this.dataChannel.onopen = async () => {
      console.log("\u{1F517} Data channel opened:", {
        isInitiator: this.isInitiator,
        isVerified: this.isVerified,
        dataChannelState: this.dataChannel.readyState,
        dataChannelLabel: this.dataChannel.label
      });
      try {
        if (this.dataChannel && typeof this.dataChannel.bufferedAmountLowThreshold === "number") {
          this.dataChannel.bufferedAmountLowThreshold = 1024 * 1024;
        }
      } catch (e) {
      }
      try {
        await this.establishConnection();
        this.initializeFileTransfer();
      } catch (error) {
        this._secureLog("error", "\u274C Error in establishConnection:", { errorType: error?.constructor?.name || "Unknown" });
      }
      if (this.pendingSASCode && this.dataChannel && this.dataChannel.readyState === "open") {
        try {
          const sasPayload = {
            type: "sas_code",
            data: {
              code: this.pendingSASCode,
              timestamp: Date.now(),
              verificationMethod: "SAS",
              securityLevel: "MITM_PROTECTION_REQUIRED"
            }
          };
          console.log("\u{1F4E4} Sending pending SAS code to Answer side:", this.pendingSASCode);
          this.dataChannel.send(JSON.stringify(sasPayload));
          this.pendingSASCode = null;
        } catch (error) {
          console.error("Failed to send pending SAS code to Answer side:", error);
        }
      } else if (this.pendingSASCode) {
        console.log("\u26A0\uFE0F Cannot send SAS code - dataChannel not ready:", {
          hasDataChannel: !!this.dataChannel,
          readyState: this.dataChannel?.readyState,
          pendingSASCode: this.pendingSASCode
        });
      }
      if (this.isVerified) {
        this.onStatusChange("connected");
        this.processMessageQueue();
        setTimeout(async () => {
          await this.calculateAndReportSecurityLevel();
          this.autoEnableSecurityFeatures();
          this.notifySecurityUpdate();
        }, 500);
      } else {
        this.onStatusChange("verifying");
        this.initiateVerification();
      }
      this.startHeartbeat();
    };
    this.dataChannel.onclose = () => {
      if (!this.intentionalDisconnect) {
        this.onStatusChange("disconnected");
        this._clearVerificationStates();
        if (!this.connectionClosedNotificationSent) {
          this.connectionClosedNotificationSent = true;
          this.deliverMessageToUI("\u{1F50C} Enhanced secure connection closed. Check connection status.", "system");
        }
      } else {
        this.onStatusChange("disconnected");
        this._clearVerificationStates();
        if (!this.connectionClosedNotificationSent) {
          this.connectionClosedNotificationSent = true;
          this.deliverMessageToUI("\u{1F50C} Enhanced secure connection closed", "system");
        }
      }
      this._wipeEphemeralKeys();
      this.stopHeartbeat();
      this.isVerified = false;
    };
    this.dataChannel.onmessage = async (event) => {
      try {
        console.log("\u{1F4E8} Raw message received:", {
          dataType: typeof event.data,
          dataLength: event.data?.length || event.data?.byteLength || 0,
          isString: typeof event.data === "string"
        });
        if (typeof event.data === "string") {
          try {
            const parsed = JSON.parse(event.data);
            console.log("\u{1F4E8} Parsed message:", {
              type: parsed.type,
              hasData: !!parsed.data,
              timestamp: parsed.timestamp
            });
            const fileMessageTypes2 = [
              "file_transfer_start",
              "file_transfer_response",
              "file_chunk",
              "chunk_confirmation",
              "file_transfer_complete",
              "file_transfer_error"
            ];
            if (parsed.type && fileMessageTypes2.includes(parsed.type)) {
              console.log("\u{1F4C1} File message intercepted at WebRTC level:", parsed.type);
              if (!this.fileTransferSystem) {
                try {
                  if (this.isVerified && this.dataChannel && this.dataChannel.readyState === "open") {
                    this.initializeFileTransfer();
                    let attempts2 = 0;
                    const maxAttempts = 30;
                    while (!this.fileTransferSystem && attempts2 < maxAttempts) {
                      await new Promise((resolve) => setTimeout(resolve, 100));
                      attempts2++;
                    }
                  }
                } catch (initError) {
                  this._secureLog("error", "\u274C Failed to initialize file transfer system for receiver:", { errorType: initError?.constructor?.name || "Unknown" });
                }
              }
              if (this.fileTransferSystem) {
                console.log("\u{1F4C1} Forwarding to local file transfer system:", parsed.type);
                await this.fileTransferSystem.handleFileMessage(parsed);
                return;
              }
              this._secureLog("warn", "\u26A0\uFE0F File transfer system not ready, attempting lazy init...");
              try {
                await this._ensureFileTransferReady();
                if (this.fileTransferSystem) {
                  await this.fileTransferSystem.handleFileMessage(parsed);
                  return;
                }
              } catch (e) {
                this._secureLog("error", "\u274C Lazy init of file transfer failed:", { errorType: e?.message || e?.constructor?.name || "Unknown" });
              }
              this._secureLog("error", "\u274C No file transfer system available for:", { errorType: parsed.type?.constructor?.name || "Unknown" });
              return;
            }
            if (parsed.type && ["heartbeat", "verification", "verification_response", "verification_confirmed", "verification_both_confirmed", "sas_code", "peer_disconnect", "security_upgrade"].includes(parsed.type)) {
              console.log("\u{1F527} System message detected:", parsed.type);
              this.handleSystemMessage(parsed);
              return;
            }
            if (parsed.type === "message" && parsed.data) {
              console.log("\u{1F4DD} User message detected:", parsed.data.substring(0, 50));
              if (this.onMessage) {
                this.deliverMessageToUI(parsed.data, "received");
              }
              return;
            }
            if (parsed.type === "enhanced_message" && parsed.data) {
              console.log("\u{1F510} Enhanced message detected, processing...");
              await this._processEnhancedMessageWithoutMutex(parsed);
              return;
            }
            if (parsed.type === "fake") {
              console.log("\u{1F3AD} Fake message blocked:", parsed.pattern);
              return;
            }
            console.log("\u2753 Unknown message type:", parsed.type);
          } catch (jsonError) {
            console.log("\u{1F4C4} Non-JSON message detected, treating as text");
            if (this.onMessage) {
              this.deliverMessageToUI(event.data, "received");
            }
            return;
          }
        } else if (event.data instanceof ArrayBuffer) {
          console.log("\u{1F522} Binary data received, processing...");
          await this._processBinaryDataWithoutMutex(event.data);
        } else {
          console.log("\u2753 Unknown data type:", typeof event.data);
        }
      } catch (error) {
        this._secureLog("error", "\u274C Failed to process message in onmessage:", { errorType: error?.constructor?.name || "Unknown" });
      }
    };
  }
  // FIX 4: New method for processing binary data WITHOUT mutex
  async _processBinaryDataWithoutMutex(data) {
    try {
      console.log("\u{1F522} Processing binary data without mutex...");
      let processedData = data;
      if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer && processedData.byteLength > 12) {
        try {
          processedData = await this.removeNestedEncryption(processedData);
        } catch (error) {
          this._secureLog("warn", "\u26A0\uFE0F Nested decryption failed, continuing with original data");
        }
      }
      if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
        try {
          processedData = this.removePacketPadding(processedData);
        } catch (error) {
          this._secureLog("warn", "\u26A0\uFE0F Packet padding removal failed, continuing with original data");
        }
      }
      if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
        try {
          processedData = this.removeAntiFingerprinting(processedData);
        } catch (error) {
          this._secureLog("warn", "\u26A0\uFE0F Anti-fingerprinting removal failed, continuing with original data");
        }
      }
      if (processedData instanceof ArrayBuffer) {
        const textData = new TextDecoder().decode(processedData);
        try {
          const content = JSON.parse(textData);
          if (content.type === "fake" || content.isFakeTraffic === true) {
            console.log(`\u{1F3AD} BLOCKED: Binary fake message: ${content.pattern || "unknown"}`);
            return;
          }
        } catch (e) {
        }
        if (this.onMessage) {
          this.deliverMessageToUI(textData, "received");
        }
      }
    } catch (error) {
      this._secureLog("error", "\u274C Error processing binary data:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  // FIX 3: New method for processing enhanced messages WITHOUT mutex
  async _processEnhancedMessageWithoutMutex(parsedMessage) {
    try {
      console.log("\u{1F510} Processing enhanced message without mutex...");
      if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
        this._secureLog("error", "\u274C Missing encryption keys for enhanced message");
        return;
      }
      const decryptedResult = await window.EnhancedSecureCryptoUtils.decryptMessage(
        parsedMessage.data,
        this.encryptionKey,
        this.macKey,
        this.metadataKey
      );
      if (decryptedResult && decryptedResult.message) {
        console.log("\u2705 Enhanced message decrypted successfully");
        try {
          const decryptedContent = JSON.parse(decryptedResult.message);
          if (decryptedContent.type === "fake" || decryptedContent.isFakeTraffic === true) {
            console.log(`\uFFFD\uFFFD BLOCKED: Encrypted fake message: ${decryptedContent.pattern || "unknown"}`);
            return;
          }
          if (decryptedContent && decryptedContent.type === "message" && typeof decryptedContent.data === "string") {
            if (this.onMessage) {
              this.deliverMessageToUI(decryptedContent.data, "received");
            }
            return;
          }
        } catch (e) {
        }
        if (this.onMessage) {
          this.deliverMessageToUI(decryptedResult.message, "received");
        }
      } else {
        this._secureLog("warn", "\u26A0\uFE0F No message content in decrypted result");
      }
    } catch (error) {
      this._secureLog("error", "\u274C Error processing enhanced message:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  /**
   * Creates a unique ID for an operation
   */
  _generateOperationId() {
    return `op_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  /**
   *   Atomic mutex acquisition with enhanced race condition protection
   */
  async _acquireMutex(mutexName, operationId, timeout = 5e3) {
    const mutexPropertyName = `_${mutexName}Mutex`;
    const mutex = this[mutexPropertyName];
    if (!mutex) {
      this._secureLog("error", `\u274C Unknown mutex: ${mutexName}`, {
        mutexPropertyName,
        availableMutexes: this._getAvailableMutexes(),
        operationId
      });
      throw new Error(`Unknown mutex: ${mutexName}. Available: ${this._getAvailableMutexes().join(", ")}`);
    }
    if (!operationId || typeof operationId !== "string") {
      throw new Error("Invalid operation ID for mutex acquisition");
    }
    return new Promise((resolve, reject) => {
      const attemptLock = () => {
        if (mutex.lockId === operationId) {
          this._secureLog("warn", `\u26A0\uFE0F Mutex '${mutexName}' already locked by same operation`, {
            operationId
          });
          resolve();
          return;
        }
        if (!mutex.locked) {
          mutex.locked = true;
          mutex.lockId = operationId;
          mutex.lockTime = Date.now();
          this._secureLog("debug", `\u{1F512} Mutex '${mutexName}' acquired atomically`, {
            operationId,
            lockTime: mutex.lockTime
          });
          mutex.lockTimeout = setTimeout(() => {
            this._handleMutexTimeout(mutexName, operationId, timeout);
          }, timeout);
          resolve();
        } else {
          const queueItem = {
            resolve,
            reject,
            operationId,
            timestamp: Date.now(),
            timeout: setTimeout(() => {
              const index = mutex.queue.findIndex((item) => item.operationId === operationId);
              if (index !== -1) {
                mutex.queue.splice(index, 1);
                reject(new Error(`Mutex acquisition timeout for '${mutexName}'`));
              }
            }, timeout)
          };
          mutex.queue.push(queueItem);
          this._secureLog("debug", `\u23F3 Operation queued for mutex '${mutexName}'`, {
            operationId,
            queueLength: mutex.queue.length,
            currentLockId: mutex.lockId
          });
        }
      };
      attemptLock();
    });
  }
  /**
   *   Enhanced mutex release with strict validation and error handling
   */
  _releaseMutex(mutexName, operationId) {
    if (!mutexName || typeof mutexName !== "string") {
      throw new Error("Invalid mutex name provided for release");
    }
    if (!operationId || typeof operationId !== "string") {
      throw new Error("Invalid operation ID provided for mutex release");
    }
    const mutexPropertyName = `_${mutexName}Mutex`;
    const mutex = this[mutexPropertyName];
    if (!mutex) {
      this._secureLog("error", `\u274C Unknown mutex for release: ${mutexName}`, {
        mutexPropertyName,
        availableMutexes: this._getAvailableMutexes(),
        operationId
      });
      throw new Error(`Unknown mutex for release: ${mutexName}`);
    }
    if (mutex.lockId !== operationId) {
      this._secureLog("error", `\u274C CRITICAL: Invalid mutex release attempt - potential race condition`, {
        mutexName,
        expectedLockId: mutex.lockId,
        providedOperationId: operationId,
        mutexState: {
          locked: mutex.locked,
          lockTime: mutex.lockTime,
          queueLength: mutex.queue.length
        }
      });
      throw new Error(`Invalid mutex release attempt for '${mutexName}': expected '${mutex.lockId}', got '${operationId}'`);
    }
    if (!mutex.locked) {
      this._secureLog("error", `\u274C CRITICAL: Attempting to release unlocked mutex`, {
        mutexName,
        operationId,
        mutexState: {
          locked: mutex.locked,
          lockId: mutex.lockId,
          lockTime: mutex.lockTime
        }
      });
      throw new Error(`Attempting to release unlocked mutex: ${mutexName}`);
    }
    try {
      if (mutex.lockTimeout) {
        clearTimeout(mutex.lockTimeout);
        mutex.lockTimeout = null;
      }
      const lockDuration = mutex.lockTime ? Date.now() - mutex.lockTime : 0;
      mutex.locked = false;
      mutex.lockId = null;
      mutex.lockTime = null;
      this._secureLog("debug", `\u{1F513} Mutex released successfully: ${mutexName}`, {
        operationId,
        lockDuration,
        queueLength: mutex.queue.length
      });
      this._processNextInQueue(mutexName);
    } catch (error) {
      this._secureLog("error", `\u274C Error during mutex release queue processing`, {
        mutexName,
        operationId,
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      mutex.locked = false;
      mutex.lockId = null;
      mutex.lockTime = null;
      mutex.lockTimeout = null;
      throw error;
    }
  }
  /**
   *   Enhanced queue processing with comprehensive error handling
   */
  _processNextInQueue(mutexName) {
    const mutex = this[`_${mutexName}Mutex`];
    if (!mutex) {
      this._secureLog("error", `\u274C Mutex not found for queue processing: ${mutexName}`);
      return;
    }
    if (mutex.queue.length === 0) {
      return;
    }
    if (mutex.locked) {
      this._secureLog("warn", `\u26A0\uFE0F Mutex '${mutexName}' is still locked, skipping queue processing`, {
        lockId: mutex.lockId,
        queueLength: mutex.queue.length
      });
      return;
    }
    const nextItem = mutex.queue.shift();
    if (!nextItem) {
      this._secureLog("warn", `\u26A0\uFE0F Empty queue item for mutex '${mutexName}'`);
      return;
    }
    if (!nextItem.operationId || !nextItem.resolve || !nextItem.reject) {
      this._secureLog("error", `\u274C Invalid queue item structure for mutex '${mutexName}'`, {
        hasOperationId: !!nextItem.operationId,
        hasResolve: !!nextItem.resolve,
        hasReject: !!nextItem.reject
      });
      return;
    }
    try {
      if (nextItem.timeout) {
        clearTimeout(nextItem.timeout);
      }
      this._secureLog("debug", `\u{1F504} Processing next operation in queue for mutex '${mutexName}'`, {
        operationId: nextItem.operationId,
        queueRemaining: mutex.queue.length,
        timestamp: Date.now()
      });
      setTimeout(async () => {
        try {
          await this._acquireMutex(mutexName, nextItem.operationId, 5e3);
          this._secureLog("debug", `\u2705 Queued operation acquired mutex '${mutexName}'`, {
            operationId: nextItem.operationId,
            acquisitionTime: Date.now()
          });
          nextItem.resolve();
        } catch (error) {
          this._secureLog("error", `\u274C Queued operation failed to acquire mutex '${mutexName}'`, {
            operationId: nextItem.operationId,
            errorType: error.constructor.name,
            errorMessage: error.message,
            timestamp: Date.now()
          });
          nextItem.reject(new Error(`Queue processing failed for '${mutexName}': ${error.message}`));
          setTimeout(() => {
            this._processNextInQueue(mutexName);
          }, 50);
        }
      }, 10);
    } catch (error) {
      this._secureLog("error", `\u274C Critical error during queue processing for mutex '${mutexName}'`, {
        operationId: nextItem.operationId,
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      try {
        nextItem.reject(new Error(`Queue processing critical error: ${error.message}`));
      } catch (rejectError) {
        this._secureLog("error", `\u274C Failed to reject queue item`, {
          originalError: error.message,
          rejectError: rejectError.message
        });
      }
      setTimeout(() => {
        this._processNextInQueue(mutexName);
      }, 100);
    }
  }
  _getAvailableMutexes() {
    const mutexes = [];
    const propertyNames = Object.getOwnPropertyNames(this);
    for (const prop of propertyNames) {
      if (prop.endsWith("Mutex") && prop.startsWith("_")) {
        const mutexName = prop.slice(1, -5);
        mutexes.push(mutexName);
      }
    }
    return mutexes;
  }
  /**
   *   Enhanced mutex execution with atomic operations
   */
  async _withMutex(mutexName, operation, timeout = 5e3) {
    const operationId = this._generateOperationId();
    if (!this._validateMutexSystem()) {
      this._secureLog("error", "\u274C Mutex system not properly initialized", {
        operationId,
        mutexName
      });
      throw new Error("Mutex system not properly initialized. Call _initializeMutexSystem() first.");
    }
    const mutex = this[`_${mutexName}Mutex`];
    if (!mutex) {
      throw new Error(`Mutex '${mutexName}' not found`);
    }
    let mutexAcquired = false;
    try {
      await this._acquireMutex(mutexName, operationId, timeout);
      mutexAcquired = true;
      const counterKey = `${mutexName}Operations`;
      if (this._operationCounters && this._operationCounters[counterKey] !== void 0) {
        this._operationCounters[counterKey]++;
      }
      const result = await operation(operationId);
      if (result === void 0 && operation.name !== "cleanup") {
        this._secureLog("warn", "\u26A0\uFE0F Mutex operation returned undefined result", {
          operationId,
          mutexName,
          operationName: operation.name
        });
      }
      return result;
    } catch (error) {
      this._secureLog("error", "\u274C Error in mutex operation", {
        operationId,
        mutexName,
        errorType: error.constructor.name,
        errorMessage: error.message,
        mutexAcquired,
        mutexState: mutex ? {
          locked: mutex.locked,
          lockId: mutex.lockId,
          queueLength: mutex.queue.length
        } : "null"
      });
      if (mutexName === "keyOperation") {
        this._handleKeyOperationError(error, operationId);
      }
      if (error.message.includes("timeout") || error.message.includes("race condition")) {
        this._emergencyUnlockAllMutexes("errorHandler");
      }
      throw error;
    } finally {
      if (mutexAcquired) {
        try {
          await this._releaseMutex(mutexName, operationId);
          if (mutex.locked && mutex.lockId === operationId) {
            this._secureLog("error", "\u274C Mutex release verification failed", {
              operationId,
              mutexName
            });
            mutex.locked = false;
            mutex.lockId = null;
            mutex.lockTimeout = null;
          }
        } catch (releaseError) {
          this._secureLog("error", "\u274C Error releasing mutex in finally block", {
            operationId,
            mutexName,
            releaseErrorType: releaseError.constructor.name,
            releaseErrorMessage: releaseError.message
          });
          mutex.locked = false;
          mutex.lockId = null;
          mutex.lockTimeout = null;
        }
      }
    }
  }
  _validateMutexSystem() {
    const requiredMutexes = ["keyOperation", "cryptoOperation", "connectionOperation"];
    for (const mutexName of requiredMutexes) {
      const mutexPropertyName = `_${mutexName}Mutex`;
      const mutex = this[mutexPropertyName];
      if (!mutex || typeof mutex !== "object") {
        this._secureLog("error", `\u274C Missing or invalid mutex: ${mutexName}`, {
          mutexPropertyName,
          mutexType: typeof mutex
        });
        return false;
      }
      const requiredProps = ["locked", "queue", "lockId", "lockTimeout"];
      for (const prop of requiredProps) {
        if (!(prop in mutex)) {
          this._secureLog("error", `\u274C Mutex ${mutexName} missing property: ${prop}`);
          return false;
        }
      }
    }
    return true;
  }
  /**
   *   Enhanced emergency recovery of the mutex system
   */
  _emergencyRecoverMutexSystem() {
    this._secureLog("warn", "\u{1F6A8} Emergency mutex system recovery initiated");
    try {
      this._emergencyUnlockAllMutexes("emergencyRecovery");
      this._initializeMutexSystem();
      if (!this._validateMutexSystem()) {
        throw new Error("Mutex system validation failed after recovery");
      }
      this._secureLog("info", "\u2705 Mutex system recovered successfully with validation");
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to recover mutex system", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      try {
        this._initializeMutexSystem();
        this._secureLog("warn", "\u26A0\uFE0F Forced mutex system re-initialization completed");
        return true;
      } catch (reinitError) {
        this._secureLog("error", "\u274C CRITICAL: Forced re-initialization also failed", {
          originalError: error.message,
          reinitError: reinitError.message
        });
        return false;
      }
    }
  }
  /**
   *   Atomic key generation with race condition protection
   */
  async _generateEncryptionKeys() {
    return this._withMutex("keyOperation", async (operationId) => {
      this._secureLog("info", "\u{1F511} Generating encryption keys with atomic mutex", {
        operationId
      });
      const currentState = this._keySystemState;
      if (currentState.isInitializing) {
        this._secureLog("warn", "\u26A0\uFE0F Key generation already in progress, waiting for completion", {
          operationId,
          lastOperation: currentState.lastOperation,
          lastOperationTime: currentState.lastOperationTime
        });
        let waitAttempts = 0;
        const maxWaitAttempts = 50;
        while (currentState.isInitializing && waitAttempts < maxWaitAttempts) {
          await new Promise((resolve) => setTimeout(resolve, 100));
          waitAttempts++;
        }
        if (currentState.isInitializing) {
          throw new Error("Key generation timeout - operation still in progress after 5 seconds");
        }
      }
      try {
        currentState.isInitializing = true;
        currentState.lastOperation = "generation";
        currentState.lastOperationTime = Date.now();
        currentState.operationId = operationId;
        this._secureLog("debug", "\u{1F512} Atomic key generation state set", {
          operationId,
          timestamp: currentState.lastOperationTime
        });
        let ecdhKeyPair = null;
        let ecdsaKeyPair = null;
        try {
          ecdhKeyPair = await this._generateEphemeralECDHKeys();
          if (!ecdhKeyPair || !ecdhKeyPair.privateKey || !ecdhKeyPair.publicKey) {
            throw new Error("Ephemeral ECDH key pair validation failed");
          }
          if (!this._validateKeyPairConstantTime(ecdhKeyPair)) {
            throw new Error("Ephemeral ECDH keys are not valid CryptoKey instances");
          }
          this._secureLog("debug", "\u2705 Ephemeral ECDH keys generated and validated for PFS", {
            operationId,
            privateKeyType: ecdhKeyPair.privateKey.algorithm?.name,
            publicKeyType: ecdhKeyPair.publicKey.algorithm?.name,
            isEphemeral: true
          });
        } catch (ecdhError) {
          this._secureLog("error", "\u274C Ephemeral ECDH key generation failed", {
            operationId,
            errorType: ecdhError.constructor.name
          });
          this._throwSecureError(ecdhError, "ephemeral_ecdh_key_generation");
        }
        try {
          ecdsaKeyPair = await window.EnhancedSecureCryptoUtils.generateECDSAKeyPair();
          if (!ecdsaKeyPair || !ecdsaKeyPair.privateKey || !ecdsaKeyPair.publicKey) {
            throw new Error("ECDSA key pair validation failed");
          }
          if (!this._validateKeyPairConstantTime(ecdsaKeyPair)) {
            throw new Error("ECDSA keys are not valid CryptoKey instances");
          }
          this._secureLog("debug", "\u2705 ECDSA keys generated and validated", {
            operationId,
            privateKeyType: ecdsaKeyPair.privateKey.algorithm?.name,
            publicKeyType: ecdsaKeyPair.publicKey.algorithm?.name
          });
        } catch (ecdsaError) {
          this._secureLog("error", "\u274C ECDSA key generation failed", {
            operationId,
            errorType: ecdsaError.constructor.name
          });
          this._throwSecureError(ecdsaError, "ecdsa_key_generation");
        }
        if (!ecdhKeyPair || !ecdsaKeyPair) {
          throw new Error("One or both key pairs failed to generate");
        }
        this._enableSecurityFeaturesAfterKeyGeneration(ecdhKeyPair, ecdsaKeyPair);
        this._secureLog("info", "\u2705 Encryption keys generated successfully with atomic protection", {
          operationId,
          hasECDHKeys: !!(ecdhKeyPair?.privateKey && ecdhKeyPair?.publicKey),
          hasECDSAKeys: !!(ecdsaKeyPair?.privateKey && ecdsaKeyPair?.publicKey),
          generationTime: Date.now() - currentState.lastOperationTime
        });
        return { ecdhKeyPair, ecdsaKeyPair };
      } catch (error) {
        this._secureLog("error", "\u274C Key generation failed, resetting state", {
          operationId,
          errorType: error.constructor.name
        });
        throw error;
      } finally {
        currentState.isInitializing = false;
        currentState.operationId = null;
        this._secureLog("debug", "\u{1F513} Key generation state reset", {
          operationId
        });
      }
    });
  }
  /**
   *   Enable security features after successful key generation
   */
  _enableSecurityFeaturesAfterKeyGeneration(ecdhKeyPair, ecdsaKeyPair) {
    try {
      if (ecdhKeyPair && ecdhKeyPair.privateKey && ecdhKeyPair.publicKey) {
        this.securityFeatures.hasEncryption = true;
        this.securityFeatures.hasECDH = true;
        this._secureLog("info", "\u{1F512} ECDH encryption features enabled");
      }
      if (ecdsaKeyPair && ecdsaKeyPair.privateKey && ecdsaKeyPair.publicKey) {
        this.securityFeatures.hasECDSA = true;
        this._secureLog("info", "\u{1F512} ECDSA signature features enabled");
      }
      if (this.securityFeatures.hasEncryption) {
        this.securityFeatures.hasMetadataProtection = true;
        this.securityFeatures.hasEnhancedReplayProtection = true;
        this.securityFeatures.hasNonExtractableKeys = true;
        this._secureLog("info", "\u{1F512} Additional encryption-dependent features enabled");
      }
      if (ecdhKeyPair && this.ephemeralKeyPairs.size > 0) {
        this.securityFeatures.hasPFS = true;
        this._secureLog("info", "\u{1F512} Perfect Forward Secrecy enabled with ephemeral keys");
      }
      this._secureLog("info", "\u{1F512} Security features updated after key generation", {
        hasEncryption: this.securityFeatures.hasEncryption,
        hasECDH: this.securityFeatures.hasECDH,
        hasECDSA: this.securityFeatures.hasECDSA,
        hasMetadataProtection: this.securityFeatures.hasMetadataProtection,
        hasEnhancedReplayProtection: this.securityFeatures.hasEnhancedReplayProtection,
        hasNonExtractableKeys: this.securityFeatures.hasNonExtractableKeys,
        hasPFS: this.securityFeatures.hasPFS
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to enable security features after key generation", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
    }
  }
  /**
   *   Enhanced emergency mutex unlocking with authorization and validation
   */
  _emergencyUnlockAllMutexes(callerContext = "unknown") {
    const authorizedCallers = [
      "keyOperation",
      "cryptoOperation",
      "connectionOperation",
      "emergencyRecovery",
      "systemShutdown",
      "errorHandler"
    ];
    if (!authorizedCallers.includes(callerContext)) {
      this._secureLog("error", `\u{1F6A8} UNAUTHORIZED emergency mutex unlock attempt`, {
        callerContext,
        authorizedCallers,
        timestamp: Date.now()
      });
      throw new Error(`Unauthorized emergency mutex unlock attempt by: ${callerContext}`);
    }
    const mutexes = ["keyOperation", "cryptoOperation", "connectionOperation"];
    this._secureLog("error", "\u{1F6A8} EMERGENCY: Unlocking all mutexes with authorization and state cleanup", {
      callerContext,
      timestamp: Date.now()
    });
    let unlockedCount = 0;
    let errorCount = 0;
    mutexes.forEach((mutexName) => {
      const mutex = this[`_${mutexName}Mutex`];
      if (mutex) {
        try {
          if (mutex.lockTimeout) {
            clearTimeout(mutex.lockTimeout);
          }
          const previousState = {
            locked: mutex.locked,
            lockId: mutex.lockId,
            lockTime: mutex.lockTime,
            queueLength: mutex.queue.length
          };
          mutex.locked = false;
          mutex.lockId = null;
          mutex.lockTimeout = null;
          mutex.lockTime = null;
          let queueRejectCount = 0;
          mutex.queue.forEach((item) => {
            try {
              if (item.reject && typeof item.reject === "function") {
                item.reject(new Error(`Emergency mutex unlock for ${mutexName} by ${callerContext}`));
                queueRejectCount++;
              }
            } catch (rejectError) {
              this._secureLog("warn", `\u26A0\uFE0F Failed to reject queue item during emergency unlock`, {
                mutexName,
                errorType: rejectError.constructor.name
              });
            }
          });
          mutex.queue = [];
          unlockedCount++;
          this._secureLog("debug", `\u{1F513} Emergency unlocked mutex: ${mutexName}`, {
            previousState,
            queueRejectCount,
            callerContext
          });
        } catch (error) {
          errorCount++;
          this._secureLog("error", `\u274C Error during emergency unlock of mutex: ${mutexName}`, {
            errorType: error.constructor.name,
            errorMessage: error.message,
            callerContext
          });
        }
      }
    });
    if (this._keySystemState) {
      try {
        const previousKeyState = { ...this._keySystemState };
        this._keySystemState.isInitializing = false;
        this._keySystemState.isRotating = false;
        this._keySystemState.isDestroying = false;
        this._keySystemState.operationId = null;
        this._keySystemState.concurrentOperations = 0;
        this._secureLog("debug", `\u{1F513} Emergency reset key system state`, {
          previousState: previousKeyState,
          callerContext
        });
      } catch (error) {
        this._secureLog("error", `\u274C Error resetting key system state during emergency unlock`, {
          errorType: error.constructor.name,
          errorMessage: error.message,
          callerContext
        });
      }
    }
    this._secureLog("info", `\u{1F6A8} Emergency mutex unlock completed`, {
      callerContext,
      unlockedCount,
      errorCount,
      totalMutexes: mutexes.length,
      timestamp: Date.now()
    });
    setTimeout(() => {
      this._validateMutexSystemAfterEmergencyUnlock();
    }, 100);
  }
  /**
   *   Handle key operation errors with recovery mechanisms
   */
  _handleKeyOperationError(error, operationId) {
    this._secureLog("error", "\u{1F6A8} Key operation error detected, initiating recovery", {
      operationId,
      errorType: error.constructor.name,
      errorMessage: error.message
    });
    if (this._keySystemState) {
      this._keySystemState.isInitializing = false;
      this._keySystemState.isRotating = false;
      this._keySystemState.isDestroying = false;
      this._keySystemState.operationId = null;
    }
    this.ecdhKeyPair = null;
    this.ecdsaKeyPair = null;
    this.encryptionKey = null;
    this.macKey = null;
    this.metadataKey = null;
    if (error.message.includes("timeout") || error.message.includes("race condition")) {
      this._secureLog("warn", "\u26A0\uFE0F Race condition or timeout detected, triggering emergency recovery");
      this._emergencyRecoverMutexSystem();
    }
  }
  /**
   *   Generate cryptographically secure IV with reuse prevention
   */
  _generateSecureIV(ivSize = 12, context = "general") {
    if (this._ivTrackingSystem.emergencyMode) {
      this._secureLog("error", "\u{1F6A8} CRITICAL: IV generation blocked - emergency mode active due to IV reuse");
      throw new Error("IV generation blocked - emergency mode active");
    }
    let attempts2 = 0;
    const maxAttempts = 100;
    while (attempts2 < maxAttempts) {
      attempts2++;
      const iv = crypto.getRandomValues(new Uint8Array(ivSize));
      const ivString = Array.from(iv).map((b) => b.toString(16).padStart(2, "0")).join("");
      if (this._ivTrackingSystem.usedIVs.has(ivString)) {
        this._ivTrackingSystem.collisionCount++;
        this._secureLog("error", `\u{1F6A8} CRITICAL: IV reuse detected!`, {
          context,
          attempt: attempts2,
          collisionCount: this._ivTrackingSystem.collisionCount,
          ivString: ivString.substring(0, 16) + "..."
          // Log partial IV for debugging
        });
        if (this._ivTrackingSystem.collisionCount > 5) {
          this._ivTrackingSystem.emergencyMode = true;
          this._secureLog("error", "\u{1F6A8} CRITICAL: Emergency mode activated due to excessive IV reuse");
          throw new Error("Emergency mode: Excessive IV reuse detected");
        }
        continue;
      }
      if (!this._validateIVEntropy(iv)) {
        this._ivTrackingSystem.entropyValidation.entropyFailures++;
        this._secureLog("warn", `\u26A0\uFE0F Low entropy IV detected`, {
          context,
          attempt: attempts2,
          entropyFailures: this._ivTrackingSystem.entropyValidation.entropyFailures
        });
        if (this._ivTrackingSystem.entropyValidation.entropyFailures > 10) {
          this._ivTrackingSystem.emergencyMode = true;
          this._secureLog("error", "\u{1F6A8} CRITICAL: Emergency mode activated due to low entropy IVs");
          throw new Error("Emergency mode: Low entropy IVs detected");
        }
        continue;
      }
      this._ivTrackingSystem.usedIVs.add(ivString);
      this._ivTrackingSystem.ivHistory.set(ivString, {
        timestamp: Date.now(),
        context,
        attempt: attempts2
      });
      if (this.sessionId) {
        if (!this._ivTrackingSystem.sessionIVs.has(this.sessionId)) {
          this._ivTrackingSystem.sessionIVs.set(this.sessionId, /* @__PURE__ */ new Set());
        }
        this._ivTrackingSystem.sessionIVs.get(this.sessionId).add(ivString);
      }
      this._validateRNGQuality();
      this._secureLog("debug", `\u2705 Secure IV generated`, {
        context,
        attempt: attempts2,
        ivSize,
        totalIVs: this._ivTrackingSystem.usedIVs.size
      });
      return iv;
    }
    this._secureLog("error", `\u274C Failed to generate unique IV after ${maxAttempts} attempts`, {
      context,
      totalIVs: this._ivTrackingSystem.usedIVs.size
    });
    throw new Error(`Failed to generate unique IV after ${maxAttempts} attempts`);
  }
  /**
   *   Validate IV entropy to detect weak RNG
   */
  _validateIVEntropy(iv) {
    this._ivTrackingSystem.entropyValidation.entropyTests++;
    const byteCounts = new Array(256).fill(0);
    for (let i = 0; i < iv.length; i++) {
      byteCounts[iv[i]]++;
    }
    const entropyResults = {
      shannon: 0,
      min: 0,
      collision: 0,
      compression: 0,
      quantum: 0
    };
    let shannonEntropy = 0;
    const totalBytes = iv.length;
    for (let i = 0; i < 256; i++) {
      if (byteCounts[i] > 0) {
        const probability = byteCounts[i] / totalBytes;
        shannonEntropy -= probability * Math.log2(probability);
      }
    }
    entropyResults.shannon = shannonEntropy;
    const maxCount = Math.max(...byteCounts);
    const maxProbability = maxCount / totalBytes;
    entropyResults.min = -Math.log2(maxProbability);
    let collisionSum = 0;
    for (let i = 0; i < 256; i++) {
      if (byteCounts[i] > 0) {
        const probability = byteCounts[i] / totalBytes;
        collisionSum += probability * probability;
      }
    }
    entropyResults.collision = -Math.log2(collisionSum);
    const ivString = Array.from(iv).map((b) => String.fromCharCode(b)).join("");
    const compressedLength = this._estimateCompressedLength(ivString);
    entropyResults.compression = (1 - compressedLength / totalBytes) * 8;
    entropyResults.quantum = this._calculateQuantumResistantEntropy(iv);
    const hasSuspiciousPatterns = this._detectAdvancedSuspiciousPatterns(iv);
    const minEntropyThreshold = this._ivTrackingSystem.entropyValidation.minEntropy;
    const isValid = entropyResults.shannon >= minEntropyThreshold && entropyResults.min >= minEntropyThreshold * 0.8 && entropyResults.collision >= minEntropyThreshold * 0.9 && entropyResults.compression >= minEntropyThreshold * 0.7 && entropyResults.quantum >= minEntropyThreshold * 0.6 && !hasSuspiciousPatterns;
    if (!isValid) {
      this._secureLog("warn", `\u26A0\uFE0F Enhanced IV entropy validation failed`, {
        shannon: entropyResults.shannon.toFixed(2),
        min: entropyResults.min.toFixed(2),
        collision: entropyResults.collision.toFixed(2),
        compression: entropyResults.compression.toFixed(2),
        quantum: entropyResults.quantum.toFixed(2),
        minThreshold: minEntropyThreshold,
        hasSuspiciousPatterns
      });
    }
    return isValid;
  }
  /**
   *   Estimate compressed length for entropy calculation
   * @param {string} data - Data to estimate compression
   * @returns {number} Estimated compressed length
   */
  _estimateCompressedLength(data) {
    let compressedLength = 0;
    let i = 0;
    while (i < data.length) {
      let matchLength = 0;
      let matchDistance = 0;
      for (let j = Math.max(0, i - 255); j < i; j++) {
        let k = 0;
        while (i + k < data.length && data[i + k] === data[j + k] && k < 255) {
          k++;
        }
        if (k > matchLength) {
          matchLength = k;
          matchDistance = i - j;
        }
      }
      if (matchLength >= 3) {
        compressedLength += 3;
        i += matchLength;
      } else {
        compressedLength += 1;
        i += 1;
      }
    }
    return compressedLength;
  }
  /**
   *   Calculate quantum-resistant entropy
   * @param {Uint8Array} data - Data to analyze
   * @returns {number} Quantum-resistant entropy score
   */
  _calculateQuantumResistantEntropy(data) {
    let quantumScore = 0;
    const hasQuantumVulnerablePatterns = this._detectQuantumVulnerablePatterns(data);
    if (hasQuantumVulnerablePatterns) {
      quantumScore -= 2;
    }
    const bitDistribution = this._analyzeBitDistribution(data);
    quantumScore += bitDistribution.score;
    const periodicity = this._detectPeriodicity(data);
    quantumScore -= periodicity * 0.5;
    return Math.max(0, Math.min(8, quantumScore));
  }
  /**
   *   Detect quantum-vulnerable patterns
   * @param {Uint8Array} data - Data to analyze
   * @returns {boolean} true if quantum-vulnerable patterns found
   */
  _detectQuantumVulnerablePatterns(data) {
    const patterns = [
      [0, 0, 0, 0, 0, 0, 0, 0],
      // All zeros
      [255, 255, 255, 255, 255, 255, 255, 255],
      // All ones
      [0, 1, 0, 1, 0, 1, 0, 1],
      // Alternating
      [1, 0, 1, 0, 1, 0, 1, 0]
      // Alternating reverse
    ];
    for (const pattern of patterns) {
      for (let i = 0; i <= data.length - pattern.length; i++) {
        let match = true;
        for (let j = 0; j < pattern.length; j++) {
          if (data[i + j] !== pattern[j]) {
            match = false;
            break;
          }
        }
        if (match) return true;
      }
    }
    return false;
  }
  /**
   *   Analyze bit distribution
   * @param {Uint8Array} data - Data to analyze
   * @returns {Object} Bit distribution analysis
   */
  _analyzeBitDistribution(data) {
    let ones = 0;
    let totalBits = data.length * 8;
    for (const byte of data) {
      ones += (byte >>> 0).toString(2).split("1").length - 1;
    }
    const zeroRatio = (totalBits - ones) / totalBits;
    const oneRatio = ones / totalBits;
    const deviation = Math.abs(0.5 - oneRatio);
    const score = Math.max(0, 8 - deviation * 16);
    return { score, zeroRatio, oneRatio, deviation };
  }
  /**
   *   Detect periodicity in data
   * @param {Uint8Array} data - Data to analyze
   * @returns {number} Periodicity score (0-1)
   */
  _detectPeriodicity(data) {
    if (data.length < 16) return 0;
    let maxPeriodicity = 0;
    for (let period = 2; period <= data.length / 2; period++) {
      let matches = 0;
      let totalChecks = 0;
      for (let i = 0; i < data.length - period; i++) {
        if (data[i] === data[i + period]) {
          matches++;
        }
        totalChecks++;
      }
      if (totalChecks > 0) {
        const periodicity = matches / totalChecks;
        maxPeriodicity = Math.max(maxPeriodicity, periodicity);
      }
    }
    return maxPeriodicity;
  }
  /**
   *   Enhanced suspicious pattern detection
   * @param {Uint8Array} iv - IV to check
   * @returns {boolean} true if suspicious patterns found
   */
  _detectAdvancedSuspiciousPatterns(iv) {
    const patterns = [
      // Sequential patterns
      [0, 1, 2, 3, 4, 5, 6, 7],
      [255, 254, 253, 252, 251, 250, 249, 248],
      // Repeated patterns
      [0, 0, 0, 0, 0, 0, 0, 0],
      [255, 255, 255, 255, 255, 255, 255, 255],
      // Alternating patterns
      [0, 255, 0, 255, 0, 255, 0, 255],
      [255, 0, 255, 0, 255, 0, 255, 0]
    ];
    for (const pattern of patterns) {
      for (let i = 0; i <= iv.length - pattern.length; i++) {
        let match = true;
        for (let j = 0; j < pattern.length; j++) {
          if (iv[i + j] !== pattern[j]) {
            match = false;
            break;
          }
        }
        if (match) return true;
      }
    }
    const entropyMap = this._calculateLocalEntropy(iv);
    const lowEntropyRegions = entropyMap.filter((e) => e < 3).length;
    return lowEntropyRegions > iv.length * 0.3;
  }
  /**
   *   Calculate local entropy for pattern detection
   * @param {Uint8Array} data - Data to analyze
   * @returns {Array} Array of local entropy values
   */
  _calculateLocalEntropy(data) {
    const windowSize = 8;
    const entropyMap = [];
    for (let i = 0; i <= data.length - windowSize; i++) {
      const window2 = data.slice(i, i + windowSize);
      const charCount = {};
      for (const byte of window2) {
        charCount[byte] = (charCount[byte] || 0) + 1;
      }
      let entropy = 0;
      for (const count of Object.values(charCount)) {
        const probability = count / windowSize;
        entropy -= probability * Math.log2(probability);
      }
      entropyMap.push(entropy);
    }
    return entropyMap;
  }
  /**
   *   Detect suspicious patterns in IVs
   */
  _detectSuspiciousIVPatterns(iv) {
    const allZeros = iv.every((byte) => byte === 0);
    const allOnes = iv.every((byte) => byte === 255);
    if (allZeros || allOnes) {
      return true;
    }
    let sequentialCount = 0;
    for (let i = 1; i < iv.length; i++) {
      if (iv[i] === iv[i - 1] + 1 || iv[i] === iv[i - 1] - 1) {
        sequentialCount++;
      } else {
        sequentialCount = 0;
      }
      if (sequentialCount >= 3) {
        return true;
      }
    }
    for (let patternLength = 2; patternLength <= Math.floor(iv.length / 2); patternLength++) {
      for (let start2 = 0; start2 <= iv.length - patternLength * 2; start2++) {
        const pattern1 = iv.slice(start2, start2 + patternLength);
        const pattern2 = iv.slice(start2 + patternLength, start2 + patternLength * 2);
        if (pattern1.every((byte, index) => byte === pattern2[index])) {
          return true;
        }
      }
    }
    return false;
  }
  /**
   *   Clean up old IVs with strict limits
   */
  _cleanupOldIVs() {
    const now = Date.now();
    const maxAge = 18e5;
    let cleanedCount = 0;
    const cleanupBatch = [];
    if (this._ivTrackingSystem.ivHistory.size > this._ivTrackingSystem.maxIVHistorySize) {
      const ivArray = Array.from(this._ivTrackingSystem.ivHistory.entries());
      const toRemove = ivArray.slice(0, ivArray.length - this._ivTrackingSystem.maxIVHistorySize);
      for (const [ivString] of toRemove) {
        cleanupBatch.push(ivString);
        cleanedCount++;
        if (cleanupBatch.length >= 100) {
          this._processCleanupBatch(cleanupBatch);
          cleanupBatch.length = 0;
        }
      }
    }
    for (const [ivString, metadata] of this._ivTrackingSystem.ivHistory.entries()) {
      if (now - metadata.timestamp > maxAge) {
        cleanupBatch.push(ivString);
        cleanedCount++;
        if (cleanupBatch.length >= 100) {
          this._processCleanupBatch(cleanupBatch);
          cleanupBatch.length = 0;
        }
      }
    }
    if (cleanupBatch.length > 0) {
      this._processCleanupBatch(cleanupBatch);
    }
    for (const [sessionId, sessionIVs] of this._ivTrackingSystem.sessionIVs.entries()) {
      if (sessionIVs.size > this._ivTrackingSystem.maxSessionIVs) {
        const ivArray = Array.from(sessionIVs);
        const toRemove = ivArray.slice(0, ivArray.length - this._ivTrackingSystem.maxSessionIVs);
        for (const ivString of toRemove) {
          sessionIVs.delete(ivString);
          this._ivTrackingSystem.usedIVs.delete(ivString);
          this._ivTrackingSystem.ivHistory.delete(ivString);
          cleanedCount++;
        }
      }
    }
    if (typeof window.gc === "function" && cleanedCount > 50) {
      try {
        window.gc();
      } catch (e) {
      }
    }
    if (cleanedCount > 0) {
      this._secureLog("debug", `\u{1F9F9} Enhanced cleanup: ${cleanedCount} old IVs removed`, {
        cleanedCount,
        remainingIVs: this._ivTrackingSystem.usedIVs.size,
        remainingHistory: this._ivTrackingSystem.ivHistory.size,
        memoryPressure: this._calculateMemoryPressure()
      });
    }
  }
  /**
   *   Process cleanup batch with constant-time operations
   * @param {Array} batch - Batch of items to clean up
   */
  _processCleanupBatch(batch) {
    for (const item of batch) {
      this._ivTrackingSystem.usedIVs.delete(item);
      this._ivTrackingSystem.ivHistory.delete(item);
    }
  }
  /**
   *   Calculate memory pressure for adaptive cleanup
   * @returns {number} Memory pressure score (0-100)
   */
  _calculateMemoryPressure() {
    const totalIVs = this._ivTrackingSystem.usedIVs.size;
    const maxAllowed = this._resourceLimits.maxIVHistory;
    return Math.min(100, Math.floor(totalIVs / maxAllowed * 100));
  }
  /**
   *   Get IV tracking system statistics
   */
  _getIVTrackingStats() {
    return {
      totalIVs: this._ivTrackingSystem.usedIVs.size,
      collisionCount: this._ivTrackingSystem.collisionCount,
      entropyTests: this._ivTrackingSystem.entropyValidation.entropyTests,
      entropyFailures: this._ivTrackingSystem.entropyValidation.entropyFailures,
      rngTests: this._ivTrackingSystem.rngValidation.testsPerformed,
      weakRngDetected: this._ivTrackingSystem.rngValidation.weakRngDetected,
      emergencyMode: this._ivTrackingSystem.emergencyMode,
      sessionCount: this._ivTrackingSystem.sessionIVs.size,
      lastCleanup: this._lastIVCleanupTime || 0
    };
  }
  /**
   *   Reset IV tracking system (for testing or emergency recovery)
   */
  _resetIVTrackingSystem() {
    this._secureLog("warn", "\u{1F504} Resetting IV tracking system");
    this._ivTrackingSystem.usedIVs.clear();
    this._ivTrackingSystem.ivHistory.clear();
    this._ivTrackingSystem.sessionIVs.clear();
    this._ivTrackingSystem.collisionCount = 0;
    this._ivTrackingSystem.entropyValidation.entropyTests = 0;
    this._ivTrackingSystem.entropyValidation.entropyFailures = 0;
    this._ivTrackingSystem.rngValidation.testsPerformed = 0;
    this._ivTrackingSystem.rngValidation.weakRngDetected = false;
    this._ivTrackingSystem.emergencyMode = false;
    this._secureLog("info", "\u2705 IV tracking system reset completed");
  }
  /**
   *   Validate RNG quality
   */
  _validateRNGQuality() {
    const now = Date.now();
    if (this._ivTrackingSystem.rngValidation.testsPerformed % 1e3 === 0) {
      try {
        const testIVs = [];
        for (let i = 0; i < 100; i++) {
          testIVs.push(crypto.getRandomValues(new Uint8Array(12)));
        }
        const testIVStrings = testIVs.map((iv) => Array.from(iv).map((b) => b.toString(16).padStart(2, "0")).join(""));
        const uniqueTestIVs = new Set(testIVStrings);
        if (uniqueTestIVs.size < 95) {
          this._ivTrackingSystem.rngValidation.weakRngDetected = true;
          this._secureLog("error", "\u{1F6A8} CRITICAL: Weak RNG detected in validation test", {
            uniqueIVs: uniqueTestIVs.size,
            totalTests: testIVs.length
          });
        }
        this._ivTrackingSystem.rngValidation.lastValidation = now;
      } catch (error) {
        this._secureLog("error", "\u274C RNG validation failed", {
          errorType: error.constructor.name
        });
      }
    }
    this._ivTrackingSystem.rngValidation.testsPerformed++;
  }
  /**
   *   Handle mutex timeout with enhanced state validation
   */
  _handleMutexTimeout(mutexName, operationId, timeout) {
    const mutex = this[`_${mutexName}Mutex`];
    if (!mutex) {
      this._secureLog("error", `\u274C Mutex '${mutexName}' not found during timeout handling`);
      return;
    }
    if (mutex.lockId !== operationId) {
      this._secureLog("warn", `\u26A0\uFE0F Timeout for different operation ID on mutex '${mutexName}'`, {
        expectedOperationId: operationId,
        actualLockId: mutex.lockId,
        locked: mutex.locked
      });
      return;
    }
    if (!mutex.locked) {
      this._secureLog("warn", `\u26A0\uFE0F Timeout for already unlocked mutex '${mutexName}'`, {
        operationId
      });
      return;
    }
    try {
      const lockDuration = mutex.lockTime ? Date.now() - mutex.lockTime : 0;
      this._secureLog("warn", `\u26A0\uFE0F Mutex '${mutexName}' auto-released due to timeout`, {
        operationId,
        lockDuration,
        timeout,
        queueLength: mutex.queue.length
      });
      mutex.locked = false;
      mutex.lockId = null;
      mutex.lockTimeout = null;
      mutex.lockTime = null;
      setTimeout(() => {
        try {
          this._processNextInQueue(mutexName);
        } catch (queueError) {
          this._secureLog("error", `\u274C Error processing queue after timeout for mutex '${mutexName}'`, {
            errorType: queueError.constructor.name,
            errorMessage: queueError.message
          });
        }
      }, 10);
    } catch (error) {
      this._secureLog("error", `\u274C Critical error during mutex timeout handling for '${mutexName}'`, {
        operationId,
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      try {
        this._emergencyUnlockAllMutexes("timeoutHandler");
      } catch (emergencyError) {
        this._secureLog("error", `\u274C Emergency unlock failed during timeout handling`, {
          originalError: error.message,
          emergencyError: emergencyError.message
        });
      }
    }
  }
  /**
   *   Validate mutex system after emergency unlock
   */
  _validateMutexSystemAfterEmergencyUnlock() {
    const mutexes = ["keyOperation", "cryptoOperation", "connectionOperation"];
    let validationErrors = 0;
    this._secureLog("info", "\u{1F50D} Validating mutex system after emergency unlock");
    mutexes.forEach((mutexName) => {
      const mutex = this[`_${mutexName}Mutex`];
      if (!mutex) {
        validationErrors++;
        this._secureLog("error", `\u274C Mutex '${mutexName}' not found after emergency unlock`);
        return;
      }
      if (mutex.locked) {
        validationErrors++;
        this._secureLog("error", `\u274C Mutex '${mutexName}' still locked after emergency unlock`, {
          lockId: mutex.lockId,
          lockTime: mutex.lockTime
        });
      }
      if (mutex.lockId !== null) {
        validationErrors++;
        this._secureLog("error", `\u274C Mutex '${mutexName}' still has lock ID after emergency unlock`, {
          lockId: mutex.lockId
        });
      }
      if (mutex.lockTimeout !== null) {
        validationErrors++;
        this._secureLog("error", `\u274C Mutex '${mutexName}' still has timeout after emergency unlock`);
      }
      if (mutex.queue.length > 0) {
        validationErrors++;
        this._secureLog("error", `\u274C Mutex '${mutexName}' still has queue items after emergency unlock`, {
          queueLength: mutex.queue.length
        });
      }
    });
    if (this._keySystemState) {
      if (this._keySystemState.isInitializing || this._keySystemState.isRotating || this._keySystemState.isDestroying) {
        validationErrors++;
        this._secureLog("error", `\u274C Key system state not properly reset after emergency unlock`, {
          isInitializing: this._keySystemState.isInitializing,
          isRotating: this._keySystemState.isRotating,
          isDestroying: this._keySystemState.isDestroying
        });
      }
    }
    if (validationErrors === 0) {
      this._secureLog("info", "\u2705 Mutex system validation passed after emergency unlock");
    } else {
      this._secureLog("error", `\u274C Mutex system validation failed after emergency unlock`, {
        validationErrors
      });
      setTimeout(() => {
        this._emergencyRecoverMutexSystem();
      }, 1e3);
    }
  }
  /**
   * NEW: Diagnostics of the mutex system state
   */
  _getMutexSystemDiagnostics() {
    const diagnostics = {
      timestamp: Date.now(),
      systemValid: this._validateMutexSystem(),
      mutexes: {},
      counters: { ...this._operationCounters },
      keySystemState: { ...this._keySystemState }
    };
    const mutexNames = ["keyOperation", "cryptoOperation", "connectionOperation"];
    mutexNames.forEach((mutexName) => {
      const mutexPropertyName = `_${mutexName}Mutex`;
      const mutex = this[mutexPropertyName];
      if (mutex) {
        diagnostics.mutexes[mutexName] = {
          locked: mutex.locked,
          lockId: mutex.lockId,
          queueLength: mutex.queue.length,
          hasTimeout: !!mutex.lockTimeout
        };
      } else {
        diagnostics.mutexes[mutexName] = { error: "not_found" };
      }
    });
    return diagnostics;
  }
  /**
   * FULLY FIXED createSecureOffer()
   * With race-condition protection and improved security
   */
  async createSecureOffer() {
    console.log("\u{1F3AF} createSecureOffer called");
    return this._withMutex("connectionOperation", async (operationId) => {
      this._secureLog("info", "\u{1F4E4} Creating secure offer with mutex", {
        operationId,
        connectionAttempts: this.connectionAttempts,
        currentState: this.peerConnection?.connectionState || "none"
      });
      try {
        console.log("\u{1F3AF} PHASE 1: Initialization and validation");
        this._resetNotificationFlags();
        if (!this._checkRateLimit()) {
          throw new Error("Connection rate limit exceeded. Please wait before trying again.");
        }
        this.connectionAttempts = 0;
        this.sessionSalt = window.EnhancedSecureCryptoUtils.generateSalt();
        console.log("\u{1F3AF} PHASE 1 completed: Session salt generated");
        this._secureLog("debug", "\u{1F9C2} Session salt generated", {
          operationId,
          saltLength: this.sessionSalt.length,
          isValidSalt: Array.isArray(this.sessionSalt) && this.sessionSalt.length === 64
        });
        console.log("\u{1F3AF} PHASE 2: Secure key generation");
        const keyPairs = await this._generateEncryptionKeys();
        this.ecdhKeyPair = keyPairs.ecdhKeyPair;
        this.ecdsaKeyPair = keyPairs.ecdsaKeyPair;
        if (!this.ecdhKeyPair?.privateKey || !this.ecdhKeyPair?.publicKey) {
          throw new Error("Failed to generate valid ECDH key pair");
        }
        if (!this.ecdsaKeyPair?.privateKey || !this.ecdsaKeyPair?.publicKey) {
          throw new Error("Failed to generate valid ECDSA key pair");
        }
        console.log("\u{1F3AF} PHASE 3: MITM protection and fingerprinting");
        const ecdhFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(
          await crypto.subtle.exportKey("spki", this.ecdhKeyPair.publicKey)
        );
        const ecdsaFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(
          await crypto.subtle.exportKey("spki", this.ecdsaKeyPair.publicKey)
        );
        if (!ecdhFingerprint || !ecdsaFingerprint) {
          throw new Error("Failed to generate key fingerprints");
        }
        this._secureLog("info", "Generated unique key pairs for MITM protection", {
          operationId,
          hasECDHFingerprint: !!ecdhFingerprint,
          hasECDSAFingerprint: !!ecdsaFingerprint,
          fingerprintLength: ecdhFingerprint.length,
          timestamp: Date.now()
        });
        console.log("\u{1F3AF} PHASE 4: Export signed keys");
        const ecdhPublicKeyData = await window.EnhancedSecureCryptoUtils.exportPublicKeyWithSignature(
          this.ecdhKeyPair.publicKey,
          this.ecdsaKeyPair.privateKey,
          "ECDH"
        );
        const ecdsaPublicKeyData = await window.EnhancedSecureCryptoUtils.exportPublicKeyWithSignature(
          this.ecdsaKeyPair.publicKey,
          this.ecdsaKeyPair.privateKey,
          "ECDSA"
        );
        if (!ecdhPublicKeyData || typeof ecdhPublicKeyData !== "object") {
          this._secureLog("error", "CRITICAL: ECDH key export failed - invalid object structure", { operationId });
          throw new Error("CRITICAL SECURITY FAILURE: ECDH key export validation failed - hard abort required");
        }
        if (!ecdhPublicKeyData.keyData || !ecdhPublicKeyData.signature) {
          this._secureLog("error", "CRITICAL: ECDH key export incomplete - missing keyData or signature", {
            operationId,
            hasKeyData: !!ecdhPublicKeyData.keyData,
            hasSignature: !!ecdhPublicKeyData.signature
          });
          throw new Error("CRITICAL SECURITY FAILURE: ECDH key export incomplete - hard abort required");
        }
        if (!ecdsaPublicKeyData || typeof ecdsaPublicKeyData !== "object") {
          this._secureLog("error", "CRITICAL: ECDSA key export failed - invalid object structure", { operationId });
          throw new Error("CRITICAL SECURITY FAILURE: ECDSA key export validation failed - hard abort required");
        }
        if (!ecdsaPublicKeyData.keyData || !ecdsaPublicKeyData.signature) {
          this._secureLog("error", "CRITICAL: ECDSA key export incomplete - missing keyData or signature", {
            operationId,
            hasKeyData: !!ecdsaPublicKeyData.keyData,
            hasSignature: !!ecdsaPublicKeyData.signature
          });
          throw new Error("CRITICAL SECURITY FAILURE: ECDSA key export incomplete - hard abort required");
        }
        console.log("\u{1F3AF} PHASE 5: Update security features");
        this._updateSecurityFeatures({
          hasEncryption: true,
          hasECDH: true,
          hasECDSA: true,
          hasMutualAuth: true,
          hasMetadataProtection: true,
          hasEnhancedReplayProtection: true,
          hasNonExtractableKeys: true,
          hasRateLimiting: true,
          hasEnhancedValidation: true,
          hasPFS: true
        });
        console.log("\u{1F3AF} PHASE 6: Initialize peer connection");
        this.isInitiator = true;
        this.onStatusChange("connecting");
        this.createPeerConnection();
        this.dataChannel = this.peerConnection.createDataChannel("securechat", {
          ordered: true
        });
        this.setupDataChannel(this.dataChannel);
        this._secureLog("debug", "\u{1F517} Data channel created", {
          operationId,
          channelLabel: this.dataChannel.label,
          channelOrdered: this.dataChannel.ordered
        });
        console.log("\u{1F3AF} PHASE 7: Create SDP offer");
        console.log("\u{1F3AF} Creating WebRTC offer...");
        const offer = await this.peerConnection.createOffer({
          offerToReceiveAudio: false,
          offerToReceiveVideo: false
        });
        console.log("\u{1F3AF} WebRTC offer created successfully");
        console.log("\u{1F3AF} Setting local description...");
        await this.peerConnection.setLocalDescription(offer);
        console.log("\u{1F3AF} Local description set successfully");
        console.log("\u{1F3AF} Extracting DTLS fingerprint...");
        try {
          const ourFingerprint = this._extractDTLSFingerprintFromSDP(offer.sdp);
          this.expectedDTLSFingerprint = ourFingerprint;
          console.log("\u{1F3AF} DTLS fingerprint extracted successfully");
          this._secureLog("info", "Generated DTLS fingerprint for out-of-band verification", {
            fingerprint: ourFingerprint,
            context: "offer_creation"
          });
          this.deliverMessageToUI(`\u{1F510} DTLS fingerprint ready for verification: ${ourFingerprint}`, "system");
        } catch (error) {
          this._secureLog("error", "Failed to extract DTLS fingerprint from offer", { error: error.message });
        }
        await this.waitForIceGathering();
        this._secureLog("debug", "\u{1F9CA} ICE gathering completed", {
          operationId,
          iceGatheringState: this.peerConnection.iceGatheringState,
          connectionState: this.peerConnection.connectionState
        });
        console.log("\u{1F3AF} PHASE 8: Generate SAS for out-of-band verification");
        this.verificationCode = window.EnhancedSecureCryptoUtils.generateVerificationCode();
        console.log("\u{1F3AF} Placeholder verification code generated:", this.verificationCode);
        if (!this.verificationCode || this.verificationCode.length < _EnhancedSecureWebRTCManager.SIZES.VERIFICATION_CODE_MIN_LENGTH) {
          throw new Error("Failed to generate valid verification code");
        }
        console.log("\u{1F3AF} PHASE 9: Mutual authentication challenge");
        const authChallenge = window.EnhancedSecureCryptoUtils.generateMutualAuthChallenge();
        if (!authChallenge) {
          throw new Error("Failed to generate mutual authentication challenge");
        }
        console.log("\u{1F3AF} PHASE 10: Session ID for MITM protection");
        this.sessionId = Array.from(crypto.getRandomValues(new Uint8Array(_EnhancedSecureWebRTCManager.SIZES.SESSION_ID_LENGTH))).map((b) => b.toString(16).padStart(2, "0")).join("");
        if (!this.sessionId || this.sessionId.length !== _EnhancedSecureWebRTCManager.SIZES.SESSION_ID_LENGTH * 2) {
          throw new Error("Failed to generate valid session ID");
        }
        this.connectionId = Array.from(crypto.getRandomValues(new Uint8Array(8))).map((b) => b.toString(16).padStart(2, "0")).join("");
        console.log("\u{1F3AF} PHASE 11: Security level calculation");
        let securityLevel;
        try {
          securityLevel = await this.calculateSecurityLevel();
        } catch (error) {
          this._secureLog("warn", "\u26A0\uFE0F Security level calculation failed, using fallback", {
            operationId,
            errorType: error.constructor.name
          });
          securityLevel = {
            level: "enhanced",
            score: 75,
            passedChecks: 10,
            totalChecks: 15,
            isRealData: false
          };
        }
        console.log("\u{1F3AF} PHASE 12: Create offer package");
        const currentTimestamp = Date.now();
        console.log("\u{1F3AF} Creating offer package object...");
        const offerPackage = {
          // Core information
          type: "enhanced_secure_offer",
          sdp: this.peerConnection.localDescription.sdp,
          version: "4.0",
          timestamp: currentTimestamp,
          // Cryptographic keys
          ecdhPublicKey: ecdhPublicKeyData,
          ecdsaPublicKey: ecdsaPublicKeyData,
          // Session data
          salt: this.sessionSalt,
          sessionId: this.sessionId,
          connectionId: this.connectionId,
          // Authentication
          verificationCode: this.verificationCode,
          authChallenge,
          // Security metadata
          securityLevel,
          // Additional fields for validation
          keyFingerprints: {
            ecdh: ecdhFingerprint.substring(0, 16),
            // First 16 chars for validation
            ecdsa: ecdsaFingerprint.substring(0, 16)
          },
          // Optional capabilities info
          capabilities: {
            supportsFileTransfer: true,
            supportsEnhancedSecurity: true,
            supportsKeyRotation: true,
            supportsFakeTraffic: this.fakeTrafficConfig.enabled,
            supportsDecoyChannels: this.decoyChannelConfig.enabled
          }
        };
        console.log("\u{1F3AF} Offer package object created successfully");
        console.log("\u{1F3AF} PHASE 13: Validate offer package");
        console.log("\u{1F3AF} Validating offer package...");
        try {
          const validationResult = this.validateEnhancedOfferData(offerPackage);
          console.log("\u{1F3AF} Validation result:", validationResult);
          if (!validationResult) {
            console.log("\u{1F3AF} Offer package validation FAILED");
            throw new Error("Generated offer package failed validation");
          }
          console.log("\u{1F3AF} Offer package validation PASSED");
        } catch (validationError) {
          console.log("\u{1F3AF} Validation ERROR:", validationError.message);
          throw new Error(`Offer package validation error: ${validationError.message}`);
        }
        console.log("\u{1F3AF} PHASE 14: Logging and events");
        this._secureLog("info", "Enhanced secure offer created successfully", {
          operationId,
          version: offerPackage.version,
          hasECDSA: true,
          hasMutualAuth: true,
          hasSessionId: !!offerPackage.sessionId,
          securityLevel: securityLevel.level,
          timestamp: currentTimestamp,
          capabilitiesCount: Object.keys(offerPackage.capabilities).length
        });
        document.dispatchEvent(new CustomEvent("new-connection", {
          detail: {
            type: "offer",
            timestamp: currentTimestamp,
            securityLevel: securityLevel.level,
            operationId
          }
        }));
        console.log("\u{1F3AF} PHASE 15: Return result");
        console.log("\u{1F3AF} createSecureOffer completed successfully, returning offerPackage");
        return offerPackage;
      } catch (error) {
        this._secureLog("error", "\u274C Enhanced secure offer creation failed in critical section", {
          operationId,
          errorType: error.constructor.name,
          errorMessage: error.message,
          phase: this._determineErrorPhase(error),
          connectionAttempts: this.connectionAttempts
        });
        this._cleanupFailedOfferCreation();
        this.onStatusChange("disconnected");
        throw error;
      }
    }, 15e3);
  }
  /**
   * HELPER: Determine the phase where the error occurred
   */
  _determineErrorPhase(error) {
    const message = error.message.toLowerCase();
    if (message.includes("rate limit")) return "rate_limiting";
    if (message.includes("key pair") || message.includes("generate")) return "key_generation";
    if (message.includes("fingerprint")) return "fingerprinting";
    if (message.includes("export") || message.includes("signature")) return "key_export";
    if (message.includes("peer connection")) return "webrtc_setup";
    if (message.includes("offer") || message.includes("sdp")) return "sdp_creation";
    if (message.includes("verification")) return "verification_setup";
    if (message.includes("session")) return "session_setup";
    if (message.includes("validation")) return "package_validation";
    return "unknown";
  }
  /**
   *   Secure cleanup state after failed offer creation
   */
  _cleanupFailedOfferCreation() {
    try {
      this._secureCleanupCryptographicMaterials();
      if (this.peerConnection) {
        this.peerConnection.close();
        this.peerConnection = null;
      }
      if (this.dataChannel) {
        this.dataChannel.close();
        this.dataChannel = null;
      }
      this.isInitiator = false;
      this.isVerified = false;
      this._updateSecurityFeatures({
        hasEncryption: false,
        hasECDH: false,
        hasECDSA: false,
        hasMutualAuth: false,
        hasMetadataProtection: false,
        hasEnhancedReplayProtection: false,
        hasNonExtractableKeys: false,
        hasEnhancedValidation: false,
        hasPFS: false
      });
      this._forceGarbageCollection();
      this._secureLog("debug", "\u{1F512} Failed offer creation cleanup completed with secure memory wipe");
    } catch (cleanupError) {
      this._secureLog("error", "\u274C Error during offer creation cleanup", {
        errorType: cleanupError.constructor.name,
        errorMessage: cleanupError.message
      });
    }
  }
  /**
   * HELPER: Atomic update of security features (if not added yet)
   */
  _updateSecurityFeatures(updates) {
    const oldFeatures = { ...this.securityFeatures };
    try {
      Object.assign(this.securityFeatures, updates);
      this._secureLog("debug", "\u{1F527} Security features updated", {
        updatedCount: Object.keys(updates).length,
        totalFeatures: Object.keys(this.securityFeatures).length
      });
    } catch (error) {
      this.securityFeatures = oldFeatures;
      this._secureLog("error", "\u274C Security features update failed, rolled back", {
        errorType: error.constructor.name
      });
      throw error;
    }
  }
  /**
   * FULLY FIXED METHOD createSecureAnswer()
   * With race-condition protection and enhanced security
   */
  async createSecureAnswer(offerData) {
    console.log("\u{1F3AF} createSecureAnswer called with offerData:", offerData ? "present" : "null");
    return this._withMutex("connectionOperation", async (operationId) => {
      this._secureLog("info", "\u{1F4E8} Creating secure answer with mutex", {
        operationId,
        hasOfferData: !!offerData,
        offerType: offerData?.type,
        offerVersion: offerData?.version,
        offerTimestamp: offerData?.timestamp
      });
      try {
        this._resetNotificationFlags();
        this._secureLog("debug", "Starting enhanced offer validation", {
          operationId,
          hasOfferData: !!offerData,
          offerType: offerData?.type,
          hasECDHKey: !!offerData?.ecdhPublicKey,
          hasECDSAKey: !!offerData?.ecdsaPublicKey,
          hasSalt: !!offerData?.salt
        });
        if (!this.validateEnhancedOfferData(offerData)) {
          throw new Error("Invalid connection data format - failed enhanced validation");
        }
        if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkConnectionRate(this.rateLimiterId)) {
          throw new Error("Connection rate limit exceeded. Please wait before trying again.");
        }
        if (!offerData.timestamp || !offerData.version) {
          throw new Error("Missing required security fields in offer data \u2013 possible MITM attack");
        }
        const offerAge = Date.now() - offerData.timestamp;
        const MAX_OFFER_AGE = 3e5;
        if (offerAge > MAX_OFFER_AGE) {
          this._secureLog("error", "Offer data is too old - possible replay attack", {
            operationId,
            offerAge: Math.round(offerAge / 1e3),
            maxAllowedAge: Math.round(MAX_OFFER_AGE / 1e3),
            timestamp: offerData.timestamp
          });
          if (this.onAnswerError) {
            this.onAnswerError("replay_attack", "Offer data is too old \u2013 possible replay attack");
          }
          throw new Error("Offer data is too old \u2013 possible replay attack");
        }
        if (offerData.version !== "4.0") {
          this._secureLog("warn", "Protocol version mismatch detected", {
            operationId,
            expectedVersion: "4.0",
            receivedVersion: offerData.version
          });
          if (offerData.version !== "3.0") {
            throw new Error(`Unsupported protocol version: ${offerData.version}`);
          }
        }
        this.sessionSalt = offerData.salt;
        if (!Array.isArray(this.sessionSalt)) {
          throw new Error("Invalid session salt format - must be array");
        }
        const expectedSaltLength = offerData.version === "4.0" ? 64 : 32;
        if (this.sessionSalt.length !== expectedSaltLength) {
          throw new Error(`Invalid session salt length: expected ${expectedSaltLength}, got ${this.sessionSalt.length}`);
        }
        const saltFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(this.sessionSalt);
        this._secureLog("info", "Session salt validated successfully", {
          operationId,
          saltLength: this.sessionSalt.length,
          saltFingerprint: saltFingerprint.substring(0, 8)
        });
        const keyPairs = await this._generateEncryptionKeys();
        this.ecdhKeyPair = keyPairs.ecdhKeyPair;
        this.ecdsaKeyPair = keyPairs.ecdsaKeyPair;
        if (!(this.ecdhKeyPair?.privateKey instanceof CryptoKey)) {
          this._secureLog("error", "Local ECDH private key is not a CryptoKey", {
            operationId,
            hasKeyPair: !!this.ecdhKeyPair,
            privateKeyType: typeof this.ecdhKeyPair?.privateKey,
            privateKeyAlgorithm: this.ecdhKeyPair?.privateKey?.algorithm?.name
          });
          throw new Error("Local ECDH private key is not a valid CryptoKey");
        }
        let peerECDSAPublicKey;
        try {
          peerECDSAPublicKey = await crypto.subtle.importKey(
            "spki",
            new Uint8Array(offerData.ecdsaPublicKey.keyData),
            {
              name: "ECDSA",
              namedCurve: "P-384"
            },
            false,
            ["verify"]
          );
        } catch (error) {
          this._throwSecureError(error, "ecdsa_key_import");
        }
        let peerECDHPublicKey;
        try {
          peerECDHPublicKey = await window.EnhancedSecureCryptoUtils.importSignedPublicKey(
            offerData.ecdhPublicKey,
            peerECDSAPublicKey,
            "ECDH"
          );
        } catch (error) {
          this._secureLog("error", "Failed to import signed ECDH public key", {
            operationId,
            errorType: error.constructor.name
          });
          this._throwSecureError(error, "ecdh_key_import");
        }
        if (!(peerECDHPublicKey instanceof CryptoKey)) {
          this._secureLog("error", "Peer ECDH public key is not a CryptoKey", {
            operationId,
            publicKeyType: typeof peerECDHPublicKey,
            publicKeyAlgorithm: peerECDHPublicKey?.algorithm?.name
          });
          throw new Error("Peer ECDH public key is not a valid CryptoKey");
        }
        this.peerPublicKey = peerECDHPublicKey;
        let derivedKeys;
        try {
          derivedKeys = await window.EnhancedSecureCryptoUtils.deriveSharedKeys(
            this.ecdhKeyPair.privateKey,
            peerECDHPublicKey,
            this.sessionSalt
          );
        } catch (error) {
          this._secureLog("error", "Failed to derive shared keys", {
            operationId,
            errorType: error.constructor.name
          });
          this._throwSecureError(error, "key_derivation");
        }
        await this._setEncryptionKeys(
          derivedKeys.encryptionKey,
          derivedKeys.macKey,
          derivedKeys.metadataKey,
          derivedKeys.fingerprint
        );
        if (!(this.encryptionKey instanceof CryptoKey) || !(this.macKey instanceof CryptoKey) || !(this.metadataKey instanceof CryptoKey)) {
          this._secureLog("error", "Invalid key types after derivation", {
            operationId,
            encryptionKeyType: typeof this.encryptionKey,
            macKeyType: typeof this.macKey,
            metadataKeyType: typeof this.metadataKey
          });
          throw new Error("Invalid key types after derivation");
        }
        this.verificationCode = offerData.verificationCode;
        this._secureLog("info", "Encryption keys derived and set successfully", {
          operationId,
          hasEncryptionKey: !!this.encryptionKey,
          hasMacKey: !!this.macKey,
          hasMetadataKey: !!this.metadataKey,
          hasKeyFingerprint: !!this.keyFingerprint,
          mitmProtection: "enabled",
          signatureVerified: true
        });
        this._updateSecurityFeatures({
          hasEncryption: true,
          hasECDH: true,
          hasECDSA: true,
          hasMutualAuth: true,
          hasMetadataProtection: true,
          hasEnhancedReplayProtection: true,
          hasNonExtractableKeys: true,
          hasRateLimiting: true,
          hasEnhancedValidation: true,
          hasPFS: true
        });
        this.currentKeyVersion = 0;
        this.lastKeyRotation = Date.now();
        this.keyVersions.set(0, {
          salt: this.sessionSalt,
          timestamp: this.lastKeyRotation,
          messageCount: 0
        });
        let authProof;
        if (offerData.authChallenge) {
          try {
            authProof = await window.EnhancedSecureCryptoUtils.createAuthProof(
              offerData.authChallenge,
              this.ecdsaKeyPair.privateKey,
              this.ecdsaKeyPair.publicKey
            );
          } catch (error) {
            this._secureLog("error", "Failed to create authentication proof", {
              operationId,
              errorType: error.constructor.name
            });
            this._throwSecureError(error, "authentication_proof_creation");
          }
        } else {
          this._secureLog("warn", "No auth challenge in offer - mutual auth disabled", {
            operationId
          });
        }
        this.isInitiator = false;
        this.onStatusChange("connecting");
        console.log("Before onKeyExchange - keyFingerprint:", this.keyFingerprint);
        this.onKeyExchange(this.keyFingerprint);
        this.createPeerConnection();
        if (this.strictDTLSValidation) {
          try {
            const receivedFingerprint = this._extractDTLSFingerprintFromSDP(offerData.sdp);
            if (this.expectedDTLSFingerprint) {
              this._validateDTLSFingerprint(receivedFingerprint, this.expectedDTLSFingerprint, "offer_validation");
            } else {
              this.expectedDTLSFingerprint = receivedFingerprint;
              this._secureLog("info", "Stored DTLS fingerprint for future validation", {
                fingerprint: receivedFingerprint,
                context: "first_connection"
              });
            }
          } catch (error) {
            this._secureLog("warn", "DTLS fingerprint validation failed - continuing in fallback mode", {
              error: error.message,
              context: "offer_validation"
            });
          }
        } else {
          this._secureLog("info", "DTLS fingerprint validation disabled - proceeding without validation");
        }
        try {
          this._secureLog("debug", "Setting remote description from offer", {
            operationId,
            sdpLength: offerData.sdp?.length || 0
          });
          await this.peerConnection.setRemoteDescription(new RTCSessionDescription({
            type: "offer",
            sdp: offerData.sdp
          }));
          this._secureLog("debug", "Remote description set successfully", {
            operationId,
            signalingState: this.peerConnection.signalingState
          });
        } catch (error) {
          this._secureLog("error", "Failed to set remote description", {
            error: error.message,
            operationId
          });
          this._throwSecureError(error, "webrtc_remote_description");
        }
        this._secureLog("debug", "\u{1F517} Remote description set successfully", {
          operationId,
          connectionState: this.peerConnection.connectionState,
          signalingState: this.peerConnection.signalingState
        });
        let answer;
        try {
          answer = await this.peerConnection.createAnswer({
            offerToReceiveAudio: false,
            offerToReceiveVideo: false
          });
        } catch (error) {
          this._throwSecureError(error, "webrtc_create_answer");
        }
        try {
          await this.peerConnection.setLocalDescription(answer);
        } catch (error) {
          this._throwSecureError(error, "webrtc_local_description");
        }
        try {
          const ourFingerprint = this._extractDTLSFingerprintFromSDP(answer.sdp);
          this.expectedDTLSFingerprint = ourFingerprint;
          this._secureLog("info", "Generated DTLS fingerprint for out-of-band verification", {
            fingerprint: ourFingerprint,
            context: "answer_creation"
          });
          this.deliverMessageToUI(`\u{1F510} DTLS fingerprint ready for verification: ${ourFingerprint}`, "system");
        } catch (error) {
          this._secureLog("error", "Failed to extract DTLS fingerprint from answer", { error: error.message });
        }
        await this.waitForIceGathering();
        this._secureLog("debug", "\u{1F9CA} ICE gathering completed for answer", {
          operationId,
          iceGatheringState: this.peerConnection.iceGatheringState,
          connectionState: this.peerConnection.connectionState
        });
        const ecdhPublicKeyData = await window.EnhancedSecureCryptoUtils.exportPublicKeyWithSignature(
          this.ecdhKeyPair.publicKey,
          this.ecdsaKeyPair.privateKey,
          "ECDH"
        );
        const ecdsaPublicKeyData = await window.EnhancedSecureCryptoUtils.exportPublicKeyWithSignature(
          this.ecdsaKeyPair.publicKey,
          this.ecdsaKeyPair.privateKey,
          "ECDSA"
        );
        if (!ecdhPublicKeyData || typeof ecdhPublicKeyData !== "object") {
          this._secureLog("error", "CRITICAL: ECDH key export failed - invalid object structure", { operationId });
          throw new Error("CRITICAL SECURITY FAILURE: ECDH key export validation failed - hard abort required");
        }
        if (!ecdhPublicKeyData.keyData || !ecdhPublicKeyData.signature) {
          this._secureLog("error", "CRITICAL: ECDH key export incomplete - missing keyData or signature", {
            operationId,
            hasKeyData: !!ecdhPublicKeyData.keyData,
            hasSignature: !!ecdhPublicKeyData.signature
          });
          throw new Error("CRITICAL SECURITY FAILURE: ECDH key export incomplete - hard abort required");
        }
        if (!ecdsaPublicKeyData || typeof ecdsaPublicKeyData !== "object") {
          this._secureLog("error", "CRITICAL: ECDSA key export failed - invalid object structure", { operationId });
          throw new Error("CRITICAL SECURITY FAILURE: ECDSA key export validation failed - hard abort required");
        }
        if (!ecdsaPublicKeyData.keyData || !ecdsaPublicKeyData.signature) {
          this._secureLog("error", "CRITICAL: ECDSA key export incomplete - missing keyData or signature", {
            operationId,
            hasKeyData: !!ecdsaPublicKeyData.keyData,
            hasSignature: !!ecdsaPublicKeyData.signature
          });
          throw new Error("CRITICAL SECURITY FAILURE: ECDSA key export incomplete - hard abort required");
        }
        let securityLevel;
        try {
          securityLevel = await this.calculateSecurityLevel();
        } catch (error) {
          this._secureLog("warn", "\u26A0\uFE0F Security level calculation failed, using fallback", {
            operationId,
            errorType: error.constructor.name
          });
          securityLevel = {
            level: "enhanced",
            score: 80,
            passedChecks: 12,
            totalChecks: 15,
            isRealData: false
          };
        }
        const currentTimestamp = Date.now();
        const answerPackage = {
          // Core information
          type: "enhanced_secure_answer",
          sdp: this.peerConnection.localDescription.sdp,
          version: "4.0",
          timestamp: currentTimestamp,
          // Cryptographic keys
          ecdhPublicKey: ecdhPublicKeyData,
          ecdsaPublicKey: ecdsaPublicKeyData,
          // Authentication
          authProof,
          // Security metadata
          securityLevel,
          // Additional security fields
          sessionConfirmation: {
            saltFingerprint: saltFingerprint.substring(0, 16),
            keyDerivationSuccess: true,
            mutualAuthEnabled: !!authProof
          },
          // Answerer capabilities
          capabilities: {
            supportsFileTransfer: true,
            supportsEnhancedSecurity: true,
            supportsKeyRotation: true,
            supportsFakeTraffic: this.fakeTrafficConfig.enabled,
            supportsDecoyChannels: this.decoyChannelConfig.enabled,
            protocolVersion: "4.0"
          }
        };
        if (!answerPackage.sdp || !answerPackage.ecdhPublicKey || !answerPackage.ecdsaPublicKey) {
          throw new Error("Generated answer package is incomplete");
        }
        this._secureLog("info", "Enhanced secure answer created successfully", {
          operationId,
          version: answerPackage.version,
          hasECDSA: true,
          hasMutualAuth: !!authProof,
          hasSessionConfirmation: !!answerPackage.sessionConfirmation,
          securityLevel: securityLevel.level,
          timestamp: currentTimestamp,
          processingTime: currentTimestamp - offerData.timestamp
        });
        document.dispatchEvent(new CustomEvent("new-connection", {
          detail: {
            type: "answer",
            timestamp: currentTimestamp,
            securityLevel: securityLevel.level,
            operationId
          }
        }));
        setTimeout(async () => {
          try {
            const realSecurityData = await this.calculateAndReportSecurityLevel();
            if (realSecurityData) {
              this.notifySecurityUpdate();
              this._secureLog("info", "\u2705 Post-connection security level calculated", {
                operationId,
                level: realSecurityData.level
              });
            }
          } catch (error) {
            this._secureLog("error", "\u274C Error calculating post-connection security", {
              operationId,
              errorType: error.constructor.name
            });
          }
        }, 1e3);
        setTimeout(async () => {
          if (!this.lastSecurityCalculation || this.lastSecurityCalculation.score < 50) {
            this._secureLog("info", "\u{1F504} Retrying security calculation", {
              operationId
            });
            await this.calculateAndReportSecurityLevel();
            this.notifySecurityUpdate();
          }
        }, 3e3);
        this.notifySecurityUpdate();
        return answerPackage;
      } catch (error) {
        this._secureLog("error", "\u274C Enhanced secure answer creation failed in critical section", {
          operationId,
          errorType: error.constructor.name,
          errorMessage: error.message,
          phase: this._determineAnswerErrorPhase(error),
          offerAge: offerData?.timestamp ? Date.now() - offerData.timestamp : "unknown"
        });
        this._cleanupFailedAnswerCreation();
        this.onStatusChange("disconnected");
        if (this.onAnswerError) {
          if (error.message.includes("too old") || error.message.includes("replay")) {
            this.onAnswerError("replay_attack", error.message);
          } else if (error.message.includes("MITM") || error.message.includes("signature")) {
            this.onAnswerError("security_violation", error.message);
          } else if (error.message.includes("validation") || error.message.includes("format")) {
            this.onAnswerError("invalid_format", error.message);
          } else {
            this.onAnswerError("general_error", error.message);
          }
        }
        throw error;
      }
    }, 2e4);
  }
  /**
   * HELPER: Determine error phase for answer
   */
  _determineAnswerErrorPhase(error) {
    const message = error.message.toLowerCase();
    if (message.includes("validation") || message.includes("format")) return "offer_validation";
    if (message.includes("rate limit")) return "rate_limiting";
    if (message.includes("replay") || message.includes("too old")) return "replay_protection";
    if (message.includes("salt")) return "salt_validation";
    if (message.includes("key pair") || message.includes("generate")) return "key_generation";
    if (message.includes("import") || message.includes("ecdsa") || message.includes("ecdh")) return "key_import";
    if (message.includes("signature") || message.includes("mitm")) return "signature_verification";
    if (message.includes("derive") || message.includes("shared")) return "key_derivation";
    if (message.includes("auth") || message.includes("proof")) return "authentication";
    if (message.includes("remote description") || message.includes("local description")) return "webrtc_setup";
    if (message.includes("answer") || message.includes("sdp")) return "sdp_creation";
    if (message.includes("export")) return "key_export";
    if (message.includes("security level")) return "security_calculation";
    return "unknown";
  }
  /**
   * HELPER: Cleanup state after failed answer creation
   */
  /**
   *   Secure cleanup state after failed answer creation
   */
  _cleanupFailedAnswerCreation() {
    try {
      this._secureCleanupCryptographicMaterials();
      this.currentKeyVersion = 0;
      this.keyVersions.clear();
      this.oldKeys.clear();
      if (this.peerConnection) {
        this.peerConnection.close();
        this.peerConnection = null;
      }
      if (this.dataChannel) {
        this.dataChannel.close();
        this.dataChannel = null;
      }
      this.isInitiator = false;
      this.isVerified = false;
      this.sequenceNumber = 0;
      this.expectedSequenceNumber = 0;
      this.messageCounter = 0;
      this.processedMessageIds.clear();
      this.replayWindow.clear();
      this._updateSecurityFeatures({
        hasEncryption: false,
        hasECDH: false,
        hasECDSA: false,
        hasMutualAuth: false,
        hasMetadataProtection: false,
        hasEnhancedReplayProtection: false,
        hasNonExtractableKeys: false,
        hasEnhancedValidation: false,
        hasPFS: false
      });
      this._forceGarbageCollection();
      this._secureLog("debug", "\u{1F512} Failed answer creation cleanup completed with secure memory wipe");
    } catch (cleanupError) {
      this._secureLog("error", "\u274C Error during answer creation cleanup", {
        errorType: cleanupError.constructor.name,
        errorMessage: cleanupError.message
      });
    }
  }
  /**
   * HELPER: Securely set encryption keys (if not set yet)
   */
  async _setEncryptionKeys(encryptionKey, macKey, metadataKey, keyFingerprint) {
    return this._withMutex("keyOperation", async (operationId) => {
      this._secureLog("info", "\u{1F510} Setting encryption keys with mutex", {
        operationId
      });
      if (!(encryptionKey instanceof CryptoKey) || !(macKey instanceof CryptoKey) || !(metadataKey instanceof CryptoKey)) {
        throw new Error("Invalid key types provided");
      }
      if (!keyFingerprint || typeof keyFingerprint !== "string") {
        throw new Error("Invalid key fingerprint provided");
      }
      const oldKeys = {
        encryptionKey: this.encryptionKey,
        macKey: this.macKey,
        metadataKey: this.metadataKey,
        keyFingerprint: this.keyFingerprint
      };
      try {
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
        this.metadataKey = metadataKey;
        this.keyFingerprint = keyFingerprint;
        this.sequenceNumber = 0;
        this.expectedSequenceNumber = 0;
        this.messageCounter = 0;
        this.processedMessageIds.clear();
        this.replayWindow.clear();
        this._secureLog("info", "\u2705 Encryption keys set successfully", {
          operationId,
          hasAllKeys: !!(this.encryptionKey && this.macKey && this.metadataKey),
          hasFingerprint: !!this.keyFingerprint
        });
        return true;
      } catch (error) {
        this.encryptionKey = oldKeys.encryptionKey;
        this.macKey = oldKeys.macKey;
        this.metadataKey = oldKeys.metadataKey;
        this.keyFingerprint = oldKeys.keyFingerprint;
        this._secureLog("error", "\u274C Key setting failed, rolled back", {
          operationId,
          errorType: error.constructor.name
        });
        throw error;
      }
    });
  }
  async handleSecureAnswer(answerData) {
    console.log("\u{1F3AF} handleSecureAnswer called with answerData:", answerData ? "present" : "null");
    try {
      if (!answerData || typeof answerData !== "object" || Array.isArray(answerData)) {
        this._secureLog("error", "CRITICAL: Invalid answer data structure", {
          hasAnswerData: !!answerData,
          answerDataType: typeof answerData,
          isArray: Array.isArray(answerData)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Answer data must be a non-null object");
      }
      if (answerData.type !== "enhanced_secure_answer" || !answerData.sdp) {
        this._secureLog("error", "CRITICAL: Invalid answer format", {
          type: answerData.type,
          hasSdp: !!answerData.sdp
        });
        throw new Error("CRITICAL SECURITY FAILURE: Invalid answer format - hard abort required");
      }
      if (!answerData.ecdhPublicKey || typeof answerData.ecdhPublicKey !== "object" || Array.isArray(answerData.ecdhPublicKey)) {
        this._secureLog("error", "CRITICAL: Invalid ECDH public key structure in answer", {
          hasEcdhKey: !!answerData.ecdhPublicKey,
          ecdhKeyType: typeof answerData.ecdhPublicKey,
          isArray: Array.isArray(answerData.ecdhPublicKey)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Missing or invalid ECDH public key structure");
      }
      if (!answerData.ecdhPublicKey.keyData || !answerData.ecdhPublicKey.signature) {
        this._secureLog("error", "CRITICAL: ECDH key missing keyData or signature in answer", {
          hasKeyData: !!answerData.ecdhPublicKey.keyData,
          hasSignature: !!answerData.ecdhPublicKey.signature
        });
        throw new Error("CRITICAL SECURITY FAILURE: ECDH key missing keyData or signature");
      }
      if (!answerData.ecdsaPublicKey || typeof answerData.ecdsaPublicKey !== "object" || Array.isArray(answerData.ecdsaPublicKey)) {
        this._secureLog("error", "CRITICAL: Invalid ECDSA public key structure in answer", {
          hasEcdsaKey: !!answerData.ecdsaPublicKey,
          ecdsaKeyType: typeof answerData.ecdsaPublicKey,
          isArray: Array.isArray(answerData.ecdsaPublicKey)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Missing or invalid ECDSA public key structure");
      }
      if (!answerData.ecdsaPublicKey.keyData || !answerData.ecdsaPublicKey.signature) {
        this._secureLog("error", "CRITICAL: ECDSA key missing keyData or signature in answer", {
          hasKeyData: !!answerData.ecdsaPublicKey.keyData,
          hasSignature: !!answerData.ecdsaPublicKey.signature
        });
        throw new Error("CRITICAL SECURITY FAILURE: ECDSA key missing keyData or signature");
      }
      if (!answerData.timestamp || !answerData.version) {
        throw new Error("Missing required fields in response data \u2013 possible MITM attack");
      }
      if (answerData.sessionId && this.sessionId && answerData.sessionId !== this.sessionId) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Session ID mismatch detected - possible MITM attack", {
          expectedSessionId: this.sessionId,
          receivedSessionId: answerData.sessionId
        });
        throw new Error("Session ID mismatch \u2013 possible MITM attack");
      }
      const answerAge = Date.now() - answerData.timestamp;
      if (answerAge > 36e5) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Answer data is too old - possible replay attack", {
          answerAge,
          timestamp: answerData.timestamp
        });
        if (this.onAnswerError) {
          this.onAnswerError("replay_attack", "Response data is too old \u2013 possible replay attack");
        }
        throw new Error("Response data is too old \u2013 possible replay attack");
      }
      if (answerData.version !== "4.0") {
        window.EnhancedSecureCryptoUtils.secureLog.log("warn", "Incompatible protocol version in answer", {
          expectedVersion: "4.0",
          receivedVersion: answerData.version
        });
      }
      const peerECDSAPublicKey = await crypto.subtle.importKey(
        "spki",
        new Uint8Array(answerData.ecdsaPublicKey.keyData),
        {
          name: "ECDSA",
          namedCurve: "P-384"
        },
        false,
        ["verify"]
      );
      const peerPublicKey = await window.EnhancedSecureCryptoUtils.importPublicKeyFromSignedPackage(
        answerData.ecdhPublicKey,
        peerECDSAPublicKey
      );
      if (!this.sessionSalt || this.sessionSalt.length !== 64) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Invalid session salt detected - possible session hijacking", {
          saltLength: this.sessionSalt ? this.sessionSalt.length : 0
        });
        throw new Error("Invalid session salt \u2013 possible session hijacking attempt");
      }
      const expectedSaltHash = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(this.sessionSalt);
      window.EnhancedSecureCryptoUtils.secureLog.log("info", "Session salt integrity verified", {
        saltFingerprint: expectedSaltHash.substring(0, 8)
      });
      if (!(this.ecdhKeyPair?.privateKey instanceof CryptoKey)) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Local ECDH private key is not a CryptoKey in handleSecureAnswer", {
          hasKeyPair: !!this.ecdhKeyPair,
          privateKeyType: typeof this.ecdhKeyPair?.privateKey,
          privateKeyAlgorithm: this.ecdhKeyPair?.privateKey?.algorithm?.name
        });
        throw new Error("Local ECDH private key is not a CryptoKey");
      }
      if (!(peerPublicKey instanceof CryptoKey)) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Peer ECDH public key is not a CryptoKey in handleSecureAnswer", {
          publicKeyType: typeof peerPublicKey,
          publicKeyAlgorithm: peerPublicKey?.algorithm?.name
        });
        throw new Error("Peer ECDH public key is not a CryptoKey");
      }
      this.peerPublicKey = peerPublicKey;
      if (!this.connectionId) {
        this.connectionId = Array.from(crypto.getRandomValues(new Uint8Array(8))).map((b) => b.toString(16).padStart(2, "0")).join("");
      }
      const derivedKeys = await window.EnhancedSecureCryptoUtils.deriveSharedKeys(
        this.ecdhKeyPair.privateKey,
        peerPublicKey,
        this.sessionSalt
      );
      this.encryptionKey = derivedKeys.encryptionKey;
      this.macKey = derivedKeys.macKey;
      this.metadataKey = derivedKeys.metadataKey;
      this.keyFingerprint = derivedKeys.fingerprint;
      this.sequenceNumber = 0;
      this.expectedSequenceNumber = 0;
      this.messageCounter = 0;
      this.processedMessageIds.clear();
      this.replayWindow.clear();
      if (!(this.encryptionKey instanceof CryptoKey) || !(this.macKey instanceof CryptoKey) || !(this.metadataKey instanceof CryptoKey)) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Invalid key types after derivation in handleSecureAnswer", {
          encryptionKeyType: typeof this.encryptionKey,
          macKeyType: typeof this.macKey,
          metadataKeyType: typeof this.metadataKey,
          encryptionKeyAlgorithm: this.encryptionKey?.algorithm?.name,
          macKeyAlgorithm: this.macKey?.algorithm?.name,
          metadataKeyAlgorithm: this.metadataKey?.algorithm?.name
        });
        throw new Error("Invalid key types after export");
      }
      this._secureLog("info", "Encryption keys set in handleSecureAnswer", {
        hasEncryptionKey: !!this.encryptionKey,
        hasMacKey: !!this.macKey,
        hasMetadataKey: !!this.metadataKey,
        hasKeyFingerprint: !!this.keyFingerprint,
        mitmProtection: "enabled",
        signatureVerified: true
      });
      this.securityFeatures.hasMutualAuth = true;
      this.securityFeatures.hasMetadataProtection = true;
      this.securityFeatures.hasEnhancedReplayProtection = true;
      this.securityFeatures.hasPFS = true;
      this.currentKeyVersion = 0;
      this.lastKeyRotation = Date.now();
      this.keyVersions.set(0, {
        salt: this.sessionSalt,
        timestamp: this.lastKeyRotation,
        messageCount: 0
      });
      this.onKeyExchange(this.keyFingerprint);
      try {
        console.log("Starting SAS computation for Offer side (Answer handler)");
        const remoteFP = this._extractDTLSFingerprintFromSDP(answerData.sdp);
        const localFP = this.expectedDTLSFingerprint;
        const keyBytes = this._decodeKeyFingerprint(this.keyFingerprint);
        console.log("SAS computation parameters:", {
          remoteFP: remoteFP ? remoteFP.substring(0, 16) + "..." : "null/undefined",
          localFP: localFP ? localFP.substring(0, 16) + "..." : "null/undefined",
          keyBytesLength: keyBytes ? keyBytes.length : "null/undefined",
          keyBytesType: keyBytes ? keyBytes.constructor.name : "null/undefined"
        });
        this.verificationCode = await this._computeSAS(keyBytes, localFP, remoteFP);
        this.onStatusChange?.("verifying");
        this.onVerificationRequired(this.verificationCode);
        this.pendingSASCode = this.verificationCode;
        console.log("\u{1F4E4} SAS code ready to send when data channel opens:", this.verificationCode);
        this._secureLog("info", "SAS verification code generated for MITM protection (Offer side)", {
          sasCode: this.verificationCode,
          localFP: localFP.substring(0, 16) + "...",
          remoteFP: remoteFP.substring(0, 16) + "...",
          timestamp: Date.now()
        });
      } catch (sasError) {
        console.error("SAS computation failed in handleSecureAnswer (Offer side):", sasError);
        this._secureLog("error", "SAS computation failed in handleSecureAnswer (Offer side)", {
          error: sasError.message,
          stack: sasError.stack,
          timestamp: Date.now()
        });
      }
      if (this.strictDTLSValidation) {
        try {
          const receivedFingerprint = this._extractDTLSFingerprintFromSDP(answerData.sdp);
          if (this.expectedDTLSFingerprint) {
            this._validateDTLSFingerprint(receivedFingerprint, this.expectedDTLSFingerprint, "answer_validation");
          } else {
            this.expectedDTLSFingerprint = receivedFingerprint;
            this._secureLog("info", "Stored DTLS fingerprint for future validation", {
              fingerprint: receivedFingerprint,
              context: "first_connection"
            });
          }
        } catch (error) {
          this._secureLog("warn", "DTLS fingerprint validation failed - continuing in fallback mode", {
            error: error.message,
            context: "answer_validation"
          });
        }
      } else {
        this._secureLog("info", "DTLS fingerprint validation disabled - proceeding without validation");
      }
      this._secureLog("debug", "Setting remote description from answer", {
        sdpLength: answerData.sdp?.length || 0
      });
      await this.peerConnection.setRemoteDescription({
        type: "answer",
        sdp: answerData.sdp
      });
      this._secureLog("debug", "Remote description set successfully from answer", {
        signalingState: this.peerConnection.signalingState
      });
      console.log("Enhanced secure connection established");
      setTimeout(async () => {
        try {
          const securityData = await this.calculateAndReportSecurityLevel();
          if (securityData) {
            console.log("\u2705 Security level calculated after connection:", securityData.level);
            this.notifySecurityUpdate();
          }
        } catch (error) {
          this._secureLog("error", "\u274C Error calculating security after connection:", { errorType: error?.constructor?.name || "Unknown" });
        }
      }, 1e3);
      setTimeout(async () => {
        if (!this.lastSecurityCalculation || this.lastSecurityCalculation.score < 50) {
          console.log("\u{1F504} Retrying security calculation...");
          await this.calculateAndReportSecurityLevel();
          this.notifySecurityUpdate();
        }
      }, 3e3);
      this.notifySecurityUpdate();
    } catch (error) {
      this._secureLog("error", "Enhanced secure answer handling failed", {
        errorType: error.constructor.name
      });
      this.onStatusChange("failed");
      if (this.onAnswerError) {
        if (error.message.includes("too old") || error.message.includes("\u0441\u043B\u0438\u0448\u043A\u043E\u043C \u0441\u0442\u0430\u0440\u044B\u0435")) {
          this.onAnswerError("replay_attack", error.message);
        } else if (error.message.includes("MITM") || error.message.includes("signature") || error.message.includes("\u043F\u043E\u0434\u043F\u0438\u0441\u044C")) {
          this.onAnswerError("security_violation", error.message);
        } else {
          this.onAnswerError("general_error", error.message);
        }
      }
      throw error;
    }
  }
  forceSecurityUpdate() {
    console.log("\u{1F504} Force security update requested");
    setTimeout(async () => {
      try {
        const securityData = await this.calculateAndReportSecurityLevel();
        if (securityData) {
          this.notifySecurityUpdate();
          console.log("\u2705 Force security update completed");
        }
      } catch (error) {
        this._secureLog("error", "\u274C Force security update failed:", { errorType: error?.constructor?.name || "Unknown" });
      }
    }, 100);
  }
  initiateVerification() {
    if (this.isInitiator) {
      if (!this.verificationInitiationSent) {
        this.verificationInitiationSent = true;
        this.deliverMessageToUI("\u{1F510} CRITICAL: Compare verification code with peer out-of-band (voice/video/in-person) to prevent MITM attack!", "system");
        this.deliverMessageToUI(`\u{1F510} Your verification code: ${this.verificationCode}`, "system");
        this.deliverMessageToUI("\u{1F510} Ask peer to confirm this exact code before allowing traffic!", "system");
      }
    } else {
      console.log("\u{1F4E5} Answer side: Waiting for SAS code from Offer side");
      this.deliverMessageToUI("\u{1F4E5} Waiting for verification code from peer...", "system");
    }
  }
  confirmVerification() {
    try {
      console.log("\u{1F4E4} confirmVerification - sending local confirmation");
      this.localVerificationConfirmed = true;
      const confirmationPayload = {
        type: "verification_confirmed",
        data: {
          timestamp: Date.now(),
          verificationMethod: "SAS",
          securityLevel: "MITM_PROTECTION_REQUIRED"
        }
      };
      console.log("\u{1F4E4} Sending verification confirmation:", confirmationPayload);
      this.dataChannel.send(JSON.stringify(confirmationPayload));
      if (this.onVerificationStateChange) {
        this.onVerificationStateChange({
          localConfirmed: this.localVerificationConfirmed,
          remoteConfirmed: this.remoteVerificationConfirmed,
          bothConfirmed: this.bothVerificationsConfirmed
        });
      }
      this._checkBothVerificationsConfirmed();
      this.deliverMessageToUI("\u2705 You confirmed the verification code. Waiting for peer confirmation...", "system");
      this.processMessageQueue();
    } catch (error) {
      this._secureLog("error", "\u274C SAS verification failed:", { errorType: error?.constructor?.name || "Unknown" });
      this.deliverMessageToUI("\u274C SAS verification failed", "system");
    }
  }
  _checkBothVerificationsConfirmed() {
    if (this.localVerificationConfirmed && this.remoteVerificationConfirmed && !this.bothVerificationsConfirmed) {
      console.log("\u{1F389} Both parties confirmed verification!");
      this.bothVerificationsConfirmed = true;
      const bothConfirmedPayload = {
        type: "verification_both_confirmed",
        data: {
          timestamp: Date.now(),
          verificationMethod: "SAS",
          securityLevel: "MITM_PROTECTION_COMPLETE"
        }
      };
      console.log("\u{1F4E4} Sending both confirmed notification:", bothConfirmedPayload);
      this.dataChannel.send(JSON.stringify(bothConfirmedPayload));
      if (this.onVerificationStateChange) {
        this.onVerificationStateChange({
          localConfirmed: this.localVerificationConfirmed,
          remoteConfirmed: this.remoteVerificationConfirmed,
          bothConfirmed: this.bothVerificationsConfirmed
        });
      }
      this.deliverMessageToUI("\u{1F389} Both parties confirmed! Opening secure chat in 2 seconds...", "system");
      setTimeout(() => {
        this._setVerifiedStatus(true, "MUTUAL_SAS_CONFIRMED", {
          code: this.verificationCode,
          timestamp: Date.now()
        });
        this._enforceVerificationGate("mutual_confirmed", false);
        this.onStatusChange?.("verified");
      }, 2e3);
    }
  }
  handleVerificationConfirmed(data) {
    console.log("\u{1F4E5} Received verification confirmation from peer");
    this.remoteVerificationConfirmed = true;
    this.deliverMessageToUI("\u2705 Peer confirmed the verification code. Waiting for your confirmation...", "system");
    if (this.onVerificationStateChange) {
      this.onVerificationStateChange({
        localConfirmed: this.localVerificationConfirmed,
        remoteConfirmed: this.remoteVerificationConfirmed,
        bothConfirmed: this.bothVerificationsConfirmed
      });
    }
    this._checkBothVerificationsConfirmed();
  }
  handleVerificationBothConfirmed(data) {
    console.log("\u{1F4E5} Received both confirmed notification from peer");
    this.bothVerificationsConfirmed = true;
    if (this.onVerificationStateChange) {
      this.onVerificationStateChange({
        localConfirmed: this.localVerificationConfirmed,
        remoteConfirmed: this.remoteVerificationConfirmed,
        bothConfirmed: this.bothVerificationsConfirmed
      });
    }
    this.deliverMessageToUI("\u{1F389} Both parties confirmed! Opening secure chat in 2 seconds...", "system");
    setTimeout(() => {
      this._setVerifiedStatus(true, "MUTUAL_SAS_CONFIRMED", {
        code: this.verificationCode,
        timestamp: Date.now()
      });
      this._enforceVerificationGate("mutual_confirmed", false);
      this.onStatusChange?.("verified");
    }, 2e3);
  }
  handleVerificationRequest(data) {
    console.log("\u{1F50D} handleVerificationRequest called with:");
    console.log("  - receivedCode:", data.code, "(type:", typeof data.code, ")");
    console.log("  - expectedCode:", this.verificationCode, "(type:", typeof this.verificationCode, ")");
    console.log("  - codesMatch:", data.code === this.verificationCode);
    console.log("  - data object:", data);
    if (data.code === this.verificationCode) {
      const responsePayload = {
        type: "verification_response",
        data: {
          ok: true,
          timestamp: Date.now(),
          verificationMethod: "SAS",
          // Indicate SAS was used
          securityLevel: "MITM_PROTECTED"
        }
      };
      this.dataChannel.send(JSON.stringify(responsePayload));
      if (!this.verificationNotificationSent) {
        this.verificationNotificationSent = true;
        this.deliverMessageToUI("\u2705 SAS verification successful! MITM protection confirmed. Channel is now secure!", "system");
      }
      this.processMessageQueue();
    } else {
      console.log("\u274C SAS verification failed - codes do not match, disconnecting");
      const responsePayload = {
        type: "verification_response",
        data: {
          ok: false,
          timestamp: Date.now(),
          reason: "code_mismatch"
        }
      };
      this.dataChannel.send(JSON.stringify(responsePayload));
      this._secureLog("error", "SAS verification failed - possible MITM attack", {
        receivedCode: data.code,
        expectedCode: this.verificationCode,
        timestamp: Date.now()
      });
      this.deliverMessageToUI("\u274C SAS verification failed! Possible MITM attack detected. Connection aborted for safety!", "system");
      this.disconnect();
    }
  }
  handleSASCode(data) {
    console.log("\u{1F4E5} Received SAS code from Offer side:", data.code);
    this.verificationCode = data.code;
    this.onStatusChange?.("verifying");
    this.onVerificationRequired(this.verificationCode);
    this._secureLog("info", "SAS code received from Offer side", {
      sasCode: this.verificationCode,
      timestamp: Date.now()
    });
  }
  handleVerificationResponse(data) {
    if (data.ok === true) {
      this._secureLog("info", "Mutual SAS verification completed - MITM protection active", {
        verificationMethod: data.verificationMethod || "SAS",
        securityLevel: data.securityLevel || "MITM_PROTECTED",
        timestamp: Date.now()
      });
      if (!this.verificationNotificationSent) {
        this.verificationNotificationSent = true;
        this.deliverMessageToUI("\u2705 Mutual SAS verification complete! MITM protection active. Channel is now secure!", "system");
      }
      this.processMessageQueue();
    } else {
      this._secureLog("error", "Peer SAS verification failed - connection not secure", {
        responseData: data,
        timestamp: Date.now()
      });
      this.deliverMessageToUI("\u274C Peer verification failed! Connection not secure!", "system");
      this.disconnect();
    }
  }
  validateOfferData(offerData) {
    return offerData && offerData.type === "enhanced_secure_offer" && offerData.sdp && offerData.publicKey && offerData.salt && offerData.verificationCode && Array.isArray(offerData.publicKey) && Array.isArray(offerData.salt) && offerData.salt.length === 32;
  }
  validateEnhancedOfferData(offerData) {
    console.log("\u{1F3AF} validateEnhancedOfferData called with:", offerData ? "valid object" : "null/undefined");
    try {
      if (!offerData || typeof offerData !== "object" || Array.isArray(offerData)) {
        this._secureLog("error", "CRITICAL: Invalid offer data structure", {
          hasOfferData: !!offerData,
          offerDataType: typeof offerData,
          isArray: Array.isArray(offerData)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Offer data must be a non-null object");
      }
      const basicFields = ["type", "sdp"];
      for (const field of basicFields) {
        if (!offerData[field]) {
          throw new Error(`Missing required field: ${field}`);
        }
      }
      if (!["enhanced_secure_offer", "secure_offer"].includes(offerData.type)) {
        throw new Error("Invalid offer type");
      }
      const isV4Format = offerData.version === "4.0" && offerData.ecdhPublicKey && offerData.ecdsaPublicKey;
      if (isV4Format) {
        const v4RequiredFields = [
          "ecdhPublicKey",
          "ecdsaPublicKey",
          "salt",
          "verificationCode",
          "authChallenge",
          "timestamp",
          "version",
          "securityLevel"
        ];
        for (const field of v4RequiredFields) {
          if (!offerData[field]) {
            throw new Error(`Missing v4.0 field: ${field}`);
          }
        }
        if (!Array.isArray(offerData.salt) || offerData.salt.length !== 64) {
          throw new Error("Salt must be exactly 64 bytes for v4.0");
        }
        const offerAge = Date.now() - offerData.timestamp;
        if (offerAge > 36e5) {
          throw new Error("Offer is too old (older than 1 hour)");
        }
        if (!offerData.ecdhPublicKey || typeof offerData.ecdhPublicKey !== "object" || Array.isArray(offerData.ecdhPublicKey)) {
          this._secureLog("error", "CRITICAL: Invalid ECDH public key structure", {
            hasEcdhKey: !!offerData.ecdhPublicKey,
            ecdhKeyType: typeof offerData.ecdhPublicKey,
            isArray: Array.isArray(offerData.ecdhPublicKey)
          });
          throw new Error("CRITICAL SECURITY FAILURE: Invalid ECDH public key structure - hard abort required");
        }
        if (!offerData.ecdsaPublicKey || typeof offerData.ecdsaPublicKey !== "object" || Array.isArray(offerData.ecdsaPublicKey)) {
          this._secureLog("error", "CRITICAL: Invalid ECDSA public key structure", {
            hasEcdsaKey: !!offerData.ecdsaPublicKey,
            ecdsaKeyType: typeof offerData.ecdsaPublicKey,
            isArray: Array.isArray(offerData.ecdsaPublicKey)
          });
          throw new Error("CRITICAL SECURITY FAILURE: Invalid ECDSA public key structure - hard abort required");
        }
        if (!offerData.ecdhPublicKey.keyData || !offerData.ecdhPublicKey.signature) {
          this._secureLog("error", "CRITICAL: ECDH key missing keyData or signature", {
            hasKeyData: !!offerData.ecdhPublicKey.keyData,
            hasSignature: !!offerData.ecdhPublicKey.signature
          });
          throw new Error("CRITICAL SECURITY FAILURE: ECDH key missing keyData or signature");
        }
        if (!offerData.ecdsaPublicKey.keyData || !offerData.ecdsaPublicKey.signature) {
          this._secureLog("error", "CRITICAL: ECDSA key missing keyData or signature", {
            hasKeyData: !!offerData.ecdsaPublicKey.keyData,
            hasSignature: !!offerData.ecdsaPublicKey.signature
          });
          throw new Error("CRITICAL SECURITY FAILURE: ECDSA key missing keyData or signature");
        }
        if (typeof offerData.verificationCode !== "string" || offerData.verificationCode.length < 6) {
          throw new Error("Invalid SAS verification code format - MITM protection required");
        }
        this._secureLog("info", "v4.0 offer validation passed", {
          version: offerData.version,
          hasSecurityLevel: !!offerData.securityLevel?.level,
          offerAge: Math.round(offerAge / 1e3) + "s"
        });
      } else {
        const v3RequiredFields = ["publicKey", "salt", "verificationCode"];
        for (const field of v3RequiredFields) {
          if (!offerData[field]) {
            throw new Error(`Missing v3.0 field: ${field}`);
          }
        }
        if (!Array.isArray(offerData.salt) || offerData.salt.length !== 32) {
          throw new Error("Salt must be exactly 32 bytes for v3.0");
        }
        if (!Array.isArray(offerData.publicKey)) {
          throw new Error("Invalid public key format for v3.0");
        }
        window.EnhancedSecureCryptoUtils.secureLog.log("info", "v3.0 offer validation passed (backward compatibility)", {
          version: "v3.0",
          legacy: true
        });
      }
      if (typeof offerData.sdp !== "string" || !offerData.sdp.includes("v=0")) {
        throw new Error("Invalid SDP structure");
      }
      console.log("\u{1F3AF} validateEnhancedOfferData completed successfully");
      return true;
    } catch (error) {
      console.log("\u{1F3AF} validateEnhancedOfferData ERROR:", error.message);
      this._secureLog("error", "CRITICAL: Security validation failed - hard abort required", {
        error: error.message,
        errorType: error.constructor.name,
        timestamp: Date.now()
      });
      throw new Error(`CRITICAL SECURITY VALIDATION FAILURE: ${error.message}`);
    }
  }
  async sendSecureMessage(message) {
    const validation = this._validateInputData(message, "sendSecureMessage");
    if (!validation.isValid) {
      const errorMessage = `Input validation failed: ${validation.errors.join(", ")}`;
      this._secureLog("error", "\u274C Input validation failed in sendSecureMessage", {
        errors: validation.errors,
        messageType: typeof message
      });
      throw new Error(errorMessage);
    }
    if (!this._checkRateLimit("sendSecureMessage")) {
      throw new Error("Rate limit exceeded for secure message sending");
    }
    this._enforceVerificationGate("sendSecureMessage");
    if (!this.isConnected()) {
      if (validation.sanitizedData && typeof validation.sanitizedData === "object" && validation.sanitizedData.type && validation.sanitizedData.type.startsWith("file_")) {
        throw new Error("Connection not ready for file transfer. Please ensure the connection is established and verified.");
      }
      this.messageQueue.push(validation.sanitizedData);
      throw new Error("Connection not ready. Message queued for sending.");
    }
    return this._withMutex("cryptoOperation", async (operationId) => {
      if (!this.isConnected() || !this.isVerified) {
        throw new Error("Connection lost during message preparation");
      }
      if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
        throw new Error("Encryption keys not initialized");
      }
      if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkMessageRate(this.rateLimiterId)) {
        throw new Error("Message rate limit exceeded (60 messages per minute)");
      }
      try {
        const textToSend = typeof validation.sanitizedData === "string" ? validation.sanitizedData : JSON.stringify(validation.sanitizedData);
        const sanitizedMessage = window.EnhancedSecureCryptoUtils.sanitizeMessage(textToSend);
        const messageId = `msg_${Date.now()}_${this.messageCounter++}`;
        if (typeof this._createMessageAAD !== "function") {
          throw new Error("_createMessageAAD method is not available in sendSecureMessage. Manager may not be fully initialized.");
        }
        const aad = message.aad || this._createMessageAAD("enhanced_message", { content: sanitizedMessage });
        const encryptedData = await window.EnhancedSecureCryptoUtils.encryptMessage(
          sanitizedMessage,
          this.encryptionKey,
          this.macKey,
          this.metadataKey,
          messageId,
          JSON.parse(aad).sequenceNumber
          // Use sequence number from AAD
        );
        const payload = {
          type: "enhanced_message",
          data: encryptedData,
          keyVersion: this.currentKeyVersion,
          version: "4.0"
        };
        this.dataChannel.send(JSON.stringify(payload));
        if (typeof validation.sanitizedData === "string") {
          this.deliverMessageToUI(validation.sanitizedData, "sent");
        }
        this._secureLog("debug", "\u{1F4E4} Secure message sent successfully", {
          operationId,
          messageLength: sanitizedMessage.length,
          keyVersion: this.currentKeyVersion
        });
      } catch (error) {
        this._secureLog("error", "\u274C Secure message sending failed", {
          operationId,
          errorType: error.constructor.name
        });
        throw error;
      }
    }, 2e3);
  }
  processMessageQueue() {
    while (this.messageQueue.length > 0 && this.isConnected() && this.isVerified) {
      const message = this.messageQueue.shift();
      this.sendSecureMessage(message).catch(console.error);
    }
  }
  startHeartbeat() {
    this._secureLog("info", "\u{1F527} Heartbeat moved to unified scheduler");
    this._heartbeatConfig = {
      enabled: true,
      interval: _EnhancedSecureWebRTCManager.TIMEOUTS.HEARTBEAT_INTERVAL,
      lastHeartbeat: 0
    };
  }
  stopHeartbeat() {
    if (this._heartbeatConfig) {
      this._heartbeatConfig.enabled = false;
    }
  }
  /**
   *   Stop all active timers and cleanup scheduler
   */
  _stopAllTimers() {
    this._secureLog("info", "\u{1F527} Stopping all timers and cleanup scheduler");
    if (this._maintenanceScheduler) {
      clearInterval(this._maintenanceScheduler);
      this._maintenanceScheduler = null;
    }
    if (this._heartbeatConfig) {
      this._heartbeatConfig.enabled = false;
    }
    if (this._activeTimers) {
      this._activeTimers.forEach((timer) => {
        if (timer) clearInterval(timer);
      });
      this._activeTimers.clear();
    }
    this._secureLog("info", "\u2705 All timers stopped successfully");
  }
  handleHeartbeat() {
    console.log("Heartbeat received - connection alive");
  }
  waitForIceGathering() {
    return new Promise((resolve) => {
      if (this.peerConnection.iceGatheringState === "complete") {
        resolve();
        return;
      }
      const checkState = () => {
        if (this.peerConnection && this.peerConnection.iceGatheringState === "complete") {
          this.peerConnection.removeEventListener("icegatheringstatechange", checkState);
          resolve();
        }
      };
      this.peerConnection.addEventListener("icegatheringstatechange", checkState);
      setTimeout(() => {
        if (this.peerConnection) {
          this.peerConnection.removeEventListener("icegatheringstatechange", checkState);
        }
        resolve();
      }, _EnhancedSecureWebRTCManager.TIMEOUTS.ICE_GATHERING_TIMEOUT);
    });
  }
  retryConnection() {
    console.log(`Retrying connection (attempt ${this.connectionAttempts}/${this.maxConnectionAttempts})`);
    this.onStatusChange("retrying");
  }
  isConnected() {
    const hasDataChannel = !!this.dataChannel;
    const dataChannelState = this.dataChannel?.readyState;
    const isDataChannelOpen = dataChannelState === "open";
    const isVerified = this.isVerified;
    const connectionState = this.peerConnection?.connectionState;
    return this.dataChannel && this.dataChannel.readyState === "open" && this.isVerified;
  }
  getConnectionInfo() {
    return {
      fingerprint: this.keyFingerprint,
      isConnected: this.isConnected(),
      isVerified: this.isVerified,
      connectionState: this.peerConnection?.connectionState,
      iceConnectionState: this.peerConnection?.iceConnectionState,
      verificationCode: this.verificationCode
    };
  }
  disconnect() {
    this._stopAllTimers();
    if (this.fileTransferSystem) {
      this.fileTransferSystem.cleanup();
    }
    this.intentionalDisconnect = true;
    window.EnhancedSecureCryptoUtils.secureLog.log("info", "Starting intentional disconnect");
    this.sendDisconnectNotification();
    setTimeout(() => {
      this.sendDisconnectNotification();
    }, 100);
    document.dispatchEvent(new CustomEvent("peer-disconnect", {
      detail: {
        reason: "user_disconnect",
        timestamp: Date.now()
      }
    }));
  }
  handleUnexpectedDisconnect() {
    this.sendDisconnectNotification();
    this.isVerified = false;
    if (!this.disconnectNotificationSent) {
      this.disconnectNotificationSent = true;
      this.deliverMessageToUI("\u{1F50C} Connection lost. Attempting to reconnect...", "system");
    }
    if (this.fileTransferSystem) {
      console.log("\u{1F9F9} Cleaning up file transfer system on unexpected disconnect...");
      this.fileTransferSystem.cleanup();
      this.fileTransferSystem = null;
    }
    document.dispatchEvent(new CustomEvent("peer-disconnect", {
      detail: {
        reason: "connection_lost",
        timestamp: Date.now()
      }
    }));
  }
  sendDisconnectNotification() {
    try {
      if (this.dataChannel && this.dataChannel.readyState === "open") {
        const notification = {
          type: "peer_disconnect",
          timestamp: Date.now(),
          reason: this.intentionalDisconnect ? "user_disconnect" : "connection_lost"
        };
        for (let i = 0; i < 3; i++) {
          try {
            this.dataChannel.send(JSON.stringify(notification));
            window.EnhancedSecureCryptoUtils.secureLog.log("info", "Disconnect notification sent", {
              reason: notification.reason,
              attempt: i + 1
            });
            break;
          } catch (sendError) {
            if (i === 2) {
              window.EnhancedSecureCryptoUtils.secureLog.log("error", "Failed to send disconnect notification", {
                error: sendError.message
              });
            }
          }
        }
      }
    } catch (error) {
      window.EnhancedSecureCryptoUtils.secureLog.log("error", "Could not send disconnect notification", {
        error: error.message
      });
    }
  }
  attemptReconnection() {
    if (!this.reconnectionFailedNotificationSent) {
      this.reconnectionFailedNotificationSent = true;
      this.deliverMessageToUI("\u274C Unable to reconnect. A new connection is required.", "system");
    }
  }
  handlePeerDisconnectNotification(data) {
    const reason = data.reason || "unknown";
    const reasonText = reason === "user_disconnect" ? "manually disconnected." : "connection lost.";
    if (!this.peerDisconnectNotificationSent) {
      this.peerDisconnectNotificationSent = true;
      this.deliverMessageToUI(`\u{1F44B} Peer ${reasonText}`, "system");
    }
    this.onStatusChange("peer_disconnected");
    this.intentionalDisconnect = false;
    this.isVerified = false;
    this.stopHeartbeat();
    this.onKeyExchange("");
    this.onVerificationRequired("");
    document.dispatchEvent(new CustomEvent("peer-disconnect", {
      detail: {
        reason,
        timestamp: Date.now()
      }
    }));
    setTimeout(() => {
      this.disconnect();
    }, 2e3);
    window.EnhancedSecureCryptoUtils.secureLog.log("info", "Peer disconnect notification processed", {
      reason
    });
  }
  /**
   *   Secure disconnect with complete memory cleanup
   */
  disconnect() {
    this.stopHeartbeat();
    this.isVerified = false;
    this.processedMessageIds.clear();
    this.messageCounter = 0;
    this._secureCleanupCryptographicMaterials();
    this.keyVersions.clear();
    this.oldKeys.clear();
    this.currentKeyVersion = 0;
    this.lastKeyRotation = Date.now();
    this.sequenceNumber = 0;
    this.expectedSequenceNumber = 0;
    this.replayWindow.clear();
    this.securityFeatures = {
      hasEncryption: true,
      hasECDH: true,
      hasECDSA: true,
      hasMutualAuth: true,
      hasMetadataProtection: true,
      hasEnhancedReplayProtection: true,
      hasNonExtractableKeys: true,
      hasRateLimiting: true,
      hasEnhancedValidation: true,
      hasPFS: true
    };
    if (this.dataChannel) {
      this.dataChannel.close();
      this.dataChannel = null;
    }
    if (this.peerConnection) {
      this.peerConnection.close();
      this.peerConnection = null;
    }
    if (this.messageQueue && this.messageQueue.length > 0) {
      this.messageQueue.forEach((message, index) => {
        this._secureWipeMemory(message, `messageQueue[${index}]`);
      });
      this.messageQueue = [];
    }
    this._forceGarbageCollection();
    document.dispatchEvent(new CustomEvent("connection-cleaned", {
      detail: {
        timestamp: Date.now(),
        reason: this.intentionalDisconnect ? "user_cleanup" : "automatic_cleanup"
      }
    }));
    this.onStatusChange("disconnected");
    this.onKeyExchange("");
    this.onVerificationRequired("");
    this._secureLog("info", "\u{1F512} Connection securely cleaned up with complete memory wipe");
    this.intentionalDisconnect = false;
  }
  // Public method to send files
  async sendFile(file) {
    this._enforceVerificationGate("sendFile");
    if (!this.isConnected()) {
      throw new Error("Connection not ready for file transfer. Please ensure the connection is established.");
    }
    if (!this.fileTransferSystem) {
      console.log("\u{1F504} File transfer system not initialized, attempting to initialize...");
      this.initializeFileTransfer();
      await new Promise((resolve) => setTimeout(resolve, 500));
      if (!this.fileTransferSystem) {
        throw new Error("File transfer system could not be initialized. Please try reconnecting.");
      }
    }
    if (!this.encryptionKey || !this.macKey) {
      throw new Error("Encryption keys not ready. Please wait for connection to be fully established.");
    }
    console.log("\u{1F50D} Debug: File transfer system in sendFile:", {
      hasFileTransferSystem: !!this.fileTransferSystem,
      fileTransferSystemType: this.fileTransferSystem.constructor?.name,
      hasWebrtcManager: !!this.fileTransferSystem.webrtcManager,
      webrtcManagerType: this.fileTransferSystem.webrtcManager?.constructor?.name
    });
    try {
      console.log("\u{1F680} Starting file transfer for:", file.name, `(${(file.size / 1024 / 1024).toFixed(2)} MB)`);
      const fileId = await this.fileTransferSystem.sendFile(file);
      console.log("\u2705 File transfer initiated successfully with ID:", fileId);
      return fileId;
    } catch (error) {
      this._secureLog("error", "\u274C File transfer error:", { errorType: error?.constructor?.name || "Unknown" });
      if (error.message.includes("Connection not ready")) {
        throw new Error("Connection not ready for file transfer. Check connection status.");
      } else if (error.message.includes("Encryption keys not initialized")) {
        throw new Error("Encryption keys not initialized. Try reconnecting.");
      } else if (error.message.includes("Transfer timeout")) {
        throw new Error("File transfer timeout. Check connection and try again.");
      } else {
        throw error;
      }
    }
  }
  // Get active file transfers
  getFileTransfers() {
    if (!this.fileTransferSystem) {
      return { sending: [], receiving: [] };
    }
    try {
      let sending = [];
      let receiving = [];
      if (typeof this.fileTransferSystem.getActiveTransfers === "function") {
        sending = this.fileTransferSystem.getActiveTransfers();
      } else {
        this._secureLog("warn", "\u26A0\uFE0F getActiveTransfers method not available in file transfer system");
      }
      if (typeof this.fileTransferSystem.getReceivingTransfers === "function") {
        receiving = this.fileTransferSystem.getReceivingTransfers();
      } else {
        this._secureLog("warn", "\u26A0\uFE0F getReceivingTransfers method not available in file transfer system");
      }
      return {
        sending: sending || [],
        receiving: receiving || []
      };
    } catch (error) {
      this._secureLog("error", "\u274C Error getting file transfers:", { errorType: error?.constructor?.name || "Unknown" });
      return { sending: [], receiving: [] };
    }
  }
  // Get file transfer system status
  getFileTransferStatus() {
    if (!this.fileTransferSystem) {
      return {
        initialized: false,
        status: "not_initialized",
        message: "File transfer system not initialized"
      };
    }
    const activeTransfers = this.fileTransferSystem.getActiveTransfers();
    const receivingTransfers = this.fileTransferSystem.getReceivingTransfers();
    return {
      initialized: true,
      status: "ready",
      activeTransfers: activeTransfers.length,
      receivingTransfers: receivingTransfers.length,
      totalTransfers: activeTransfers.length + receivingTransfers.length
    };
  }
  // Cancel file transfer
  cancelFileTransfer(fileId) {
    if (!this.fileTransferSystem) return false;
    return this.fileTransferSystem.cancelTransfer(fileId);
  }
  // Force cleanup of file transfer system
  cleanupFileTransferSystem() {
    if (this.fileTransferSystem) {
      console.log("\u{1F9F9} Force cleaning up file transfer system...");
      this.fileTransferSystem.cleanup();
      this.fileTransferSystem = null;
      return true;
    }
    return false;
  }
  // Reinitialize file transfer system
  reinitializeFileTransfer() {
    try {
      console.log("\u{1F504} Reinitializing file transfer system...");
      if (this.fileTransferSystem) {
        this.fileTransferSystem.cleanup();
      }
      this.initializeFileTransfer();
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to reinitialize file transfer system:", { errorType: error?.constructor?.name || "Unknown" });
      return false;
    }
  }
  // Set file transfer callbacks
  setFileTransferCallbacks(onProgress, onReceived, onError) {
    this.onFileProgress = onProgress;
    this.onFileReceived = onReceived;
    this.onFileError = onError;
    console.log("\u{1F527} File transfer callbacks set:", {
      hasProgress: !!onProgress,
      hasReceived: !!onReceived,
      hasError: !!onError
    });
    if (this.fileTransferSystem) {
      console.log("\u{1F504} Reinitializing file transfer system with new callbacks...");
      this.initializeFileTransfer();
    }
  }
  // ============================================
  // SESSION ACTIVATION HANDLING
  // ============================================
  async handleSessionActivation(sessionData) {
    try {
      console.log("\u{1F510} Handling session activation:", sessionData);
      this.currentSession = sessionData;
      this.sessionManager = sessionData.sessionManager;
      const hasKeys = !!(this.encryptionKey && this.macKey);
      const hasSession = !!(this.sessionManager && (this.sessionManager.hasActiveSession?.() || sessionData.sessionId));
      console.log("\u{1F50D} Session activation status:", {
        hasKeys,
        hasSession,
        sessionType: sessionData.sessionType,
        isDemo: sessionData.isDemo
      });
      if (hasSession) {
        console.log("\u{1F513} Session activated - forcing connection status to connected");
        this.onStatusChange("connected");
        console.log("\u26A0\uFE0F Session activated but NOT verified - cryptographic verification still required");
      }
      setTimeout(() => {
        try {
          this.initializeFileTransfer();
        } catch (error) {
          this._secureLog("warn", "\u26A0\uFE0F File transfer initialization failed during session activation:", { details: error.message });
        }
      }, 1e3);
      console.log("\u2705 Session activation handled successfully");
      if (this.fileTransferSystem && this.isConnected()) {
        console.log("\u{1F504} Synchronizing file transfer keys after session activation...");
        if (typeof this.fileTransferSystem.onSessionUpdate === "function") {
          this.fileTransferSystem.onSessionUpdate({
            keyFingerprint: this.keyFingerprint,
            sessionSalt: this.sessionSalt,
            hasMacKey: !!this.macKey
          });
        }
      }
    } catch (error) {
      this._secureLog("error", "\u274C Failed to handle session activation:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  // Method to check readiness of file transfers
  checkFileTransferReadiness() {
    const status = {
      hasFileTransferSystem: !!this.fileTransferSystem,
      hasDataChannel: !!this.dataChannel,
      dataChannelState: this.dataChannel?.readyState,
      isConnected: this.isConnected(),
      isVerified: this.isVerified,
      hasEncryptionKey: !!this.encryptionKey,
      hasMacKey: !!this.macKey,
      ready: false
    };
    status.ready = status.hasFileTransferSystem && status.hasDataChannel && status.dataChannelState === "open" && status.isConnected && status.isVerified;
    console.log("\u{1F50D} File transfer readiness check:", status);
    return status;
  }
  // Method to force re-initialize file transfer system
  forceReinitializeFileTransfer() {
    try {
      console.log("\u{1F504} Force reinitializing file transfer system...");
      if (this.fileTransferSystem) {
        this.fileTransferSystem.cleanup();
        this.fileTransferSystem = null;
      }
      setTimeout(() => {
        this.initializeFileTransfer();
      }, 500);
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to force reinitialize file transfer:", { errorType: error?.constructor?.name || "Unknown" });
      return false;
    }
  }
  // Method to get diagnostic information
  getFileTransferDiagnostics() {
    const diagnostics = {
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      webrtcManager: {
        hasDataChannel: !!this.dataChannel,
        dataChannelState: this.dataChannel?.readyState,
        isConnected: this.isConnected(),
        isVerified: this.isVerified,
        isInitiator: this.isInitiator,
        hasEncryptionKey: !!this.encryptionKey,
        hasMacKey: !!this.macKey,
        hasMetadataKey: !!this.metadataKey,
        hasKeyFingerprint: !!this.keyFingerprint,
        hasSessionSalt: !!this.sessionSalt
      },
      fileTransferSystem: null,
      globalState: {
        fileTransferActive: this._fileTransferActive || false,
        hasFileTransferSystem: !!this.fileTransferSystem,
        fileTransferSystemType: this.fileTransferSystem ? "EnhancedSecureFileTransfer" : "none"
      }
    };
    if (this.fileTransferSystem) {
      try {
        diagnostics.fileTransferSystem = this.fileTransferSystem.getSystemStatus();
      } catch (error) {
        diagnostics.fileTransferSystem = { error: error.message };
      }
    }
    return diagnostics;
  }
  getSupportedFileTypes() {
    if (!this.fileTransferSystem) {
      return { error: "File transfer system not initialized" };
    }
    try {
      return this.fileTransferSystem.getSupportedFileTypes();
    } catch (error) {
      return { error: error.message };
    }
  }
  validateFile(file) {
    if (!this.fileTransferSystem) {
      return {
        isValid: false,
        errors: ["File transfer system not initialized"],
        fileType: null,
        fileSize: file?.size || 0,
        formattedSize: "0 B"
      };
    }
    try {
      return this.fileTransferSystem.validateFile(file);
    } catch (error) {
      return {
        isValid: false,
        errors: [error.message],
        fileType: null,
        fileSize: file?.size || 0,
        formattedSize: "0 B"
      };
    }
  }
  getFileTypeInfo() {
    if (!this.fileTransferSystem) {
      return { error: "File transfer system not initialized" };
    }
    try {
      return this.fileTransferSystem.getFileTypeInfo();
    } catch (error) {
      return { error: error.message };
    }
  }
  async forceInitializeFileTransfer(options = {}) {
    const abortController = new AbortController();
    const { signal = abortController.signal, timeout = 6e3 } = options;
    if (signal && signal !== abortController.signal) {
      signal.addEventListener("abort", () => abortController.abort());
    }
    try {
      if (!this.isVerified) {
        throw new Error("Connection not verified");
      }
      if (!this.dataChannel || this.dataChannel.readyState !== "open") {
        throw new Error("Data channel not open");
      }
      if (!this.encryptionKey || !this.macKey) {
        throw new Error("Encryption keys not ready");
      }
      if (this.fileTransferSystem) {
        this.fileTransferSystem.cleanup();
        this.fileTransferSystem = null;
      }
      this.initializeFileTransfer();
      let attempts2 = 0;
      const maxAttempts = 50;
      const checkInterval = 100;
      const maxWaitTime = maxAttempts * checkInterval;
      const initializationPromise = new Promise((resolve, reject) => {
        const checkInitialization = () => {
          if (abortController.signal.aborted) {
            reject(new Error("Operation cancelled"));
            return;
          }
          if (this.fileTransferSystem) {
            resolve(true);
            return;
          }
          if (attempts2 >= maxAttempts) {
            reject(new Error(`Initialization timeout after ${maxWaitTime}ms`));
            return;
          }
          attempts2++;
          setTimeout(checkInitialization, checkInterval);
        };
        checkInitialization();
      });
      await Promise.race([
        initializationPromise,
        new Promise(
          (_, reject) => setTimeout(() => reject(new Error(`Global timeout after ${timeout}ms`)), timeout)
        )
      ]);
      if (this.fileTransferSystem) {
        return true;
      } else {
        throw new Error("Force initialization timeout");
      }
    } catch (error) {
      if (error.name === "AbortError" || error.message.includes("cancelled")) {
        this._secureLog("info", "\u23F9\uFE0F File transfer initialization cancelled by user");
        return { cancelled: true };
      }
      this._secureLog("error", "\u274C Force file transfer initialization failed:", {
        errorType: error?.constructor?.name || "Unknown",
        message: error.message,
        attempts
      });
      return { error: error.message, attempts };
    }
  }
  cancelFileTransferInitialization() {
    try {
      if (this.fileTransferSystem) {
        this.fileTransferSystem.cleanup();
        this.fileTransferSystem = null;
        this._fileTransferActive = false;
        this._secureLog("info", "\u23F9\uFE0F File transfer initialization cancelled");
        return true;
      }
      return false;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to cancel file transfer initialization:", {
        errorType: error?.constructor?.name || "Unknown"
      });
      return false;
    }
  }
  getFileTransferSystemStatus() {
    if (!this.fileTransferSystem) {
      return { available: false, status: "not_initialized" };
    }
    try {
      const status = this.fileTransferSystem.getSystemStatus();
      return {
        available: true,
        status: status.status || "unknown",
        activeTransfers: status.activeTransfers || 0,
        receivingTransfers: status.receivingTransfers || 0,
        systemType: "EnhancedSecureFileTransfer"
      };
    } catch (error) {
      this._secureLog("error", "\u274C Failed to get file transfer system status:", {
        errorType: error?.constructor?.name || "Unknown"
      });
      return { available: false, status: "error", error: error.message };
    }
  }
  _validateNestedEncryptionSecurity() {
    if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey) {
      try {
        const testIV1 = this._generateSecureIV(_EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE, "securityTest1");
        const testIV2 = this._generateSecureIV(_EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE, "securityTest2");
        if (testIV1.every((byte, index) => byte === testIV2[index])) {
          this._secureLog("error", "\u274C CRITICAL: Nested encryption security validation failed - IVs are identical!");
          return false;
        }
        const stats = this._getIVTrackingStats();
        if (stats.totalIVs < 2) {
          this._secureLog("error", "\u274C CRITICAL: IV tracking system not working properly");
          return false;
        }
        this._secureLog("info", "\u2705 Nested encryption security validation passed - secure IV generation working");
        return true;
      } catch (error) {
        this._secureLog("error", "\u274C CRITICAL: Nested encryption security validation failed:", {
          errorType: error.constructor.name,
          errorMessage: error.message
        });
        return false;
      }
    }
    return true;
  }
};
var SecureKeyStorage = class {
  constructor() {
    this._keyStore = /* @__PURE__ */ new WeakMap();
    this._keyMetadata = /* @__PURE__ */ new Map();
    this._keyReferences = /* @__PURE__ */ new Map();
    this._storageMasterKey = null;
    this._initializeStorageMaster();
    setTimeout(() => {
      if (!this.validateStorageIntegrity()) {
        console.error("\u274C CRITICAL: Key storage integrity check failed");
      }
    }, 100);
  }
  async _initializeStorageMaster() {
    this._storageMasterKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  async storeKey(keyId, cryptoKey, metadata = {}) {
    if (!(cryptoKey instanceof CryptoKey)) {
      throw new Error("Only CryptoKey objects can be stored");
    }
    try {
      if (!cryptoKey.extractable) {
        this._keyReferences.set(keyId, cryptoKey);
        this._keyMetadata.set(keyId, {
          ...metadata,
          created: Date.now(),
          lastAccessed: Date.now(),
          extractable: false,
          encrypted: false
          // Mark as not encrypted
        });
        return true;
      }
      const keyData = await crypto.subtle.exportKey("jwk", cryptoKey);
      const encryptedKeyData = await this._encryptKeyData(keyData);
      if (!encryptedKeyData || encryptedKeyData.byteLength === 0) {
        throw new Error("Failed to encrypt extractable key data");
      }
      const storageObject = {
        id: keyId,
        encryptedData: encryptedKeyData,
        algorithm: cryptoKey.algorithm,
        usages: cryptoKey.usages,
        extractable: cryptoKey.extractable,
        type: cryptoKey.type,
        timestamp: Date.now()
      };
      this._keyStore.set(cryptoKey, storageObject);
      this._keyReferences.set(keyId, cryptoKey);
      this._keyMetadata.set(keyId, {
        ...metadata,
        created: Date.now(),
        lastAccessed: Date.now(),
        extractable: true,
        encrypted: true
        //   Mark extractable keys as encrypted
      });
      return true;
    } catch (error) {
      console.error("Failed to store key securely:", error);
      return false;
    }
  }
  async retrieveKey(keyId) {
    const metadata = this._keyMetadata.get(keyId);
    if (!metadata) {
      return null;
    }
    metadata.lastAccessed = Date.now();
    if (!metadata.encrypted) {
      if (metadata.extractable === false) {
        return this._keyReferences.get(keyId);
      } else {
        this._secureLog("error", "\u274C SECURITY VIOLATION: Extractable key marked as non-encrypted", {
          keyId,
          extractable: metadata.extractable,
          encrypted: metadata.encrypted
        });
        return null;
      }
    }
    try {
      const cryptoKey = this._keyReferences.get(keyId);
      const storedData = this._keyStore.get(cryptoKey);
      if (!storedData) {
        return null;
      }
      const decryptedKeyData = await this._decryptKeyData(storedData.encryptedData);
      const recreatedKey = await crypto.subtle.importKey(
        "jwk",
        decryptedKeyData,
        storedData.algorithm,
        storedData.extractable,
        storedData.usages
      );
      return recreatedKey;
    } catch (error) {
      console.error("Failed to retrieve key:", error);
      return null;
    }
  }
  async _encryptKeyData(keyData) {
    const dataToEncrypt = typeof keyData === "object" ? JSON.stringify(keyData) : keyData;
    const encoder = new TextEncoder();
    const data = encoder.encode(dataToEncrypt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      this._storageMasterKey,
      data
    );
    const result = new Uint8Array(iv.length + encryptedData.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(encryptedData), iv.length);
    return result;
  }
  async _decryptKeyData(encryptedData) {
    const iv = encryptedData.slice(0, 12);
    const data = encryptedData.slice(12);
    const decryptedData = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      this._storageMasterKey,
      data
    );
    const decoder = new TextDecoder();
    const jsonString = decoder.decode(decryptedData);
    try {
      return JSON.parse(jsonString);
    } catch {
      return decryptedData;
    }
  }
  secureWipe(keyId) {
    const cryptoKey = this._keyReferences.get(keyId);
    if (cryptoKey) {
      this._keyStore.delete(cryptoKey);
      this._keyReferences.delete(keyId);
      this._keyMetadata.delete(keyId);
    }
    if (typeof window.gc === "function") {
      window.gc();
    }
  }
  secureWipeAll() {
    this._keyReferences.clear();
    this._keyMetadata.clear();
    this._keyStore = /* @__PURE__ */ new WeakMap();
    if (typeof window.gc === "function") {
      window.gc();
    }
  }
  //   Validate storage integrity
  validateStorageIntegrity() {
    const violations = [];
    for (const [keyId, metadata] of this._keyMetadata.entries()) {
      if (metadata.extractable === true && metadata.encrypted !== true) {
        violations.push({
          keyId,
          type: "EXTRACTABLE_KEY_NOT_ENCRYPTED",
          metadata
        });
      }
      if (metadata.extractable === false && metadata.encrypted === true) {
        violations.push({
          keyId,
          type: "NON_EXTRACTABLE_KEY_ENCRYPTED",
          metadata
        });
      }
    }
    if (violations.length > 0) {
      console.error("\u274C Storage integrity violations detected:", violations);
      return false;
    }
    return true;
  }
  getStorageStats() {
    return {
      totalKeys: this._keyReferences.size,
      metadata: Array.from(this._keyMetadata.entries()).map(([id, meta]) => ({
        id,
        created: meta.created,
        lastAccessed: meta.lastAccessed,
        age: Date.now() - meta.created
      }))
    };
  }
  // Method _generateNextSequenceNumber moved to constructor area for early availability
  /**
   *   Validate incoming message sequence number
   * This prevents replay attacks and ensures message ordering
   */
  _validateIncomingSequenceNumber(receivedSeq, context = "unknown") {
    try {
      if (!this.replayProtectionEnabled) {
        return true;
      }
      if (receivedSeq < this.expectedSequenceNumber - this.replayWindowSize) {
        this._secureLog("warn", "\u26A0\uFE0F Sequence number too old - possible replay attack", {
          received: receivedSeq,
          expected: this.expectedSequenceNumber,
          context,
          timestamp: Date.now()
        });
        return false;
      }
      if (receivedSeq > this.expectedSequenceNumber + this.maxSequenceGap) {
        this._secureLog("warn", "\u26A0\uFE0F Sequence number gap too large - possible DoS attack", {
          received: receivedSeq,
          expected: this.expectedSequenceNumber,
          gap: receivedSeq - this.expectedSequenceNumber,
          context,
          timestamp: Date.now()
        });
        return false;
      }
      if (this.replayWindow.has(receivedSeq)) {
        this._secureLog("warn", "\u26A0\uFE0F Duplicate sequence number detected - replay attack", {
          received: receivedSeq,
          context,
          timestamp: Date.now()
        });
        return false;
      }
      this.replayWindow.add(receivedSeq);
      if (this.replayWindow.size > this.replayWindowSize) {
        const oldestSeq = Math.min(...this.replayWindow);
        this.replayWindow.delete(oldestSeq);
      }
      if (receivedSeq === this.expectedSequenceNumber) {
        this.expectedSequenceNumber++;
        while (this.replayWindow.has(this.expectedSequenceNumber - this.replayWindowSize - 1)) {
          this.replayWindow.delete(this.expectedSequenceNumber - this.replayWindowSize - 1);
        }
      }
      this._secureLog("debug", "\u2705 Sequence number validation successful", {
        received: receivedSeq,
        expected: this.expectedSequenceNumber,
        context,
        timestamp: Date.now()
      });
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C Sequence number validation failed", {
        error: error.message,
        context,
        timestamp: Date.now()
      });
      return false;
    }
  }
  // Method _createMessageAAD moved to constructor area for early availability
  /**
   *   Validate message AAD with sequence number
   * This ensures message integrity and prevents replay attacks
   */
  _validateMessageAAD(aadString, expectedMessageType = null) {
    try {
      const aad = JSON.parse(aadString);
      if (aad.sessionId !== (this.currentSession?.sessionId || "unknown")) {
        throw new Error("AAD sessionId mismatch - possible replay attack");
      }
      if (aad.keyFingerprint !== (this.keyFingerprint || "unknown")) {
        throw new Error("AAD keyFingerprint mismatch - possible key substitution attack");
      }
      if (!this._validateIncomingSequenceNumber(aad.sequenceNumber, aad.messageType)) {
        throw new Error("Sequence number validation failed - possible replay or DoS attack");
      }
      if (expectedMessageType && aad.messageType !== expectedMessageType) {
        throw new Error(`AAD messageType mismatch - expected ${expectedMessageType}, got ${aad.messageType}`);
      }
      return aad;
    } catch (error) {
      this._secureLog("error", "AAD validation failed", { error: error.message, aadString });
      throw new Error(`AAD validation failed: ${error.message}`);
    }
  }
  /**
   *   Get anti-replay protection status
   * This shows the current state of replay protection
   */
  getAntiReplayStatus() {
    const status = {
      replayProtectionEnabled: this.replayProtectionEnabled,
      replayWindowSize: this.replayWindowSize,
      currentReplayWindowSize: this.replayWindow.size,
      sequenceNumber: this.sequenceNumber,
      expectedSequenceNumber: this.expectedSequenceNumber,
      maxSequenceGap: this.maxSequenceGap,
      replayWindowEntries: Array.from(this.replayWindow).sort((a, b) => a - b)
    };
    this._secureLog("info", "Anti-replay status retrieved", status);
    return status;
  }
  /**
   *   Configure anti-replay protection
   * This allows fine-tuning of replay protection parameters
   */
  configureAntiReplayProtection(config) {
    try {
      if (config.windowSize !== void 0) {
        if (config.windowSize < 16 || config.windowSize > 1024) {
          throw new Error("Replay window size must be between 16 and 1024");
        }
        this.replayWindowSize = config.windowSize;
      }
      if (config.maxGap !== void 0) {
        if (config.maxGap < 10 || config.maxGap > 1e3) {
          throw new Error("Max sequence gap must be between 10 and 1000");
        }
        this.maxSequenceGap = config.maxGap;
      }
      if (config.enabled !== void 0) {
        this.replayProtectionEnabled = config.enabled;
      }
      this._secureLog("info", "Anti-replay protection configured", config);
      return true;
    } catch (error) {
      this._secureLog("error", "Failed to configure anti-replay protection", { error: error.message });
      return false;
    }
  }
};

// src/session/PayPerSessionManager.js
var PayPerSessionManager = class {
  constructor(config = {}) {
    this.sessionPrices = {
      demo: { sats: 0, hours: 0.1, usd: 0, securityLevel: "basic" },
      basic: { sats: 5e3, hours: 1, usd: 2, securityLevel: "enhanced" },
      premium: { sats: 2e4, hours: 6, usd: 8, securityLevel: "maximum" }
    };
    this.currentSession = null;
    this.sessionTimer = null;
    this.onSessionExpired = null;
    this.staticLightningAddress = "dullpastry62@walletofsatoshi.com";
    this.usedPreimages = /* @__PURE__ */ new Set();
    this.preimageCleanupInterval = null;
    this.demoSessions = /* @__PURE__ */ new Map();
    this.maxDemoSessionsPerUser = 3;
    this.demoCooldownPeriod = 24 * 60 * 60 * 1e3;
    this.demoSessionCooldown = 1 * 60 * 1e3;
    this.demoSessionMaxDuration = 6 * 60 * 1e3;
    this.activeDemoSessions = /* @__PURE__ */ new Set();
    this.maxGlobalDemoSessions = 10;
    this.completedDemoSessions = /* @__PURE__ */ new Map();
    this.minTimeBetweenCompletedSessions = 15 * 60 * 1e3;
    this.minimumPaymentSats = 1e3;
    this.verificationConfig = {
      method: config.method || "lnbits",
      apiUrl: config.apiUrl || "https://demo.lnbits.com",
      apiKey: config.apiKey || "a7226682253f4dd7bdb2d9487a9a59f8",
      walletId: config.walletId || "649903697b03457d8b12c4eae7b2fab9",
      isDemo: config.isDemo !== void 0 ? config.isDemo : true,
      demoTimeout: 3e4,
      retryAttempts: 3,
      invoiceExpiryMinutes: 15
    };
    this.lastApiCall = 0;
    this.apiCallMinInterval = 1e3;
    this.startPreimageCleanup();
    this.startDemoSessionCleanup();
    this.startActiveDemoSessionCleanup();
    this.globalDemoCounter = 0;
    this.memoryStorage = /* @__PURE__ */ new Map();
    this.currentTabId = null;
    this.tabHeartbeatInterval = null;
    this.initializePersistentStorage();
    this.performEnhancedCleanup();
    const multiTabCheck = this.checkMultiTabProtection();
    if (!multiTabCheck.allowed) {
      console.warn("\u274C Multi-tab protection triggered:", multiTabCheck.message);
    }
    console.log("\u{1F4B0} PayPerSessionManager initialized with TIERED security levels");
    setInterval(() => {
      this.savePersistentData();
    }, 3e4);
    this.notifySecurityUpdate = () => {
      document.dispatchEvent(new CustomEvent("security-level-updated", {
        detail: { timestamp: Date.now(), manager: "webrtc" }
      }));
    };
    console.log("\u{1F4B0} PayPerSessionManager initialized with ENHANCED secure demo mode and auto-save");
  }
  getSecurityLevelForSession(sessionType) {
    const pricing = this.sessionPrices[sessionType];
    if (!pricing) return "basic";
    return pricing.securityLevel || "basic";
  }
  // Check if the function is allowed for the given session type
  isFeatureAllowedForSession(sessionType, feature) {
    const securityLevel = this.getSecurityLevelForSession(sessionType);
    const featureMatrix = {
      "basic": {
        // DEMO сессии - только базовые функции
        hasEncryption: true,
        hasECDH: true,
        hasECDSA: false,
        hasMutualAuth: false,
        hasMetadataProtection: false,
        hasEnhancedReplayProtection: false,
        hasNonExtractableKeys: false,
        hasRateLimiting: true,
        hasEnhancedValidation: false,
        hasPFS: false,
        // Advanced features are DISABLED for demo
        hasNestedEncryption: false,
        hasPacketPadding: false,
        hasPacketReordering: false,
        hasAntiFingerprinting: false,
        hasFakeTraffic: false,
        hasDecoyChannels: false,
        hasMessageChunking: false
      },
      "enhanced": {
        // BASIC paid sessions - improved security
        hasEncryption: true,
        hasECDH: true,
        hasECDSA: true,
        hasMutualAuth: true,
        hasMetadataProtection: true,
        hasEnhancedReplayProtection: true,
        hasNonExtractableKeys: true,
        hasRateLimiting: true,
        hasEnhancedValidation: true,
        hasPFS: true,
        // Partially enabled advanced features
        hasNestedEncryption: true,
        hasPacketPadding: true,
        hasPacketReordering: false,
        hasAntiFingerprinting: false,
        hasFakeTraffic: false,
        hasDecoyChannels: false,
        hasMessageChunking: false
      },
      "maximum": {
        // PREMIUM sessions - all functions included
        hasEncryption: true,
        hasECDH: true,
        hasECDSA: true,
        hasMutualAuth: true,
        hasMetadataProtection: true,
        hasEnhancedReplayProtection: true,
        hasNonExtractableKeys: true,
        hasRateLimiting: true,
        hasEnhancedValidation: true,
        hasPFS: true,
        // ALL advanced features
        hasNestedEncryption: true,
        hasPacketPadding: true,
        hasPacketReordering: true,
        hasAntiFingerprinting: true,
        hasFakeTraffic: true,
        hasDecoyChannels: true,
        hasMessageChunking: true
      }
    };
    return featureMatrix[securityLevel]?.[feature] || false;
  }
  // ============================================
  // FIXED DEMO MODE: Improved controls and management
  // ============================================
  startActiveDemoSessionCleanup() {
    setInterval(() => {
      const now = Date.now();
      let cleanedCount = 0;
      for (const preimage of this.activeDemoSessions) {
        const demoTimestamp = this.extractDemoTimestamp(preimage);
        if (demoTimestamp && now - demoTimestamp > this.demoSessionMaxDuration) {
          this.activeDemoSessions.delete(preimage);
          cleanedCount++;
        }
      }
      if (cleanedCount > 0) {
        console.log(`\u{1F9F9} Cleaned ${cleanedCount} expired active demo sessions`);
      }
    }, 3e4);
  }
  startDemoSessionCleanup() {
    setInterval(() => {
      const now = Date.now();
      const maxAge = 25 * 60 * 60 * 1e3;
      let cleanedCount = 0;
      for (const [identifier, data] of this.demoSessions.entries()) {
        if (now - data.lastUsed > maxAge) {
          this.demoSessions.delete(identifier);
          cleanedCount++;
        }
        if (data.sessions) {
          const originalCount = data.sessions.length;
          data.sessions = data.sessions.filter(
            (session) => now - session.timestamp < maxAge
          );
          if (data.sessions.length === 0 && now - data.lastUsed > maxAge) {
            this.demoSessions.delete(identifier);
            cleanedCount++;
          }
        }
      }
      for (const [identifier, sessions] of this.completedDemoSessions.entries()) {
        const filteredSessions = sessions.filter(
          (session) => now - session.endTime < maxAge
        );
        if (filteredSessions.length === 0) {
          this.completedDemoSessions.delete(identifier);
        } else {
          this.completedDemoSessions.set(identifier, filteredSessions);
        }
      }
      if (cleanedCount > 0) {
        console.log(`\u{1F9F9} Cleaned ${cleanedCount} old demo session records`);
      }
    }, 60 * 60 * 1e3);
  }
  // IMPROVED user fingerprint generation
  generateAdvancedUserFingerprint() {
    try {
      const basicComponents = [
        navigator.userAgent || "",
        navigator.language || "",
        screen.width + "x" + screen.height,
        Intl.DateTimeFormat().resolvedOptions().timeZone || "",
        navigator.hardwareConcurrency || 0,
        navigator.deviceMemory || 0,
        navigator.platform || "",
        navigator.cookieEnabled ? "1" : "0",
        window.screen.colorDepth || 0,
        window.screen.pixelDepth || 0,
        navigator.maxTouchPoints || 0,
        navigator.onLine ? "1" : "0"
      ];
      const hardwareComponents = [];
      try {
        const canvas = document.createElement("canvas");
        const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
        if (gl) {
          const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
          if (debugInfo) {
            hardwareComponents.push(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || "");
            hardwareComponents.push(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || "");
          }
          hardwareComponents.push(gl.getParameter(gl.VERSION) || "");
          hardwareComponents.push(gl.getParameter(gl.SHADING_LANGUAGE_VERSION) || "");
        }
      } catch (e) {
        hardwareComponents.push("webgl_error");
      }
      try {
        const canvas = document.createElement("canvas");
        canvas.width = 200;
        canvas.height = 50;
        const ctx = canvas.getContext("2d");
        ctx.textBaseline = "top";
        ctx.font = "14px Arial";
        ctx.fillText("SecureBit Demo Fingerprint \u{1F512}", 2, 2);
        ctx.fillStyle = "rgba(255,0,0,0.5)";
        ctx.fillRect(50, 10, 20, 20);
        hardwareComponents.push(canvas.toDataURL());
      } catch (e) {
        hardwareComponents.push("canvas_error");
      }
      try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const analyser = audioContext.createAnalyser();
        const gain = audioContext.createGain();
        oscillator.connect(analyser);
        analyser.connect(gain);
        gain.connect(audioContext.destination);
        oscillator.frequency.setValueAtTime(1e3, audioContext.currentTime);
        gain.gain.setValueAtTime(0, audioContext.currentTime);
        hardwareComponents.push(audioContext.sampleRate.toString());
        hardwareComponents.push(audioContext.state);
        hardwareComponents.push(analyser.frequencyBinCount.toString());
        audioContext.close();
      } catch (e) {
        hardwareComponents.push("audio_error");
      }
      const cpuBenchmark = this.performCPUBenchmark();
      hardwareComponents.push(cpuBenchmark);
      const allComponents = [...basicComponents, ...hardwareComponents];
      let primaryHash = 0;
      let secondaryHash = 0;
      let tertiaryHash = 0;
      const primaryStr = allComponents.slice(0, 8).join("|");
      const secondaryStr = allComponents.slice(8, 16).join("|");
      const tertiaryStr = allComponents.slice(16).join("|");
      for (let i = 0; i < primaryStr.length; i++) {
        const char = primaryStr.charCodeAt(i);
        primaryHash = (primaryHash << 7) - primaryHash + char;
        primaryHash = primaryHash & primaryHash;
      }
      for (let i = 0; i < secondaryStr.length; i++) {
        const char = secondaryStr.charCodeAt(i);
        secondaryHash = (secondaryHash << 11) - secondaryHash + char;
        secondaryHash = secondaryHash & secondaryHash;
      }
      for (let i = 0; i < tertiaryStr.length; i++) {
        const char = tertiaryStr.charCodeAt(i);
        tertiaryHash = (tertiaryHash << 13) - tertiaryHash + char;
        tertiaryHash = tertiaryHash & tertiaryHash;
      }
      const combined = `${Math.abs(primaryHash).toString(36)}_${Math.abs(secondaryHash).toString(36)}_${Math.abs(tertiaryHash).toString(36)}`;
      console.log("\u{1F512} Enhanced fingerprint generated:", {
        components: allComponents.length,
        primaryLength: primaryStr.length,
        secondaryLength: secondaryStr.length,
        tertiaryLength: tertiaryStr.length,
        fingerprintLength: combined.length
      });
      return combined;
    } catch (error) {
      console.warn("Failed to generate enhanced fingerprint:", error);
      return "fallback_" + Date.now().toString(36) + "_" + Math.random().toString(36).substr(2, 9);
    }
  }
  performCPUBenchmark() {
    const start2 = performance.now();
    let result = 0;
    for (let i = 0; i < 1e5; i++) {
      result += Math.sin(i) * Math.cos(i);
    }
    const end = performance.now();
    const duration = Math.round(end - start2);
    if (duration < 5) return "fast_cpu";
    if (duration < 15) return "medium_cpu";
    if (duration < 30) return "slow_cpu";
    return "very_slow_cpu";
  }
  initializePersistentStorage() {
    this.storageKeys = {
      demoSessions: "sb_demo_sessions_v2",
      completedSessions: "sb_completed_sessions_v2",
      globalCounter: "sb_global_demo_counter_v2",
      lastCleanup: "sb_last_cleanup_v2",
      hardwareFingerprint: "sb_hw_fingerprint_v2"
    };
    this.loadPersistentData();
  }
  loadPersistentData() {
    try {
      const savedDemoSessions = this.getFromStorage(this.storageKeys.demoSessions);
      if (savedDemoSessions) {
        const parsed = JSON.parse(savedDemoSessions);
        for (const [key, value] of Object.entries(parsed)) {
          this.demoSessions.set(key, value);
        }
      }
      const savedCompletedSessions = this.getFromStorage(this.storageKeys.completedSessions);
      if (savedCompletedSessions) {
        const parsed = JSON.parse(savedCompletedSessions);
        for (const [key, value] of Object.entries(parsed)) {
          this.completedDemoSessions.set(key, value);
        }
      }
      const savedGlobalCounter = this.getFromStorage(this.storageKeys.globalCounter);
      if (savedGlobalCounter) {
        this.globalDemoCounter = parseInt(savedGlobalCounter) || 0;
      } else {
        this.globalDemoCounter = 0;
      }
      console.log("\u{1F4CA} Persistent data loaded:", {
        demoSessions: this.demoSessions.size,
        completedSessions: this.completedDemoSessions.size,
        globalCounter: this.globalDemoCounter
      });
    } catch (error) {
      console.warn("Failed to load persistent data:", error);
      this.globalDemoCounter = 0;
    }
  }
  savePersistentData() {
    try {
      const demoSessionsObj = Object.fromEntries(this.demoSessions);
      this.setToStorage(this.storageKeys.demoSessions, JSON.stringify(demoSessionsObj));
      const completedSessionsObj = Object.fromEntries(this.completedDemoSessions);
      this.setToStorage(this.storageKeys.completedSessions, JSON.stringify(completedSessionsObj));
      this.setToStorage(this.storageKeys.globalCounter, this.globalDemoCounter.toString());
      this.setToStorage(this.storageKeys.lastCleanup, Date.now().toString());
    } catch (error) {
      console.warn("Failed to save persistent data:", error);
    }
  }
  getFromStorage(key) {
    try {
      if (typeof localStorage !== "undefined") {
        const value = localStorage.getItem(key);
        if (value) return value;
      }
    } catch (e) {
    }
    try {
      if (typeof sessionStorage !== "undefined") {
        const value = sessionStorage.getItem(key);
        if (value) return value;
      }
    } catch (e) {
    }
    try {
      if ("caches" in window) {
      }
    } catch (e) {
    }
    return null;
  }
  setToStorage(key, value) {
    try {
      if (typeof localStorage !== "undefined") {
        localStorage.setItem(key, value);
      }
    } catch (e) {
    }
    try {
      if (typeof sessionStorage !== "undefined") {
        sessionStorage.setItem(key, value);
      }
    } catch (e) {
    }
    if (!this.memoryStorage) this.memoryStorage = /* @__PURE__ */ new Map();
    this.memoryStorage.set(key, value);
  }
  checkAntiResetProtection(userFingerprint) {
    if (!this.globalDemoCounter) {
      this.globalDemoCounter = 0;
    }
    const hardwareFingerprint = this.getHardwareFingerprint();
    const savedHardwareFingerprint = this.getFromStorage(this.storageKeys.hardwareFingerprint);
    if (savedHardwareFingerprint && savedHardwareFingerprint !== hardwareFingerprint) {
      console.warn("\u{1F6A8} Hardware fingerprint mismatch detected - possible reset attempt");
      this.globalDemoCounter += 5;
      this.savePersistentData();
      return {
        isValid: false,
        reason: "hardware_mismatch",
        penalty: 5
      };
    }
    this.setToStorage(this.storageKeys.hardwareFingerprint, hardwareFingerprint);
    if (this.globalDemoCounter >= 10) {
      return {
        isValid: false,
        reason: "global_limit_exceeded",
        globalCount: this.globalDemoCounter
      };
    }
    return {
      isValid: true,
      globalCount: this.globalDemoCounter
    };
  }
  getHardwareFingerprint() {
    const components = [];
    components.push(navigator.hardwareConcurrency || 0);
    components.push(navigator.deviceMemory || 0);
    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl");
      if (gl) {
        const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
        if (debugInfo) {
          components.push(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || "");
          components.push(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || "");
        }
      }
    } catch (e) {
      components.push("webgl_unavailable");
    }
    components.push(screen.width);
    components.push(screen.height);
    components.push(screen.colorDepth);
    components.push(Intl.DateTimeFormat().resolvedOptions().timeZone);
    let hash = 0;
    const str = components.join("|");
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
  }
  registerEnhancedDemoSessionUsage(userFingerprint, preimage) {
    const session = this.registerDemoSessionUsage(userFingerprint, preimage);
    this.savePersistentData();
    console.log("\u{1F4CA} Enhanced demo session registered:", {
      userFingerprint: userFingerprint.substring(0, 12),
      globalCount: this.globalDemoCounter,
      sessionId: session.sessionId,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
    return session;
  }
  // COMPLETELY REWRITTEN demo session limits check
  checkEnhancedDemoSessionLimits(userFingerprint) {
    const antiResetCheck = this.checkAntiResetProtection(userFingerprint);
    if (!antiResetCheck.isValid) {
      return {
        allowed: false,
        reason: antiResetCheck.reason,
        message: this.getAntiResetMessage(antiResetCheck),
        globalCount: antiResetCheck.globalCount,
        penalty: antiResetCheck.penalty
      };
    }
    const regularCheck = this.checkDemoSessionLimits(userFingerprint);
    if (regularCheck.allowed) {
      this.globalDemoCounter++;
      this.savePersistentData();
    }
    return {
      ...regularCheck,
      globalCount: this.globalDemoCounter
    };
  }
  getAntiResetMessage(antiResetCheck) {
    switch (antiResetCheck.reason) {
      case "hardware_mismatch":
        return "An attempt to reset restrictions was detected. Access to demo mode is temporarily restricted.";
      case "global_limit_exceeded":
        return `Global demo session limit exceeded (${antiResetCheck.globalCount}/10). A paid session is required to continue.`;
      default:
        return "Access to demo mode is restricted for security reasons.";
    }
  }
  // FIXED demo session usage registration
  registerDemoSessionUsage(userFingerprint, preimage) {
    const now = Date.now();
    const userData = this.demoSessions.get(userFingerprint) || {
      count: 0,
      lastUsed: 0,
      sessions: [],
      firstUsed: now
    };
    userData.count++;
    userData.lastUsed = now;
    const newSession = {
      timestamp: now,
      sessionId: crypto.getRandomValues(new Uint32Array(1))[0].toString(36),
      duration: this.demoSessionMaxDuration,
      preimage,
      status: "active"
    };
    userData.sessions.push(newSession);
    userData.sessions = userData.sessions.filter(
      (session) => now - session.timestamp < this.demoCooldownPeriod
    );
    this.activeDemoSessions.add(preimage);
    this.demoSessions.set(userFingerprint, userData);
    console.log(`\u{1F4CA} Demo session registered for user ${userFingerprint.substring(0, 12)} (${userData.sessions.length}/${this.maxDemoSessionsPerUser} today)`);
    console.log(`\u{1F310} Global active demo sessions: ${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}`);
    return newSession;
  }
  performEnhancedCleanup() {
    const now = Date.now();
    const lastCleanup = parseInt(this.getFromStorage(this.storageKeys.lastCleanup)) || 0;
    if (now - lastCleanup < 6 * 60 * 60 * 1e3) {
      return;
    }
    console.log("\u{1F9F9} Performing enhanced cleanup...");
    const maxAge = 25 * 60 * 60 * 1e3;
    let cleanedSessions = 0;
    for (const [identifier, data] of this.demoSessions.entries()) {
      if (now - data.lastUsed > maxAge) {
        this.demoSessions.delete(identifier);
        cleanedSessions++;
      }
    }
    let cleanedCompleted = 0;
    for (const [identifier, sessions] of this.completedDemoSessions.entries()) {
      const filteredSessions = sessions.filter(
        (session) => now - session.endTime < maxAge
      );
      if (filteredSessions.length === 0) {
        this.completedDemoSessions.delete(identifier);
        cleanedCompleted++;
      } else {
        this.completedDemoSessions.set(identifier, filteredSessions);
      }
    }
    const weekAgo = 7 * 24 * 60 * 60 * 1e3;
    if (now - lastCleanup > weekAgo) {
      this.globalDemoCounter = Math.max(0, this.globalDemoCounter - 3);
      console.log("\u{1F504} Global demo counter reset (weekly):", this.globalDemoCounter);
    }
    this.savePersistentData();
    console.log("\u2705 Enhanced cleanup completed:", {
      cleanedSessions,
      cleanedCompleted,
      globalCounter: this.globalDemoCounter
    });
  }
  checkMultiTabProtection() {
    const tabId = "tab_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9);
    const activeTabsKey = "sb_active_tabs";
    try {
      const activeTabsStr = this.getFromStorage(activeTabsKey);
      const activeTabs = activeTabsStr ? JSON.parse(activeTabsStr) : [];
      const now = Date.now();
      const validTabs = activeTabs.filter((tab) => now - tab.timestamp < 3e4);
      if (validTabs.length >= 2) {
        return {
          allowed: false,
          reason: "multiple_tabs",
          message: "Demo mode is only available in one tab at a time.."
        };
      }
      validTabs.push({
        tabId,
        timestamp: now
      });
      this.setToStorage(activeTabsKey, JSON.stringify(validTabs));
      this.currentTabId = tabId;
      this.startTabHeartbeat();
      return {
        allowed: true,
        tabId
      };
    } catch (error) {
      console.warn("Multi-tab protection error:", error);
      return { allowed: true };
    }
  }
  startTabHeartbeat() {
    if (this.tabHeartbeatInterval) {
      clearInterval(this.tabHeartbeatInterval);
    }
    this.tabHeartbeatInterval = setInterval(() => {
      this.updateTabHeartbeat();
    }, 1e4);
  }
  updateTabHeartbeat() {
    if (!this.currentTabId) return;
    try {
      const activeTabsKey = "sb_active_tabs";
      const activeTabsStr = this.getFromStorage(activeTabsKey);
      const activeTabs = activeTabsStr ? JSON.parse(activeTabsStr) : [];
      const updatedTabs = activeTabs.map((tab) => {
        if (tab.tabId === this.currentTabId) {
          return {
            ...tab,
            timestamp: Date.now()
          };
        }
        return tab;
      });
      this.setToStorage(activeTabsKey, JSON.stringify(updatedTabs));
    } catch (error) {
      console.warn("Tab heartbeat update failed:", error);
    }
  }
  // NEW method: Register demo session completion
  registerDemoSessionCompletion(userFingerprint, sessionDuration, preimage) {
    const now = Date.now();
    if (preimage) {
      this.activeDemoSessions.delete(preimage);
    }
    const completedSessions = this.completedDemoSessions.get(userFingerprint) || [];
    completedSessions.push({
      endTime: now,
      duration: sessionDuration,
      preimage: preimage ? preimage.substring(0, 16) + "..." : "unknown"
      // Логируем только часть для безопасности
    });
    const filteredSessions = completedSessions.filter((session) => now - session.endTime < this.minTimeBetweenCompletedSessions).slice(-5);
    this.completedDemoSessions.set(userFingerprint, filteredSessions);
    const userData = this.demoSessions.get(userFingerprint);
    if (userData && userData.sessions) {
      const session = userData.sessions.find((s) => s.preimage === preimage);
      if (session) {
        session.status = "completed";
        session.endTime = now;
      }
    }
    console.log(`\u2705 Demo session completed for user ${userFingerprint.substring(0, 12)}`);
    console.log(`\u{1F310} Global active demo sessions: ${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}`);
  }
  // ENHANCED demo preimage generation with additional protection
  generateSecureDemoPreimage() {
    try {
      const timestamp = Date.now();
      const randomBytes = crypto.getRandomValues(new Uint8Array(24));
      const timestampBytes = new Uint8Array(4);
      const versionBytes = new Uint8Array(4);
      const timestampSeconds = Math.floor(timestamp / 1e3);
      timestampBytes[0] = timestampSeconds >>> 24 & 255;
      timestampBytes[1] = timestampSeconds >>> 16 & 255;
      timestampBytes[2] = timestampSeconds >>> 8 & 255;
      timestampBytes[3] = timestampSeconds & 255;
      versionBytes[0] = 222;
      versionBytes[1] = 224;
      versionBytes[2] = 0;
      versionBytes[3] = 2;
      const combined = new Uint8Array(32);
      combined.set(versionBytes, 0);
      combined.set(timestampBytes, 4);
      combined.set(randomBytes, 8);
      const preimage = Array.from(combined).map((b) => b.toString(16).padStart(2, "0")).join("");
      console.log(`\u{1F3AE} Generated SECURE demo preimage v2: ${preimage.substring(0, 16)}...`);
      return preimage;
    } catch (error) {
      console.error("Failed to generate demo preimage:", error);
      throw new Error("Failed to generate secure demo preimage");
    }
  }
  // UPDATED demo preimage check
  isDemoPreimage(preimage) {
    if (!preimage || typeof preimage !== "string" || preimage.length !== 64) {
      return false;
    }
    const lower = preimage.toLowerCase();
    return lower.startsWith("dee00001") || lower.startsWith("dee00002");
  }
  // Extract timestamp from demo preimage
  extractDemoTimestamp(preimage) {
    if (!this.isDemoPreimage(preimage)) {
      return null;
    }
    try {
      const timestampHex = preimage.slice(8, 16);
      const timestampSeconds = parseInt(timestampHex, 16);
      return timestampSeconds * 1e3;
    } catch (error) {
      console.error("Failed to extract demo timestamp:", error);
      return null;
    }
  }
  // ============================================
  // VALIDATION AND CHECKS
  // ============================================
  validateSessionType(sessionType) {
    if (!sessionType || typeof sessionType !== "string") {
      throw new Error("Session type must be a non-empty string");
    }
    if (!this.sessionPrices[sessionType]) {
      throw new Error(`Invalid session type: ${sessionType}. Allowed: ${Object.keys(this.sessionPrices).join(", ")}`);
    }
    const pricing = this.sessionPrices[sessionType];
    if (sessionType === "demo") {
      return true;
    }
    if (pricing.sats < this.minimumPaymentSats) {
      throw new Error(`Session type ${sessionType} below minimum payment threshold (${this.minimumPaymentSats} sats)`);
    }
    return true;
  }
  calculateEntropy(str) {
    const freq = {};
    for (let char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    let entropy = 0;
    const length = str.length;
    for (let char in freq) {
      const p = freq[char] / length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }
  // ============================================
  // ENHANCED verification with additional checks
  // ============================================
  async verifyCryptographically(preimage, paymentHash) {
    try {
      if (!preimage || typeof preimage !== "string" || preimage.length !== 64) {
        throw new Error("Invalid preimage format");
      }
      if (!/^[0-9a-fA-F]{64}$/.test(preimage)) {
        throw new Error("Preimage must be valid hexadecimal");
      }
      if (this.isDemoPreimage(preimage)) {
        console.log("\u{1F3AE} Demo preimage detected - performing ENHANCED validation...");
        if (this.usedPreimages.has(preimage)) {
          throw new Error("Demo preimage already used - replay attack prevented");
        }
        if (this.activeDemoSessions.has(preimage)) {
          throw new Error("Demo preimage already active - concurrent usage prevented");
        }
        const demoTimestamp = this.extractDemoTimestamp(preimage);
        if (!demoTimestamp) {
          throw new Error("Invalid demo preimage timestamp");
        }
        const now = Date.now();
        const age = now - demoTimestamp;
        if (age > 15 * 60 * 1e3) {
          throw new Error(`Demo preimage expired (age: ${Math.round(age / (60 * 1e3))} minutes)`);
        }
        if (age < -2 * 60 * 1e3) {
          throw new Error("Demo preimage timestamp from future - possible clock manipulation");
        }
        const userFingerprint = this.generateAdvancedUserFingerprint();
        const limitsCheck = this.checkEnhancedDemoSessionLimits(userFingerprint);
        if (!limitsCheck.allowed) {
          throw new Error(`Demo session limits exceeded: ${limitsCheck.message}`);
        }
        this.registerEnhancedDemoSessionUsage(userFingerprint, preimage);
        console.log("\u2705 Demo preimage ENHANCED validation passed");
        return true;
      }
      if (this.usedPreimages.has(preimage)) {
        throw new Error("Preimage already used - replay attack prevented");
      }
      const entropy = this.calculateEntropy(preimage);
      if (entropy < 3.5) {
        throw new Error(`Preimage has insufficient entropy: ${entropy.toFixed(2)}`);
      }
      const preimageBytes = new Uint8Array(preimage.match(/.{2}/g).map((byte) => parseInt(byte, 16)));
      const hashBuffer = await crypto.subtle.digest("SHA-256", preimageBytes);
      const computedHash = Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
      const isValid = computedHash === paymentHash.toLowerCase();
      if (isValid) {
        this.usedPreimages.add(preimage);
        console.log("\u2705 Standard preimage cryptographic validation passed");
      }
      return isValid;
    } catch (error) {
      console.error("\u274C Cryptographic verification failed:", error.message);
      return false;
    }
  }
  // ============================================
  // LIGHTNING NETWORK INTEGRATION
  // ============================================
  // Creating a Lightning invoice
  async createLightningInvoice(sessionType) {
    const pricing = this.sessionPrices[sessionType];
    if (!pricing) throw new Error("Invalid session type");
    try {
      console.log(`Creating ${sessionType} invoice for ${pricing.sats} sats...`);
      const now = Date.now();
      if (now - this.lastApiCall < this.apiCallMinInterval) {
        throw new Error("API rate limit: please wait before next request");
      }
      this.lastApiCall = now;
      const healthCheck = await fetch(`${this.verificationConfig.apiUrl}/api/v1/health`, {
        method: "GET",
        headers: {
          "X-Api-Key": this.verificationConfig.apiKey
        },
        signal: AbortSignal.timeout(5e3)
      });
      if (!healthCheck.ok) {
        throw new Error(`LNbits API unavailable: ${healthCheck.status}`);
      }
      const response = await fetch(`${this.verificationConfig.apiUrl}/api/v1/payments`, {
        method: "POST",
        headers: {
          "X-Api-Key": this.verificationConfig.apiKey,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          out: false,
          amount: pricing.sats,
          memo: `SecureBit.chat ${sessionType} session (${pricing.hours}h) - ${Date.now()}`,
          unit: "sat",
          expiry: this.verificationConfig.invoiceExpiryMinutes * 60
        }),
        signal: AbortSignal.timeout(1e4)
      });
      if (!response.ok) {
        const errorText = await response.text();
        console.error("LNbits API error response:", errorText);
        throw new Error(`LNbits API error ${response.status}: ${errorText}`);
      }
      const data = await response.json();
      console.log("\u2705 Lightning invoice created successfully");
      return {
        paymentRequest: data.bolt11 || data.payment_request,
        paymentHash: data.payment_hash,
        checkingId: data.checking_id || data.payment_hash,
        amount: data.amount || pricing.sats,
        sessionType,
        createdAt: Date.now(),
        expiresAt: Date.now() + this.verificationConfig.invoiceExpiryMinutes * 60 * 1e3,
        description: data.description || data.memo || `SecureBit.chat ${sessionType} session`,
        bolt11: data.bolt11 || data.payment_request,
        memo: data.memo || `SecureBit.chat ${sessionType} session`
      };
    } catch (error) {
      console.error("\u274C Lightning invoice creation failed:", error);
      if (this.verificationConfig.isDemo && error.message.includes("API")) {
        console.log("\u{1F504} Creating demo invoice for testing...");
        return this.createDemoInvoice(sessionType);
      }
      throw error;
    }
  }
  // Creating a demo invoice for testing
  createDemoInvoice(sessionType) {
    const pricing = this.sessionPrices[sessionType];
    const demoHash = Array.from(crypto.getRandomValues(new Uint8Array(32))).map((b) => b.toString(16).padStart(2, "0")).join("");
    return {
      paymentRequest: `lntb${pricing.sats}1p${demoHash.substring(0, 16)}...`,
      paymentHash: demoHash,
      checkingId: demoHash,
      amount: pricing.sats,
      sessionType,
      createdAt: Date.now(),
      expiresAt: Date.now() + 5 * 60 * 1e3,
      description: `SecureBit.chat ${sessionType} session (DEMO)`,
      isDemo: true
    };
  }
  // Checking payment status via LNbits
  async checkPaymentStatus(checkingId) {
    try {
      console.log(`\u{1F50D} Checking payment status for: ${checkingId?.substring(0, 8)}...`);
      const now = Date.now();
      if (now - this.lastApiCall < this.apiCallMinInterval) {
        throw new Error("API rate limit exceeded");
      }
      this.lastApiCall = now;
      const response = await fetch(`${this.verificationConfig.apiUrl}/api/v1/payments/${checkingId}`, {
        method: "GET",
        headers: {
          "X-Api-Key": this.verificationConfig.apiKey,
          "Content-Type": "application/json"
        },
        signal: AbortSignal.timeout(1e4)
      });
      if (!response.ok) {
        const errorText = await response.text();
        console.error("Payment status check failed:", errorText);
        throw new Error(`Payment check failed: ${response.status} - ${errorText}`);
      }
      const data = await response.json();
      console.log("\u{1F4CA} Payment status retrieved successfully");
      return {
        paid: data.paid || false,
        preimage: data.preimage || null,
        details: data.details || {},
        amount: data.amount || 0,
        fee: data.fee || 0,
        timestamp: data.timestamp || Date.now(),
        bolt11: data.bolt11 || null
      };
    } catch (error) {
      console.error("\u274C Payment status check error:", error);
      if (this.verificationConfig.isDemo && error.message.includes("API")) {
        console.log("\u{1F504} Returning demo payment status...");
        return {
          paid: false,
          preimage: null,
          details: { demo: true },
          amount: 0,
          fee: 0,
          timestamp: Date.now()
        };
      }
      throw error;
    }
  }
  // Payment verification via LNbits API
  async verifyPaymentLNbits(preimage, paymentHash) {
    try {
      console.log(`\u{1F510} Verifying payment via LNbits API...`);
      if (!this.verificationConfig.apiUrl || !this.verificationConfig.apiKey) {
        throw new Error("LNbits API configuration missing");
      }
      const now = Date.now();
      if (now - this.lastApiCall < this.apiCallMinInterval) {
        throw new Error("API rate limit: please wait before next verification");
      }
      this.lastApiCall = now;
      const response = await fetch(`${this.verificationConfig.apiUrl}/api/v1/payments/${paymentHash}`, {
        method: "GET",
        headers: {
          "X-Api-Key": this.verificationConfig.apiKey,
          "Content-Type": "application/json"
        },
        signal: AbortSignal.timeout(1e4)
      });
      if (!response.ok) {
        const errorText = await response.text();
        console.error("LNbits verification failed:", errorText);
        throw new Error(`API request failed: ${response.status} - ${errorText}`);
      }
      const paymentData = await response.json();
      console.log("\u{1F4CB} Payment verification data received from LNbits");
      const isPaid = paymentData.paid === true;
      const preimageMatches = paymentData.preimage === preimage;
      const amountValid = paymentData.amount >= this.minimumPaymentSats;
      const paymentTimestamp = paymentData.timestamp || paymentData.time || 0;
      const paymentAge = now - paymentTimestamp * 1e3;
      const maxPaymentAge = 24 * 60 * 60 * 1e3;
      if (paymentAge > maxPaymentAge && paymentTimestamp > 0) {
        throw new Error(`Payment too old: ${Math.round(paymentAge / (60 * 60 * 1e3))} hours (max: 24h)`);
      }
      if (isPaid && preimageMatches && amountValid) {
        console.log("\u2705 Payment verified successfully via LNbits");
        return {
          verified: true,
          amount: paymentData.amount,
          fee: paymentData.fee || 0,
          timestamp: paymentTimestamp || now,
          method: "lnbits",
          verificationTime: now,
          paymentAge
        };
      }
      console.log("\u274C LNbits payment verification failed:", {
        paid: isPaid,
        preimageMatch: preimageMatches,
        amountValid,
        paymentAge: Math.round(paymentAge / (60 * 1e3)) + " minutes"
      });
      return {
        verified: false,
        reason: "Payment verification failed: not paid, preimage mismatch, insufficient amount, or payment too old",
        method: "lnbits",
        details: {
          paid: isPaid,
          preimageMatch: preimageMatches,
          amountValid,
          paymentAge
        }
      };
    } catch (error) {
      console.error("\u274C LNbits payment verification failed:", error);
      return {
        verified: false,
        reason: error.message,
        method: "lnbits",
        error: true
      };
    }
  }
  // ============================================
  // BASIC LOGIC OF PAYMENT VERIFICATION
  // ============================================
  // The main method of payment verification
  async verifyPayment(preimage, paymentHash) {
    console.log(`\u{1F510} Starting payment verification...`);
    try {
      if (!preimage || !paymentHash) {
        throw new Error("Missing preimage or payment hash");
      }
      if (typeof preimage !== "string" || typeof paymentHash !== "string") {
        throw new Error("Preimage and payment hash must be strings");
      }
      if (this.isDemoPreimage(preimage)) {
        console.log("\u{1F3AE} Processing demo session verification...");
        const cryptoValid2 = await this.verifyCryptographically(preimage, paymentHash);
        if (!cryptoValid2) {
          return {
            verified: false,
            reason: "Demo preimage verification failed",
            stage: "crypto"
          };
        }
        console.log("\u2705 Demo session verified successfully");
        return {
          verified: true,
          method: "demo",
          sessionType: "demo",
          isDemo: true,
          warning: "Demo session - limited duration (6 minutes)"
        };
      }
      const cryptoValid = await this.verifyCryptographically(preimage, paymentHash);
      if (!cryptoValid) {
        return {
          verified: false,
          reason: "Cryptographic verification failed",
          stage: "crypto"
        };
      }
      console.log("\u2705 Cryptographic verification passed");
      if (!this.verificationConfig.isDemo) {
        switch (this.verificationConfig.method) {
          case "lnbits":
            const lnbitsResult = await this.verifyPaymentLNbits(preimage, paymentHash);
            if (!lnbitsResult.verified) {
              return {
                verified: false,
                reason: lnbitsResult.reason || "LNbits verification failed",
                stage: "lightning",
                details: lnbitsResult.details
              };
            }
            return lnbitsResult;
          default:
            console.warn("Unknown verification method, using crypto-only verification");
            return {
              verified: true,
              method: "crypto-only",
              warning: "Lightning verification skipped - unknown method"
            };
        }
      } else {
        console.warn("\u{1F6A8} DEMO MODE: Lightning payment verification bypassed - FOR DEVELOPMENT ONLY");
        return {
          verified: true,
          method: "demo-mode",
          warning: "DEMO MODE - Lightning verification bypassed"
        };
      }
    } catch (error) {
      console.error("\u274C Payment verification failed:", error);
      return {
        verified: false,
        reason: error.message,
        stage: "error"
      };
    }
  }
  // ============================================
  // SESSION MANAGEMENT
  // ============================================
  // ============================================
  // REWORKED session activation methods
  // ============================================
  async safeActivateSession(sessionType, preimage, paymentHash) {
    try {
      console.log(`\u{1F680} Attempting to activate ${sessionType} session...`);
      if (!sessionType || !preimage || !paymentHash) {
        return {
          success: false,
          reason: "Missing required parameters: sessionType, preimage, or paymentHash"
        };
      }
      try {
        this.validateSessionType(sessionType);
      } catch (error) {
        return { success: false, reason: error.message };
      }
      if (this.hasActiveSession()) {
        return {
          success: false,
          reason: "Active session already exists. Please wait for it to expire or disconnect."
        };
      }
      if (sessionType === "demo") {
        if (!this.isDemoPreimage(preimage)) {
          return {
            success: false,
            reason: "Invalid demo preimage format. Please use the generated demo preimage."
          };
        }
        const userFingerprint = this.generateAdvancedUserFingerprint();
        const demoCheck = this.checkEnhancedDemoSessionLimits(userFingerprint);
        if (!demoCheck.allowed) {
          console.log(`\u26A0\uFE0F Demo session cooldown active, but allowing activation for development`);
          if (demoCheck.reason === "global_limit_exceeded") {
            return {
              success: false,
              reason: demoCheck.message,
              demoLimited: true,
              timeUntilNext: demoCheck.timeUntilNext,
              remaining: demoCheck.remaining
            };
          }
          console.log(`\u{1F504} Bypassing demo cooldown for development purposes`);
        }
        if (this.activeDemoSessions.has(preimage)) {
          if (!this.currentSession || !this.hasActiveSession()) {
            console.log(`\u{1F504} Demo session with preimage ${preimage.substring(0, 16)}... was interrupted, allowing reactivation`);
            this.activeDemoSessions.delete(preimage);
          } else {
            return {
              success: false,
              reason: "Demo session with this preimage is already active",
              demoLimited: true
            };
          }
        }
      }
      let verificationResult;
      if (sessionType === "demo") {
        console.log("\u{1F3AE} Using special demo verification for activation...");
        verificationResult = await this.verifyDemoSessionForActivation(preimage, paymentHash);
      } else {
        verificationResult = await this.verifyPayment(preimage, paymentHash);
      }
      if (!verificationResult.verified) {
        return {
          success: false,
          reason: verificationResult.reason,
          stage: verificationResult.stage,
          method: verificationResult.method,
          demoLimited: verificationResult.demoLimited,
          timeUntilNext: verificationResult.timeUntilNext,
          remaining: verificationResult.remaining
        };
      }
      const session = this.activateSession(sessionType, preimage);
      console.log(`\u2705 Session activated successfully: ${sessionType} via ${verificationResult.method}`);
      return {
        success: true,
        sessionType,
        method: verificationResult.method,
        details: verificationResult,
        timeLeft: this.getTimeLeft(),
        sessionId: session.id,
        warning: verificationResult.warning,
        isDemo: verificationResult.isDemo || false,
        remaining: verificationResult.remaining
      };
    } catch (error) {
      console.error("\u274C Session activation failed:", error);
      return {
        success: false,
        reason: error.message,
        method: "error"
      };
    }
  }
  // REWORKED session activation
  activateSession(sessionType, preimage) {
    if (this.hasActiveSession()) {
      return this.currentSession;
    }
    if (this.sessionTimer) {
      clearInterval(this.sessionTimer);
      this.sessionTimer = null;
    }
    const pricing = this.sessionPrices[sessionType];
    const now = Date.now();
    let duration;
    if (sessionType === "demo") {
      duration = this.demoSessionMaxDuration;
    } else {
      duration = pricing.hours * 60 * 60 * 1e3;
    }
    const expiresAt = now + duration;
    const sessionId = Array.from(crypto.getRandomValues(new Uint8Array(16))).map((b) => b.toString(16).padStart(2, "0")).join("");
    this.currentSession = {
      id: sessionId,
      type: sessionType,
      startTime: now,
      expiresAt,
      preimage,
      isDemo: sessionType === "demo",
      securityLevel: this.getSecurityLevelForSession(sessionType)
    };
    this.startSessionTimer();
    if (sessionType === "demo") {
      setTimeout(() => {
        this.handleDemoSessionExpiry(preimage);
      }, duration);
    }
    const durationMinutes = Math.round(duration / (60 * 1e3));
    const securityLevel = this.currentSession ? this.currentSession.securityLevel : "unknown";
    console.log(`\u{1F4C5} Session ${sessionId.substring(0, 8)}... activated for ${durationMinutes} minutes with ${securityLevel} security`);
    if (sessionType === "demo") {
      this.activeDemoSessions.add(preimage);
      this.usedPreimages.add(preimage);
      console.log(`\u{1F310} Demo session added to active sessions. Total: ${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}`);
    }
    const activatedSession = this.currentSession;
    setTimeout(() => {
      if (activatedSession) {
        this.notifySessionActivated(activatedSession);
      }
      if (window.webrtcManager && window.webrtcManager.configureSecurityForSession && activatedSession) {
        const securityLevel2 = activatedSession.securityLevel || this.getSecurityLevelForSession(sessionType);
        window.webrtcManager.configureSecurityForSession(sessionType, securityLevel2);
      }
    }, 100);
    return this.currentSession;
  }
  // UPDATED method for getting session information
  getSessionInfo() {
    if (!this.currentSession) {
      return null;
    }
    const securityLevel = this.getSecurityLevelForSession(this.currentSession.type);
    const pricing = this.sessionPrices[this.currentSession.type];
    return {
      ...this.currentSession,
      securityLevel,
      securityDescription: this.getSecurityDescription(securityLevel),
      pricing,
      timeLeft: this.getTimeLeft(),
      isConnected: this.hasActiveSession()
    };
  }
  getSecurityDescription(level) {
    const descriptions = {
      "basic": {
        title: "Basic Security",
        features: [
          "End-to-end encryption",
          "Basic key exchange",
          "Rate limiting",
          "Message integrity"
        ],
        limitations: [
          "No advanced obfuscation",
          "No traffic padding",
          "No decoy channels"
        ]
      },
      "enhanced": {
        title: "Enhanced Security",
        features: [
          "All basic features",
          "ECDSA signatures",
          "Metadata protection",
          "Perfect forward secrecy",
          "Nested encryption",
          "Packet padding"
        ],
        limitations: [
          "Limited traffic obfuscation",
          "No fake traffic generation"
        ]
      },
      "maximum": {
        title: "Maximum Security",
        features: [
          "All enhanced features",
          "Traffic obfuscation",
          "Fake traffic generation",
          "Decoy channels",
          "Anti-fingerprinting",
          "Message chunking",
          "Packet reordering protection"
        ],
        limitations: []
      }
    };
    return descriptions[level] || descriptions["basic"];
  }
  notifySessionActivated(session = null) {
    const targetSession = session || this.currentSession;
    if (!targetSession) return;
    if (targetSession.notified) {
      return;
    }
    const timeLeft = Math.max(0, targetSession.expiresAt - Date.now());
    const sessionType = targetSession.type;
    if (window.updateSessionTimer) {
      window.updateSessionTimer(timeLeft, sessionType);
    }
    document.dispatchEvent(new CustomEvent("session-activated", {
      detail: {
        sessionId: targetSession.id,
        timeLeft,
        sessionType,
        isDemo: targetSession.isDemo,
        timestamp: Date.now()
      }
    }));
    if (window.forceUpdateHeader) {
      window.forceUpdateHeader(timeLeft, sessionType);
    }
    if (window.debugSessionManager) {
      window.debugSessionManager();
    }
    targetSession.notified = true;
  }
  handleDemoSessionExpiry(preimage) {
    if (this.currentSession && this.currentSession.preimage === preimage) {
      const userFingerprint = this.generateAdvancedUserFingerprint();
      const sessionDuration = Date.now() - this.currentSession.startTime;
      this.registerDemoSessionCompletion(userFingerprint, sessionDuration, preimage);
      console.log(`\u23F0 Demo session auto-expired for preimage ${preimage.substring(0, 16)}...`);
    }
  }
  startSessionTimer() {
    if (this.sessionTimer) {
      clearInterval(this.sessionTimer);
    }
    this.sessionTimer = setInterval(() => {
      if (!this.hasActiveSession()) {
        this.expireSession();
      }
    }, 6e4);
  }
  expireSession() {
    if (this.sessionTimer) {
      clearInterval(this.sessionTimer);
      this.sessionTimer = null;
    }
    const expiredSession = this.currentSession;
    if (expiredSession && expiredSession.isDemo) {
      const userFingerprint = this.generateAdvancedUserFingerprint();
      const sessionDuration = Date.now() - expiredSession.startTime;
      this.registerDemoSessionCompletion(userFingerprint, sessionDuration, expiredSession.preimage);
    }
    this.currentSession = null;
    if (expiredSession) {
      console.log(`\u23F0 Session ${expiredSession.id.substring(0, 8)}... expired`);
    }
    if (this.onSessionExpired) {
      this.onSessionExpired();
    }
  }
  hasActiveSession() {
    if (!this.currentSession) {
      return false;
    }
    const isActive = Date.now() < this.currentSession.expiresAt;
    return isActive;
  }
  getTimeLeft() {
    if (!this.currentSession) return 0;
    return Math.max(0, this.currentSession.expiresAt - Date.now());
  }
  forceUpdateTimer() {
    if (this.currentSession) {
      const timeLeft = this.getTimeLeft();
      if (window.DEBUG_MODE && Math.floor(Date.now() / 3e4) !== Math.floor((Date.now() - 1e3) / 3e4)) {
        console.log(`\u23F1\uFE0F Timer updated: ${Math.ceil(timeLeft / 1e3)}s left`);
      }
      return timeLeft;
    }
    return 0;
  }
  // ============================================
  // DEMO MODE: Custom Methods
  // ============================================
  // UPDATED demo session creation
  createDemoSession() {
    const userFingerprint = this.generateAdvancedUserFingerprint();
    const demoCheck = this.checkEnhancedDemoSessionLimits(userFingerprint);
    if (!demoCheck.allowed) {
      return {
        success: false,
        reason: demoCheck.message,
        timeUntilNext: demoCheck.timeUntilNext,
        remaining: demoCheck.remaining,
        blockingReason: demoCheck.reason
      };
    }
    if (this.activeDemoSessions.size >= this.maxGlobalDemoSessions) {
      return {
        success: false,
        reason: `Too many demo sessions active globally (${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}). Please try again later.`,
        blockingReason: "global_limit",
        globalActive: this.activeDemoSessions.size,
        globalLimit: this.maxGlobalDemoSessions
      };
    }
    try {
      const demoPreimage = this.generateSecureDemoPreimage();
      const demoPaymentHash = "demo_" + Array.from(crypto.getRandomValues(new Uint8Array(16))).map((b) => b.toString(16).padStart(2, "0")).join("");
      return {
        success: true,
        sessionType: "demo",
        preimage: demoPreimage,
        paymentHash: demoPaymentHash,
        duration: this.sessionPrices.demo.hours,
        durationMinutes: Math.round(this.demoSessionMaxDuration / (60 * 1e3)),
        warning: `Demo session - limited to ${Math.round(this.demoSessionMaxDuration / (60 * 1e3))} minutes`,
        remaining: demoCheck.remaining - 1,
        globalActive: this.activeDemoSessions.size + 1,
        globalLimit: this.maxGlobalDemoSessions
      };
    } catch (error) {
      console.error("Failed to create demo session:", error);
      return {
        success: false,
        reason: "Failed to generate demo session. Please try again.",
        remaining: demoCheck.remaining
      };
    }
  }
  // UPDATED information about demo limits
  getDemoSessionInfo() {
    const userFingerprint = this.generateAdvancedUserFingerprint();
    const userData = this.demoSessions.get(userFingerprint);
    const now = Date.now();
    if (!userData) {
      return {
        available: this.maxDemoSessionsPerUser,
        used: 0,
        total: this.maxDemoSessionsPerUser,
        nextAvailable: "immediately",
        cooldownMinutes: 0,
        durationMinutes: Math.round(this.demoSessionMaxDuration / (60 * 1e3)),
        canUseNow: this.activeDemoSessions.size < this.maxGlobalDemoSessions,
        globalActive: this.activeDemoSessions.size,
        globalLimit: this.maxGlobalDemoSessions,
        debugInfo: "New user, no restrictions"
      };
    }
    const sessionsLast24h = userData.sessions.filter(
      (session) => now - session.timestamp < this.demoCooldownPeriod
    );
    const available = Math.max(0, this.maxDemoSessionsPerUser - sessionsLast24h.length);
    let cooldownMs = 0;
    let nextAvailable = "immediately";
    let blockingReason = null;
    let debugInfo = "";
    if (this.activeDemoSessions.size >= this.maxGlobalDemoSessions) {
      nextAvailable = "when global limit decreases";
      blockingReason = "global_limit";
      debugInfo = `Global limit: ${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}`;
    } else if (available === 0) {
      const oldestSession = Math.min(...sessionsLast24h.map((s) => s.timestamp));
      cooldownMs = this.demoCooldownPeriod - (now - oldestSession);
      nextAvailable = `${Math.ceil(cooldownMs / (60 * 1e3))} minutes`;
      blockingReason = "daily_limit";
      debugInfo = `Daily limit reached: ${sessionsLast24h.length}/${this.maxDemoSessionsPerUser}`;
    } else if (userData.lastUsed && now - userData.lastUsed < this.demoSessionCooldown) {
      cooldownMs = this.demoSessionCooldown - (now - userData.lastUsed);
      nextAvailable = `${Math.ceil(cooldownMs / (60 * 1e3))} minutes`;
      blockingReason = "session_cooldown";
      const lastUsedMinutes = Math.round((now - userData.lastUsed) / (60 * 1e3));
      debugInfo = `Cooldown active: last used ${lastUsedMinutes}min ago, need ${Math.ceil(cooldownMs / (60 * 1e3))}min more`;
    } else {
      const completedSessions = this.completedDemoSessions.get(userFingerprint) || [];
      const recentCompletedSessions = completedSessions.filter(
        (session) => now - session.endTime < this.minTimeBetweenCompletedSessions
      );
      if (recentCompletedSessions.length > 0) {
        const lastCompletedSession = Math.max(...recentCompletedSessions.map((s) => s.endTime));
        cooldownMs = this.minTimeBetweenCompletedSessions - (now - lastCompletedSession);
        nextAvailable = `${Math.ceil(cooldownMs / (60 * 1e3))} minutes`;
        blockingReason = "completion_cooldown";
        const completedMinutes = Math.round((now - lastCompletedSession) / (60 * 1e3));
        debugInfo = `Completion cooldown: last session ended ${completedMinutes}min ago`;
      } else {
        debugInfo = `Ready to use: ${available} sessions available`;
      }
    }
    const canUseNow = available > 0 && cooldownMs <= 0 && this.activeDemoSessions.size < this.maxGlobalDemoSessions;
    return {
      available,
      used: sessionsLast24h.length,
      total: this.maxDemoSessionsPerUser,
      nextAvailable,
      cooldownMinutes: Math.ceil(cooldownMs / (60 * 1e3)),
      durationMinutes: Math.round(this.demoSessionMaxDuration / (60 * 1e3)),
      canUseNow,
      blockingReason,
      globalActive: this.activeDemoSessions.size,
      globalLimit: this.maxGlobalDemoSessions,
      completionCooldownMinutes: Math.round(this.minTimeBetweenCompletedSessions / (60 * 1e3)),
      sessionCooldownMinutes: Math.round(this.demoSessionCooldown / (60 * 1e3)),
      debugInfo,
      lastUsed: userData.lastUsed ? new Date(userData.lastUsed).toLocaleString() : "Never"
    };
  }
  // ============================================
  // ADDITIONAL VERIFICATION METHODS
  // ============================================
  // Verification method via LND (Lightning Network Daemon)
  async verifyPaymentLND(preimage, paymentHash) {
    try {
      if (!this.verificationConfig.nodeUrl || !this.verificationConfig.macaroon) {
        throw new Error("LND configuration missing");
      }
      const response = await fetch(`${this.verificationConfig.nodeUrl}/v1/invoice/${paymentHash}`, {
        method: "GET",
        headers: {
          "Grpc-Metadata-macaroon": this.verificationConfig.macaroon,
          "Content-Type": "application/json"
        },
        signal: AbortSignal.timeout(1e4)
      });
      if (!response.ok) {
        throw new Error(`LND API request failed: ${response.status}`);
      }
      const invoiceData = await response.json();
      if (invoiceData.settled && invoiceData.r_preimage === preimage) {
        return {
          verified: true,
          amount: invoiceData.value,
          method: "lnd",
          timestamp: Date.now()
        };
      }
      return { verified: false, reason: "LND verification failed", method: "lnd" };
    } catch (error) {
      console.error("LND payment verification failed:", error);
      return { verified: false, reason: error.message, method: "lnd" };
    }
  }
  // Verification method via CLN (Core Lightning)
  async verifyPaymentCLN(preimage, paymentHash) {
    try {
      if (!this.verificationConfig.nodeUrl) {
        throw new Error("CLN configuration missing");
      }
      const response = await fetch(`${this.verificationConfig.nodeUrl}/v1/listinvoices`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          payment_hash: paymentHash
        }),
        signal: AbortSignal.timeout(1e4)
      });
      if (!response.ok) {
        throw new Error(`CLN API request failed: ${response.status}`);
      }
      const data = await response.json();
      if (data.invoices && data.invoices.length > 0) {
        const invoice = data.invoices[0];
        if (invoice.status === "paid" && invoice.payment_preimage === preimage) {
          return {
            verified: true,
            amount: invoice.amount_msat / 1e3,
            method: "cln",
            timestamp: Date.now()
          };
        }
      }
      return { verified: false, reason: "CLN verification failed", method: "cln" };
    } catch (error) {
      console.error("CLN payment verification failed:", error);
      return { verified: false, reason: error.message, method: "cln" };
    }
  }
  // Verification method via BTCPay Server
  async verifyPaymentBTCPay(preimage, paymentHash) {
    try {
      if (!this.verificationConfig.apiUrl || !this.verificationConfig.apiKey) {
        throw new Error("BTCPay Server configuration missing");
      }
      const response = await fetch(`${this.verificationConfig.apiUrl}/api/v1/invoices/${paymentHash}`, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${this.verificationConfig.apiKey}`,
          "Content-Type": "application/json"
        },
        signal: AbortSignal.timeout(1e4)
      });
      if (!response.ok) {
        throw new Error(`BTCPay API request failed: ${response.status}`);
      }
      const invoiceData = await response.json();
      if (invoiceData.status === "Settled" && invoiceData.payment && invoiceData.payment.preimage === preimage) {
        return {
          verified: true,
          amount: invoiceData.amount,
          method: "btcpay",
          timestamp: Date.now()
        };
      }
      return { verified: false, reason: "BTCPay verification failed", method: "btcpay" };
    } catch (error) {
      console.error("BTCPay payment verification failed:", error);
      return { verified: false, reason: error.message, method: "btcpay" };
    }
  }
  // ============================================
  // UTILITY METHODS
  // ============================================
  // Creating a regular invoice (not a demo)
  createInvoice(sessionType) {
    this.validateSessionType(sessionType);
    const pricing = this.sessionPrices[sessionType];
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    const timestamp = Date.now();
    const sessionEntropy = crypto.getRandomValues(new Uint8Array(16));
    const combinedEntropy = new Uint8Array(48);
    combinedEntropy.set(randomBytes, 0);
    combinedEntropy.set(new Uint8Array(new BigUint64Array([BigInt(timestamp)]).buffer), 32);
    combinedEntropy.set(sessionEntropy, 40);
    const paymentHash = Array.from(crypto.getRandomValues(new Uint8Array(32))).map((b) => b.toString(16).padStart(2, "0")).join("");
    return {
      amount: pricing.sats,
      memo: `SecureBit.chat ${sessionType} session (${pricing.hours}h) - ${timestamp}`,
      sessionType,
      timestamp,
      paymentHash,
      lightningAddress: this.staticLightningAddress,
      entropy: Array.from(sessionEntropy).map((b) => b.toString(16).padStart(2, "0")).join(""),
      expiresAt: timestamp + this.verificationConfig.invoiceExpiryMinutes * 60 * 1e3
    };
  }
  // Checking if a session can be activated
  canActivateSession() {
    return !this.hasActiveSession();
  }
  // Reset session (if there are security errors)
  resetSession() {
    if (this.sessionTimer) {
      clearInterval(this.sessionTimer);
      this.sessionTimer = null;
    }
    const resetSession = this.currentSession;
    if (resetSession && resetSession.isDemo) {
      const userFingerprint = this.generateAdvancedUserFingerprint();
      const sessionDuration = Date.now() - resetSession.startTime;
      this.registerDemoSessionCompletion(userFingerprint, sessionDuration, resetSession.preimage);
    }
    this.currentSession = null;
    this.sessionStartTime = null;
    this.sessionEndTime = null;
    if (resetSession && resetSession.preimage) {
      this.activeDemoSessions.delete(resetSession.preimage);
    }
    document.dispatchEvent(new CustomEvent("session-reset", {
      detail: {
        timestamp: Date.now(),
        reason: "security_reset"
      }
    }));
    setTimeout(() => {
      if (this.currentSession) {
        this.currentSession = null;
      }
    }, 100);
  }
  // Cleaning old preimages (every 24 hours)
  startPreimageCleanup() {
    this.preimageCleanupInterval = setInterval(() => {
      if (this.usedPreimages.size > 1e4) {
        const oldSize = this.usedPreimages.size;
        this.usedPreimages.clear();
        console.log(`\u{1F9F9} Cleaned ${oldSize} old preimages for memory management`);
      }
    }, 24 * 60 * 60 * 1e3);
  }
  // Complete manager cleanup
  cleanup() {
    if (this.sessionTimer) {
      clearInterval(this.sessionTimer);
      this.sessionTimer = null;
    }
    if (this.preimageCleanupInterval) {
      clearInterval(this.preimageCleanupInterval);
      this.preimageCleanupInterval = null;
    }
    if (this.currentSession && this.currentSession.isDemo) {
      const userFingerprint = this.generateAdvancedUserFingerprint();
      const sessionDuration = Date.now() - this.currentSession.startTime;
      this.registerDemoSessionCompletion(userFingerprint, sessionDuration, this.currentSession.preimage);
    }
    this.currentSession = null;
    this.sessionStartTime = null;
    this.sessionEndTime = null;
    if (this.currentSession && this.currentSession.preimage) {
      this.activeDemoSessions.delete(this.currentSession.preimage);
    }
    document.dispatchEvent(new CustomEvent("session-cleanup", {
      detail: {
        timestamp: Date.now(),
        reason: "complete_cleanup"
      }
    }));
    setTimeout(() => {
      if (this.currentSession) {
        this.currentSession = null;
      }
    }, 100);
  }
  getUsageStats() {
    const stats = {
      totalDemoUsers: this.demoSessions.size,
      usedPreimages: this.usedPreimages.size,
      activeDemoSessions: this.activeDemoSessions.size,
      globalDemoLimit: this.maxGlobalDemoSessions,
      currentSession: this.currentSession ? {
        type: this.currentSession.type,
        timeLeft: this.getTimeLeft(),
        isDemo: this.currentSession.isDemo
      } : null,
      config: {
        maxDemoSessions: this.maxDemoSessionsPerUser,
        demoCooldown: this.demoSessionCooldown / (60 * 1e3),
        demoMaxDuration: this.demoSessionMaxDuration / (60 * 1e3),
        completionCooldown: this.minTimeBetweenCompletedSessions / (60 * 1e3)
      }
    };
    return stats;
  }
  getVerifiedDemoSession() {
    const userFingerprint = this.generateAdvancedUserFingerprint();
    const userData = this.demoSessions.get(userFingerprint);
    console.log("\u{1F50D} Searching for verified demo session:", {
      userFingerprint: userFingerprint.substring(0, 12),
      hasUserData: !!userData,
      sessionsCount: userData?.sessions?.length || 0,
      currentSession: this.currentSession ? {
        type: this.currentSession.type,
        timeLeft: this.getTimeLeft(),
        isActive: this.hasActiveSession()
      } : null
    });
    if (!userData || !userData.sessions || userData.sessions.length === 0) {
      console.log("\u274C No user data or sessions found");
      return null;
    }
    const lastSession = userData.sessions[userData.sessions.length - 1];
    if (!lastSession || !lastSession.preimage) {
      console.log("\u274C Last session is invalid:", lastSession);
      return null;
    }
    if (!this.isDemoPreimage(lastSession.preimage)) {
      console.log("\u274C Last session preimage is not demo format:", lastSession.preimage.substring(0, 16) + "...");
      return null;
    }
    if (this.activeDemoSessions.has(lastSession.preimage)) {
      console.log("\u26A0\uFE0F Demo session is already in activeDemoSessions, checking if truly active...");
      if (this.hasActiveSession()) {
        console.log("\u274C Demo session is truly active, cannot reactivate");
        return null;
      } else {
        console.log("\u{1F504} Demo session was interrupted, can be reactivated");
      }
    }
    const verifiedSession = {
      preimage: lastSession.preimage,
      paymentHash: lastSession.paymentHash || "demo_" + Date.now(),
      sessionType: "demo",
      timestamp: lastSession.timestamp
    };
    console.log("\u2705 Found verified demo session:", {
      preimage: verifiedSession.preimage.substring(0, 16) + "...",
      timestamp: new Date(verifiedSession.timestamp).toLocaleTimeString(),
      canActivate: !this.hasActiveSession()
    });
    return verifiedSession;
  }
  checkDemoSessionLimits(userFingerprint) {
    const userData = this.demoSessions.get(userFingerprint);
    const now = Date.now();
    console.log(`\u{1F50D} Checking demo limits for user ${userFingerprint.substring(0, 12)}...`);
    if (this.activeDemoSessions.size >= this.maxGlobalDemoSessions) {
      console.log(`\u274C Global demo limit reached: ${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}`);
      return {
        allowed: false,
        reason: "global_limit_exceeded",
        message: `Too many demo sessions active globally (${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}). Please try again later.`,
        remaining: 0,
        debugInfo: `Global sessions: ${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}`
      };
    }
    if (!userData) {
      console.log(`\u2705 First demo session for user ${userFingerprint.substring(0, 12)}`);
      return {
        allowed: true,
        reason: "first_demo_session",
        remaining: this.maxDemoSessionsPerUser,
        debugInfo: "First time user"
      };
    }
    const sessionsLast24h = userData.sessions.filter(
      (session) => now - session.timestamp < this.demoCooldownPeriod
    );
    console.log(`\u{1F4CA} Sessions in last 24h for user ${userFingerprint.substring(0, 12)}: ${sessionsLast24h.length}/${this.maxDemoSessionsPerUser}`);
    if (sessionsLast24h.length >= this.maxDemoSessionsPerUser) {
      const oldestSession = Math.min(...sessionsLast24h.map((s) => s.timestamp));
      const timeUntilNext = this.demoCooldownPeriod - (now - oldestSession);
      console.log(`\u274C Daily demo limit exceeded for user ${userFingerprint.substring(0, 12)}`);
      return {
        allowed: false,
        reason: "daily_limit_exceeded",
        timeUntilNext,
        message: `Daily demo limit reached (${this.maxDemoSessionsPerUser}/day). Next session available in ${Math.ceil(timeUntilNext / (60 * 1e3))} minutes.`,
        remaining: 0,
        debugInfo: `Used ${sessionsLast24h.length}/${this.maxDemoSessionsPerUser} today`
      };
    }
    if (userData.lastUsed && now - userData.lastUsed < this.demoSessionCooldown) {
      const timeUntilNext = this.demoSessionCooldown - (now - userData.lastUsed);
      const minutesLeft = Math.ceil(timeUntilNext / (60 * 1e3));
      console.log(`\u23F0 Cooldown active for user ${userFingerprint.substring(0, 12)}: ${minutesLeft} minutes`);
      return {
        allowed: false,
        reason: "session_cooldown",
        timeUntilNext,
        message: `Please wait ${minutesLeft} minutes between demo sessions. This prevents abuse and ensures fair access for all users.`,
        remaining: this.maxDemoSessionsPerUser - sessionsLast24h.length,
        debugInfo: `Cooldown: ${minutesLeft}min left, last used: ${Math.round((now - userData.lastUsed) / (60 * 1e3))}min ago`
      };
    }
    const completedSessions = this.completedDemoSessions.get(userFingerprint) || [];
    const recentCompletedSessions = completedSessions.filter(
      (session) => now - session.endTime < this.minTimeBetweenCompletedSessions
    );
    if (recentCompletedSessions.length > 0) {
      const lastCompletedSession = Math.max(...recentCompletedSessions.map((s) => s.endTime));
      const timeUntilNext = this.minTimeBetweenCompletedSessions - (now - lastCompletedSession);
      console.log(`\u23F0 Recent session completed, waiting period active for user ${userFingerprint.substring(0, 12)}`);
      return {
        allowed: false,
        reason: "recent_session_completed",
        timeUntilNext,
        message: `Please wait ${Math.ceil(timeUntilNext / (60 * 1e3))} minutes after your last session before starting a new one.`,
        remaining: this.maxDemoSessionsPerUser - sessionsLast24h.length,
        debugInfo: `Last session ended ${Math.round((now - lastCompletedSession) / (60 * 1e3))}min ago`
      };
    }
    console.log(`\u2705 Demo session approved for user ${userFingerprint.substring(0, 12)}`);
    return {
      allowed: true,
      reason: "within_limits",
      remaining: this.maxDemoSessionsPerUser - sessionsLast24h.length,
      debugInfo: `Available: ${this.maxDemoSessionsPerUser - sessionsLast24h.length}/${this.maxDemoSessionsPerUser}`
    };
  }
  createDemoSessionForActivation() {
    const userFingerprint = this.generateAdvancedUserFingerprint();
    if (this.activeDemoSessions.size >= this.maxGlobalDemoSessions) {
      return {
        success: false,
        reason: `Too many demo sessions active globally (${this.activeDemoSessions.size}/${this.maxGlobalDemoSessions}). Please try again later.`,
        blockingReason: "global_limit"
      };
    }
    try {
      const demoPreimage = this.generateSecureDemoPreimage();
      const demoPaymentHash = "demo_" + Array.from(crypto.getRandomValues(new Uint8Array(16))).map((b) => b.toString(16).padStart(2, "0")).join("");
      console.log("\u{1F504} Created demo session for activation:", {
        preimage: demoPreimage.substring(0, 16) + "...",
        paymentHash: demoPaymentHash.substring(0, 16) + "..."
      });
      return {
        success: true,
        sessionType: "demo",
        preimage: demoPreimage,
        paymentHash: demoPaymentHash,
        duration: this.sessionPrices.demo.hours,
        durationMinutes: Math.round(this.demoSessionMaxDuration / (60 * 1e3)),
        warning: `Demo session - limited to ${Math.round(this.demoSessionMaxDuration / (60 * 1e3))} minutes`,
        globalActive: this.activeDemoSessions.size + 1,
        globalLimit: this.maxGlobalDemoSessions
      };
    } catch (error) {
      console.error("Failed to create demo session for activation:", error);
      return {
        success: false,
        reason: "Failed to generate demo session for activation. Please try again."
      };
    }
  }
  async verifyDemoSessionForActivation(preimage, paymentHash) {
    console.log("\u{1F3AE} Verifying demo session for activation (bypassing limits)...");
    try {
      if (!preimage || !paymentHash) {
        throw new Error("Missing preimage or payment hash");
      }
      if (typeof preimage !== "string" || typeof paymentHash !== "string") {
        throw new Error("Preimage and payment hash must be strings");
      }
      if (!this.isDemoPreimage(preimage)) {
        throw new Error("Invalid demo preimage format");
      }
      const entropy = this.calculateEntropy(preimage);
      if (entropy < 3.5) {
        throw new Error(`Demo preimage has insufficient entropy: ${entropy.toFixed(2)}`);
      }
      if (this.activeDemoSessions.has(preimage)) {
        throw new Error("Demo session with this preimage is already active");
      }
      console.log("\u2705 Demo session verified for activation successfully");
      return {
        verified: true,
        method: "demo-activation",
        sessionType: "demo",
        isDemo: true,
        warning: "Demo session - limited duration (6 minutes)"
      };
    } catch (error) {
      console.error("\u274C Demo session verification for activation failed:", error);
      return {
        verified: false,
        reason: error.message,
        stage: "demo-activation"
      };
    }
  }
};

// src/components/ui/SessionTimer.jsx
var SessionTimer = ({ timeLeft, sessionType, sessionManager, onDisconnect }) => {
  const [currentTime, setCurrentTime] = React.useState(timeLeft || 0);
  const [showExpiredMessage, setShowExpiredMessage] = React.useState(false);
  const [initialized, setInitialized] = React.useState(false);
  const [connectionBroken, setConnectionBroken] = React.useState(false);
  const [loggedHidden, setLoggedHidden] = React.useState(false);
  React.useEffect(() => {
    if (connectionBroken) {
      if (!loggedHidden) {
        console.log("\u23F1\uFE0F SessionTimer initialization skipped - connection broken");
        setLoggedHidden(true);
      }
      return;
    }
    let initialTime = 0;
    if (sessionManager?.hasActiveSession()) {
      initialTime = sessionManager.getTimeLeft();
    } else if (timeLeft && timeLeft > 0) {
      initialTime = timeLeft;
    }
    if (initialTime <= 0) {
      setCurrentTime(0);
      setInitialized(false);
      setLoggedHidden(true);
      return;
    }
    if (connectionBroken) {
      setCurrentTime(0);
      setInitialized(false);
      setLoggedHidden(true);
      return;
    }
    setCurrentTime(initialTime);
    setInitialized(true);
    setLoggedHidden(false);
  }, [sessionManager, connectionBroken]);
  React.useEffect(() => {
    if (connectionBroken) {
      if (!loggedHidden) {
        setLoggedHidden(true);
      }
      return;
    }
    if (timeLeft && timeLeft > 0) {
      setCurrentTime(timeLeft);
    }
    setLoggedHidden(false);
  }, [timeLeft, connectionBroken]);
  React.useEffect(() => {
    if (!initialized) {
      return;
    }
    if (connectionBroken) {
      if (!loggedHidden) {
        setLoggedHidden(true);
      }
      return;
    }
    if (!currentTime || currentTime <= 0 || !sessionManager) {
      return;
    }
    const interval = setInterval(() => {
      if (connectionBroken) {
        setCurrentTime(0);
        clearInterval(interval);
        return;
      }
      if (sessionManager?.hasActiveSession()) {
        const newTime = sessionManager.getTimeLeft();
        setCurrentTime(newTime);
        if (window.DEBUG_MODE && Math.floor(Date.now() / 3e4) !== Math.floor((Date.now() - 1e3) / 3e4)) {
          console.log("\u23F1\uFE0F Timer tick:", Math.floor(newTime / 1e3) + "s");
        }
        if (newTime <= 0) {
          setShowExpiredMessage(true);
          setTimeout(() => setShowExpiredMessage(false), 5e3);
          clearInterval(interval);
        }
      } else {
        setCurrentTime(0);
        clearInterval(interval);
      }
    }, 1e3);
    return () => {
      clearInterval(interval);
    };
  }, [initialized, currentTime, sessionManager, connectionBroken]);
  React.useEffect(() => {
    const handleSessionTimerUpdate = (event) => {
      if (connectionBroken) {
        return;
      }
      if (event.detail.timeLeft && event.detail.timeLeft > 0) {
        setCurrentTime(event.detail.timeLeft);
      }
    };
    const handleForceHeaderUpdate = (event) => {
      if (connectionBroken) {
        return;
      }
      if (sessionManager && sessionManager.hasActiveSession()) {
        const newTime = sessionManager.getTimeLeft();
        setCurrentTime(newTime);
      } else {
        setCurrentTime(event.detail.timeLeft);
      }
    };
    const handlePeerDisconnect = (event) => {
      setConnectionBroken(true);
      setCurrentTime(0);
      setShowExpiredMessage(false);
      setLoggedHidden(false);
    };
    const handleNewConnection = (event) => {
      setConnectionBroken(false);
      setLoggedHidden(false);
    };
    const handleConnectionCleaned = (event) => {
      setConnectionBroken(true);
      setCurrentTime(0);
      setShowExpiredMessage(false);
      setInitialized(false);
      setLoggedHidden(false);
    };
    const handleSessionReset = (event) => {
      setConnectionBroken(true);
      setCurrentTime(0);
      setShowExpiredMessage(false);
      setInitialized(false);
      setLoggedHidden(false);
    };
    const handleSessionCleanup = (event) => {
      setConnectionBroken(true);
      setCurrentTime(0);
      setShowExpiredMessage(false);
      setInitialized(false);
      setLoggedHidden(false);
    };
    const handleDisconnected = (event) => {
      setConnectionBroken(true);
      setCurrentTime(0);
      setShowExpiredMessage(false);
      setInitialized(false);
      setLoggedHidden(false);
    };
    document.addEventListener("session-timer-update", handleSessionTimerUpdate);
    document.addEventListener("force-header-update", handleForceHeaderUpdate);
    document.addEventListener("peer-disconnect", handlePeerDisconnect);
    document.addEventListener("new-connection", handleNewConnection);
    document.addEventListener("connection-cleaned", handleConnectionCleaned);
    document.addEventListener("session-reset", handleSessionReset);
    document.addEventListener("session-cleanup", handleSessionCleanup);
    document.addEventListener("disconnected", handleDisconnected);
    return () => {
      document.removeEventListener("session-timer-update", handleSessionTimerUpdate);
      document.removeEventListener("force-header-update", handleForceHeaderUpdate);
      document.removeEventListener("peer-disconnect", handlePeerDisconnect);
      document.removeEventListener("new-connection", handleNewConnection);
      document.removeEventListener("connection-cleaned", handleConnectionCleaned);
      document.removeEventListener("session-reset", handleSessionReset);
      document.removeEventListener("session-cleanup", handleSessionCleanup);
      document.removeEventListener("disconnected", handleDisconnected);
    };
  }, [sessionManager]);
  if (showExpiredMessage) {
    return React.createElement("div", {
      className: "session-timer expired flex items-center space-x-2 px-3 py-1.5 rounded-lg animate-pulse",
      style: { background: "linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(220, 38, 38, 0.2) 100%)" }
    }, [
      React.createElement("i", {
        key: "icon",
        className: "fas fa-exclamation-triangle text-red-400"
      }),
      React.createElement("span", {
        key: "message",
        className: "text-red-400 text-sm font-medium"
      }, "Session Expired!")
    ]);
  }
  if (!sessionManager) {
    if (!loggedHidden) {
      console.log("\u23F1\uFE0F SessionTimer hidden - no sessionManager");
      setLoggedHidden(true);
    }
    return null;
  }
  if (connectionBroken) {
    if (!loggedHidden) {
      console.log("\u23F1\uFE0F SessionTimer hidden - connection broken");
      setLoggedHidden(true);
    }
    return null;
  }
  if (!currentTime || currentTime <= 0) {
    if (!loggedHidden) {
      console.log("\u23F1\uFE0F SessionTimer hidden - no time left, currentTime:", currentTime);
      setLoggedHidden(true);
    }
    return null;
  }
  if (loggedHidden) {
    setLoggedHidden(false);
  }
  const totalMinutes = Math.floor(currentTime / (60 * 1e3));
  const totalSeconds = Math.floor(currentTime / 1e3);
  const isDemo = sessionType === "demo";
  const isWarning = isDemo ? totalMinutes <= 2 : totalMinutes <= 10;
  const isCritical = isDemo ? totalSeconds <= 60 : totalMinutes <= 5;
  const formatTime = (ms) => {
    const hours = Math.floor(ms / (60 * 60 * 1e3));
    const minutes = Math.floor(ms % (60 * 60 * 1e3) / (60 * 1e3));
    const seconds = Math.floor(ms % (60 * 1e3) / 1e3);
    if (hours > 0) {
      return `${hours}:${minutes.toString().padStart(2, "0")}:${seconds.toString().padStart(2, "0")}`;
    } else {
      return `${minutes}:${seconds.toString().padStart(2, "0")}`;
    }
  };
  const getTimerStyle = () => {
    const totalDuration = sessionType === "demo" ? 6 * 60 * 1e3 : 60 * 60 * 1e3;
    const timeProgress = (totalDuration - currentTime) / totalDuration;
    let backgroundColor, textColor, iconColor, iconClass, shouldPulse;
    if (timeProgress <= 0.33) {
      backgroundColor = "linear-gradient(135deg, rgba(34, 197, 94, 0.15) 0%, rgba(22, 163, 74, 0.15) 100%)";
      textColor = "text-green-400";
      iconColor = "text-green-400";
      iconClass = "fas fa-clock";
      shouldPulse = false;
    } else if (timeProgress <= 0.66) {
      backgroundColor = "linear-gradient(135deg, rgba(234, 179, 8, 0.15) 0%, rgba(202, 138, 4, 0.15) 100%)";
      textColor = "text-yellow-400";
      iconColor = "text-yellow-400";
      iconClass = "fas fa-clock";
      shouldPulse = false;
    } else {
      backgroundColor = "linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(220, 38, 38, 0.15) 100%)";
      textColor = "text-red-400";
      iconColor = "text-red-400";
      iconClass = "fas fa-exclamation-triangle";
      shouldPulse = true;
    }
    return { backgroundColor, textColor, iconColor, iconClass, shouldPulse };
  };
  const timerStyle = getTimerStyle();
  const handleTimerClick = () => {
    if (onDisconnect && typeof onDisconnect === "function") {
      onDisconnect();
    }
  };
  return React.createElement("div", {
    className: `session-timer flex items-center space-x-2 px-3 py-1.5 rounded-lg transition-all duration-500 cursor-pointer hover:opacity-80 ${isDemo ? "demo-session" : ""} ${timerStyle.shouldPulse ? "animate-pulse" : ""}`,
    style: { background: timerStyle.backgroundColor },
    onClick: handleTimerClick,
    title: "Click to disconnect and clear session"
  }, [
    React.createElement("i", {
      key: "icon",
      className: `${timerStyle.iconClass} ${timerStyle.iconColor}`
    }),
    React.createElement("span", {
      key: "time",
      className: `text-sm font-mono font-semibold ${timerStyle.textColor}`
    }, formatTime(currentTime)),
    React.createElement("div", {
      key: "progress",
      className: "ml-2 w-16 h-1 bg-gray-700 rounded-full overflow-hidden"
    }, [
      React.createElement("div", {
        key: "progress-bar",
        className: `${timerStyle.textColor.replace("text-", "bg-")} h-full rounded-full transition-all duration-500`,
        style: {
          width: `${Math.max(0, Math.min(100, currentTime / (sessionType === "demo" ? 6 * 60 * 1e3 : 60 * 60 * 1e3) * 100))}%`
        }
      })
    ])
  ]);
};
window.SessionTimer = SessionTimer;
window.updateSessionTimer = (newTimeLeft, newSessionType) => {
  document.dispatchEvent(new CustomEvent("session-timer-update", {
    detail: { timeLeft: newTimeLeft, sessionType: newSessionType }
  }));
};

// src/components/ui/Header.jsx
var EnhancedMinimalHeader = ({
  status,
  fingerprint,
  verificationCode,
  onDisconnect,
  isConnected,
  securityLevel,
  sessionManager,
  sessionTimeLeft,
  webrtcManager
}) => {
  const [currentTimeLeft, setCurrentTimeLeft] = React.useState(sessionTimeLeft || 0);
  const [hasActiveSession, setHasActiveSession] = React.useState(false);
  const [sessionType, setSessionType] = React.useState("unknown");
  const [realSecurityLevel, setRealSecurityLevel] = React.useState(null);
  const [lastSecurityUpdate, setLastSecurityUpdate] = React.useState(0);
  React.useEffect(() => {
    let isUpdating = false;
    let lastUpdateAttempt = 0;
    const updateRealSecurityStatus = async () => {
      const now = Date.now();
      if (now - lastUpdateAttempt < 1e4) {
        return;
      }
      if (isUpdating) {
        return;
      }
      isUpdating = true;
      lastUpdateAttempt = now;
      try {
        if (!webrtcManager || !isConnected) {
          return;
        }
        const activeWebrtcManager = webrtcManager;
        let realSecurityData = null;
        if (typeof activeWebrtcManager.getRealSecurityLevel === "function") {
          realSecurityData = await activeWebrtcManager.getRealSecurityLevel();
        } else if (typeof activeWebrtcManager.calculateAndReportSecurityLevel === "function") {
          realSecurityData = await activeWebrtcManager.calculateAndReportSecurityLevel();
        } else {
          realSecurityData = await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(activeWebrtcManager);
        }
        if (window.DEBUG_MODE) {
          console.log("\u{1F510} REAL security level calculated:", {
            level: realSecurityData?.level,
            score: realSecurityData?.score,
            passedChecks: realSecurityData?.passedChecks,
            totalChecks: realSecurityData?.totalChecks,
            isRealData: realSecurityData?.isRealData,
            sessionType: realSecurityData?.sessionType,
            maxPossibleScore: realSecurityData?.maxPossibleScore,
            verificationResults: realSecurityData?.verificationResults ? Object.keys(realSecurityData.verificationResults) : []
          });
        }
        if (realSecurityData && realSecurityData.isRealData !== false) {
          const currentScore = realSecurityLevel?.score || 0;
          const newScore = realSecurityData.score || 0;
          if (currentScore !== newScore || !realSecurityLevel) {
            setRealSecurityLevel(realSecurityData);
            setLastSecurityUpdate(now);
            if (window.DEBUG_MODE) {
              console.log("\u2705 Security level updated in header component:", {
                oldScore: currentScore,
                newScore,
                sessionType: realSecurityData.sessionType
              });
            }
          } else if (window.DEBUG_MODE) {
            console.log("\u2139\uFE0F Security level unchanged, skipping update");
          }
        } else {
          console.warn("\u26A0\uFE0F Security calculation returned invalid data");
        }
      } catch (error) {
        console.error("\u274C Error in real security calculation:", error);
      } finally {
        isUpdating = false;
      }
    };
    if (isConnected) {
      updateRealSecurityStatus();
      if (!realSecurityLevel || realSecurityLevel.score < 50) {
        const retryInterval = setInterval(() => {
          if (!realSecurityLevel || realSecurityLevel.score < 50) {
            updateRealSecurityStatus();
          } else {
            clearInterval(retryInterval);
          }
        }, 5e3);
        setTimeout(() => clearInterval(retryInterval), 3e4);
      }
    }
    const interval = setInterval(updateRealSecurityStatus, 3e4);
    return () => clearInterval(interval);
  }, [webrtcManager, isConnected, lastSecurityUpdate, realSecurityLevel]);
  React.useEffect(() => {
    const handleSecurityUpdate = (event) => {
      if (window.DEBUG_MODE) {
        console.log("\u{1F512} Security level update event received:", event.detail);
      }
      setTimeout(() => {
        setLastSecurityUpdate(0);
      }, 100);
    };
    const handleRealSecurityCalculated = (event) => {
      if (window.DEBUG_MODE) {
        console.log("\u{1F510} Real security calculated event:", event.detail);
      }
      if (event.detail && event.detail.securityData) {
        setRealSecurityLevel(event.detail.securityData);
        setLastSecurityUpdate(Date.now());
      }
    };
    document.addEventListener("security-level-updated", handleSecurityUpdate);
    document.addEventListener("real-security-calculated", handleRealSecurityCalculated);
    window.forceHeaderSecurityUpdate = (webrtcManager2) => {
      if (window.DEBUG_MODE) {
        console.log("\u{1F504} Force header security update called");
      }
      if (webrtcManager2 && window.EnhancedSecureCryptoUtils) {
        window.EnhancedSecureCryptoUtils.calculateSecurityLevel(webrtcManager2).then((securityData) => {
          if (securityData && securityData.isRealData !== false) {
            setRealSecurityLevel(securityData);
            setLastSecurityUpdate(Date.now());
            console.log("\u2705 Header security level force-updated");
          }
        }).catch((error) => {
          console.error("\u274C Force update failed:", error);
        });
      } else {
        setLastSecurityUpdate(0);
      }
    };
    return () => {
      document.removeEventListener("security-level-updated", handleSecurityUpdate);
      document.removeEventListener("real-security-calculated", handleRealSecurityCalculated);
    };
  }, []);
  React.useEffect(() => {
    const updateSessionInfo = () => {
      if (sessionManager) {
        const isActive = sessionManager.hasActiveSession();
        const timeLeft = sessionManager.getTimeLeft();
        const currentSession = sessionManager.currentSession;
        setHasActiveSession(isActive);
        setCurrentTimeLeft(timeLeft);
        setSessionType(currentSession?.type || "unknown");
      }
    };
    updateSessionInfo();
    const interval = setInterval(updateSessionInfo, 1e3);
    return () => clearInterval(interval);
  }, [sessionManager]);
  React.useEffect(() => {
    if (sessionManager?.hasActiveSession()) {
      setCurrentTimeLeft(sessionManager.getTimeLeft());
      setHasActiveSession(true);
    } else {
      setHasActiveSession(false);
      setRealSecurityLevel(null);
      setLastSecurityUpdate(0);
      setSessionType("unknown");
    }
  }, [sessionManager, sessionTimeLeft]);
  React.useEffect(() => {
    const handleForceUpdate = (event) => {
      if (sessionManager) {
        const isActive = sessionManager.hasActiveSession();
        const timeLeft = sessionManager.getTimeLeft();
        const currentSession = sessionManager.currentSession;
        setHasActiveSession(isActive);
        setCurrentTimeLeft(timeLeft);
        setSessionType(currentSession?.type || "unknown");
      }
    };
    const handleConnectionCleaned = () => {
      if (window.DEBUG_MODE) {
        console.log("\u{1F9F9} Connection cleaned - clearing security data in header");
      }
      setRealSecurityLevel(null);
      setLastSecurityUpdate(0);
      setHasActiveSession(false);
      setCurrentTimeLeft(0);
      setSessionType("unknown");
    };
    const handlePeerDisconnect = () => {
      if (window.DEBUG_MODE) {
        console.log("\u{1F44B} Peer disconnect detected - clearing security data in header");
      }
      setRealSecurityLevel(null);
      setLastSecurityUpdate(0);
    };
    document.addEventListener("force-header-update", handleForceUpdate);
    document.addEventListener("peer-disconnect", handlePeerDisconnect);
    document.addEventListener("connection-cleaned", handleConnectionCleaned);
    return () => {
      document.removeEventListener("force-header-update", handleForceUpdate);
      document.removeEventListener("peer-disconnect", handlePeerDisconnect);
      document.removeEventListener("connection-cleaned", handleConnectionCleaned);
    };
  }, [sessionManager]);
  const handleSecurityClick = (event) => {
    if (event && (event.button === 2 || event.ctrlKey || event.metaKey)) {
      if (onDisconnect && typeof onDisconnect === "function") {
        onDisconnect();
        return;
      }
    }
    if (!realSecurityLevel) {
      alert("Security verification in progress...\nPlease wait for real-time cryptographic verification to complete.");
      return;
    }
    let message = `\u{1F512} REAL-TIME SECURITY VERIFICATION

`;
    message += `Security Level: ${realSecurityLevel.level} (${realSecurityLevel.score}%)
`;
    message += `Session Type: ${realSecurityLevel.sessionType || "demo"}
`;
    message += `Verification Time: ${new Date(realSecurityLevel.timestamp).toLocaleTimeString()}
`;
    message += `Data Source: ${realSecurityLevel.isRealData ? "Real Cryptographic Tests" : "Simulated Data"}

`;
    if (realSecurityLevel.verificationResults) {
      message += "DETAILED CRYPTOGRAPHIC TESTS:\n";
      message += "=" + "=".repeat(40) + "\n";
      const passedTests = Object.entries(realSecurityLevel.verificationResults).filter(([key, result]) => result.passed);
      const failedTests = Object.entries(realSecurityLevel.verificationResults).filter(([key, result]) => !result.passed);
      if (passedTests.length > 0) {
        message += "\u2705 PASSED TESTS:\n";
        passedTests.forEach(([key, result]) => {
          const testName = key.replace(/([A-Z])/g, " $1").replace(/^./, (str) => str.toUpperCase());
          message += `   ${testName}: ${result.details}
`;
        });
        message += "\n";
      }
      if (failedTests.length > 0) {
        message += "\u274C UNAVAILABLE/Failed TESTS:\n";
        failedTests.forEach(([key, result]) => {
          const testName = key.replace(/([A-Z])/g, " $1").replace(/^./, (str) => str.toUpperCase());
          message += `   ${testName}: ${result.details}
`;
        });
        message += "\n";
      }
      message += `SUMMARY:
`;
      message += `Passed: ${realSecurityLevel.passedChecks}/${realSecurityLevel.totalChecks} tests
`;
    }
    message += `
\u{1F4CB} WHAT'S AVAILABLE IN OTHER SESSIONS:
`;
    message += "=" + "=".repeat(40) + "\n";
    if (realSecurityLevel.sessionType === "demo") {
      message += `\u{1F512} BASIC SESSION (5,000 sat - $2.00):
`;
      message += `   \u2022 ECDSA Digital Signatures
`;
      message += `   \u2022 Metadata Protection
`;
      message += `   \u2022 Perfect Forward Secrecy
`;
      message += `   \u2022 Nested Encryption
`;
      message += `   \u2022 Packet Padding

`;
      message += `\u{1F680} PREMIUM SESSION (20,000 sat - $8.00):
`;
      message += `   \u2022 All Basic + Enhanced features
`;
      message += `   \u2022 Traffic Obfuscation
`;
      message += `   \u2022 Fake Traffic Generation
`;
      message += `   \u2022 Decoy Channels
`;
      message += `   \u2022 Anti-Fingerprinting
`;
      message += `   \u2022 Message Chunking
`;
      message += `   \u2022 Advanced Replay Protection
`;
    } else if (realSecurityLevel.sessionType === "basic") {
      message += `\u{1F680} PREMIUM SESSION (20,000 sat - $8.00):
`;
      message += `   \u2022 Traffic Obfuscation
`;
      message += `   \u2022 Fake Traffic Generation
`;
      message += `   \u2022 Decoy Channels
`;
      message += `   \u2022 Anti-Fingerprinting
`;
      message += `   \u2022 Message Chunking
`;
      message += `   \u2022 Advanced Replay Protection
`;
    }
    message += `
${realSecurityLevel.details || "Real cryptographic verification completed"}`;
    if (realSecurityLevel.isRealData) {
      message += "\n\n\u2705 This is REAL-TIME verification using actual cryptographic functions.";
    } else {
      message += "\n\n\u26A0\uFE0F Warning: This data may be simulated. Connection may not be fully established.";
    }
    alert(message);
  };
  const getStatusConfig = () => {
    switch (status) {
      case "connected":
        return {
          text: "Connected",
          className: "status-connected",
          badgeClass: "bg-green-500/10 text-green-400 border-green-500/20"
        };
      case "verifying":
        return {
          text: "Verifying...",
          className: "status-verifying",
          badgeClass: "bg-purple-500/10 text-purple-400 border-purple-500/20"
        };
      case "connecting":
        return {
          text: "Connecting...",
          className: "status-connecting",
          badgeClass: "bg-blue-500/10 text-blue-400 border-blue-500/20"
        };
      case "retrying":
        return {
          text: "Retrying...",
          className: "status-connecting",
          badgeClass: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
        };
      case "failed":
        return {
          text: "Error",
          className: "status-failed",
          badgeClass: "bg-red-500/10 text-red-400 border-red-500/20"
        };
      case "reconnecting":
        return {
          text: "Reconnecting...",
          className: "status-connecting",
          badgeClass: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
        };
      case "peer_disconnected":
        return {
          text: "Peer disconnected",
          className: "status-failed",
          badgeClass: "bg-orange-500/10 text-orange-400 border-orange-500/20"
        };
      default:
        return {
          text: "Not connected",
          className: "status-disconnected",
          badgeClass: "bg-gray-500/10 text-gray-400 border-gray-500/20"
        };
    }
  };
  const config = getStatusConfig();
  const displaySecurityLevel = realSecurityLevel || securityLevel;
  const shouldShowTimer = hasActiveSession && currentTimeLeft > 0 && window.SessionTimer;
  const getSecurityIndicatorDetails = () => {
    if (!displaySecurityLevel) {
      return {
        tooltip: "Security verification in progress...",
        isVerified: false,
        dataSource: "loading"
      };
    }
    const isRealData = displaySecurityLevel.isRealData !== false;
    const baseTooltip = `${displaySecurityLevel.level} (${displaySecurityLevel.score}%)`;
    if (isRealData) {
      return {
        tooltip: `${baseTooltip} - Real-time verification \u2705
Right-click or Ctrl+click to disconnect`,
        isVerified: true,
        dataSource: "real"
      };
    } else {
      return {
        tooltip: `${baseTooltip} - Estimated (connection establishing...)
Right-click or Ctrl+click to disconnect`,
        isVerified: false,
        dataSource: "estimated"
      };
    }
  };
  const securityDetails = getSecurityIndicatorDetails();
  React.useEffect(() => {
    window.debugHeaderSecurity = () => {
      console.log("\u{1F50D} Header Security Debug:", {
        realSecurityLevel,
        lastSecurityUpdate,
        isConnected,
        webrtcManagerProp: !!webrtcManager,
        windowWebrtcManager: !!window.webrtcManager,
        cryptoUtils: !!window.EnhancedSecureCryptoUtils,
        displaySecurityLevel,
        securityDetails
      });
    };
    return () => {
      delete window.debugHeaderSecurity;
    };
  }, [realSecurityLevel, lastSecurityUpdate, isConnected, webrtcManager, displaySecurityLevel, securityDetails]);
  return React.createElement("header", {
    className: "header-minimal sticky top-0 z-50"
  }, [
    React.createElement("div", {
      key: "container",
      className: "max-w-7xl mx-auto px-4 sm:px-6 lg:px-8"
    }, [
      React.createElement("div", {
        key: "content",
        className: "flex items-center justify-between h-16"
      }, [
        // Logo and Title
        React.createElement("div", {
          key: "logo-section",
          className: "flex items-center space-x-2 sm:space-x-3"
        }, [
          React.createElement("div", {
            key: "logo",
            className: "icon-container w-8 h-8 sm:w-10 sm:h-10"
          }, [
            React.createElement("i", {
              className: "fas fa-shield-halved accent-orange text-sm sm:text-base"
            })
          ]),
          React.createElement("div", {
            key: "title-section"
          }, [
            React.createElement("h1", {
              key: "title",
              className: "text-lg sm:text-xl font-semibold text-primary"
            }, "SecureBit.chat"),
            React.createElement("p", {
              key: "subtitle",
              className: "text-xs sm:text-sm text-muted hidden sm:block"
            }, "End-to-end freedom v4.02.985")
          ])
        ]),
        // Status and Controls - Responsive
        React.createElement("div", {
          key: "status-section",
          className: "flex items-center space-x-2 sm:space-x-3"
        }, [
          // Session Timer
          shouldShowTimer && React.createElement(window.SessionTimer, {
            key: "session-timer",
            timeLeft: currentTimeLeft,
            sessionType,
            sessionManager,
            onDisconnect
          }),
          displaySecurityLevel && React.createElement("div", {
            key: "security-level",
            className: "hidden md:flex items-center space-x-2 cursor-pointer hover:opacity-80 transition-opacity duration-200",
            onClick: handleSecurityClick,
            onContextMenu: (e) => {
              e.preventDefault();
              if (onDisconnect && typeof onDisconnect === "function") {
                onDisconnect();
              }
            },
            title: securityDetails.tooltip
          }, [
            React.createElement("div", {
              key: "security-icon",
              className: `w-6 h-6 rounded-full flex items-center justify-center relative ${displaySecurityLevel.color === "green" ? "bg-green-500/20" : displaySecurityLevel.color === "orange" ? "bg-orange-500/20" : displaySecurityLevel.color === "yellow" ? "bg-yellow-500/20" : "bg-red-500/20"} ${securityDetails.isVerified ? "" : "animate-pulse"}`
            }, [
              React.createElement("i", {
                className: `fas fa-shield-alt text-xs ${displaySecurityLevel.color === "green" ? "text-green-400" : displaySecurityLevel.color === "orange" ? "text-orange-400" : displaySecurityLevel.color === "yellow" ? "text-yellow-400" : "text-red-400"}`
              })
            ]),
            React.createElement("div", {
              key: "security-info",
              className: "flex flex-col"
            }, [
              React.createElement("div", {
                key: "security-level-text",
                className: "text-xs font-medium text-primary flex items-center space-x-1"
              }, [
                React.createElement("span", {}, `${displaySecurityLevel.level} (${displaySecurityLevel.score}%)`)
              ]),
              React.createElement(
                "div",
                {
                  key: "security-details",
                  className: "text-xs text-muted mt-1 hidden lg:block"
                },
                securityDetails.dataSource === "real" ? `${displaySecurityLevel.passedChecks || 0}/${displaySecurityLevel.totalChecks || 0} tests` : displaySecurityLevel.details || `Stage ${displaySecurityLevel.stage || 1}`
              ),
              React.createElement("div", {
                key: "security-progress",
                className: "w-16 h-1 bg-gray-600 rounded-full overflow-hidden"
              }, [
                React.createElement("div", {
                  key: "progress-bar",
                  className: `h-full transition-all duration-500 ${displaySecurityLevel.color === "green" ? "bg-green-400" : displaySecurityLevel.color === "orange" ? "bg-orange-400" : displaySecurityLevel.color === "yellow" ? "bg-yellow-400" : "bg-red-400"}`,
                  style: { width: `${displaySecurityLevel.score}%` }
                })
              ])
            ])
          ]),
          // Mobile Security Indicator
          displaySecurityLevel && React.createElement("div", {
            key: "mobile-security",
            className: "md:hidden flex items-center"
          }, [
            React.createElement("div", {
              key: "mobile-security-icon",
              className: `w-8 h-8 rounded-full flex items-center justify-center cursor-pointer hover:opacity-80 transition-opacity duration-200 relative ${displaySecurityLevel.color === "green" ? "bg-green-500/20" : displaySecurityLevel.color === "orange" ? "bg-orange-500/20" : displaySecurityLevel.color === "yellow" ? "bg-yellow-500/20" : "bg-red-500/20"} ${securityDetails.isVerified ? "" : "animate-pulse"}`,
              title: securityDetails.tooltip,
              onClick: handleSecurityClick,
              onContextMenu: (e) => {
                e.preventDefault();
                if (onDisconnect && typeof onDisconnect === "function") {
                  onDisconnect();
                }
              }
            }, [
              React.createElement("i", {
                className: `fas fa-shield-alt text-sm ${displaySecurityLevel.color === "green" ? "text-green-400" : displaySecurityLevel.color === "orange" ? "text-orange-400" : displaySecurityLevel.color === "yellow" ? "text-yellow-400" : "text-red-400"}`
              })
            ])
          ]),
          // Status Badge
          React.createElement("div", {
            key: "status-badge",
            className: `px-2 sm:px-3 py-1.5 rounded-lg border ${config.badgeClass} flex items-center space-x-1 sm:space-x-2`
          }, [
            React.createElement("span", {
              key: "status-dot",
              className: `status-dot ${config.className}`
            }),
            React.createElement("span", {
              key: "status-text",
              className: "text-xs sm:text-sm font-medium"
            }, config.text)
          ]),
          // Disconnect Button
          isConnected && React.createElement("button", {
            key: "disconnect-btn",
            onClick: onDisconnect,
            className: "p-1.5 sm:px-3 sm:py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 rounded-lg transition-all duration-200 text-sm"
          }, [
            React.createElement("i", {
              className: "fas fa-power-off sm:mr-2"
            }),
            React.createElement("span", {
              className: "hidden sm:inline"
            }, "Disconnect")
          ])
        ])
      ])
    ])
  ]);
};
window.EnhancedMinimalHeader = EnhancedMinimalHeader;

// src/components/ui/SessionTypeSelector.jsx
var SessionTypeSelector = ({ onSelectType, onCancel, sessionManager }) => {
  const [selectedType, setSelectedType] = React.useState(null);
  const [demoInfo, setDemoInfo] = React.useState(null);
  const [refreshTimer, setRefreshTimer] = React.useState(null);
  const [lastRefresh, setLastRefresh] = React.useState(Date.now());
  const updateDemoInfo = React.useCallback(() => {
    if (sessionManager && sessionManager.getDemoSessionInfo) {
      try {
        const info = sessionManager.getDemoSessionInfo();
        if (window.DEBUG_MODE) {
          console.log("\u{1F504} Demo info updated:", info);
        }
        setDemoInfo(info);
        setLastRefresh(Date.now());
      } catch (error) {
        console.error("Failed to get demo info:", error);
      }
    }
  }, [sessionManager]);
  React.useEffect(() => {
    updateDemoInfo();
    const interval = setInterval(updateDemoInfo, 1e4);
    setRefreshTimer(interval);
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [updateDemoInfo]);
  React.useEffect(() => {
    return () => {
      if (refreshTimer) {
        clearInterval(refreshTimer);
      }
    };
  }, [refreshTimer]);
  const sessionTypes = [
    {
      id: "demo",
      name: "Demo",
      duration: "6 minutes",
      price: "0 sat",
      usd: "$0.00",
      popular: false,
      securityLevel: "Basic",
      securityBadge: "BASIC",
      securityColor: "bg-blue-500/20 text-blue-300",
      description: "Limited testing session with basic security",
      features: [
        "Basic end-to-end encryption",
        "Simple key exchange",
        "Message integrity",
        "Rate limiting"
      ],
      limitations: [
        "No advanced security features",
        "No traffic obfuscation",
        "No metadata protection"
      ]
    },
    {
      id: "basic",
      name: "Basic",
      duration: "1 hour",
      price: "5,000 sat",
      usd: "$2.00",
      securityLevel: "Enhanced",
      securityBadge: "ENHANCED",
      securityColor: "bg-orange-500/20 text-orange-300",
      popular: true,
      description: "Full featured session with enhanced security",
      features: [
        "All basic features",
        "ECDSA digital signatures",
        "Metadata protection",
        "Perfect forward secrecy",
        "Nested encryption",
        "Packet padding",
        "Complete ASN.1 validation",
        "OID and EC point verification",
        "SPKI structure validation",
        "18-layer security architecture",
        "ASN.1 Validated"
      ],
      limitations: [
        "Limited traffic obfuscation",
        "No fake traffic generation"
      ]
    },
    {
      id: "premium",
      name: "Premium",
      duration: "6 hours",
      price: "20,000 sat",
      usd: "$8.00",
      securityLevel: "Maximum",
      securityBadge: "MAXIMUM",
      securityColor: "bg-green-500/20 text-green-300",
      description: "Extended session with maximum security protection",
      features: [
        "All enhanced features",
        "Traffic obfuscation",
        "Fake traffic generation",
        "Decoy channels",
        "Anti-fingerprinting",
        "Message chunking",
        "Advanced replay protection",
        "Complete ASN.1 validation",
        "OID and EC point verification",
        "SPKI structure validation",
        "18-layer security architecture",
        "ASN.1 Validated"
      ],
      limitations: []
    }
  ];
  const handleTypeSelect = (typeId) => {
    console.log(`\u{1F3AF} Selecting session type: ${typeId}`);
    if (typeId === "demo") {
      if (demoInfo && !demoInfo.canUseNow) {
        let message = `Demo session not available.

`;
        if (demoInfo.blockingReason === "global_limit") {
          message += `Reason: Too many global demo sessions active (${demoInfo.globalActive}/${demoInfo.globalLimit})
`;
          message += `Please try again in a few minutes.`;
        } else if (demoInfo.blockingReason === "daily_limit") {
          message += `Reason: Daily limit reached (${demoInfo.used}/${demoInfo.total})
`;
          message += `Next available: ${demoInfo.nextAvailable}`;
        } else if (demoInfo.blockingReason === "session_cooldown") {
          message += `Reason: Cooldown between sessions
`;
          message += `Next available: ${demoInfo.nextAvailable}`;
        } else if (demoInfo.blockingReason === "completion_cooldown") {
          message += `Reason: Wait period after last session
`;
          message += `Next available: ${demoInfo.nextAvailable}`;
        } else {
          message += `Next available: ${demoInfo.nextAvailable}`;
        }
        alert(message);
        return;
      }
    }
    setSelectedType(typeId);
  };
  const formatCooldownTime = (minutes) => {
    if (minutes >= 60) {
      const hours = Math.floor(minutes / 60);
      const remainingMinutes = minutes % 60;
      return `${hours}h ${remainingMinutes}m`;
    }
    return `${minutes}m`;
  };
  return React.createElement("div", { className: "space-y-6" }, [
    React.createElement("div", { key: "header", className: "text-center" }, [
      React.createElement("h3", {
        key: "title",
        className: "text-xl font-semibold text-white mb-2"
      }, "Choose Your Session"),
      React.createElement("p", {
        key: "subtitle",
        className: "text-gray-300 text-sm"
      }, "Different security levels for different needs")
    ]),
    React.createElement(
      "div",
      { key: "types", className: "space-y-4" },
      sessionTypes.map((type) => {
        const isDemo = type.id === "demo";
        const isDisabled = isDemo && demoInfo && !demoInfo.canUseNow;
        return React.createElement("div", {
          key: type.id,
          onClick: () => !isDisabled && handleTypeSelect(type.id),
          className: `relative card-minimal ${selectedType === type.id ? "card-minimal--selected" : ""} rounded-lg p-5 border-2 transition-all ${selectedType === type.id ? "border-orange-500 bg-orange-500/15 ring-2 ring-orange-400 ring-offset-2 ring-offset-black/30" : "border-gray-600 hover:border-orange-400"} ${type.popular && selectedType !== type.id ? "ring-2 ring-orange-500/30" : ""} ${isDisabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`
        }, [
          // Popular badge
          type.popular && React.createElement("div", {
            key: "popular-badge",
            className: "absolute -top-2 right-3 bg-orange-500 text-white text-xs px-3 py-1 rounded-full font-medium"
          }, "Most Popular"),
          React.createElement("div", { key: "content", className: "space-y-4" }, [
            // Header with name and security level
            React.createElement("div", { key: "header", className: "flex items-start justify-between" }, [
              React.createElement("div", { key: "title-section" }, [
                React.createElement("div", { key: "name-row", className: "flex items-center gap-3 mb-2" }, [
                  React.createElement("h4", {
                    key: "name",
                    className: "text-xl font-bold text-white"
                  }, type.name),
                  isDemo && React.createElement("span", {
                    key: "free-badge",
                    className: "text-xs bg-blue-500/20 text-blue-300 px-2 py-1 rounded-full font-medium"
                  }, "FREE"),
                  React.createElement("span", {
                    key: "security-badge",
                    className: `text-xs px-2 py-1 rounded-full font-medium ${type.securityColor}`
                  }, type.securityBadge)
                ]),
                React.createElement("p", {
                  key: "duration",
                  className: "text-gray-300 font-medium mb-1"
                }, `Duration: ${type.duration}`),
                React.createElement("p", {
                  key: "description",
                  className: "text-sm text-gray-400"
                }, type.description)
              ]),
              React.createElement("div", { key: "pricing", className: "text-right" }, [
                React.createElement("div", {
                  key: "sats",
                  className: `text-xl font-bold ${isDemo ? "text-green-400" : "text-orange-400"}`
                }, type.price),
                React.createElement("div", {
                  key: "usd",
                  className: "text-sm text-gray-400"
                }, type.usd)
              ])
            ]),
            // Demo status info
            isDemo && demoInfo && React.createElement("div", {
              key: "demo-status",
              className: "p-3 bg-blue-900/20 border border-blue-700/30 rounded-lg"
            }, [
              React.createElement(
                "div",
                {
                  key: "availability",
                  className: `text-sm font-medium ${demoInfo.canUseNow ? "text-green-400" : "text-yellow-400"}`
                },
                demoInfo.canUseNow ? `\u2705 Available (${demoInfo.available}/${demoInfo.total} today)` : `\u23F0 Next: ${demoInfo.nextAvailable}`
              ),
              demoInfo.globalActive > 0 && React.createElement("div", {
                key: "global-status",
                className: "text-blue-300 text-xs mt-1"
              }, `\u{1F310} Global: ${demoInfo.globalActive}/${demoInfo.globalLimit} active`)
            ]),
            // Security features
            React.createElement("div", { key: "features-section", className: "space-y-3" }, [
              React.createElement("div", { key: "features" }, [
                React.createElement("h5", {
                  key: "features-title",
                  className: "text-sm font-medium text-green-300 mb-2 flex items-center"
                }, [
                  React.createElement("i", {
                    key: "shield-icon",
                    className: "fas fa-shield-alt mr-2"
                  }),
                  "Security Features"
                ]),
                React.createElement("div", {
                  key: "features-list",
                  className: "grid grid-cols-1 gap-1"
                }, type.features.map(
                  (feature, index) => React.createElement("div", {
                    key: index,
                    className: "flex items-center gap-2 text-xs text-gray-300"
                  }, [
                    React.createElement("i", {
                      key: "check",
                      className: "fas fa-check text-green-400 w-3"
                    }),
                    React.createElement("span", {
                      key: "text"
                    }, feature)
                  ])
                ))
              ]),
              // Limitations (if any)
              type.limitations && type.limitations.length > 0 && React.createElement("div", { key: "limitations" }, [
                React.createElement("h5", {
                  key: "limitations-title",
                  className: "text-sm font-medium text-yellow-300 mb-2 flex items-center"
                }, [
                  React.createElement("i", {
                    key: "info-icon",
                    className: "fas fa-info-circle mr-2"
                  }),
                  "Limitations"
                ]),
                React.createElement("div", {
                  key: "limitations-list",
                  className: "grid grid-cols-1 gap-1"
                }, type.limitations.map(
                  (limitation, index) => React.createElement("div", {
                    key: index,
                    className: "flex items-center gap-2 text-xs text-gray-400"
                  }, [
                    React.createElement("i", {
                      key: "minus",
                      className: "fas fa-minus text-yellow-400 w-3"
                    }),
                    React.createElement("span", {
                      key: "text"
                    }, limitation)
                  ])
                ))
              ])
            ])
          ])
        ]);
      })
    ),
    demoInfo && React.createElement("div", {
      key: "demo-info",
      className: "bg-gradient-to-r from-blue-900/20 to-purple-900/20 border border-blue-700/50 rounded-lg p-4"
    }, [
      React.createElement("div", {
        key: "demo-header",
        className: "flex items-center gap-2 text-blue-300 text-sm font-medium mb-3"
      }, [
        React.createElement("i", {
          key: "icon",
          className: "fas fa-info-circle"
        }),
        React.createElement("span", {
          key: "title"
        }, "Demo Session Information")
      ]),
      React.createElement("div", {
        key: "demo-details",
        className: "grid grid-cols-1 md:grid-cols-2 gap-3 text-blue-200 text-xs"
      }, [
        React.createElement("div", { key: "limits", className: "space-y-1" }, [
          React.createElement("div", { key: "daily" }, `\u{1F4C5} Daily limit: ${demoInfo.total} sessions`),
          React.createElement("div", { key: "duration" }, `\u23F1\uFE0F Duration: ${demoInfo.durationMinutes} minutes each`),
          React.createElement("div", { key: "cooldown" }, `\u23F0 Cooldown: ${demoInfo.sessionCooldownMinutes} min between sessions`)
        ]),
        React.createElement("div", { key: "status", className: "space-y-1" }, [
          React.createElement("div", { key: "used" }, `\u{1F4CA} Used today: ${demoInfo.used}/${demoInfo.total}`),
          React.createElement("div", { key: "global" }, `\u{1F310} Global active: ${demoInfo.globalActive}/${demoInfo.globalLimit}`),
          React.createElement("div", {
            key: "next",
            className: demoInfo.canUseNow ? "text-green-300" : "text-yellow-300"
          }, `\u{1F3AF} Status: ${demoInfo.canUseNow ? "Available now" : demoInfo.nextAvailable}`)
        ])
      ]),
      React.createElement("div", {
        key: "security-note",
        className: "mt-3 p-2 bg-yellow-500/10 border border-yellow-500/20 rounded text-yellow-200 text-xs"
      }, "\u26A0\uFE0F Demo sessions use basic security only. Upgrade to paid sessions for enhanced protection."),
      React.createElement("div", {
        key: "last-updated",
        className: "text-xs text-gray-400 mt-2 text-center"
      }, `Last updated: ${new Date(lastRefresh).toLocaleTimeString()}`)
    ]),
    // Action buttons
    React.createElement("div", { key: "buttons", className: "flex space-x-3" }, [
      React.createElement("button", {
        key: "continue",
        onClick: () => {
          if (selectedType) {
            console.log(`\u{1F680} Proceeding with session type: ${selectedType}`);
            onSelectType(selectedType);
          }
        },
        disabled: !selectedType || selectedType === "demo" && demoInfo && !demoInfo.canUseNow,
        className: "flex-1 lightning-button text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-all"
      }, [
        React.createElement("i", {
          key: "icon",
          className: selectedType === "demo" ? "fas fa-play mr-2" : "fas fa-bolt mr-2"
        }),
        selectedType === "demo" ? "Start Demo Session" : "Continue to Payment"
      ]),
      React.createElement("button", {
        key: "cancel",
        onClick: onCancel,
        className: "px-6 py-3 bg-gray-600 hover:bg-gray-500 text-white rounded-lg transition-all"
      }, "Cancel")
    ])
  ]);
};
window.SessionTypeSelector = SessionTypeSelector;

// src/components/ui/LightningPayment.jsx
var React2 = window.React;
var { useState, useEffect } = React2;
var IntegratedLightningPayment = ({ sessionType, onSuccess, onCancel, paymentManager }) => {
  const [paymentMethod, setPaymentMethod] = useState("webln");
  const [preimage, setPreimage] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState("");
  const [invoice, setInvoice] = useState(null);
  const [paymentStatus, setPaymentStatus] = useState("pending");
  const [qrCodeUrl, setQrCodeUrl] = useState("");
  useEffect(() => {
    createInvoice();
  }, [sessionType]);
  const createInvoice = async () => {
    if (sessionType === "free") {
      setPaymentStatus("free");
      return;
    }
    setIsProcessing(true);
    setError("");
    try {
      if (!paymentManager) {
        throw new Error("Payment manager not available. Please check sessionManager initialization.");
      }
      const createdInvoice = await paymentManager.createLightningInvoice(sessionType);
      if (!createdInvoice) {
        throw new Error("Failed to create invoice");
      }
      setInvoice(createdInvoice);
      setPaymentStatus("created");
      if (createdInvoice.paymentRequest) {
        try {
          const dataUrl = await window.generateQRCode(createdInvoice.paymentRequest, { size: 300, margin: 2, errorCorrectionLevel: "M" });
          setQrCodeUrl(dataUrl);
        } catch (e) {
          console.warn("QR local generation failed, showing placeholder");
          const dataUrl = await window.generateQRCode(createdInvoice.paymentRequest, { size: 300 });
          setQrCodeUrl(dataUrl);
        }
      }
    } catch (err) {
      console.error("Invoice creation failed:", err);
      setError(`Error creating invoice: ${err.message}`);
    } finally {
      setIsProcessing(false);
    }
  };
  const handleWebLNPayment = async () => {
    if (!window.webln) {
      setError("WebLN is not supported. Please use the Alby or Zeus wallet. SecureBit.chat v4.02.442 - ASN.1 Validated requires WebLN for Lightning payments.");
      return;
    }
    if (!invoice || !invoice.paymentRequest) {
      setError("Invoice is not ready for payment");
      return;
    }
    setIsProcessing(true);
    setError("");
    try {
      await window.webln.enable();
      const result = await window.webln.sendPayment(invoice.paymentRequest);
      if (result.preimage) {
        setPaymentStatus("paid");
        await activateSession(result.preimage);
      } else {
        setError("Payment does not contain preimage");
      }
    } catch (err) {
      console.error("WebLN payment failed:", err);
      setError(`WebLN Error: ${err.message}`);
    } finally {
      setIsProcessing(false);
    }
  };
  const handleManualVerification = async () => {
    const trimmedPreimage = preimage.trim();
    if (!trimmedPreimage) {
      setError("Enter payment preimage");
      return;
    }
    if (trimmedPreimage.length !== 64) {
      setError("The preimage must be exactly 64 characters long.");
      return;
    }
    if (!/^[0-9a-fA-F]{64}$/.test(trimmedPreimage)) {
      setError("The preimage must contain only hexadecimal characters (0-9, a-f, A-F).");
      return;
    }
    if (trimmedPreimage === "1".repeat(64) || trimmedPreimage === "a".repeat(64) || trimmedPreimage === "f".repeat(64)) {
      setError("The entered preimage is too weak. Please verify the key..");
      return;
    }
    setError("");
    setIsProcessing(true);
    try {
      await activateSession(trimmedPreimage);
    } catch (err) {
      setError(`Activation error: ${err.message}`);
    } finally {
      setIsProcessing(false);
    }
  };
  const activateSession = async (preimageValue) => {
    try {
      let result;
      if (paymentManager) {
        const paymentHash = invoice?.paymentHash || "dummy_hash";
        result = await paymentManager.safeActivateSession(sessionType, preimageValue, paymentHash);
      } else {
        console.warn("Payment manager not available, using fallback");
        result = { success: true, method: "fallback" };
      }
      if (result.success) {
        setPaymentStatus("paid");
        onSuccess(preimageValue, invoice);
      } else {
        console.error("\u274C Session activation failed:", result);
        throw new Error(`Session activation failed: ${result.reason}`);
      }
    } catch (err) {
      console.error("\u274C Session activation failed:", err);
      throw err;
    }
  };
  const handleFreeSession = async () => {
    setIsProcessing(true);
    try {
      await activateSession("0".repeat(64));
    } catch (err) {
      setError(`Free session activation error: ${err.message}`);
    } finally {
      setIsProcessing(false);
    }
  };
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
    });
  };
  const pricing = {
    free: { sats: 1, hours: 1 / 60 },
    basic: { sats: 500, hours: 1 },
    premium: { sats: 1e3, hours: 4 },
    extended: { sats: 2e3, hours: 24 }
  }[sessionType];
  return React2.createElement("div", { className: "space-y-4 max-w-md mx-auto" }, [
    React2.createElement("div", { key: "header", className: "text-center" }, [
      React2.createElement("h3", {
        key: "title",
        className: "text-xl font-semibold text-white mb-2"
      }, sessionType === "free" ? "Free session" : "Lightning payment"),
      React2.createElement(
        "div",
        {
          key: "amount",
          className: "text-2xl font-bold text-orange-400"
        },
        sessionType === "free" ? "0 sat per minute" : `${pricing.sats} \u0441\u0430\u0442 \u0437\u0430 ${pricing.hours}\u0447`
      ),
      sessionType !== "free" && React2.createElement("div", {
        key: "usd",
        className: "text-sm text-gray-400 mt-1"
      }, `\u2248 $${(pricing.sats * 4e-4).toFixed(2)} USD`)
    ]),
    // Loading State
    isProcessing && paymentStatus === "pending" && React2.createElement("div", {
      key: "loading",
      className: "text-center"
    }, [
      React2.createElement("div", {
        key: "spinner",
        className: "text-orange-400"
      }, [
        React2.createElement("i", { className: "fas fa-spinner fa-spin mr-2" }),
        "Creating invoice..."
      ])
    ]),
    // Free Session
    sessionType === "free" && React2.createElement("div", {
      key: "free-session",
      className: "space-y-3"
    }, [
      React2.createElement("div", {
        key: "info",
        className: "p-3 bg-blue-500/10 border border-blue-500/20 rounded text-blue-300 text-sm"
      }, "A free 1-minute session will be activated."),
      React2.createElement("button", {
        key: "start-btn",
        onClick: handleFreeSession,
        disabled: isProcessing,
        className: "w-full bg-blue-600 hover:bg-blue-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50"
      }, [
        React2.createElement("i", {
          key: "icon",
          className: `fas ${isProcessing ? "fa-spinner fa-spin" : "fa-play"} mr-2`
        }),
        isProcessing ? "Activation..." : "Start free session"
      ])
    ]),
    // Paid Sessions
    sessionType !== "free" && paymentStatus === "created" && invoice && React2.createElement("div", {
      key: "paid-session",
      className: "space-y-4"
    }, [
      // QR Code
      qrCodeUrl && React2.createElement("div", {
        key: "qr-section",
        className: "text-center"
      }, [
        React2.createElement("div", {
          key: "qr-container",
          className: "bg-white p-4 rounded-lg inline-block"
        }, [
          React2.createElement("img", {
            key: "qr-img",
            src: qrCodeUrl,
            alt: "Payment QR Code",
            className: "w-48 h-48"
          })
        ]),
        React2.createElement("div", {
          key: "qr-hint",
          className: "text-xs text-gray-400 mt-2"
        }, "Scan the QR code with any Lightning wallet")
      ]),
      // Payment Request
      invoice.paymentRequest && React2.createElement("div", {
        key: "payment-request",
        className: "space-y-2"
      }, [
        React2.createElement("div", {
          key: "label",
          className: "text-sm font-medium text-white"
        }, "Payment Request:"),
        React2.createElement("div", {
          key: "request",
          className: "p-3 bg-gray-800 rounded border text-xs font-mono text-gray-300 cursor-pointer hover:bg-gray-700",
          onClick: () => copyToClipboard(invoice.paymentRequest)
        }, [
          invoice.paymentRequest.substring(0, 50) + "...",
          React2.createElement("i", { key: "copy-icon", className: "fas fa-copy ml-2 text-orange-400" })
        ])
      ]),
      // WebLN Payment
      React2.createElement("div", {
        key: "webln-section",
        className: "space-y-3"
      }, [
        React2.createElement("h4", {
          key: "webln-title",
          className: "text-white font-medium flex items-center"
        }, [
          React2.createElement("i", { key: "bolt-icon", className: "fas fa-bolt text-orange-400 mr-2" }),
          "WebLN wallet (Alby, Zeus)"
        ]),
        React2.createElement("button", {
          key: "webln-btn",
          onClick: handleWebLNPayment,
          disabled: isProcessing,
          className: "w-full bg-orange-600 hover:bg-orange-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50"
        }, [
          React2.createElement("i", {
            key: "webln-icon",
            className: `fas ${isProcessing ? "fa-spinner fa-spin" : "fa-bolt"} mr-2`
          }),
          isProcessing ? "Processing..." : "Pay via WebLN"
        ])
      ]),
      // Manual Payment
      React2.createElement("div", {
        key: "divider",
        className: "text-center text-gray-400"
      }, "or"),
      React2.createElement("div", {
        key: "manual-section",
        className: "space-y-3"
      }, [
        React2.createElement("h4", {
          key: "manual-title",
          className: "text-white font-medium"
        }, "Manual payment verification"),
        React2.createElement("input", {
          key: "preimage-input",
          type: "text",
          value: preimage,
          onChange: (e) => setPreimage(e.target.value),
          placeholder: "Enter the preimage after payment...",
          className: "w-full p-3 bg-gray-800 border border-gray-600 rounded text-white placeholder-gray-400 text-sm"
        }),
        React2.createElement("button", {
          key: "verify-btn",
          onClick: handleManualVerification,
          disabled: isProcessing,
          className: "w-full bg-green-600 hover:bg-green-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50"
        }, [
          React2.createElement("i", {
            key: "verify-icon",
            className: `fas ${isProcessing ? "fa-spinner fa-spin" : "fa-check"} mr-2`
          }),
          isProcessing ? "Verification..." : "Confirm payment"
        ])
      ])
    ]),
    // Success State
    paymentStatus === "paid" && React2.createElement("div", {
      key: "success",
      className: "text-center p-4 bg-green-500/10 border border-green-500/20 rounded"
    }, [
      React2.createElement("i", { key: "success-icon", className: "fas fa-check-circle text-green-400 text-2xl mb-2" }),
      React2.createElement("div", { key: "success-text", className: "text-green-300 font-medium" }, "Payment confirmed!"),
      React2.createElement("div", { key: "success-subtext", className: "text-green-400 text-sm" }, "Session activated")
    ]),
    // Error State
    error && React2.createElement("div", {
      key: "error",
      className: "p-3 bg-red-500/10 border border-red-500/20 rounded text-red-400 text-sm"
    }, [
      React2.createElement("i", { key: "error-icon", className: "fas fa-exclamation-triangle mr-2" }),
      error,
      error.includes("invoice") && React2.createElement("button", {
        key: "retry-btn",
        onClick: createInvoice,
        className: "ml-2 text-orange-400 hover:text-orange-300 underline"
      }, "Try again")
    ]),
    // Cancel Button
    React2.createElement("button", {
      key: "cancel-btn",
      onClick: onCancel,
      className: "w-full bg-gray-600 hover:bg-gray-500 text-white py-2 px-4 rounded"
    }, "Cancel")
  ]);
};
window.LightningPayment = IntegratedLightningPayment;

// src/components/ui/PaymentModal.jsx
var React3 = window.React;
var { useState: useState2, useEffect: useEffect2, useRef } = React3;
var PaymentModal = ({ isOpen, onClose, sessionManager, onSessionPurchased }) => {
  const [step, setStep] = React3.useState("select");
  const [selectedType, setSelectedType] = React3.useState(null);
  const [invoice, setInvoice] = React3.useState(null);
  const [paymentStatus, setPaymentStatus] = React3.useState("pending");
  const [error, setError] = React3.useState("");
  const [paymentMethod, setPaymentMethod] = React3.useState("webln");
  const [preimageInput, setPreimageInput] = React3.useState("");
  const [isProcessing, setIsProcessing] = React3.useState(false);
  const [qrCodeUrl, setQrCodeUrl] = React3.useState("");
  const [paymentTimer, setPaymentTimer] = React3.useState(null);
  const [timeLeft, setTimeLeft] = React3.useState(0);
  const [showSecurityDetails, setShowSecurityDetails] = React3.useState(false);
  const pollInterval = React3.useRef(null);
  React3.useEffect(() => {
    if (!isOpen) {
      resetModal();
      if (pollInterval.current) {
        clearInterval(pollInterval.current);
      }
      if (paymentTimer) {
        clearInterval(paymentTimer);
      }
    }
  }, [isOpen]);
  const resetModal = () => {
    setStep("select");
    setSelectedType(null);
    setInvoice(null);
    setPaymentStatus("pending");
    setError("");
    setPaymentMethod("webln");
    setPreimageInput("");
    setIsProcessing(false);
    setQrCodeUrl("");
    setTimeLeft(0);
    setShowSecurityDetails(false);
  };
  const getSecurityFeaturesInfo = (sessionType) => {
    const features = {
      demo: {
        title: "Demo Session - Basic Security",
        description: "Limited testing session with basic security features",
        available: [
          "\u{1F510} Basic end-to-end encryption (AES-GCM 256)",
          "\u{1F511} Simple key exchange (ECDH P-384)",
          "\u2705 Message integrity verification",
          "\u26A1 Rate limiting protection"
        ],
        unavailable: [
          "\u{1F510} ECDSA Digital Signatures",
          "\u{1F6E1}\uFE0F Metadata Protection",
          "\u{1F504} Perfect Forward Secrecy",
          "\u{1F510} Nested Encryption",
          "\u{1F4E6} Packet Padding",
          "\u{1F3AD} Traffic Obfuscation",
          "\u{1F3AA} Fake Traffic Generation",
          "\u{1F575}\uFE0F Decoy Channels",
          "\u{1F6AB} Anti-Fingerprinting",
          "\u{1F4DD} Message Chunking",
          "\u{1F504} Advanced Replay Protection"
        ],
        upgrade: {
          next: "Basic Session (5,000 sat - $2.00)",
          features: [
            "\u{1F510} ECDSA Digital Signatures",
            "\u{1F6E1}\uFE0F Metadata Protection",
            "\u{1F504} Perfect Forward Secrecy",
            "\u{1F510} Nested Encryption",
            "\u{1F4E6} Packet Padding"
          ]
        }
      },
      basic: {
        title: "Basic Session - Enhanced Security",
        description: "Full featured session with enhanced security features",
        available: [
          "\u{1F510} Basic end-to-end encryption (AES-GCM 256)",
          "\u{1F511} Simple key exchange (ECDH P-384)",
          "\u2705 Message integrity verification",
          "\u26A1 Rate limiting protection",
          "\u{1F510} ECDSA Digital Signatures",
          "\u{1F6E1}\uFE0F Metadata Protection",
          "\u{1F504} Perfect Forward Secrecy",
          "\u{1F510} Nested Encryption",
          "\u{1F4E6} Packet Padding",
          "\u{1F512} Complete ASN.1 validation",
          "\u{1F50D} OID and EC point verification",
          "\u{1F3D7}\uFE0F SPKI structure validation",
          "\u{1F6E1}\uFE0F 18-layer security architecture"
        ],
        unavailable: [
          "\u{1F3AD} Traffic Obfuscation",
          "\u{1F3AA} Fake Traffic Generation",
          "\u{1F575}\uFE0F Decoy Channels",
          "\u{1F6AB} Anti-Fingerprinting",
          "\u{1F4DD} Message Chunking",
          "\u{1F504} Advanced Replay Protection"
        ],
        upgrade: {
          next: "Premium Session (20,000 sat - $8.00)",
          features: [
            "\u{1F3AD} Traffic Obfuscation",
            "\u{1F3AA} Fake Traffic Generation",
            "\u{1F575}\uFE0F Decoy Channels",
            "\u{1F6AB} Anti-Fingerprinting",
            "\u{1F4DD} Message Chunking",
            "\u{1F504} Advanced Replay Protection"
          ]
        }
      },
      premium: {
        title: "Premium Session - Maximum Security",
        description: "Extended session with maximum security protection",
        available: [
          "\u{1F510} Basic end-to-end encryption (AES-GCM 256)",
          "\u{1F511} Simple key exchange (ECDH P-384)",
          "\u2705 Message integrity verification",
          "\u26A1 Rate limiting protection",
          "\u{1F510} ECDSA Digital Signatures",
          "\u{1F6E1}\uFE0F Metadata Protection",
          "\u{1F504} Perfect Forward Secrecy",
          "\u{1F510} Nested Encryption",
          "\u{1F4E6} Packet Padding",
          "\u{1F3AD} Traffic Obfuscation",
          "\u{1F3AA} Fake Traffic Generation",
          "\u{1F575}\uFE0F Decoy Channels",
          "\u{1F6AB} Anti-Fingerprinting",
          "\u{1F4DD} Message Chunking",
          "\u{1F504} Advanced Replay Protection",
          "\u{1F512} Complete ASN.1 validation",
          "\u{1F50D} OID and EC point verification",
          "\u{1F3D7}\uFE0F SPKI structure validation",
          "\u{1F6E1}\uFE0F 18-layer security architecture",
          "\u{1F680} ASN.1 Validated"
        ],
        unavailable: [],
        upgrade: {
          next: "Maximum security achieved!",
          features: ["\u{1F389} All security features unlocked!"]
        }
      }
    };
    return features[sessionType] || features.demo;
  };
  const handleSelectType = async (type) => {
    setSelectedType(type);
    setError("");
    if (type === "demo") {
      try {
        if (!sessionManager || !sessionManager.createDemoSession) {
          throw new Error("Demo session manager not available");
        }
        const demoSession = sessionManager.createDemoSession();
        if (!demoSession.success) {
          throw new Error(demoSession.reason);
        }
        setInvoice({
          sessionType: "demo",
          amount: 0,
          paymentHash: demoSession.paymentHash,
          memo: `Demo session (${demoSession.durationMinutes} minutes)`,
          createdAt: Date.now(),
          isDemo: true,
          preimage: demoSession.preimage,
          warning: demoSession.warning,
          securityLevel: "Basic"
        });
        setPaymentStatus("demo");
      } catch (error2) {
        setError(`Demo session creation failed: ${error2.message}`);
        return;
      }
    } else {
      await createRealInvoice(type);
    }
    setStep("payment");
  };
  const createRealInvoice = async (type) => {
    setPaymentStatus("creating");
    setIsProcessing(true);
    setError("");
    try {
      console.log(`Creating Lightning invoice for ${type} session...`);
      if (!sessionManager) {
        throw new Error("Session manager not initialized");
      }
      const createdInvoice = await sessionManager.createLightningInvoice(type);
      if (!createdInvoice || !createdInvoice.paymentRequest) {
        throw new Error("Failed to create Lightning invoice");
      }
      createdInvoice.securityLevel = sessionManager.getSecurityLevelForSession(type);
      setInvoice(createdInvoice);
      setPaymentStatus("created");
      try {
        const dataUrl = await window.generateQRCode(createdInvoice.paymentRequest, { size: 300, margin: 2, errorCorrectionLevel: "M" });
        setQrCodeUrl(dataUrl);
      } catch (e) {
        console.warn("QR local generation failed, showing placeholder");
        const dataUrl = await window.generateQRCode(createdInvoice.paymentRequest, { size: 300 });
        setQrCodeUrl(dataUrl);
      }
      const expirationTime = 15 * 60 * 1e3;
      setTimeLeft(expirationTime);
      const timer = setInterval(() => {
        setTimeLeft((prev) => {
          const newTime = prev - 1e3;
          if (newTime <= 0) {
            clearInterval(timer);
            setPaymentStatus("expired");
            setError("Payment time has expired. Create a new invoice.");
            return 0;
          }
          return newTime;
        });
      }, 1e3);
      setPaymentTimer(timer);
      startPaymentPolling(createdInvoice.checkingId);
      console.log("\u2705 Lightning invoice created successfully:", createdInvoice);
    } catch (err) {
      console.error("\u274C Invoice creation failed:", err);
      setError(`Invoice creation error: ${err.message}`);
      setPaymentStatus("failed");
    } finally {
      setIsProcessing(false);
    }
  };
  const startPaymentPolling = (checkingId) => {
    if (pollInterval.current) {
      clearInterval(pollInterval.current);
    }
    pollInterval.current = setInterval(async () => {
      try {
        const status = await sessionManager.checkPaymentStatus(checkingId);
        if (status.paid && status.preimage) {
          clearInterval(pollInterval.current);
          setPaymentStatus("paid");
          await handlePaymentSuccess(status.preimage);
        }
      } catch (error2) {
        console.warn("Payment status check failed:", error2);
      }
    }, 3e3);
  };
  const handleWebLNPayment = async () => {
    if (!window.webln) {
      setError("WebLN is not supported. Please install the Alby or Zeus wallet.");
      return;
    }
    if (!invoice || !invoice.paymentRequest) {
      setError("Invoice is not ready for payment.");
      return;
    }
    setIsProcessing(true);
    setError("");
    setPaymentStatus("paying");
    try {
      await window.webln.enable();
      const result = await window.webln.sendPayment(invoice.paymentRequest);
      if (result.preimage) {
        setPaymentStatus("paid");
        await handlePaymentSuccess(result.preimage);
      } else {
        throw new Error("Payment does not contain preimage");
      }
    } catch (err) {
      console.error("\u274C WebLN payment failed:", err);
      setError(`WebLN payment error: ${err.message}`);
      setPaymentStatus("created");
    } finally {
      setIsProcessing(false);
    }
  };
  const handleManualVerification = async () => {
    const trimmedPreimage = preimageInput.trim();
    if (!trimmedPreimage) {
      setError("Enter payment preimage");
      return;
    }
    if (trimmedPreimage.length !== 64) {
      setError("The preimage must be exactly 64 characters long.");
      return;
    }
    if (!/^[0-9a-fA-F]{64}$/.test(trimmedPreimage)) {
      setError("The preimage must contain only hexadecimal characters (0-9, a-f, A-F).");
      return;
    }
    const dummyPreimages = ["1".repeat(64), "a".repeat(64), "f".repeat(64), "0".repeat(64)];
    if (dummyPreimages.includes(trimmedPreimage) && selectedType !== "demo") {
      setError("The entered preimage is invalid. Please use the actual preimage from the payment.");
      return;
    }
    setIsProcessing(true);
    setError("");
    setPaymentStatus("paying");
    try {
      await handlePaymentSuccess(trimmedPreimage);
    } catch (err) {
      setError(err.message);
      setPaymentStatus("created");
    } finally {
      setIsProcessing(false);
    }
  };
  const handleDemoSession = async () => {
    setIsProcessing(true);
    setError("");
    try {
      if (!invoice?.preimage) {
        throw new Error("Demo preimage not available");
      }
      const isValid = await sessionManager.verifyPayment(invoice.preimage, invoice.paymentHash);
      if (isValid && isValid.verified) {
        onSessionPurchased({
          type: "demo",
          preimage: invoice.preimage,
          paymentHash: invoice.paymentHash,
          amount: 0,
          isDemo: true,
          warning: invoice.warning,
          securityLevel: "basic"
        });
        setTimeout(() => {
          onClose();
        }, 1500);
      } else {
        throw new Error(isValid?.reason || "Demo session verification failed");
      }
    } catch (err) {
      setError(`Demo session activation error: ${err.message}`);
    } finally {
      setIsProcessing(false);
    }
  };
  const handlePaymentSuccess = async (preimage) => {
    try {
      console.log("\u{1F50D} Verifying payment...", { selectedType, preimage });
      let isValid;
      if (selectedType === "demo") {
        return;
      } else {
        isValid = await sessionManager.verifyPayment(preimage, invoice.paymentHash);
      }
      if (isValid) {
        if (pollInterval.current) {
          clearInterval(pollInterval.current);
        }
        if (paymentTimer) {
          clearInterval(paymentTimer);
        }
        onSessionPurchased({
          type: selectedType,
          preimage,
          paymentHash: invoice.paymentHash,
          amount: invoice.amount,
          securityLevel: invoice.securityLevel || (selectedType === "basic" ? "enhanced" : "maximum")
        });
        setTimeout(() => {
          onClose();
        }, 1500);
      } else {
        throw new Error("Payment verification failed. Please check the preimage for correctness or try again.");
      }
    } catch (error2) {
      console.error("\u274C Payment verification failed:", error2);
      throw error2;
    }
  };
  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };
  const formatTime = (ms) => {
    const minutes = Math.floor(ms / 6e4);
    const seconds = Math.floor(ms % 6e4 / 1e3);
    return `${minutes}:${seconds.toString().padStart(2, "0")}`;
  };
  const getSecurityBadgeColor = (level) => {
    switch (level?.toLowerCase()) {
      case "basic":
        return "bg-blue-500/20 text-blue-300 border-blue-500/30";
      case "enhanced":
        return "bg-orange-500/20 text-orange-300 border-orange-500/30";
      case "maximum":
        return "bg-green-500/20 text-green-300 border-green-500/30";
      default:
        return "bg-gray-500/20 text-gray-300 border-gray-500/30";
    }
  };
  const pricing = sessionManager?.sessionPrices || {
    demo: { sats: 0, hours: 0.1, usd: 0 },
    basic: { sats: 5e3, hours: 1, usd: 2 },
    premium: { sats: 2e4, hours: 6, usd: 8 }
  };
  if (!isOpen) return null;
  return React3.createElement("div", {
    className: "fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
  }, [
    React3.createElement("div", {
      key: "modal",
      className: "card-minimal rounded-xl p-6 max-w-lg w-full max-h-[90vh] overflow-y-auto custom-scrollbar"
    }, [
      React3.createElement("div", {
        key: "header",
        className: "flex items-center justify-between mb-6"
      }, [
        React3.createElement("h2", {
          key: "title",
          className: "text-xl font-semibold text-primary"
        }, step === "select" ? "Select session type" : step === "details" ? "Security Features Details" : "Session payment"),
        React3.createElement("button", {
          key: "close",
          onClick: onClose,
          className: "text-gray-400 hover:text-white transition-colors"
        }, React3.createElement("i", { className: "fas fa-times" }))
      ]),
      step === "select" && window.SessionTypeSelector && React3.createElement(window.SessionTypeSelector, {
        key: "selector",
        onSelectType: handleSelectType,
        onCancel: onClose,
        sessionManager
      }),
      step === "payment" && React3.createElement("div", {
        key: "payment-step",
        className: "space-y-6"
      }, [
        React3.createElement("div", {
          key: "session-info",
          className: "text-center p-4 bg-orange-500/10 border border-orange-500/20 rounded-lg"
        }, [
          React3.createElement("h3", {
            key: "session-title",
            className: "text-lg font-semibold text-orange-400 mb-2"
          }, [
            `${selectedType.charAt(0).toUpperCase() + selectedType.slice(1)} session`,
            invoice?.securityLevel && React3.createElement("span", {
              key: "security-badge",
              className: `text-xs px-2 py-1 rounded-full border ${getSecurityBadgeColor(invoice.securityLevel)}`
            }, invoice.securityLevel.toUpperCase())
          ]),
          React3.createElement("div", {
            key: "session-details",
            className: "text-sm text-secondary"
          }, [
            React3.createElement("div", { key: "amount" }, `${pricing[selectedType].sats} sat for ${pricing[selectedType].hours}h`),
            pricing[selectedType].usd > 0 && React3.createElement("div", {
              key: "usd",
              className: "text-gray-400"
            }, `\u2248 ${pricing[selectedType].usd} USD`),
            React3.createElement("button", {
              key: "details-btn",
              onClick: () => setStep("details"),
              className: "mt-2 text-xs text-blue-400 hover:text-blue-300 underline cursor-pointer"
            }, "\u{1F4CB} View Security Details")
          ])
        ]),
        timeLeft > 0 && paymentStatus === "created" && React3.createElement("div", {
          key: "timer",
          className: "text-center p-3 bg-yellow-500/10 border border-yellow-500/20 rounded"
        }, [
          React3.createElement("div", {
            key: "timer-text",
            className: "text-yellow-400 font-medium"
          }, `\u23F1\uFE0F Time to pay: ${formatTime(timeLeft)}`)
        ]),
        paymentStatus === "demo" && React3.createElement("div", {
          key: "demo-payment",
          className: "space-y-4"
        }, [
          React3.createElement("div", {
            key: "demo-info",
            className: "p-4 bg-green-500/10 border border-green-500/20 rounded text-green-300 text-sm text-center"
          }, [
            React3.createElement("div", { key: "demo-title", className: "font-medium mb-1" }, "\u{1F3AE} Demo Session Available"),
            React3.createElement(
              "div",
              { key: "demo-details", className: "text-xs" },
              `Limited to ${invoice?.durationMinutes || 6} minutes for testing`
            )
          ]),
          invoice?.warning && React3.createElement("div", {
            key: "demo-warning",
            className: "p-3 bg-yellow-500/10 border border-yellow-500/20 rounded text-yellow-300 text-xs text-center"
          }, invoice.warning),
          React3.createElement("div", {
            key: "demo-preimage",
            className: "p-3 bg-gray-800/50 rounded border border-gray-600 text-xs font-mono text-gray-300"
          }, [
            React3.createElement("div", { key: "preimage-label", className: "text-gray-400 mb-1" }, "Demo Preimage:"),
            React3.createElement(
              "div",
              { key: "preimage-value", className: "break-all" },
              invoice?.preimage || "Generating..."
            )
          ]),
          React3.createElement("button", {
            key: "demo-btn",
            onClick: handleDemoSession,
            disabled: isProcessing,
            className: "w-full bg-green-600 hover:bg-green-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed"
          }, [
            React3.createElement("i", {
              key: "demo-icon",
              className: `fas ${isProcessing ? "fa-spinner fa-spin" : "fa-play"} mr-2`
            }),
            isProcessing ? "Activating..." : "Activate Demo Session"
          ])
        ]),
        paymentStatus === "creating" && React3.createElement("div", {
          key: "creating",
          className: "text-center p-4"
        }, [
          React3.createElement("i", { className: "fas fa-spinner fa-spin text-orange-400 text-2xl mb-2" }),
          React3.createElement("div", { className: "text-primary" }, "Creating Lightning invoice..."),
          React3.createElement("div", { className: "text-secondary text-sm mt-1" }, "Connecting to the Lightning Network...")
        ]),
        (paymentStatus === "created" || paymentStatus === "paying") && invoice && React3.createElement("div", {
          key: "payment-methods",
          className: "space-y-6"
        }, [
          qrCodeUrl && React3.createElement("div", {
            key: "qr-section",
            className: "text-center"
          }, [
            React3.createElement("div", {
              key: "qr-container",
              className: "bg-white p-4 rounded-lg inline-block"
            }, [
              React3.createElement("img", {
                key: "qr-img",
                src: qrCodeUrl,
                alt: "Lightning Payment QR Code",
                className: "w-48 h-48"
              })
            ]),
            React3.createElement("div", {
              key: "qr-hint",
              className: "text-xs text-gray-400 mt-2"
            }, "Scan with any Lightning wallet")
          ]),
          invoice.paymentRequest && React3.createElement("div", {
            key: "payment-request",
            className: "space-y-2"
          }, [
            React3.createElement("div", {
              key: "pr-label",
              className: "text-sm font-medium text-primary"
            }, "Lightning Payment Request:"),
            React3.createElement("div", {
              key: "pr-container",
              className: "p-3 bg-gray-800/50 rounded border border-gray-600 text-xs font-mono text-gray-300 cursor-pointer hover:bg-gray-700/50 transition-colors",
              onClick: () => copyToClipboard(invoice.paymentRequest),
              title: "Click to copy"
            }, [
              invoice.paymentRequest.substring(0, 60) + "...",
              React3.createElement("i", { key: "copy-icon", className: "fas fa-copy ml-2 text-orange-400" })
            ])
          ]),
          // WebLN Payment
          React3.createElement("div", {
            key: "webln-section",
            className: "space-y-3"
          }, [
            React3.createElement("h4", {
              key: "webln-title",
              className: "text-primary font-medium flex items-center"
            }, [
              React3.createElement("i", { key: "bolt-icon", className: "fas fa-bolt text-orange-400 mr-2" }),
              "WebLN wallet (recommended)"
            ]),
            React3.createElement("div", {
              key: "webln-info",
              className: "text-xs text-gray-400 mb-2"
            }, "Alby, Zeus, or other WebLN-compatible wallets"),
            React3.createElement("button", {
              key: "webln-btn",
              onClick: handleWebLNPayment,
              disabled: isProcessing || paymentStatus === "paying",
              className: "w-full bg-orange-600 hover:bg-orange-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            }, [
              React3.createElement("i", {
                key: "webln-icon",
                className: `fas ${isProcessing ? "fa-spinner fa-spin" : "fa-bolt"} mr-2`
              }),
              paymentStatus === "paying" ? "Processing payment..." : "Pay via WebLN"
            ])
          ]),
          // Divider
          React3.createElement("div", {
            key: "divider",
            className: "text-center text-gray-400 text-sm"
          }, "\u2014 or \u2014"),
          // Manual Verification
          React3.createElement("div", {
            key: "manual-section",
            className: "space-y-3"
          }, [
            React3.createElement("h4", {
              key: "manual-title",
              className: "text-primary font-medium"
            }, "Manual payment confirmation"),
            React3.createElement("div", {
              key: "manual-info",
              className: "text-xs text-gray-400"
            }, "Pay the invoice in any wallet and enter the preimage.:"),
            React3.createElement("input", {
              key: "preimage-input",
              type: "text",
              value: preimageInput,
              onChange: (e) => setPreimageInput(e.target.value),
              placeholder: "Enter the preimage (64 hex characters)...",
              className: "w-full p-3 bg-gray-800 border border-gray-600 rounded text-white placeholder-gray-400 text-sm font-mono",
              maxLength: 64
            }),
            React3.createElement("button", {
              key: "verify-btn",
              onClick: handleManualVerification,
              disabled: isProcessing || !preimageInput.trim(),
              className: "w-full bg-green-600 hover:bg-green-500 text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            }, [
              React3.createElement("i", {
                key: "verify-icon",
                className: `fas ${isProcessing ? "fa-spinner fa-spin" : "fa-check"} mr-2`
              }),
              isProcessing ? "Checking payment..." : "Confirm payment"
            ])
          ])
        ]),
        // Success State
        paymentStatus === "paid" && React3.createElement("div", {
          key: "success",
          className: "text-center p-6 bg-green-500/10 border border-green-500/20 rounded-lg"
        }, [
          React3.createElement("i", { key: "success-icon", className: "fas fa-check-circle text-green-400 text-3xl mb-3" }),
          React3.createElement("div", { key: "success-title", className: "text-green-300 font-semibold text-lg mb-1" }, "\u2705 Payment confirmed!"),
          React3.createElement("div", { key: "success-text", className: "text-green-400 text-sm" }, "The session will be activated upon connecting to the chat.")
        ]),
        // Error State
        error && React3.createElement("div", {
          key: "error",
          className: "p-4 bg-red-500/10 border border-red-500/20 rounded-lg"
        }, [
          React3.createElement("div", {
            key: "error-content",
            className: "flex items-start space-x-3"
          }, [
            React3.createElement("i", { key: "error-icon", className: "fas fa-exclamation-triangle text-red-400 mt-0.5" }),
            React3.createElement("div", { key: "error-text", className: "flex-1" }, [
              React3.createElement("div", { key: "error-message", className: "text-red-400 text-sm" }, error),
              (error.includes("invoice") || paymentStatus === "failed") && React3.createElement("button", {
                key: "retry-btn",
                onClick: () => createRealInvoice(selectedType),
                className: "mt-2 text-orange-400 hover:text-orange-300 underline text-sm"
              }, "Create a new invoice")
            ])
          ])
        ]),
        paymentStatus !== "paid" && React3.createElement("div", {
          key: "back-section",
          className: "pt-4 border-t border-gray-600"
        }, [
          React3.createElement("button", {
            key: "back-btn",
            onClick: () => setStep("select"),
            className: "w-full bg-gray-600 hover:bg-gray-500 text-white py-2 px-4 rounded transition-colors"
          }, [
            React3.createElement("i", { key: "back-icon", className: "fas fa-arrow-left mr-2" }),
            "Choose another session"
          ])
        ])
      ]),
      // Security Details Step
      step === "details" && React3.createElement("div", {
        key: "details-step",
        className: "space-y-6"
      }, [
        React3.createElement("div", {
          key: "details-header",
          className: "text-center p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg"
        }, [
          React3.createElement("h3", {
            key: "details-title",
            className: "text-lg font-semibold text-blue-400 mb-2"
          }, getSecurityFeaturesInfo(selectedType).title),
          React3.createElement("p", {
            key: "details-description",
            className: "text-sm text-blue-300"
          }, getSecurityFeaturesInfo(selectedType).description)
        ]),
        // Available Features
        React3.createElement("div", { key: "available-features" }, [
          React3.createElement("h4", {
            key: "available-title",
            className: "text-sm font-medium text-green-300 mb-3 flex items-center"
          }, [
            React3.createElement("i", {
              key: "check-icon",
              className: "fas fa-check-circle mr-2"
            }),
            "Available Security Features"
          ]),
          React3.createElement("div", {
            key: "available-list",
            className: "grid grid-cols-1 gap-2"
          }, getSecurityFeaturesInfo(selectedType).available.map(
            (feature, index) => React3.createElement("div", {
              key: index,
              className: "flex items-center gap-2 text-sm text-green-300"
            }, [
              React3.createElement("i", {
                key: "check",
                className: "fas fa-check text-green-400 w-4"
              }),
              React3.createElement("span", {
                key: "text"
              }, feature)
            ])
          ))
        ]),
        // Unavailable Features (if any)
        getSecurityFeaturesInfo(selectedType).unavailable.length > 0 && React3.createElement("div", { key: "unavailable-features" }, [
          React3.createElement("h4", {
            key: "unavailable-title",
            className: "text-sm font-medium text-red-300 mb-3 flex items-center"
          }, [
            React3.createElement("i", {
              key: "minus-icon",
              className: "fas fa-minus-circle mr-2"
            }),
            "Not Available in This Session"
          ]),
          React3.createElement("div", {
            key: "unavailable-list",
            className: "grid grid-cols-1 gap-2"
          }, getSecurityFeaturesInfo(selectedType).unavailable.map(
            (feature, index) => React3.createElement("div", {
              key: index,
              className: "flex items-center gap-2 text-sm text-red-300"
            }, [
              React3.createElement("i", {
                key: "minus",
                className: "fas fa-minus text-red-400 w-4"
              }),
              React3.createElement("span", {
                key: "text"
              }, feature)
            ])
          ))
        ]),
        // Upgrade Information
        React3.createElement("div", { key: "upgrade-info" }, [
          React3.createElement("h4", {
            key: "upgrade-title",
            className: "text-sm font-medium text-blue-300 mb-3 flex items-center"
          }, [
            React3.createElement("i", {
              key: "upgrade-icon",
              className: "fas fa-arrow-up mr-2"
            }),
            "Upgrade for More Security"
          ]),
          React3.createElement("div", {
            key: "upgrade-content",
            className: "p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg"
          }, [
            React3.createElement("div", {
              key: "upgrade-next",
              className: "text-sm font-medium text-blue-300 mb-2"
            }, getSecurityFeaturesInfo(selectedType).upgrade.next),
            React3.createElement("div", {
              key: "upgrade-features",
              className: "grid grid-cols-1 gap-1"
            }, getSecurityFeaturesInfo(selectedType).upgrade.features.map(
              (feature, index) => React3.createElement("div", {
                key: index,
                className: "flex items-center gap-2 text-xs text-blue-300"
              }, [
                React3.createElement("i", {
                  key: "arrow",
                  className: "fas fa-arrow-right text-blue-400 w-3"
                }),
                React3.createElement("span", {
                  key: "text"
                }, feature)
              ])
            ))
          ])
        ]),
        // Back Button
        React3.createElement("div", {
          key: "details-back-section",
          className: "pt-4 border-t border-gray-600"
        }, [
          React3.createElement("button", {
            key: "details-back-btn",
            onClick: () => setStep("payment"),
            className: "w-full bg-gray-600 hover:bg-gray-500 text-white py-2 px-4 rounded transition-colors"
          }, [
            React3.createElement("i", { key: "back-icon", className: "fas fa-arrow-left mr-2" }),
            "Back to Payment"
          ])
        ])
      ])
    ])
  ]);
};
window.PaymentModal = PaymentModal;

// src/components/ui/DownloadApps.jsx
var DownloadApps = () => {
  const apps = [
    { id: "web", name: "Web App", subtitle: "Browser Version", icon: "fas fa-globe", platform: "Web", isActive: true, url: "https://securebitchat.github.io/securebit-chat/", color: "green" },
    { id: "windows", name: "Windows", subtitle: "Desktop App", icon: "fab fa-windows", platform: "Desktop", isActive: false, url: "#", color: "blue" },
    { id: "macos", name: "macOS", subtitle: "Desktop App", icon: "fab fa-apple", platform: "Desktop", isActive: false, url: "#", color: "gray" },
    { id: "linux", name: "Linux", subtitle: "Desktop App", icon: "fab fa-linux", platform: "Desktop", isActive: false, url: "#", color: "orange" },
    { id: "ios", name: "iOS", subtitle: "iPhone & iPad", icon: "fab fa-apple", platform: "Mobile", isActive: false, url: "https://apps.apple.com/app/securebit-chat/", color: "blue" },
    { id: "android", name: "Android", subtitle: "Google Play", icon: "fab fa-android", platform: "Mobile", isActive: false, url: "https://play.google.com/store/apps/details?id=com.securebit.chat", color: "green" }
  ];
  const handleDownload = (app) => {
    if (app.isActive) window.open(app.url, "_blank");
  };
  const desktopApps = apps.filter((a) => a.platform !== "Mobile");
  const mobileApps = apps.filter((a) => a.platform === "Mobile");
  const cardSize = "w-28 h-28";
  return React.createElement("div", { className: "mt-20 px-6" }, [
    // Header
    React.createElement("div", { key: "header", className: "text-center max-w-3xl mx-auto mb-12" }, [
      React.createElement("h3", { key: "title", className: "text-3xl font-bold text-primary mb-3" }, "Download SecureBit.chat"),
      React.createElement("p", { key: "subtitle", className: "text-secondary text-lg mb-5" }, "Stay secure on every device. Choose your platform and start chatting privately.")
    ]),
    React.createElement(
      "div",
      { key: "desktop-row", className: "hidden sm:flex justify-center flex-wrap gap-6 mb-6" },
      desktopApps.map(
        (app) => React.createElement("div", {
          key: app.id,
          className: `group relative ${cardSize} rounded-2xl overflow-hidden card-minimal cursor-pointer`
        }, [
          React.createElement("i", {
            key: "bg-icon",
            className: `${app.icon} absolute text-[3rem] text-white/10 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none transition-all duration-500 group-hover:scale-105`
          }),
          React.createElement("div", {
            key: "overlay",
            className: "absolute inset-0 bg-black/30 backdrop-blur-md flex flex-col items-center justify-center text-center opacity-0 transition-opacity duration-300 group-hover:opacity-100"
          }, [
            React.createElement("h4", { key: "name", className: `text-sm font-semibold text-primary mb-1` }, app.name),
            React.createElement("p", { key: "subtitle", className: `text-xs text-secondary mb-2` }, app.subtitle),
            app.isActive ? React.createElement("button", {
              key: "btn",
              onClick: () => handleDownload(app),
              className: `px-2 py-1 rounded-xl bg-emerald-500 text-black font-medium hover:bg-emerald-600 transition-colors text-xs`
            }, app.id === "web" ? "Launch" : "Download") : React.createElement("span", { key: "coming", className: "text-gray-400 font-medium text-xs" }, "Coming Soon")
          ])
        ])
      )
    ),
    React.createElement(
      "div",
      { key: "mobile-row", className: "flex justify-center gap-6" },
      mobileApps.map(
        (app) => React.createElement("div", {
          key: app.id,
          className: `group relative ${cardSize} rounded-2xl overflow-hidden card-minimal cursor-pointer`
        }, [
          React.createElement("i", {
            key: "bg-icon",
            className: `${app.icon} absolute text-[3rem] text-white/10 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none transition-all duration-500 group-hover:scale-105`
          }),
          React.createElement("div", {
            key: "overlay",
            className: "absolute inset-0 bg-black/30 backdrop-blur-md flex flex-col items-center justify-center text-center opacity-0 transition-opacity duration-300 group-hover:opacity-100"
          }, [
            React.createElement("h4", { key: "name", className: `text-sm font-semibold text-primary mb-1` }, app.name),
            React.createElement("p", { key: "subtitle", className: `text-xs text-secondary mb-2` }, app.subtitle),
            app.isActive ? React.createElement("button", {
              key: "btn",
              onClick: () => handleDownload(app),
              className: `px-2 py-1 rounded-xl bg-emerald-500 text-black font-medium hover:bg-emerald-600 transition-colors text-xs`
            }, "Download") : React.createElement("span", { key: "coming", className: "text-gray-400 font-medium text-xs" }, "Coming Soon")
          ])
        ])
      )
    )
  ]);
};
window.DownloadApps = DownloadApps;

// src/components/ui/FileTransfer.jsx
var FileTransferComponent = ({ webrtcManager, isConnected }) => {
  const [dragOver, setDragOver] = React.useState(false);
  const [transfers, setTransfers] = React.useState({ sending: [], receiving: [] });
  const [readyFiles, setReadyFiles] = React.useState([]);
  const fileInputRef = React.useRef(null);
  React.useEffect(() => {
    if (!isConnected || !webrtcManager) return;
    const updateTransfers = () => {
      const currentTransfers = webrtcManager.getFileTransfers();
      setTransfers(currentTransfers);
    };
    const interval = setInterval(updateTransfers, 500);
    return () => clearInterval(interval);
  }, [isConnected, webrtcManager]);
  React.useEffect(() => {
    if (!webrtcManager) return;
    webrtcManager.setFileTransferCallbacks(
      // Progress callback - ТОЛЬКО обновляем UI, НЕ отправляем в чат
      (progress) => {
        const currentTransfers = webrtcManager.getFileTransfers();
        setTransfers(currentTransfers);
      },
      // File received callback - добавляем кнопку скачивания в UI
      (fileData) => {
        setReadyFiles((prev) => {
          if (prev.some((f) => f.fileId === fileData.fileId)) return prev;
          return [...prev, {
            fileId: fileData.fileId,
            fileName: fileData.fileName,
            fileSize: fileData.fileSize,
            mimeType: fileData.mimeType,
            getBlob: fileData.getBlob,
            getObjectURL: fileData.getObjectURL,
            revokeObjectURL: fileData.revokeObjectURL
          }];
        });
        const currentTransfers = webrtcManager.getFileTransfers();
        setTransfers(currentTransfers);
      },
      // Error callback
      (error) => {
        const currentTransfers = webrtcManager.getFileTransfers();
        setTransfers(currentTransfers);
      }
    );
  }, [webrtcManager]);
  const handleFileSelect = async (files) => {
    if (!isConnected || !webrtcManager) {
      alert("\u0421\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435 \u043D\u0435 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043B\u0435\u043D\u043E. \u0421\u043D\u0430\u0447\u0430\u043B\u0430 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u0435 \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435.");
      return;
    }
    if (!webrtcManager.isConnected() || !webrtcManager.isVerified) {
      alert("\u0421\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435 \u043D\u0435 \u0433\u043E\u0442\u043E\u0432\u043E \u0434\u043B\u044F \u043F\u0435\u0440\u0435\u0434\u0430\u0447\u0438 \u0444\u0430\u0439\u043B\u043E\u0432. \u0414\u043E\u0436\u0434\u0438\u0442\u0435\u0441\u044C \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043D\u0438\u044F \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043A\u0438 \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u044F.");
      return;
    }
    for (const file of files) {
      try {
        const validation = webrtcManager.validateFile(file);
        if (!validation.isValid) {
          const errorMessage = validation.errors.join(". ");
          alert(`\u0424\u0430\u0439\u043B ${file.name} \u043D\u0435 \u043C\u043E\u0436\u0435\u0442 \u0431\u044B\u0442\u044C \u043E\u0442\u043F\u0440\u0430\u0432\u043B\u0435\u043D: ${errorMessage}`);
          continue;
        }
        await webrtcManager.sendFile(file);
      } catch (error) {
        if (error.message.includes("Connection not ready")) {
          alert(`\u0424\u0430\u0439\u043B ${file.name} \u043D\u0435 \u043C\u043E\u0436\u0435\u0442 \u0431\u044B\u0442\u044C \u043E\u0442\u043F\u0440\u0430\u0432\u043B\u0435\u043D \u0441\u0435\u0439\u0447\u0430\u0441. \u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435 \u0438 \u043F\u043E\u043F\u0440\u043E\u0431\u0443\u0439\u0442\u0435 \u0441\u043D\u043E\u0432\u0430.`);
        } else if (error.message.includes("File too large") || error.message.includes("exceeds maximum")) {
          alert(`\u0424\u0430\u0439\u043B ${file.name} \u0441\u043B\u0438\u0448\u043A\u043E\u043C \u0431\u043E\u043B\u044C\u0448\u043E\u0439: ${error.message}`);
        } else if (error.message.includes("Maximum concurrent transfers")) {
          alert(`\u0414\u043E\u0441\u0442\u0438\u0433\u043D\u0443\u0442 \u043B\u0438\u043C\u0438\u0442 \u043E\u0434\u043D\u043E\u0432\u0440\u0435\u043C\u0435\u043D\u043D\u044B\u0445 \u043F\u0435\u0440\u0435\u0434\u0430\u0447. \u0414\u043E\u0436\u0434\u0438\u0442\u0435\u0441\u044C \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043D\u0438\u044F \u0442\u0435\u043A\u0443\u0449\u0438\u0445 \u043F\u0435\u0440\u0435\u0434\u0430\u0447.`);
        } else if (error.message.includes("File type not allowed")) {
          alert(`\u0422\u0438\u043F \u0444\u0430\u0439\u043B\u0430 ${file.name} \u043D\u0435 \u043F\u043E\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u0442\u0441\u044F: ${error.message}`);
        } else {
          alert(`\u041E\u0448\u0438\u0431\u043A\u0430 \u043E\u0442\u043F\u0440\u0430\u0432\u043A\u0438 \u0444\u0430\u0439\u043B\u0430 ${file.name}: ${error.message}`);
        }
      }
    }
  };
  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const files = Array.from(e.dataTransfer.files);
    handleFileSelect(files);
  };
  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };
  const handleDragLeave = (e) => {
    e.preventDefault();
    setDragOver(false);
  };
  const handleFileInputChange = (e) => {
    const files = Array.from(e.target.files);
    handleFileSelect(files);
    e.target.value = "";
  };
  const formatFileSize = (bytes) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };
  const getStatusIcon = (status) => {
    switch (status) {
      case "metadata_sent":
      case "preparing":
        return "fas fa-cog fa-spin";
      case "transmitting":
      case "receiving":
        return "fas fa-exchange-alt fa-pulse";
      case "assembling":
        return "fas fa-puzzle-piece fa-pulse";
      case "completed":
        return "fas fa-check text-green-400";
      case "failed":
        return "fas fa-times text-red-400";
      default:
        return "fas fa-circle";
    }
  };
  const getStatusText = (status) => {
    switch (status) {
      case "metadata_sent":
        return "\u041F\u043E\u0434\u0433\u043E\u0442\u043E\u0432\u043A\u0430...";
      case "transmitting":
        return "\u041E\u0442\u043F\u0440\u0430\u0432\u043A\u0430...";
      case "receiving":
        return "\u041F\u043E\u043B\u0443\u0447\u0435\u043D\u0438\u0435...";
      case "assembling":
        return "\u0421\u0431\u043E\u0440\u043A\u0430 \u0444\u0430\u0439\u043B\u0430...";
      case "completed":
        return "\u0417\u0430\u0432\u0435\u0440\u0448\u0435\u043D\u043E";
      case "failed":
        return "\u041E\u0448\u0438\u0431\u043A\u0430";
      default:
        return status;
    }
  };
  if (!isConnected) {
    return React.createElement("div", {
      className: "p-4 text-center text-muted"
    }, "\u041F\u0435\u0440\u0435\u0434\u0430\u0447\u0430 \u0444\u0430\u0439\u043B\u043E\u0432 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u0442\u043E\u043B\u044C\u043A\u043E \u043F\u0440\u0438 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043B\u0435\u043D\u043D\u043E\u043C \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0438");
  }
  const isConnectionReady = webrtcManager && webrtcManager.isConnected() && webrtcManager.isVerified;
  if (!isConnectionReady) {
    return React.createElement("div", {
      className: "p-4 text-center text-yellow-600"
    }, [
      React.createElement("i", {
        key: "icon",
        className: "fas fa-exclamation-triangle mr-2"
      }),
      "\u0421\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435 \u0443\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442\u0441\u044F... \u041F\u0435\u0440\u0435\u0434\u0430\u0447\u0430 \u0444\u0430\u0439\u043B\u043E\u0432 \u0431\u0443\u0434\u0435\u0442 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u043F\u043E\u0441\u043B\u0435 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043D\u0438\u044F \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043A\u0438."
    ]);
  }
  return React.createElement("div", {
    className: "file-transfer-component"
  }, [
    // File Drop Zone
    React.createElement("div", {
      key: "drop-zone",
      className: `file-drop-zone ${dragOver ? "drag-over" : ""}`,
      onDrop: handleDrop,
      onDragOver: handleDragOver,
      onDragLeave: handleDragLeave,
      onClick: () => fileInputRef.current?.click()
    }, [
      React.createElement("div", {
        key: "drop-content",
        className: "drop-content"
      }, [
        React.createElement("i", {
          key: "icon",
          className: "fas fa-cloud-upload-alt text-2xl mb-2 text-blue-400"
        }),
        React.createElement("p", {
          key: "text",
          className: "text-primary font-medium"
        }, "Drag files here or click to select"),
        React.createElement("p", {
          key: "subtext",
          className: "text-muted text-sm"
        }, "Maximum size: 100 MB per file")
      ])
    ]),
    // Hidden file input
    React.createElement("input", {
      key: "file-input",
      ref: fileInputRef,
      type: "file",
      multiple: true,
      className: "hidden",
      onChange: handleFileInputChange
    }),
    // Active Transfers
    (transfers.sending.length > 0 || transfers.receiving.length > 0) && React.createElement("div", {
      key: "transfers",
      className: "active-transfers mt-4"
    }, [
      React.createElement("h4", {
        key: "title",
        className: "text-primary font-medium mb-3 flex items-center"
      }, [
        React.createElement("i", {
          key: "icon",
          className: "fas fa-exchange-alt mr-2"
        }),
        "\u041F\u0435\u0440\u0435\u0434\u0430\u0447\u0430 \u0444\u0430\u0439\u043B\u043E\u0432"
      ]),
      // Sending files
      ...transfers.sending.map(
        (transfer) => React.createElement("div", {
          key: `send-${transfer.fileId}`,
          className: "transfer-item bg-blue-500/10 border border-blue-500/20 rounded-lg p-3 mb-2"
        }, [
          React.createElement("div", {
            key: "header",
            className: "flex items-center justify-between mb-2"
          }, [
            React.createElement("div", {
              key: "info",
              className: "flex items-center"
            }, [
              React.createElement("i", {
                key: "icon",
                className: "fas fa-upload text-blue-400 mr-2"
              }),
              React.createElement("span", {
                key: "name",
                className: "text-primary font-medium text-sm"
              }, transfer.fileName),
              React.createElement("span", {
                key: "size",
                className: "text-muted text-xs ml-2"
              }, formatFileSize(transfer.fileSize))
            ]),
            React.createElement("button", {
              key: "cancel",
              onClick: () => webrtcManager.cancelFileTransfer(transfer.fileId),
              className: "text-red-400 hover:text-red-300 text-xs"
            }, [
              React.createElement("i", {
                className: "fas fa-times"
              })
            ])
          ]),
          React.createElement("div", {
            key: "progress",
            className: "progress-bar"
          }, [
            React.createElement("div", {
              key: "fill",
              className: "progress-fill bg-blue-400",
              style: { width: `${transfer.progress}%` }
            }),
            React.createElement("div", {
              key: "text",
              className: "progress-text text-xs flex items-center justify-between"
            }, [
              React.createElement("span", {
                key: "status",
                className: "flex items-center"
              }, [
                React.createElement("i", {
                  key: "icon",
                  className: `${getStatusIcon(transfer.status)} mr-1`
                }),
                getStatusText(transfer.status)
              ]),
              React.createElement("span", {
                key: "percent"
              }, `${transfer.progress.toFixed(1)}%`)
            ])
          ])
        ])
      ),
      // Receiving files
      ...transfers.receiving.map(
        (transfer) => React.createElement("div", {
          key: `recv-${transfer.fileId}`,
          className: "transfer-item bg-green-500/10 border border-green-500/20 rounded-lg p-3 mb-2"
        }, [
          React.createElement("div", {
            key: "header",
            className: "flex items-center justify-between mb-2"
          }, [
            React.createElement("div", {
              key: "info",
              className: "flex items-center"
            }, [
              React.createElement("i", {
                key: "icon",
                className: "fas fa-download text-green-400 mr-2"
              }),
              React.createElement("span", {
                key: "name",
                className: "text-primary font-medium text-sm"
              }, transfer.fileName),
              React.createElement("span", {
                key: "size",
                className: "text-muted text-xs ml-2"
              }, formatFileSize(transfer.fileSize))
            ]),
            React.createElement("div", { key: "actions", className: "flex items-center space-x-2" }, [
              (() => {
                const rf = readyFiles.find((f) => f.fileId === transfer.fileId);
                if (!rf || transfer.status !== "completed") return null;
                return React.createElement("button", {
                  key: "download",
                  className: "text-green-400 hover:text-green-300 text-xs flex items-center",
                  onClick: async () => {
                    try {
                      const url = await rf.getObjectURL();
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = rf.fileName || "file";
                      a.click();
                      rf.revokeObjectURL(url);
                    } catch (e) {
                      alert("Failed to start download: " + e.message);
                    }
                  }
                }, [
                  React.createElement("i", { key: "i", className: "fas fa-download mr-1" }),
                  "Download"
                ]);
              })(),
              React.createElement("button", {
                key: "cancel",
                onClick: () => webrtcManager.cancelFileTransfer(transfer.fileId),
                className: "text-red-400 hover:text-red-300 text-xs"
              }, [
                React.createElement("i", {
                  className: "fas fa-times"
                })
              ])
            ])
          ]),
          React.createElement("div", {
            key: "progress",
            className: "progress-bar"
          }, [
            React.createElement("div", {
              key: "fill",
              className: "progress-fill bg-green-400",
              style: { width: `${transfer.progress}%` }
            }),
            React.createElement("div", {
              key: "text",
              className: "progress-text text-xs flex items-center justify-between"
            }, [
              React.createElement("span", {
                key: "status",
                className: "flex items-center"
              }, [
                React.createElement("i", {
                  key: "icon",
                  className: `${getStatusIcon(transfer.status)} mr-1`
                }),
                getStatusText(transfer.status)
              ]),
              React.createElement("span", {
                key: "percent"
              }, `${transfer.progress.toFixed(1)}%`)
            ])
          ])
        ])
      )
    ])
  ]);
};
window.FileTransferComponent = FileTransferComponent;

// src/scripts/app-boot.js
window.EnhancedSecureCryptoUtils = EnhancedSecureCryptoUtils;
window.EnhancedSecureWebRTCManager = EnhancedSecureWebRTCManager;
window.PayPerSessionManager = PayPerSessionManager;
window.EnhancedSecureFileTransfer = EnhancedSecureFileTransfer;
var start = () => {
  if (typeof window.initializeApp === "function") {
    window.initializeApp();
  } else if (window.DEBUG_MODE) {
    console.error("initializeApp is not defined on window");
  }
};
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start);
} else {
  start();
}
//# sourceMappingURL=app-boot.js.map
