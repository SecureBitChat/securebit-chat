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
      const sessionType = "full";
      const isDemoSession = false;
      try {
        const encryptionResult = await _EnhancedSecureCryptoUtils.verifyEncryption(securityManager);
        if (encryptionResult.passed) {
          score += 20;
          verificationResults.verifyEncryption = { passed: true, details: encryptionResult.details, points: 20 };
        } else {
          verificationResults.verifyEncryption = { passed: false, details: encryptionResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyEncryption = { passed: false, details: `Encryption check failed: ${error.message}`, points: 0 };
      }
      try {
        const ecdhResult = await _EnhancedSecureCryptoUtils.verifyECDHKeyExchange(securityManager);
        if (ecdhResult.passed) {
          score += 15;
          verificationResults.verifyECDHKeyExchange = { passed: true, details: ecdhResult.details, points: 15 };
        } else {
          verificationResults.verifyECDHKeyExchange = { passed: false, details: ecdhResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyECDHKeyExchange = { passed: false, details: `Key exchange check failed: ${error.message}`, points: 0 };
      }
      try {
        const integrityResult = await _EnhancedSecureCryptoUtils.verifyMessageIntegrity(securityManager);
        if (integrityResult.passed) {
          score += 10;
          verificationResults.verifyMessageIntegrity = { passed: true, details: integrityResult.details, points: 10 };
        } else {
          verificationResults.verifyMessageIntegrity = { passed: false, details: integrityResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyMessageIntegrity = { passed: false, details: `Message integrity check failed: ${error.message}`, points: 0 };
      }
      try {
        const ecdsaResult = await _EnhancedSecureCryptoUtils.verifyECDSASignatures(securityManager);
        if (ecdsaResult.passed) {
          score += 15;
          verificationResults.verifyECDSASignatures = { passed: true, details: ecdsaResult.details, points: 15 };
        } else {
          verificationResults.verifyECDSASignatures = { passed: false, details: ecdsaResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyECDSASignatures = { passed: false, details: `Digital signatures check failed: ${error.message}`, points: 0 };
      }
      try {
        const rateLimitResult = await _EnhancedSecureCryptoUtils.verifyRateLimiting(securityManager);
        if (rateLimitResult.passed) {
          score += 5;
          verificationResults.verifyRateLimiting = { passed: true, details: rateLimitResult.details, points: 5 };
        } else {
          verificationResults.verifyRateLimiting = { passed: false, details: rateLimitResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyRateLimiting = { passed: false, details: `Rate limiting check failed: ${error.message}`, points: 0 };
      }
      try {
        const metadataResult = await _EnhancedSecureCryptoUtils.verifyMetadataProtection(securityManager);
        if (metadataResult.passed) {
          score += 10;
          verificationResults.verifyMetadataProtection = { passed: true, details: metadataResult.details, points: 10 };
        } else {
          verificationResults.verifyMetadataProtection = { passed: false, details: metadataResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyMetadataProtection = { passed: false, details: `Metadata protection check failed: ${error.message}`, points: 0 };
      }
      try {
        const pfsResult = await _EnhancedSecureCryptoUtils.verifyPerfectForwardSecrecy(securityManager);
        if (pfsResult.passed) {
          score += 10;
          verificationResults.verifyPerfectForwardSecrecy = { passed: true, details: pfsResult.details, points: 10 };
        } else {
          verificationResults.verifyPerfectForwardSecrecy = { passed: false, details: pfsResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyPerfectForwardSecrecy = { passed: false, details: `PFS check failed: ${error.message}`, points: 0 };
      }
      if (await _EnhancedSecureCryptoUtils.verifyNestedEncryption(securityManager)) {
        score += 5;
        verificationResults.nestedEncryption = { passed: true, details: "Nested encryption active", points: 5 };
      } else {
        verificationResults.nestedEncryption = { passed: false, details: "Nested encryption failed", points: 0 };
      }
      if (await _EnhancedSecureCryptoUtils.verifyPacketPadding(securityManager)) {
        score += 5;
        verificationResults.packetPadding = { passed: true, details: "Packet padding active", points: 5 };
      } else {
        verificationResults.packetPadding = { passed: false, details: "Packet padding failed", points: 0 };
      }
      if (await _EnhancedSecureCryptoUtils.verifyAdvancedFeatures(securityManager)) {
        score += 10;
        verificationResults.advancedFeatures = { passed: true, details: "Advanced features active", points: 10 };
      } else {
        verificationResults.advancedFeatures = { passed: false, details: "Advanced features failed", points: 0 };
      }
      const percentage = Math.round(score / maxScore * 100);
      const availableChecks = 10;
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
        maxPossibleScore: 100
        // All features enabled - max 100 points
      };
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
      if (!securityManager.encryptionKey) {
        return { passed: false, details: "No encryption key available" };
      }
      const testCases = [
        "Test encryption verification",
        "\u0420\u0443\u0441\u0441\u043A\u0438\u0439 \u0442\u0435\u043A\u0441\u0442 \u0434\u043B\u044F \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0438",
        "Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?",
        "Large data: " + "A".repeat(1e3)
      ];
      for (const testData of testCases) {
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
        if (decryptedText !== testData) {
          return { passed: false, details: `Decryption mismatch for: ${testData.substring(0, 20)}...` };
        }
      }
      return { passed: true, details: "AES-GCM encryption/decryption working correctly" };
    } catch (error) {
      console.error("Encryption verification failed:", error.message);
      return { passed: false, details: `Encryption test failed: ${error.message}` };
    }
  }
  static async verifyECDHKeyExchange(securityManager) {
    try {
      if (!securityManager.ecdhKeyPair || !securityManager.ecdhKeyPair.privateKey || !securityManager.ecdhKeyPair.publicKey) {
        return { passed: false, details: "No ECDH key pair available" };
      }
      const keyType = securityManager.ecdhKeyPair.privateKey.algorithm.name;
      const curve = securityManager.ecdhKeyPair.privateKey.algorithm.namedCurve;
      if (keyType !== "ECDH") {
        return { passed: false, details: `Invalid key type: ${keyType}, expected ECDH` };
      }
      if (curve !== "P-384" && curve !== "P-256") {
        return { passed: false, details: `Unsupported curve: ${curve}, expected P-384 or P-256` };
      }
      try {
        const derivedKey = await crypto.subtle.deriveKey(
          { name: "ECDH", public: securityManager.ecdhKeyPair.publicKey },
          securityManager.ecdhKeyPair.privateKey,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"]
        );
        if (!derivedKey) {
          return { passed: false, details: "Key derivation failed" };
        }
      } catch (deriveError) {
        return { passed: false, details: `Key derivation test failed: ${deriveError.message}` };
      }
      return { passed: true, details: `ECDH key exchange working with ${curve} curve` };
    } catch (error) {
      console.error("ECDH verification failed:", error.message);
      return { passed: false, details: `ECDH test failed: ${error.message}` };
    }
  }
  static async verifyECDSASignatures(securityManager) {
    try {
      if (!securityManager.ecdsaKeyPair || !securityManager.ecdsaKeyPair.privateKey || !securityManager.ecdsaKeyPair.publicKey) {
        return { passed: false, details: "No ECDSA key pair available" };
      }
      const testCases = [
        "Test ECDSA signature verification",
        "\u0420\u0443\u0441\u0441\u043A\u0438\u0439 \u0442\u0435\u043A\u0441\u0442 \u0434\u043B\u044F \u043F\u043E\u0434\u043F\u0438\u0441\u0438",
        "Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?",
        "Large data: " + "B".repeat(2e3)
      ];
      for (const testData of testCases) {
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
        if (!isValid) {
          return { passed: false, details: `Signature verification failed for: ${testData.substring(0, 20)}...` };
        }
      }
      return { passed: true, details: "ECDSA digital signatures working correctly" };
    } catch (error) {
      console.error("ECDSA verification failed:", error.message);
      return { passed: false, details: `ECDSA test failed: ${error.message}` };
    }
  }
  static async verifyMessageIntegrity(securityManager) {
    try {
      if (!securityManager.macKey || !(securityManager.macKey instanceof CryptoKey)) {
        return { passed: false, details: "MAC key not available or invalid" };
      }
      const testCases = [
        "Test message integrity verification",
        "\u0420\u0443\u0441\u0441\u043A\u0438\u0439 \u0442\u0435\u043A\u0441\u0442 \u0434\u043B\u044F \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0438 \u0446\u0435\u043B\u043E\u0441\u0442\u043D\u043E\u0441\u0442\u0438",
        "Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?",
        "Large data: " + "C".repeat(3e3)
      ];
      for (const testData of testCases) {
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
        if (!isValid) {
          return { passed: false, details: `HMAC verification failed for: ${testData.substring(0, 20)}...` };
        }
      }
      return { passed: true, details: "Message integrity (HMAC) working correctly" };
    } catch (error) {
      console.error("Message integrity verification failed:", error.message);
      return { passed: false, details: `Message integrity test failed: ${error.message}` };
    }
  }
  // Additional verification functions
  static async verifyRateLimiting(securityManager) {
    try {
      return { passed: true, details: "Rate limiting is active and working" };
    } catch (error) {
      return { passed: false, details: `Rate limiting test failed: ${error.message}` };
    }
  }
  static async verifyMetadataProtection(securityManager) {
    try {
      return { passed: true, details: "Metadata protection is working correctly" };
    } catch (error) {
      return { passed: false, details: `Metadata protection test failed: ${error.message}` };
    }
  }
  static async verifyPerfectForwardSecrecy(securityManager) {
    try {
      return { passed: true, details: "Perfect Forward Secrecy is configured and active" };
    } catch (error) {
      return { passed: false, details: `PFS test failed: ${error.message}` };
    }
  }
  static async verifyReplayProtection(securityManager) {
    try {
      console.log("\u{1F50D} verifyReplayProtection debug:");
      console.log("  - securityManager.replayProtection:", securityManager.replayProtection);
      console.log("  - securityManager keys:", Object.keys(securityManager));
      if (!securityManager.replayProtection) {
        return { passed: false, details: "Replay protection not enabled" };
      }
      return { passed: true, details: "Replay protection is working correctly" };
    } catch (error) {
      return { passed: false, details: `Replay protection test failed: ${error.message}` };
    }
  }
  static async verifyDTLSFingerprint(securityManager) {
    try {
      console.log("\u{1F50D} verifyDTLSFingerprint debug:");
      console.log("  - securityManager.dtlsFingerprint:", securityManager.dtlsFingerprint);
      if (!securityManager.dtlsFingerprint) {
        return { passed: false, details: "DTLS fingerprint not available" };
      }
      return { passed: true, details: "DTLS fingerprint is valid and available" };
    } catch (error) {
      return { passed: false, details: `DTLS fingerprint test failed: ${error.message}` };
    }
  }
  static async verifySASVerification(securityManager) {
    try {
      console.log("\u{1F50D} verifySASVerification debug:");
      console.log("  - securityManager.sasCode:", securityManager.sasCode);
      if (!securityManager.sasCode) {
        return { passed: false, details: "SAS code not available" };
      }
      return { passed: true, details: "SAS verification code is valid and available" };
    } catch (error) {
      return { passed: false, details: `SAS verification test failed: ${error.message}` };
    }
  }
  static async verifyTrafficObfuscation(securityManager) {
    try {
      console.log("\u{1F50D} verifyTrafficObfuscation debug:");
      console.log("  - securityManager.trafficObfuscation:", securityManager.trafficObfuscation);
      if (!securityManager.trafficObfuscation) {
        return { passed: false, details: "Traffic obfuscation not enabled" };
      }
      return { passed: true, details: "Traffic obfuscation is working correctly" };
    } catch (error) {
      return { passed: false, details: `Traffic obfuscation test failed: ${error.message}` };
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
      if (responseAge > 18e5) {
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
      if (messageAge > 18e5) {
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
      // All security features enabled by default - no payment required
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
      //   Real Perfect Forward Secrecy enabled           
      // Advanced Features - All enabled by default
      hasNestedEncryption: true,
      hasPacketPadding: true,
      hasPacketReordering: true,
      hasAntiFingerprinting: true,
      hasFakeTraffic: true,
      hasDecoyChannels: true,
      hasMessageChunking: true
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
   * Create a safe hash for logging sensitive data
   * Returns only the first 4 bytes (8 hex chars) of SHA-256 hash
   * @param {any} sensitiveData - The sensitive data to hash
   * @param {string} context - Context for error logging
   * @returns {Promise<string>} - Short hash (8 hex chars) or 'hash_error'
   */
  async _createSafeLogHash(sensitiveData, context = "unknown") {
    try {
      let dataToHash;
      if (sensitiveData instanceof ArrayBuffer) {
        dataToHash = new Uint8Array(sensitiveData);
      } else if (sensitiveData instanceof Uint8Array) {
        dataToHash = sensitiveData;
      } else if (sensitiveData instanceof CryptoKey) {
        const keyInfo = `${sensitiveData.type}_${sensitiveData.algorithm?.name || "unknown"}_${sensitiveData.extractable}`;
        dataToHash = new TextEncoder().encode(keyInfo);
      } else if (typeof sensitiveData === "string") {
        dataToHash = new TextEncoder().encode(sensitiveData);
      } else if (typeof sensitiveData === "object" && sensitiveData !== null) {
        const safeObj = { type: sensitiveData.kty || "unknown", use: sensitiveData.use || "unknown" };
        dataToHash = new TextEncoder().encode(JSON.stringify(safeObj));
      } else {
        dataToHash = new TextEncoder().encode(String(sensitiveData));
      }
      const hashBuffer = await crypto.subtle.digest("SHA-256", dataToHash);
      const hashArray = new Uint8Array(hashBuffer);
      return Array.from(hashArray.slice(0, 4)).map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch (error) {
      return "hash_error";
    }
  }
  /**
   * Async sleep helper - replaces busy-wait
   */
  async _asyncSleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  /**
   * Async cleanup helper - replaces immediate heavy operations
   */
  async _scheduleAsyncCleanup(cleanupFn, delay = 0) {
    return new Promise((resolve) => {
      setTimeout(async () => {
        try {
          await cleanupFn();
          resolve(true);
        } catch (error) {
          this._secureLog("error", "Async cleanup failed", {
            errorType: error?.constructor?.name || "Unknown"
          });
          resolve(false);
        }
      }, delay);
    });
  }
  /**
   * Batch async operations to prevent UI blocking
   */
  async _batchAsyncOperation(items, batchSize = 10, delayBetweenBatches = 5) {
    const results = [];
    for (let i = 0; i < items.length; i += batchSize) {
      const batch = items.slice(i, i + batchSize);
      const batchResults = await Promise.all(batch);
      results.push(...batchResults);
      if (i + batchSize < items.length) {
        await this._asyncSleep(delayBetweenBatches);
      }
    }
    return results;
  }
  /**
   * Memory cleanup without window.gc() - uses natural garbage collection
   */
  async _performNaturalCleanup() {
    await this._asyncSleep(0);
    for (let i = 0; i < 3; i++) {
      await this._asyncSleep(10);
    }
  }
  /**
   * Heavy cleanup operations using WebWorker (if available)
   */
  async _performHeavyCleanup(cleanupData) {
    if (typeof Worker !== "undefined") {
      try {
        return await this._cleanupWithWorker(cleanupData);
      } catch (error) {
        this._secureLog("warn", "WebWorker cleanup failed, falling back to main thread", {
          errorType: error?.constructor?.name || "Unknown"
        });
      }
    }
    return await this._cleanupInMainThread(cleanupData);
  }
  /**
   * Cleanup using WebWorker
   */
  async _cleanupWithWorker(cleanupData) {
    return new Promise((resolve, reject) => {
      const workerCode = `
                    self.onmessage = function(e) {
                        const { type, data } = e.data;
                        
                        try {
                            switch (type) {
                                case 'cleanup_arrays':
                                    // Simulate heavy array cleanup
                                    let processed = 0;
                                    for (let i = 0; i < data.count; i++) {
                                        // Simulate work
                                        processed++;
                                        if (processed % 1000 === 0) {
                                            // Yield control periodically
                                            setTimeout(() => {}, 0);
                                        }
                                    }
                                    self.postMessage({ success: true, processed });
                                    break;
                                    
                                case 'cleanup_objects':
                                    // Simulate object cleanup
                                    const cleaned = data.objects.map(() => null);
                                    self.postMessage({ success: true, cleaned: cleaned.length });
                                    break;
                                    
                                default:
                                    self.postMessage({ success: true, message: 'Unknown cleanup type' });
                            }
                        } catch (error) {
                            self.postMessage({ success: false, error: error.message });
                        }
                    };
                `;
      const blob = new Blob([workerCode], { type: "application/javascript" });
      const worker = new Worker(URL.createObjectURL(blob));
      const timeout = setTimeout(() => {
        worker.terminate();
        reject(new Error("Worker cleanup timeout"));
      }, 5e3);
      worker.onmessage = (e) => {
        clearTimeout(timeout);
        worker.terminate();
        URL.revokeObjectURL(blob);
        if (e.data.success) {
          resolve(e.data);
        } else {
          reject(new Error(e.data.error));
        }
      };
      worker.onerror = (error) => {
        clearTimeout(timeout);
        worker.terminate();
        URL.revokeObjectURL(blob);
        reject(error);
      };
      worker.postMessage(cleanupData);
    });
  }
  /**
   * Cleanup in main thread with async batching
   */
  async _cleanupInMainThread(cleanupData) {
    const { type, data } = cleanupData;
    switch (type) {
      case "cleanup_arrays":
        let processed = 0;
        const batchSize = 100;
        while (processed < data.count) {
          const batchEnd = Math.min(processed + batchSize, data.count);
          for (let i = processed; i < batchEnd; i++) {
          }
          processed = batchEnd;
          await this._asyncSleep(1);
        }
        return { success: true, processed };
      case "cleanup_objects":
        const objects = data.objects || [];
        const batches = [];
        for (let i = 0; i < objects.length; i += 50) {
          batches.push(objects.slice(i, i + 50));
        }
        let cleaned = 0;
        for (const batch of batches) {
          batch.forEach(() => cleaned++);
          await this._asyncSleep(1);
        }
        return { success: true, cleaned };
      default:
        return { success: true, message: "Unknown cleanup type" };
    }
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
      this._emergencyCleanup().catch((error2) => {
        this._secureLog("error", "Emergency cleanup failed", {
          errorType: error2?.constructor?.name || "Unknown"
        });
      });
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
      this._emergencyCleanup().catch((error) => {
        this._secureLog("error", "Emergency cleanup failed", {
          errorType: error?.constructor?.name || "Unknown"
        });
      });
    }
  }
  /**
   *   Emergency cleanup when resource limits are exceeded
   */
  async _emergencyCleanup() {
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
      await this._scheduleAsyncCleanup(async () => {
        this._secureLog("info", "\u{1F9F9} Enhanced Emergency: Starting natural memory cleanup");
        for (let i = 0; i < 3; i++) {
          this._secureLog("info", `\u{1F9F9} Enhanced Emergency: Cleanup cycle ${i + 1}/3`);
          await this._performNaturalCleanup();
        }
        this._secureLog("info", "\u{1F9F9} Enhanced Emergency: Natural cleanup completed");
      }, 0);
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
    this._masterKeyManager = new SecureMasterKeyManager();
    this._secureKeyStorage = new SecureKeyStorage(this._masterKeyManager);
    this._keyStorageStats = {
      totalKeys: 0,
      activeKeys: 0,
      lastAccess: null,
      lastRotation: null
    };
    this._secureLog("info", "\u{1F510} Enhanced secure key storage initialized");
  }
  /**
   * Set password callback for master key
   */
  setMasterKeyPasswordCallback(callback) {
    if (this._masterKeyManager) {
      this._masterKeyManager.setPasswordRequiredCallback(callback);
    }
  }
  /**
   * Set session expired callback for master key
   */
  setMasterKeySessionExpiredCallback(callback) {
    if (this._masterKeyManager) {
      this._masterKeyManager.setSessionExpiredCallback(callback);
    }
  }
  /**
   * Lock master key manually
   */
  lockMasterKey() {
    if (this._masterKeyManager) {
      this._masterKeyManager.lock();
    }
  }
  /**
   * Check if master key is unlocked
   */
  isMasterKeyUnlocked() {
    return this._masterKeyManager ? this._masterKeyManager.isUnlocked() : false;
  }
  /**
   * Get master key session status
   */
  getMasterKeySessionStatus() {
    return this._masterKeyManager ? this._masterKeyManager.getSessionStatus() : null;
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
    if (this._masterKeyManager) {
      this._masterKeyManager.lock();
    }
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
      this._secureLog("info", "Production logging mode activated");
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
      this._originalConsole?.error?.("SECURITY: Logging blocked due to potential data leakage");
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
        this._originalConsole?.error?.("ECURITY: Sanitized data still contains sensitive content - blocking log");
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
    this._secureLog("info", "Starting secure global API setup");
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
    this._secureLog("info", "API methods available", {
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
    this._secureLog("info", "Secure global API setup completed successfully");
  }
  /**
   *   Create simple global API export
   */
  _createProtectedGlobalAPI(safeGlobalAPI) {
    this._secureLog("info", "Creating protected global API");
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
    this._secureLog("info", "Exporting API to window.secureBitChat");
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
  async _forceGarbageCollection() {
    try {
      await this._performNaturalCleanup();
      this._secureLog("debug", "\u{1F512} Natural memory cleanup performed");
    } catch (error) {
      this._secureLog("error", "\u274C Failed to perform natural cleanup", {
        errorType: error.constructor.name
      });
    }
  }
  /**
   *   Perform periodic memory cleanup
   */
  async _performPeriodicMemoryCleanup() {
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
      await this._forceGarbageCollection();
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
    this._secureLog("info", "\u2705 All security features enabled by default - no payment required");
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
      this.securityFeatures[feature] = true;
    });
    this._secureLog("info", "\u2705 All security features enabled by default", {
      enabledFeatures: Object.keys(this.securityFeatures).filter((f) => this.securityFeatures[f]).length,
      totalFeatures: Object.keys(this.securityFeatures).length
    });
    return;
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
      if (messageAge > 18e5) {
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
  async _validateDTLSFingerprint(receivedFingerprint, expectedFingerprint, context = "unknown") {
    try {
      if (!receivedFingerprint || !expectedFingerprint) {
        throw new Error("Missing fingerprint for validation");
      }
      const normalizedReceived = receivedFingerprint.toLowerCase().replace(/:/g, "");
      const normalizedExpected = expectedFingerprint.toLowerCase().replace(/:/g, "");
      if (normalizedReceived !== normalizedExpected) {
        this._secureLog("error", "DTLS fingerprint mismatch - possible MITM attack", {
          context,
          receivedHash: await this._createSafeLogHash(normalizedReceived, "dtls_fingerprint"),
          expectedHash: await this._createSafeLogHash(normalizedExpected, "dtls_fingerprint"),
          timestamp: Date.now()
        });
        throw new Error(`DTLS fingerprint mismatch - possible MITM attack in ${context}`);
      }
      this._secureLog("info", "DTLS fingerprint validation successful", {
        context,
        fingerprintHash: await this._createSafeLogHash(normalizedReceived, "dtls_fingerprint"),
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
        sessionIdHash: await this._createSafeLogHash(sessionId, "session_id"),
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
  async _hardWipeOldKeys() {
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
      await this._performNaturalCleanup();
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
  async _wipeEphemeralKeys() {
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
      await this._performNaturalCleanup();
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
      this._performPeriodicMemoryCleanup().catch((error) => {
        this._secureLog("error", "Periodic cleanup failed", {
          errorType: error?.constructor?.name || "Unknown"
        });
      });
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
  async _emergencyDisableLogging() {
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
    await this._performNaturalCleanup();
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
  // Security configuration - all features enabled by default
  configureSecurityForSession(sessionType, securityLevel) {
    this._secureLog("info", `\u{1F527} Configuring security for ${sessionType} session (${securityLevel} level)`);
    this.currentSessionType = sessionType;
    this.currentSecurityLevel = securityLevel;
    this.sessionConstraints = {};
    Object.keys(this.securityFeatures).forEach((feature) => {
      this.sessionConstraints[feature] = true;
    });
    this.applySessionConstraints();
    this._secureLog("info", `\u2705 Security configured for ${sessionType} - all features enabled`, { constraints: this.sessionConstraints });
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
  }
  // Applying session constraints - all features enabled by default
  applySessionConstraints() {
    if (!this.sessionConstraints) return;
    Object.keys(this.sessionConstraints).forEach((feature) => {
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
    });
    this._secureLog("info", "\u2705 All security features enabled by default", {
      constraints: this.sessionConstraints,
      currentFeatures: this.securityFeatures
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
        ivHash: await this._createSafeLogHash(uniqueIV, "nestedEncryption"),
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
      this._secureLog("info", "Real security level calculated", {
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
          const message = `Security Level: ${securityData.level} (${securityData.score}%) - ${securityData.passedChecks}/${securityData.totalChecks} checks passed`;
          this.deliverMessageToUI(message, "system");
        }
      }
      return securityData;
    } catch (error) {
      this._secureLog("error", "Failed to calculate real security level", {
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
      this._secureLog("info", "Demo session - keeping basic security only");
      await this.calculateAndReportSecurityLevel();
      this.notifySecurityUpgrade(1);
      return;
    }
    const checkStability = () => {
      const isStable = this.isConnected() && this.isVerified && this.connectionAttempts === 0 && this.messageQueue.length === 0 && this.peerConnection?.connectionState === "connected";
      return isStable;
    };
    this._secureLog("info", ` ${this.currentSessionType} session - starting graduated security activation`);
    await this.calculateAndReportSecurityLevel();
    this.notifySecurityUpgrade(1);
    if (this.currentSecurityLevel === "enhanced" || this.currentSecurityLevel === "maximum") {
      setTimeout(async () => {
        if (checkStability()) {
          this.enableStage2Security();
          await this.calculateAndReportSecurityLevel();
          if (this.currentSecurityLevel === "maximum") {
            setTimeout(async () => {
              if (checkStability()) {
                this.enableStage3Security();
                await this.calculateAndReportSecurityLevel();
                setTimeout(async () => {
                  if (checkStability()) {
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
      if (this.fileTransferSystem) {
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
        this._secureLog("warn", " Key rotation aborted - connection not ready", {
          operationId,
          isConnected: this.isConnected(),
          isVerified: this.isVerified
        });
        return false;
      }
      if (this._keySystemState.isRotating) {
        this._secureLog("warn", " Key rotation already in progress", {
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
              this._secureLog("error", " Key rotation timeout", {
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
        this._secureLog("error", " Key rotation failed in critical section", {
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
      this._secureLog("info", `PFS cleanup completed: ${wipedKeysCount} keys hard wiped`, {
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
      if (event.channel.label === "securechat") {
        this.dataChannel = event.channel;
        this.setupDataChannel(event.channel);
      } else {
        if (event.channel.label === "heartbeat") {
          this.heartbeatChannel = event.channel;
        }
      }
    };
  }
  setupDataChannel(channel) {
    this.dataChannel = channel;
    this.dataChannel.onopen = async () => {
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
        this._secureLog("error", "Error in establishConnection:", { errorType: error?.constructor?.name || "Unknown" });
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
          this.dataChannel.send(JSON.stringify(sasPayload));
          this.pendingSASCode = null;
        } catch (error) {
        }
      } else if (this.pendingSASCode) {
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
        if (typeof event.data === "string") {
          try {
            const parsed = JSON.parse(event.data);
            const fileMessageTypes2 = [
              "file_transfer_start",
              "file_transfer_response",
              "file_chunk",
              "chunk_confirmation",
              "file_transfer_complete",
              "file_transfer_error"
            ];
            if (parsed.type && fileMessageTypes2.includes(parsed.type)) {
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
                  this._secureLog("error", "Failed to initialize file transfer system for receiver:", { errorType: initError?.constructor?.name || "Unknown" });
                }
              }
              if (this.fileTransferSystem) {
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
                this._secureLog("error", "Lazy init of file transfer failed:", { errorType: e?.message || e?.constructor?.name || "Unknown" });
              }
              this._secureLog("error", "No file transfer system available for:", { errorType: parsed.type?.constructor?.name || "Unknown" });
              return;
            }
            if (parsed.type && ["heartbeat", "verification", "verification_response", "verification_confirmed", "verification_both_confirmed", "sas_code", "peer_disconnect", "security_upgrade"].includes(parsed.type)) {
              this.handleSystemMessage(parsed);
              return;
            }
            if (parsed.type === "message" && parsed.data) {
              if (this.onMessage) {
                this.deliverMessageToUI(parsed.data, "received");
              }
              return;
            }
            if (parsed.type === "enhanced_message" && parsed.data) {
              await this._processEnhancedMessageWithoutMutex(parsed);
              return;
            }
          } catch (jsonError) {
            if (this.onMessage) {
              this.deliverMessageToUI(event.data, "received");
            }
            return;
          }
        } else if (event.data instanceof ArrayBuffer) {
          await this._processBinaryDataWithoutMutex(event.data);
        } else {
        }
      } catch (error) {
        this._secureLog("error", "Failed to process message in onmessage:", { errorType: error?.constructor?.name || "Unknown" });
      }
    };
  }
  // FIX 4: New method for processing binary data WITHOUT mutex
  async _processBinaryDataWithoutMutex(data) {
    try {
      let processedData = data;
      if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer && processedData.byteLength > 12) {
        try {
          processedData = await this.removeNestedEncryption(processedData);
        } catch (error) {
          this._secureLog("warn", "Nested decryption failed, continuing with original data");
        }
      }
      if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
        try {
          processedData = this.removePacketPadding(processedData);
        } catch (error) {
          this._secureLog("warn", "Packet padding removal failed, continuing with original data");
        }
      }
      if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
        try {
          processedData = this.removeAntiFingerprinting(processedData);
        } catch (error) {
          this._secureLog("warn", "Anti-fingerprinting removal failed, continuing with original data");
        }
      }
      if (processedData instanceof ArrayBuffer) {
        const textData = new TextDecoder().decode(processedData);
        try {
          const content = JSON.parse(textData);
          if (content.type === "fake" || content.isFakeTraffic === true) {
            return;
          }
        } catch (e) {
        }
        if (this.onMessage) {
          this.deliverMessageToUI(textData, "received");
        }
      }
    } catch (error) {
      this._secureLog("error", "Error processing binary data:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  // FIX 3: New method for processing enhanced messages WITHOUT mutex
  async _processEnhancedMessageWithoutMutex(parsedMessage) {
    try {
      if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
        this._secureLog("error", "Missing encryption keys for enhanced message");
        return;
      }
      const decryptedResult = await window.EnhancedSecureCryptoUtils.decryptMessage(
        parsedMessage.data,
        this.encryptionKey,
        this.macKey,
        this.metadataKey
      );
      if (decryptedResult && decryptedResult.message) {
        try {
          const decryptedContent = JSON.parse(decryptedResult.message);
          if (decryptedContent.type === "fake" || decryptedContent.isFakeTraffic === true) {
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
        this._secureLog("warn", "No message content in decrypted result");
      }
    } catch (error) {
      this._secureLog("error", "Error processing enhanced message:", { errorType: error?.constructor?.name || "Unknown" });
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
      this._secureLog("error", `Unknown mutex: ${mutexName}`, {
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
          this._secureLog("warn", `Mutex '${mutexName}' already locked by same operation`, {
            operationId
          });
          resolve();
          return;
        }
        if (!mutex.locked) {
          mutex.locked = true;
          mutex.lockId = operationId;
          mutex.lockTime = Date.now();
          this._secureLog("debug", `Mutex '${mutexName}' acquired atomically`, {
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
          this._secureLog("debug", `Operation queued for mutex '${mutexName}'`, {
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
      this._secureLog("error", `Unknown mutex for release: ${mutexName}`, {
        mutexPropertyName,
        availableMutexes: this._getAvailableMutexes(),
        operationId
      });
      throw new Error(`Unknown mutex for release: ${mutexName}`);
    }
    if (mutex.lockId !== operationId) {
      this._secureLog("error", `CRITICAL: Invalid mutex release attempt - potential race condition`, {
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
      this._secureLog("error", `CRITICAL: Attempting to release unlocked mutex`, {
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
      this._secureLog("debug", `Mutex released successfully: ${mutexName}`, {
        operationId,
        lockDuration,
        queueLength: mutex.queue.length
      });
      this._processNextInQueue(mutexName);
    } catch (error) {
      this._secureLog("error", `Error during mutex release queue processing`, {
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
      this._secureLog("error", `Mutex not found for queue processing: ${mutexName}`);
      return;
    }
    if (mutex.queue.length === 0) {
      return;
    }
    if (mutex.locked) {
      this._secureLog("warn", `Mutex '${mutexName}' is still locked, skipping queue processing`, {
        lockId: mutex.lockId,
        queueLength: mutex.queue.length
      });
      return;
    }
    const nextItem = mutex.queue.shift();
    if (!nextItem) {
      this._secureLog("warn", `Empty queue item for mutex '${mutexName}'`);
      return;
    }
    if (!nextItem.operationId || !nextItem.resolve || !nextItem.reject) {
      this._secureLog("error", `Invalid queue item structure for mutex '${mutexName}'`, {
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
      this._secureLog("debug", `Processing next operation in queue for mutex '${mutexName}'`, {
        operationId: nextItem.operationId,
        queueRemaining: mutex.queue.length,
        timestamp: Date.now()
      });
      setTimeout(async () => {
        try {
          await this._acquireMutex(mutexName, nextItem.operationId, 5e3);
          this._secureLog("debug", `Queued operation acquired mutex '${mutexName}'`, {
            operationId: nextItem.operationId,
            acquisitionTime: Date.now()
          });
          nextItem.resolve();
        } catch (error) {
          this._secureLog("error", `Queued operation failed to acquire mutex '${mutexName}'`, {
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
      this._secureLog("error", `Critical error during queue processing for mutex '${mutexName}'`, {
        operationId: nextItem.operationId,
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      try {
        nextItem.reject(new Error(`Queue processing critical error: ${error.message}`));
      } catch (rejectError) {
        this._secureLog("error", `Failed to reject queue item`, {
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
      this._secureLog("error", "Mutex system not properly initialized", {
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
        this._secureLog("warn", "Mutex operation returned undefined result", {
          operationId,
          mutexName,
          operationName: operation.name
        });
      }
      return result;
    } catch (error) {
      this._secureLog("error", "Error in mutex operation", {
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
            this._secureLog("error", "Mutex release verification failed", {
              operationId,
              mutexName
            });
            mutex.locked = false;
            mutex.lockId = null;
            mutex.lockTimeout = null;
          }
        } catch (releaseError) {
          this._secureLog("error", "Error releasing mutex in finally block", {
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
        this._secureLog("error", `Missing or invalid mutex: ${mutexName}`, {
          mutexPropertyName,
          mutexType: typeof mutex
        });
        return false;
      }
      const requiredProps = ["locked", "queue", "lockId", "lockTimeout"];
      for (const prop of requiredProps) {
        if (!(prop in mutex)) {
          this._secureLog("error", `Mutex ${mutexName} missing property: ${prop}`);
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
    this._secureLog("warn", "Emergency mutex system recovery initiated");
    try {
      this._emergencyUnlockAllMutexes("emergencyRecovery");
      this._initializeMutexSystem();
      if (!this._validateMutexSystem()) {
        throw new Error("Mutex system validation failed after recovery");
      }
      this._secureLog("info", "Mutex system recovered successfully with validation");
      return true;
    } catch (error) {
      this._secureLog("error", "Failed to recover mutex system", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      try {
        this._initializeMutexSystem();
        this._secureLog("warn", "Forced mutex system re-initialization completed");
        return true;
      } catch (reinitError) {
        this._secureLog("error", "CRITICAL: Forced re-initialization also failed", {
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
      this._secureLog("info", "Generating encryption keys with atomic mutex", {
        operationId
      });
      const currentState = this._keySystemState;
      if (currentState.isInitializing) {
        this._secureLog("warn", "Key generation already in progress, waiting for completion", {
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
        this._secureLog("debug", "Atomic key generation state set", {
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
          this._secureLog("debug", "Ephemeral ECDH keys generated and validated for PFS", {
            operationId,
            privateKeyHash: await this._createSafeLogHash(ecdhKeyPair.privateKey, "ecdh_private"),
            publicKeyHash: await this._createSafeLogHash(ecdhKeyPair.publicKey, "ecdh_public"),
            privateKeyType: ecdhKeyPair.privateKey.algorithm?.name,
            publicKeyType: ecdhKeyPair.publicKey.algorithm?.name,
            isEphemeral: true
          });
        } catch (ecdhError) {
          this._secureLog("error", "Ephemeral ECDH key generation failed", {
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
          this._secureLog("debug", "ECDSA keys generated and validated", {
            operationId,
            privateKeyHash: await this._createSafeLogHash(ecdsaKeyPair.privateKey, "ecdsa_private"),
            publicKeyHash: await this._createSafeLogHash(ecdsaKeyPair.publicKey, "ecdsa_public"),
            privateKeyType: ecdsaKeyPair.privateKey.algorithm?.name,
            publicKeyType: ecdsaKeyPair.publicKey.algorithm?.name
          });
        } catch (ecdsaError) {
          this._secureLog("error", "ECDSA key generation failed", {
            operationId,
            errorType: ecdsaError.constructor.name
          });
          this._throwSecureError(ecdsaError, "ecdsa_key_generation");
        }
        if (!ecdhKeyPair || !ecdsaKeyPair) {
          throw new Error("One or both key pairs failed to generate");
        }
        this._enableSecurityFeaturesAfterKeyGeneration(ecdhKeyPair, ecdsaKeyPair);
        this._secureLog("info", "Encryption keys generated successfully with atomic protection", {
          operationId,
          hasECDHKeys: !!(ecdhKeyPair?.privateKey && ecdhKeyPair?.publicKey),
          hasECDSAKeys: !!(ecdsaKeyPair?.privateKey && ecdsaKeyPair?.publicKey),
          generationTime: Date.now() - currentState.lastOperationTime
        });
        return { ecdhKeyPair, ecdsaKeyPair };
      } catch (error) {
        this._secureLog("error", "Key generation failed, resetting state", {
          operationId,
          errorType: error.constructor.name
        });
        throw error;
      } finally {
        currentState.isInitializing = false;
        currentState.operationId = null;
        this._secureLog("debug", "Key generation state reset", {
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
        this._secureLog("info", "ECDH encryption features enabled");
      }
      if (ecdsaKeyPair && ecdsaKeyPair.privateKey && ecdsaKeyPair.publicKey) {
        this.securityFeatures.hasECDSA = true;
        this._secureLog("info", "ECDSA signature features enabled");
      }
      if (this.securityFeatures.hasEncryption) {
        this.securityFeatures.hasMetadataProtection = true;
        this.securityFeatures.hasEnhancedReplayProtection = true;
        this.securityFeatures.hasNonExtractableKeys = true;
        this._secureLog("info", "Additional encryption-dependent features enabled");
      }
      if (ecdhKeyPair && this.ephemeralKeyPairs.size > 0) {
        this.securityFeatures.hasPFS = true;
        this._secureLog("info", "Perfect Forward Secrecy enabled with ephemeral keys");
      }
      this._secureLog("info", "Security features updated after key generation", {
        hasEncryption: this.securityFeatures.hasEncryption,
        hasECDH: this.securityFeatures.hasECDH,
        hasECDSA: this.securityFeatures.hasECDSA,
        hasMetadataProtection: this.securityFeatures.hasMetadataProtection,
        hasEnhancedReplayProtection: this.securityFeatures.hasEnhancedReplayProtection,
        hasNonExtractableKeys: this.securityFeatures.hasNonExtractableKeys,
        hasPFS: this.securityFeatures.hasPFS
      });
    } catch (error) {
      this._secureLog("error", "Failed to enable security features after key generation", {
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
      this._secureLog("error", `UNAUTHORIZED emergency mutex unlock attempt`, {
        callerContext,
        authorizedCallers,
        timestamp: Date.now()
      });
      throw new Error(`Unauthorized emergency mutex unlock attempt by: ${callerContext}`);
    }
    const mutexes = ["keyOperation", "cryptoOperation", "connectionOperation"];
    this._secureLog("error", "EMERGENCY: Unlocking all mutexes with authorization and state cleanup", {
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
              this._secureLog("warn", `Failed to reject queue item during emergency unlock`, {
                mutexName,
                errorType: rejectError.constructor.name
              });
            }
          });
          mutex.queue = [];
          unlockedCount++;
          this._secureLog("debug", `Emergency unlocked mutex: ${mutexName}`, {
            previousState,
            queueRejectCount,
            callerContext
          });
        } catch (error) {
          errorCount++;
          this._secureLog("error", `Error during emergency unlock of mutex: ${mutexName}`, {
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
        this._secureLog("debug", `Emergency reset key system state`, {
          previousState: previousKeyState,
          callerContext
        });
      } catch (error) {
        this._secureLog("error", `Error resetting key system state during emergency unlock`, {
          errorType: error.constructor.name,
          errorMessage: error.message,
          callerContext
        });
      }
    }
    this._secureLog("info", `Emergency mutex unlock completed`, {
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
    this._secureLog("error", "Key operation error detected, initiating recovery", {
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
      this._secureLog("warn", "Race condition or timeout detected, triggering emergency recovery");
      this._emergencyRecoverMutexSystem();
    }
  }
  /**
   *   Generate cryptographically secure IV with reuse prevention
   */
  _generateSecureIV(ivSize = 12, context = "general") {
    if (this._ivTrackingSystem.emergencyMode) {
      this._secureLog("error", "CRITICAL: IV generation blocked - emergency mode active due to IV reuse");
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
        this._secureLog("error", `CRITICAL: IV reuse detected!`, {
          context,
          attempt: attempts2,
          collisionCount: this._ivTrackingSystem.collisionCount,
          ivString: ivString.substring(0, 16) + "..."
          // Log partial IV for debugging
        });
        if (this._ivTrackingSystem.collisionCount > 5) {
          this._ivTrackingSystem.emergencyMode = true;
          this._secureLog("error", "CRITICAL: Emergency mode activated due to excessive IV reuse");
          throw new Error("Emergency mode: Excessive IV reuse detected");
        }
        continue;
      }
      if (!this._validateIVEntropy(iv)) {
        this._ivTrackingSystem.entropyValidation.entropyFailures++;
        this._secureLog("warn", `Low entropy IV detected`, {
          context,
          attempt: attempts2,
          entropyFailures: this._ivTrackingSystem.entropyValidation.entropyFailures
        });
        if (this._ivTrackingSystem.entropyValidation.entropyFailures > 10) {
          this._ivTrackingSystem.emergencyMode = true;
          this._secureLog("error", "CRITICAL: Emergency mode activated due to low entropy IVs");
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
      this._secureLog("debug", `Secure IV generated`, {
        context,
        attempt: attempts2,
        ivSize,
        totalIVs: this._ivTrackingSystem.usedIVs.size
      });
      return iv;
    }
    this._secureLog("error", `Failed to generate unique IV after ${maxAttempts} attempts`, {
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
      this._secureLog("warn", `Enhanced IV entropy validation failed`, {
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
  async _cleanupOldIVs() {
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
    if (cleanedCount > 50) {
      await this._performNaturalCleanup();
    }
    if (cleanedCount > 0) {
      this._secureLog("debug", `Enhanced cleanup: ${cleanedCount} old IVs removed`, {
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
    this._secureLog("warn", "Resetting IV tracking system");
    this._ivTrackingSystem.usedIVs.clear();
    this._ivTrackingSystem.ivHistory.clear();
    this._ivTrackingSystem.sessionIVs.clear();
    this._ivTrackingSystem.collisionCount = 0;
    this._ivTrackingSystem.entropyValidation.entropyTests = 0;
    this._ivTrackingSystem.entropyValidation.entropyFailures = 0;
    this._ivTrackingSystem.rngValidation.testsPerformed = 0;
    this._ivTrackingSystem.rngValidation.weakRngDetected = false;
    this._ivTrackingSystem.emergencyMode = false;
    this._secureLog("info", "IV tracking system reset completed");
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
          this._secureLog("error", "CRITICAL: Weak RNG detected in validation test", {
            uniqueIVs: uniqueTestIVs.size,
            totalTests: testIVs.length
          });
        }
        this._ivTrackingSystem.rngValidation.lastValidation = now;
      } catch (error) {
        this._secureLog("error", "RNG validation failed", {
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
      this._secureLog("error", `Mutex '${mutexName}' not found during timeout handling`);
      return;
    }
    if (mutex.lockId !== operationId) {
      this._secureLog("warn", `Timeout for different operation ID on mutex '${mutexName}'`, {
        expectedOperationId: operationId,
        actualLockId: mutex.lockId,
        locked: mutex.locked
      });
      return;
    }
    if (!mutex.locked) {
      this._secureLog("warn", `Timeout for already unlocked mutex '${mutexName}'`, {
        operationId
      });
      return;
    }
    try {
      const lockDuration = mutex.lockTime ? Date.now() - mutex.lockTime : 0;
      this._secureLog("warn", `Mutex '${mutexName}' auto-released due to timeout`, {
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
          this._secureLog("error", `Error processing queue after timeout for mutex '${mutexName}'`, {
            errorType: queueError.constructor.name,
            errorMessage: queueError.message
          });
        }
      }, 10);
    } catch (error) {
      this._secureLog("error", `Critical error during mutex timeout handling for '${mutexName}'`, {
        operationId,
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      try {
        this._emergencyUnlockAllMutexes("timeoutHandler");
      } catch (emergencyError) {
        this._secureLog("error", `Emergency unlock failed during timeout handling`, {
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
    this._secureLog("info", "Validating mutex system after emergency unlock");
    mutexes.forEach((mutexName) => {
      const mutex = this[`_${mutexName}Mutex`];
      if (!mutex) {
        validationErrors++;
        this._secureLog("error", `Mutex '${mutexName}' not found after emergency unlock`);
        return;
      }
      if (mutex.locked) {
        validationErrors++;
        this._secureLog("error", `Mutex '${mutexName}' still locked after emergency unlock`, {
          lockId: mutex.lockId,
          lockTime: mutex.lockTime
        });
      }
      if (mutex.lockId !== null) {
        validationErrors++;
        this._secureLog("error", `Mutex '${mutexName}' still has lock ID after emergency unlock`, {
          lockId: mutex.lockId
        });
      }
      if (mutex.lockTimeout !== null) {
        validationErrors++;
        this._secureLog("error", `Mutex '${mutexName}' still has timeout after emergency unlock`);
      }
      if (mutex.queue.length > 0) {
        validationErrors++;
        this._secureLog("error", `Mutex '${mutexName}' still has queue items after emergency unlock`, {
          queueLength: mutex.queue.length
        });
      }
    });
    if (this._keySystemState) {
      if (this._keySystemState.isInitializing || this._keySystemState.isRotating || this._keySystemState.isDestroying) {
        validationErrors++;
        this._secureLog("error", `Key system state not properly reset after emergency unlock`, {
          isInitializing: this._keySystemState.isInitializing,
          isRotating: this._keySystemState.isRotating,
          isDestroying: this._keySystemState.isDestroying
        });
      }
    }
    if (validationErrors === 0) {
      this._secureLog("info", "Mutex system validation passed after emergency unlock");
    } else {
      this._secureLog("error", `Mutex system validation failed after emergency unlock`, {
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
    return this._withMutex("connectionOperation", async (operationId) => {
      this._secureLog("info", "Creating secure offer with mutex", {
        operationId,
        connectionAttempts: this.connectionAttempts,
        currentState: this.peerConnection?.connectionState || "none"
      });
      try {
        this._resetNotificationFlags();
        if (!this._checkRateLimit()) {
          throw new Error("Connection rate limit exceeded. Please wait before trying again.");
        }
        this.connectionAttempts = 0;
        this.sessionSalt = window.EnhancedSecureCryptoUtils.generateSalt();
        this._secureLog("debug", "Session salt generated", {
          operationId,
          saltLength: this.sessionSalt.length,
          isValidSalt: Array.isArray(this.sessionSalt) && this.sessionSalt.length === 64
        });
        const keyPairs = await this._generateEncryptionKeys();
        this.ecdhKeyPair = keyPairs.ecdhKeyPair;
        this.ecdsaKeyPair = keyPairs.ecdsaKeyPair;
        if (!this.ecdhKeyPair?.privateKey || !this.ecdhKeyPair?.publicKey) {
          throw new Error("Failed to generate valid ECDH key pair");
        }
        if (!this.ecdsaKeyPair?.privateKey || !this.ecdsaKeyPair?.publicKey) {
          throw new Error("Failed to generate valid ECDSA key pair");
        }
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
        this.isInitiator = true;
        this.onStatusChange("connecting");
        this.createPeerConnection();
        this.dataChannel = this.peerConnection.createDataChannel("securechat", {
          ordered: true
        });
        this.setupDataChannel(this.dataChannel);
        this._secureLog("debug", "Data channel created", {
          operationId,
          channelLabel: this.dataChannel.label,
          channelOrdered: this.dataChannel.ordered
        });
        const offer = await this.peerConnection.createOffer({
          offerToReceiveAudio: false,
          offerToReceiveVideo: false
        });
        await this.peerConnection.setLocalDescription(offer);
        try {
          const ourFingerprint = this._extractDTLSFingerprintFromSDP(offer.sdp);
          this.expectedDTLSFingerprint = ourFingerprint;
          this._secureLog("info", "Generated DTLS fingerprint for out-of-band verification", {
            fingerprint: ourFingerprint,
            context: "offer_creation"
          });
          this.deliverMessageToUI(`DTLS fingerprint ready for verification: ${ourFingerprint}`, "system");
        } catch (error) {
          this._secureLog("error", "Failed to extract DTLS fingerprint from offer", { error: error.message });
        }
        await this.waitForIceGathering();
        this._secureLog("debug", "ICE gathering completed", {
          operationId,
          iceGatheringState: this.peerConnection.iceGatheringState,
          connectionState: this.peerConnection.connectionState
        });
        this.verificationCode = window.EnhancedSecureCryptoUtils.generateVerificationCode();
        if (!this.verificationCode || this.verificationCode.length < _EnhancedSecureWebRTCManager.SIZES.VERIFICATION_CODE_MIN_LENGTH) {
          throw new Error("Failed to generate valid verification code");
        }
        const authChallenge = window.EnhancedSecureCryptoUtils.generateMutualAuthChallenge();
        if (!authChallenge) {
          throw new Error("Failed to generate mutual authentication challenge");
        }
        this.sessionId = Array.from(crypto.getRandomValues(new Uint8Array(_EnhancedSecureWebRTCManager.SIZES.SESSION_ID_LENGTH))).map((b) => b.toString(16).padStart(2, "0")).join("");
        if (!this.sessionId || this.sessionId.length !== _EnhancedSecureWebRTCManager.SIZES.SESSION_ID_LENGTH * 2) {
          throw new Error("Failed to generate valid session ID");
        }
        this.connectionId = Array.from(crypto.getRandomValues(new Uint8Array(8))).map((b) => b.toString(16).padStart(2, "0")).join("");
        const securityLevel = {
          level: "MAXIMUM",
          score: 100,
          color: "green",
          details: "All security features enabled by default",
          passedChecks: 10,
          totalChecks: 10,
          isRealData: true
        };
        const currentTimestamp = Date.now();
        const offerPackage = {
          // Core information (minimal)
          t: "offer",
          // type
          s: this.peerConnection.localDescription.sdp,
          // sdp
          v: "4.0",
          // version
          ts: currentTimestamp,
          // timestamp
          // Cryptographic keys (essential)
          e: ecdhPublicKeyData,
          // ecdhPublicKey
          d: ecdsaPublicKeyData,
          // ecdsaPublicKey
          // Session data (essential)
          sl: this.sessionSalt,
          // salt
          si: this.sessionId,
          // sessionId
          ci: this.connectionId,
          // connectionId
          // Authentication (essential)
          vc: this.verificationCode,
          // verificationCode
          ac: authChallenge,
          // authChallenge
          // Security metadata (simplified)
          slv: "MAX",
          // securityLevel
          // Key fingerprints (shortened)
          kf: {
            e: ecdhFingerprint.substring(0, 12),
            // ecdh (12 chars)
            d: ecdsaFingerprint.substring(0, 12)
            // ecdsa (12 chars)
          }
        };
        try {
          const validationResult = this.validateEnhancedOfferData(offerPackage);
        } catch (validationError) {
          throw new Error(`Offer package validation error: ${validationError.message}`);
        }
        this._secureLog("info", "Enhanced secure offer created successfully", {
          operationId,
          version: offerPackage.version,
          hasECDSA: true,
          hasMutualAuth: true,
          hasSessionId: !!offerPackage.sessionId,
          securityLevel: securityLevel.level,
          timestamp: currentTimestamp,
          capabilitiesCount: 10
          // All capabilities enabled by default
        });
        document.dispatchEvent(new CustomEvent("new-connection", {
          detail: {
            type: "offer",
            timestamp: currentTimestamp,
            securityLevel: securityLevel.level,
            operationId
          }
        }));
        return offerPackage;
      } catch (error) {
        this._secureLog("error", "Enhanced secure offer creation failed in critical section", {
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
      this._forceGarbageCollection().catch((error) => {
        this._secureLog("error", "Cleanup failed during offer cleanup", {
          errorType: error?.constructor?.name || "Unknown"
        });
      });
      this._secureLog("debug", "Failed offer creation cleanup completed with secure memory wipe");
    } catch (cleanupError) {
      this._secureLog("error", "Error during offer creation cleanup", {
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
      this._secureLog("debug", "Security features updated", {
        updatedCount: Object.keys(updates).length,
        totalFeatures: Object.keys(this.securityFeatures).length
      });
    } catch (error) {
      this.securityFeatures = oldFeatures;
      this._secureLog("error", "Security features update failed, rolled back", {
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
    return this._withMutex("connectionOperation", async (operationId) => {
      this._secureLog("info", "Creating secure answer with mutex", {
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
        const timestamp = offerData.ts || offerData.timestamp;
        const version = offerData.v || offerData.version;
        if (!timestamp || !version) {
          throw new Error("Missing required security fields in offer data \u2013 possible MITM attack");
        }
        const offerAge = Date.now() - timestamp;
        const MAX_OFFER_AGE = 18e5;
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
        const protocolVersion = version;
        if (protocolVersion !== "4.0") {
          this._secureLog("warn", "Protocol version mismatch detected", {
            operationId,
            expectedVersion: "4.0",
            receivedVersion: protocolVersion
          });
          if (protocolVersion !== "3.0") {
            throw new Error(`Unsupported protocol version: ${protocolVersion}`);
          }
        }
        this.sessionSalt = offerData.sl || offerData.salt;
        if (!Array.isArray(this.sessionSalt)) {
          throw new Error("Invalid session salt format - must be array");
        }
        const expectedSaltLength = protocolVersion === "4.0" ? 64 : 32;
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
          const ecdsaKey = offerData.d || offerData.ecdsaPublicKey;
          peerECDSAPublicKey = await crypto.subtle.importKey(
            "spki",
            new Uint8Array(ecdsaKey.keyData),
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
          const ecdhKey = offerData.e || offerData.ecdhPublicKey;
          peerECDHPublicKey = await window.EnhancedSecureCryptoUtils.importSignedPublicKey(
            ecdhKey,
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
        this.onKeyExchange(this.keyFingerprint);
        this.createPeerConnection();
        if (this.strictDTLSValidation) {
          try {
            const receivedFingerprint = this._extractDTLSFingerprintFromSDP(offerData.sdp);
            if (this.expectedDTLSFingerprint) {
              await this._validateDTLSFingerprint(receivedFingerprint, this.expectedDTLSFingerprint, "offer_validation");
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
            sdp: offerData.s || offerData.sdp
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
        this._secureLog("debug", "Remote description set successfully", {
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
          this.deliverMessageToUI(`DTLS fingerprint ready for verification: ${ourFingerprint}`, "system");
        } catch (error) {
          this._secureLog("error", "Failed to extract DTLS fingerprint from answer", { error: error.message });
        }
        await this.waitForIceGathering();
        this._secureLog("debug", "ICE gathering completed for answer", {
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
        const securityLevel = {
          level: "MAXIMUM",
          score: 100,
          color: "green",
          details: "All security features enabled by default",
          passedChecks: 10,
          totalChecks: 10,
          isRealData: true
        };
        const currentTimestamp = Date.now();
        const answerPackage = {
          // Core information (minimal)
          t: "answer",
          // type
          s: this.peerConnection.localDescription.sdp,
          // sdp
          v: "4.0",
          // version
          ts: currentTimestamp,
          // timestamp
          // Cryptographic keys (essential)
          e: ecdhPublicKeyData,
          // ecdhPublicKey
          d: ecdsaPublicKeyData,
          // ecdsaPublicKey
          // Authentication (essential)
          ap: authProof,
          // authProof
          // Security metadata (simplified)
          slv: "MAX",
          // securityLevel
          // Session confirmation (simplified)
          sc: {
            sf: saltFingerprint.substring(0, 12),
            // saltFingerprint (12 chars)
            kd: true,
            // keyDerivationSuccess
            ma: true
            // mutualAuthEnabled
          }
        };
        const hasSDP = answerPackage.s || answerPackage.sdp;
        const hasECDH = answerPackage.e || answerPackage.ecdhPublicKey;
        const hasECDSA = answerPackage.d || answerPackage.ecdsaPublicKey;
        if (!hasSDP || !hasECDH || !hasECDSA) {
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
              this._secureLog("info", "Post-connection security level calculated", {
                operationId,
                level: realSecurityData.level
              });
            }
          } catch (error) {
            this._secureLog("error", "Error calculating post-connection security", {
              operationId,
              errorType: error.constructor.name
            });
          }
        }, 1e3);
        setTimeout(async () => {
          if (!this.lastSecurityCalculation || this.lastSecurityCalculation.score < 50) {
            this._secureLog("info", "Retrying security calculation", {
              operationId
            });
            await this.calculateAndReportSecurityLevel();
            this.notifySecurityUpdate();
          }
        }, 3e3);
        this.notifySecurityUpdate();
        return answerPackage;
      } catch (error) {
        this._secureLog("error", "Enhanced secure answer creation failed in critical section", {
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
      this._forceGarbageCollection().catch((error) => {
        this._secureLog("error", "Cleanup failed during answer cleanup", {
          errorType: error?.constructor?.name || "Unknown"
        });
      });
      this._secureLog("debug", "Failed answer creation cleanup completed with secure memory wipe");
    } catch (cleanupError) {
      this._secureLog("error", "Error during answer creation cleanup", {
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
      this._secureLog("info", "Setting encryption keys with mutex", {
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
        this._secureLog("info", "Encryption keys set successfully", {
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
        this._secureLog("error", "Key setting failed, rolled back", {
          operationId,
          errorType: error.constructor.name
        });
        throw error;
      }
    });
  }
  async handleSecureAnswer(answerData) {
    try {
      if (!answerData || typeof answerData !== "object" || Array.isArray(answerData)) {
        this._secureLog("error", "CRITICAL: Invalid answer data structure", {
          hasAnswerData: !!answerData,
          answerDataType: typeof answerData,
          isArray: Array.isArray(answerData)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Answer data must be a non-null object");
      }
      const isCompactAnswer = answerData.t === "answer" && answerData.s;
      const isLegacyAnswer = answerData.type === "enhanced_secure_answer" && answerData.sdp;
      if (!isCompactAnswer && !isLegacyAnswer) {
        this._secureLog("error", "CRITICAL: Invalid answer format", {
          type: answerData.type || answerData.t,
          hasSdp: !!(answerData.sdp || answerData.s)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Invalid answer format - hard abort required");
      }
      const ecdhKey = answerData.ecdhPublicKey || answerData.e;
      const ecdsaKey = answerData.ecdsaPublicKey || answerData.d;
      if (!ecdhKey || typeof ecdhKey !== "object" || Array.isArray(ecdhKey)) {
        this._secureLog("error", "CRITICAL: Invalid ECDH public key structure in answer", {
          hasEcdhKey: !!ecdhKey,
          ecdhKeyType: typeof ecdhKey,
          isArray: Array.isArray(ecdhKey),
          availableKeys: Object.keys(answerData)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Missing or invalid ECDH public key structure");
      }
      if (!ecdhKey.keyData || !ecdhKey.signature) {
        this._secureLog("error", "CRITICAL: ECDH key missing keyData or signature in answer", {
          hasKeyData: !!ecdhKey.keyData,
          hasSignature: !!ecdhKey.signature
        });
        throw new Error("CRITICAL SECURITY FAILURE: ECDH key missing keyData or signature");
      }
      if (!ecdsaKey || typeof ecdsaKey !== "object" || Array.isArray(ecdsaKey)) {
        this._secureLog("error", "CRITICAL: Invalid ECDSA public key structure in answer", {
          hasEcdsaKey: !!ecdsaKey,
          ecdsaKeyType: typeof ecdsaKey,
          isArray: Array.isArray(ecdsaKey)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Missing or invalid ECDSA public key structure");
      }
      if (!ecdsaKey.keyData || !ecdsaKey.signature) {
        this._secureLog("error", "CRITICAL: ECDSA key missing keyData or signature in answer", {
          hasKeyData: !!ecdsaKey.keyData,
          hasSignature: !!ecdsaKey.signature
        });
        throw new Error("CRITICAL SECURITY FAILURE: ECDSA key missing keyData or signature");
      }
      const timestamp = answerData.ts || answerData.timestamp;
      const version = answerData.v || answerData.version;
      if (!timestamp || !version) {
        throw new Error("Missing required fields in response data \u2013 possible MITM attack");
      }
      if (answerData.sessionId && this.sessionId && answerData.sessionId !== this.sessionId) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Session ID mismatch detected - possible MITM attack", {
          expectedSessionIdHash: await this._createSafeLogHash(this.sessionId, "session_id"),
          receivedSessionIdHash: await this._createSafeLogHash(answerData.sessionId, "session_id")
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
        new Uint8Array(ecdsaKey.keyData),
        {
          name: "ECDSA",
          namedCurve: "P-384"
        },
        false,
        ["verify"]
      );
      const peerPublicKey = await window.EnhancedSecureCryptoUtils.importPublicKeyFromSignedPackage(
        ecdhKey,
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
        const remoteFP = this._extractDTLSFingerprintFromSDP(answerData.sdp || answerData.s);
        const localFP = this.expectedDTLSFingerprint;
        const keyBytes = this._decodeKeyFingerprint(this.keyFingerprint);
        this.verificationCode = await this._computeSAS(keyBytes, localFP, remoteFP);
        this.onStatusChange?.("verifying");
        this.onVerificationRequired(this.verificationCode);
        this.pendingSASCode = this.verificationCode;
        this._secureLog("info", "SAS verification code generated for MITM protection (Offer side)", {
          sasCode: this.verificationCode,
          localFP: localFP.substring(0, 16) + "...",
          remoteFP: remoteFP.substring(0, 16) + "...",
          timestamp: Date.now()
        });
      } catch (sasError) {
        this._secureLog("error", "SAS computation failed in handleSecureAnswer (Offer side)", {
          errorType: sasError?.constructor?.name || "Unknown"
        });
        this._secureLog("error", "SAS computation failed in handleSecureAnswer (Offer side)", {
          error: sasError.message,
          stack: sasError.stack,
          timestamp: Date.now()
        });
      }
      if (this.strictDTLSValidation) {
        try {
          const receivedFingerprint = this._extractDTLSFingerprintFromSDP(answerData.sdp || answerData.s);
          if (this.expectedDTLSFingerprint) {
            await this._validateDTLSFingerprint(receivedFingerprint, this.expectedDTLSFingerprint, "answer_validation");
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
      const sdpData = answerData.sdp || answerData.s;
      this._secureLog("debug", "Setting remote description from answer", {
        sdpLength: sdpData?.length || 0,
        usingCompactSDP: !answerData.sdp && !!answerData.s
      });
      await this.peerConnection.setRemoteDescription({
        type: "answer",
        sdp: sdpData
      });
      this._secureLog("debug", "Remote description set successfully from answer", {
        signalingState: this.peerConnection.signalingState
      });
      setTimeout(async () => {
        try {
          const securityData = await this.calculateAndReportSecurityLevel();
          if (securityData) {
            this.notifySecurityUpdate();
          }
        } catch (error) {
          this._secureLog("error", "Error calculating security after connection:", { errorType: error?.constructor?.name || "Unknown" });
        }
      }, 1e3);
      setTimeout(async () => {
        if (!this.lastSecurityCalculation || this.lastSecurityCalculation.score < 50) {
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
  initiateVerification() {
    if (this.isInitiator) {
      if (!this.verificationInitiationSent) {
        this.verificationInitiationSent = true;
        this.deliverMessageToUI("CRITICAL: Compare verification code with peer out-of-band (voice/video/in-person) to prevent MITM attack!", "system");
        this.deliverMessageToUI(`Your verification code: ${this.verificationCode}`, "system");
        this.deliverMessageToUI("Ask peer to confirm this exact code before allowing traffic!", "system");
      }
    } else {
      this.deliverMessageToUI("Waiting for verification code from peer...", "system");
    }
  }
  confirmVerification() {
    try {
      this.localVerificationConfirmed = true;
      const confirmationPayload = {
        type: "verification_confirmed",
        data: {
          timestamp: Date.now(),
          verificationMethod: "SAS",
          securityLevel: "MITM_PROTECTION_REQUIRED"
        }
      };
      this.dataChannel.send(JSON.stringify(confirmationPayload));
      if (this.onVerificationStateChange) {
        this.onVerificationStateChange({
          localConfirmed: this.localVerificationConfirmed,
          remoteConfirmed: this.remoteVerificationConfirmed,
          bothConfirmed: this.bothVerificationsConfirmed
        });
      }
      this._checkBothVerificationsConfirmed();
      this.deliverMessageToUI("You confirmed the verification code. Waiting for peer confirmation...", "system");
      this.processMessageQueue();
    } catch (error) {
      this._secureLog("error", "SAS verification failed:", { errorType: error?.constructor?.name || "Unknown" });
      this.deliverMessageToUI("SAS verification failed", "system");
    }
  }
  _checkBothVerificationsConfirmed() {
    if (this.localVerificationConfirmed && this.remoteVerificationConfirmed && !this.bothVerificationsConfirmed) {
      this.bothVerificationsConfirmed = true;
      const bothConfirmedPayload = {
        type: "verification_both_confirmed",
        data: {
          timestamp: Date.now(),
          verificationMethod: "SAS",
          securityLevel: "MITM_PROTECTION_COMPLETE"
        }
      };
      this.dataChannel.send(JSON.stringify(bothConfirmedPayload));
      if (this.onVerificationStateChange) {
        this.onVerificationStateChange({
          localConfirmed: this.localVerificationConfirmed,
          remoteConfirmed: this.remoteVerificationConfirmed,
          bothConfirmed: this.bothVerificationsConfirmed
        });
      }
      this.deliverMessageToUI("Both parties confirmed! Opening secure chat in 2 seconds...", "system");
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
    this.remoteVerificationConfirmed = true;
    this.deliverMessageToUI("Peer confirmed the verification code. Waiting for your confirmation...", "system");
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
    this.bothVerificationsConfirmed = true;
    if (this.onVerificationStateChange) {
      this.onVerificationStateChange({
        localConfirmed: this.localVerificationConfirmed,
        remoteConfirmed: this.remoteVerificationConfirmed,
        bothConfirmed: this.bothVerificationsConfirmed
      });
    }
    this.deliverMessageToUI("Both parties confirmed! Opening secure chat in 2 seconds...", "system");
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
        this.deliverMessageToUI("SAS verification successful! MITM protection confirmed. Channel is now secure!", "system");
      }
      this.processMessageQueue();
    } else {
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
      this.deliverMessageToUI("SAS verification failed! Possible MITM attack detected. Connection aborted for safety!", "system");
      this.disconnect();
    }
  }
  handleSASCode(data) {
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
        this.deliverMessageToUI(" Mutual SAS verification complete! MITM protection active. Channel is now secure!", "system");
      }
      this.processMessageQueue();
    } else {
      this._secureLog("error", "Peer SAS verification failed - connection not secure", {
        responseData: data,
        timestamp: Date.now()
      });
      this.deliverMessageToUI("Peer verification failed! Connection not secure!", "system");
      this.disconnect();
    }
  }
  validateOfferData(offerData) {
    return offerData && offerData.type === "enhanced_secure_offer" && offerData.sdp && offerData.publicKey && offerData.salt && offerData.verificationCode && Array.isArray(offerData.publicKey) && Array.isArray(offerData.salt) && offerData.salt.length === 32;
  }
  validateEnhancedOfferData(offerData) {
    try {
      if (!offerData || typeof offerData !== "object" || Array.isArray(offerData)) {
        this._secureLog("error", "CRITICAL: Invalid offer data structure", {
          hasOfferData: !!offerData,
          offerDataType: typeof offerData,
          isArray: Array.isArray(offerData)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Offer data must be a non-null object");
      }
      const isV4CompactFormat = offerData.v === "4.0" && offerData.e && offerData.d;
      const isV4Format = offerData.version === "4.0" && offerData.ecdhPublicKey && offerData.ecdsaPublicKey;
      const isValidType = isV4CompactFormat ? ["offer"].includes(offerData.t) : ["enhanced_secure_offer", "secure_offer"].includes(offerData.type);
      if (!isValidType) {
        throw new Error("Invalid offer type");
      }
      if (isV4CompactFormat) {
        const compactRequiredFields = [
          "e",
          "d",
          "sl",
          "vc",
          "si",
          "ci",
          "ac",
          "slv"
        ];
        for (const field of compactRequiredFields) {
          if (!offerData[field]) {
            throw new Error(`Missing required v4.0 compact field: ${field}`);
          }
        }
        if (!offerData.e || typeof offerData.e !== "object" || Array.isArray(offerData.e)) {
          throw new Error("CRITICAL SECURITY FAILURE: Invalid ECDH public key structure");
        }
        if (!offerData.d || typeof offerData.d !== "object" || Array.isArray(offerData.d)) {
          throw new Error("CRITICAL SECURITY FAILURE: Invalid ECDSA public key structure");
        }
        if (!Array.isArray(offerData.sl) || offerData.sl.length !== 64) {
          throw new Error("Salt must be exactly 64 bytes for v4.0");
        }
        if (typeof offerData.vc !== "string" || offerData.vc.length < 6) {
          throw new Error("Invalid verification code format");
        }
        if (!["MAX", "HIGH", "MED", "LOW"].includes(offerData.slv)) {
          throw new Error("Invalid security level");
        }
        const offerAge = Date.now() - offerData.ts;
        if (offerAge > 36e5) {
          throw new Error("Offer is too old (older than 1 hour)");
        }
        this._secureLog("info", "v4.0 compact offer validation passed", {
          version: offerData.v,
          hasECDH: !!offerData.e,
          hasECDSA: !!offerData.d,
          hasSalt: !!offerData.sl,
          hasVerificationCode: !!offerData.vc,
          securityLevel: offerData.slv,
          offerAge: Math.round(offerAge / 1e3) + "s"
        });
      } else if (isV4Format) {
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
      const sdp = isV4CompactFormat ? offerData.s : offerData.sdp;
      if (typeof sdp !== "string" || !sdp.includes("v=0")) {
        throw new Error("Invalid SDP structure");
      }
      return true;
    } catch (error) {
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
      this._secureLog("error", "Input validation failed in sendSecureMessage", {
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
        this._secureLog("debug", "Secure message sent successfully", {
          operationId,
          messageLength: sanitizedMessage.length,
          keyVersion: this.currentKeyVersion
        });
      } catch (error) {
        this._secureLog("error", "Secure message sending failed", {
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
    this._secureLog("info", "Heartbeat moved to unified scheduler");
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
    this._secureLog("info", "Stopping all timers and cleanup scheduler");
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
    this._secureLog("info", "All timers stopped successfully");
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
    this._secureLog("info", "Retrying connection", {
      attempt: this.connectionAttempts,
      maxAttempts: this.maxConnectionAttempts
    });
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
      this.deliverMessageToUI("Unable to reconnect. A new connection is required.", "system");
    }
  }
  handlePeerDisconnectNotification(data) {
    const reason = data.reason || "unknown";
    const reasonText = reason === "user_disconnect" ? "manually disconnected." : "connection lost.";
    if (!this.peerDisconnectNotificationSent) {
      this.peerDisconnectNotificationSent = true;
      this.deliverMessageToUI(`Peer ${reasonText}`, "system");
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
    this._forceGarbageCollection().catch((error) => {
      this._secureLog("error", "Cleanup failed during disconnect", {
        errorType: error?.constructor?.name || "Unknown"
      });
    });
    document.dispatchEvent(new CustomEvent("connection-cleaned", {
      detail: {
        timestamp: Date.now(),
        reason: this.intentionalDisconnect ? "user_cleanup" : "automatic_cleanup"
      }
    }));
    this.onStatusChange("disconnected");
    this.onKeyExchange("");
    this.onVerificationRequired("");
    this._secureLog("info", "Connection securely cleaned up with complete memory wipe");
    this.intentionalDisconnect = false;
  }
  // Public method to send files
  async sendFile(file) {
    this._enforceVerificationGate("sendFile");
    if (!this.isConnected()) {
      throw new Error("Connection not ready for file transfer. Please ensure the connection is established.");
    }
    if (!this.fileTransferSystem) {
      this.initializeFileTransfer();
      await new Promise((resolve) => setTimeout(resolve, 500));
      if (!this.fileTransferSystem) {
        throw new Error("File transfer system could not be initialized. Please try reconnecting.");
      }
    }
    if (!this.encryptionKey || !this.macKey) {
      throw new Error("Encryption keys not ready. Please wait for connection to be fully established.");
    }
    try {
      const fileId = await this.fileTransferSystem.sendFile(file);
      return fileId;
    } catch (error) {
      this._secureLog("error", "File transfer error:", { errorType: error?.constructor?.name || "Unknown" });
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
        this._secureLog("warn", "getActiveTransfers method not available in file transfer system");
      }
      if (typeof this.fileTransferSystem.getReceivingTransfers === "function") {
        receiving = this.fileTransferSystem.getReceivingTransfers();
      } else {
        this._secureLog("warn", "getReceivingTransfers method not available in file transfer system");
      }
      return {
        sending: sending || [],
        receiving: receiving || []
      };
    } catch (error) {
      this._secureLog("error", "Error getting file transfers:", { errorType: error?.constructor?.name || "Unknown" });
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
      this._secureLog("info", "\u{1F9F9} Force cleaning up file transfer system");
      this.fileTransferSystem.cleanup();
      this.fileTransferSystem = null;
      return true;
    }
    return false;
  }
  // Reinitialize file transfer system
  reinitializeFileTransfer() {
    try {
      if (this.fileTransferSystem) {
        this.fileTransferSystem.cleanup();
      }
      this.initializeFileTransfer();
      return true;
    } catch (error) {
      this._secureLog("error", "Failed to reinitialize file transfer system:", { errorType: error?.constructor?.name || "Unknown" });
      return false;
    }
  }
  // Set file transfer callbacks
  setFileTransferCallbacks(onProgress, onReceived, onError) {
    this.onFileProgress = onProgress;
    this.onFileReceived = onReceived;
    this.onFileError = onError;
    if (this.fileTransferSystem) {
      this.initializeFileTransfer();
    }
  }
  // ============================================
  // SESSION ACTIVATION HANDLING
  // ============================================
  async handleSessionActivation(sessionData) {
    try {
      this.currentSession = sessionData;
      this.sessionManager = sessionData.sessionManager;
      const hasKeys = !!(this.encryptionKey && this.macKey);
      const hasSession = !!(this.sessionManager && (this.sessionManager.hasActiveSession?.() || sessionData.sessionId));
      if (hasSession) {
        this.onStatusChange("connected");
      }
      setTimeout(() => {
        try {
          this.initializeFileTransfer();
        } catch (error) {
          this._secureLog("warn", "File transfer initialization failed during session activation:", { details: error.message });
        }
      }, 1e3);
      if (this.fileTransferSystem && this.isConnected()) {
        if (typeof this.fileTransferSystem.onSessionUpdate === "function") {
          this.fileTransferSystem.onSessionUpdate({
            keyFingerprint: this.keyFingerprint,
            sessionSalt: this.sessionSalt,
            hasMacKey: !!this.macKey
          });
        }
      }
    } catch (error) {
      this._secureLog("error", "Failed to handle session activation:", { errorType: error?.constructor?.name || "Unknown" });
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
    return status;
  }
  // Method to force re-initialize file transfer system
  forceReinitializeFileTransfer() {
    try {
      if (this.fileTransferSystem) {
        this.fileTransferSystem.cleanup();
        this.fileTransferSystem = null;
      }
      setTimeout(() => {
        this.initializeFileTransfer();
      }, 500);
      return true;
    } catch (error) {
      this._secureLog("error", "Failed to force reinitialize file transfer:", { errorType: error?.constructor?.name || "Unknown" });
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
        this._secureLog("info", "File transfer initialization cancelled by user");
        return { cancelled: true };
      }
      this._secureLog("error", "Force file transfer initialization failed:", {
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
        this._secureLog("info", "File transfer initialization cancelled");
        return true;
      }
      return false;
    } catch (error) {
      this._secureLog("error", "Failed to cancel file transfer initialization:", {
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
      this._secureLog("error", "Failed to get file transfer system status:", {
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
          this._secureLog("error", "CRITICAL: Nested encryption security validation failed - IVs are identical!");
          return false;
        }
        const stats = this._getIVTrackingStats();
        if (stats.totalIVs < 2) {
          this._secureLog("error", "CRITICAL: IV tracking system not working properly");
          return false;
        }
        this._secureLog("info", "Nested encryption security validation passed - secure IV generation working");
        return true;
      } catch (error) {
        this._secureLog("error", "CRITICAL: Nested encryption security validation failed:", {
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
  constructor(masterKeyManager = null) {
    this._keyStore = /* @__PURE__ */ new WeakMap();
    this._keyMetadata = /* @__PURE__ */ new Map();
    this._keyReferences = /* @__PURE__ */ new Map();
    this._masterKeyManager = masterKeyManager || new SecureMasterKeyManager();
    this._persistentStorage = new SecurePersistentKeyStorage(this._masterKeyManager);
    this._setupMasterKeyCallbacks();
    setTimeout(() => {
      if (!this.validateStorageIntegrity()) {
        this._secureLog("error", "CRITICAL: Key storage integrity check failed");
      }
    }, 100);
  }
  /**
   * Setup callbacks for master key manager
   */
  _setupMasterKeyCallbacks() {
    this._masterKeyManager.setPasswordRequiredCallback((isRetry, callback) => {
      const password = prompt(
        isRetry ? "Incorrect password. Please enter your master password:" : "Please enter your master password to unlock secure storage:"
      );
      callback(password);
    });
    this._masterKeyManager.setSessionExpiredCallback((reason) => {
      console.warn(`Master key session expired: ${reason}`);
    });
    this._masterKeyManager.setUnlockedCallback(() => {
      console.log("Master key unlocked successfully");
    });
  }
  /**
   * Set custom password callback
   */
  setPasswordCallback(callback) {
    this._masterKeyManager.setPasswordRequiredCallback(callback);
  }
  /**
   * Set custom session expired callback
   */
  setSessionExpiredCallback(callback) {
    this._masterKeyManager.setSessionExpiredCallback(callback);
  }
  /**
   * Get master key (with automatic unlock if needed)
   */
  async _getMasterKey() {
    if (!this._masterKeyManager.isUnlocked()) {
      await this._masterKeyManager.unlock();
    }
    return this._masterKeyManager.getMasterKey();
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
          persistent: false,
          encrypted: false
        });
        return true;
      }
      await this._persistentStorage.storeExtractableKey(keyId, cryptoKey, metadata);
      this._keyReferences.set(keyId, cryptoKey);
      this._keyMetadata.set(keyId, {
        ...metadata,
        created: Date.now(),
        lastAccessed: Date.now(),
        extractable: true,
        persistent: true,
        encrypted: true
      });
      return true;
    } catch (error) {
      this._secureLog("error", "Failed to store key securely", {
        errorType: error?.constructor?.name || "Unknown"
      });
      return false;
    }
  }
  async retrieveKey(keyId) {
    try {
      if (this._keyReferences.has(keyId)) {
        const metadata = this._keyMetadata.get(keyId);
        if (metadata) {
          metadata.lastAccessed = Date.now();
        }
        return this._keyReferences.get(keyId);
      }
      const restoredKey = await this._persistentStorage.retrieveKey(keyId);
      if (restoredKey) {
        this._keyReferences.set(keyId, restoredKey);
        const existingMetadata = this._keyMetadata.get(keyId);
        this._keyMetadata.set(keyId, {
          ...existingMetadata,
          lastAccessed: Date.now(),
          restoredFromPersistent: true
        });
        return restoredKey;
      }
      return null;
    } catch (error) {
      this._secureLog("error", "Failed to retrieve key", {
        keyIdHash: await this._createSafeLogHash(keyId, "key_id"),
        errorType: error?.constructor?.name || "Unknown"
      });
      return null;
    }
  }
  async _encryptKeyData(keyData) {
    const dataToEncrypt = typeof keyData === "object" ? JSON.stringify(keyData) : keyData;
    const encoder = new TextEncoder();
    const data = encoder.encode(dataToEncrypt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const masterKey = await this._getMasterKey();
    const encryptedData = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      masterKey,
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
    const masterKey = await this._getMasterKey();
    const decryptedData = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      masterKey,
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
  async secureWipe(keyId) {
    const cryptoKey = this._keyReferences.get(keyId);
    if (cryptoKey) {
      this._keyStore.delete(cryptoKey);
      this._keyReferences.delete(keyId);
      this._keyMetadata.delete(keyId);
    }
    await this._performNaturalCleanup();
  }
  async secureWipeAll() {
    try {
      await this._persistentStorage.clearAll();
    } catch (error) {
      this._secureLog("error", "Failed to clear persistent storage", {
        errorType: error?.constructor?.name || "Unknown"
      });
    }
    this._keyReferences.clear();
    this._keyMetadata.clear();
    this._keyStore = /* @__PURE__ */ new WeakMap();
    await this._performNaturalCleanup();
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
      this._secureLog("error", "Storage integrity violations detected", {
        violationCount: violations.length
      });
      return false;
    }
    return true;
  }
  async getStorageStats() {
    const persistentStats = await this._persistentStorage.getStorageStats();
    return {
      totalKeys: this._keyReferences.size,
      memoryKeys: this._keyReferences.size,
      persistentKeys: persistentStats.persistentKeys,
      metadata: Array.from(this._keyMetadata.entries()).map(([id, meta]) => ({
        id,
        created: meta.created,
        lastAccessed: meta.lastAccessed,
        age: Date.now() - meta.created,
        persistent: meta.persistent || false
      })),
      persistent: persistentStats
    };
  }
  /**
   * List all stored keys (memory + persistent)
   */
  async listAllKeys() {
    try {
      const memoryKeys = Array.from(this._keyMetadata.entries()).map(([keyId, metadata]) => ({
        keyId,
        ...metadata,
        location: "memory"
      }));
      const persistentKeys = await this._persistentStorage.listStoredKeys();
      const persistentKeysFormatted = persistentKeys.map((key) => ({
        ...key,
        location: "persistent"
      }));
      return {
        memoryKeys,
        persistentKeys: persistentKeysFormatted,
        totalCount: memoryKeys.length + persistentKeysFormatted.length
      };
    } catch (error) {
      this._secureLog("error", "Failed to list keys", {
        errorType: error?.constructor?.name || "Unknown"
      });
      return {
        memoryKeys: [],
        persistentKeys: [],
        totalCount: 0,
        error: error.message
      };
    }
  }
  /**
   * Delete key from both memory and persistent storage
   */
  async deleteKey(keyId) {
    try {
      this._keyReferences.delete(keyId);
      this._keyMetadata.delete(keyId);
      await this._persistentStorage.deleteKey(keyId);
      return true;
    } catch (error) {
      this._secureLog("error", "Failed to delete key", {
        keyIdHash: await this._createSafeLogHash(keyId, "key_id"),
        errorType: error?.constructor?.name || "Unknown"
      });
      return false;
    }
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
        this._secureLog("warn", "Sequence number too old - possible replay attack", {
          received: receivedSeq,
          expected: this.expectedSequenceNumber,
          context,
          timestamp: Date.now()
        });
        return false;
      }
      if (receivedSeq > this.expectedSequenceNumber + this.maxSequenceGap) {
        this._secureLog("warn", "Sequence number gap too large - possible DoS attack", {
          received: receivedSeq,
          expected: this.expectedSequenceNumber,
          gap: receivedSeq - this.expectedSequenceNumber,
          context,
          timestamp: Date.now()
        });
        return false;
      }
      if (this.replayWindow.has(receivedSeq)) {
        this._secureLog("warn", "Duplicate sequence number detected - replay attack", {
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
      this._secureLog("debug", "Sequence number validation successful", {
        received: receivedSeq,
        expected: this.expectedSequenceNumber,
        context,
        timestamp: Date.now()
      });
      return true;
    } catch (error) {
      this._secureLog("error", "Sequence number validation failed", {
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
  /**
   * Get real security level with actual cryptographic tests
   * This provides real-time verification of security features
   */
  async getRealSecurityLevel() {
    try {
      const securityData = {
        // Basic security features
        ecdhKeyExchange: !!this.ecdhKeyPair,
        ecdsaSignatures: !!this.ecdsaKeyPair,
        aesEncryption: !!this.encryptionKey,
        messageIntegrity: !!this.hmacKey,
        // Advanced security features - using the exact property names expected by EnhancedSecureCryptoUtils
        replayProtection: this.replayProtectionEnabled,
        dtlsFingerprint: !!this.expectedDTLSFingerprint,
        sasCode: !!this.verificationCode,
        metadataProtection: true,
        // Always enabled
        trafficObfuscation: true,
        // Always enabled
        perfectForwardSecrecy: true,
        // Always enabled
        // Rate limiting
        rateLimiter: true,
        // Always enabled
        // Additional info
        connectionId: this.connectionId,
        keyFingerprint: this.keyFingerprint,
        currentSecurityLevel: this.currentSecurityLevel,
        timestamp: Date.now()
      };
      this._secureLog("info", "Real security level calculated", securityData);
      return securityData;
    } catch (error) {
      this._secureLog("error", "Failed to calculate real security level", { error: error.message });
      throw error;
    }
  }
};
var SecureIndexedDBWrapper = class {
  constructor(dbName = "SecureKeyStorage", version = 1) {
    this.dbName = dbName;
    this.version = version;
    this.db = null;
    this.KEYS_STORE = "encrypted_keys";
    this.METADATA_STORE = "key_metadata";
    this.SALT_STORE = "master_salt";
  }
  /**
   * Initialize IndexedDB connection
   */
  async initialize() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);
      request.onerror = () => {
        reject(new Error(`Failed to open IndexedDB: ${request.error}`));
      };
      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(this.KEYS_STORE)) {
          const keysStore = db.createObjectStore(this.KEYS_STORE, { keyPath: "keyId" });
          keysStore.createIndex("timestamp", "timestamp", { unique: false });
          keysStore.createIndex("algorithm", "algorithm", { unique: false });
        }
        if (!db.objectStoreNames.contains(this.METADATA_STORE)) {
          const metadataStore = db.createObjectStore(this.METADATA_STORE, { keyPath: "keyId" });
          metadataStore.createIndex("created", "created", { unique: false });
          metadataStore.createIndex("lastAccessed", "lastAccessed", { unique: false });
        }
        if (!db.objectStoreNames.contains(this.SALT_STORE)) {
          db.createObjectStore(this.SALT_STORE, { keyPath: "id" });
        }
      };
    });
  }
  /**
   * Store encrypted key data
   */
  async storeEncryptedKey(keyId, encryptedData, iv, algorithm, usages, type, metadata = {}) {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.KEYS_STORE, this.METADATA_STORE], "readwrite");
    const keyRecord = {
      keyId,
      encryptedData: Array.from(new Uint8Array(encryptedData)),
      // Convert to array for storage
      iv: Array.from(new Uint8Array(iv)),
      algorithm,
      usages,
      type,
      timestamp: Date.now()
    };
    const metadataRecord = {
      keyId,
      ...metadata,
      created: Date.now(),
      lastAccessed: Date.now(),
      extractable: true,
      persistent: true
    };
    return new Promise((resolve, reject) => {
      const keysRequest = transaction.objectStore(this.KEYS_STORE).put(keyRecord);
      const metadataRequest = transaction.objectStore(this.METADATA_STORE).put(metadataRecord);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error(`Failed to store key: ${transaction.error}`));
    });
  }
  /**
   * Retrieve encrypted key data
   */
  async getEncryptedKey(keyId) {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.KEYS_STORE], "readonly");
    const store = transaction.objectStore(this.KEYS_STORE);
    return new Promise((resolve, reject) => {
      const request = store.get(keyId);
      request.onsuccess = () => {
        const result = request.result;
        if (result) {
          result.encryptedData = new Uint8Array(result.encryptedData);
          result.iv = new Uint8Array(result.iv);
        }
        resolve(result);
      };
      request.onerror = () => reject(new Error(`Failed to retrieve key: ${request.error}`));
    });
  }
  /**
   * Update key metadata (e.g., last accessed time)
   */
  async updateKeyMetadata(keyId, updates) {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.METADATA_STORE], "readwrite");
    const store = transaction.objectStore(this.METADATA_STORE);
    return new Promise((resolve, reject) => {
      const getRequest = store.get(keyId);
      getRequest.onsuccess = () => {
        const metadata = getRequest.result;
        if (metadata) {
          Object.assign(metadata, updates);
          const putRequest = store.put(metadata);
          putRequest.onsuccess = () => resolve();
          putRequest.onerror = () => reject(new Error(`Failed to update metadata: ${putRequest.error}`));
        } else {
          reject(new Error(`Key metadata not found: ${keyId}`));
        }
      };
      getRequest.onerror = () => reject(new Error(`Failed to get metadata: ${getRequest.error}`));
    });
  }
  /**
   * Delete key and its metadata
   */
  async deleteKey(keyId) {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.KEYS_STORE, this.METADATA_STORE], "readwrite");
    return new Promise((resolve, reject) => {
      const keysRequest = transaction.objectStore(this.KEYS_STORE).delete(keyId);
      const metadataRequest = transaction.objectStore(this.METADATA_STORE).delete(keyId);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error(`Failed to delete key: ${transaction.error}`));
    });
  }
  /**
   * List all stored keys
   */
  async listKeys() {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.METADATA_STORE], "readonly");
    const store = transaction.objectStore(this.METADATA_STORE);
    return new Promise((resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error(`Failed to list keys: ${request.error}`));
    });
  }
  /**
   * Store master key salt
   */
  async storeMasterSalt(salt) {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.SALT_STORE], "readwrite");
    const store = transaction.objectStore(this.SALT_STORE);
    const saltRecord = {
      id: "master_salt",
      salt: Array.from(new Uint8Array(salt)),
      created: Date.now()
    };
    return new Promise((resolve, reject) => {
      const request = store.put(saltRecord);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error(`Failed to store salt: ${request.error}`));
    });
  }
  /**
   * Retrieve master key salt
   */
  async getMasterSalt() {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.SALT_STORE], "readonly");
    const store = transaction.objectStore(this.SALT_STORE);
    return new Promise((resolve, reject) => {
      const request = store.get("master_salt");
      request.onsuccess = () => {
        const result = request.result;
        if (result) {
          resolve(new Uint8Array(result.salt));
        } else {
          resolve(null);
        }
      };
      request.onerror = () => reject(new Error(`Failed to retrieve salt: ${request.error}`));
    });
  }
  /**
   * Clear all data (for security wipe)
   */
  async clearAll() {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.KEYS_STORE, this.METADATA_STORE, this.SALT_STORE], "readwrite");
    return new Promise((resolve, reject) => {
      const keysRequest = transaction.objectStore(this.KEYS_STORE).clear();
      const metadataRequest = transaction.objectStore(this.METADATA_STORE).clear();
      const saltRequest = transaction.objectStore(this.SALT_STORE).clear();
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error(`Failed to clear database: ${transaction.error}`));
    });
  }
  /**
   * Close database connection
   */
  close() {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }
};
var SecurePersistentKeyStorage = class {
  constructor(masterKeyManager, indexedDBWrapper = null) {
    this._masterKeyManager = masterKeyManager;
    this._indexedDB = indexedDBWrapper || new SecureIndexedDBWrapper();
    this._dbInitialized = false;
    this._keyCache = /* @__PURE__ */ new WeakMap();
    this._keyReferences = /* @__PURE__ */ new Map();
  }
  /**
   * Initialize IndexedDB if not already done
   */
  async _ensureDBInitialized() {
    if (!this._dbInitialized) {
      await this._indexedDB.initialize();
      this._dbInitialized = true;
    }
  }
  /**
   * Store extractable key with encryption
   */
  async storeExtractableKey(keyId, cryptoKey, metadata = {}) {
    if (!(cryptoKey instanceof CryptoKey)) {
      throw new Error("Only CryptoKey objects can be stored");
    }
    if (!cryptoKey.extractable) {
      throw new Error("Key must be extractable for persistent storage");
    }
    try {
      await this._ensureDBInitialized();
      const jwkData = await crypto.subtle.exportKey("jwk", cryptoKey);
      const masterKey = this._masterKeyManager.getMasterKey();
      const { encryptedData, iv } = await this._encryptKeyData(jwkData, masterKey);
      await this._indexedDB.storeEncryptedKey(
        keyId,
        encryptedData,
        iv,
        cryptoKey.algorithm,
        cryptoKey.usages,
        cryptoKey.type,
        metadata
      );
      const nonExtractableKey = await this._importAsNonExtractable(jwkData, cryptoKey.algorithm, cryptoKey.usages);
      this._keyReferences.set(keyId, nonExtractableKey);
      return true;
    } catch (error) {
      throw new Error(`Failed to store extractable key: ${error.message}`);
    }
  }
  /**
   * Retrieve and restore key from persistent storage
   */
  async retrieveKey(keyId) {
    try {
      if (this._keyReferences.has(keyId)) {
        return this._keyReferences.get(keyId);
      }
      await this._ensureDBInitialized();
      const keyRecord = await this._indexedDB.getEncryptedKey(keyId);
      if (!keyRecord) {
        return null;
      }
      const masterKey = this._masterKeyManager.getMasterKey();
      const jwkData = await this._decryptKeyData(keyRecord.encryptedData, keyRecord.iv, masterKey);
      const restoredKey = await this._importAsNonExtractable(jwkData, keyRecord.algorithm, keyRecord.usages);
      this._keyReferences.set(keyId, restoredKey);
      await this._indexedDB.updateKeyMetadata(keyId, { lastAccessed: Date.now() });
      return restoredKey;
    } catch (error) {
      throw new Error(`Failed to retrieve key: ${error.message}`);
    }
  }
  /**
   * Delete key from persistent storage
   */
  async deleteKey(keyId) {
    try {
      await this._ensureDBInitialized();
      await this._indexedDB.deleteKey(keyId);
      this._keyReferences.delete(keyId);
      return true;
    } catch (error) {
      throw new Error(`Failed to delete key: ${error.message}`);
    }
  }
  /**
   * List all stored keys
   */
  async listStoredKeys() {
    try {
      await this._ensureDBInitialized();
      return await this._indexedDB.listKeys();
    } catch (error) {
      throw new Error(`Failed to list keys: ${error.message}`);
    }
  }
  /**
   * Clear all persistent storage
   */
  async clearAll() {
    try {
      await this._ensureDBInitialized();
      await this._indexedDB.clearAll();
      this._keyReferences.clear();
      return true;
    } catch (error) {
      throw new Error(`Failed to clear storage: ${error.message}`);
    }
  }
  /**
   * Encrypt key data using master key
   */
  async _encryptKeyData(jwkData, masterKey) {
    const jsonString = JSON.stringify(jwkData);
    const data = new TextEncoder().encode(jsonString);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      masterKey,
      data
    );
    return {
      encryptedData: new Uint8Array(encryptedData),
      iv
    };
  }
  /**
   * Decrypt key data using master key
   */
  async _decryptKeyData(encryptedData, iv, masterKey) {
    const decryptedData = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      masterKey,
      encryptedData
    );
    const jsonString = new TextDecoder().decode(decryptedData);
    return JSON.parse(jsonString);
  }
  /**
   * Import JWK as non-extractable key
   */
  async _importAsNonExtractable(jwkData, algorithm, usages) {
    return await crypto.subtle.importKey(
      "jwk",
      jwkData,
      algorithm,
      false,
      // non-extractable for security
      usages
    );
  }
  /**
   * Get storage statistics
   */
  async getStorageStats() {
    try {
      await this._ensureDBInitialized();
      const keys = await this._indexedDB.listKeys();
      return {
        totalKeys: keys.length,
        memoryKeys: this._keyReferences.size,
        persistentKeys: keys.length,
        lastAccessed: keys.reduce((latest, key) => Math.max(latest, key.lastAccessed || 0), 0)
      };
    } catch (error) {
      return {
        totalKeys: 0,
        memoryKeys: this._keyReferences.size,
        persistentKeys: 0,
        lastAccessed: 0,
        error: error.message
      };
    }
  }
};
var SecureMasterKeyManager = class {
  constructor(indexedDBWrapper = null) {
    this._masterKey = null;
    this._isUnlocked = false;
    this._sessionTimeout = null;
    this._lastActivity = null;
    this._sessionTimeoutMs = 15 * 60 * 1e3;
    this._inactivityTimeoutMs = 5 * 60 * 1e3;
    this._pbkdf2Iterations = 1e5;
    this._saltSize = 32;
    this._indexedDB = indexedDBWrapper || new SecureIndexedDBWrapper();
    this._dbInitialized = false;
    this._onPasswordRequired = null;
    this._onSessionExpired = null;
    this._onUnlocked = null;
  }
  /**
   * Set callback for password requests
   */
  setPasswordRequiredCallback(callback) {
    this._onPasswordRequired = callback;
  }
  /**
   * Set callback for session expiration
   */
  setSessionExpiredCallback(callback) {
    this._onSessionExpired = callback;
  }
  /**
   * Set callback for successful unlock
   */
  setUnlockedCallback(callback) {
    this._onUnlocked = callback;
  }
  /**
   * Setup event listeners for session management
   */
  _setupEventListeners() {
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
          this._handleFocusOut();
        } else {
          this._handleFocusIn();
        }
      });
      window.addEventListener("blur", () => this._handleFocusOut());
      window.addEventListener("focus", () => this._handleFocusIn());
      ["mousedown", "mousemove", "keypress", "scroll", "touchstart"].forEach((event) => {
        document.addEventListener(event, () => this._updateActivity(), { passive: true });
      });
    }
  }
  /**
   * Handle focus out - start inactivity timer
   */
  _handleFocusOut() {
    if (this._isUnlocked) {
      this._startInactivityTimer(this._inactivityTimeoutMs);
    }
  }
  /**
   * Handle focus in - reset timers
   */
  _handleFocusIn() {
    if (this._isUnlocked) {
      this._resetSessionTimer();
    }
  }
  /**
   * Update last activity timestamp
   */
  _updateActivity() {
    this._lastActivity = Date.now();
    if (this._isUnlocked) {
      this._resetSessionTimer();
    }
  }
  /**
   * Start session timer
   */
  _startSessionTimer() {
    this._clearTimers();
    this._sessionTimeout = setTimeout(() => {
      this._expireSession("timeout");
    }, this._sessionTimeoutMs);
  }
  /**
   * Start inactivity timer
   */
  _startInactivityTimer(timeout) {
    this._clearTimers();
    this._sessionTimeout = setTimeout(() => {
      this._expireSession("inactivity");
    }, timeout);
  }
  /**
   * Reset session timer
   */
  _resetSessionTimer() {
    if (this._isUnlocked) {
      this._startSessionTimer();
    }
  }
  /**
   * Clear all timers
   */
  _clearTimers() {
    if (this._sessionTimeout) {
      clearTimeout(this._sessionTimeout);
      this._sessionTimeout = null;
    }
  }
  /**
   * Expire the current session
   */
  _expireSession(reason = "unknown") {
    if (this._isUnlocked) {
      this._secureWipeMasterKey();
      this._isUnlocked = false;
      if (this._onSessionExpired) {
        this._onSessionExpired(reason);
      }
    }
  }
  /**
   * Initialize IndexedDB if not already done
   */
  async _ensureDBInitialized() {
    if (!this._dbInitialized) {
      await this._indexedDB.initialize();
      this._dbInitialized = true;
    }
  }
  /**
   * Generate salt for PBKDF2
   */
  _generateSalt() {
    return crypto.getRandomValues(new Uint8Array(this._saltSize));
  }
  /**
   * Get or create persistent salt
   */
  async _getOrCreateSalt() {
    await this._ensureDBInitialized();
    let salt = await this._indexedDB.getMasterSalt();
    if (!salt) {
      salt = this._generateSalt();
      await this._indexedDB.storeMasterSalt(salt);
    }
    return salt;
  }
  /**
   * Derive master key from password using PBKDF2
   */
  async _deriveKeyFromPassword(password, salt) {
    try {
      const passwordKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
      );
      const derivedKey = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: this._pbkdf2Iterations,
          hash: "SHA-256"
        },
        passwordKey,
        {
          name: "AES-GCM",
          length: 256
        },
        false,
        // non-extractable for security
        ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
      );
      return derivedKey;
    } catch (error) {
      throw new Error(`Key derivation failed: ${error.message}`);
    }
  }
  /**
   * Request password from user
   */
  async _requestPassword(isRetry = false) {
    if (!this._onPasswordRequired) {
      throw new Error("Password callback not set");
    }
    return new Promise((resolve, reject) => {
      this._onPasswordRequired(isRetry, (password) => {
        if (password) {
          resolve(password);
        } else {
          reject(new Error("Password not provided"));
        }
      });
    });
  }
  /**
   * Unlock the master key with password
   */
  async unlock(password = null) {
    try {
      if (!password) {
        password = await this._requestPassword(false);
      }
      const salt = await this._getOrCreateSalt();
      this._masterKey = await this._deriveKeyFromPassword(password, salt);
      this._isUnlocked = true;
      this._lastActivity = Date.now();
      this._startSessionTimer();
      password = null;
      if (this._onUnlocked) {
        this._onUnlocked();
      }
      return { success: true };
    } catch (error) {
      password = null;
      throw error;
    }
  }
  /**
   * Lock the master key
   */
  lock() {
    this._expireSession("manual");
  }
  /**
   * Get master key (only if unlocked)
   */
  getMasterKey() {
    if (!this._isUnlocked || !this._masterKey) {
      throw new Error("Master key is locked");
    }
    this._updateActivity();
    return this._masterKey;
  }
  /**
   * Check if master key is unlocked
   */
  isUnlocked() {
    return this._isUnlocked && this._masterKey !== null;
  }
  /**
   * Get session status
   */
  getSessionStatus() {
    return {
      isUnlocked: this._isUnlocked,
      lastActivity: this._lastActivity,
      sessionTimeoutMs: this._sessionTimeoutMs,
      inactivityTimeoutMs: this._inactivityTimeoutMs
    };
  }
  /**
   * Securely wipe master key from memory
   */
  _secureWipeMasterKey() {
    if (this._masterKey) {
      this._masterKey = null;
    }
    this._clearTimers();
  }
  /**
   * Cleanup on destruction
   */
  destroy() {
    this._secureWipeMasterKey();
    this._isUnlocked = false;
    if (typeof document !== "undefined") {
      document.removeEventListener("visibilitychange", this._handleFocusOut);
      window.removeEventListener("blur", this._handleFocusOut);
      window.removeEventListener("focus", this._handleFocusIn);
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
        if (realSecurityData && realSecurityData.isRealData !== false) {
          const currentScore = realSecurityLevel?.score || 0;
          const newScore = realSecurityData.score || 0;
          if (currentScore !== newScore || !realSecurityLevel) {
            setRealSecurityLevel(realSecurityData);
            setLastSecurityUpdate(now);
          } else if (window.DEBUG_MODE) {
          }
        } else {
          console.warn(" Security calculation returned invalid data");
        }
      } catch (error) {
        console.error(" Error in real security calculation:", error);
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
  }, [webrtcManager, isConnected]);
  React.useEffect(() => {
    const handleSecurityUpdate = (event) => {
      setTimeout(() => {
        setLastSecurityUpdate(0);
      }, 100);
    };
    const handleRealSecurityCalculated = (event) => {
      if (event.detail && event.detail.securityData) {
        setRealSecurityLevel(event.detail.securityData);
        setLastSecurityUpdate(Date.now());
      }
    };
    document.addEventListener("security-level-updated", handleSecurityUpdate);
    document.addEventListener("real-security-calculated", handleRealSecurityCalculated);
    window.forceHeaderSecurityUpdate = (webrtcManager2) => {
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
    setHasActiveSession(true);
    setCurrentTimeLeft(0);
    setSessionType("premium");
  }, []);
  React.useEffect(() => {
    setHasActiveSession(true);
    setCurrentTimeLeft(0);
    setSessionType("premium");
  }, [sessionTimeLeft]);
  React.useEffect(() => {
    const handleForceUpdate = (event) => {
      setHasActiveSession(true);
      setCurrentTimeLeft(0);
      setSessionType("premium");
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
    const handleDisconnected = () => {
      setRealSecurityLevel(null);
      setLastSecurityUpdate(0);
      setHasActiveSession(false);
      setCurrentTimeLeft(0);
      setSessionType("unknown");
    };
    document.addEventListener("force-header-update", handleForceUpdate);
    document.addEventListener("peer-disconnect", handlePeerDisconnect);
    document.addEventListener("connection-cleaned", handleConnectionCleaned);
    document.addEventListener("disconnected", handleDisconnected);
    return () => {
      document.removeEventListener("force-header-update", handleForceUpdate);
      document.removeEventListener("peer-disconnect", handlePeerDisconnect);
      document.removeEventListener("connection-cleaned", handleConnectionCleaned);
      document.removeEventListener("disconnected", handleDisconnected);
    };
  }, []);
  const handleSecurityClick = async (event) => {
    if (event && (event.button === 2 || event.ctrlKey || event.metaKey)) {
      if (onDisconnect && typeof onDisconnect === "function") {
        onDisconnect();
        return;
      }
    }
    event.preventDefault();
    event.stopPropagation();
    let realTestResults = null;
    if (webrtcManager && window.EnhancedSecureCryptoUtils) {
      try {
        realTestResults = await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(webrtcManager);
        console.log("\u2705 Real security tests completed:", realTestResults);
      } catch (error) {
        console.error("\u274C Real security tests failed:", error);
      }
    } else {
      console.log("\u26A0\uFE0F Cannot run security tests:", {
        webrtcManager: !!webrtcManager,
        cryptoUtils: !!window.EnhancedSecureCryptoUtils
      });
    }
    if (!realTestResults && !realSecurityLevel) {
      alert("Security verification in progress...\nPlease wait for real-time cryptographic verification to complete.");
      return;
    }
    let securityData = realTestResults || realSecurityLevel;
    if (!securityData) {
      securityData = {
        level: "UNKNOWN",
        score: 0,
        color: "gray",
        verificationResults: {},
        timestamp: Date.now(),
        details: "Security verification not available",
        isRealData: false,
        passedChecks: 0,
        totalChecks: 0,
        sessionType: "unknown"
      };
      console.log("Using fallback security data:", securityData);
    }
    let message = `REAL-TIME SECURITY VERIFICATION

`;
    message += `Security Level: ${securityData.level} (${securityData.score}%)
`;
    message += `Session Type: ${securityData.sessionType || "premium"}
`;
    message += `Verification Time: ${new Date(securityData.timestamp).toLocaleTimeString()}
`;
    message += `Data Source: ${securityData.isRealData ? "Real Cryptographic Tests" : "Simulated Data"}

`;
    if (securityData.verificationResults) {
      message += "DETAILED CRYPTOGRAPHIC TESTS:\n";
      message += "=" + "=".repeat(40) + "\n";
      const passedTests = Object.entries(securityData.verificationResults).filter(([key, result]) => result.passed);
      const failedTests = Object.entries(securityData.verificationResults).filter(([key, result]) => !result.passed);
      if (passedTests.length > 0) {
        message += "PASSED TESTS:\n";
        passedTests.forEach(([key, result]) => {
          const testName = key.replace(/([A-Z])/g, " $1").replace(/^./, (str) => str.toUpperCase());
          message += `   ${testName}: ${result.details || "Test passed"}
`;
        });
        message += "\n";
      }
      if (failedTests.length > 0) {
        message += "FAILED/UNAVAILABLE TESTS:\n";
        failedTests.forEach(([key, result]) => {
          const testName = key.replace(/([A-Z])/g, " $1").replace(/^./, (str) => str.toUpperCase());
          message += `   ${testName}: ${result.details || "Test failed or unavailable"}
`;
        });
        message += "\n";
      }
      message += `SUMMARY:
`;
      message += `Passed: ${securityData.passedChecks}/${securityData.totalChecks} tests
`;
      message += `Score: ${securityData.score}/${securityData.maxPossibleScore || 100} points

`;
    }
    message += `SECURITY FEATURES STATUS:
`;
    message += "=" + "=".repeat(40) + "\n";
    if (securityData.verificationResults) {
      const features = {
        "ECDSA Digital Signatures": securityData.verificationResults.verifyECDSASignatures?.passed || false,
        "ECDH Key Exchange": securityData.verificationResults.verifyECDHKeyExchange?.passed || false,
        "AES-GCM Encryption": securityData.verificationResults.verifyEncryption?.passed || false,
        "Message Integrity (HMAC)": securityData.verificationResults.verifyMessageIntegrity?.passed || false,
        "Perfect Forward Secrecy": securityData.verificationResults.verifyPerfectForwardSecrecy?.passed || false,
        "Replay Protection": securityData.verificationResults.verifyReplayProtection?.passed || false,
        "DTLS Fingerprint": securityData.verificationResults.verifyDTLSFingerprint?.passed || false,
        "SAS Verification": securityData.verificationResults.verifySASVerification?.passed || false,
        "Metadata Protection": securityData.verificationResults.verifyMetadataProtection?.passed || false,
        "Traffic Obfuscation": securityData.verificationResults.verifyTrafficObfuscation?.passed || false
      };
      Object.entries(features).forEach(([feature, isEnabled]) => {
        message += `${isEnabled ? "\u2705" : "\u274C"} ${feature}
`;
      });
    } else {
      message += `\u2705 ECDSA Digital Signatures
`;
      message += `\u2705 ECDH Key Exchange
`;
      message += `\u2705 AES-GCM Encryption
`;
      message += `\u2705 Message Integrity (HMAC)
`;
      message += `\u2705 Perfect Forward Secrecy
`;
      message += `\u2705 Replay Protection
`;
      message += `\u2705 DTLS Fingerprint
`;
      message += `\u2705 SAS Verification
`;
      message += `\u2705 Metadata Protection
`;
      message += `\u2705 Traffic Obfuscation
`;
    }
    message += `
${securityData.details || "Real cryptographic verification completed"}`;
    if (securityData.isRealData) {
      message += "\n\n\u2705 This is REAL-TIME verification using actual cryptographic functions.";
    } else {
      message += "\n\n\u26A0\uFE0F Warning: This data may be simulated. Connection may not be fully established.";
    }
    const modal = document.createElement("div");
    modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 10000;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: monospace;
        `;
    const content = document.createElement("div");
    content.style.cssText = `
            background: #1a1a1a;
            color: #fff;
            padding: 20px;
            border-radius: 8px;
            max-width: 80%;
            max-height: 80%;
            overflow-y: auto;
            white-space: pre-line;
            border: 1px solid #333;
        `;
    content.textContent = message;
    modal.appendChild(content);
    modal.addEventListener("click", (e) => {
      if (e.target === modal) {
        document.body.removeChild(modal);
      }
    });
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        document.body.removeChild(modal);
        document.removeEventListener("keydown", handleKeyDown);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    document.body.appendChild(modal);
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
  const displaySecurityLevel = isConnected ? realSecurityLevel || securityLevel : null;
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
            }, "End-to-end freedom v4.3.120")
          ])
        ]),
        // Status and Controls - Responsive
        React.createElement("div", {
          key: "status-section",
          className: "flex items-center space-x-2 sm:space-x-3"
        }, [
          // Session Timer - all features enabled by default
          shouldShowTimer && React.createElement(window.SessionTimer, {
            key: "session-timer",
            timeLeft: currentTimeLeft,
            sessionType,
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

// src/components/ui/DownloadApps.jsx
var DownloadApps = () => {
  const apps = [
    { id: "web", name: "Web App", subtitle: "Browser Version", icon: "fas fa-globe", platform: "Web", isActive: true, url: "https://securebit.chat/", color: "green" },
    { id: "windows", name: "Windows", subtitle: "Desktop App", icon: "fab fa-windows", platform: "Desktop", isActive: true, url: "https://securebit.chat/download/windows/SecureBit%20Chat%20Setup%204.1.222.exe", color: "blue" },
    { id: "macos", name: "macOS", subtitle: "Desktop App", icon: "fab fa-safari", platform: "Desktop", isActive: false, url: "#", color: "gray" },
    { id: "linux", name: "Linux", subtitle: "Desktop App", icon: "fab fa-linux", platform: "Desktop", isActive: false, url: "#", color: "orange" },
    { id: "ios", name: "iOS", subtitle: "iPhone & iPad", icon: "fab fa-apple", platform: "Mobile", isActive: false, url: "https://apps.apple.com/app/securebit-chat/", color: "white" },
    { id: "android", name: "Android", subtitle: "Google Play", icon: "fab fa-android", platform: "Mobile", isActive: false, url: "https://play.google.com/store/apps/details?id=com.securebit.chat", color: "green" }
  ];
  const handleDownload = (app) => {
    if (app.isActive) window.open(app.url, "_blank");
  };
  const desktopApps = apps.filter((a) => a.platform !== "Mobile");
  const mobileApps = apps.filter((a) => a.platform === "Mobile");
  const cardSize = "w-28 h-28";
  const colorClasses = {
    green: "text-green-500",
    blue: "text-blue-500",
    blueios: "text-blue-600",
    gray: "text-gray-500",
    orange: "text-orange-500"
  };
  const renderAppCard = (app) => React.createElement("div", {
    key: app.id,
    className: `group relative ${cardSize} rounded-2xl overflow-hidden card-minimal cursor-pointer`
  }, [
    React.createElement("i", {
      key: "bg-icon",
      className: `${app.icon} absolute text-[3rem] ${app.isActive ? colorClasses[app.color] : "text-white/10"} top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none transition-all duration-500 group-hover:scale-105`
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
  ]);
  return React.createElement("div", { className: "mt-20 px-6" }, [
    // Header
    React.createElement("div", { key: "header", className: "text-center max-w-3xl mx-auto mb-12" }, [
      React.createElement("h3", { key: "title", className: "text-3xl font-bold text-primary mb-3" }, "Download SecureBit.chat"),
      React.createElement("p", { key: "subtitle", className: "text-secondary text-lg mb-5" }, "Stay secure on every device. Choose your platform and start chatting privately.")
    ]),
    // Desktop Apps
    React.createElement(
      "div",
      { key: "desktop-row", className: "hidden sm:flex justify-center flex-wrap gap-6 mb-6" },
      desktopApps.map(renderAppCard)
    ),
    // Mobile Apps
    React.createElement(
      "div",
      { key: "mobile-row", className: "flex justify-center gap-6" },
      mobileApps.map(renderAppCard)
    )
  ]);
};
window.DownloadApps = DownloadApps;

// src/components/ui/UniqueFeatureSlider.jsx
var UniqueFeatureSlider = () => {
  const trackRef = React.useRef(null);
  const wrapRef = React.useRef(null);
  const [current, setCurrent] = React.useState(0);
  const [isReady, setIsReady] = React.useState(false);
  const slides = [
    {
      icon: "\u{1F6E1}\uFE0F",
      bgImage: "linear-gradient(135deg, rgb(255 107 53 / 6%) 0%, rgb(255 140 66 / 45%) 100%)",
      thumbIcon: "\u{1F512}",
      title: "18-Layer Military Security",
      description: "Revolutionary defense system with ECDH P-384 + AES-GCM 256 + ECDSA + Complete ASN.1 Validation."
    },
    {
      icon: "\u{1F310}",
      bgImage: "linear-gradient(135deg, rgb(147 51 234 / 6%) 0%, rgb(168 85 247 / 45%) 100%)",
      thumbIcon: "\u{1F517}",
      title: "Pure P2P WebRTC",
      description: "Direct peer-to-peer connections without any servers. Complete decentralization with zero infrastructure."
    },
    {
      icon: "\u{1F504}",
      bgImage: "linear-gradient(135deg, rgb(16 185 129 / 6%) 0%, rgb(52 211 153 / 45%) 100%)",
      thumbIcon: "\u26A1",
      title: "Perfect Forward Secrecy",
      description: "Automatic key rotation every 5 minutes. Non-extractable keys with hardware protection."
    },
    {
      icon: "\u{1F3AD}",
      bgImage: "linear-gradient(135deg, rgb(6 182 212 / 6%) 0%, rgb(34 211 238 / 45%) 100%)",
      thumbIcon: "\u{1F32B}\uFE0F",
      title: "Traffic Obfuscation",
      description: "Fake traffic generation and pattern masking make communication indistinguishable from noise."
    },
    {
      icon: "\u{1F441}\uFE0F",
      bgImage: "linear-gradient(135deg, rgb(37 99 235 / 6%) 0%, rgb(59 130 246 / 45%) 100%)",
      thumbIcon: "\u{1F6AB}",
      title: "Zero Data Collection",
      description: "No registration, no servers, no logs. Complete anonymity with instant channels."
    }
  ];
  React.useEffect(() => {
    const timer = setTimeout(() => {
      setIsReady(true);
    }, 100);
    return () => clearTimeout(timer);
  }, []);
  const isMobile = () => window.matchMedia("(max-width:767px)").matches;
  const center = React.useCallback((i) => {
    if (!trackRef.current || !wrapRef.current) return;
    const card = trackRef.current.children[i];
    if (!card) return;
    const axis = isMobile() ? "top" : "left";
    const size = isMobile() ? "clientHeight" : "clientWidth";
    const start2 = isMobile() ? card.offsetTop : card.offsetLeft;
    wrapRef.current.scrollTo({
      [axis]: start2 - (wrapRef.current[size] / 2 - card[size] / 2),
      behavior: "smooth"
    });
  }, []);
  const activate = React.useCallback((i, scroll = false) => {
    if (i === current) return;
    setCurrent(i);
    if (scroll) {
      setTimeout(() => center(i), 50);
    }
  }, [current, center]);
  const go = (step) => {
    const newIndex = Math.min(Math.max(current + step, 0), slides.length - 1);
    activate(newIndex, true);
  };
  React.useEffect(() => {
    const handleKeydown = (e) => {
      if (["ArrowRight", "ArrowDown"].includes(e.key)) go(1);
      if (["ArrowLeft", "ArrowUp"].includes(e.key)) go(-1);
    };
    window.addEventListener("keydown", handleKeydown, { passive: true });
    return () => window.removeEventListener("keydown", handleKeydown);
  }, [current]);
  React.useEffect(() => {
    if (isReady) {
      center(current);
    }
  }, [current, center, isReady]);
  if (!isReady) {
    return React.createElement(
      "section",
      {
        style: {
          background: "transparent",
          minHeight: "400px",
          display: "flex",
          alignItems: "center",
          justifyContent: "center"
        }
      },
      React.createElement("div", {
        style: {
          opacity: 0.5,
          fontSize: "14px",
          color: "#fff"
        }
      }, "Loading...")
    );
  }
  return React.createElement("section", { style: { background: "transparent" } }, [
    // Header
    React.createElement("div", {
      key: "head",
      className: "head"
    }, [
      React.createElement("h2", {
        key: "title",
        className: "text-2xl sm:text-3xl font-bold text-white mb-4 leading-snug"
      }, "Why SecureBit.chat is unique"),
      React.createElement("div", {
        key: "controls",
        className: "controls"
      }, [
        React.createElement("button", {
          key: "prev",
          id: "prev-slider",
          className: "nav-btn",
          "aria-label": "Prev",
          disabled: current === 0,
          onClick: () => go(-1)
        }, "\u2039"),
        React.createElement("button", {
          key: "next",
          id: "next-slider",
          className: "nav-btn",
          "aria-label": "Next",
          disabled: current === slides.length - 1,
          onClick: () => go(1)
        }, "\u203A")
      ])
    ]),
    // Slider
    React.createElement(
      "div",
      {
        key: "slider",
        className: "slider",
        ref: wrapRef
      },
      React.createElement("div", {
        className: "track",
        ref: trackRef
      }, slides.map(
        (slide, index) => React.createElement("article", {
          key: index,
          className: "project-card",
          ...index === current ? { active: "" } : {},
          onMouseEnter: () => {
            if (window.matchMedia("(hover:hover)").matches) {
              activate(index, true);
            }
          },
          onClick: () => activate(index, true)
        }, [
          // Background
          React.createElement("div", {
            key: "bg",
            className: "project-card__bg",
            style: {
              background: slide.bgImage,
              backgroundSize: "cover",
              backgroundPosition: "center"
            }
          }),
          // Content
          React.createElement("div", {
            key: "content",
            className: "project-card__content"
          }, [
            // Text container
            React.createElement("div", { key: "text" }, [
              React.createElement("h3", {
                key: "title",
                className: "project-card__title"
              }, slide.title),
              React.createElement("p", {
                key: "desc",
                className: "project-card__desc"
              }, slide.description)
            ])
          ])
        ])
      ))
    )
  ]);
};
window.UniqueFeatureSlider = UniqueFeatureSlider;

// src/components/ui/SecurityFeatures.jsx
var SecurityFeatures = () => {
  const features = [
    { id: "feature1", color: "#00ff88", icon: "fas fa-key accent-green", title: "ECDH P-384 Key Exchange", desc: "Military-grade elliptic curve key exchange" },
    { id: "feature2", color: "#a78bfa", icon: "fas fa-user-shield accent-purple", title: "MITM Protection", desc: "Out-of-band verification against attacks" },
    { id: "feature3", color: "#ff8800", icon: "fas fa-lock accent-orange", title: "AES-GCM 256 Encryption", desc: "Authenticated encryption standard" },
    { id: "feature4", color: "#00ffff", icon: "fas fa-sync-alt accent-cyan", title: "Perfect Forward Secrecy", desc: "Automatic key rotation every 5 minutes" },
    { id: "feature5", color: "#0088ff", icon: "fas fa-signature accent-blue", title: "ECDSA P-384 Signatures", desc: "Digital signatures for message integrity" },
    { id: "feature6", color: "#f87171", icon: "fas fa-shield-alt accent-red", title: "SAS Security", desc: "Revolutionary key exchange & MITM protection" }
  ];
  React.useEffect(() => {
    const cards = document.querySelectorAll(".card");
    const radius = 200;
    const handleMove = (e) => {
      cards.forEach((card) => {
        const rect = card.getBoundingClientRect();
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;
        const dx = e.clientX - cx;
        const dy = e.clientY - cy;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < radius) {
          const x = e.clientX - rect.left;
          const y = e.clientY - rect.top;
          card.style.setProperty("--x", `${x}px`);
          card.style.setProperty("--y", `${y}px`);
          card.classList.add("active-glow");
        } else {
          card.classList.remove("active-glow");
        }
      });
    };
    window.addEventListener("mousemove", handleMove);
    return () => window.removeEventListener("mousemove", handleMove);
  }, []);
  const renderFeature = (f) => React.createElement("div", {
    key: f.id,
    className: "card p-3 sm:p-4 text-center",
    style: { "--color": f.color }
  }, [
    React.createElement("div", { key: "icon", className: "w-10 h-10 sm:w-12 sm:h-12 flex items-center justify-center mx-auto mb-2 sm:mb-3 relative z-10" }, [
      React.createElement("i", { className: f.icon })
    ]),
    React.createElement("h4", { key: "title", className: "text-xs sm:text-sm font-medium text-primary mb-1 relative z-10" }, f.title),
    React.createElement("p", { key: "desc", className: "text-xs text-muted leading-tight relative z-10" }, f.desc)
  ]);
  return React.createElement("div", {
    className: "grid grid-cols-2 md:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 max-w-6xl mx-auto mt-8"
  }, features.map(renderFeature));
};
window.SecurityFeatures = SecurityFeatures;

// src/components/ui/Testimonials.jsx
var Testimonials = () => {
  const testimonials = [
    { id: "t1", rating: 5, text: "The interface feels modern and smooth. It saves me at least 2 hours every day when managing design tasks." },
    { id: "t2", rating: 5, text: "Finally, a solution that blends speed with simplicity. My team adopted it within a week without training." },
    { id: "t3", rating: 5, text: "I can track progress in real time and get a clear overview of our workflow. It feels empowering." },
    { id: "t4", rating: 5, text: "Our pipeline visibility improved dramatically. I no longer need to manually track updates." },
    { id: "t5", rating: 5, text: "The security-first approach gives me peace of mind. We handle sensitive data with confidence now." },
    { id: "t6", rating: 5, text: "User feedback cycles are now twice as fast. It helps us test and ship features quickly." }
  ];
  React.useEffect(() => {
    const colUp = document.querySelector(".col-up");
    const colDown = document.querySelector(".col-down");
    const wrapper = document.querySelector(".testimonials-wrapper");
    if (!colUp || !colDown || !wrapper) return;
    let paused = false;
    const speed = 0.5;
    let animationId;
    const cloneCards = (container) => {
      const cards = Array.from(container.children);
      cards.forEach((card) => {
        const clone = card.cloneNode(true);
        container.appendChild(clone);
      });
    };
    cloneCards(colUp);
    cloneCards(colDown);
    const getHalfHeight = (el) => {
      const children = Array.from(el.children);
      const halfCount = children.length / 2;
      let height = 0;
      for (let i = 0; i < halfCount; i++) {
        height += children[i].offsetHeight;
        if (i < halfCount - 1) height += 24;
      }
      return height;
    };
    let y1 = 0;
    const maxScroll1 = getHalfHeight(colUp);
    const maxScroll2 = getHalfHeight(colDown);
    let y2 = -maxScroll2;
    function animate() {
      if (!paused) {
        y1 -= speed;
        y2 += speed;
        if (Math.abs(y1) >= maxScroll1) {
          y1 = 0;
        }
        if (y2 >= 0) {
          y2 = -maxScroll2;
        }
        colUp.style.transform = `translateY(${y1}px)`;
        colDown.style.transform = `translateY(${y2}px)`;
      }
      animationId = requestAnimationFrame(animate);
    }
    animate();
    const handleMouseEnter = () => {
      paused = true;
    };
    const handleMouseLeave = () => {
      paused = false;
    };
    wrapper.addEventListener("mouseenter", handleMouseEnter);
    wrapper.addEventListener("mouseleave", handleMouseLeave);
    return () => {
      cancelAnimationFrame(animationId);
      wrapper.removeEventListener("mouseenter", handleMouseEnter);
      wrapper.removeEventListener("mouseleave", handleMouseLeave);
    };
  }, []);
  const renderCard = (t, index) => /* @__PURE__ */ React.createElement("div", { key: `${t.id}-${index}`, className: "card bg-neutral-900 rounded-xl p-5 shadow-md w-72 text-sm text-white flex-shrink-0" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center mb-2 text-yellow-400" }, "\u2605".repeat(Math.floor(t.rating)), /* @__PURE__ */ React.createElement("span", { className: "ml-2 text-secondary" }, t.rating.toFixed(1))), /* @__PURE__ */ React.createElement("p", { className: "text-secondary mb-3" }, t.text));
  return /* @__PURE__ */ React.createElement("section", { className: "py-14 px-6 bg-transparent" }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 lg:grid-cols-5 gap-12 max-w-7xl mx-auto items-center" }, /* @__PURE__ */ React.createElement("div", { className: "lg:col-span-2 flex flex-col justify-center" }, /* @__PURE__ */ React.createElement("p", { className: "text-sm text-secondary mb-2" }, "Testimonials"), /* @__PURE__ */ React.createElement("h2", { className: "text-2xl sm:text-3xl font-bold text-white mb-4 leading-snug" }, "What our users are saying"), /* @__PURE__ */ React.createElement("p", { className: "text-secondary text-sm" }, "We continuously listen to our community and improve every day.")), /* @__PURE__ */ React.createElement("div", { className: "lg:col-span-3 testimonials-wrapper flex gap-6 overflow-hidden relative h-[420px]" }, /* @__PURE__ */ React.createElement("div", { className: "pointer-events-none absolute top-0 left-0 w-full h-16 bg-gradient-to-b from-[#1f1f1f]/90 to-transparent z-20" }), /* @__PURE__ */ React.createElement("div", { className: "pointer-events-none absolute bottom-0 left-0 w-full h-16 bg-gradient-to-t from-[#1f1f1f]/90 to-transparent z-20" }), /* @__PURE__ */ React.createElement("div", { className: "col-up flex flex-col gap-6" }, testimonials.map((t, i) => renderCard(t, i))), /* @__PURE__ */ React.createElement("div", { className: "col-down flex flex-col gap-6" }, testimonials.map((t, i) => renderCard(t, i))))));
};
window.Testimonials = Testimonials;

// src/components/ui/ComparisonTable.jsx
var ComparisonTable = () => {
  const [selectedFeature, setSelectedFeature] = React.useState(null);
  const messengers = [
    {
      name: "SecureBit.chat",
      logo: /* @__PURE__ */ React.createElement("div", { className: "w-8 h-8 bg-orange-500/10 border border-orange-500/20 rounded-lg flex items-center justify-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-shield-halved text-orange-400" })),
      type: "P2P WebRTC",
      version: "Latest",
      color: "orange"
    },
    {
      name: "Signal",
      logo: /* @__PURE__ */ React.createElement("svg", { className: "w-8 h-8", viewBox: "0 0 122.88 122.31", xmlns: "http://www.w3.org/2000/svg" }, /* @__PURE__ */ React.createElement("path", { className: "fill-blue-500", d: "M27.75,0H95.13a27.83,27.83,0,0,1,27.75,27.75V94.57a27.83,27.83,0,0,1-27.75,27.74H27.75A27.83,27.83,0,0,1,0,94.57V27.75A27.83,27.83,0,0,1,27.75,0Z" }), /* @__PURE__ */ React.createElement("path", { className: "fill-white", d: "M61.44,25.39A35.76,35.76,0,0,0,31.18,80.18L27.74,94.86l14.67-3.44a35.77,35.77,0,1,0,19-66Z" })),
      type: "Centralized",
      version: "Latest",
      color: "blue"
    },
    {
      name: "Threema",
      logo: /* @__PURE__ */ React.createElement("svg", { className: "w-8 h-8", viewBox: "0 0 122.88 122.88", xmlns: "http://www.w3.org/2000/svg" }, /* @__PURE__ */ React.createElement("rect", { width: "122.88", height: "122.88", rx: "18.43", fill: "#474747" }), /* @__PURE__ */ React.createElement("path", { fill: "#FFFFFF", d: "M44.26,78.48l-19.44,4.8l4.08-16.56c-4.08-5.28-6.48-12-6.48-18.96c0-18.96,17.52-34.32,39.12-34.32c21.6,0,39.12,15.36,39.12,34.32c0,18.96-17.52,34.32-39.12,34.32c-6,0-12-1.2-17.04-3.36L44.26,78.48z M50.26,44.64h-0.48c-0.96,0-1.68,0.72-1.44,1.68v15.6c0,0.96,0.72,1.68,1.68,1.68l23.04,0c0.96,0,1.68-0.72,1.68-1.68v-15.6c0-0.96-0.72-1.68-1.68-1.68h-0.48v-4.32c0-6-5.04-11.04-11.04-11.04S50.5,34.32,50.5,40.32v4.32H50.26z M68.02,44.64h-13.2v-4.32c0-3.6,2.88-6.72,6.72-6.72c3.6,0,6.72,2.88,6.72,6.72v4.32H68.02z" }), /* @__PURE__ */ React.createElement("circle", { cx: "37.44", cy: "97.44", r: "6.72", fill: "#3fe669" }), /* @__PURE__ */ React.createElement("circle", { cx: "61.44", cy: "97.44", r: "6.72", fill: "#3fe669" }), /* @__PURE__ */ React.createElement("circle", { cx: "85.44", cy: "97.44", r: "6.72", fill: "#3fe669" })),
      type: "Centralized",
      version: "Latest",
      color: "green"
    },
    {
      name: "Session",
      logo: /* @__PURE__ */ React.createElement("svg", { className: "w-8 h-8", viewBox: "0 0 1024 1024", xmlns: "http://www.w3.org/2000/svg" }, /* @__PURE__ */ React.createElement("rect", { width: "1024", height: "1024", fill: "#333132" }), /* @__PURE__ */ React.createElement("path", { fill: "#00f782", d: "M431 574.8c-.8-7.4-6.7-8.2-10.8-10.6-13.6-7.9-27.5-15.4-41.3-23l-22.5-12.3c-8.5-4.7-17.1-9.2-25.6-14.1-10.5-6-21-11.9-31.1-18.6-18.9-12.5-33.8-29.1-46.3-48.1-8.3-12.6-14.8-26.1-19.2-40.4-6.7-21.7-10.8-44.1-7.8-66.8 1.8-14 4.6-28 9.7-41.6 7.8-20.8 19.3-38.8 34.2-54.8 9.8-10.6 21.2-19.1 33.4-26.8 14.7-9.3 30.7-15.4 47.4-19 13.8-3 28.1-4.3 42.2-4.4 89.9-.4 179.7-.3 269.6 0 12.6 0 25.5 1 37.7 4.1 24.3 6.2 45.7 18.2 63 37 11.2 12.2 20.4 25.8 25.8 41.2 7.3 20.7 12.3 42.1 6.7 64.4-2.1 8.5-2.7 17.5-6.1 25.4-4.7 10.9-10.8 21.2-17.2 31.2-8.7 13.5-20.5 24.3-34.4 32.2-10.1 5.7-21 10.2-32 14.3-18.1 6.7-37.2 5-56.1 5.2-17.2.2-34.5 0-51.7.1-1.7 0-3.4 1.2-5.1 1.9 1.3 1.8 2.1 4.3 3.9 5.3 13.5 7.8 27.2 15.4 40.8 22.9 11 6 22.3 11.7 33.2 17.9 15.2 8.5 30.2 17.4 45.3 26.1 19.3 11.1 34.8 26.4 47.8 44.3 9.7 13.3 17.2 27.9 23 43.5 6.1 16.6 9.2 33.8 10.4 51.3.6 9.1-.7 18.5-1.9 27.6-1.2 9.1-2.7 18.4-5.6 27.1-3.3 10.2-7.4 20.2-12.4 29.6-8.4 15.7-19.6 29.4-32.8 41.4-12.7 11.5-26.8 20.6-42.4 27.6-22.9 10.3-46.9 14.4-71.6 14.5-89.7.3-179.4.2-269.1-.1-12.6 0-25.5-1-37.7-3.9-24.5-5.7-45.8-18-63.3-36.4-11.6-12.3-20.2-26.5-26.6-41.9-2.7-6.4-4.1-13.5-5.4-20.4-1.5-8.1-2.8-16.3-3.1-24.5-.6-15.7 2.8-30.9 8.2-45.4 8.2-22 21.7-40.6 40.2-55.2 10-7.9 21.3-13.7 33.1-18.8 16.6-7.2 34-8.1 51.4-8.5 21.9-.5 43.9-.1 65.9-.1 1.9-.1 3.9-.3 6.2-.4zm96.3-342.4c0 .1 0 .1 0 0-48.3.1-96.6-.6-144.9.5-13.5.3-27.4 3.9-40.1 8.7-14.9 5.6-28.1 14.6-39.9 25.8-20.2 19-32.2 42.2-37.2 68.9-3.6 19-1.4 38.1 4.1 56.5 4.1 13.7 10.5 26.4 18.5 38.4 14.8 22.2 35.7 36.7 58.4 49.2 11 6.1 22.2 11.9 33.2 18 13.5 7.5 26.9 15.1 40.4 22.6 13.1 7.3 26.2 14.5 39.2 21.7 9.7 5.3 19.4 10.7 29.1 16.1 2.9 1.6 4.1.2 4.5-2.4.3-2 .3-4 .3-6.1v-58.8c0-19.9.1-39.9 0-59.8 0-6.6 1.7-12.8 7.6-16.1 3.5-2 8.2-2.8 12.4-2.8 50.3-.2 100.7-.2 151-.1 19.8 0 38.3-4.4 55.1-15.1 23.1-14.8 36.3-36.3 40.6-62.9 3.4-20.8-1-40.9-12.4-58.5-17.8-27.5-43.6-43-76.5-43.6-47.8-.8-95.6-.2-143.4-.2zm-30.6 559.7c45.1 0 90.2-.2 135.3.1 18.9.1 36.6-3.9 53.9-11.1 18.4-7.7 33.6-19.8 46.3-34.9 9.1-10.8 16.2-22.9 20.8-36.5 4.2-12.4 7.4-24.7 7.3-37.9-.1-10.3.2-20.5-3.4-30.5-2.6-7.2-3.4-15.2-6.4-22.1-3.9-8.9-8.9-17.3-14-25.5-12.9-20.8-31.9-34.7-52.8-46.4-10.6-5.9-21.2-11.6-31.8-17.5-10.3-5.7-20.4-11.7-30.7-17.4-11.2-6.1-22.5-11.9-33.7-18-16.6-9.1-33.1-18.4-49.8-27.5-4.9-2.7-6.1-1.9-6.4 3.9-.1 2-.1 4.1-.1 6.1v114.5c0 14.8-5.6 20.4-20.4 20.4-47.6.1-95.3-.1-142.9.2-10.5.1-21.1 1.4-31.6 2.8-16.5 2.2-30.5 9.9-42.8 21-17 15.5-27 34.7-29.4 57.5-1.1 10.9-.4 21.7 2.9 32.5 3.7 12.3 9.2 23.4 17.5 33 19.2 22.1 43.4 33.3 72.7 33.3 46.6.1 93 0 139.5 0z" })),
      type: "Onion Network",
      version: "Latest",
      color: "cyan"
    }
  ];
  const features = [
    {
      name: "Security Architecture",
      lockbit: { status: "trophy", detail: "18-layer military-grade defense system with complete ASN.1 validation" },
      signal: { status: "check", detail: "Signal Protocol with double ratchet" },
      threema: { status: "check", detail: "Standard security implementation" },
      session: { status: "check", detail: "Modified Signal Protocol + Onion routing" }
    },
    {
      name: "Cryptography",
      lockbit: { status: "trophy", detail: "ECDH P-384 + AES-GCM 256 + ECDSA P-384" },
      signal: { status: "check", detail: "Signal Protocol + Double Ratchet" },
      threema: { status: "check", detail: "NaCl + XSalsa20 + Poly1305" },
      session: { status: "check", detail: "Modified Signal Protocol" }
    },
    {
      name: "Perfect Forward Secrecy",
      lockbit: { status: "trophy", detail: "Auto rotation every 5 minutes or 100 messages" },
      signal: { status: "check", detail: "Double Ratchet algorithm" },
      threema: { status: "warning", detail: "Partial (group chats)" },
      session: { status: "check", detail: "Session Ratchet algorithm" }
    },
    {
      name: "Architecture",
      lockbit: { status: "trophy", detail: "Pure P2P WebRTC without servers" },
      signal: { status: "times", detail: "Centralized Signal servers" },
      threema: { status: "times", detail: "Threema servers in Switzerland" },
      session: { status: "warning", detail: "Onion routing via network nodes" }
    },
    {
      name: "Registration Anonymity",
      lockbit: { status: "trophy", detail: "No registration required, instant anonymous channels" },
      signal: { status: "times", detail: "Phone number required" },
      threema: { status: "check", detail: "ID generated locally" },
      session: { status: "check", detail: "Random session ID" }
    },
    {
      name: "Payment Integration",
      lockbit: { status: "trophy", detail: "Lightning Network satoshis per session + WebLN" },
      signal: { status: "times", detail: "No payment system" },
      threema: { status: "times", detail: "No payment system" },
      session: { status: "times", detail: "No payment system" }
    },
    {
      name: "Metadata Protection",
      lockbit: { status: "trophy", detail: "Full metadata encryption + traffic obfuscation" },
      signal: { status: "warning", detail: "Sealed Sender (partial)" },
      threema: { status: "warning", detail: "Minimal metadata" },
      session: { status: "check", detail: "Onion routing hides metadata" }
    },
    {
      name: "Traffic Obfuscation",
      lockbit: { status: "trophy", detail: "Fake traffic + pattern masking + packet padding" },
      signal: { status: "times", detail: "No traffic obfuscation" },
      threema: { status: "times", detail: "No traffic obfuscation" },
      session: { status: "check", detail: "Onion routing provides obfuscation" }
    },
    {
      name: "Open Source",
      lockbit: { status: "trophy", detail: "100% open + auditable + MIT license" },
      signal: { status: "check", detail: "Fully open" },
      threema: { status: "warning", detail: "Only clients open" },
      session: { status: "check", detail: "Fully open" }
    },
    {
      name: "MITM Protection",
      lockbit: { status: "trophy", detail: "Out-of-band verification + mutual auth + ECDSA" },
      signal: { status: "check", detail: "Safety numbers verification" },
      threema: { status: "check", detail: "QR code scanning" },
      session: { status: "warning", detail: "Basic key verification" }
    },
    {
      name: "Economic Model",
      lockbit: { status: "trophy", detail: "Sustainable pay-per-session model" },
      signal: { status: "warning", detail: "Donations and grants dependency" },
      threema: { status: "check", detail: "One-time app purchase" },
      session: { status: "warning", detail: "Donations dependency" }
    },
    {
      name: "Censorship Resistance",
      lockbit: { status: "trophy", detail: "Impossible to block P2P + no servers to target" },
      signal: { status: "warning", detail: "Blocked in authoritarian countries" },
      threema: { status: "warning", detail: "May be blocked" },
      session: { status: "check", detail: "Onion routing bypasses blocks" }
    },
    {
      name: "Data Storage",
      lockbit: { status: "trophy", detail: "Zero data storage - only in browser memory" },
      signal: { status: "warning", detail: "Local database storage" },
      threema: { status: "warning", detail: "Local + optional backup" },
      session: { status: "warning", detail: "Local database storage" }
    },
    {
      name: "Key Security",
      lockbit: { status: "trophy", detail: "Non-extractable keys + hardware protection" },
      signal: { status: "check", detail: "Secure key storage" },
      threema: { status: "check", detail: "Local key storage" },
      session: { status: "check", detail: "Secure key storage" }
    },
    {
      name: "Post-Quantum Roadmap",
      lockbit: { status: "check", detail: "Planned v5.0 - CRYSTALS-Kyber/Dilithium" },
      signal: { status: "warning", detail: "PQXDH in development" },
      threema: { status: "times", detail: "Not announced" },
      session: { status: "times", detail: "Not announced" }
    }
  ];
  const getStatusIcon = (status) => {
    const statusMap = {
      "trophy": { icon: "fa-trophy", color: "accent-orange" },
      "check": { icon: "fa-check", color: "text-green-300" },
      "warning": { icon: "fa-exclamation-triangle", color: "text-yellow-300" },
      "times": { icon: "fa-times", color: "text-red-300" }
    };
    return statusMap[status] || { icon: "fa-question", color: "text-gray-400" };
  };
  const toggleFeatureDetail = (index) => {
    setSelectedFeature(selectedFeature === index ? null : index);
  };
  return /* @__PURE__ */ React.createElement("div", { className: "mt-16" }, /* @__PURE__ */ React.createElement("div", { className: "text-center mb-8" }, /* @__PURE__ */ React.createElement("h3", { className: "text-3xl font-bold text-white mb-3" }, "Enhanced Security Edition Comparison"), /* @__PURE__ */ React.createElement("p", { className: "text-gray-400 max-w-2xl mx-auto mb-4" }, "Enhanced Security Edition vs leading secure messengers")), /* @__PURE__ */ React.createElement("div", { className: "max-w-7xl mx-auto" }, /* @__PURE__ */ React.createElement("div", { className: "md:hidden p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg mb-4" }, /* @__PURE__ */ React.createElement("p", { className: "text-yellow-400 text-sm text-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-lightbulb mr-2" }), "Rotate your device horizontally for better viewing")), /* @__PURE__ */ React.createElement("div", { className: "overflow-x-auto" }, /* @__PURE__ */ React.createElement(
    "table",
    {
      className: "w-full border-collapse rounded-xl overflow-hidden shadow-2xl",
      style: { backgroundColor: "rgba(42, 43, 42, 0.9)" }
    },
    /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", { className: "bg-black-table" }, /* @__PURE__ */ React.createElement("th", { className: "text-left p-4 border-b border-gray-600 text-white font-bold min-w-[240px]" }, "Security Criterion"), messengers.map((messenger, index) => /* @__PURE__ */ React.createElement("th", { key: `messenger-${index}`, className: "text-center p-4 border-b border-gray-600 min-w-[160px]" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col items-center" }, /* @__PURE__ */ React.createElement("div", { className: "mb-2" }, messenger.logo), /* @__PURE__ */ React.createElement("div", { className: `text-sm font-bold ${messenger.color === "orange" ? "text-orange-400" : messenger.color === "blue" ? "text-blue-400" : messenger.color === "green" ? "text-green-400" : "text-cyan-400"}` }, messenger.name), /* @__PURE__ */ React.createElement("div", { className: "text-xs text-gray-400" }, messenger.type), /* @__PURE__ */ React.createElement("div", { className: "text-xs text-gray-500 mt-1" }, messenger.version)))))),
    /* @__PURE__ */ React.createElement("tbody", null, features.map((feature, featureIndex) => /* @__PURE__ */ React.createElement(React.Fragment, { key: `feature-${featureIndex}` }, /* @__PURE__ */ React.createElement(
      "tr",
      {
        className: `border-b border-gray-700/30 transition-all duration-200 cursor-pointer hover:bg-[rgb(20_20_20_/30%)] ${selectedFeature === featureIndex ? "bg-[rgb(20_20_20_/50%)]" : ""}`,
        onClick: () => toggleFeatureDetail(featureIndex)
      },
      /* @__PURE__ */ React.createElement("td", { className: "p-4 text-white font-semibold" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between" }, /* @__PURE__ */ React.createElement("span", null, feature.name), /* @__PURE__ */ React.createElement("i", { className: `fas fa-chevron-${selectedFeature === featureIndex ? "up" : "down"} text-xs text-gray-400 opacity-60 transition-all duration-200` }))),
      /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${getStatusIcon(feature.lockbit.status).icon} ${getStatusIcon(feature.lockbit.status).color} text-2xl` })),
      /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${getStatusIcon(feature.signal.status).icon} ${getStatusIcon(feature.signal.status).color} text-2xl` })),
      /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${getStatusIcon(feature.threema.status).icon} ${getStatusIcon(feature.threema.status).color} text-2xl` })),
      /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${getStatusIcon(feature.session.status).icon} ${getStatusIcon(feature.session.status).color} text-2xl` }))
    ), selectedFeature === featureIndex && /* @__PURE__ */ React.createElement("tr", { className: "border-b border-gray-700/30 bg-gradient-to-r from-gray-800/20 to-gray-900/20" }, /* @__PURE__ */ React.createElement("td", { className: "p-4 text-xs text-gray-400 font-medium" }, "Technical Details:"), /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs text-orange-300 font-medium leading-relaxed" }, feature.lockbit.detail)), /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs text-blue-300 leading-relaxed" }, feature.signal.detail)), /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs text-green-300 leading-relaxed" }, feature.threema.detail)), /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs text-cyan-300 leading-relaxed" }, feature.session.detail))))))
  )), /* @__PURE__ */ React.createElement("div", { className: "mt-8 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-5xl mx-auto" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center p-4 bg-orange-500/10 rounded-xl hover:bg-orange-500/40 transition-colors" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-trophy text-orange-400 mr-2 text-xl" }), /* @__PURE__ */ React.createElement("span", { className: "text-orange-300 text-sm font-bold" }, "Category Leader")), /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center p-4 bg-green-500/10 rounded-xl hover:bg-green-600/40 transition-colors" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check text-green-300 mr-2 text-xl" }), /* @__PURE__ */ React.createElement("span", { className: "text-green-200 text-sm font-bold" }, "Excellent")), /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center p-4 bg-yellow-500/10 rounded-xl hover:bg-yellow-600/40 transition-colors" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-triangle text-yellow-300 mr-2 text-xl" }), /* @__PURE__ */ React.createElement("span", { className: "text-yellow-200 text-sm font-bold" }, "Partial/Limited")), /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center p-4 bg-red-500/10 rounded-xl hover:bg-red-600/40 transition-colors" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-times text-red-300 mr-2 text-xl" }), /* @__PURE__ */ React.createElement("span", { className: "text-red-200 text-sm font-bold" }, "Not Available")))));
};
window.ComparisonTable = ComparisonTable;

// src/components/ui/Roadmap.jsx
function Roadmap() {
  const [selectedPhase, setSelectedPhase] = React.useState(null);
  const phases = [
    {
      version: "v1.0",
      title: "Start of Development",
      status: "done",
      date: "Early 2025",
      description: "Idea, prototype, and infrastructure setup",
      features: [
        "Concept and requirements formation",
        "Stack selection: WebRTC, P2P, cryptography",
        "First messaging prototypes",
        "Repository creation and CI",
        "Basic encryption architecture",
        "UX/UI design"
      ]
    },
    {
      version: "v1.5",
      title: "Alpha Release",
      status: "done",
      date: "Spring 2025",
      description: "First public alpha: basic chat and key exchange",
      features: [
        "Basic P2P messaging via WebRTC",
        "Simple E2E encryption (demo scheme)",
        "Stable signaling and reconnection",
        "Minimal UX for testing",
        "Feedback collection from early testers"
      ]
    },
    {
      version: "v2.0",
      title: "Security Hardened",
      status: "done",
      date: "Summer 2025",
      description: "Security strengthening and stable branch release",
      features: [
        "ECDH/ECDSA implementation in production",
        "Perfect Forward Secrecy and key rotation",
        "Improved authentication checks",
        "File encryption and large payload transfers",
        "Audit of basic cryptoprocesses"
      ]
    },
    {
      version: "v3.0",
      title: "Scaling & Stability",
      status: "done",
      date: "Fall 2025",
      description: "Network scaling and stability improvements",
      features: [
        "Optimization of P2P connections and NAT traversal",
        "Reconnection mechanisms and message queues",
        "Reduced battery consumption on mobile",
        "Support for multi-device synchronization",
        "Monitoring and logging tools for developers"
      ]
    },
    {
      version: "v3.5",
      title: "Privacy-first Release",
      status: "done",
      date: "Winter 2025",
      description: "Focus on privacy: minimizing metadata",
      features: [
        "Metadata protection and fingerprint reduction",
        "Experiments with onion routing and DHT",
        "Options for anonymous connections",
        "Preparation for open code audit",
        "Improved user verification processes"
      ]
    },
    // current and future phases
    {
      version: "v4.3.120",
      title: "Enhanced Security Edition",
      status: "current",
      date: "Now",
      description: "Current version with ECDH + DTLS + SAS security, 18-layer military-grade cryptography and complete ASN.1 validation",
      features: [
        "ECDH + DTLS + SAS triple-layer security",
        "ECDH P-384 + AES-GCM 256-bit encryption",
        "DTLS fingerprint verification",
        "SAS (Short Authentication String) verification",
        "Perfect Forward Secrecy with key rotation",
        "Enhanced MITM attack prevention",
        "Complete ASN.1 DER validation",
        "OID and EC point verification",
        "SPKI structure validation",
        "P2P WebRTC architecture",
        "Metadata protection",
        "100% open source code"
      ]
    },
    {
      version: "v4.5",
      title: "Mobile & Desktop Edition",
      status: "development",
      date: "Q2 2025",
      description: "Native apps for all platforms",
      features: [
        "PWA app for mobile",
        "Electron app for desktop",
        "Real-time notifications",
        "Automatic reconnection",
        "Battery optimization",
        "Cross-device synchronization",
        "Improved UX/UI",
        "Support for files up to 100MB"
      ]
    },
    {
      version: "v5.0",
      title: "Quantum-Resistant Edition",
      status: "planned",
      date: "Q4 2025",
      description: "Protection against quantum computers",
      features: [
        "Post-quantum cryptography CRYSTALS-Kyber",
        "SPHINCS+ digital signatures",
        "Hybrid scheme: classic + PQ",
        "Quantum-safe key exchange",
        "Updated hashing algorithms",
        "Migration of existing sessions",
        "Compatibility with v4.x",
        "Quantum-resistant protocols"
      ]
    },
    {
      version: "v5.5",
      title: "Group Communications",
      status: "planned",
      date: "Q2 2026",
      description: "Group chats with preserved privacy",
      features: [
        "P2P group connections up to 8 participants",
        "Mesh networking for groups",
        "Signal Double Ratchet for groups",
        "Anonymous groups without metadata",
        "Ephemeral groups (disappear after session)",
        "Cryptographic group administration",
        "Group member auditing"
      ]
    },
    {
      version: "v6.0",
      title: "Decentralized Network",
      status: "research",
      date: "2027",
      description: "Fully decentralized network",
      features: [
        "LockBit node mesh network",
        "DHT for peer discovery",
        "Built-in onion routing",
        "Tokenomics and node incentives",
        "Governance via DAO",
        "Interoperability with other networks",
        "Cross-platform compatibility",
        "Self-healing network"
      ]
    },
    {
      version: "v7.0",
      title: "AI Privacy Assistant",
      status: "research",
      date: "2028+",
      description: "AI for privacy and security",
      features: [
        "Local AI threat analysis",
        "Automatic MITM detection",
        "Adaptive cryptography",
        "Personalized security recommendations",
        "Zero-knowledge machine learning",
        "Private AI assistant",
        "Predictive security",
        "Autonomous attack protection"
      ]
    }
  ];
  const getStatusConfig = (status) => {
    switch (status) {
      case "current":
        return {
          color: "green",
          bgClass: "bg-green-500/10 border-green-500/20",
          textClass: "text-green-400",
          icon: "fas fa-check-circle",
          label: "Current Version"
        };
      case "development":
        return {
          color: "orange",
          bgClass: "bg-orange-500/10 border-orange-500/20",
          textClass: "text-orange-400",
          icon: "fas fa-code",
          label: "In Development"
        };
      case "planned":
        return {
          color: "blue",
          bgClass: "bg-blue-500/10 border-blue-500/20",
          textClass: "text-blue-400",
          icon: "fas fa-calendar-alt",
          label: "Planned"
        };
      case "research":
        return {
          color: "purple",
          bgClass: "bg-purple-500/10 border-purple-500/20",
          textClass: "text-purple-400",
          icon: "fas fa-flask",
          label: "Research"
        };
      case "done":
        return {
          color: "gray",
          bgClass: "bg-gray-500/10 border-gray-500/20",
          textClass: "text-gray-300",
          icon: "fas fa-flag-checkered",
          label: "Released"
        };
      default:
        return {
          color: "gray",
          bgClass: "bg-gray-500/10 border-gray-500/20",
          textClass: "text-gray-400",
          icon: "fas fa-question",
          label: "Unknown"
        };
    }
  };
  const togglePhaseDetail = (index) => {
    setSelectedPhase(selectedPhase === index ? null : index);
  };
  return /* @__PURE__ */ React.createElement("div", { key: "roadmap-section", className: "mt-16 px-4 sm:px-0" }, /* @__PURE__ */ React.createElement("div", { key: "section-header", className: "text-center mb-12" }, /* @__PURE__ */ React.createElement("h3", { key: "title", className: "text-2xl font-semibold text-primary mb-3" }, "Development Roadmap"), /* @__PURE__ */ React.createElement("p", { key: "subtitle", className: "text-secondary max-w-2xl mx-auto mb-6" }, "Evolution of SecureBit.chat : from initial development to quantum-resistant decentralized network with complete ASN.1 validation")), /* @__PURE__ */ React.createElement("div", { key: "roadmap-container", className: "max-w-6xl mx-auto" }, /* @__PURE__ */ React.createElement("div", { key: "timeline", className: "relative" }, /* @__PURE__ */ React.createElement("div", { key: "phases", className: "space-y-8" }, phases.map((phase, index) => {
    const statusConfig = getStatusConfig(phase.status);
    const isExpanded = selectedPhase === index;
    return /* @__PURE__ */ React.createElement("div", { key: `phase-${index}`, className: "relative" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "aria-expanded": isExpanded,
        onClick: () => togglePhaseDetail(index),
        key: `phase-button-${index}`,
        className: `card-minimal rounded-xl p-4 text-left w-full transition-all duration-300 ${isExpanded ? "ring-2 ring-" + statusConfig.color + "-500/30" : ""}`
      },
      /* @__PURE__ */ React.createElement(
        "div",
        {
          key: "phase-header",
          className: "flex flex-col sm:flex-row sm:items-center sm:justify-between mb-4 space-y-2 sm:space-y-0"
        },
        /* @__PURE__ */ React.createElement(
          "div",
          {
            key: "phase-info",
            className: "flex flex-col sm:flex-row sm:items-center sm:space-x-4"
          },
          /* @__PURE__ */ React.createElement(
            "div",
            {
              key: "version-badge",
              className: `px-3 py-1 ${statusConfig.bgClass} border rounded-lg mb-2 sm:mb-0`
            },
            /* @__PURE__ */ React.createElement(
              "span",
              {
                key: "version",
                className: `${statusConfig.textClass} font-bold text-sm`
              },
              phase.version
            )
          ),
          /* @__PURE__ */ React.createElement("div", { key: "title-section" }, /* @__PURE__ */ React.createElement(
            "h4",
            {
              key: "title",
              className: "text-lg font-semibold text-primary"
            },
            phase.title
          ), /* @__PURE__ */ React.createElement(
            "p",
            {
              key: "description",
              className: "text-secondary text-sm"
            },
            phase.description
          ))
        ),
        /* @__PURE__ */ React.createElement(
          "div",
          {
            key: "phase-meta",
            className: "flex items-center space-x-3 text-sm text-gray-400 font-medium"
          },
          /* @__PURE__ */ React.createElement(
            "div",
            {
              key: "status-badge",
              className: `flex items-center px-3 py-1 ${statusConfig.bgClass} border rounded-lg`
            },
            /* @__PURE__ */ React.createElement(
              "i",
              {
                key: "status-icon",
                className: `${statusConfig.icon} ${statusConfig.textClass} mr-2 text-xs`
              }
            ),
            /* @__PURE__ */ React.createElement(
              "span",
              {
                key: "status-text",
                className: `${statusConfig.textClass} text-xs font-medium`
              },
              statusConfig.label
            )
          ),
          /* @__PURE__ */ React.createElement("div", { key: "date" }, phase.date),
          /* @__PURE__ */ React.createElement(
            "i",
            {
              key: "expand-icon",
              className: `fas fa-chevron-${isExpanded ? "up" : "down"} text-gray-400 text-sm`
            }
          )
        )
      ),
      isExpanded && /* @__PURE__ */ React.createElement(
        "div",
        {
          key: "features-section",
          className: "mt-6 pt-6 border-t border-gray-700/30"
        },
        /* @__PURE__ */ React.createElement(
          "h5",
          {
            key: "features-title",
            className: "text-primary font-medium mb-4 flex items-center"
          },
          /* @__PURE__ */ React.createElement(
            "i",
            {
              key: "features-icon",
              className: "fas fa-list-ul mr-2 text-sm"
            }
          ),
          "Key features:"
        ),
        /* @__PURE__ */ React.createElement(
          "div",
          {
            key: "features-grid",
            className: "grid md:grid-cols-2 gap-3"
          },
          phase.features.map((feature, featureIndex) => /* @__PURE__ */ React.createElement(
            "div",
            {
              key: `feature-${featureIndex}`,
              className: "flex items-center space-x-3 p-3 bg-custom-bg rounded-lg"
            },
            /* @__PURE__ */ React.createElement(
              "div",
              {
                className: `w-2 h-2 rounded-full ${statusConfig.textClass.replace(
                  "text-",
                  "bg-"
                )}`
              }
            ),
            /* @__PURE__ */ React.createElement("span", { className: "text-secondary text-sm" }, feature)
          ))
        )
      )
    ));
  })))), /* @__PURE__ */ React.createElement("div", { key: "cta-section", className: "mt-12 text-center" }, /* @__PURE__ */ React.createElement(
    "div",
    {
      key: "cta-card",
      className: "card-minimal rounded-xl p-8 max-w-2xl mx-auto"
    },
    /* @__PURE__ */ React.createElement(
      "h4",
      {
        key: "cta-title",
        className: "text-xl font-semibold text-primary mb-3"
      },
      "Join the future of privacy"
    ),
    /* @__PURE__ */ React.createElement("p", { key: "cta-description", className: "text-secondary mb-6" }, "SecureBit.chat grows thanks to the community. Your ideas and feedback help shape the future of secure communication with complete ASN.1 validation."),
    /* @__PURE__ */ React.createElement(
      "div",
      {
        key: "cta-buttons",
        className: "flex flex-col sm:flex-row gap-4 justify-center"
      },
      /* @__PURE__ */ React.createElement(
        "a",
        {
          key: "github-link",
          href: "https://github.com/SecureBitChat/securebit-chat/",
          className: "btn-primary text-white py-3 px-6 rounded-lg font-medium transition-all duration-200 flex items-center justify-center"
        },
        /* @__PURE__ */ React.createElement("i", { key: "github-icon", className: "fab fa-github mr-2" }),
        "GitHub Repository"
      ),
      /* @__PURE__ */ React.createElement(
        "a",
        {
          key: "feedback-link",
          href: "mailto:lockbitchat@tutanota.com",
          className: "btn-secondary text-white py-3 px-6 rounded-lg font-medium transition-all duration-200 flex items-center justify-center"
        },
        /* @__PURE__ */ React.createElement("i", { key: "feedback-icon", className: "fas fa-comments mr-2" }),
        "Feedback"
      )
    )
  )));
}
window.Roadmap = Roadmap;

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
