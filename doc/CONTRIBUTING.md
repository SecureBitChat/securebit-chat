# Contributing to SecureBit.chat

🎉 **Thank you for your interest in contributing to SecureBit.chat!** 

We're building the most secure P2P messenger with Lightning Network integration, and we need your help to make it even better. **Version 4.02.442 introduces complete ASN.1 validation for enhanced key security.**

## 🌟 Ways to Contribute

### 🐛 Bug Reports
Found a bug? Help us squash it!

### 💡 Feature Requests  
Have an idea for improvement? We'd love to hear it!

### 🔒 Security Research
Help audit our cryptographic implementation and ASN.1 validation framework

### 📖 Documentation
Improve guides, tutorials, and technical docs

### 🌍 Translations
Help make SecureBit.chat accessible worldwide

### 💻 Code Contributions
Submit pull requests for bug fixes and features

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this.checkCustomCondition(parsed)) {
        throw new Error('Custom validation failed');
    }
    return true;
}

// Integrate with main validation
validateKeyStructure(keyData) {
    const parsed = this.parseDER(keyData);
    
    // Existing validations...
    if (!this.validateSPKI(parsed)) return false;
    if (!this.validateOID(parsed)) return false;
    if (!this.validateECPoint(parsed)) return false;
    
    // New custom validation
    if (!this.validateCustomRule(parsed)) return false;
    
    return true;
}
```

### Testing ASN.1 Validation

#### **Unit Tests**
```javascript
describe('ASN.1 Validation Framework', () => {
    test('Validates correct P-384 key structure', () => {
        const validKey = generateValidP384Key();
        expect(asn1Validator.validateKeyStructure(validKey)).toBe(true);
    });
    
    test('Rejects modified key with valid header', () => {
        const modifiedKey = modifyKeyData(validKey);
        expect(asn1Validator.validateKeyStructure(modifiedKey)).toBe(false);
    });
    
    test('Rejects unsupported curve OID', () => {
        const invalidOIDKey = generateKeyWithInvalidOID();
        expect(asn1Validator.validateKeyStructure(invalidOIDKey)).toBe(false);
    });
});
```

#### **Performance Tests**
```javascript
describe('ASN.1 Validation Performance', () => {
    test('Validation completes within 10ms', () => {
        const start = performance.now();
        asn1Validator.validateKeyStructure(validKey);
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(10);
    });
});
```

### Security Guidelines for ASN.1 Contributions

#### **Critical Requirements**
1. **Never bypass validation** - All keys must pass complete ASN.1 validation
2. **Maintain strict OID checking** - Only support verified, secure algorithms
3. **Preserve size limits** - Key size limits prevent DoS attacks
4. **Validate all structural elements** - Complete verification is mandatory

#### **Common Pitfalls to Avoid**
```javascript
// ❌ DON'T: Skip validation for performance
const fastImport = (keyData) => {
    // Bypassing validation for speed
    return crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};

// ✅ DO: Always validate before processing
const secureImport = async (keyData) => {
    if (!asn1Validator.validateKeyStructure(keyData)) {
        throw new Error('Key validation failed');
    }
    return await crypto.subtle.importKey('spki', keyData, algorithm, false, ['verify']);
};
```

#### **Validation Order**
1. **Parse DER** - Complete ASN.1 structure parsing
2. **Validate SPKI** - SubjectPublicKeyInfo structure
3. **Validate OID** - Algorithm and curve verification
4. **Validate EC Point** - Format and structure verification
5. **Apply custom rules** - Any additional validation requirements

### Breaking Changes and Compatibility

#### **Version 4.02.442 Changes**
- **Enhanced key validation** now performs complete ASN.1 parsing
- **Stricter key acceptance** criteria for improved security
- **Fallback support** from P-384 to P-256 maintained
- **Backward compatibility** for valid key structures

#### **Migration Considerations**
- **Existing keys** are validated on next use
- **New keys** must pass complete validation
- **Invalid keys** are rejected with clear error messages
- **Performance impact** is minimal (< 10ms per validation)

### Documentation Requirements

#### **Code Documentation**
```javascript
/**
 * Validates cryptographic key structure using complete ASN.1 DER parsing
 * 
 * @param {ArrayBuffer} keyData - Raw key data to validate
 * @returns {boolean} - True if validation passes, false otherwise
 * @throws {Error} - Detailed error message for validation failures
 * 
 * @example
 * const isValid = asn1Validator.validateKeyStructure(keyData);
 * if (!isValid) {
 *     console.error('Key validation failed');
 * }
 */
validateKeyStructure(keyData) {
    // Implementation...
}
```

#### **API Documentation**
- **Function signatures** with parameter types
- **Return values** and error conditions
- **Usage examples** for common scenarios
- **Performance characteristics** and limitations

### Contributing Guidelines Summary

#### **For ASN.1 Framework Contributions**
1. **Understand the security model** - Complete validation is mandatory
2. **Follow validation order** - Parse → SPKI → OID → EC Point → Custom
3. **Maintain performance** - Keep validation time under 10ms
4. **Add comprehensive tests** - Unit, integration, and performance tests
5. **Document thoroughly** - Code comments, API docs, and examples
6. **Consider breaking changes** - Ensure backward compatibility where possible

#### **Security Review Process**
1. **Code review** by cryptographic experts
2. **Security testing** for validation bypass attempts
3. **Performance validation** for timing attacks
4. **Compatibility testing** with existing key formats
5. **Documentation review** for accuracy and completeness

---

## 🚀 Getting Started

### Prerequisites
- **Browser:** Modern browser with WebRTC and WebCrypto support
- **Git:** For version control
- **Text Editor:** VS Code, Vim, or your favorite editor
- **Lightning Wallet:** For testing payment features (optional)

### Development Setup
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/yourusername/securebit-chat.git
cd securebit-chat

# 3. Create a development branch
git checkout -b feature/your-feature-name

# 4. Start development server
python -m http.server 8000
# or
npx serve .

# 5. Open http://localhost:8000
# Make your changes
# Test thoroughly
# Commit with descriptive messages
git commit -m "feat: add quantum-resistant key exchange

- Implement CRYSTALS-Kyber for post-quantum security
- Add fallback to classical ECDH
- Update security level calculations
- Add comprehensive test suite

Closes #123"
```

## 📋 Contribution Guidelines

### 🔍 Before You Start

- Check existing issues - avoid duplicate work
- Create an issue - discuss your idea first
- Get feedback - ensure alignment with project goals
- Fork and branch - work on a feature branch

### 💻 Code Standards

#### JavaScript Style
```javascript
// ✅ Good
const encryptionKey = await crypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256
}, false, ['encrypt', 'decrypt']);

// ❌ Bad
var key=crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
```

#### Naming Conventions

- **Functions:** camelCase - `generateSecureKey()`
- **Classes:** PascalCase - `EnhancedSecureCryptoUtils`
- **Constants:** UPPER_SNAKE_CASE - `MAX_MESSAGE_LENGTH`
- **Files:** kebab-case - `crypto-utils.js`

### 📖 Documentation

## 🔒 Security Considerations

### Critical Areas
These areas require extra careful review:

- **Cryptographic functions** - All crypto code must be reviewed
- **Key generation** - Entropy and randomness
- **Message handling** - Input validation and sanitization
- **P2P communication** - WebRTC security
- **Lightning integration** - Payment verification
- **ASN.1 validation** - Key structure verification (NEW)

### Security Checklist

## 🔐 ASN.1 Validation Framework (NEW)

### Overview
SecureBit.chat v4.02.442 implements a complete ASN.1 DER parser and validation system. This framework requires special attention when contributing to cryptographic code.

### Key Components

#### **ASN1Validator Class**
```javascript
// Core validation class for cryptographic keys
class ASN1Validator {
    constructor() {
        this.supportedOIDs = {
            '1.2.840.10045.3.1.7': 'P-256',  // secp256r1
            '1.3.132.0.34': 'P-384'          // secp384r1
        };
        this.maxKeySize = 2000;  // bytes
        this.minKeySize = 50;    // bytes
    }

    // Complete DER parsing and validation
    validateKeyStructure(keyData) {
        // Implementation details...
    }
}
```

#### **Integration Points**
- **Key import operations** - All keys must pass ASN.1 validation
- **Key export operations** - Exported keys are validated
- **Real-time validation** - Continuous validation during operations

### Contributing to ASN.1 Framework

#### **Adding New Curve Support**
```javascript
// To add support for a new elliptic curve:
const newCurveOID = '1.3.132.0.XX';  // Replace XX with actual OID
const curveName = 'P-XXX';            // Replace XXX with curve name

// Add to supportedOIDs
this.supportedOIDs[newCurveOID] = curveName;

// Update validation logic if needed
// Ensure proper EC point format validation
```

#### **Extending Validation Rules**
```javascript
// To add new validation rules:
validateCustomRule(parsed) {
    // Implement your validation logic
    if (!this