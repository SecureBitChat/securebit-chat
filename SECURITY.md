# Security Policy

## 🛡️ Security Overview

LockBit.chat is built with security-first principles. We take security vulnerabilities seriously and appreciate responsible disclosure from the security community.

## 🔒 Security Features

### Cryptographic Implementation
- **Key Exchange:** ECDH P-384 (NIST recommended curve)
- **Encryption:** AES-GCM 256-bit with authenticated encryption
- **Digital Signatures:** ECDSA P-384 for message authenticity
- **Perfect Forward Secrecy:** Automatic key rotation every 5 minutes
- **Non-extractable Keys:** All cryptographic keys are hardware-protected
- **MITM Protection:** Out-of-band verification codes

### Architecture Security
- **Zero-trust Model:** No central servers to compromise
- **P2P Direct:** WebRTC encrypted channels
- **No Data Persistence:** Messages exist only in memory
- **Rate Limiting:** Protection against spam and DoS
- **Replay Protection:** Sequence numbers and message IDs

## 🚨 Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 4.0.x   | ✅ Yes            |
| < 4.0   | ❌ No             |

## 📋 Reporting a Vulnerability

### 🔴 Critical Vulnerabilities
For **critical security issues** that could compromise user safety:

**DO NOT** create a public GitHub issue.

**Contact us privately:**
- 📧 **Email:** security@lockbit.chat (PGP key below)
- 🔒 **Signal:** +[REDACTED] (ask for Signal number via email)
- 🔐 **Keybase:** @lockbitchat

### 🟡 Non-Critical Issues
For general security improvements or non-critical findings:
- Create a GitHub issue with `[SECURITY]` prefix
- Use our security issue template

## 📝 Vulnerability Disclosure Process

1. **Report:** Send details to security@lockbit.chat
2. **Acknowledgment:** We'll respond within 24 hours
3. **Investigation:** We'll investigate and keep you updated
4. **Fix:** We'll develop and test a fix
5. **Disclosure:** Public disclosure after fix is deployed
6. **Credit:** We'll credit you in our security hall of fame

### Timeline Expectations
- **Initial Response:** < 24 hours
- **Status Update:** Every 72 hours
- **Fix Timeline:** Critical bugs < 7 days, Others < 30 days

## 🏆 Security Hall of Fame

We maintain a hall of fame for security researchers who help improve LockBit.chat:

<!-- Security researchers will be listed here -->
*Be the first to help secure LockBit.chat!*

## 🔍 Security Audit History

### Independent Audits
- **Pending:** Professional cryptographic audit (Q2 2025)
- **Community:** Ongoing peer review by security researchers

### Internal Security Measures
- **Code Review:** All cryptographic code reviewed by multiple developers
- **Testing:** Comprehensive security test suite
- **Dependencies:** Regular security updates for all dependencies

## 🛠️ Security Best Practices for Users

### For Maximum Security:
1. **Verify Authenticity:** Always verify out-of-band codes
2. **Use Official Source:** Only use https://lockbit.chat
3. **Keep Updated:** Use the latest version
4. **Secure Environment:** Use updated browsers on secure devices
5. **Lightning Wallets:** Use reputable Lightning wallets (Alby, Zeus, etc.)

### Red Flags:
- ❌ Codes don't match during verification
- ❌ Unusual connection behavior
- ❌ Requests for private keys or seed phrases
- ❌ Unofficial domains or mirrors

## 🔬 Security Research Guidelines

### Scope
**In Scope:**
- ✅ Cryptographic implementation flaws
- ✅ WebRTC security issues
- ✅ Authentication bypass
- ✅ Input validation vulnerabilities
- ✅ Client-side security issues

**Out of Scope:**
- ❌ Social engineering attacks
- ❌ Physical attacks on user devices
- ❌ DoS attacks on user connections
- ❌ Issues requiring physical access
- ❌ Lightning Network protocol issues

### Research Ethics
- **No Disruption:** Don't interfere with live users
- **Responsible Disclosure:** Follow our disclosure timeline
- **No Data Harvesting:** Don't collect user communications
- **Legal Compliance:** Follow all applicable laws

## 📊 Security Metrics

We track and publish these security metrics:
- **Response Time:** Average time to acknowledge reports
- **Fix Time:** Average time to deploy fixes
- **Vulnerability Count:** Number of reported/fixed issues
- **Audit Coverage:** Percentage of code under security review

## 🔄 Security Updates

### How We Notify Users:
- **Critical:** Immediate notification on website
- **Important:** GitHub releases and social media
- **Minor:** Regular update cycles

### Auto-Update Policy:
- **Critical Security Fixes:** Automatic for web version
- **Feature Updates:** User-controlled
- **Breaking Changes:** Advance notice with migration guide

## 🤝 Working with Security Researchers

We value the security community and offer:
- **Recognition:** Public credit and hall of fame listing
- **Swag:** LockBit.chat merchandise for quality reports
- **References:** LinkedIn recommendations for exceptional work
- **Early Access:** Beta access to new security features

## 📚 Security Resources

### Technical Documentation:
- [Cryptographic Architecture](docs/CRYPTOGRAPHY.md)
- [P2P Security Model](docs/P2P-SECURITY.md)
- [Lightning Integration Security](docs/LIGHTNING-SECURITY.md)

### External Resources:
- [WebRTC Security Guide](https://webrtc-security.github.io/)
- [Web Crypto API Best Practices](https://www.w3.org/TR/WebCryptoAPI/)
- [Lightning Network Security](https://lightning.network/lightning-network-paper.pdf)

## 📞 Contact Information

- **Security Team:** security@lockbit.chat
- **General Contact:** lockbitchat@tutanota.com
- **GitHub Issues:** https://github.com/lockbitchat/lockbit-chat/issues

---

*This security policy is reviewed and updated quarterly. Last updated: 08/09/2025*
