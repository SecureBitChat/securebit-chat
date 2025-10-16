# SecureBit.chat v4.4.18

<div align="center">

![SecureBit.chat Logo](logo/favicon.ico)

**World's first P2P messenger with ECDH + DTLS + SAS security and military-grade cryptography**

[![Latest Release](https://img.shields.io/github/v/release/SecureBitChat/securebit-chat?style=for-the-badge&logo=github&color=orange)](https://github.com/SecureBitChat/securebit-chat/releases/latest)
[![Live Demo](https://img.shields.io/badge/🌐_Live_Demo-Try_Now-success?style=for-the-badge)](https://securebitchat.github.io/securebit-chat/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

[🚀 Try Now](https://securebitchat.github.io/securebit-chat/) • [📖 Documentation](#-quick-start) • [🔒 Security](#-security) • [🤝 Contribute](#-contributing)

</div>

---

## 🎯 Overview

SecureBit.chat is a revolutionary peer-to-peer messenger that prioritizes your privacy with military-grade encryption. No servers, no registration, no data collection - just pure, secure communication.

### Key Features

- 🔐 **19-Layer Military Security** - ECDH + DTLS + SAS verification
- 🌐 **Pure P2P Architecture** - No servers, truly decentralized
- 📱 **Progressive Web App** - Install like a native app
- 📂 **Secure File Transfer** - End-to-end encrypted P2P file sharing
- 🔔 **Smart Notifications** - Browser alerts only when away
- 🎭 **Complete Anonymity** - Zero data collection, no registration

---

## ✨ What's New in v4.4.18

### 🔔 Secure Browser Notifications
- Smart delivery when user is away from chat tab
- Cross-browser compatibility (Chrome, Firefox, Safari, Edge)
- Page Visibility API integration with proper tab focus detection
- XSS protection with text sanitization and URL validation
- Rate limiting and spam protection
- Automatic cleanup and memory management

### 🧹 Code Cleanup & Architecture
- Removed session management logic for simplified architecture
- Eliminated experimental Bluetooth module
- Cleaned debug logging from production code
- Removed test functions from production build
- Enhanced error handling for production stability

### 🛡️ Security Enhancements
- **ECDH + DTLS + SAS System** - Triple-layer security verification
- **ASN.1 Full Structure Validation** - Complete key structure verification
- **Enhanced MITM Protection** - Multi-layer defense system
- **Secure Key Storage** - WeakMap-based isolation
- **Production-Ready Logging** - Data sanitization and privacy protection

---

## 🏆 Why SecureBit.chat?

### Security Comparison

| Feature | **SecureBit.chat** | Signal | Threema | Session |
|---------|-------------------|--------|---------|---------|
| Architecture | 🏆 Pure P2P WebRTC | ❌ Centralized | ❌ Centralized | ⚠️ Onion network |
| File Transfer | 🏆 P2P encrypted | ✅ Via servers | ✅ Via servers | ✅ Via servers |
| PWA Support | 🏆 Full PWA | ❌ None | ❌ None | ❌ None |
| Registration | 🏆 Anonymous | ❌ Phone required | ✅ ID generated | ✅ Random ID |
| Traffic Obfuscation | 🏆 Advanced | ❌ None | ❌ None | ✅ Onion routing |
| Data Storage | 🏆 Zero storage | ⚠️ Local database | ⚠️ Local + backup | ⚠️ Local database |
| ASN.1 Validation | 🏆 Complete | ⚠️ Basic | ⚠️ Basic | ⚠️ Basic |

**Legend:** 🏆 Category Leader • ✅ Excellent • ⚠️ Partial/Limited • ❌ Not Available

### 19-Layer Military Security

1. WebRTC DTLS transport encryption
2. ECDH P-384 perfect forward secrecy
3. AES-GCM 256 authenticated encryption
4. ECDSA P-384 message integrity
5. Replay protection with timestamp validation
6. Automatic key rotation (every 5 min/100 messages)
7. MITM verification with out-of-band codes
8. Traffic obfuscation and pattern masking
9. Complete metadata protection
10. Memory protection with no persistent storage
11. Hardware security with non-extractable keys
12. Session isolation and complete cleanup
13. Mutex framework for race condition protection
14. Secure key storage with WeakMap isolation
15. Production logging with data sanitization
16. ASN.1 complete key structure verification
17. OID validation for algorithms and curves
18. EC point format and structure verification
19. Smart notifications with XSS protection

---

## 🚀 Quick Start

### Option 1: Use Online (Recommended)

1. Visit [securebitchat.github.io/securebit-chat](https://securebitchat.github.io/securebit-chat/)
2. Install PWA by clicking "Install" button for native app experience
3. Choose "Create Channel" or "Join Channel"
4. Complete secure key exchange with verification
5. Verify security codes and start chatting
6. Communicate with military-grade encryption

### Option 2: Self-Host

```bash
# Clone repository
git clone https://github.com/SecureBitChat/securebit-chat.git
cd securebit-chat

# Serve locally
python -m http.server 8000        # Python
npx serve .                       # Node.js
php -S localhost:8000             # PHP

# Open browser
open http://localhost:8000
```

---

## 📂 Secure File Transfer

### Features
- **P2P Direct Transfer** - No servers, direct WebRTC channels
- **Military-Grade Encryption** - AES-GCM 256-bit + ECDH P-384
- **Chunk-Level Security** - Individual encryption per file chunk
- **Hash Validation** - SHA-384 checksums prevent tampering
- **Automatic Recovery** - Retry mechanisms for interruptions
- **Stream Isolation** - Separate channels from chat messages

### Supported Files
Documents (PDF, DOC, TXT), Images (JPG, PNG, GIF), Archives (ZIP, RAR), Media (MP3, MP4), and any file type up to size limits.

---

## 🔧 Technical Architecture

### Cryptographic Stack

```
📂 File Transfer:     AES-GCM 256-bit + SHA-384 + Chunking
🔐 Application:       AES-GCM 256-bit + ECDSA P-384
🔑 Key Exchange:      ECDH P-384 (Perfect Forward Secrecy)
🛡️ Transport:         WebRTC DTLS 1.2
🌐 Network:           P2P WebRTC Data Channels
📱 PWA:               Service Workers + Cache API
🔒 Validation:        Complete ASN.1 DER parsing
```

### Standards Compliance
- NIST SP 800-56A (ECDH Key Agreement)
- NIST SP 800-186 (Elliptic Curve Cryptography)
- RFC 8446 (TLS 1.3 for WebRTC)
- RFC 5280 (X.509 Certificate Structure)
- RFC 5480 (EC Subject Public Key Information)

### Browser Requirements
Modern browser with WebRTC support (Chrome 60+, Firefox 60+, Safari 12+), HTTPS connection, JavaScript enabled, Service Worker support for PWA.

---

## 🗺️ Roadmap

**Current: v4.4.18** - Browser Notifications & Code Cleanup ✅

**Next Releases:**

- **v4.5 (Q2 2025)** - Mobile & Desktop Apps
  - Native mobile applications (iOS/Android)
  - Electron desktop application
  - Push notifications and cross-device sync

- **v5.0 (Q4 2025)** - Quantum-Resistant Edition
  - CRYSTALS-Kyber post-quantum key exchange
  - SPHINCS+ post-quantum signatures
  - Hybrid classical + post-quantum schemes

- **v5.5 (Q2 2026)** - Group Communications
  - P2P group chats (up to 8 participants)
  - Mesh networking topology
  - Anonymous group administration

- **v6.0 (2027)** - Decentralized Network
  - DHT-based peer discovery
  - Built-in onion routing
  - Decentralized identity system

---

## 💻 Development

### Project Structure

```
securebit-chat/
├── index.html                    # Main application
├── manifest.json                 # PWA manifest
├── sw.js                         # Service worker
├── src/
│   ├── components/ui/            # React UI components
│   ├── crypto/                   # Cryptographic utilities
│   │   └── ASN1Validator.js     # ASN.1 DER parser
│   ├── network/                  # WebRTC P2P manager
│   ├── notifications/            # Browser notifications
│   ├── transfer/                 # File transfer system
│   ├── pwa/                      # PWA management
│   └── styles/                   # CSS styling
├── logo/                         # Icons and logos
└── docs/                         # Documentation
```

### Build Workflow

```bash
# CSS changes (Tailwind)
npm run build:css

# JavaScript/JSX changes
npm run build:js

# Full rebuild (recommended)
npm run build

# Development with live server
npm run dev
```

**Important:** Always rebuild after changes. Source files are in `src/`, generated files in `assets/` and `dist/`. Never edit generated files directly.

### Technology Stack
- **Frontend:** Pure JavaScript + React (via CDN)
- **PWA:** Service Workers + Cache API + Web App Manifest
- **Cryptography:** Web Crypto API + custom ECDH/ECDSA + ASN.1 parser
- **Network:** WebRTC P2P Data Channels
- **Notifications:** Browser Notifications API + Page Visibility API
- **File Transfer:** Enhanced secure P2P streaming with chunked encryption
- **Styling:** TailwindCSS + custom CSS

---

## 🛡️ Security

### Audit Status
- ✅ Internal cryptographic review completed
- ✅ P2P protocol security analysis completed
- ✅ File transfer security validation completed
- ✅ ASN.1 validation and key verification completed
- 🔄 Professional security audit planned Q3 2025

### Vulnerability Reporting
Contact: **SecureBitChat@proton.me**

See **SECURITY.md** for detailed security policy.

### Security Features
- Perfect Forward Secrecy for messages and files
- Out-of-band verification prevents MITM attacks
- Traffic obfuscation defeats network analysis
- Memory protection with no persistent storage
- Complete ASN.1 key structure validation
- File integrity with SHA-384 hash validation

---

## 📊 Performance

- **Connection setup:** < 3 seconds
- **Message latency:** < 100 ms (P2P direct)
- **File transfer speed:** Up to 5 MB/s
- **Memory usage:** < 50 MB active session
- **PWA install size:** < 2 MB
- **Key validation:** < 10 ms (ASN.1 parsing)

---

## 🤝 Contributing

We welcome contributions! Here's how:

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m "Add amazing feature"`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

### Contribution Areas
🔐 Cryptography • 🌐 Network • 🔔 Notifications • 📂 File Transfer • 📱 PWA • 🎨 UI/UX • 📚 Documentation • 🔒 ASN.1 Validation

---

## 📞 Contact & Support

- **Email:** SecureBitChat@proton.me
- **GitHub:** Issues & Discussions
- **Security:** SecureBitChat@proton.me

---

## ⚠️ Important Disclaimers

### Security Notice
While SecureBit.chat implements military-grade cryptography, no system is 100% secure. Always verify security codes out-of-band and keep devices updated.

### Legal Notice
This software is provided "as is" for educational and research purposes. Users are responsible for compliance with local laws regarding cryptographic software and private communications.

### Privacy Statement
SecureBit.chat collects zero data, stores nothing, requires no registration, and uses no servers. All data exists only in browser memory with direct P2P connections.

---

## 📄 License

MIT License - see **LICENSE** file for details.

100% open source with full transparency, no telemetry, and zero data collection.

---

<div align="center">

**SecureBit.chat Security Team**

*Committed to protecting your privacy with military-grade security*

**Report vulnerabilities:** SecureBitChat@proton.me

---

**Latest Release: v4.4.18** - Browser Notifications & Code Cleanup

[🚀 Try Now](https://securebitchat.github.io/securebit-chat/) • [⭐ Star on GitHub](https://github.com/SecureBitChat/securebit-chat)

</div>