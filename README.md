# SecureBit.chat v4.7.55

<div align="center">

![SecureBit.chat Logo](logo/favicon.ico)

**World's first P2P messenger with ECDH + DTLS + SAS security and military-grade cryptography**

[![Latest Release](https://img.shields.io/github/v/release/SecureBitChat/securebit-chat?style=for-the-badge&logo=github&color=orange)](https://github.com/SecureBitChat/securebit-chat/releases/latest)
[![Live Demo](https://img.shields.io/badge/🌐_Live_Demo-Try_Now-success?style=for-the-badge)](https://securebit.chat/)
[![Desktop Apps](https://img.shields.io/badge/🖥️_Desktop_Apps-Available-blue?style=for-the-badge)](https://github.com/SecureBitChat/securebit-desktop)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

[Try Web Version](https://securebit.chat/) • [🖥️ Download Desktop Apps](https://github.com/SecureBitChat/securebit-desktop) • [📖 Documentation](#-quick-start) • [🔒 Security](#-security)

</div>

---
## 🔐 Shared Security Core

SecureBitChat uses a shared Rust-based cryptographic core:  
https://github.com/SecureBitChat/securebit-core

This core is used across all platforms (web, desktop, mobile) as a single source of truth for all security-critical logic.

Community review is welcome. Bug reports and security feedback can be submitted via GitHub Issues.

## Now Available: Desktop Applications!

**SecureBit Chat native desktop apps are now available for Windows, macOS, and Linux!**

[![Download Desktop Apps](https://img.shields.io/badge/Download-Desktop%20Apps%20v0.1.0-blue?style=for-the-badge&logo=github)](https://github.com/SecureBitChat/securebit-desktop)

###  Get Desktop Apps
- **Windows 10/11** - NSIS Installer (x64)
- **macOS 11+** - Universal App (Intel + Apple Silicon)  
- **Linux** - AppImage (Universal, amd64)

**Status:** Public Beta v0.1.0 Available  
**Technology:** Built with Tauri v2 (Rust + Web Technologies)  
**Coming Q1 2026:** Windows Store, Mac App Store, Snap Store

**[Download Desktop Apps →](https://github.com/SecureBitChat/securebit-desktop/releases/latest)**

---

## Shared Security Core

**All SecureBit applications share the same open-source cryptographic core:**

[![Core Repository](https://img.shields.io/badge/Core-securebit--core-blue?style=for-the-badge&logo=rust)](https://github.com/SecureBitChat/securebit-core)

### Platform Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    User Applications                        │
├──────────────────┬──────────────────┬──────────────────────┤
│   Web Version    │  Desktop Apps    │   Mobile (Coming)   │
│   (This Repo)    │  (Tauri v2)      │      (Q1 2026)      │
│   Browser PWA    │  Windows/Mac/    │    iOS/Android      │
│   v4.7.55        │     Linux        │   Native Apps       │
│                  │   v0.1.0 Beta    │                      │
└────────┬─────────┴────────┬─────────┴──────────┬───────────┘
         │                  │                    │
         └──────────────────┼────────────────────┘
                            │
                            ▼
         ┌──────────────────────────────────────────┐
         │   securebit-core (Open Source)           │
         │   • All Cryptographic Operations         │
         │   • P2P Protocol Implementation          │
         │   • End-to-End Encryption             │
         │   • Key Exchange & Verification          │
         │   • ASN.1 Structure Validation           │
         │   License: Apache 2.0                    │
         └──────────────────────────────────────────┘
```

### Why This Architecture?

- **100% of cryptography is open source** - Audit at [securebit-core](https://github.com/SecureBitChat/securebit-core)
- **Single source of truth** - Same security across all platforms
- **Full transparency** - Security-critical code is publicly auditable
- **Community reviewed** - Bug reports and security feedback welcome
- **Memory-safe core** - Rust implementation prevents entire classes of vulnerabilities
- **Cross-platform consistency** - Identical security guarantees on all platforms

**Core Repository:** https://github.com/SecureBitChat/securebit-core  
**License:** Apache License 2.0  
**Language:** Rust (memory-safe, zero-cost abstractions)

---

## Overview

SecureBit.chat is a revolutionary peer-to-peer messenger that prioritizes your privacy with military-grade encryption. No servers, no registration, no data collection - just pure, secure communication.

### Platform Availability

| Platform | Status | Version | Link |
|----------|--------|---------|------|
| **Web Browser** | Production | v4.7.55 | [Launch Web App](https://securebitchat.github.io/securebit-chat/) |
| **Windows Desktop** | Beta | v0.1.0 | [Download](https://github.com/SecureBitChat/securebit-desktop/releases/latest) |
| **macOS Desktop** | Beta | v0.1.0 | [Download](https://github.com/SecureBitChat/securebit-desktop/releases/latest) |
| **Linux Desktop** | Beta | v0.1.0 | [Download](https://github.com/SecureBitChat/securebit-desktop/releases/latest) |
| **iOS Mobile** | 🔄 In Development | - | Coming Q1 2026 |
| **Android Mobile** | 🔄 In Development | - | Coming Q1 2026 |

### Key Features

- **18-Layer Military Security** - ECDH + DTLS + SAS triple-layer verification
- **Pure P2P Architecture** - No servers, truly decentralized
- **Progressive Web App** - Install like a native app on any device
- **Native Desktop Apps** - Windows, macOS, Linux (Tauri v2)
- **Native Mobile Apps** - iOS (Swift/SwiftUI), Android (Kotlin/Jetpack Compose) - Coming Q1 2026
- **Secure File Transfer** - End-to-end encrypted P2P file sharing
- **Smart Notifications** - Browser and desktop alerts
- **Complete Anonymity** - Zero data collection, no registration
- **Open Source Security** - Cryptographic core is fully auditable
- **ASN.1 Validation** - Complete key structure verification
- **Perfect Forward Secrecy** - Automatic key rotation

---

## ✨ What's New in v4.7.55

### Desktop Edition Release

- **Native Desktop Applications** - Windows, macOS, and Linux support
- **Tauri v2 Framework** - Lightweight, secure, and performant
- **System Integration** - Native notifications, system tray, auto-start
- **Offline Support** - Works without internet connection
- **Multi-window Support** - Multiple conversation windows
- **Improved Performance** - Native code execution for crypto operations

### Bug Fixes & Improvements

- **Fix:** Prevent encryption key loss and IndexedDB connection errors
- **Fix:** Disable timer-based key rotation for Double Ratchet mode
- **Fix:** Auto-reinitialize encryption keys when missing but ECDH available
- **Fix:** Preserve active keys during periodic cleanup in ratchet sessions
- **Fix:** IndexedDB "database closing" errors with connection checking
- **Improvement:** Individual transactions per queue item to prevent race conditions
- **Improvement:** Enhanced message text wrapping in chat interface

### Security Enhancements

- **ECDH + DTLS + SAS System** - Triple-layer security verification
- **ASN.1 Full Structure Validation** - Complete key structure verification
- **Enhanced MITM Protection** - Multi-layer defense system
- **Secure Key Storage** - WeakMap-based isolation
- **Production-Ready Logging** - Data sanitization and privacy protection
- **HKDF Key Derivation** - RFC 5869 compliant key separation and derivation

---

## Quick Start

### Web Version (Browser)

1. **Visit** [https://securebit.chat/](https://securebit.chat/)
2. **Share your link** or enter your peer's link
3. **Start chatting** - No registration required!

**Install as PWA:**
- Click the install prompt in your browser
- Or use browser menu: "Install SecureBit.chat"

### Desktop Version (Native Apps)

1. **Download** installer from [securebit-desktop releases](https://github.com/SecureBitChat/securebit-desktop/releases/latest)
2. **Install** on Windows, macOS, or Linux
3. **Launch** and start secure communication

**Platform-specific instructions:**
- **Windows:** Run `.exe` installer, follow setup wizard
- **macOS:** Open `.zip`, drag `SecureBit Chat.app` to Applications
- **Linux:** Make AppImage executable: `chmod +x SecureBit.Chat_*.AppImage`, then run

### Features Comparison

| Feature | Web Version | Desktop Apps |
|---------|-------------|--------------|
| **P2P Encryption** | ✅ | ✅ |
| **File Sharing** | ✅ | ✅ |
| **Voice/Video Calls** | ✅ | ✅ |
| **Screen Sharing** | ✅ | ✅ |
| **System Notifications** | ✅ (Browser) | ✅ (Native) |
| **Offline Mode** | ❌ | ✅ |
| **Auto-start** | ❌ | ✅ |
| **System Tray** | ❌ | ✅ |
| **Multi-window** | ❌ | ✅ |
| **Background Operation** | ❌ | ✅ |
| **Lower Resource Usage** | ❌ | ✅ (Tauri) |

---

## 🗺️ Roadmap

**Current: v4.7.55** - Desktop Edition Available 

### Released Versions

- **v4.5** - Enhanced Security Edition 
  - ECDH + DTLS + SAS triple-layer security
  - 18-layer military-grade cryptography
  - Complete ASN.1 validation
  - Perfect Forward Secrecy

- **v4.7** - Desktop Edition  (Current)
  - Native desktop applications (Windows, macOS, Linux)
  - Built with Tauri v2
  - System tray integration and native notifications
  - Offline support and multi-window

- **v0.1.0** - Desktop Apps Beta 
  - Initial desktop release
  - Windows, macOS, Linux support

### Upcoming Releases

- **v5.0 (Q1 2026)** - Mobile Edition 
  - Native iOS app (Swift/SwiftUI)
  - Native Android app (Kotlin/Jetpack Compose)
  - PWA support for mobile browsers
  - Real-time push notifications
  - Battery optimization
  - Biometric authentication

- **v5.5 (Q2 2026)** - Quantum-Resistant Edition 
  - CRYSTALS-Kyber post-quantum key exchange
  - SPHINCS+ post-quantum signatures
  - Hybrid classical + post-quantum schemes
  - Quantum-safe key exchange
  - Migration of existing sessions

- **v6.0 (Q4 2026)** - Group Communications 
  - P2P group connections up to 8 participants
  - Mesh networking for groups
  - Signal Double Ratchet for groups
  - Anonymous groups without metadata
  - Ephemeral groups (disappear after session)

- **v6.5 (2027)** - Decentralized Network 
  - DHT for peer discovery
  - Built-in onion routing
  - Tokenomics and node incentives
  - Governance via DAO
  - Self-healing network

- **v7.0 (2028+)** - AI Privacy Assistant 
  - Local AI threat analysis
  - Automatic MITM detection
  - Adaptive cryptography
  - Zero-knowledge machine learning

---

##  Security

### Open Source Cryptographic Core

**All security-critical code is open source and auditable:**

- **Repository:** [securebit-core](https://github.com/SecureBitChat/securebit-core)
- **License:** Apache License 2.0
- **Language:** Rust (memory-safe, prevents entire vulnerability classes)
- **Auditable:** 100% of cryptographic operations
- **Standards:** RFC 5869 (HKDF), NIST SP 800-56A (ECDH), RFC 8446 (DTLS)

### Security Features

#### Triple-Layer Verification
1. **ECDH (Elliptic Curve Diffie-Hellman)** - P-384 curve key exchange
2. **DTLS (Datagram Transport Layer Security)** - WebRTC transport security with fingerprint verification
3. **SAS (Short Authentication String)** - Visual MITM detection and verification

#### Cryptographic Primitives
- **Key Exchange:** ECDH P-384 (NIST curve)
- **Signatures:** ECDSA P-384
- **Encryption:** AES-256-GCM
- **Key Derivation:** HKDF-SHA-256 (RFC 5869)
- **Authentication:** HMAC-SHA-256
- **Hashing:** SHA-256, SHA-384

#### Protocol Security
- Perfect Forward Secrecy (PFS)
- End-to-End Encryption (E2EE)
- Zero-Knowledge Architecture
- Replay Protection
- Metadata Protection
- ASN.1 Structure Validation
- OID and EC Point Verification
- SPKI Structure Validation

#### Security Architecture
- **18-Layer Defense System** - Multiple independent security layers
- **MITM Attack Prevention** - Triple verification prevents man-in-the-middle attacks
- **Key Isolation** - WeakMap-based secure key storage
- **Secure Memory Management** - Automatic secure deletion of sensitive data
- **Production Logging** - Sanitized logs prevent information leakage

### What We DON'T Collect
- No personal information
- No phone numbers or emails
- No contact lists on servers
- No message content or metadata
- No telemetry or analytics
- No usage statistics
- No IP addresses logged
- No device fingerprints
- No location data

### Security Audit

Want to audit our security? Check these repositories:

1. **[securebit-core](https://github.com/SecureBitChat/securebit-core)** - All cryptographic operations (Rust)
2. **[securebit-chat](https://github.com/SecureBitChat/securebit-chat)** - Web UI implementation (this repo, JavaScript/React)

**Report Security Issues:** SecureBitChat@proton.me  
**PGP Key:** Available on request for encrypted security reports

---

## Development

### Prerequisites

- **Node.js** 18+ 
- **npm** or **yarn**
- **Git**

### Installation

```bash
# Clone repository
git clone https://github.com/SecureBitChat/securebit-chat.git
cd securebit-chat

# Install dependencies
npm install

# Run development server
npm run dev
```

### Building

```bash
# Build for production
npm run build

# Build CSS only
npm run build:css

# Build JavaScript only
npm run build:js

# Preview production build (requires Python)
python -m http.server 8000
```

### Development Scripts

```bash
# Development server with hot reload
npm run dev

# Watch CSS changes
npm run watch

# Build everything
npm run build

# Serve built files
npm run serve
```

### Project Structure

```
securebit-chat/
├── src/
│   ├── components/          # React components
│   │   ├── ui/             # UI components (Header, Roadmap, etc.)
│   │   └── QRScanner.jsx   # QR code scanner
│   ├── crypto/             # Cryptography utilities
│   │   └── EnhancedSecureCryptoUtils.js
│   ├── network/            # WebRTC P2P logic
│   │   └── EnhancedSecureWebRTCManager.js
│   ├── transfer/           # File transfer
│   │   └── EnhancedSecureFileTransfer.js
│   ├── notifications/      # Notification system
│   ├── pwa/                # PWA functionality
│   ├── scripts/            # Bootstrap and initialization
│   └── styles/             # CSS stylesheets
├── dist/                   # Built files (generated)
├── assets/                 # Static assets
├── public/                 # Public files
└── docs/                   # Documentation
```

### Contributing to Core

Want to improve security? Contribute to the cryptographic core:
- **Repository:** [securebit-core](https://github.com/SecureBitChat/securebit-core)
- **Focus:** Cryptography, protocol implementation, security features
- **Language:** Rust


## Related Projects

### Official SecureBit Ecosystem

| Project | Description | Status | License |
|---------|-------------|--------|---------|
| **[securebit-core](https://github.com/SecureBitChat/securebit-core)** | Cryptographic kernel (Rust) | ✅ Production | Apache 2.0 |
| **[securebit-chat](https://github.com/SecureBitChat/securebit-chat)** | Web application (this repo) | ✅ Production v4.7.55 | MIT |
| **[securebit-desktop](https://github.com/SecureBitChat/securebit-desktop)** | Desktop apps (Windows/Mac/Linux) | ✅ Beta v0.1.0 | Proprietary* |
| **securebit-mobile** | Mobile apps (iOS/Android) | 🔄 Coming Q1 2026 | TBD |

*\* Desktop apps are free for personal and commercial use. Only the UI layer is proprietary - all cryptography is open source in securebit-core.*

### Technology Stack

- **Frontend:** React, Tailwind CSS
- **Build:** esbuild, Tailwind CLI
- **P2P:** WebRTC
- **Crypto Core:** Rust (securebit-core)
- **Desktop:** Tauri v2
- **Mobile (Future):** Swift/SwiftUI (iOS), Kotlin/Jetpack Compose (Android)

---

## Contributing

We welcome contributions! Here's how:

### Contributing to Web Version (This Repo)

1. **Fork** the repository
2. **Create** feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** changes: `git commit -m "Add amazing feature"`
4. **Push** to branch: `git push origin feature/amazing-feature`
5. **Open** Pull Request

### Contributing to Cryptographic Core

Want to improve security? Contribute to the core:
- **Repository:** [securebit-core](https://github.com/SecureBitChat/securebit-core)
- **Focus:** Cryptography, protocol implementation, security features
- **Language:** Rust

### Contributing to Desktop Apps

- **Repository:** [securebit-desktop](https://github.com/SecureBitChat/securebit-desktop)
- **Focus:** UI/UX improvements, platform-specific features
- **Technology:** Tauri v2, Rust, TypeScript

### Other Ways to Help

- **Report bugs** - Open issues on GitHub
- **Security research** - Email SecureBitChat@proton.me
- **Improve documentation** - Help others understand the project
- **Star the repositories** - Support visibility and development
- **Spread the word** - Share with privacy advocates
- **Provide feedback** - Help shape the future of SecureBit

**If you support our mission - please star the repos!**
- [⭐ Star securebit-chat (Web)](https://github.com/SecureBitChat/securebit-chat)
- [⭐ Star securebit-core (Crypto)](https://github.com/SecureBitChat/securebit-core)
- [⭐ Star securebit-desktop (Apps)](https://github.com/SecureBitChat/securebit-desktop)

---

## 📄 License

### This Repository (Web Version)
**License:** MIT License

### Cryptographic Core
**License:** Apache License 2.0  
**Repository:** [securebit-core](https://github.com/SecureBitChat/securebit-core)

### Desktop Applications
**License:** Proprietary (Free for personal & commercial use)  
**Repository:** [securebit-desktop](https://github.com/SecureBitChat/securebit-desktop)

*Note: Desktop apps are free to use. Only the UI layer is proprietary - all cryptography is open source.*

---

## Community & Support

### Get Help
- **Documentation:** Check README and [core docs](https://github.com/SecureBitChat/securebit-core)**
- **Discussions:** [GitHub Discussions](https://github.com/SecureBitChat/securebit-chat/discussions)
- **Issues:** [Report bugs on GitHub](https://github.com/SecureBitChat/securebit-chat/issues)
- **Email:** SecureBitChat@proton.me

### Contact
- **Security Issues:** SecureBitChat@proton.me (encrypted preferred)
- **Business Inquiries:** hello@securebit.chat
- **Twitter/X:** [@SecureBitChat](https://twitter.com/SecureBitChat)
- **Website:** https://securebit.chat (coming soon)

### Community Guidelines

- Be respectful and constructive
- Focus on privacy and security
- Help others learn and contribute
- Report security issues responsibly
- Follow the code of conduct

---

## Acknowledgments

### Built With
- **React** - UI framework
- **Tailwind CSS** - Styling
- **esbuild** - Build tool
- **WebRTC** - P2P communication
- **IndexedDB** - Local storage
- **Rust** - Cryptographic core
- **Tauri v2** - Desktop framework

### Special Thanks
- **Rust Crypto Team** - Cryptographic primitives and standards
- **WebRTC Community** - P2P technology and standards
- **Tauri Team** - Desktop framework development
- **Security Researchers** - Audits, feedback, and improvements
- **Contributors** - Code, docs, testing, and support
- **Privacy Advocates** - Inspiration and mission support

### Standards & Specifications
- **RFC 5869** - HKDF key derivation
- **NIST SP 800-56A** - ECDH key agreement
- **RFC 8446** - DTLS 1.3
- **RFC 7748** - Elliptic curves for security
- **X.509** - ASN.1 certificate structure

---

## Project Status

### Active Development
- **Web Version** - Stable (v4.7.55), receiving bug fixes and improvements
- **Desktop Apps** - Public beta (v0.1.0), active development
- **Cryptographic Core** - Stable, production-ready
- **Mobile Apps** - In development (Q1 2026)

### Community
- **GitHub Stars** - [Help us grow!](https://github.com/SecureBitChat/securebit-chat)
- **Contributors** - [See all contributors](https://github.com/SecureBitChat/securebit-chat/graphs/contributors)
- **Issues** - [Open issues](https://github.com/SecureBitChat/securebit-chat/issues)
- **Pull Requests** - [Contribute](https://github.com/SecureBitChat/securebit-chat/pulls)
- **Discussions** - [Join the conversation](https://github.com/SecureBitChat/securebit-chat/discussions)

### Metrics
- **Downloads** - Desktop apps available for all platforms
- **Security** - 18-layer military-grade protection
- **Platforms** - Web, Windows, macOS, Linux (Mobile coming Q1 2026)
- **License** - Open source core, free desktop apps

---

<div align="center">

**SecureBit.chat Security Team**

*Committed to protecting your privacy with military-grade security*

---

**Latest Release: v4.7.55** - Desktop Edition Available  
**Desktop Apps: v0.1.0** - Public Beta Available  
**Mobile Apps: Coming Q1 2026**

[🚀 Try Web Version](https://securebit.chat/) • [🖥️ Download Desktop Apps](https://github.com/SecureBitChat/securebit-desktop) • [⭐ Star on GitHub](https://github.com/SecureBitChat/securebit-chat)

---

**Made with 🔒 for privacy advocates worldwide**

Copyright © 2025-2026 SecureBit Team. All rights reserved.

</div>
