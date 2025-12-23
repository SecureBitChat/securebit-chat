# SecureBit.chat v4.5.22

<div align="center">

![SecureBit.chat Logo](logo/favicon.ico)

**World's first P2P messenger with ECDH + DTLS + SAS security and military-grade cryptography**

[![Latest Release](https://img.shields.io/github/v/release/SecureBitChat/securebit-chat?style=for-the-badge&logo=github&color=orange)](https://github.com/SecureBitChat/securebit-chat/releases/latest)
[![Live Demo](https://img.shields.io/badge/🌐_Live_Demo-Try_Now-success?style=for-the-badge)](https://securebitchat.github.io/securebit-chat/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

[🚀 Try Now](https://securebitchat.github.io/securebit-chat/) • [📖 Documentation](#-quick-start) • [🔒 Security](#-security) • [🤝 Contribute](#-contributing)

</div>

---
## 🔐 Shared Security Core

SecureBitChat uses a shared Rust-based cryptographic core:  
https://github.com/SecureBitChat/securebit-core

This core is used across all platforms (web, desktop, mobile) as a single source of truth for all security-critical logic.

Community review is welcome. Bug reports and security feedback can be submitted via GitHub Issues.

## 🚧 Project Update: Transition to Desktop & Mobile Versions

The **web version of SecureBit.chat** will remain available and stable,  
but **no major updates** are planned in the near future.

We are now focusing on developing **next-generation desktop and mobile applications** powered by **Tauri v2**,  
bringing new features that will be **fully backward-compatible** with the current web version:

- **Offline communication** via LoRa & mesh networking  
- **Improved encryption performance** with native crypto modules  
- **Cross-platform synchronization** between devices  
- **Local secure storage & hardware key integration**

These new builds will enable true **serverless communication** even under restricted or offline conditions.

If you appreciate our mission to build **decentralized, censorship-resistant communication**,  
please **support the project by starring it on GitHub** — your support helps development and visibility!

👉 [⭐ Star SecureBit.chat on GitHub](https://github.com/SecureBitChat/securebit-chat)

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

## ✨ What's New in v4.5.22

### fix: prevent encryption key loss and IndexedDB connection errors

- Disable timer-based key rotation for Double Ratchet mode
- Auto-reinitialize encryption keys when missing but ECDH available
- Preserve active keys during periodic cleanup in ratchet sessions
- Fix IndexedDB "database closing" errors with connection checking
- Add individual transactions per queue item to prevent race conditions

### 🛡️ Security Enhancements
- **ECDH + DTLS + SAS System** - Triple-layer security verification
- **ASN.1 Full Structure Validation** - Complete key structure verification
- **Enhanced MITM Protection** - Multi-layer defense system
- **Secure Key Storage** - WeakMap-based isolation
- **Production-Ready Logging** - Data sanitization and privacy protection
- **HKDF Key Derivation** - RFC 5869 compliant key separation and derivation

---

## 🗺️ Roadmap

**Current: v4.5.22** - Browser Notifications & Code Cleanup ✅

**Next Releases:**

- **v4.5 (Q2 2025)** - Mobile & Desktop Apps  
  - Native mobile applications (iOS/Android)  
  - **Tauri v2 desktop clients (Windows/macOS/Linux)**  
  - Push notifications and cross-device sync  

- **v5.0 (Q4 2025)** - Quantum-Resistant Edition  
  - CRYSTALS-Kyber post-quantum key exchange  
  - SPHINCS+ post-quantum signatures  
  - Hybrid classical + post-quantum schemes  

---

## 🤝 Contributing

We welcome contributions! Here's how:

1. Fork the repository  
2. Create feature branch: `git checkout -b feature/amazing-feature`  
3. Commit changes: `git commit -m "Add amazing feature"`  
4. Push to branch: `git push origin feature/amazing-feature`  
5. Open Pull Request  

If you support the mission — **please star the repo!**  
[⭐ Star SecureBit.chat on GitHub](https://github.com/SecureBitChat/securebit-chat)

---

<div align="center">

**SecureBit.chat Security Team**

*Committed to protecting your privacy with military-grade security*

**Report vulnerabilities:** SecureBitChat@proton.me

---

**Latest Release: v4.5.22** - Browser Notifications & Code Cleanup

[🚀 Try Now](https://securebitchat.github.io/securebit-chat/) • [⭐ Star on GitHub](https://github.com/SecureBitChat/securebit-chat)

</div>
