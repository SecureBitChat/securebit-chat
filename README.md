# SecureBit.chat - Enhanced Security Edition

<div align="center">

![SecureBit.chat Logo](logo/favicon.ico)

**The world's first P2P messenger with Lightning Network payments and military-grade cryptography**

[![Latest Release](https://img.shields.io/github/v/release/SecureBitChat/securebit-chat?style=for-the-badge&logo=github&color=orange)](https://github.com/SecureBitChat/securebit-chat/releases/latest)
[![Live Demo](https://img.shields.io/badge/🌐_Live_Demo-Try_Now-success?style=for-the-badge)](https://securebitchat.github.io/securebit-chat/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Security: Military-Grade](https://img.shields.io/badge/Security-Military_Grade-red.svg?style=for-the-badge)]()

</div>

---

## ✨ What's New in v4.01.413

### 🔒 Comprehensive Connection Security Overhaul
* **Advanced mutex framework** with 15-second timeout protection
* **Race condition prevention** through atomic key generation
* **Multi-stage validation pipeline** with automatic rollback
* **Enhanced MITM protection** with unique encryption key fingerprints
* **Session ID anti-hijacking** with mutual authentication challenges
* **Package integrity validation** for all connection operations

### 🔐 Secure Key Storage System
* **WeakMap-based isolation** for all cryptographic keys
* **Private key storage** replacing public key properties
* **Secure access methods** with validation and rotation
* **Emergency key wipe** capabilities for threat response
* **Key security monitoring** with lifetime limits enforcement
* **Backward compatibility** maintained through getters/setters

### 🛡️ Production-Ready Security Logging
* **Environment-aware logging** (production vs development)
* **Data sanitization** preventing sensitive information leaks
* **Rate limiting** and automatic memory cleanup
* **Secure debugging** without exposing encryption keys
* **Privacy protection** while maintaining useful diagnostics

### 📱 Progressive Web App (PWA)
* **Install directly** on mobile and desktop devices
* **Offline mode support** with session persistence
* **Improved performance** through smart caching and service workers
* **Native app experience** without app store requirements

### 📂 Secure File Transfer
* **End-to-end encrypted** file transfers over pure P2P WebRTC channels
* **File chunking** with individual encryption per block
* **Hash validation** for every chunk to prevent tampering or MITM attacks
* **Automatic recovery** for lost packets and interrupted transfers
* **AES-GCM 256-bit + ECDH P-384** encryption for files
* **SHA-384 checksums** for integrity enforcement

### 🔍 Enhanced Security Testing
* **Comprehensive data leakage testing** of chat sessions
* **Verified MITM and replay attack resistance**
* **Enhanced memory cleanup algorithms** for session termination
* **Isolated file streams** separated from chat channels

---

## 🚀 Try It Now

### 🌐 [Live Demo — SecureBit.chat](https://securebitchat.github.io/securebit-chat/)

*No installation required — works directly in your browser with military-grade encryption.*

**New:** Install as PWA for native app experience on mobile and desktop!

---

## ✨ What Makes SecureBit.chat Unique

### 🏆 Industry Leader

* **Dominates in 11/15 security categories** vs Signal, Threema, Session
* **First messenger** with Lightning Network integration
* **Military-grade cryptography** exceeding government standards
* **Zero servers** — truly decentralized P2P architecture
* **PWA technology** — install like native apps without app stores

### ⚡ Lightning Network Pioneer

* **Instant satoshi payments** for secure sessions
* **Pay-per-session model** — no ads, no data harvesting
* **WebLN integration** with all major Lightning wallets
* **Sustainable economics** for private communication

### 🔐 12-Layer Military Security

1. **WebRTC DTLS** — Transport encryption
2. **ECDH P-384** — Perfect forward secrecy
3. **AES-GCM 256** — Authenticated encryption
4. **ECDSA P-384** — Message integrity
5. **Replay protection** — Timestamp validation
6. **Key rotation** — Every 5 minutes/100 messages
7. **MITM verification** — Out-of-band codes
8. **Traffic obfuscation** — Pattern masking
9. **Metadata protection** — Zero leakage
10. **Memory protection** — No persistent storage
11. **Hardware security** — Non-extractable keys
12. **Session isolation** — Complete cleanup
13. **Mutex framework** — Race condition protection
14. **Secure key storage** — WeakMap isolation
15. **Production logging** — Data sanitization

### 🎭 Advanced Privacy

* **Complete anonymity** — no registration required
* **Zero data collection** — messages only in browser memory
* **Traffic analysis resistance** — fake traffic generation
* **Censorship resistance** — no servers to block
* **Instant anonymous channels** — connect in seconds
* **Secure file transfers** — encrypted P2P file sharing

---

## 🛡️ Security Comparison

| Feature                     | **SecureBit.chat**            | Signal                       | Threema               | Session                |
| --------------------------- | ----------------------------- | ---------------------------- | --------------------- | ---------------------- |
| **Architecture**            | 🏆 Pure P2P WebRTC            | ❌ Centralized servers        | ❌ Centralized servers | ⚠️ Onion network       |
| **Payment Integration**     | 🏆 Lightning Network          | ❌ None                       | ❌ None                | ❌ None                 |
| **File Transfer**           | 🏆 P2P encrypted + chunked    | ✅ Encrypted via servers     | ✅ Encrypted via servers | ✅ Encrypted via servers |
| **PWA Support**             | 🏆 Full PWA installation      | ❌ None                       | ❌ None                | ❌ None                 |
| **Registration**            | 🏆 Anonymous                  | ❌ Phone required             | ✅ ID generated        | ✅ Random ID            |
| **Traffic Obfuscation**     | 🏆 Advanced fake traffic      | ❌ None                       | ❌ None                | ✅ Onion routing        |
| **Censorship Resistance**   | 🏆 Hard to block              | ⚠️ Blocked in some countries | ⚠️ May be blocked     | ✅ Onion routing        |
| **Data Storage**            | 🏆 Zero storage               | ⚠️ Local database            | ⚠️ Local + backup     | ⚠️ Local database      |
| **Economic Model**          | 🏆 Pay‑per‑session            | ⚠️ Donations dependent       | ✅ One‑time purchase   | ⚠️ Donations dependent |
| **Metadata Protection**     | 🏆 Full encryption            | ⚠️ Sealed Sender (partial)   | ⚠️ Minimal metadata   | ✅ Onion routing        |
| **Key Security**            | 🏆 Non‑extractable + hardware | ✅ Secure storage             | ✅ Local storage       | ✅ Secure storage       |
| **Perfect Forward Secrecy** | 🏆 Auto rotation (5 min)      | ✅ Double Ratchet             | ⚠️ Partial (groups)   | ✅ Session Ratchet      |
| **Open Source**             | 🏆 100% + auditable           | ✅ Fully open                 | ⚠️ Only clients       | ✅ Fully open           |

**Legend:** 🏆 Category Leader | ✅ Excellent | ⚠️ Partial/Limited | ❌ Not Available

---

## 🚀 Quick Start

### Option 1: Use Online (Recommended)

1. **Visit:** [https://securebitchat.github.io/securebit-chat/](https://securebitchat.github.io/securebit-chat/)
2. **Install PWA:** Click "Install" button for native app experience
3. **Choose:** *Create Channel* or *Join Channel*
4. **Complete:** Secure key exchange with verification
5. **Select:** Session type (Demo / Basic / Premium)
6. **Communicate:** With military‑grade encryption + secure file transfers

### Option 2: Self‑Host

```bash
# Clone repository
git clone https://github.com/SecureBitChat/securebit-chat.git
cd securebit-chat

# Serve locally (choose one method)
python -m http.server 8000        # Python
npx serve .                       # Node.js
php -S localhost:8000             # PHP

# Open browser
open http://localhost:8000
```

---

## 📂 Secure File Transfer

### Features

* **P2P Direct Transfer** — No servers involved, direct WebRTC channels
* **Military-Grade Encryption** — AES-GCM 256-bit + ECDH P-384
* **Chunk-Level Security** — Each file chunk individually encrypted
* **Hash Validation** — SHA-384 checksums prevent tampering
* **Automatic Recovery** — Retry mechanisms for interrupted transfers
* **Stream Isolation** — Separate channels from chat messages

### Supported File Types

* **Documents:** PDF, DOC, TXT, MD
* **Images:** JPG, PNG, GIF, WEBP
* **Archives:** ZIP, RAR, 7Z
* **Media:** MP3, MP4, AVI (size limits apply)
* **General:** Any file type up to size limits

### Security Guarantees

* End-to-end encryption with perfect forward secrecy
* MITM attack prevention through hash validation
* Zero server storage — files transfer directly P2P
* Complete cleanup after transfer completion

---

## ⚡ Lightning Network Integration

### Session Types

* **🎮 Demo:** 6 minutes free (testing)
* **⚡ Basic:** 1 hour for 50 satoshis
* **💎 Premium:** 6 hours for 200 satoshis

### Supported Wallets

| Wallet            | WebLN | Mobile | Desktop |
| ----------------- | :---: | :----: | :-----: |
| Alby              |   ✅   |    ✅   |    ✅    |
| Zeus              |   ✅   |    ✅   |    ✅    |
| Wallet of Satoshi |   ✅   |    ✅   |    ❌    |
| Muun              |   ⚠️  |    ✅   |    ❌    |
| Breez             |   ✅   |    ✅   |    ❌    |
| Strike            |   ✅   |    ✅   |    ✅    |

*And many more WebLN‑compatible wallets.*

---

## 🔧 Technical Architecture

### Cryptographic Stack

```
📂 File Transfer Layer:  AES-GCM 256-bit + SHA-384 + Chunking
🔐 Application Layer:    AES-GCM 256-bit + ECDSA P-384
🔑 Key Exchange:         ECDH P-384 (Perfect Forward Secrecy)
🛡️ Transport Layer:      WebRTC DTLS 1.2
🌐 Network Layer:        P2P WebRTC Data Channels
⚡ Payment Layer:        Lightning Network + WebLN
📱 PWA Layer:            Service Workers + Cache API
```

### Security Standards

* NIST SP 800‑56A — ECDH Key Agreement
* NIST SP 800‑186 — Elliptic Curve Cryptography
* RFC 6090 — Fundamental ECC Algorithms
* RFC 8446 — TLS 1.3 for WebRTC
* RFC 3874 — SHA-384 Hash Algorithm

### Browser Requirements

* Modern browser with WebRTC support (Chrome 60+, Firefox 60+, Safari 12+)
* HTTPS connection (required for WebRTC and PWA)
* JavaScript enabled
* Lightning wallet with WebLN (for payments)
* Service Worker support for PWA features

---

## 🗺️ Development Roadmap

**Current:** v4.01.413 — PWA & File Transfer Edition ✅

* Progressive Web App installation
* Secure P2P file transfer system
* Enhanced security testing and MITM protection
* Improved memory cleanup algorithms

**Next Releases**

### v4.5 (Q2 2025) — Mobile & Desktop Apps

* Native mobile applications (iOS/Android)
* Electron desktop application
* Push notifications
* Cross‑device synchronization
* Enhanced PWA features

### v5.0 (Q4 2025) — Quantum‑Resistant Edition

* CRYSTALS‑Kyber post‑quantum key exchange
* SPHINCS+ post‑quantum signatures
* Hybrid classical + post‑quantum schemes
* Quantum‑safe migration path

### v5.5 (Q2 2026) — Group Communications

* P2P group chats (up to 8 participants)
* Mesh networking topology
* Group Lightning payments
* Anonymous group administration
* Group file sharing

### v6.0 (2027) — Decentralized Network

* DHT‑based peer discovery
* Built‑in onion routing
* Decentralized identity system
* Node incentive mechanisms

---

## 🧪 Development

### Project Structure

```
securebit-chat/
├── index.html                 # Main application
├── manifest.json              # PWA manifest  
├── sw.js                      # Service worker
├── browserconfig.xml          # Browser configuration for PWA
├── src/
│   ├── components/ui/         # React UI components
│   │   ├── DownloadApps.js    # PWA download/install component
│   │   ├── FileTransfer.js    # File transfer UI component
│   │   └── ...                # Other UI components
│   ├── crypto/                # Cryptographic utilities
│   ├── network/               # WebRTC P2P manager
│   ├── session/               # Payment session manager
│   ├── transfer/              # File transfer system
│   │   └── EnhancedSecureFileTransfer.js  # Secure P2P file transfer
│   ├── pwa/                   # PWA management
│   │   ├── install-prompt.js  # PWA installation prompts
│   │   ├── offline-manager.js # Offline mode management
│   │   └── pwa-manager.js     # PWA lifecycle management
│   └── styles/                # CSS styling
│       ├── pwa.css           # PWA-specific styles
│       └── ...               # Other stylesheets
├── logo/                      # Wallet logos and icons
├── docs/                      # Documentation
└── README.md                  # This file
```

### Technology Stack

* **Frontend:** Pure JavaScript + React (via CDN)
* **PWA:** Service Workers + Cache API + Web App Manifest + Install Prompts
* **Cryptography:** Web Crypto API + custom ECDH/ECDSA
* **Network:** WebRTC P2P Data Channels
* **File Transfer:** Enhanced secure P2P streaming with chunked encryption
* **Payments:** Lightning Network via WebLN
* **Offline Support:** Smart caching with offline-manager
* **Styling:** TailwindCSS + custom CSS + PWA-specific styles

### Development Setup

```bash
# Clone repository
git clone https://github.com/SecureBitChat/securebit-chat.git
cd securebit-chat

# No build process required — pure client‑side
# Just serve the files over HTTPS

# For development
python -m http.server 8000

# For production
# Deploy to any static hosting (GitHub Pages, Netlify, etc.)
```

---

## 🛡️ Security

### Security Audit Status

* ✅ Internal cryptographic review completed
* ✅ P2P protocol security analysis completed
* ✅ File transfer security validation completed
* ✅ MITM and replay attack resistance verified
* 🔄 Professional security audit planned Q3 2025
* 🔄 Post‑quantum cryptography review for v5.0

### Vulnerability Reporting

See **SECURITY.md** for detailed security policy and reporting instructions.
Contact: **[SecureBitChat@proton.me](mailto:SecureBitChat@proton.me)**

### Security Features

* Perfect Forward Secrecy — Past messages and files secure even if keys compromised
* Out‑of‑band verification — Prevents man‑in‑the‑middle attacks
* Traffic obfuscation — Defeats network analysis
* Memory protection — No persistent storage of sensitive data
* Session isolation — Complete cleanup between sessions
* File integrity — SHA-384 hash validation prevents tampering
* Chunked encryption — Individual encryption per file block

---

## 📊 Performance

### Benchmarks

* Connection setup: < 3 seconds
* Message latency: < 100 ms (P2P direct)
* File transfer speed: Up to 5 MB/s per connection
* Throughput: Up to 1 MB/s per connection
* Memory usage: < 50 MB for active session
* Battery impact: Minimal (optimized WebRTC)
* PWA install size: < 2 MB

### Scalability

* Concurrent connections: Limited by device capabilities
* Message size: Up to 2000 characters
* File size: Up to 100 MB per file
* File types: All formats supported
* Group size: Up to 8 participants (v5.5)

---

## 📄 License

MIT License — see **LICENSE** file for details.

### Open Source Commitment

* 100% open source — full transparency
* MIT license — maximum freedom
* No telemetry — zero data collection
* Community‑driven — contributions welcome

---

## 🤝 Contributing

We welcome contributions from the community!

### How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m "Add amazing feature"`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Contribution Areas

* 🔐 Cryptography — Security improvements and audits
* 🌐 Network — P2P optimization and reliability
* ⚡ Lightning — Payment integration enhancements
* 📂 File Transfer — EnhancedSecureFileTransfer improvements
* 📱 PWA — Install prompts, offline management, and PWA lifecycle
* 🎨 UI/UX — Interface improvements, FileTransfer and DownloadApps components
* 📚 Documentation — Guides, tutorials, translations

### Development Guidelines

* Follow existing code style
* Add tests for new features
* Update documentation
* Respect security‑first principles
* Test PWA functionality across devices

---

## 📞 Contact & Support

### Official Channels

* Email: **[SecureBitChat@proton.me](mailto:SecureBitChat@proton.me)**
* GitHub: **Issues & Discussions**
* Security: **[SecureBitChat@proton.me](mailto:SecureBitChat@proton.me)**

### Community

* Discussions: GitHub Discussions for feature requests
* Issues: Bug reports and technical support
* Wiki: Documentation and guides

---

## ⚠️ Important Disclaimers

### Security Notice
While SecureBit.chat implements military-grade cryptography and follows security best practices, no communication system is 100% secure. Users should:

* Always verify security codes out-of-band
* Keep devices and browsers updated
* Be aware of endpoint security risks
* Use reputable Lightning wallets
* **File transfers are protected with the same military-grade cryptography as chat messages**

### Legal Notice
This software is provided "as is" for educational and research purposes. Users are responsible for compliance with local laws and regulations regarding:

* Cryptographic software usage
* Private communications
* Bitcoin/Lightning Network transactions
* File sharing and transfer

### Privacy Statement
SecureBit.chat:

* Collects zero data - no analytics, tracking, or telemetry
* Stores nothing - all data exists only in browser memory
* Requires no registration - completely anonymous usage
* Uses no servers - direct P2P connections only
* **Files are transferred directly P2P with zero server storage**

---

## 🎯 Why Choose SecureBit.chat?

### For Privacy Advocates

* True zero-knowledge architecture
* Military-grade encryption standards
* Complete anonymity and untraceability
* Resistance to censorship and surveillance
* **Secure P2P file sharing without servers**

### For Bitcoin/Lightning Users

* Native Lightning Network integration
* Sustainable pay-per-session model
* Support for all major Lightning wallets
* No KYC or account requirements

### For Mobile Users

* **Progressive Web App installation**
* **Offline mode support**
* **Native app experience without app stores**
* **Works on all modern mobile devices**

### For Developers

* 100% open source transparency
* Modern cryptographic standards
* Clean, auditable codebase
* Extensible modular architecture
* **PWA best practices implementation**

### For Everyone

* **Install like native apps**
* **Works offline with session persistence**
* Works on all modern devices
* Intuitive user interface
* Professional security standards
* **Secure file transfers included**

---

<div align="center">

**SecureBit.chat Security Team**

*Committed to protecting your privacy with military-grade security*

**Report vulnerabilities:** SecureBitChat@proton.me

---

**Latest Release: v4.01.413** — PWA & Secure File Transfer

</div>
