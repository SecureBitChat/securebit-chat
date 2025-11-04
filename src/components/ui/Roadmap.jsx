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
                                          version: "v4.5.22",
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
                        case 'current':
                        return {
                            color: 'green',
                            bgClass: 'bg-green-500/10 border-green-500/20',
                            textClass: 'text-green-400',
                            icon: 'fas fa-check-circle',
                            label: 'Current Version'
                        };
                        case 'development':
                        return {
                            color: 'orange',
                            bgClass: 'bg-orange-500/10 border-orange-500/20',
                            textClass: 'text-orange-400',
                            icon: 'fas fa-code',
                            label: 'In Development'
                        };
                        case 'planned':
                        return {
                            color: 'blue',
                            bgClass: 'bg-blue-500/10 border-blue-500/20',
                            textClass: 'text-blue-400',
                            icon: 'fas fa-calendar-alt',
                            label: 'Planned'
                        };
                        case 'research':
                        return {
                            color: 'purple',
                            bgClass: 'bg-purple-500/10 border-purple-500/20',
                            textClass: 'text-purple-400',
                            icon: 'fas fa-flask',
                            label: 'Research'
                        };
                        case 'done':
                        return {
                            color: 'gray',
                            bgClass: 'bg-gray-500/10 border-gray-500/20',
                            textClass: 'text-gray-300',
                            icon: 'fas fa-flag-checkered',
                            label: 'Released'
                        };
                        default:
                        return {
                            color: 'gray',
                            bgClass: 'bg-gray-500/10 border-gray-500/20',
                            textClass: 'text-gray-400',
                            icon: 'fas fa-question',
                            label: 'Unknown'
                        };
                    }
                    };
        
                
                  const togglePhaseDetail = (index) => {
                    setSelectedPhase(selectedPhase === index ? null : index);
                  };
                return (
                    <div key="roadmap-section" className="mt-16 px-4 sm:px-0">
                      <div key="section-header" className="text-center mb-12">
                        <h3 key="title" className="text-2xl font-semibold text-primary mb-3">
                          Development Roadmap
                        </h3>
                        <p key="subtitle" className="text-secondary max-w-2xl mx-auto mb-6">
                          Evolution of SecureBit.chat : from initial development to quantum-resistant decentralized network with complete ASN.1 validation
                        </p>
                      </div>
                
                      <div key="roadmap-container" className="max-w-6xl mx-auto">
                        <div key="timeline" className="relative">
                          {/* The line has been removed */}
                
                          <div key="phases" className="space-y-8">
                            {phases.map((phase, index) => {
                              const statusConfig = getStatusConfig(phase.status);
                              const isExpanded = selectedPhase === index;
                
                              return (
                                <div key={`phase-${index}`} className="relative">
                                  {/* The dots are visible only on sm and larger screens */}
                
                                  <button
                                    type="button"
                                    aria-expanded={isExpanded}
                                    onClick={() => togglePhaseDetail(index)}
                                    key={`phase-button-${index}`}
                                    className={`card-minimal rounded-xl p-4 text-left w-full transition-all duration-300 ${
                                      isExpanded
                                        ? "ring-2 ring-" + statusConfig.color + "-500/30"
                                        : ""
                                    }`}
                                  >
                                    <div
                                      key="phase-header"
                                      className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-4 space-y-2 sm:space-y-0"
                                    >
                                      <div
                                        key="phase-info"
                                        className="flex flex-col sm:flex-row sm:items-center sm:space-x-4"
                                      >
                                        <div
                                          key="version-badge"
                                          className={`px-3 py-1 ${statusConfig.bgClass} border rounded-lg mb-2 sm:mb-0`}
                                        >
                                          <span
                                            key="version"
                                            className={`${statusConfig.textClass} font-bold text-sm`}
                                          >
                                            {phase.version}
                                          </span>
                                        </div>
                
                                        <div key="title-section">
                                          <h4
                                            key="title"
                                            className="text-lg font-semibold text-primary"
                                          >
                                            {phase.title}
                                          </h4>
                                          <p
                                            key="description"
                                            className="text-secondary text-sm"
                                          >
                                            {phase.description}
                                          </p>
                                        </div>
                                      </div>
                
                                      <div
                                        key="phase-meta"
                                        className="flex items-center space-x-3 text-sm text-gray-400 font-medium"
                                      >
                                        <div
                                          key="status-badge"
                                          className={`flex items-center px-3 py-1 ${statusConfig.bgClass} border rounded-lg`}
                                        >
                                          <i
                                            key="status-icon"
                                            className={`${statusConfig.icon} ${statusConfig.textClass} mr-2 text-xs`}
                                          />
                                          <span
                                            key="status-text"
                                            className={`${statusConfig.textClass} text-xs font-medium`}
                                          >
                                            {statusConfig.label}
                                          </span>
                                        </div>
                
                                        <div key="date">{phase.date}</div>
                                        <i
                                          key="expand-icon"
                                          className={`fas fa-chevron-${
                                            isExpanded ? "up" : "down"
                                          } text-gray-400 text-sm`}
                                        />
                                      </div>
                                    </div>
                
                                    {isExpanded && (
                                      <div
                                        key="features-section"
                                        className="mt-6 pt-6 border-t border-gray-700/30"
                                      >
                                        <h5
                                          key="features-title"
                                          className="text-primary font-medium mb-4 flex items-center"
                                        >
                                          <i
                                            key="features-icon"
                                            className="fas fa-list-ul mr-2 text-sm"
                                          />
                                          Key features:
                                        </h5>
                
                                        <div
                                          key="features-grid"
                                          className="grid md:grid-cols-2 gap-3"
                                        >
                                          {phase.features.map((feature, featureIndex) => (
                                            <div
                                              key={`feature-${featureIndex}`}
                                              className="flex items-center space-x-3 p-3 bg-custom-bg rounded-lg"
                                            >
                                              <div
                                                className={`w-2 h-2 rounded-full ${statusConfig.textClass.replace(
                                                  "text-",
                                                  "bg-"
                                                )}`}
                                              />
                                              <span className="text-secondary text-sm">
                                                {feature}
                                              </span>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                  </button>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                
                      <div key="cta-section" className="mt-12 text-center">
                        <div
                          key="cta-card"
                          className="card-minimal rounded-xl p-8 max-w-2xl mx-auto"
                        >
                          <h4
                            key="cta-title"
                            className="text-xl font-semibold text-primary mb-3"
                          >
                            Join the future of privacy
                          </h4>
                          <p key="cta-description" className="text-secondary mb-6">
                            SecureBit.chat grows thanks to the community. Your ideas and feedback help shape the future of secure communication with complete ASN.1 validation.
                          </p>
                
                          <div
                            key="cta-buttons"
                            className="flex flex-col sm:flex-row gap-4 justify-center"
                          >
                            <a
                              key="github-link"
                              href="https://github.com/SecureBitChat/securebit-chat/"
                              className="btn-primary text-white py-3 px-6 rounded-lg font-medium transition-all duration-200 flex items-center justify-center"
                            >
                              <i key="github-icon" className="fab fa-github mr-2" />
                              GitHub Repository
                            </a>
                
                            <a
                              key="feedback-link"
                              href="mailto:lockbitchat@tutanota.com"
                              className="btn-secondary text-white py-3 px-6 rounded-lg font-medium transition-all duration-200 flex items-center justify-center"
                            >
                              <i key="feedback-icon" className="fas fa-comments mr-2" />
                              Feedback
                            </a>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                };
    window.Roadmap = Roadmap;