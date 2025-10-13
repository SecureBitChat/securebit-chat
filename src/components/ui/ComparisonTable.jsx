
        
        
                const ComparisonTable = () => {
                const [selectedFeature, setSelectedFeature] = React.useState(null);

                const messengers = [
                    {
                    name: "SecureBit.chat",
                    logo: <div className="w-8 h-8 bg-orange-500/10 border border-orange-500/20 rounded-lg flex items-center justify-center">
                            <i className="fas fa-shield-halved text-orange-400" />
                            </div>,
                    type: "P2P WebRTC",
                    version: "Latest",
                    color: "orange",
                    },
                    {
                    name: "Signal",
                    logo: (
                        <svg className="w-8 h-8" viewBox="0 0 122.88 122.31" xmlns="http://www.w3.org/2000/svg">
                        <path className="fill-blue-500" d="M27.75,0H95.13a27.83,27.83,0,0,1,27.75,27.75V94.57a27.83,27.83,0,0,1-27.75,27.74H27.75A27.83,27.83,0,0,1,0,94.57V27.75A27.83,27.83,0,0,1,27.75,0Z" />
                        <path className="fill-white" d="M61.44,25.39A35.76,35.76,0,0,0,31.18,80.18L27.74,94.86l14.67-3.44a35.77,35.77,0,1,0,19-66Z" />
                        </svg>
                    ),
                    type: "Centralized",
                    version: "Latest",
                    color: "blue",
                    },
                    {
                    name: "Threema",
                    logo: (
                        <svg className="w-8 h-8" viewBox="0 0 122.88 122.88" xmlns="http://www.w3.org/2000/svg">
                        <rect width="122.88" height="122.88" rx="18.43" fill="#474747" />
                        <path fill="#FFFFFF" d="M44.26,78.48l-19.44,4.8l4.08-16.56c-4.08-5.28-6.48-12-6.48-18.96c0-18.96,17.52-34.32,39.12-34.32c21.6,0,39.12,15.36,39.12,34.32c0,18.96-17.52,34.32-39.12,34.32c-6,0-12-1.2-17.04-3.36L44.26,78.48z M50.26,44.64h-0.48c-0.96,0-1.68,0.72-1.44,1.68v15.6c0,0.96,0.72,1.68,1.68,1.68l23.04,0c0.96,0,1.68-0.72,1.68-1.68v-15.6c0-0.96-0.72-1.68-1.68-1.68h-0.48v-4.32c0-6-5.04-11.04-11.04-11.04S50.5,34.32,50.5,40.32v4.32H50.26z M68.02,44.64h-13.2v-4.32c0-3.6,2.88-6.72,6.72-6.72c3.6,0,6.72,2.88,6.72,6.72v4.32H68.02z" />
                        <circle cx="37.44" cy="97.44" r="6.72" fill="#3fe669" />
                        <circle cx="61.44" cy="97.44" r="6.72" fill="#3fe669" />
                        <circle cx="85.44" cy="97.44" r="6.72" fill="#3fe669" />
                        </svg>
                    ),
                    type: "Centralized",
                    version: "Latest",
                    color: "green",
                    },
                    {
                    name: "Session",
                    logo: (
                        <svg className="w-8 h-8" viewBox="0 0 1024 1024" xmlns="http://www.w3.org/2000/svg">
                        <rect width="1024" height="1024" fill="#333132" />
                        <path fill="#00f782" d="M431 574.8c-.8-7.4-6.7-8.2-10.8-10.6-13.6-7.9-27.5-15.4-41.3-23l-22.5-12.3c-8.5-4.7-17.1-9.2-25.6-14.1-10.5-6-21-11.9-31.1-18.6-18.9-12.5-33.8-29.1-46.3-48.1-8.3-12.6-14.8-26.1-19.2-40.4-6.7-21.7-10.8-44.1-7.8-66.8 1.8-14 4.6-28 9.7-41.6 7.8-20.8 19.3-38.8 34.2-54.8 9.8-10.6 21.2-19.1 33.4-26.8 14.7-9.3 30.7-15.4 47.4-19 13.8-3 28.1-4.3 42.2-4.4 89.9-.4 179.7-.3 269.6 0 12.6 0 25.5 1 37.7 4.1 24.3 6.2 45.7 18.2 63 37 11.2 12.2 20.4 25.8 25.8 41.2 7.3 20.7 12.3 42.1 6.7 64.4-2.1 8.5-2.7 17.5-6.1 25.4-4.7 10.9-10.8 21.2-17.2 31.2-8.7 13.5-20.5 24.3-34.4 32.2-10.1 5.7-21 10.2-32 14.3-18.1 6.7-37.2 5-56.1 5.2-17.2.2-34.5 0-51.7.1-1.7 0-3.4 1.2-5.1 1.9 1.3 1.8 2.1 4.3 3.9 5.3 13.5 7.8 27.2 15.4 40.8 22.9 11 6 22.3 11.7 33.2 17.9 15.2 8.5 30.2 17.4 45.3 26.1 19.3 11.1 34.8 26.4 47.8 44.3 9.7 13.3 17.2 27.9 23 43.5 6.1 16.6 9.2 33.8 10.4 51.3.6 9.1-.7 18.5-1.9 27.6-1.2 9.1-2.7 18.4-5.6 27.1-3.3 10.2-7.4 20.2-12.4 29.6-8.4 15.7-19.6 29.4-32.8 41.4-12.7 11.5-26.8 20.6-42.4 27.6-22.9 10.3-46.9 14.4-71.6 14.5-89.7.3-179.4.2-269.1-.1-12.6 0-25.5-1-37.7-3.9-24.5-5.7-45.8-18-63.3-36.4-11.6-12.3-20.2-26.5-26.6-41.9-2.7-6.4-4.1-13.5-5.4-20.4-1.5-8.1-2.8-16.3-3.1-24.5-.6-15.7 2.8-30.9 8.2-45.4 8.2-22 21.7-40.6 40.2-55.2 10-7.9 21.3-13.7 33.1-18.8 16.6-7.2 34-8.1 51.4-8.5 21.9-.5 43.9-.1 65.9-.1 1.9-.1 3.9-.3 6.2-.4zm96.3-342.4c0 .1 0 .1 0 0-48.3.1-96.6-.6-144.9.5-13.5.3-27.4 3.9-40.1 8.7-14.9 5.6-28.1 14.6-39.9 25.8-20.2 19-32.2 42.2-37.2 68.9-3.6 19-1.4 38.1 4.1 56.5 4.1 13.7 10.5 26.4 18.5 38.4 14.8 22.2 35.7 36.7 58.4 49.2 11 6.1 22.2 11.9 33.2 18 13.5 7.5 26.9 15.1 40.4 22.6 13.1 7.3 26.2 14.5 39.2 21.7 9.7 5.3 19.4 10.7 29.1 16.1 2.9 1.6 4.1.2 4.5-2.4.3-2 .3-4 .3-6.1v-58.8c0-19.9.1-39.9 0-59.8 0-6.6 1.7-12.8 7.6-16.1 3.5-2 8.2-2.8 12.4-2.8 50.3-.2 100.7-.2 151-.1 19.8 0 38.3-4.4 55.1-15.1 23.1-14.8 36.3-36.3 40.6-62.9 3.4-20.8-1-40.9-12.4-58.5-17.8-27.5-43.6-43-76.5-43.6-47.8-.8-95.6-.2-143.4-.2zm-30.6 559.7c45.1 0 90.2-.2 135.3.1 18.9.1 36.6-3.9 53.9-11.1 18.4-7.7 33.6-19.8 46.3-34.9 9.1-10.8 16.2-22.9 20.8-36.5 4.2-12.4 7.4-24.7 7.3-37.9-.1-10.3.2-20.5-3.4-30.5-2.6-7.2-3.4-15.2-6.4-22.1-3.9-8.9-8.9-17.3-14-25.5-12.9-20.8-31.9-34.7-52.8-46.4-10.6-5.9-21.2-11.6-31.8-17.5-10.3-5.7-20.4-11.7-30.7-17.4-11.2-6.1-22.5-11.9-33.7-18-16.6-9.1-33.1-18.4-49.8-27.5-4.9-2.7-6.1-1.9-6.4 3.9-.1 2-.1 4.1-.1 6.1v114.5c0 14.8-5.6 20.4-20.4 20.4-47.6.1-95.3-.1-142.9.2-10.5.1-21.1 1.4-31.6 2.8-16.5 2.2-30.5 9.9-42.8 21-17 15.5-27 34.7-29.4 57.5-1.1 10.9-.4 21.7 2.9 32.5 3.7 12.3 9.2 23.4 17.5 33 19.2 22.1 43.4 33.3 72.7 33.3 46.6.1 93 0 139.5 0z" />
                        </svg>
                    ),
                    type: "Onion Network",
                    version: "Latest",
                    color: "cyan",
                    },
                ];

                const features = [
                    {
                    name: "Security Architecture",
                    lockbit: { status: "trophy", detail: "18-layer military-grade defense system with complete ASN.1 validation" },
                    signal: { status: "check", detail: "Signal Protocol with double ratchet" },
                    threema: { status: "check", detail: "Standard security implementation" },
                    session: { status: "check", detail: "Modified Signal Protocol + Onion routing" },
                    },
                    {
                    name: "Cryptography",
                    lockbit: { status: "trophy", detail: "ECDH P-384 + AES-GCM 256 + ECDSA P-384" },
                    signal: { status: "check", detail: "Signal Protocol + Double Ratchet" },
                    threema: { status: "check", detail: "NaCl + XSalsa20 + Poly1305" },
                    session: { status: "check", detail: "Modified Signal Protocol" },
                    },
                    {
                    name: "Perfect Forward Secrecy",
                    lockbit: { status: "trophy", detail: "Auto rotation every 5 minutes or 100 messages" },
                    signal: { status: "check", detail: "Double Ratchet algorithm" },
                    threema: { status: "warning", detail: "Partial (group chats)" },
                    session: { status: "check", detail: "Session Ratchet algorithm" },
                    },
                    {
                    name: "Architecture",
                    lockbit: { status: "trophy", detail: "Pure P2P WebRTC without servers" },
                    signal: { status: "times", detail: "Centralized Signal servers" },
                    threema: { status: "times", detail: "Threema servers in Switzerland" },
                    session: { status: "warning", detail: "Onion routing via network nodes" },
                    },
                    {
                    name: "Registration Anonymity",
                    lockbit: { status: "trophy", detail: "No registration required, instant anonymous channels" },
                    signal: { status: "times", detail: "Phone number required" },
                    threema: { status: "check", detail: "ID generated locally" },
                    session: { status: "check", detail: "Random session ID" },
                    },
                    {
                    name: "Metadata Protection",
                    lockbit: { status: "trophy", detail: "Full metadata encryption + traffic obfuscation" },
                    signal: { status: "warning", detail: "Sealed Sender (partial)" },
                    threema: { status: "warning", detail: "Minimal metadata" },
                    session: { status: "check", detail: "Onion routing hides metadata" },
                    },
                    {
                    name: "Traffic Obfuscation",
                    lockbit: { status: "trophy", detail: "Fake traffic + pattern masking + packet padding" },
                    signal: { status: "times", detail: "No traffic obfuscation" },
                    threema: { status: "times", detail: "No traffic obfuscation" },
                    session: { status: "check", detail: "Onion routing provides obfuscation" },
                    },
                    {
                    name: "Open Source",
                    lockbit: { status: "trophy", detail: "100% open + auditable + MIT license" },
                    signal: { status: "check", detail: "Fully open" },
                    threema: { status: "warning", detail: "Only clients open" },
                    session: { status: "check", detail: "Fully open" },
                    },
                    {
                    name: "MITM Protection",
                    lockbit: { status: "trophy", detail: "Out-of-band verification + mutual auth + ECDSA" },
                    signal: { status: "check", detail: "Safety numbers verification" },
                    threema: { status: "check", detail: "QR code scanning" },
                    session: { status: "warning", detail: "Basic key verification" },
                    },
                    {
                    name: "Censorship Resistance",
                    lockbit: { status: "trophy", detail: "Impossible to block P2P + no servers to target" },
                    signal: { status: "warning", detail: "Blocked in authoritarian countries" },
                    threema: { status: "warning", detail: "May be blocked" },
                    session: { status: "check", detail: "Onion routing bypasses blocks" },
                    },
                    {
                    name: "Data Storage",
                    lockbit: { status: "trophy", detail: "Zero data storage - only in browser memory" },
                    signal: { status: "warning", detail: "Local database storage" },
                    threema: { status: "warning", detail: "Local + optional backup" },
                    session: { status: "warning", detail: "Local database storage" },
                    },
                    {
                    name: "Key Security",
                    lockbit: { status: "trophy", detail: "Non-extractable keys + hardware protection" },
                    signal: { status: "check", detail: "Secure key storage" },
                    threema: { status: "check", detail: "Local key storage" },
                    session: { status: "check", detail: "Secure key storage" },
                    },
                    {
                    name: "Post-Quantum Roadmap",
                    lockbit: { status: "check", detail: "Planned v5.0 - CRYSTALS-Kyber/Dilithium" },
                    signal: { status: "warning", detail: "PQXDH in development" },
                    threema: { status: "times", detail: "Not announced" },
                    session: { status: "times", detail: "Not announced" },
                    },
                ];

                const getStatusIcon = (status) => {
                    const statusMap = {
                    "trophy": { icon: "fa-trophy", color: "accent-orange" },
                    "check": { icon: "fa-check", color: "text-green-300" },
                    "warning": { icon: "fa-exclamation-triangle", color: "text-yellow-300" },
                    "times": { icon: "fa-times", color: "text-red-300" },
                    };
                    return statusMap[status] || { icon: "fa-question", color: "text-gray-400" };
                };

                const toggleFeatureDetail = (index) => {
                    setSelectedFeature(selectedFeature === index ? null : index);
                };

                return (
                    <div className="mt-16">
                    {/* Title */}
                    <div className="text-center mb-8">
                        <h3 className="text-3xl font-bold text-white mb-3">
                        Enhanced Security Edition Comparison
                        </h3>
                        <p className="text-gray-400 max-w-2xl mx-auto mb-4">
                        Enhanced Security Edition vs leading secure messengers
                        </p>
                    </div>

                    {/* Table container */}
                    <div className="max-w-7xl mx-auto">
                        {/* Mobile Alert */}
                        <div className="md:hidden p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg mb-4">
                        <p className="text-yellow-400 text-sm text-center">
                            <i className="fas fa-lightbulb mr-2"></i>
                            Rotate your device horizontally for better viewing
                        </p>
                        </div>

                        {/* Table */}
                        <div className="overflow-x-auto">
                        <table
                            className="w-full border-collapse rounded-xl overflow-hidden shadow-2xl"
                            style={{ backgroundColor: "rgba(42, 43, 42, 0.9)" }}
                        >
                            {/* Table Header */}
                            <thead>
                            <tr className="bg-black-table">
                                <th className="text-left p-4 border-b border-gray-600 text-white font-bold min-w-[240px]">
                                Security Criterion
                                </th>
                                {messengers.map((messenger, index) => (
                                <th key={`messenger-${index}`} className="text-center p-4 border-b border-gray-600 min-w-[160px]">
                                    <div className="flex flex-col items-center">
                                    <div className="mb-2">{messenger.logo}</div>
                                    <div className={`text-sm font-bold ${
                                        messenger.color === 'orange' ? 'text-orange-400' :
                                        messenger.color === 'blue' ? 'text-blue-400' :
                                        messenger.color === 'green' ? 'text-green-400' :
                                        'text-cyan-400'
                                    }`}>
                                        {messenger.name}
                                    </div>
                                    <div className="text-xs text-gray-400">{messenger.type}</div>
                                    <div className="text-xs text-gray-500 mt-1">{messenger.version}</div>
                                    </div>
                                </th>
                                ))}
                            </tr>
                            </thead>

                            {/* Table body */}
                            <tbody>
                            {features.map((feature, featureIndex) => (
                                <React.Fragment key={`feature-${featureIndex}`}>
                                <tr
                                className={`border-b border-gray-700/30 transition-all duration-200 cursor-pointer hover:bg-[rgb(20_20_20_/30%)] ${
                                    selectedFeature === featureIndex ? 'bg-[rgb(20_20_20_/50%)]' : ''
                                }`}
                                onClick={() => toggleFeatureDetail(featureIndex)}
                                >
                                    <td className="p-4 text-white font-semibold">
                                    <div className="flex items-center justify-between">
                                        <span>{feature.name}</span>
                                        <i className={`fas fa-chevron-${selectedFeature === featureIndex ? 'up' : 'down'} text-xs text-gray-400 opacity-60 transition-all duration-200`} />
                                    </div>
                                    </td>
                                    <td className="p-4 text-center">
                                    <i className={`fas ${getStatusIcon(feature.lockbit.status).icon} ${getStatusIcon(feature.lockbit.status).color} text-2xl`} />
                                    </td>
                                    <td className="p-4 text-center">
                                    <i className={`fas ${getStatusIcon(feature.signal.status).icon} ${getStatusIcon(feature.signal.status).color} text-2xl`} />
                                    </td>
                                    <td className="p-4 text-center">
                                    <i className={`fas ${getStatusIcon(feature.threema.status).icon} ${getStatusIcon(feature.threema.status).color} text-2xl`} />
                                    </td>
                                    <td className="p-4 text-center">
                                    <i className={`fas ${getStatusIcon(feature.session.status).icon} ${getStatusIcon(feature.session.status).color} text-2xl`} />
                                    </td>
                                </tr>

                                {/* Details */}
                                {selectedFeature === featureIndex && (
                                    <tr className="border-b border-gray-700/30 bg-gradient-to-r from-gray-800/20 to-gray-900/20">
                                    <td className="p-4 text-xs text-gray-400 font-medium">Technical Details:</td>
                                    <td className="p-4 text-center">
                                        <div className="text-xs text-orange-300 font-medium leading-relaxed">
                                        {feature.lockbit.detail}
                                        </div>
                                    </td>
                                    <td className="p-4 text-center">
                                        <div className="text-xs text-blue-300 leading-relaxed">
                                        {feature.signal.detail}
                                        </div>
                                    </td>
                                    <td className="p-4 text-center">
                                        <div className="text-xs text-green-300 leading-relaxed">
                                        {feature.threema.detail}
                                        </div>
                                    </td>
                                    <td className="p-4 text-center">
                                        <div className="text-xs text-cyan-300 leading-relaxed">
                                        {feature.session.detail}
                                        </div>
                                    </td>
                                    </tr>
                                )}
                                </React.Fragment>
                            ))}
                            </tbody>
                        </table>
                        </div>

                        {/* Legend */}
                        <div className="mt-8 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-5xl mx-auto">
                        <div className="flex items-center justify-center p-4 bg-orange-500/10 rounded-xl hover:bg-orange-500/40 transition-colors">
                            <i className="fas fa-trophy text-orange-400 mr-2 text-xl"></i>
                            <span className="text-orange-300 text-sm font-bold">Category Leader</span>
                        </div>

                        <div className="flex items-center justify-center p-4 bg-green-500/10 rounded-xl hover:bg-green-600/40 transition-colors">
                            <i className="fas fa-check text-green-300 mr-2 text-xl"></i>
                            <span className="text-green-200 text-sm font-bold">Excellent</span>
                        </div>
                        <div className="flex items-center justify-center p-4 bg-yellow-500/10 rounded-xl hover:bg-yellow-600/40 transition-colors">
                            <i className="fas fa-exclamation-triangle text-yellow-300 mr-2 text-xl"></i>
                            <span className="text-yellow-200 text-sm font-bold">Partial/Limited</span>
                        </div>
                        <div className="flex items-center justify-center p-4 bg-red-500/10 rounded-xl hover:bg-red-600/40 transition-colors">
                            <i className="fas fa-times text-red-300 mr-2 text-xl"></i>
                            <span className="text-red-200 text-sm font-bold">Not Available</span>
                        </div>
                        </div>
                    </div>
                    </div>
                );
            };
    window.ComparisonTable = ComparisonTable;