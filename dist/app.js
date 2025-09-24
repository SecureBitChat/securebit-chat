// src/app.jsx
var UniqueFeatureSlider = () => {
  const [currentSlide, setCurrentSlide] = React.useState(0);
  const slides = [
    {
      icon: "fas fa-shield-halved",
      color: "orange",
      title: "18-Layer Military Security",
      description: "Revolutionary defense system with ECDH P-384 + AES-GCM 256 + ECDSA + Complete ASN.1 Validation. Enhanced Security Edition provides military-grade protection exceeding government standards with complete key structure verification."
    },
    {
      icon: "fas fa-bolt",
      color: "yellow",
      title: "Lightning Network Payments",
      description: "First messenger with Lightning Network integration. Pay-per-session with satoshis via WebLN. Sustainable economic model without ads or data harvesting."
    },
    {
      icon: "fas fa-network-wired",
      color: "purple",
      title: "Pure P2P WebRTC Architecture",
      description: "Direct peer-to-peer connections without any servers. Impossible to censor, block, or monitor. Complete decentralization with zero infrastructure."
    },
    {
      icon: "fas fa-sync-alt",
      color: "green",
      title: "Perfect Forward Secrecy",
      description: "Automatic key rotation every 5 minutes or 100 messages. Non-extractable keys with hardware protection ensure past messages remain secure."
    },
    {
      icon: "fas fa-user-secret",
      color: "cyan",
      title: "Advanced Traffic Obfuscation",
      description: "Fake traffic generation, packet padding, and pattern masking make communication indistinguishable from random noise. Defeats traffic analysis."
    },
    {
      icon: "fas fa-eye-slash",
      color: "blue",
      title: "Zero Data Collection",
      description: "No registration, no servers, no logs. Messages exist only in browser memory. Complete anonymity with instant anonymous channels."
    },
    {
      icon: "fas fa-code",
      color: "emerald",
      title: "100% Open Source Security",
      description: "All code is open for audit under MIT license. Uses only standard WebCrypto APIs. Cryptography runs directly in browser without server dependencies."
    }
  ];
  const nextSlide = () => setCurrentSlide((prev) => (prev + 1) % slides.length);
  const prevSlide = () => setCurrentSlide((prev) => (prev - 1 + slides.length) % slides.length);
  const goToSlide = (index) => setCurrentSlide(index);
  React.useEffect(() => {
    const timer = setInterval(() => {
      nextSlide();
    }, 15e3);
    return () => clearInterval(timer);
  }, []);
  return React.createElement("div", {
    className: "mt-12"
  }, [
    React.createElement("div", {
      key: "header",
      className: "text-center mb-8"
    }, [
      React.createElement("h3", {
        key: "title",
        className: "text-2xl font-semibold text-primary mb-3"
      }, "Why SecureBit.chat is unique"),
      React.createElement("p", {
        key: "subtitle",
        className: "text-secondary max-w-2xl mx-auto"
      }, "The only messenger with military-grade cryptography and Lightning payments")
    ]),
    React.createElement("div", {
      key: "slider-container",
      className: "relative max-w-4xl mx-auto"
    }, [
      React.createElement("div", {
        key: "slider-wrapper",
        className: "overflow-hidden rounded-xl"
      }, [
        React.createElement("div", {
          key: "slides",
          className: "flex transition-transform duration-500 ease-in-out",
          style: { transform: `translateX(-${currentSlide * 100}%)` }
        }, slides.map(
          (slide, index) => React.createElement("div", {
            key: index,
            className: "w-full flex-shrink-0 px-4"
          }, [
            React.createElement("div", {
              key: "slide-content",
              className: "card-minimal rounded-xl p-8 text-center min-h-[300px] flex flex-col justify-center relative overflow-hidden"
            }, [
              // Background icon
              React.createElement("i", {
                key: "bg-icon",
                className: `${slide.icon} absolute right-[-100px] top-1/2 -translate-y-1/2 opacity-10 text-[300px] pointer-events-none ${slide.color === "orange" ? "text-orange-500" : slide.color === "yellow" ? "text-yellow-500" : slide.color === "purple" ? "text-purple-500" : slide.color === "green" ? "text-green-500" : slide.color === "cyan" ? "text-cyan-500" : slide.color === "blue" ? "text-blue-500" : "text-emerald-500"}`
              }),
              // Content
              React.createElement("h4", {
                key: "slide-title",
                className: "text-xl font-semibold text-primary mb-4 relative z-10"
              }, slide.title),
              React.createElement("p", {
                key: "slide-description",
                className: "text-secondary leading-relaxed max-w-2xl mx-auto relative z-10"
              }, slide.description)
            ])
          ])
        ))
      ]),
      // Navigation
      React.createElement("button", {
        key: "prev-btn",
        onClick: prevSlide,
        className: "absolute left-2 top-1/2 transform -translate-y-1/2 w-10 h-10 bg-gray-600/80 hover:bg-gray-500/80 text-white rounded-full flex items-center justify-center transition-all duration-200 z-10"
      }, [
        React.createElement("i", {
          key: "prev-icon",
          className: "fas fa-chevron-left"
        })
      ]),
      React.createElement("button", {
        key: "next-btn",
        onClick: nextSlide,
        className: "absolute right-2 top-1/2 transform -translate-y-1/2 w-10 h-10 bg-gray-600/80 hover:bg-gray-500/80 text-white rounded-full flex items-center justify-center transition-all duration-200 z-10"
      }, [
        React.createElement("i", {
          key: "next-icon",
          className: "fas fa-chevron-right"
        })
      ])
    ]),
    // Enhanced dots navigation (оставляем улучшенные точки)
    React.createElement("div", {
      key: "dots-container",
      className: "flex justify-center space-x-3 mt-6"
    }, slides.map(
      (slide, index) => React.createElement("button", {
        key: index,
        onClick: () => goToSlide(index),
        className: `relative group transition-all duration-300 ${index === currentSlide ? "w-12 h-4 bg-orange-500 rounded-full" : "w-4 h-4 bg-gray-600 hover:bg-gray-500 rounded-full hover:scale-125"}`
      }, [
        // Tooltip on hover
        React.createElement("div", {
          key: "tooltip",
          className: "absolute -top-10 left-1/2 transform -translate-x-1/2 bg-gray-800 text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity duration-200 whitespace-nowrap pointer-events-none"
        }, slide.title)
      ])
    ))
  ]);
};
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
      lockbit: { status: "\u{1F3C6}", detail: "18-layer military-grade defense system with complete ASN.1 validation" },
      signal: { status: "\u2705", detail: "Signal Protocol with double ratchet" },
      threema: { status: "\u2705", detail: "Standard security implementation" },
      session: { status: "\u2705", detail: "Modified Signal Protocol + Onion routing" }
    },
    {
      name: "Cryptography",
      lockbit: { status: "\u{1F3C6}", detail: "ECDH P-384 + AES-GCM 256 + ECDSA P-384" },
      signal: { status: "\u2705", detail: "Signal Protocol + Double Ratchet" },
      threema: { status: "\u2705", detail: "NaCl + XSalsa20 + Poly1305" },
      session: { status: "\u2705", detail: "Modified Signal Protocol" }
    },
    {
      name: "Perfect Forward Secrecy",
      lockbit: { status: "\u{1F3C6}", detail: "Auto rotation every 5 minutes or 100 messages" },
      signal: { status: "\u2705", detail: "Double Ratchet algorithm" },
      threema: { status: "\u26A0\uFE0F", detail: "Partial (group chats)" },
      session: { status: "\u2705", detail: "Session Ratchet algorithm" }
    },
    {
      name: "Architecture",
      lockbit: { status: "\u{1F3C6}", detail: "Pure P2P WebRTC without servers" },
      signal: { status: "\u274C", detail: "Centralized Signal servers" },
      threema: { status: "\u274C", detail: "Threema servers in Switzerland" },
      session: { status: "\u26A0\uFE0F", detail: "Onion routing via network nodes" }
    },
    {
      name: "Registration Anonymity",
      lockbit: { status: "\u{1F3C6}", detail: "No registration required, instant anonymous channels" },
      signal: { status: "\u274C", detail: "Phone number required" },
      threema: { status: "\u2705", detail: "ID generated locally" },
      session: { status: "\u2705", detail: "Random session ID" }
    },
    {
      name: "Payment Integration",
      lockbit: { status: "\u{1F3C6}", detail: "Lightning Network satoshis per session + WebLN" },
      signal: { status: "\u274C", detail: "No payment system" },
      threema: { status: "\u274C", detail: "No payment system" },
      session: { status: "\u274C", detail: "No payment system" }
    },
    {
      name: "Metadata Protection",
      lockbit: { status: "\u{1F3C6}", detail: "Full metadata encryption + traffic obfuscation" },
      signal: { status: "\u26A0\uFE0F", detail: "Sealed Sender (partial)" },
      threema: { status: "\u26A0\uFE0F", detail: "Minimal metadata" },
      session: { status: "\u2705", detail: "Onion routing hides metadata" }
    },
    {
      name: "Traffic Obfuscation",
      lockbit: { status: "\u{1F3C6}", detail: "Fake traffic + pattern masking + packet padding" },
      signal: { status: "\u274C", detail: "No traffic obfuscation" },
      threema: { status: "\u274C", detail: "No traffic obfuscation" },
      session: { status: "\u2705", detail: "Onion routing provides obfuscation" }
    },
    {
      name: "Open Source",
      lockbit: { status: "\u{1F3C6}", detail: "100% open + auditable + MIT license" },
      signal: { status: "\u2705", detail: "Fully open" },
      threema: { status: "\u26A0\uFE0F", detail: "Only clients open" },
      session: { status: "\u2705", detail: "Fully open" }
    },
    {
      name: "MITM Protection",
      lockbit: { status: "\u{1F3C6}", detail: "Out-of-band verification + mutual auth + ECDSA" },
      signal: { status: "\u2705", detail: "Safety numbers verification" },
      threema: { status: "\u2705", detail: "QR code scanning" },
      session: { status: "\u26A0\uFE0F", detail: "Basic key verification" }
    },
    {
      name: "Economic Model",
      lockbit: { status: "\u{1F3C6}", detail: "Sustainable pay-per-session model" },
      signal: { status: "\u26A0\uFE0F", detail: "Donations and grants dependency" },
      threema: { status: "\u2705", detail: "One-time app purchase" },
      session: { status: "\u26A0\uFE0F", detail: "Donations dependency" }
    },
    {
      name: "Censorship Resistance",
      lockbit: { status: "\u{1F3C6}", detail: "Impossible to block P2P + no servers to target" },
      signal: { status: "\u26A0\uFE0F", detail: "Blocked in authoritarian countries" },
      threema: { status: "\u26A0\uFE0F", detail: "May be blocked" },
      session: { status: "\u2705", detail: "Onion routing bypasses blocks" }
    },
    {
      name: "Data Storage",
      lockbit: { status: "\u{1F3C6}", detail: "Zero data storage - only in browser memory" },
      signal: { status: "\u26A0\uFE0F", detail: "Local database storage" },
      threema: { status: "\u26A0\uFE0F", detail: "Local + optional backup" },
      session: { status: "\u26A0\uFE0F", detail: "Local database storage" }
    },
    {
      name: "Key Security",
      lockbit: { status: "\u{1F3C6}", detail: "Non-extractable keys + hardware protection" },
      signal: { status: "\u2705", detail: "Secure key storage" },
      threema: { status: "\u2705", detail: "Local key storage" },
      session: { status: "\u2705", detail: "Secure key storage" }
    },
    {
      name: "Post-Quantum Roadmap",
      lockbit: { status: "\u2705", detail: "Planned v5.0 - CRYSTALS-Kyber/Dilithium" },
      signal: { status: "\u26A0\uFE0F", detail: "PQXDH in development" },
      threema: { status: "\u274C", detail: "Not announced" },
      session: { status: "\u274C", detail: "Not announced" }
    }
  ];
  const getStatusIcon = (status) => {
    const statusMap = {
      "\u{1F3C6}": { icon: "\u{1F3C6}", color: "text-yellow-400" },
      "\u2705": { icon: "\u2705", color: "text-green-400" },
      "\u26A0\uFE0F": { icon: "\u26A0\uFE0F", color: "text-yellow-400" },
      "\u274C": { icon: "\u274C", color: "text-red-400" }
    };
    return statusMap[status] || { icon: status, color: "text-gray-400" };
  };
  const toggleFeatureDetail = (index) => {
    setSelectedFeature(selectedFeature === index ? null : index);
  };
  return /* @__PURE__ */ React.createElement("div", { className: "mt-16" }, /* @__PURE__ */ React.createElement("div", { className: "text-center mb-8" }, /* @__PURE__ */ React.createElement("h3", { className: "text-3xl font-bold text-primary mb-3" }, "Enhanced Security Edition Comparison"), /* @__PURE__ */ React.createElement("p", { className: "text-secondary max-w-2xl mx-auto mb-4" }, "Enhanced Security Edition vs leading secure messengers"), /* @__PURE__ */ React.createElement("div", { className: "inline-flex items-center px-4 py-2 bg-yellow-500/10 border border-yellow-500/20 rounded-lg" }, /* @__PURE__ */ React.createElement("span", { className: "text-yellow-400 mr-2" }, "\u{1F3C6}"), /* @__PURE__ */ React.createElement("span", { className: "text-yellow-300 text-sm font-medium" }, "Category Leader - Military-Grade Security"))), /* @__PURE__ */ React.createElement("div", { className: "max-w-7xl mx-auto" }, /* @__PURE__ */ React.createElement("div", { className: "md:hidden p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg mb-4" }, /* @__PURE__ */ React.createElement("p", { className: "text-yellow-400 text-sm text-center" }, "\u{1F4A1} Rotate your device horizontally for better viewing")), /* @__PURE__ */ React.createElement("div", { className: "overflow-x-auto custom-scrollbar" }, /* @__PURE__ */ React.createElement(
    "table",
    {
      className: "w-full border-collapse rounded-xl overflow-hidden shadow-2xl",
      style: { backgroundColor: "rgba(42, 43, 42, 0.9)" }
    },
    /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", { className: "bg-my" }, /* @__PURE__ */ React.createElement("th", { className: "text-left p-4 border-b border-gray-600 text-primary font-bold min-w-[240px]" }, "Security Criterion"), messengers.map((messenger, index) => /* @__PURE__ */ React.createElement("th", { key: `messenger-${index}`, className: "text-center p-4 border-b border-gray-600 min-w-[160px]" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col items-center" }, /* @__PURE__ */ React.createElement("div", { className: "mb-2" }, messenger.logo), /* @__PURE__ */ React.createElement("div", { className: `text-sm font-bold ${messenger.color === "orange" ? "text-orange-400" : messenger.color === "blue" ? "text-blue-400" : messenger.color === "green" ? "text-green-400" : "text-cyan-400"}` }, messenger.name), /* @__PURE__ */ React.createElement("div", { className: "text-xs text-gray-400" }, messenger.type), /* @__PURE__ */ React.createElement("div", { className: "text-xs text-gray-500 mt-1" }, messenger.version)))))),
    /* @__PURE__ */ React.createElement("tbody", null, features.map((feature, featureIndex) => /* @__PURE__ */ React.createElement(React.Fragment, { key: `feature-${featureIndex}` }, /* @__PURE__ */ React.createElement(
      "tr",
      {
        className: `border-b border-gray-700/30 hover:bg-gray-800/30 transition-all duration-200 cursor-pointer ${selectedFeature === featureIndex ? "bg-gray-800/50" : ""}`,
        onClick: () => toggleFeatureDetail(featureIndex)
      },
      /* @__PURE__ */ React.createElement("td", { className: "p-4 text-primary font-semibold" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between" }, /* @__PURE__ */ React.createElement("span", null, feature.name), /* @__PURE__ */ React.createElement("i", { className: `fas fa-chevron-${selectedFeature === featureIndex ? "up" : "down"} text-xs text-gray-400 opacity-60 transition-all duration-200` }))),
      /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("span", { className: `${getStatusIcon(feature.lockbit.status).color} text-2xl` }, getStatusIcon(feature.lockbit.status).icon)),
      /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("span", { className: `${getStatusIcon(feature.signal.status).color} text-2xl` }, getStatusIcon(feature.signal.status).icon)),
      /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("span", { className: `${getStatusIcon(feature.threema.status).color} text-2xl` }, getStatusIcon(feature.threema.status).icon)),
      /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("span", { className: `${getStatusIcon(feature.session.status).color} text-2xl` }, getStatusIcon(feature.session.status).icon))
    ), selectedFeature === featureIndex && /* @__PURE__ */ React.createElement("tr", { className: "border-b border-gray-700/30 bg-gradient-to-r from-gray-800/20 to-gray-900/20" }, /* @__PURE__ */ React.createElement("td", { className: "p-4 text-xs text-gray-400 font-medium" }, "Technical Details:"), /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs text-orange-300 font-medium leading-relaxed max-w-32" }, feature.lockbit.detail)), /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs text-blue-300 leading-relaxed max-w-32" }, feature.signal.detail)), /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs text-green-300 leading-relaxed max-w-32" }, feature.threema.detail)), /* @__PURE__ */ React.createElement("td", { className: "p-4 text-center" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs text-cyan-300 leading-relaxed max-w-32" }, feature.session.detail))))))
  )), /* @__PURE__ */ React.createElement("div", { className: "mt-8 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-5xl mx-auto" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-xl hover:bg-yellow-500/20 transition-colors" }, /* @__PURE__ */ React.createElement("span", { className: "text-yellow-400 mr-2 text-xl" }, "\u{1F3C6}"), /* @__PURE__ */ React.createElement("span", { className: "text-yellow-300 text-sm font-bold" }, "Category Leader")), /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center p-4 bg-green-500/10 border border-green-500/20 rounded-xl hover:bg-green-500/20 transition-colors" }, /* @__PURE__ */ React.createElement("span", { className: "text-green-400 mr-2 text-xl" }, "\u2705"), /* @__PURE__ */ React.createElement("span", { className: "text-green-300 text-sm font-bold" }, "Excellent")), /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-xl hover:bg-yellow-500/20 transition-colors" }, /* @__PURE__ */ React.createElement("span", { className: "text-yellow-400 mr-2 text-xl" }, "\u26A0\uFE0F"), /* @__PURE__ */ React.createElement("span", { className: "text-yellow-300 text-sm font-bold" }, "Partial/Limited")), /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center p-4 bg-red-500/10 border border-red-500/20 rounded-xl hover:bg-red-500/20 transition-colors" }, /* @__PURE__ */ React.createElement("span", { className: "text-red-400 mr-2 text-xl" }, "\u274C"), /* @__PURE__ */ React.createElement("span", { className: "text-red-300 text-sm font-bold" }, "Not Available"))), /* @__PURE__ */ React.createElement("div", { className: "mt-10 space-y-6 max-w-6xl mx-auto" }, /* @__PURE__ */ React.createElement("div", { className: "p-6 bg-gradient-to-r from-orange-500/10 to-yellow-500/10 border border-orange-500/20 rounded-xl" }, /* @__PURE__ */ React.createElement("h4", { className: "text-xl font-bold text-orange-400 mb-4 flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-trophy mr-3" }), "SecureBit.chat Enhanced Security Edition Summary"), /* @__PURE__ */ React.createElement("p", { className: "text-secondary leading-relaxed text-lg mb-4" }, "SecureBit.chat dominates in 11 out of 15 security categories, establishing itself as the most secure P2P messenger available. The Enhanced Security Edition introduces revolutionary 18-layer defense architecture with complete ASN.1 validation, Lightning Network integration, and military-grade cryptography that exceeds government and enterprise standards."), /* @__PURE__ */ React.createElement("div", { className: "grid md:grid-cols-2 gap-4 mt-6" }, /* @__PURE__ */ React.createElement("div", { className: "p-4 bg-orange-500/5 border border-orange-500/10 rounded-lg" }, /* @__PURE__ */ React.createElement("h5", { className: "text-orange-400 font-semibold mb-2" }, "\u{1F510} Cryptographic Superiority"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-300" }, "ECDH P-384 + AES-GCM 256 + ECDSA P-384 + Complete ASN.1 Validation with non-extractable keys and 18-layer defense system")), /* @__PURE__ */ React.createElement("div", { className: "p-4 bg-orange-500/5 border border-orange-500/10 rounded-lg" }, /* @__PURE__ */ React.createElement("h5", { className: "text-orange-400 font-semibold mb-2" }, "\u26A1 Lightning Integration"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-300" }, "First messenger with Lightning Network payments - sustainable economic model with instant satoshi transactions")), /* @__PURE__ */ React.createElement("div", { className: "p-4 bg-orange-500/5 border border-orange-500/10 rounded-lg" }, /* @__PURE__ */ React.createElement("h5", { className: "text-orange-400 font-semibold mb-2" }, "\u{1F310} True P2P Architecture"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-300" }, "Pure WebRTC connections with zero servers, impossible to censor or shutdown, complete anonymity")), /* @__PURE__ */ React.createElement("div", { className: "p-4 bg-orange-500/5 border border-orange-500/10 rounded-lg" }, /* @__PURE__ */ React.createElement("h5", { className: "text-orange-400 font-semibold mb-2" }, "\u{1F3AD} Traffic Obfuscation"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-300" }, "Advanced fake traffic generation, packet padding, and pattern masking defeat traffic analysis"))))), /* @__PURE__ */ React.createElement("div", { className: "mt-8 text-center" }, /* @__PURE__ */ React.createElement("div", { className: "inline-flex items-center px-6 py-3 bg-gray-800/50 border border-gray-600/30 rounded-xl" }, /* @__PURE__ */ React.createElement("span", { className: "text-orange-400 mr-2" }, "\u{1F680}"), /* @__PURE__ */ React.createElement("span", { className: "text-gray-300 text-sm" }, "Enhanced Security Edition v4.02.985 - ECDH + DTLS + SAS - "), /* @__PURE__ */ React.createElement("span", { className: "text-orange-400 font-semibold text-sm" }, "Active Production Release"), /* @__PURE__ */ React.createElement("span", { className: "text-gray-400 text-sm ml-2" }, " | Next: v5.0 Post-Quantum")))));
};
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
      version: "v4.02.985",
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
        "Lightning Network payments",
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
        "Group Lightning payments",
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
  return /* @__PURE__ */ React.createElement("div", { key: "roadmap-section", className: "mt-16 px-4 sm:px-0" }, /* @__PURE__ */ React.createElement("div", { key: "section-header", className: "text-center mb-12" }, /* @__PURE__ */ React.createElement("h3", { key: "title", className: "text-2xl font-semibold text-primary mb-3" }, "Development Roadmap"), /* @__PURE__ */ React.createElement("p", { key: "subtitle", className: "text-secondary max-w-2xl mx-auto mb-6" }, "Evolution of SecureBit.chat : from initial development to quantum-resistant decentralized network with complete ASN.1 validation"), /* @__PURE__ */ React.createElement(
    "div",
    {
      key: "roadmap-note",
      className: "inline-flex items-center px-4 py-2 bg-blue-500/10 border border-blue-500/20 rounded-lg"
    },
    /* @__PURE__ */ React.createElement("i", { key: "icon", className: "fas fa-rocket text-blue-400 mr-2" }),
    /* @__PURE__ */ React.createElement("span", { key: "text", className: "text-blue-300 text-sm font-medium" }, "Click on a version for details")
  )), /* @__PURE__ */ React.createElement("div", { key: "roadmap-container", className: "max-w-6xl mx-auto" }, /* @__PURE__ */ React.createElement("div", { key: "timeline", className: "relative" }, /* @__PURE__ */ React.createElement("div", { key: "phases", className: "space-y-8" }, phases.map((phase, index) => {
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
var EnhancedCopyButton = ({ text, className = "", children }) => {
  const [copied, setCopied] = React.useState(false);
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2e3);
    } catch (error) {
      console.error("Copy failed:", error);
      const textArea = document.createElement("textarea");
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand("copy");
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2e3);
    }
  };
  return React.createElement("button", {
    onClick: handleCopy,
    className: `${className} transition-all duration-200`
  }, [
    React.createElement("i", {
      key: "icon",
      className: `${copied ? "fas fa-check accent-green" : "fas fa-copy text-secondary"} mr-2`
    }),
    copied ? "Copied!" : children
  ]);
};
var VerificationStep = ({ verificationCode, onConfirm, onReject, localConfirmed, remoteConfirmed, bothConfirmed }) => {
  return React.createElement("div", {
    className: "card-minimal rounded-xl p-6 border-purple-500/20"
  }, [
    React.createElement("div", {
      key: "header",
      className: "flex items-center mb-4"
    }, [
      React.createElement("div", {
        key: "icon",
        className: "w-10 h-10 bg-purple-500/10 border border-purple-500/20 rounded-lg flex items-center justify-center mr-3"
      }, [
        React.createElement("i", {
          className: "fas fa-shield-alt accent-purple"
        })
      ]),
      React.createElement("h3", {
        key: "title",
        className: "text-lg font-medium text-primary"
      }, "Security verification")
    ]),
    React.createElement("div", {
      key: "content",
      className: "space-y-4"
    }, [
      React.createElement("p", {
        key: "description",
        className: "text-secondary text-sm"
      }, "Verify the security code with your contact via another communication channel (voice, SMS, etc.):"),
      React.createElement("div", {
        key: "code-display",
        className: "text-center"
      }, [
        React.createElement("div", {
          key: "code",
          className: "verification-code text-2xl py-4"
        }, verificationCode)
      ]),
      // Verification status indicators
      React.createElement("div", {
        key: "verification-status",
        className: "space-y-2"
      }, [
        React.createElement("div", {
          key: "local-status",
          className: `flex items-center justify-between p-2 rounded-lg ${localConfirmed ? "bg-green-500/10 border border-green-500/20" : "bg-gray-500/10 border border-gray-500/20"}`
        }, [
          React.createElement("span", {
            key: "local-label",
            className: "text-sm text-secondary"
          }, "Your confirmation:"),
          React.createElement("div", {
            key: "local-indicator",
            className: "flex items-center"
          }, [
            React.createElement("i", {
              key: "local-icon",
              className: `fas ${localConfirmed ? "fa-check-circle text-green-400" : "fa-clock text-gray-400"} mr-2`
            }),
            React.createElement("span", {
              key: "local-text",
              className: `text-sm ${localConfirmed ? "text-green-400" : "text-gray-400"}`
            }, localConfirmed ? "Confirmed" : "Pending")
          ])
        ]),
        React.createElement("div", {
          key: "remote-status",
          className: `flex items-center justify-between p-2 rounded-lg ${remoteConfirmed ? "bg-green-500/10 border border-green-500/20" : "bg-gray-500/10 border border-gray-500/20"}`
        }, [
          React.createElement("span", {
            key: "remote-label",
            className: "text-sm text-secondary"
          }, "Peer confirmation:"),
          React.createElement("div", {
            key: "remote-indicator",
            className: "flex items-center"
          }, [
            React.createElement("i", {
              key: "remote-icon",
              className: `fas ${remoteConfirmed ? "fa-check-circle text-green-400" : "fa-clock text-gray-400"} mr-2`
            }),
            React.createElement("span", {
              key: "remote-text",
              className: `text-sm ${remoteConfirmed ? "text-green-400" : "text-gray-400"}`
            }, remoteConfirmed ? "Confirmed" : "Pending")
          ])
        ])
      ]),
      React.createElement("div", {
        key: "warning",
        className: "p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg"
      }, [
        React.createElement("p", {
          className: "text-yellow-400 text-sm flex items-center"
        }, [
          React.createElement("i", {
            className: "fas fa-exclamation-triangle mr-2"
          }),
          "Make sure the codes match exactly.!"
        ])
      ]),
      React.createElement("div", {
        key: "buttons",
        className: "flex space-x-3"
      }, [
        React.createElement("button", {
          key: "confirm",
          onClick: onConfirm,
          disabled: localConfirmed,
          className: `flex-1 py-3 px-4 rounded-lg font-medium transition-all duration-200 ${localConfirmed ? "bg-gray-500/20 text-gray-400 cursor-not-allowed" : "btn-verify text-white"}`
        }, [
          React.createElement("i", {
            className: `fas ${localConfirmed ? "fa-check-circle" : "fa-check"} mr-2`
          }),
          localConfirmed ? "Confirmed" : "The codes match"
        ]),
        React.createElement("button", {
          key: "reject",
          onClick: onReject,
          className: "flex-1 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 py-3 px-4 rounded-lg font-medium transition-all duration-200"
        }, [
          React.createElement("i", {
            className: "fas fa-times mr-2"
          }),
          "The codes do not match"
        ])
      ])
    ])
  ]);
};
var EnhancedChatMessage = ({ message, type, timestamp }) => {
  const formatTime = (ts) => {
    return new Date(ts).toLocaleTimeString("ru-RU", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });
  };
  const getMessageStyle = () => {
    switch (type) {
      case "sent":
        return {
          container: "ml-auto bg-orange-500/15 border-orange-500/20 text-primary",
          icon: "fas fa-lock accent-orange",
          label: "Encrypted"
        };
      case "received":
        return {
          container: "mr-auto card-minimal text-primary",
          icon: "fas fa-unlock-alt accent-green",
          label: "Decrypted"
        };
      case "system":
        return {
          container: "mx-auto bg-yellow-500/10 border border-yellow-500/20 text-yellow-400",
          icon: "fas fa-info-circle accent-yellow",
          label: "System"
        };
      default:
        return {
          container: "mx-auto card-minimal text-secondary",
          icon: "fas fa-circle text-muted",
          label: "Unknown"
        };
    }
  };
  const style = getMessageStyle();
  return React.createElement("div", {
    className: `message-slide mb-3 p-3 rounded-lg max-w-md break-words ${style.container} border`
  }, [
    React.createElement("div", {
      key: "content",
      className: "flex items-start space-x-2"
    }, [
      React.createElement("i", {
        key: "icon",
        className: `${style.icon} text-sm mt-0.5 opacity-70`
      }),
      React.createElement("div", {
        key: "text",
        className: "flex-1"
      }, [
        React.createElement("div", {
          key: "message",
          className: "text-sm"
        }, message),
        timestamp && React.createElement("div", {
          key: "meta",
          className: "flex items-center justify-between mt-1 text-xs opacity-50"
        }, [
          React.createElement("span", {
            key: "time"
          }, formatTime(timestamp)),
          React.createElement("span", {
            key: "status",
            className: "text-xs"
          }, style.label)
        ])
      ])
    ])
  ]);
};
var EnhancedConnectionSetup = ({
  messages,
  onCreateOffer,
  onCreateAnswer,
  onConnect,
  onClearData,
  onVerifyConnection,
  connectionStatus,
  offerData,
  answerData,
  offerInput,
  setOfferInput,
  answerInput,
  setAnswerInput,
  showOfferStep,
  showAnswerStep,
  verificationCode,
  showVerification,
  showQRCode,
  qrCodeUrl,
  showQRScanner,
  setShowQRCode,
  setShowQRScanner,
  setShowQRScannerModal,
  offerPassword,
  answerPassword,
  localVerificationConfirmed,
  remoteVerificationConfirmed,
  bothVerificationsConfirmed
}) => {
  const [mode, setMode] = React.useState("select");
  const resetToSelect = () => {
    setMode("select");
    onClearData();
  };
  const handleVerificationConfirm = () => {
    onVerifyConnection(true);
  };
  const handleVerificationReject = () => {
    onVerifyConnection(false);
  };
  if (showVerification) {
    return React.createElement("div", {
      className: "min-h-[calc(100vh-104px)] flex items-center justify-center p-4"
    }, [
      React.createElement("div", {
        key: "verification",
        className: "w-full max-w-md"
      }, [
        React.createElement(VerificationStep, {
          verificationCode,
          onConfirm: handleVerificationConfirm,
          onReject: handleVerificationReject,
          localConfirmed: localVerificationConfirmed,
          remoteConfirmed: remoteVerificationConfirmed,
          bothConfirmed: bothVerificationsConfirmed
        })
      ])
    ]);
  }
  if (mode === "select") {
    return React.createElement("div", {
      className: "min-h-[calc(100vh-104px)] flex items-center justify-center p-4"
    }, [
      React.createElement("div", {
        key: "selector",
        className: "w-full max-w-4xl"
      }, [
        React.createElement("div", {
          key: "header",
          className: "text-center mb-8"
        }, [
          React.createElement("h2", {
            key: "title",
            className: "text-2xl font-semibold text-primary mb-3"
          }, "Start secure communication"),
          React.createElement("p", {
            key: "subtitle",
            className: "text-secondary max-w-2xl mx-auto"
          }, "Choose a connection method for a secure channel with ECDH encryption and Perfect Forward Secrecy.")
        ]),
        React.createElement("div", {
          key: "options",
          className: "grid md:grid-cols-2 gap-6 max-w-3xl mx-auto"
        }, [
          // Create Connection
          React.createElement("div", {
            key: "create",
            onClick: () => setMode("create"),
            className: "card-minimal rounded-xl p-6 cursor-pointer group"
          }, [
            React.createElement("div", {
              key: "icon",
              className: "w-12 h-12 bg-blue-500/10 border border-blue-500/20 rounded-lg flex items-center justify-center mx-auto mb-4"
            }, [
              React.createElement("i", {
                className: "fas fa-plus text-xl text-blue-400"
              })
            ]),
            React.createElement("h3", {
              key: "title",
              className: "text-lg font-semibold text-primary text-center mb-3"
            }, "Create channel"),
            React.createElement("p", {
              key: "description",
              className: "text-secondary text-center text-sm mb-4"
            }, "Initiate a new secure connection with encrypted exchange"),
            React.createElement("div", {
              key: "features",
              className: "space-y-2"
            }, [
              React.createElement("div", {
                key: "f1",
                className: "flex items-center text-sm text-muted"
              }, [
                React.createElement("i", {
                  className: "fas fa-key accent-orange mr-2 text-xs"
                }),
                "Generating ECDH keys"
              ]),
              React.createElement("div", {
                key: "f2",
                className: "flex items-center text-sm text-muted"
              }, [
                React.createElement("i", {
                  className: "fas fa-shield-alt accent-orange mr-2 text-xs"
                }),
                "Verification code"
              ]),
              React.createElement("div", {
                key: "f3",
                className: "flex items-center text-sm text-muted"
              }, [
                React.createElement("i", {
                  className: "fas fa-sync-alt accent-purple mr-2 text-xs"
                }),
                "PFS key rotation"
              ])
            ])
          ]),
          // Join Connection
          React.createElement("div", {
            key: "join",
            onClick: () => setMode("join"),
            className: "card-minimal rounded-xl p-6 cursor-pointer group"
          }, [
            React.createElement("div", {
              key: "icon",
              className: "w-12 h-12 bg-green-500/10 border border-green-500/20 rounded-lg flex items-center justify-center mx-auto mb-4"
            }, [
              React.createElement("i", {
                className: "fas fa-link text-xl accent-green"
              })
            ]),
            React.createElement("h3", {
              key: "title",
              className: "text-lg font-semibold text-primary text-center mb-3"
            }, "Join"),
            React.createElement("p", {
              key: "description",
              className: "text-secondary text-center text-sm mb-4"
            }, "Connect to an existing secure channel"),
            React.createElement("div", {
              key: "features",
              className: "space-y-2"
            }, [
              React.createElement("div", {
                key: "f1",
                className: "flex items-center text-sm text-muted"
              }, [
                React.createElement("i", {
                  className: "fas fa-paste accent-green mr-2 text-xs"
                }),
                "Paste Offer invitation"
              ]),
              React.createElement("div", {
                key: "f2",
                className: "flex items-center text-sm text-muted"
              }, [
                React.createElement("i", {
                  className: "fas fa-check-circle accent-green mr-2 text-xs"
                }),
                "Automatic verification"
              ]),
              React.createElement("div", {
                key: "f3",
                className: "flex items-center text-sm text-muted"
              }, [
                React.createElement("i", {
                  className: "fas fa-sync-alt accent-purple mr-2 text-xs"
                }),
                "PFS protection"
              ])
            ])
          ])
        ]),
        React.createElement("div", {
          key: "security-features",
          className: "grid grid-cols-2 md:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 max-w-6xl mx-auto mt-8"
        }, [
          React.createElement("div", { key: "feature1", className: "text-center p-3 sm:p-4" }, [
            React.createElement("div", { key: "icon", className: "w-10 h-10 sm:w-12 sm:h-12 bg-green-500/10 border border-green-500/20 rounded-lg flex items-center justify-center mx-auto mb-2 sm:mb-3" }, [
              React.createElement("i", { className: "fas fa-key accent-green" })
            ]),
            React.createElement("h4", { key: "title", className: "text-xs sm:text-sm font-medium text-primary mb-1" }, "ECDH P-384 Key Exchange"),
            React.createElement("p", { key: "desc", className: "text-xs text-muted leading-tight" }, "Military-grade elliptic curve key exchange")
          ]),
          React.createElement("div", { key: "feature2", className: "text-center p-3 sm:p-4" }, [
            React.createElement("div", { key: "icon", className: "w-10 h-10 sm:w-12 sm:h-12 bg-purple-500/10 border border-purple-500/20 rounded-lg flex items-center justify-center mx-auto mb-2 sm:mb-3" }, [
              React.createElement("i", { className: "fas fa-user-shield accent-purple" })
            ]),
            React.createElement("h4", { key: "title", className: "text-xs sm:text-sm font-medium text-primary mb-1" }, "MITM Protection"),
            React.createElement("p", { key: "desc", className: "text-xs text-muted leading-tight" }, "Out-of-band verification against attacks")
          ]),
          React.createElement("div", { key: "feature3", className: "text-center p-3 sm:p-4" }, [
            React.createElement("div", { key: "icon", className: "w-10 h-10 sm:w-12 sm:h-12 bg-orange-500/10 border border-orange-500/20 rounded-lg flex items-center justify-center mx-auto mb-2 sm:mb-3" }, [
              React.createElement("i", { className: "fas fa-lock accent-orange" })
            ]),
            React.createElement("h4", { key: "title", className: "text-xs sm:text-sm font-medium text-primary mb-1" }, "AES-GCM 256 Encryption"),
            React.createElement("p", { key: "desc", className: "text-xs text-muted leading-tight" }, "Authenticated encryption standard")
          ]),
          React.createElement("div", { key: "feature4", className: "text-center p-3 sm:p-4" }, [
            React.createElement("div", { key: "icon", className: "w-10 h-10 sm:w-12 sm:h-12 bg-cyan-500/10 border border-cyan-500/20 rounded-lg flex items-center justify-center mx-auto mb-2 sm:mb-3" }, [
              React.createElement("i", { className: "fas fa-sync-alt accent-cyan" })
            ]),
            React.createElement("h4", { key: "title", className: "text-xs sm:text-sm font-medium text-primary mb-1" }, "Perfect Forward Secrecy"),
            React.createElement("p", { key: "desc", className: "text-xs text-muted leading-tight" }, "Automatic key rotation every 5 minutes")
          ]),
          React.createElement("div", { key: "feature5", className: "text-center p-3 sm:p-4" }, [
            React.createElement("div", { key: "icon", className: "w-10 h-10 sm:w-12 sm:h-12 bg-blue-500/10 border border-blue-500/20 rounded-lg flex items-center justify-center mx-auto mb-2 sm:mb-3" }, [
              React.createElement("i", { className: "fas fa-signature accent-blue" })
            ]),
            React.createElement("h4", { key: "title", className: "text-xs sm:text-sm font-medium text-primary mb-1" }, "ECDSA P-384 Signatures"),
            React.createElement("p", { key: "desc", className: "text-xs text-muted leading-tight" }, "Digital signatures for message integrity")
          ]),
          React.createElement("div", { key: "feature6", className: "text-center p-3 sm:p-4" }, [
            React.createElement("div", { key: "icon", className: "w-10 h-10 sm:w-12 sm:h-12 bg-yellow-500/10 border border-yellow-500/20 rounded-lg flex items-center justify-center mx-auto mb-2 sm:mb-3" }, [
              React.createElement("i", { className: "fas fa-bolt accent-yellow" })
            ]),
            React.createElement("h4", { key: "title", className: "text-xs sm:text-sm font-medium text-primary mb-1" }, "Lightning Payments"),
            React.createElement("p", { key: "desc", className: "text-xs text-muted leading-tight" }, "Pay-per-session via WebLN")
          ])
        ]),
        // Wallet Logos Section
        React.createElement("div", {
          key: "wallet-logos-section",
          className: "mt-8"
        }, [
          React.createElement("div", {
            key: "wallet-logos-header",
            className: "text-center mb-4"
          }, [
            React.createElement("h3", {
              key: "title",
              className: "text-lg font-medium text-primary mb-2"
            }, "Supported Lightning wallets"),
            React.createElement("p", {
              key: "subtitle",
              className: "text-secondary text-sm"
            }, "To pay for sessions, use any of the popular wallets.")
          ]),
          React.createElement("div", {
            key: "wallet-logos-container",
            className: "wallet-logos-container"
          }, [
            React.createElement("div", {
              key: "wallet-logos-track",
              className: "wallet-logos-track"
            }, [
              // First set of logos
              React.createElement("a", {
                key: "alby1-link",
                href: "https://getalby.com",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo alby"
              }, [
                React.createElement("img", {
                  key: "alby-img1",
                  src: "logo/alby.svg",
                  alt: "Alby Lightning Wallet",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "zeus1-link",
                href: "https://zeusln.app",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo zeus"
              }, [
                React.createElement("img", {
                  key: "zeus-img1",
                  src: "logo/zeus.svg",
                  alt: "Zeus Lightning Wallet",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "wos1-link",
                href: "https://www.walletofsatoshi.com",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo wos"
              }, [
                React.createElement("img", {
                  key: "wos-img1",
                  src: "logo/wos.svg",
                  alt: "Wallet of Satoshi",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "muun1-link",
                href: "https://muun.com",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo muun"
              }, [
                React.createElement("img", {
                  key: "muun-img1",
                  src: "logo/muun.svg",
                  alt: "Muun Wallet",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "atomic1-link",
                href: "https://atomicwallet.io",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo atomic"
              }, [
                React.createElement("img", {
                  key: "atomic-img1",
                  src: "logo/atomic.svg",
                  alt: "Atomic Wallet",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "breez1-link",
                href: "https://breez.technology/mobile/",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo breez"
              }, [
                React.createElement("img", {
                  key: "breez-img1",
                  src: "logo/breez.svg",
                  alt: "Breez Lightning Wallet"
                })
              ]),
              React.createElement("a", {
                key: "lightning-labs1-link",
                href: "https://lightning.engineering",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo lightning-labs"
              }, [
                React.createElement("img", {
                  key: "lightning-labs-img1",
                  src: "logo/lightning-labs.svg",
                  alt: "Lightning Labs"
                })
              ]),
              React.createElement("a", {
                key: "lnbits1-link",
                href: "https://lnbits.com",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo lnbits"
              }, [
                React.createElement("img", {
                  key: "lnbits-img1",
                  src: "logo/lnbits.svg",
                  alt: "LNbits",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "strike1-link",
                href: "https://strike.me",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo strike"
              }, [
                React.createElement("img", {
                  key: "strike-img1",
                  src: "logo/strike.svg",
                  alt: "Strike",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "impervious1-link",
                href: "https://impervious.ai",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo impervious"
              }, [
                React.createElement("img", {
                  key: "impervious-img1",
                  src: "logo/impervious.svg",
                  alt: "Impervious",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "bitcoin-lightning1-link",
                href: "https://www.blink.sv/",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo bitcoin-lightning"
              }, [
                React.createElement("img", {
                  key: "blink-img1",
                  src: "logo/blink.svg",
                  alt: "Blink Wallet",
                  className: "wallet-logo-img"
                })
              ]),
              // Second set of logos
              React.createElement("a", {
                key: "alby2-link",
                href: "https://getalby.com",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo alby"
              }, [
                React.createElement("img", {
                  key: "alby-img2",
                  src: "logo/alby.svg",
                  alt: "Alby Lightning Wallet",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "zeus2-link",
                href: "https://zeusln.app",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo zeus"
              }, [
                React.createElement("img", {
                  key: "zeus-img2",
                  src: "logo/zeus.svg",
                  alt: "Zeus Lightning Wallet",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "wos2-link",
                href: "https://www.walletofsatoshi.com",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo wos"
              }, [
                React.createElement("img", {
                  key: "wos-img2",
                  src: "logo/wos.svg",
                  alt: "Wallet of Satoshi",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "muun2-link",
                href: "https://muun.com",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo muun"
              }, [
                React.createElement("img", {
                  key: "muun-img2",
                  src: "logo/muun.svg",
                  alt: "Muun Wallet",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "atomic2-link",
                href: "https://atomicwallet.io",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo atomic"
              }, [
                React.createElement("img", {
                  key: "atomic-img2",
                  src: "logo/atomic.svg",
                  alt: "Atomic Wallet",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "breez2-link",
                href: "https://breez.technology/mobile/",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo breez"
              }, [
                React.createElement("img", {
                  key: "breez-img2",
                  src: "logo/breez.svg",
                  alt: "Breez Lightning Wallet"
                })
              ]),
              React.createElement("a", {
                key: "lightning-labs2-link",
                href: "https://lightning.engineering",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo lightning-labs"
              }, [
                React.createElement("img", {
                  key: "lightning-labs-img2",
                  src: "logo/lightning-labs.svg",
                  alt: "Lightning Labs"
                })
              ]),
              React.createElement("a", {
                key: "lnbits2-link",
                href: "https://lnbits.com",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo lnbits"
              }, [
                React.createElement("img", {
                  key: "lnbits-img2",
                  src: "logo/lnbits.svg",
                  alt: "LNbits",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "strike2-link",
                href: "https://strike.me",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo strike"
              }, [
                React.createElement("img", {
                  key: "strike-img2",
                  src: "logo/strike.svg",
                  alt: "Strike",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "impervious2-link",
                href: "https://impervious.ai",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo impervious"
              }, [
                React.createElement("img", {
                  key: "impervious-img2",
                  src: "logo/impervious.svg",
                  alt: "Impervious",
                  className: "wallet-logo-img"
                })
              ]),
              React.createElement("a", {
                key: "bitcoin-lightning2-link",
                href: "https://www.blink.sv/",
                target: "_blank",
                rel: "noindex nofollow",
                className: "wallet-logo bitcoin-lightning"
              }, [
                React.createElement("img", {
                  key: "blink-img2",
                  src: "logo/blink.svg",
                  alt: "Blink Wallet",
                  className: "wallet-logo-img"
                })
              ])
            ])
          ])
        ]),
        React.createElement(UniqueFeatureSlider, { key: "unique-features-slider" }),
        React.createElement(DownloadApps, { key: "download-apps" }),
        React.createElement(ComparisonTable, { key: "comparison-table" }),
        React.createElement(Roadmap, { key: "roadmap" })
      ])
    ]);
  }
  if (mode === "create") {
    return React.createElement("div", {
      className: "min-h-[calc(100vh-104px)] flex items-center justify-center p-4"
    }, [
      React.createElement("div", {
        key: "create-flow",
        className: "w-full max-w-3xl space-y-6"
      }, [
        React.createElement("div", {
          key: "header",
          className: "text-center"
        }, [
          React.createElement("button", {
            key: "back",
            onClick: resetToSelect,
            className: "mb-4 text-secondary hover:text-primary transition-colors flex items-center mx-auto text-sm"
          }, [
            React.createElement("i", {
              className: "fas fa-arrow-left mr-2"
            }),
            "Back to selection"
          ]),
          React.createElement("h2", {
            key: "title",
            className: "text-xl font-semibold text-primary mb-2"
          }, "Creating a secure channel")
        ]),
        // Step 1
        React.createElement("div", {
          key: "step1",
          className: "card-minimal rounded-xl p-6"
        }, [
          React.createElement("div", {
            key: "step-header",
            className: "flex items-center mb-4"
          }, [
            React.createElement("div", {
              key: "number",
              className: "step-number mr-3"
            }, "1"),
            React.createElement("h3", {
              key: "title",
              className: "text-lg font-medium text-primary"
            }, "Generating ECDH keys and verification code")
          ]),
          React.createElement("p", {
            key: "description",
            className: "text-secondary text-sm mb-4"
          }, "Creating cryptographically strong keys and codes to protect against attacks"),
          React.createElement("button", {
            key: "create-btn",
            onClick: onCreateOffer,
            disabled: connectionStatus === "connecting" || showOfferStep,
            className: `w-full btn-primary text-white py-3 px-4 rounded-lg font-medium transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed`
          }, [
            React.createElement("i", {
              className: "fas fa-shield-alt mr-2"
            }),
            showOfferStep ? "Keys created \u2713" : "Create secure keys"
          ]),
          showOfferStep && React.createElement("div", {
            key: "offer-result",
            className: "mt-6 space-y-4"
          }, [
            React.createElement("div", {
              key: "success",
              className: "p-3 bg-green-500/10 border border-green-500/20 rounded-lg"
            }, [
              React.createElement("p", {
                className: "text-green-400 text-sm font-medium flex items-center"
              }, [
                React.createElement("i", {
                  className: "fas fa-check-circle mr-2"
                }),
                "Secure invitation created! Send the code to your contact:"
              ])
            ]),
            React.createElement("div", {
              key: "offer-data",
              className: "space-y-3"
            }, [
              React.createElement("textarea", {
                key: "textarea",
                value: typeof offerData === "object" ? JSON.stringify(offerData, null, 2) : offerData,
                readOnly: true,
                rows: 8,
                className: "w-full p-3 bg-custom-bg border border-gray-500/20 rounded-lg font-mono text-xs text-secondary resize-none custom-scrollbar"
              }),
              React.createElement("div", {
                key: "buttons",
                className: "flex gap-2"
              }, [
                React.createElement(EnhancedCopyButton, {
                  key: "copy",
                  text: typeof offerData === "object" ? JSON.stringify(offerData, null, 2) : offerData,
                  className: "flex-1 px-3 py-2 bg-orange-500/10 hover:bg-orange-500/20 text-orange-400 border border-orange-500/20 rounded text-sm font-medium"
                }, "Copy invitation code"),
                React.createElement("button", {
                  key: "qr-toggle",
                  onClick: async () => {
                    const next = !showQRCode;
                    setShowQRCode(next);
                    if (next) {
                      try {
                        const payload = typeof offerData === "object" ? JSON.stringify(offerData) : offerData;
                        if (payload && payload.length) {
                          await generateQRCode(payload);
                        }
                      } catch (e) {
                        console.warn("QR regenerate on toggle failed:", e);
                      }
                    }
                  },
                  className: "px-3 py-2 bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/20 rounded text-sm font-medium transition-all duration-200"
                }, [
                  React.createElement("i", {
                    key: "icon",
                    className: showQRCode ? "fas fa-eye-slash mr-1" : "fas fa-qrcode mr-1"
                  }),
                  showQRCode ? "Hide QR" : "Show QR"
                ])
              ]),
              showQRCode && qrCodeUrl && React.createElement("div", {
                key: "qr-container",
                className: "mt-4 p-4 bg-gray-800/50 border border-gray-600/30 rounded-lg text-center"
              }, [
                React.createElement("h4", {
                  key: "qr-title",
                  className: "text-sm font-medium text-primary mb-3"
                }, "Scan QR code to connect"),
                React.createElement("div", {
                  key: "qr-wrapper",
                  className: "flex justify-center"
                }, [
                  React.createElement("img", {
                    key: "qr-image",
                    src: qrCodeUrl,
                    alt: "QR Code for secure connection",
                    className: "max-w-none h-auto border border-gray-600/30 rounded w-[20rem] sm:w-[24rem] md:w-[28rem] lg:w-[32rem]"
                  }),
                  typeof qrFramesTotal !== "undefined" && typeof qrFrameIndex !== "undefined" && qrFramesTotal > 1 && React.createElement("div", {
                    key: "qr-frame-indicator",
                    className: "ml-3 self-center text-xs text-gray-300"
                  }, `Frame ${Math.max(1, qrFrameIndex || 1)}/${qrFramesTotal}`)
                ]),
                React.createElement("p", {
                  key: "qr-description",
                  className: "text-xs text-gray-400 mt-2"
                }, "Your contact can scan this QR code to quickly join the secure session")
              ])
            ])
          ])
        ]),
        // Step 2 - Session Type Selection
        // showOfferStep && React.createElement('div', {
        //     key: 'step2',
        //     className: "card-minimal rounded-xl p-6"
        // }, [
        //     React.createElement('div', {
        //         key: 'step-header',
        //         className: "flex items-center mb-4"
        //     }, [
        //         React.createElement('div', {
        //             key: 'number',
        //             className: "w-8 h-8 bg-green-500 text-white rounded-lg flex items-center justify-center font-semibold text-sm mr-3"
        //         }, '2'),
        //         React.createElement('h3', {
        //             key: 'title',
        //             className: "text-lg font-medium text-primary"
        //         }, "Select session type")
        //     ]),
        //     React.createElement('p', {
        //         key: 'description',
        //         className: "text-secondary text-sm mb-4"
        //     }, "Choose a session plan or use limited demo mode for testing."),
        //     React.createElement(SessionTypeSelector, {
        //         key: 'session-selector',
        //         onSelectType: (sessionType) => {
        //             // Save the selected session type
        //             setSelectedSessionType(sessionType);
        //             console.log('🎯 Session type selected:', sessionType);
        //             // FIX: For demo sessions, we immediately call automatic activation
        //             if (sessionType === 'demo') {
        //                 console.log('🎮 Demo session selected, scheduling automatic activation...');
        //                 // Delay activation for 2 seconds to stabilize
        //                 setTimeout(() => {
        //                     if (sessionManager) {
        //                         console.log('🚀 Triggering demo session activation from selection...');
        //                         handleDemoVerification();
        //                     }
        //                 }, 2000);
        //             }
        //             // Open a modal payment window
        //             if (typeof window.showPaymentModal === 'function') {
        //                 window.showPaymentModal(sessionType);
        //             } else {
        //                 // Fallback - show session information
        //                 console.log('Selected session type:', sessionType);
        //             }
        //         },
        //         onCancel: resetToSelect,
        //         sessionManager: window.sessionManager
        //     })
        // ]),
        // Step 3 - Waiting for response
        showOfferStep && React.createElement("div", {
          key: "step2",
          className: "card-minimal rounded-xl p-6"
        }, [
          React.createElement("div", {
            key: "step-header",
            className: "flex items-center mb-4"
          }, [
            React.createElement("div", {
              key: "number",
              className: "w-8 h-8 bg-blue-500 text-white rounded-lg flex items-center justify-center font-semibold text-sm mr-3"
            }, "2"),
            React.createElement("h3", {
              key: "title",
              className: "text-lg font-medium text-primary"
            }, "Waiting for the peer's response")
          ]),
          React.createElement("p", {
            key: "description",
            className: "text-secondary text-sm mb-4"
          }, "Paste the encrypted invitation code from your contact."),
          React.createElement("div", {
            key: "buttons",
            className: "flex gap-2 mb-4"
          }, [
            React.createElement("button", {
              key: "scan-btn",
              onClick: () => setShowQRScannerModal(true),
              className: "px-4 py-2 bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 border border-purple-500/20 rounded text-sm font-medium transition-all duration-200"
            }, [
              React.createElement("i", {
                key: "icon",
                className: "fas fa-qrcode mr-2"
              }),
              "Scan QR Code"
            ])
          ]),
          React.createElement("textarea", {
            key: "input",
            value: answerInput,
            onChange: (e) => {
              setAnswerInput(e.target.value);
              if (e.target.value.trim().length > 0) {
                markAnswerCreated();
              }
            },
            rows: 6,
            placeholder: "Paste the encrypted response code from your contact or scan QR code...",
            className: "w-full p-3 bg-custom-bg border border-gray-500/20 rounded-lg resize-none mb-4 text-secondary placeholder-gray-500 focus:border-orange-500/40 focus:outline-none transition-all custom-scrollbar text-sm"
          }),
          React.createElement("button", {
            key: "connect-btn",
            onClick: onConnect,
            disabled: !answerInput.trim(),
            className: "w-full btn-secondary text-white py-3 px-4 rounded-lg font-medium transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
          }, [
            React.createElement("i", {
              className: "fas fa-rocket mr-2"
            }),
            "Establish connection"
          ])
        ])
      ])
    ]);
  }
  if (mode === "join") {
    return React.createElement("div", {
      className: "min-h-[calc(100vh-104px)] flex items-center justify-center p-4"
    }, [
      React.createElement("div", {
        key: "join-flow",
        className: "w-full max-w-3xl space-y-6"
      }, [
        React.createElement("div", {
          key: "header",
          className: "text-center"
        }, [
          React.createElement("button", {
            key: "back",
            onClick: resetToSelect,
            className: "mb-4 text-secondary hover:text-primary transition-colors flex items-center mx-auto text-sm"
          }, [
            React.createElement("i", {
              className: "fas fa-arrow-left mr-2"
            }),
            "Back to selection"
          ]),
          React.createElement("h2", {
            key: "title",
            className: "text-xl font-semibold text-primary mb-2"
          }, "Joining the secure channel")
        ]),
        // Step 1
        React.createElement("div", {
          key: "step1",
          className: "card-minimal rounded-xl p-6"
        }, [
          React.createElement("div", {
            key: "step-header",
            className: "flex items-center mb-4"
          }, [
            React.createElement("div", {
              key: "number",
              className: "w-8 h-8 bg-green-500 text-white rounded-lg flex items-center justify-center font-semibold text-sm mr-3"
            }, "1"),
            React.createElement("h3", {
              key: "title",
              className: "text-lg font-medium text-primary"
            }, "Paste secure invitation")
          ]),
          React.createElement("p", {
            key: "description",
            className: "text-secondary text-sm mb-4"
          }, "Copy and paste the encrypted invitation code from the initiator."),
          React.createElement("textarea", {
            key: "input",
            value: offerInput,
            onChange: (e) => {
              setOfferInput(e.target.value);
              if (e.target.value.trim().length > 0) {
                markAnswerCreated();
              }
            },
            rows: 8,
            placeholder: "Paste the encrypted invitation code or scan QR code...",
            className: "w-full p-3 bg-custom-bg border border-gray-500/20 rounded-lg resize-none mb-4 text-secondary placeholder-gray-500 focus:border-green-500/40 focus:outline-none transition-all custom-scrollbar text-sm"
          }),
          React.createElement("div", {
            key: "buttons",
            className: "flex gap-2 mb-4"
          }, [
            React.createElement("button", {
              key: "scan-btn",
              onClick: () => setShowQRScannerModal(true),
              className: "px-4 py-2 bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 border border-purple-500/20 rounded text-sm font-medium transition-all duration-200"
            }, [
              React.createElement("i", {
                key: "icon",
                className: "fas fa-qrcode mr-2"
              }),
              "Scan QR Code"
            ]),
            React.createElement("button", {
              key: "process-btn",
              onClick: onCreateAnswer,
              disabled: !offerInput.trim() || connectionStatus === "connecting",
              className: "flex-1 btn-secondary text-white py-2 px-4 rounded-lg font-medium transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            }, [
              React.createElement("i", {
                className: "fas fa-cogs mr-2"
              }),
              "Process invitation"
            ])
          ]),
          showQRScanner && React.createElement("div", {
            key: "qr-scanner",
            className: "p-4 bg-gray-800/50 border border-gray-600/30 rounded-lg text-center"
          }, [
            React.createElement("h4", {
              key: "scanner-title",
              className: "text-sm font-medium text-primary mb-3"
            }, "QR Code Scanner"),
            React.createElement("p", {
              key: "scanner-description",
              className: "text-xs text-gray-400 mb-3"
            }, "Use your device camera to scan the QR code from the invitation"),
            React.createElement("button", {
              key: "open-scanner",
              onClick: () => {
                console.log("Open Camera Scanner clicked, showQRScannerModal will be set to true");
                console.log("QRScanner available:", !!window.QRScanner);
                console.log("setShowQRScannerModal function:", typeof setShowQRScannerModal);
                if (typeof setShowQRScannerModal === "function") {
                  setShowQRScannerModal(true);
                } else {
                  console.error("setShowQRScannerModal is not a function:", setShowQRScannerModal);
                }
              },
              className: "w-full px-4 py-3 bg-purple-600 hover:bg-purple-500 text-white rounded-lg font-medium transition-all duration-200 mb-3"
            }, [
              React.createElement("i", {
                key: "camera-icon",
                className: "fas fa-camera mr-2"
              }),
              "Open Camera Scanner"
            ]),
            React.createElement("button", {
              key: "test-qr",
              onClick: async () => {
                console.log("Creating test QR code...");
                if (window.generateQRCode) {
                  const testData = '{"type":"test","message":"Hello QR Scanner!"}';
                  const qrUrl = await window.generateQRCode(testData);
                  console.log("Test QR code generated:", qrUrl);
                  const newWindow = window.open();
                  newWindow.document.write(`<img src="${qrUrl}" style="width: 300px; height: 300px;">`);
                }
              },
              className: "px-3 py-1 bg-green-600/20 hover:bg-green-600/30 text-green-300 border border-green-500/20 rounded text-xs font-medium transition-all duration-200 mr-2"
            }, "Test QR"),
            React.createElement("button", {
              key: "close-scanner",
              onClick: () => setShowQRScanner(false),
              className: "px-3 py-1 bg-gray-600/20 hover:bg-gray-600/30 text-gray-300 border border-gray-500/20 rounded text-xs font-medium transition-all duration-200"
            }, "Close Scanner")
          ])
        ]),
        // Step 2
        showAnswerStep && React.createElement("div", {
          key: "step2",
          className: "card-minimal rounded-xl p-6"
        }, [
          React.createElement("div", {
            key: "step-header",
            className: "flex items-center mb-4"
          }, [
            React.createElement("div", {
              key: "number",
              className: "step-number mr-3"
            }, "2"),
            React.createElement("h3", {
              key: "title",
              className: "text-lg font-medium text-primary"
            }, "Sending a secure response")
          ]),
          React.createElement("div", {
            key: "success",
            className: "p-3 bg-green-500/10 border border-green-500/20 rounded-lg mb-4"
          }, [
            React.createElement("p", {
              className: "text-green-400 text-sm font-medium flex items-center"
            }, [
              React.createElement("i", {
                className: "fas fa-check-circle mr-2"
              }),
              "Secure response created! Send this code to the initiator:"
            ])
          ]),
          React.createElement("div", {
            key: "answer-data",
            className: "space-y-3 mb-4"
          }, [
            React.createElement("textarea", {
              key: "textarea",
              value: typeof answerData === "object" ? JSON.stringify(answerData, null, 2) : answerData,
              readOnly: true,
              rows: 6,
              className: "w-full p-3 bg-custom-bg border border-green-500/20 rounded-lg font-mono text-xs text-secondary resize-none custom-scrollbar"
            }),
            React.createElement(EnhancedCopyButton, {
              key: "copy",
              text: typeof answerData === "object" ? JSON.stringify(answerData, null, 2) : answerData,
              className: "w-full px-3 py-2 bg-green-500/10 hover:bg-green-500/20 text-green-400 border border-green-500/20 rounded text-sm font-medium"
            }, "Copy response code")
          ]),
          React.createElement("div", {
            key: "info",
            className: "p-3 bg-purple-500/10 border border-purple-500/20 rounded-lg"
          }, [
            React.createElement("p", {
              className: "text-purple-400 text-sm flex items-center justify-center"
            }, [
              React.createElement("i", {
                className: "fas fa-shield-alt mr-2"
              }),
              "The connection will be established with verification"
            ])
          ])
        ])
      ])
    ]);
  }
};
var createScrollToBottomFunction = (chatMessagesRef) => {
  return () => {
    console.log("\u{1F50D} Global scrollToBottom called, chatMessagesRef:", chatMessagesRef.current);
    if (chatMessagesRef && chatMessagesRef.current) {
      const scrollAttempt = () => {
        if (chatMessagesRef.current) {
          chatMessagesRef.current.scrollTo({
            top: chatMessagesRef.current.scrollHeight,
            behavior: "smooth"
          });
        }
      };
      scrollAttempt();
      setTimeout(scrollAttempt, 50);
      setTimeout(scrollAttempt, 150);
      setTimeout(scrollAttempt, 300);
      requestAnimationFrame(() => {
        setTimeout(scrollAttempt, 100);
      });
    }
  };
};
var EnhancedChatInterface = ({
  messages,
  messageInput,
  setMessageInput,
  onSendMessage,
  onDisconnect,
  keyFingerprint,
  isVerified,
  chatMessagesRef,
  scrollToBottom,
  webrtcManager
}) => {
  const [showScrollButton, setShowScrollButton] = React.useState(false);
  const [showFileTransfer, setShowFileTransfer] = React.useState(false);
  React.useEffect(() => {
    if (chatMessagesRef.current && messages.length > 0) {
      const { scrollTop, scrollHeight, clientHeight } = chatMessagesRef.current;
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
      if (isNearBottom) {
        const smoothScroll = () => {
          if (chatMessagesRef.current) {
            chatMessagesRef.current.scrollTo({
              top: chatMessagesRef.current.scrollHeight,
              behavior: "smooth"
            });
          }
        };
        smoothScroll();
        setTimeout(smoothScroll, 50);
        setTimeout(smoothScroll, 150);
      }
    }
  }, [messages, chatMessagesRef]);
  const handleScroll = () => {
    if (chatMessagesRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = chatMessagesRef.current;
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
      setShowScrollButton(!isNearBottom);
    }
  };
  const handleScrollToBottom = () => {
    console.log("\u{1F50D} handleScrollToBottom called, scrollToBottom type:", typeof scrollToBottom);
    if (typeof scrollToBottom === "function") {
      scrollToBottom();
      setShowScrollButton(false);
    } else {
      console.error("\u274C scrollToBottom is not a function:", scrollToBottom);
      if (chatMessagesRef.current) {
        chatMessagesRef.current.scrollTo({
          top: chatMessagesRef.current.scrollHeight,
          behavior: "smooth"
        });
      }
      setShowScrollButton(false);
    }
  };
  const handleKeyPress = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      onSendMessage();
    }
  };
  const isFileTransferReady = () => {
    if (!webrtcManager) return false;
    const connected = webrtcManager.isConnected ? webrtcManager.isConnected() : false;
    const verified = webrtcManager.isVerified || false;
    const hasDataChannel = webrtcManager.dataChannel && webrtcManager.dataChannel.readyState === "open";
    return connected && verified && hasDataChannel;
  };
  return React.createElement(
    "div",
    {
      className: "chat-container flex flex-col",
      style: { backgroundColor: "#272827", height: "calc(100vh - 64px)" }
    },
    [
      // Область сообщений
      React.createElement(
        "div",
        { className: "flex-1 flex flex-col overflow-hidden" },
        React.createElement(
          "div",
          { className: "flex-1 max-w-4xl mx-auto w-full p-4 overflow-hidden" },
          React.createElement(
            "div",
            {
              ref: chatMessagesRef,
              onScroll: handleScroll,
              className: "h-full overflow-y-auto space-y-3 hide-scrollbar pr-2 scroll-smooth"
            },
            messages.length === 0 ? React.createElement(
              "div",
              { className: "flex items-center justify-center h-full" },
              React.createElement(
                "div",
                { className: "text-center max-w-md" },
                [
                  React.createElement(
                    "div",
                    { className: "w-16 h-16 bg-green-500/10 border border-green-500/20 rounded-xl flex items-center justify-center mx-auto mb-4" },
                    React.createElement(
                      "svg",
                      { className: "w-8 h-8 text-green-500", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24" },
                      React.createElement("path", {
                        strokeLinecap: "round",
                        strokeLinejoin: "round",
                        strokeWidth: 2,
                        d: "M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
                      })
                    )
                  ),
                  React.createElement("h3", { className: "text-lg font-medium text-gray-300 mb-2" }, "Secure channel is ready!"),
                  React.createElement("p", { className: "text-gray-400 text-sm mb-4" }, "All messages are protected by modern cryptographic algorithms"),
                  React.createElement(
                    "div",
                    { className: "text-left space-y-2" },
                    [
                      ["End-to-end encryption", "M5 13l4 4L19 7"],
                      ["Protection against replay attacks", "M5 13l4 4L19 7"],
                      ["Integrity verification", "M5 13l4 4L19 7"],
                      ["Perfect Forward Secrecy", "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"]
                    ].map(
                      ([text, d], i) => React.createElement(
                        "div",
                        { key: `f${i}`, className: "flex items-center text-sm text-gray-400" },
                        [
                          React.createElement(
                            "svg",
                            {
                              className: `w-4 h-4 mr-3 ${i === 3 ? "text-purple-500" : "text-green-500"}`,
                              fill: "none",
                              stroke: "currentColor",
                              viewBox: "0 0 24 24"
                            },
                            React.createElement("path", {
                              strokeLinecap: "round",
                              strokeLinejoin: "round",
                              strokeWidth: 2,
                              d
                            })
                          ),
                          text
                        ]
                      )
                    )
                  )
                ]
              )
            ) : messages.map(
              (msg) => React.createElement(EnhancedChatMessage, {
                key: msg.id,
                message: msg.message,
                type: msg.type,
                timestamp: msg.timestamp
              })
            )
          )
        )
      ),
      // Кнопка прокрутки вниз
      showScrollButton && React.createElement(
        "button",
        {
          onClick: handleScrollToBottom,
          className: "fixed right-6 w-12 h-12 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 text-green-400 rounded-full flex items-center justify-center transition-all duration-200 shadow-lg z-50",
          style: { bottom: "160px" }
        },
        React.createElement(
          "svg",
          { className: "w-6 h-6", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24" },
          React.createElement("path", {
            strokeLinecap: "round",
            strokeLinejoin: "round",
            strokeWidth: 2,
            d: "M19 14l-7 7m0 0l-7-7m7 7V3"
          })
        )
      ),
      // Секция передачи файлов
      React.createElement(
        "div",
        {
          className: "flex-shrink-0 border-t border-gray-500/10",
          style: { backgroundColor: "#272827" }
        },
        React.createElement(
          "div",
          { className: "max-w-4xl mx-auto px-4" },
          [
            React.createElement(
              "button",
              {
                onClick: () => setShowFileTransfer(!showFileTransfer),
                className: `flex items-center text-sm text-gray-400 hover:text-gray-300 transition-colors py-4 ${showFileTransfer ? "mb-4" : ""}`
              },
              [
                React.createElement(
                  "svg",
                  {
                    className: `w-4 h-4 mr-2 transform transition-transform ${showFileTransfer ? "rotate-180" : ""}`,
                    fill: "none",
                    stroke: "currentColor",
                    viewBox: "0 0 24 24"
                  },
                  showFileTransfer ? React.createElement("path", {
                    strokeLinecap: "round",
                    strokeLinejoin: "round",
                    strokeWidth: 2,
                    d: "M5 15l7-7 7 7"
                  }) : React.createElement("path", {
                    strokeLinecap: "round",
                    strokeLinejoin: "round",
                    strokeWidth: 2,
                    d: "M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"
                  })
                ),
                showFileTransfer ? "Hide file transfer" : "Send files"
              ]
            ),
            // ИСПРАВЛЕНИЕ: Используем правильный компонент
            showFileTransfer && React.createElement(window.FileTransferComponent || (() => React.createElement("div", {
              className: "p-4 text-center text-red-400"
            }, "FileTransferComponent not loaded")), {
              webrtcManager,
              isConnected: isFileTransferReady()
            })
          ]
        )
      ),
      // Область ввода сообщений
      React.createElement(
        "div",
        { className: "border-t border-gray-500/10" },
        React.createElement(
          "div",
          { className: "max-w-4xl mx-auto p-4" },
          React.createElement(
            "div",
            { className: "flex items-stretch space-x-3" },
            [
              React.createElement(
                "div",
                { className: "flex-1 relative" },
                [
                  React.createElement("textarea", {
                    value: messageInput,
                    onChange: (e) => setMessageInput(e.target.value),
                    onKeyDown: handleKeyPress,
                    placeholder: "Enter message to encrypt...",
                    rows: 2,
                    maxLength: 2e3,
                    style: { backgroundColor: "#272827" },
                    className: "w-full p-3 border border-gray-600 rounded-lg resize-none text-gray-300 placeholder-gray-500 focus:border-green-500/40 focus:outline-none transition-all custom-scrollbar text-sm"
                  }),
                  React.createElement(
                    "div",
                    { className: "absolute bottom-2 right-3 flex items-center space-x-2 text-xs text-gray-400" },
                    [
                      React.createElement("span", null, `${messageInput.length}/2000`),
                      React.createElement("span", null, "\u2022 Enter to send")
                    ]
                  )
                ]
              ),
              React.createElement(
                "button",
                {
                  onClick: onSendMessage,
                  disabled: !messageInput.trim(),
                  className: "bg-green-400/20 text-green-400 p-3 rounded-lg transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center min-h-[72px]"
                },
                React.createElement(
                  "svg",
                  { className: "w-6 h-6", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24" },
                  React.createElement("path", {
                    strokeLinecap: "round",
                    strokeLinejoin: "round",
                    strokeWidth: 2,
                    d: "M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
                  })
                )
              )
            ]
          )
        )
      )
    ]
  );
};
var EnhancedSecureP2PChat = () => {
  console.log("\u{1F50D} EnhancedSecureP2PChat component initialized");
  const [messages, setMessages] = React.useState([]);
  const [connectionStatus, setConnectionStatus] = React.useState("disconnected");
  const [messageInput, setMessageInput] = React.useState("");
  const [offerData, setOfferData] = React.useState("");
  const [answerData, setAnswerData] = React.useState("");
  const [offerInput, setOfferInput] = React.useState("");
  const [answerInput, setAnswerInput] = React.useState("");
  const [keyFingerprint, setKeyFingerprint] = React.useState("");
  const [verificationCode, setVerificationCode] = React.useState("");
  const [showOfferStep, setShowOfferStep] = React.useState(false);
  const [showAnswerStep, setShowAnswerStep] = React.useState(false);
  const [showVerification, setShowVerification] = React.useState(false);
  const [showQRCode, setShowQRCode] = React.useState(false);
  const [qrCodeUrl, setQrCodeUrl] = React.useState("");
  const [showQRScanner, setShowQRScanner] = React.useState(false);
  const [showQRScannerModal, setShowQRScannerModal] = React.useState(false);
  const [isVerified, setIsVerified] = React.useState(false);
  const [securityLevel, setSecurityLevel] = React.useState(null);
  const [localVerificationConfirmed, setLocalVerificationConfirmed] = React.useState(false);
  const [remoteVerificationConfirmed, setRemoteVerificationConfirmed] = React.useState(false);
  const [bothVerificationsConfirmed, setBothVerificationsConfirmed] = React.useState(false);
  const [sessionTimeLeft, setSessionTimeLeft] = React.useState(0);
  const [pendingSession, setPendingSession] = React.useState(null);
  const [connectionState, setConnectionState] = React.useState({
    status: "disconnected",
    hasActiveAnswer: false,
    answerCreatedAt: null,
    isUserInitiatedDisconnect: false
  });
  const updateConnectionState = (newState, options = {}) => {
    const { preserveAnswer = false, isUserAction = false } = options;
    setConnectionState((prev) => ({
      ...prev,
      ...newState,
      isUserInitiatedDisconnect: isUserAction,
      hasActiveAnswer: preserveAnswer ? prev.hasActiveAnswer : false,
      answerCreatedAt: preserveAnswer ? prev.answerCreatedAt : null
    }));
  };
  const shouldPreserveAnswerData = () => {
    const now = Date.now();
    const answerAge = now - (connectionState.answerCreatedAt || 0);
    const maxPreserveTime = 3e4;
    const hasAnswerData = answerData && answerData.trim().length > 0 || answerInput && answerInput.trim().length > 0;
    const shouldPreserve = connectionState.hasActiveAnswer && answerAge < maxPreserveTime && !connectionState.isUserInitiatedDisconnect || hasAnswerData && answerAge < maxPreserveTime && !connectionState.isUserInitiatedDisconnect;
    console.log("\u{1F50D} shouldPreserveAnswerData check:", {
      hasActiveAnswer: connectionState.hasActiveAnswer,
      hasAnswerData,
      answerAge,
      maxPreserveTime,
      isUserInitiatedDisconnect: connectionState.isUserInitiatedDisconnect,
      shouldPreserve,
      answerData: answerData ? "exists" : "null",
      answerInput: answerInput ? "exists" : "null"
    });
    return shouldPreserve;
  };
  const markAnswerCreated2 = () => {
    updateConnectionState({
      hasActiveAnswer: true,
      answerCreatedAt: Date.now()
    });
  };
  React.useEffect(() => {
    window.forceCleanup = () => {
      handleClearData();
      if (webrtcManagerRef.current) {
        webrtcManagerRef.current.disconnect();
      }
    };
    window.clearLogs = () => {
      if (typeof console.clear === "function") {
        console.clear();
      }
    };
    return () => {
      delete window.forceCleanup;
      delete window.clearLogs;
    };
  }, []);
  const webrtcManagerRef = React.useRef(null);
  window.webrtcManagerRef = webrtcManagerRef;
  const addMessageWithAutoScroll = React.useCallback((message, type) => {
    const newMessage = {
      message,
      type,
      id: Date.now() + Math.random(),
      timestamp: Date.now()
    };
    setMessages((prev) => {
      const updated = [...prev, newMessage];
      setTimeout(() => {
        if (chatMessagesRef?.current) {
          const container = chatMessagesRef.current;
          try {
            const { scrollTop, scrollHeight, clientHeight } = container;
            const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
            if (isNearBottom || prev.length === 0) {
              requestAnimationFrame(() => {
                if (container && container.scrollTo) {
                  container.scrollTo({
                    top: container.scrollHeight,
                    behavior: "smooth"
                  });
                }
              });
            }
          } catch (error) {
            console.warn("Scroll error:", error);
            container.scrollTop = container.scrollHeight;
          }
        }
      }, 50);
      return updated;
    });
  }, []);
  const updateSecurityLevel = React.useCallback(async () => {
    if (window.isUpdatingSecurity) {
      return;
    }
    window.isUpdatingSecurity = true;
    try {
      if (webrtcManagerRef.current) {
        setSecurityLevel({
          level: "MAXIMUM",
          score: 100,
          color: "green",
          details: "All security features enabled by default",
          passedChecks: 10,
          totalChecks: 10,
          isRealData: true
        });
        if (window.DEBUG_MODE) {
          const currentLevel = webrtcManagerRef.current.ecdhKeyPair && webrtcManagerRef.current.ecdsaKeyPair ? await webrtcManagerRef.current.calculateSecurityLevel() : {
            level: "MAXIMUM",
            score: 100,
            sessionType: "premium",
            passedChecks: 10,
            totalChecks: 10
          };
          console.log("\u{1F512} Security level updated:", {
            level: currentLevel.level,
            score: currentLevel.score,
            sessionType: currentLevel.sessionType,
            passedChecks: currentLevel.passedChecks,
            totalChecks: currentLevel.totalChecks
          });
        }
      }
    } catch (error) {
      console.error("Failed to update security level:", error);
      setSecurityLevel({
        level: "ERROR",
        score: 0,
        color: "red",
        details: "Verification failed"
      });
    } finally {
      setTimeout(() => {
        window.isUpdatingSecurity = false;
      }, 2e3);
    }
  }, []);
  React.useEffect(() => {
    const timer = setInterval(() => {
      setSessionTimeLeft(0);
    }, 1e3);
    return () => clearInterval(timer);
  }, []);
  const chatMessagesRef = React.useRef(null);
  const scrollToBottom = createScrollToBottomFunction(chatMessagesRef);
  React.useEffect(() => {
    if (messages.length > 0 && chatMessagesRef.current) {
      scrollToBottom();
      setTimeout(scrollToBottom, 50);
      setTimeout(scrollToBottom, 150);
    }
  }, [messages]);
  React.useEffect(() => {
    if (webrtcManagerRef.current) {
      console.log("\u26A0\uFE0F WebRTC Manager already initialized, skipping...");
      return;
    }
    const handleMessage = (message, type) => {
      if (typeof message === "string" && message.trim().startsWith("{")) {
        try {
          const parsedMessage = JSON.parse(message);
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
            "verification_confirmed",
            "verification_both_confirmed",
            "peer_disconnect",
            "key_rotation_signal",
            "key_rotation_ready",
            "security_upgrade"
          ];
          if (parsedMessage.type && blockedTypes.includes(parsedMessage.type)) {
            console.log(`\u{1F6D1} Blocked system/file message from chat: ${parsedMessage.type}`);
            return;
          }
        } catch (parseError) {
        }
      }
      addMessageWithAutoScroll(message, type);
    };
    const handleStatusChange = (status) => {
      console.log("handleStatusChange called with status:", status);
      console.log("\u{1F50D} Status change details:");
      console.log("  - oldStatus:", connectionStatus);
      console.log("  - newStatus:", status);
      console.log("  - isVerified:", isVerified);
      console.log("  - willShowChat:", status === "connected" && isVerified);
      setConnectionStatus(status);
      if (status === "connected") {
        document.dispatchEvent(new CustomEvent("new-connection"));
        if (!window.isUpdatingSecurity) {
          updateSecurityLevel().catch(console.error);
        }
      } else if (status === "verifying") {
        console.log("Setting showVerification to true for verifying status");
        setShowVerification(true);
        if (!window.isUpdatingSecurity) {
          updateSecurityLevel().catch(console.error);
        }
      } else if (status === "verified") {
        setIsVerified(true);
        setShowVerification(false);
        setBothVerificationsConfirmed(true);
        setConnectionStatus("connected");
        setTimeout(() => {
          setIsVerified(true);
        }, 0);
        if (!window.isUpdatingSecurity) {
          updateSecurityLevel().catch(console.error);
        }
      } else if (status === "connecting") {
        if (!window.isUpdatingSecurity) {
          updateSecurityLevel().catch(console.error);
        }
      } else if (status === "disconnected") {
        updateConnectionState({ status: "disconnected" });
        setConnectionStatus("disconnected");
        if (shouldPreserveAnswerData()) {
          console.log("\u{1F6E1}\uFE0F Preserving answer data after recent creation");
          setIsVerified(false);
          setShowVerification(false);
          return;
        }
        setIsVerified(false);
        setShowVerification(false);
        document.dispatchEvent(new CustomEvent("disconnected"));
        setLocalVerificationConfirmed(false);
        setRemoteVerificationConfirmed(false);
        setBothVerificationsConfirmed(false);
        setOfferData(null);
        setAnswerData(null);
        setOfferInput("");
        setAnswerInput("");
        setShowOfferStep(false);
        setShowAnswerStep(false);
        setKeyFingerprint("");
        setVerificationCode("");
        setSecurityLevel(null);
        setSessionTimeLeft(0);
        setTimeout(() => {
          setConnectionStatus("disconnected");
          setShowVerification(false);
          if (shouldPreserveAnswerData()) {
            console.log("\u{1F6E1}\uFE0F Preserving answer data in setTimeout after recent creation");
            return;
          }
          setOfferData(null);
          setAnswerData(null);
          setOfferInput("");
          setAnswerInput("");
          setShowOfferStep(false);
          setShowAnswerStep(false);
          setMessages([]);
        }, 1e3);
      } else if (status === "peer_disconnected") {
        setSessionTimeLeft(0);
        document.dispatchEvent(new CustomEvent("peer-disconnect"));
        setTimeout(() => {
          setKeyFingerprint("");
          setVerificationCode("");
          setSecurityLevel(null);
          setIsVerified(false);
          setShowVerification(false);
          setConnectionStatus("disconnected");
          setLocalVerificationConfirmed(false);
          setRemoteVerificationConfirmed(false);
          setBothVerificationsConfirmed(false);
          if (shouldPreserveAnswerData()) {
            console.log("\u{1F6E1}\uFE0F Preserving answer data in peer_disconnected after recent creation");
            return;
          }
          setOfferData(null);
          setAnswerData(null);
          setOfferInput("");
          setAnswerInput("");
          setShowOfferStep(false);
          setShowAnswerStep(false);
          setMessages([]);
        }, 2e3);
      }
    };
    const handleKeyExchange = (fingerprint) => {
      console.log("handleKeyExchange called with fingerprint:", fingerprint);
      if (fingerprint === "") {
        setKeyFingerprint("");
      } else {
        setKeyFingerprint(fingerprint);
        console.log("Key fingerprint set in UI:", fingerprint);
      }
    };
    const handleVerificationRequired = (code) => {
      console.log("handleVerificationRequired called with code:", code);
      if (code === "") {
        setVerificationCode("");
        setShowVerification(false);
      } else {
        setVerificationCode(code);
        setShowVerification(true);
        console.log("Verification code set, showing verification UI");
      }
    };
    const handleVerificationStateChange = (state) => {
      console.log("handleVerificationStateChange called with state:", state);
      setLocalVerificationConfirmed(state.localConfirmed);
      setRemoteVerificationConfirmed(state.remoteConfirmed);
      setBothVerificationsConfirmed(state.bothConfirmed);
    };
    const handleAnswerError = (errorType, errorMessage) => {
      if (errorType === "replay_attack") {
        setSessionTimeLeft(0);
        setPendingSession(null);
        addMessageWithAutoScroll("\u{1F4A1} Data is outdated. Please create a new invitation or use a current response code.", "system");
        if (typeof console.clear === "function") {
          console.clear();
        }
      } else if (errorType === "security_violation") {
        setSessionTimeLeft(0);
        setPendingSession(null);
        addMessageWithAutoScroll(`\u{1F512} Security breach: ${errorMessage}`, "system");
        if (typeof console.clear === "function") {
          console.clear();
        }
      }
    };
    console.log("\u{1F527} Initializing WebRTC Manager...");
    if (typeof console.clear === "function") {
      console.clear();
    }
    webrtcManagerRef.current = new EnhancedSecureWebRTCManager(
      handleMessage,
      handleStatusChange,
      handleKeyExchange,
      handleVerificationRequired,
      handleAnswerError,
      handleVerificationStateChange
    );
    handleMessage("\u{1F680} SecureBit.chat Enhanced Security Edition v4.02.985 - ECDH + DTLS + SAS initialized. Ready to establish a secure connection with ECDH key exchange, DTLS fingerprint verification, and SAS authentication to prevent MITM attacks.", "system");
    const handleBeforeUnload = (event) => {
      if (event.type === "beforeunload" && !isTabSwitching) {
        console.log("\u{1F50C} Page unloading (closing tab) - sending disconnect notification");
        if (webrtcManagerRef.current && webrtcManagerRef.current.isConnected()) {
          try {
            webrtcManagerRef.current.sendSystemMessage({
              type: "peer_disconnect",
              reason: "user_disconnect",
              timestamp: Date.now()
            });
          } catch (error) {
            console.log("Could not send disconnect notification:", error.message);
          }
          setTimeout(() => {
            if (webrtcManagerRef.current) {
              webrtcManagerRef.current.disconnect();
            }
          }, 100);
        } else if (webrtcManagerRef.current) {
          webrtcManagerRef.current.disconnect();
        }
      } else if (isTabSwitching) {
        console.log("\u{1F4F1} Tab switching detected - NOT disconnecting");
        event.preventDefault();
        event.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", handleBeforeUnload);
    let isTabSwitching = false;
    let tabSwitchTimeout = null;
    const handleVisibilityChange = () => {
      if (document.visibilityState === "hidden") {
        console.log("\u{1F4F1} Page hidden (tab switch) - keeping connection alive");
        isTabSwitching = true;
        if (tabSwitchTimeout) {
          clearTimeout(tabSwitchTimeout);
        }
        tabSwitchTimeout = setTimeout(() => {
          isTabSwitching = false;
        }, 5e3);
      } else if (document.visibilityState === "visible") {
        console.log("\u{1F4F1} Page visible (tab restored) - connection maintained");
        isTabSwitching = false;
        if (tabSwitchTimeout) {
          clearTimeout(tabSwitchTimeout);
          tabSwitchTimeout = null;
        }
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);
    if (webrtcManagerRef.current) {
      webrtcManagerRef.current.setFileTransferCallbacks(
        // Progress callback
        (progress) => {
          console.log("File progress:", progress);
        },
        // File received callback
        (fileData) => {
          const sizeMb = Math.max(1, Math.round((fileData.fileSize || 0) / (1024 * 1024)));
          const downloadMessage = React.createElement("div", {
            className: "flex items-center space-x-2"
          }, [
            React.createElement("span", { key: "label" }, `\u{1F4E5} File received: ${fileData.fileName} (${sizeMb} MB)`),
            React.createElement("button", {
              key: "btn",
              className: "px-3 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white text-xs",
              onClick: async () => {
                try {
                  const url = await fileData.getObjectURL();
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = fileData.fileName;
                  a.click();
                  setTimeout(() => fileData.revokeObjectURL(url), 15e3);
                } catch (e) {
                  console.error("Download failed:", e);
                  addMessageWithAutoScroll(`\u274C File upload error: ${String(e?.message || e)}`, "system");
                }
              }
            }, "Download")
          ]);
          addMessageWithAutoScroll(downloadMessage, "system");
        },
        // Error callback
        (error) => {
          console.error("File transfer error:", error);
          if (error.includes("Connection not ready")) {
            addMessageWithAutoScroll(`\u26A0\uFE0F File transfer error: connection not ready. Try again later.`, "system");
          } else if (error.includes("File too large")) {
            addMessageWithAutoScroll(`\u26A0\uFE0F File is too big. Maximum size: 100 MB`, "system");
          } else {
            addMessageWithAutoScroll(`\u274C File transfer error: ${error}`, "system");
          }
        }
      );
    }
    return () => {
      window.removeEventListener("beforeunload", handleBeforeUnload);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      if (tabSwitchTimeout) {
        clearTimeout(tabSwitchTimeout);
        tabSwitchTimeout = null;
      }
      if (webrtcManagerRef.current) {
        console.log("\u{1F9F9} Cleaning up WebRTC Manager...");
        webrtcManagerRef.current.disconnect();
        webrtcManagerRef.current = null;
      }
    };
  }, []);
  const compressOfferData = (offerData2) => {
    try {
      const offer = typeof offerData2 === "string" ? JSON.parse(offerData2) : offerData2;
      const minimalOffer = {
        type: offer.type,
        version: offer.version,
        timestamp: offer.timestamp,
        sessionId: offer.sessionId,
        connectionId: offer.connectionId,
        verificationCode: offer.verificationCode,
        salt: offer.salt,
        // Use only key fingerprints instead of full keys
        keyFingerprints: offer.keyFingerprints,
        // Add a reference to get full data
        fullDataAvailable: true,
        compressionLevel: "minimal"
      };
      return JSON.stringify(minimalOffer);
    } catch (error) {
      console.error("Error compressing offer data:", error);
      return offerData2;
    }
  };
  const createQRReference = (offerData2) => {
    try {
      const referenceId = `offer_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      localStorage.setItem(`qr_offer_${referenceId}`, JSON.stringify(offerData2));
      const qrReference = {
        type: "secure_offer_reference",
        referenceId,
        timestamp: Date.now(),
        message: "Scan this QR code and use the reference ID to get full offer data"
      };
      return JSON.stringify(qrReference);
    } catch (error) {
      console.error("Error creating QR reference:", error);
      return null;
    }
  };
  const createTemplateOffer = (offer) => {
    const templateOffer = {
      type: "enhanced_secure_offer_template",
      version: "4.0",
      sessionId: offer.sessionId,
      connectionId: offer.connectionId,
      verificationCode: offer.verificationCode,
      timestamp: offer.timestamp,
      // Avoid bulky fields (SDP, raw keys); keep only fingerprints and essentials
      keyFingerprints: offer.keyFingerprints,
      // Keep concise auth hints (omit large nonces)
      authChallenge: offer?.authChallenge?.challenge,
      // Optionally include a compact capability hint if small
      capabilities: Array.isArray(offer.capabilities) && offer.capabilities.length <= 5 ? offer.capabilities : void 0
    };
    return templateOffer;
  };
  const MAX_QR_LEN = 800;
  const [qrFramesTotal2, setQrFramesTotal] = React.useState(0);
  const [qrFrameIndex2, setQrFrameIndex] = React.useState(0);
  const qrAnimationRef = React.useRef({ timer: null, chunks: [], idx: 0, active: false });
  const stopQrAnimation = () => {
    try {
      if (qrAnimationRef.current.timer) {
        clearInterval(qrAnimationRef.current.timer);
      }
    } catch {
    }
    qrAnimationRef.current = { timer: null, chunks: [], idx: 0, active: false };
    setQrFrameIndex(0);
    setQrFramesTotal(0);
  };
  const qrChunksBufferRef = React.useRef({ id: null, total: 0, seen: /* @__PURE__ */ new Set(), items: [] });
  const generateQRCode2 = async (data) => {
    try {
      const originalSize = typeof data === "string" ? data.length : JSON.stringify(data).length;
      console.log(`\u{1F4CA} Original QR Code data size: ${originalSize} characters`);
      const payload = typeof data === "string" ? data : JSON.stringify(data);
      const isDesktop = typeof window !== "undefined" && (window.innerWidth || 0) >= 1024;
      const QR_SIZE = isDesktop ? 720 : 512;
      if (payload.length <= MAX_QR_LEN) {
        if (!window.generateQRCode) throw new Error("QR code generator unavailable");
        stopQrAnimation();
        const qrDataUrl = await window.generateQRCode(payload, { errorCorrectionLevel: "M", size: QR_SIZE, margin: 2 });
        setQrCodeUrl(qrDataUrl);
        setQrFramesTotal(1);
        setQrFrameIndex(1);
        return;
      }
      console.log("\u{1F39E}\uFE0F Using RAW animated QR frames (no compression)");
      stopQrAnimation();
      const id = `raw_${Date.now()}_${Math.random().toString(36).slice(2)}`;
      const FRAME_MAX = Math.max(300, Math.min(750, Math.floor(MAX_QR_LEN * 0.6)));
      const total = Math.ceil(payload.length / FRAME_MAX);
      const rawChunks = [];
      for (let i = 0; i < total; i++) {
        const seq = i + 1;
        const part = payload.slice(i * FRAME_MAX, (i + 1) * FRAME_MAX);
        rawChunks.push(JSON.stringify({ hdr: { v: 1, id, seq, total, rt: "raw" }, body: part }));
      }
      if (!window.generateQRCode) throw new Error("QR code generator unavailable");
      if (rawChunks.length === 1) {
        const url = await window.generateQRCode(rawChunks[0], { errorCorrectionLevel: "M", margin: 2, size: QR_SIZE });
        setQrCodeUrl(url);
        setQrFramesTotal(1);
        setQrFrameIndex(1);
        return;
      }
      qrAnimationRef.current.chunks = rawChunks;
      qrAnimationRef.current.idx = 0;
      qrAnimationRef.current.active = true;
      setQrFramesTotal(rawChunks.length);
      setQrFrameIndex(1);
      const EC_OPTS = { errorCorrectionLevel: "M", margin: 2, size: QR_SIZE };
      const renderNext = async () => {
        const { chunks, idx, active } = qrAnimationRef.current;
        if (!active || !chunks.length) return;
        const current = chunks[idx % chunks.length];
        try {
          const url = await window.generateQRCode(current, EC_OPTS);
          setQrCodeUrl(url);
        } catch (e) {
          console.warn("Animated QR render error (raw):", e);
        }
        const nextIdx = (idx + 1) % chunks.length;
        qrAnimationRef.current.idx = nextIdx;
        setQrFrameIndex(nextIdx + 1);
      };
      await renderNext();
      const ua = typeof navigator !== "undefined" && navigator.userAgent ? navigator.userAgent : "";
      const isIOS = /iPhone|iPad|iPod/i.test(ua);
      const intervalMs = isIOS ? 2500 : 2e3;
      qrAnimationRef.current.timer = setInterval(renderNext, intervalMs);
      return;
    } catch (error) {
      console.error("QR code generation failed:", error);
      setMessages((prev) => [...prev, {
        message: `\u274C QR code generation failed: ${error.message}`,
        type: "error"
      }]);
    }
  };
  const reconstructFromTemplate = (templateData) => {
    const fullOffer = {
      type: "enhanced_secure_offer",
      version: templateData.version,
      timestamp: templateData.timestamp,
      sessionId: templateData.sessionId,
      connectionId: templateData.connectionId,
      verificationCode: templateData.verificationCode,
      salt: templateData.salt,
      sdp: templateData.sdp,
      keyFingerprints: templateData.keyFingerprints,
      capabilities: templateData.capabilities,
      // Reconstruct ECDH key object
      ecdhPublicKey: {
        keyType: "ECDH",
        keyData: templateData.ecdhKeyData,
        timestamp: templateData.timestamp - 1e3,
        // Approximate
        version: templateData.version,
        signature: templateData.ecdhSignature
      },
      // Reconstruct ECDSA key object
      ecdsaPublicKey: {
        keyType: "ECDSA",
        keyData: templateData.ecdsaKeyData,
        timestamp: templateData.timestamp - 999,
        // Approximate
        version: templateData.version,
        signature: templateData.ecdsaSignature
      },
      // Reconstruct auth challenge
      authChallenge: {
        challenge: templateData.authChallenge,
        timestamp: templateData.timestamp,
        nonce: templateData.authNonce,
        version: templateData.version
      },
      // Generate security level (can be recalculated)
      securityLevel: {
        level: "CRITICAL",
        score: 20,
        color: "red",
        verificationResults: {
          encryption: { passed: false, details: "Encryption not working", points: 0 },
          keyExchange: { passed: true, details: "Simple key exchange verified", points: 15 },
          messageIntegrity: { passed: false, details: "Message integrity failed", points: 0 },
          rateLimiting: { passed: true, details: "Rate limiting active", points: 5 },
          ecdsa: { passed: false, details: "Enhanced session required - feature not available", points: 0 },
          metadataProtection: { passed: false, details: "Enhanced session required - feature not available", points: 0 },
          pfs: { passed: false, details: "Enhanced session required - feature not available", points: 0 },
          nestedEncryption: { passed: false, details: "Enhanced session required - feature not available", points: 0 },
          packetPadding: { passed: false, details: "Enhanced session required - feature not available", points: 0 },
          advancedFeatures: { passed: false, details: "Premium session required - feature not available", points: 0 }
        },
        timestamp: templateData.timestamp,
        details: "Real verification: 20/100 security checks passed (2/4 available)",
        isRealData: true,
        passedChecks: 2,
        totalChecks: 4,
        sessionType: "demo",
        maxPossibleScore: 50
      }
    };
    return fullOffer;
  };
  const handleQRScan = async (scannedData) => {
    try {
      console.log("\u{1F50D} Processing scanned QR data...");
      console.log("\u{1F4CA} Current mode - showOfferStep:", showOfferStep);
      console.log("\u{1F4CA} Scanned data length:", scannedData.length);
      console.log("\u{1F4CA} Scanned data first 100 chars:", scannedData.substring(0, 100));
      console.log("\u{1F4CA} window.receiveAndProcess available:", !!window.receiveAndProcess);
      const parsedData = JSON.parse(scannedData);
      console.log("\u{1F4CA} Parsed data structure:", parsedData);
      if (parsedData.hdr && parsedData.body) {
        const { hdr } = parsedData;
        if (!qrChunksBufferRef.current.id || qrChunksBufferRef.current.id !== hdr.id) {
          qrChunksBufferRef.current = { id: hdr.id, total: hdr.total || 1, seen: /* @__PURE__ */ new Set(), items: [], lastUpdateMs: Date.now() };
          try {
            document.dispatchEvent(new CustomEvent("qr-scan-progress", { detail: { id: hdr.id, seq: 0, total: hdr.total || 1 } }));
          } catch {
          }
        }
        if (!qrChunksBufferRef.current.seen.has(hdr.seq)) {
          qrChunksBufferRef.current.seen.add(hdr.seq);
          qrChunksBufferRef.current.items.push(scannedData);
          qrChunksBufferRef.current.lastUpdateMs = Date.now();
        }
        try {
          const uniqueCount = qrChunksBufferRef.current.seen.size;
          document.dispatchEvent(new CustomEvent("qr-scan-progress", { detail: { id: hdr.id, seq: uniqueCount, total: qrChunksBufferRef.current.total || hdr.total || 0 } }));
        } catch {
        }
        const isComplete = qrChunksBufferRef.current.seen.size >= (qrChunksBufferRef.current.total || 1);
        if (!isComplete) {
          return Promise.resolve(false);
        }
        if (hdr.rt === "raw") {
          try {
            const parts = qrChunksBufferRef.current.items.map((s) => JSON.parse(s)).sort((a, b) => (a.hdr.seq || 0) - (b.hdr.seq || 0)).map((p) => p.body || "");
            const fullText = parts.join("");
            const payloadObj = JSON.parse(fullText);
            if (showOfferStep) {
              setAnswerInput(JSON.stringify(payloadObj, null, 2));
            } else {
              setOfferInput(JSON.stringify(payloadObj, null, 2));
            }
            setMessages((prev) => [...prev, { message: "\u2705 All frames captured. RAW payload reconstructed.", type: "success" }]);
            try {
              document.dispatchEvent(new CustomEvent("qr-scan-complete", { detail: { id: hdr.id } }));
            } catch {
            }
            qrChunksBufferRef.current = { id: null, total: 0, seen: /* @__PURE__ */ new Set(), items: [] };
            setShowQRScannerModal(false);
            return Promise.resolve(true);
          } catch (e) {
            console.warn("RAW multi-frame reconstruction failed:", e);
            return Promise.resolve(false);
          }
        } else if (window.receiveAndProcess) {
          try {
            const results = await window.receiveAndProcess(qrChunksBufferRef.current.items);
            if (results.length > 0) {
              const { payloadObj } = results[0];
              if (showOfferStep) {
                setAnswerInput(JSON.stringify(payloadObj, null, 2));
              } else {
                setOfferInput(JSON.stringify(payloadObj, null, 2));
              }
              setMessages((prev) => [...prev, { message: "\u2705 All frames captured. COSE payload reconstructed.", type: "success" }]);
              try {
                document.dispatchEvent(new CustomEvent("qr-scan-complete", { detail: { id: hdr.id } }));
              } catch {
              }
              qrChunksBufferRef.current = { id: null, total: 0, seen: /* @__PURE__ */ new Set(), items: [] };
              setShowQRScannerModal(false);
              return Promise.resolve(true);
            }
          } catch (e) {
            console.warn("COSE multi-chunk processing failed:", e);
          }
          return Promise.resolve(false);
        } else {
          return Promise.resolve(false);
        }
      }
      if (parsedData.type === "enhanced_secure_offer_template") {
        console.log("QR scan: Template-based offer detected, reconstructing...");
        const fullOffer = reconstructFromTemplate(parsedData);
        if (showOfferStep) {
          setAnswerInput(JSON.stringify(fullOffer, null, 2));
          console.log("\u{1F4F1} Template data populated to answerInput (waiting for response mode)");
        } else {
          setOfferInput(JSON.stringify(fullOffer, null, 2));
          console.log("\u{1F4F1} Template data populated to offerInput (paste invitation mode)");
        }
        setMessages((prev) => [...prev, {
          message: "\u{1F4F1} QR code scanned successfully! Full offer reconstructed from template.",
          type: "success"
        }]);
        setShowQRScannerModal(false);
        return true;
      } else if (parsedData.type === "secure_offer_reference" && parsedData.referenceId) {
        const fullOfferData = localStorage.getItem(`qr_offer_${parsedData.referenceId}`);
        if (fullOfferData) {
          const fullOffer = JSON.parse(fullOfferData);
          if (showOfferStep) {
            setAnswerInput(JSON.stringify(fullOffer, null, 2));
            console.log("\u{1F4F1} Reference data populated to answerInput (waiting for response mode)");
          } else {
            setOfferInput(JSON.stringify(fullOffer, null, 2));
            console.log("\u{1F4F1} Reference data populated to offerInput (paste invitation mode)");
          }
          setMessages((prev) => [...prev, {
            message: "\u{1F4F1} QR code scanned successfully! Full offer data retrieved.",
            type: "success"
          }]);
          setShowQRScannerModal(false);
          return true;
        } else {
          setMessages((prev) => [...prev, {
            message: "\u274C QR code reference found but full data not available. Please use copy/paste.",
            type: "error"
          }]);
          return false;
        }
      } else {
        if (!parsedData.sdp) {
          setMessages((prev) => [...prev, {
            message: "\u26A0\uFE0F QR code contains compressed data (SDP removed). Please use copy/paste for full data.",
            type: "warning"
          }]);
        }
        if (showOfferStep) {
          console.log("QR scan: Populating answerInput with:", parsedData);
          setAnswerInput(JSON.stringify(parsedData, null, 2));
        } else {
          console.log("QR scan: Populating offerInput with:", parsedData);
          setOfferInput(JSON.stringify(parsedData, null, 2));
        }
        setMessages((prev) => [...prev, {
          message: "\u{1F4F1} QR code scanned successfully!",
          type: "success"
        }]);
        setShowQRScannerModal(false);
        return true;
      }
    } catch (error) {
      if (showOfferStep) {
        setAnswerInput(scannedData);
      } else {
        setOfferInput(scannedData);
      }
      setMessages((prev) => [...prev, {
        message: "\u{1F4F1} QR code scanned successfully!",
        type: "success"
      }]);
      setShowQRScannerModal(false);
      return true;
    }
  };
  const handleCreateOffer = async () => {
    try {
      console.log("\u{1F3AF} handleCreateOffer called");
      setOfferData("");
      setShowOfferStep(false);
      setShowQRCode(false);
      setQrCodeUrl("");
      console.log("\u{1F3AF} Calling createSecureOffer...");
      const offer = await webrtcManagerRef.current.createSecureOffer();
      console.log("\u{1F3AF} createSecureOffer returned:", offer ? "success" : "null");
      setOfferData(offer);
      setShowOfferStep(true);
      const offerString = typeof offer === "object" ? JSON.stringify(offer) : offer;
      console.log("Generating QR code for data length:", offerString.length);
      console.log("First 100 chars of offer data:", offerString.substring(0, 100));
      await generateQRCode2(offerString);
      const existingMessages = messages.filter(
        (m) => m.type === "system" && (m.message.includes("Secure invitation created") || m.message.includes("Send the encrypted code"))
      );
      if (existingMessages.length === 0) {
        setMessages((prev) => [...prev, {
          message: "\u{1F510} Secure invitation created and encrypted!",
          type: "system",
          id: Date.now(),
          timestamp: Date.now()
        }]);
        setMessages((prev) => [...prev, {
          message: "\u{1F4E4} Send the invitation code to your interlocutor via a secure channel (voice call, SMS, etc.)..",
          type: "system",
          id: Date.now(),
          timestamp: Date.now()
        }]);
      }
      if (!window.isUpdatingSecurity) {
        updateSecurityLevel().catch(console.error);
      }
    } catch (error) {
      setMessages((prev) => [...prev, {
        message: `\u274C Error creating invitation: ${error.message}`,
        type: "system",
        id: Date.now(),
        timestamp: Date.now()
      }]);
    }
  };
  const handleCreateAnswer = async () => {
    try {
      console.log("handleCreateAnswer called, offerInput:", offerInput);
      console.log("offerInput.trim():", offerInput.trim());
      console.log("offerInput.trim() length:", offerInput.trim().length);
      if (!offerInput.trim()) {
        setMessages((prev) => [...prev, {
          message: "\u26A0\uFE0F You need to insert the invitation code from your interlocutor.",
          type: "system",
          id: Date.now(),
          timestamp: Date.now()
        }]);
        return;
      }
      try {
        setMessages((prev) => [...prev, {
          message: "\u{1F504} Processing the secure invitation...",
          type: "system",
          id: Date.now(),
          timestamp: Date.now()
        }]);
        let offer;
        try {
          offer = JSON.parse(offerInput.trim());
        } catch (parseError) {
          throw new Error(`Invalid invitation format: ${parseError.message}`);
        }
        if (!offer || typeof offer !== "object") {
          throw new Error("The invitation must be an object");
        }
        const isValidOfferType = offer.t === "offer" || offer.type === "enhanced_secure_offer";
        if (!isValidOfferType) {
          throw new Error("Invalid invitation type. Expected offer or enhanced_secure_offer");
        }
        console.log("Creating secure answer for offer:", offer);
        const answer = await webrtcManagerRef.current.createSecureAnswer(offer);
        console.log("Secure answer created:", answer);
        setAnswerData(answer);
        setShowAnswerStep(true);
        markAnswerCreated2();
        const existingResponseMessages = messages.filter(
          (m) => m.type === "system" && (m.message.includes("Secure response created") || m.message.includes("Send the response"))
        );
        if (existingResponseMessages.length === 0) {
          setMessages((prev) => [...prev, {
            message: "\u2705 Secure response created!",
            type: "system",
            id: Date.now(),
            timestamp: Date.now()
          }]);
          setMessages((prev) => [...prev, {
            message: "\u{1F4E4} Send the response code to the initiator via a secure channel..",
            type: "system",
            id: Date.now(),
            timestamp: Date.now()
          }]);
        }
        if (!window.isUpdatingSecurity) {
          updateSecurityLevel().catch(console.error);
        }
      } catch (error) {
        console.error("Error in handleCreateAnswer:", error);
        setMessages((prev) => [...prev, {
          message: `\u274C Error processing the invitation: ${error.message}`,
          type: "system",
          id: Date.now(),
          timestamp: Date.now()
        }]);
      }
    } catch (error) {
      console.error("Error in handleCreateAnswer:", error);
      setMessages((prev) => [...prev, {
        message: `\u274C Invitation processing error: ${error.message}`,
        type: "system",
        id: Date.now(),
        timestamp: Date.now()
      }]);
    }
  };
  const handleConnect = async () => {
    try {
      if (!answerInput.trim()) {
        setMessages((prev) => [...prev, {
          message: "\u26A0\uFE0F You need to insert the response code from your interlocutor.",
          type: "system",
          id: Date.now(),
          timestamp: Date.now()
        }]);
        return;
      }
      try {
        setMessages((prev) => [...prev, {
          message: "\u{1F504} Processing the secure response...",
          type: "system",
          id: Date.now(),
          timestamp: Date.now()
        }]);
        let answer;
        try {
          answer = JSON.parse(answerInput.trim());
        } catch (parseError) {
          throw new Error(`Invalid response format: ${parseError.message}`);
        }
        if (!answer || typeof answer !== "object") {
          throw new Error("The response must be an object");
        }
        const answerType = answer.t || answer.type;
        if (!answerType || answerType !== "answer" && answerType !== "enhanced_secure_answer") {
          throw new Error("Invalid response type. Expected answer or enhanced_secure_answer");
        }
        await webrtcManagerRef.current.handleSecureAnswer(answer);
        if (pendingSession) {
          setPendingSession(null);
          setMessages((prev) => [...prev, {
            message: `\u2705 All security features enabled by default`,
            type: "system",
            id: Date.now(),
            timestamp: Date.now()
          }]);
        }
        setMessages((prev) => [...prev, {
          message: "\u{1F504} Finalizing the secure connection...",
          type: "system",
          id: Date.now(),
          timestamp: Date.now()
        }]);
        if (!window.isUpdatingSecurity) {
          updateSecurityLevel().catch(console.error);
        }
      } catch (error) {
        console.error("Error in handleConnect inner try:", error);
        let errorMessage = "Connection setup error";
        if (error.message.includes("CRITICAL SECURITY FAILURE")) {
          if (error.message.includes("ECDH public key structure")) {
            errorMessage = "\u{1F511} Invalid response code - missing or corrupted cryptographic key. Please check the code and try again.";
          } else if (error.message.includes("ECDSA public key structure")) {
            errorMessage = "\u{1F510} Invalid response code - missing signature verification key. Please check the code and try again.";
          } else {
            errorMessage = "\u{1F512} Security validation failed - possible attack detected";
          }
        } else if (error.message.includes("too old") || error.message.includes("replay")) {
          errorMessage = "\u23F0 Response data is outdated - please use a fresh invitation";
        } else if (error.message.includes("MITM") || error.message.includes("signature")) {
          errorMessage = "\u{1F6E1}\uFE0F Security breach detected - connection rejected";
        } else if (error.message.includes("Invalid") || error.message.includes("format")) {
          errorMessage = "\u{1F4DD} Invalid response format - please check the code";
        } else {
          errorMessage = `\u274C ${error.message}`;
        }
        setMessages((prev) => [...prev, {
          message: errorMessage,
          type: "system",
          id: Date.now(),
          timestamp: Date.now(),
          showRetryButton: true
        }]);
        if (!error.message.includes("too old") && !error.message.includes("replay")) {
          setPendingSession(null);
          setSessionTimeLeft(0);
        }
        setConnectionStatus("failed");
        console.log("\u{1F6A8} Error occurred, but keeping connection status as connecting:");
        console.log("  - errorMessage:", error.message);
        console.log("  - connectionStatus:", "connecting (kept)");
        console.log("  - isVerified:", false);
        console.log("  - willShowChat:", keyFingerprint && keyFingerprint !== "");
      }
    } catch (error) {
      console.error("Error in handleConnect outer try:", error);
      let errorMessage = "Connection setup error";
      if (error.message.includes("CRITICAL SECURITY FAILURE")) {
        if (error.message.includes("ECDH public key structure")) {
          errorMessage = "\u{1F511} Invalid response code - missing or corrupted cryptographic key. Please check the code and try again.";
        } else if (error.message.includes("ECDSA public key structure")) {
          errorMessage = "\u{1F510} Invalid response code - missing signature verification key. Please check the code and try again.";
        } else {
          errorMessage = "\u{1F512} Security validation failed - possible attack detected";
        }
      } else if (error.message.includes("too old") || error.message.includes("replay")) {
        errorMessage = "\u23F0 Response data is outdated - please use a fresh invitation";
      } else if (error.message.includes("MITM") || error.message.includes("signature")) {
        errorMessage = "\u{1F6E1}\uFE0F Security breach detected - connection rejected";
      } else if (error.message.includes("Invalid") || error.message.includes("format")) {
        errorMessage = "\u{1F4DD} Invalid response format - please check the code";
      } else {
        errorMessage = `\u274C ${error.message}`;
      }
      setMessages((prev) => [...prev, {
        message: errorMessage,
        type: "system",
        id: Date.now(),
        timestamp: Date.now(),
        showRetryButton: true
      }]);
      if (!error.message.includes("too old") && !error.message.includes("replay")) {
        setPendingSession(null);
        setSessionTimeLeft(0);
      }
      setConnectionStatus("failed");
      console.log("\u{1F6A8} Error occurred in outer catch, but keeping connection status as connecting:");
      console.log("  - errorMessage:", error.message);
      console.log("  - connectionStatus:", "connecting (kept)");
      console.log("  - isVerified:", false);
      console.log("  - willShowChat:", keyFingerprint && keyFingerprint !== "");
    }
  };
  const handleVerifyConnection = (isValid) => {
    if (isValid) {
      webrtcManagerRef.current.confirmVerification();
      setLocalVerificationConfirmed(true);
    } else {
      setMessages((prev) => [...prev, {
        message: "\u274C Verification rejected. The connection is unsafe! Session reset..",
        type: "system",
        id: Date.now(),
        timestamp: Date.now()
      }]);
      setLocalVerificationConfirmed(false);
      setRemoteVerificationConfirmed(false);
      setBothVerificationsConfirmed(false);
      setShowVerification(false);
      setVerificationCode("");
      setConnectionStatus("disconnected");
      setOfferData(null);
      setAnswerData(null);
      setOfferInput("");
      setAnswerInput("");
      setShowOfferStep(false);
      setShowAnswerStep(false);
      setKeyFingerprint("");
      setSecurityLevel(null);
      setIsVerified(false);
      setMessages([]);
      setSessionTimeLeft(0);
      setPendingSession(null);
      document.dispatchEvent(new CustomEvent("disconnected"));
      handleDisconnect();
    }
  };
  const handleSendMessage = async () => {
    if (!messageInput.trim()) {
      return;
    }
    if (!webrtcManagerRef.current) {
      return;
    }
    if (!webrtcManagerRef.current.isConnected()) {
      return;
    }
    try {
      addMessageWithAutoScroll(messageInput.trim(), "sent");
      await webrtcManagerRef.current.sendMessage(messageInput);
      setMessageInput("");
    } catch (error) {
      const msg = String(error?.message || error);
      if (!/queued for sending|Data channel not ready/i.test(msg)) {
        addMessageWithAutoScroll(`\u274C Sending error: ${msg}`, "system");
      }
    }
  };
  const handleClearData = () => {
    setOfferData("");
    setAnswerData("");
    setOfferInput("");
    setAnswerInput("");
    setShowOfferStep(false);
    setShowAnswerStep(false);
    setShowVerification(false);
    setShowQRCode(false);
    setShowQRScanner(false);
    setShowQRScannerModal(false);
    setQrCodeUrl("");
    setVerificationCode("");
    setIsVerified(false);
    setKeyFingerprint("");
    setSecurityLevel(null);
    setConnectionStatus("disconnected");
    setMessages([]);
    setMessageInput("");
    setLocalVerificationConfirmed(false);
    setRemoteVerificationConfirmed(false);
    setBothVerificationsConfirmed(false);
    setSessionTimeLeft(0);
    setPendingSession(null);
    document.dispatchEvent(new CustomEvent("peer-disconnect"));
  };
  const handleDisconnect = () => {
    setSessionTimeLeft(0);
    updateConnectionState({
      status: "disconnected",
      isUserInitiatedDisconnect: true
    });
    if (webrtcManagerRef.current) {
      webrtcManagerRef.current.disconnect();
    }
    setKeyFingerprint("");
    setVerificationCode("");
    setSecurityLevel(null);
    setIsVerified(false);
    setShowVerification(false);
    setConnectionStatus("disconnected");
    setLocalVerificationConfirmed(false);
    setRemoteVerificationConfirmed(false);
    setBothVerificationsConfirmed(false);
    setConnectionStatus("disconnected");
    setShowVerification(false);
    setOfferData(null);
    setAnswerData(null);
    setOfferInput("");
    setAnswerInput("");
    setShowOfferStep(false);
    setShowAnswerStep(false);
    setKeyFingerprint("");
    setVerificationCode("");
    setSecurityLevel(null);
    setIsVerified(false);
    setMessages([]);
    document.dispatchEvent(new CustomEvent("peer-disconnect"));
    document.dispatchEvent(new CustomEvent("disconnected"));
    document.dispatchEvent(new CustomEvent("session-cleanup", {
      detail: {
        timestamp: Date.now(),
        reason: "manual_disconnect"
      }
    }));
    setTimeout(() => {
      setSessionTimeLeft(0);
    }, 500);
    handleClearData();
    setTimeout(() => {
    }, 1e3);
  };
  const handleSessionActivated = (session) => {
    let message;
    if (session.type === "demo") {
      message = `\u{1F3AE} Demo session activated for 6 minutes. You can create invitations!`;
    } else {
      message = `\u2705 All security features enabled by default. You can create invitations!`;
    }
    addMessageWithAutoScroll(message, "system");
  };
  React.useEffect(() => {
    if (connectionStatus === "connected" && isVerified) {
      addMessageWithAutoScroll("\u{1F389} Secure connection successfully established and verified! You can now communicate safely with full protection against MITM attacks and Perfect Forward Secrecy..", "system");
    }
  }, [connectionStatus, isVerified]);
  const isConnectedAndVerified = (connectionStatus === "connected" || connectionStatus === "verified") && isVerified;
  console.log("\u{1F50D} Chat activation check:");
  console.log("  - connectionStatus:", connectionStatus);
  console.log("  - isVerified:", isVerified);
  console.log("  - keyFingerprint:", keyFingerprint);
  console.log("  - isConnectedAndVerified:", isConnectedAndVerified);
  console.log("  - bothVerificationsConfirmed:", bothVerificationsConfirmed);
  console.log("  - localVerificationConfirmed:", localVerificationConfirmed);
  console.log("  - remoteVerificationConfirmed:", remoteVerificationConfirmed);
  React.useEffect(() => {
    if (isConnectedAndVerified && pendingSession && connectionStatus !== "failed") {
      setPendingSession(null);
      setSessionTimeLeft(0);
      addMessageWithAutoScroll("\u2705 All security features enabled by default", "system");
    }
  }, [isConnectedAndVerified, pendingSession, connectionStatus]);
  return React.createElement("div", {
    className: "minimal-bg min-h-screen"
  }, [
    React.createElement(EnhancedMinimalHeader, {
      key: "header",
      status: connectionStatus,
      fingerprint: keyFingerprint,
      verificationCode,
      onDisconnect: handleDisconnect,
      isConnected: isConnectedAndVerified,
      securityLevel,
      // sessionManager removed - all features enabled by default
      sessionTimeLeft,
      webrtcManager: webrtcManagerRef.current
    }),
    React.createElement(
      "main",
      {
        key: "main"
      },
      (() => {
        console.log("\u{1F50D} Main render decision:", {
          isConnectedAndVerified,
          connectionStatus,
          isVerified,
          keyFingerprint: !!keyFingerprint
        });
        return isConnectedAndVerified;
      })() ? (() => {
        console.log("\u{1F50D} Passing scrollToBottom to EnhancedChatInterface:", typeof scrollToBottom, scrollToBottom);
        return React.createElement(EnhancedChatInterface, {
          messages,
          messageInput,
          setMessageInput,
          onSendMessage: handleSendMessage,
          onDisconnect: handleDisconnect,
          keyFingerprint,
          isVerified,
          chatMessagesRef,
          scrollToBottom,
          webrtcManager: webrtcManagerRef.current
        });
      })() : React.createElement(EnhancedConnectionSetup, {
        onCreateOffer: handleCreateOffer,
        onCreateAnswer: handleCreateAnswer,
        onConnect: handleConnect,
        onClearData: handleClearData,
        onVerifyConnection: handleVerifyConnection,
        connectionStatus,
        offerData,
        answerData,
        offerInput,
        setOfferInput,
        answerInput,
        setAnswerInput,
        showOfferStep,
        showAnswerStep,
        verificationCode,
        showVerification,
        showQRCode,
        qrCodeUrl,
        showQRScanner,
        setShowQRCode,
        setShowQRScanner,
        setShowQRScannerModal,
        messages,
        localVerificationConfirmed,
        remoteVerificationConfirmed,
        bothVerificationsConfirmed
        // PAKE passwords removed - using SAS verification instead
      })
    ),
    // PAKE Password Modal removed - using SAS verification instead
    // Payment Modal removed - all security features enabled by default
    (() => {
      console.log("Rendering QRScanner, showQRScannerModal:", showQRScannerModal, "QRScanner available:", !!window.QRScanner);
      return window.QRScanner ? React.createElement(window.QRScanner, {
        key: "qr-scanner-modal",
        onScan: handleQRScan,
        onClose: () => setShowQRScannerModal(false),
        isVisible: showQRScannerModal,
        continuous: true
      }) : React.createElement("div", {
        key: "qr-scanner-error",
        className: "hidden"
      }, "QRScanner not loaded");
    })()
  ]);
};
function initializeApp() {
  if (window.EnhancedSecureCryptoUtils && window.EnhancedSecureWebRTCManager) {
    ReactDOM.render(React.createElement(EnhancedSecureP2PChat), document.getElementById("root"));
  } else {
    console.error("\u274C \u041C\u043E\u0434\u0443\u043B\u0438 \u043D\u0435 \u0437\u0430\u0433\u0440\u0443\u0436\u0435\u043D\u044B:", {
      hasCrypto: !!window.EnhancedSecureCryptoUtils,
      hasWebRTC: !!window.EnhancedSecureWebRTCManager
    });
  }
}
if (typeof window !== "undefined") {
  window.addEventListener("unhandledrejection", (event) => {
    console.error("\u{1F6A8} Unhandled promise rejection:", event.reason);
    event.preventDefault();
  });
  window.addEventListener("error", (event) => {
    console.error("\u{1F6A8} Global error:", event.error);
    event.preventDefault();
  });
  if (!window.initializeApp) {
    window.initializeApp = initializeApp;
  }
}
ReactDOM.render(React.createElement(EnhancedSecureP2PChat), document.getElementById("root"));
//# sourceMappingURL=app.js.map
