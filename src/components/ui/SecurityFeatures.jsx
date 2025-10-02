const SecurityFeatures = () => {
  const features = [
    { id: 'feature1', color: '#00ff88', icon: 'fas fa-key accent-green', title: 'ECDH P-384 Key Exchange', desc: 'Military-grade elliptic curve key exchange' },
    { id: 'feature2', color: '#a78bfa', icon: 'fas fa-user-shield accent-purple', title: 'MITM Protection', desc: 'Out-of-band verification against attacks' },
    { id: 'feature3', color: '#ff8800', icon: 'fas fa-lock accent-orange', title: 'AES-GCM 256 Encryption', desc: 'Authenticated encryption standard' },
    { id: 'feature4', color: '#00ffff', icon: 'fas fa-sync-alt accent-cyan', title: 'Perfect Forward Secrecy', desc: 'Automatic key rotation every 5 minutes' },
    { id: 'feature5', color: '#0088ff', icon: 'fas fa-signature accent-blue', title: 'ECDSA P-384 Signatures', desc: 'Digital signatures for message integrity' },
    { id: 'feature6', color: '#ff0044', icon: 'fas fa-shield-alt accent-red', title: 'SAS Security', desc: 'Revolutionary key exchange & MITM protection' }
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

  const renderFeature = (f) =>
    React.createElement('div', {
      key: f.id,
      className: "card p-3 sm:p-4 text-center",
      style: { "--color": f.color }
    }, [
      React.createElement('div', { key: 'icon', className: "w-10 h-10 sm:w-12 sm:h-12 flex items-center justify-center mx-auto mb-2 sm:mb-3 relative z-10" }, [
        React.createElement('i', { className: f.icon })
      ]),
      React.createElement('h4', { key: 'title', className: "text-xs sm:text-sm font-medium text-primary mb-1 relative z-10" }, f.title),
      React.createElement('p', { key: 'desc', className: "text-xs text-muted leading-tight relative z-10" }, f.desc)
    ]);

  return React.createElement('div', {
    className: "grid grid-cols-2 md:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 max-w-6xl mx-auto mt-8"
  }, features.map(renderFeature));
};

window.SecurityFeatures = SecurityFeatures;
