// Enhanced Modern Slider Component with Original CSS Classes
const UniqueFeatureSlider = () => {
  const trackRef = React.useRef(null);
  const wrapRef = React.useRef(null);
  const [current, setCurrent] = React.useState(0);

  const slides = [
    {
      icon: "🛡️",
      bgImage: "linear-gradient(135deg, rgb(255 107 53 / 6%) 0%, rgb(255 140 66 / 45%) 100%)",
      thumbIcon: "🔒",
      title: "18-Layer Military Security",
      description: "Revolutionary defense system with ECDH P-384 + AES-GCM 256 + ECDSA + Complete ASN.1 Validation."
    },
    {
      icon: "🌐",
      bgImage: "linear-gradient(135deg, rgb(147 51 234 / 6%) 0%, rgb(168 85 247 / 45%) 100%)",
      thumbIcon: "🔗",
      title: "Pure P2P WebRTC",
      description: "Direct peer-to-peer connections without any servers. Complete decentralization with zero infrastructure."
    },
    {
      icon: "🔄",
      bgImage: "linear-gradient(135deg, rgb(16 185 129 / 6%) 0%, rgb(52 211 153 / 45%) 100%)",
      thumbIcon: "⚡",
      title: "Perfect Forward Secrecy",
      description: "Automatic key rotation every 5 minutes. Non-extractable keys with hardware protection."
    },
    {
      icon: "🎭",
      bgImage: "linear-gradient(135deg, rgb(6 182 212 / 6%) 0%, rgb(34 211 238 / 45%) 100%)",
      thumbIcon: "🌫️",
      title: "Traffic Obfuscation",
      description: "Fake traffic generation and pattern masking make communication indistinguishable from noise."
    },
    {
      icon: "👁️",
      bgImage: "linear-gradient(135deg, rgb(37 99 235 / 6%) 0%, rgb(59 130 246 / 45%) 100%)",
      thumbIcon: "🚫",
      title: "Zero Data Collection",
      description: "No registration, no servers, no logs. Complete anonymity with instant channels."
    }
  ];

  const isMobile = () => window.matchMedia("(max-width:767px)").matches;

  const center = React.useCallback((i) => {
    if (!trackRef.current || !wrapRef.current) return;
    const card = trackRef.current.children[i];
    if (!card) return;

    const axis = isMobile() ? "top" : "left";
    const size = isMobile() ? "clientHeight" : "clientWidth";
    const start = isMobile() ? card.offsetTop : card.offsetLeft;
    
    wrapRef.current.scrollTo({
      [axis]: start - (wrapRef.current[size] / 2 - card[size] / 2),
      behavior: "smooth"
    });
  }, []);

  const activate = React.useCallback((i, scroll = false) => {
    if (i === current) return;
    setCurrent(i);
    if (scroll) {
      setTimeout(() => center(i), 50);
    }
  }, [current, center]);

  const go = (step) => {
    const newIndex = Math.min(Math.max(current + step, 0), slides.length - 1);
    activate(newIndex, true);
  };

  React.useEffect(() => {
    const handleKeydown = (e) => {
      if (["ArrowRight", "ArrowDown"].includes(e.key)) go(1);
      if (["ArrowLeft", "ArrowUp"].includes(e.key)) go(-1);
    };

    window.addEventListener("keydown", handleKeydown, { passive: true });
    return () => window.removeEventListener("keydown", handleKeydown);
  }, [current]);

  React.useEffect(() => {
    center(current);
  }, [current, center]);

  return React.createElement('section', { style: { background: 'transparent' } }, [
    // Header
    React.createElement('div', { 
      key: 'head',
      className: 'head'
    }, [
      React.createElement('h2', { key: 'title', className: 'text-2xl sm:text-3xl font-bold text-white mb-4 leading-snug' }, 'Why SecureBit.chat is unique'),
      React.createElement('div', { 
        key: 'controls',
        className: 'controls'
      }, [
        React.createElement('button', {
          key: 'prev',
          id: 'prev-slider',
          className: 'nav-btn',
          'aria-label': 'Prev',
          disabled: current === 0,
          onClick: () => go(-1)
        }, '‹'),
        React.createElement('button', {
          key: 'next',
          id: 'next-slider',
          className: 'nav-btn',
          'aria-label': 'Next',
          disabled: current === slides.length - 1,
          onClick: () => go(1)
        }, '›')
      ])
    ]),

    // Slider
    React.createElement('div', {
      key: 'slider',
      className: 'slider',
      ref: wrapRef
    },
      React.createElement('div', {
        className: 'track',
        ref: trackRef
      }, slides.map((slide, index) =>
        React.createElement('article', {
          key: index,
          className: 'project-card',
          ...(index === current ? { active: '' } : {}),
          onMouseEnter: () => {
            if (window.matchMedia("(hover:hover)").matches) {
              activate(index, true);
            }
          },
          onClick: () => activate(index, true)
        }, [
          // Background
          React.createElement('div', {
            key: 'bg',
            className: 'project-card__bg',
            style: {
              background: slide.bgImage,
              backgroundSize: 'cover',
              backgroundPosition: 'center'
            }
          }),

          // Content
          React.createElement('div', {
            key: 'content',
            className: 'project-card__content'
          }, [
            // Text container
            React.createElement('div', { key: 'text' }, [
              React.createElement('h3', {
                key: 'title',
                className: 'project-card__title'
              }, slide.title),
              React.createElement('p', {
                key: 'desc',
                className: 'project-card__desc'
              }, slide.description)
            ])
          ])
        ])
      ))
    ),
  ]);
};

// Export for use in your app
window.UniqueFeatureSlider = UniqueFeatureSlider;