// Slider Component
        const UniqueFeatureSlider = () => {
            const [currentSlide, setCurrentSlide] = React.useState(0);
        
            const slides = [
                {
                    icon: "fas fa-shield-halved",
                    color: "orange",
                    title: "18-Layer Military Security",
                    description: "Revolutionary defense system with ECDH P-384 + AES-GCM 256 + ECDSA + Complete ASN.1 Validation. Enhanced Security Edition provides military-grade protection exceeding government standards with complete key structure verification."
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
                }, 15000);
                return () => clearInterval(timer);
            }, []);
        
            return React.createElement('div', {
                className: "mt-12"
            }, [
                React.createElement('div', {
                    key: 'header',
                    className: "text-center mb-8"
                }, [
                    React.createElement('h3', {
                        key: 'title',
                        className: "text-2xl font-semibold text-primary mb-3"
                    }, 'Why SecureBit.chat is unique'),
                    React.createElement('p', {
                        key: 'subtitle',
                        className: "text-secondary max-w-2xl mx-auto"
                    }, 'The only messenger with military-grade cryptography')
                ]),
        
                React.createElement('div', {
                    key: 'slider-container',
                    className: "relative max-w-4xl mx-auto"
                }, [
                    React.createElement('div', {
                        key: 'slider-wrapper',
                        className: "overflow-hidden rounded-xl"
                    }, [
                        React.createElement('div', {
                            key: 'slides',
                            className: "flex transition-transform duration-500 ease-in-out",
                            style: { transform: `translateX(-${currentSlide * 100}%)` }
                        }, slides.map((slide, index) =>
                            React.createElement('div', {
                                key: index,
                                className: "w-full flex-shrink-0 px-4"
                            }, [
                                React.createElement('div', {
                                    key: 'slide-content',
                                    className: "card-minimal rounded-xl p-8 text-center min-h-[300px] flex flex-col justify-center relative overflow-hidden"
                                }, [
                                    // Background icon
                                    React.createElement('i', {
                                        key: 'bg-icon',
                                        className: `${slide.icon} absolute right-[-100px] top-1/2 -translate-y-1/2 opacity-10 text-[300px] pointer-events-none ${
                                            slide.color === 'orange' ? 'text-orange-500' :
                                            slide.color === 'yellow' ? 'text-yellow-500' :
                                            slide.color === 'purple' ? 'text-purple-500' :
                                            slide.color === 'green' ? 'text-green-500' :
                                            slide.color === 'cyan' ? 'text-cyan-500' :
                                            slide.color === 'blue' ? 'text-blue-500' :
                                            'text-emerald-500'
                                        }`
                                    }),
        
                                    // Content
                                    React.createElement('h4', {
                                        key: 'slide-title',
                                        className: "text-xl font-semibold text-primary mb-4 relative z-10"
                                    }, slide.title),
                                    React.createElement('p', {
                                        key: 'slide-description',
                                        className: "text-secondary leading-relaxed max-w-2xl mx-auto relative z-10"
                                    }, slide.description)
                                ])
                            ])
                        ))
                    ]),
        
                    // Navigation
                    React.createElement('button', {
                        key: 'prev-btn',
                        onClick: prevSlide,
                        className: "absolute left-2 top-1/2 transform -translate-y-1/2 w-10 h-10 bg-gray-600/80 hover:bg-gray-500/80 text-white rounded-full flex items-center justify-center transition-all duration-200 z-10"
                    }, [
                        React.createElement('i', {
                            key: 'prev-icon',
                            className: "fas fa-chevron-left"
                        })
                    ]),
                    React.createElement('button', {
                        key: 'next-btn',
                        onClick: nextSlide,
                        className: "absolute right-2 top-1/2 transform -translate-y-1/2 w-10 h-10 bg-gray-600/80 hover:bg-gray-500/80 text-white rounded-full flex items-center justify-center transition-all duration-200 z-10"
                    }, [
                        React.createElement('i', {
                            key: 'next-icon',
                            className: "fas fa-chevron-right"
                        })
                    ])
                ]),
        
                // Enhanced dots navigation (оставляем улучшенные точки)
                React.createElement('div', {
                    key: 'dots-container',
                    className: "flex justify-center space-x-3 mt-6"
                }, slides.map((slide, index) =>
                    React.createElement('button', {
                        key: index,
                        onClick: () => goToSlide(index),
                        className: `relative group transition-all duration-300 ${
                            index === currentSlide
                                ? 'w-12 h-2 bg-orange-500 rounded-full'
                                : 'w-4 h-2 bg-gray-600 hover:bg-gray-500 rounded-full hover:scale-125'
                        }`
                    }, [
                        // Tooltip on hover
                        React.createElement('div', {
                            key: 'tooltip',
                            className: "absolute -top-10 left-1/2 transform -translate-x-1/2 bg-gray-800 text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity duration-200 whitespace-nowrap pointer-events-none"
                        }, slide.title)
                    ])
                ))
            ]);
        };

        window.UniqueFeatureSlider = UniqueFeatureSlider;