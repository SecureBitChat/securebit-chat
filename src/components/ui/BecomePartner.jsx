const BecomePartner = () => {
    const partners = [
        { id: 'aegis', name: 'Aegis', logo: 'logo/aegis.png', isColor: true, url: 'https://aegis-investment.com/' },
        { id: 'furi', name: 'Furi Labs', logo: 'logo/furi.png', isColor: true, url: 'https://furilabs.com/' }
    ];

    const formUrl = 'https://docs.google.com/forms/d/e/1FAIpQLSc9ijV9PCoyXkus6vEx1OWwvwAsLq8fKS6-H5BmX-c-bvia6w/viewform?usp=dialog';

    return React.createElement('div', { className: "mt-20 px-6" }, [
        // Header "Trusted by our partners"
        React.createElement('div', { key: 'header', className: "text-center max-w-3xl mx-auto mb-8" }, [
            React.createElement('h3', { key: 'title', className: "text-3xl font-bold text-primary mb-3" }, 'Trusted by our partners')
        ]),

        // First divider line with fade
        React.createElement('div', {
            key: 'divider-1',
            className: "h-px w-full max-w-3xl mx-auto mb-8 bg-gradient-to-r from-transparent via-zinc-700 to-transparent"
        }),

        // Partner Logos
        React.createElement('div', { 
            key: 'partners-row', 
            className: "flex justify-center items-center flex-wrap gap-12 mb-8" 
        },
            partners.map(partner => 
                React.createElement('a', {
                    key: partner.id,
                    href: partner.url,
                    target: '_blank',
                    rel: 'noopener noreferrer',
                    className: "flex items-center justify-center cursor-pointer hover:opacity-100 transition-opacity duration-300"
                }, [
                    React.createElement('img', {
                        key: 'logo',
                        src: partner.logo,
                        alt: partner.name,
                        className: "h-12 sm:h-16 opacity-80 hover:opacity-100 transition-opacity duration-300",
                        style: partner.isColor ? {
                            filter: 'grayscale(100%) brightness(1.2) contrast(1.1)',
                            WebkitFilter: 'grayscale(100%) brightness(1.2) contrast(1.1)'
                        } : {}
                    })
                ])
            )
        ),

        // Second divider line with fade
        React.createElement('div', {
            key: 'divider-2',
            className: "h-px w-full max-w-3xl mx-auto mb-8 bg-gradient-to-r from-transparent via-zinc-700 to-transparent"
        }),

        // Section with subtitle and text
        React.createElement('div', { key: 'cta-section', className: "text-center max-w-3xl mx-auto" }, [
            React.createElement('h4', {
                key: 'subtitle',
                className: "text-base font-semibold text-primary mb-4"
            }, 'Technology & Community Partners'),
            
            React.createElement('p', {
                key: 'description',
                className: "text-secondary text-sm mb-6"
            }, 'Interested in partnering with us?'),

            // CTA Button with 3D glass effect
            React.createElement('div', {
                key: 'button-wrapper',
                className: "button-container flex justify-center"
            }, [
                React.createElement('a', {
                    key: 'button-link',
                    href: formUrl,
                    target: '_blank',
                    rel: 'noopener noreferrer',
                    className: "button"
                }, [
                    React.createElement('span', { key: 'text' }, 'Become a Partner')
                ])
            ])
        ])
    ]);
};

window.BecomePartner = BecomePartner;

