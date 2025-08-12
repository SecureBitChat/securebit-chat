const React = window.React;

const SessionTypeSelector = ({ onSelectType, onCancel }) => {
    const [selectedType, setSelectedType] = React.useState(null);

    const sessionTypes = [
    { 
        id: 'free', 
        name: 'Free', 
        duration: '1 minute', 
        price: '0 sat', 
        usd: '$0.00', 
        popular: true 
    },
    { 
        id: 'basic', 
        name: 'Basic', 
        duration: '1 hour', 
        price: '500 sat', 
        usd: '$0.20' 
    },
    { 
        id: 'premium', 
        name: 'Premium', 
        duration: '4 hours', 
        price: '1000 sat', 
        usd: '$0.40', 
        popular: true 
    },
    { 
        id: 'extended', 
        name: 'Extended', 
        duration: '24 hours', 
        price: '2000 sat', 
        usd: '$0.80' 
    }
    ];


    return React.createElement('div', { className: 'space-y-6' }, [
        React.createElement('div', { key: 'header', className: 'text-center' }, [
            React.createElement('h3', { 
                key: 'title', 
                className: 'text-xl font-semibold text-white mb-2' 
            }, 'Choose a plan'),
            React.createElement('p', { 
                key: 'subtitle', 
                className: 'text-gray-300 text-sm' 
            }, 'Pay via Lightning Network to access the chat')
        ]),
        
        React.createElement('div', { key: 'types', className: 'space-y-3' }, 
            sessionTypes.map(type => 
                React.createElement('div', {
                    key: type.id,
                    onClick: () => setSelectedType(type.id),
                    className: `card-minimal rounded-lg p-4 cursor-pointer border-2 transition-all ${
                        selectedType === type.id ? 'border-orange-500 bg-orange-500/10' : 'border-gray-600 hover:border-orange-400'
                    } ${type.popular ? 'relative' : ''}`
                }, [
                    type.popular && React.createElement('div', { 
                        key: 'badge', 
                        className: 'absolute -top-2 right-3 bg-orange-500 text-white text-xs px-2 py-1 rounded-full' 
                    }, 'Popular'),
                    
                    React.createElement('div', { key: 'content', className: 'flex items-center justify-between' }, [
                        React.createElement('div', { key: 'info' }, [
                            React.createElement('h4', { 
                                key: 'name', 
                                className: 'text-lg font-semibold text-white' 
                            }, type.name),
                            React.createElement('p', { 
                                key: 'duration', 
                                className: 'text-gray-300 text-sm' 
                            }, type.duration)
                        ]),
                        React.createElement('div', { key: 'pricing', className: 'text-right' }, [
                            React.createElement('div', { 
                                key: 'sats', 
                                className: 'text-lg font-bold text-orange-400' 
                            }, type.price),
                            React.createElement('div', { 
                                key: 'usd', 
                                className: 'text-xs text-gray-400' 
                            }, type.usd)
                        ])
                    ])
                ])
            )
        ),
        
        React.createElement('div', { key: 'buttons', className: 'flex space-x-3' }, [
            React.createElement('button', { 
                key: 'continue', 
                onClick: () => selectedType && onSelectType(selectedType), 
                disabled: !selectedType, 
                className: 'flex-1 lightning-button text-white py-3 px-4 rounded-lg font-medium disabled:opacity-50' 
            }, [
                React.createElement('i', { className: 'fas fa-bolt mr-2' }), 
                'Continue to payment'
            ]),
            React.createElement('button', { 
                key: 'cancel', 
                onClick: onCancel, 
                className: 'px-6 py-3 bg-gray-600 hover:bg-gray-500 text-white rounded-lg' 
            }, 'Cancel')
        ])
    ]);
};

window.SessionTypeSelector = SessionTypeSelector;