const React = window.React;

const PasswordModal = ({ isOpen, onClose, onSubmit, action, password, setPassword }) => {
    if (!isOpen) return null;
    
    const handleSubmit = (e) => {
        e.preventDefault();
        if (password.trim()) {
            onSubmit(password.trim());
            setPassword('');
        }
    };
    
    const getActionText = () => {
        return action === 'offer' ? 'приглашения' : 'ответа';
    };
    
    return React.createElement('div', {
        className: 'fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4'
    }, [
        React.createElement('div', {
            key: 'modal',
            className: 'card-minimal rounded-xl p-6 max-w-md w-full border-purple-500/20'
        }, [
            React.createElement('div', {
                key: 'header',
                className: 'flex items-center mb-4'
            }, [
                React.createElement('div', {
                    key: 'icon',
                    className: 'w-10 h-10 bg-purple-500/10 border border-purple-500/20 rounded-lg flex items-center justify-center mr-3'
                }, [
                    React.createElement('i', {
                        className: 'fas fa-key accent-purple'
                    })
                ]),
                React.createElement('h3', {
                    key: 'title',
                    className: 'text-lg font-medium text-primary'
                }, 'Ввод пароля')
            ]),
            React.createElement('form', {
                key: 'form',
                onSubmit: handleSubmit,
                className: 'space-y-4'
            }, [
                React.createElement('p', {
                    key: 'description',
                    className: 'text-secondary text-sm'
                }, `Введите пароль для расшифровки ${getActionText()}:`),
                React.createElement('input', {
                    key: 'password-input',
                    type: 'password',
                    value: password,
                    onChange: (e) => setPassword(e.target.value),
                    placeholder: 'Введите пароль...',
                    className: 'w-full p-3 bg-gray-900/30 border border-gray-500/20 rounded-lg text-primary placeholder-gray-500 focus:border-purple-500/40 focus:outline-none transition-all',
                    autoFocus: true
                }),
                React.createElement('div', {
                    key: 'buttons',
                    className: 'flex space-x-3'
                }, [
                    React.createElement('button', {
                        key: 'submit',
                        type: 'submit',
                        className: 'flex-1 btn-primary text-white py-3 px-4 rounded-lg font-medium transition-all duration-200'
                    }, [
                        React.createElement('i', {
                            className: 'fas fa-unlock-alt mr-2'
                        }),
                        'Расшифровать'
                    ]),
                    React.createElement('button', {
                        key: 'cancel',
                        type: 'button',
                        onClick: onClose,
                        className: 'flex-1 btn-secondary text-white py-3 px-4 rounded-lg font-medium transition-all duration-200'
                    }, [
                        React.createElement('i', {
                            className: 'fas fa-times mr-2'
                        }),
                        'Отмена'
                    ])
                ])
            ])
        ])
    ]);
};

window.PasswordModal = PasswordModal;