// Advanced network settings: lets a user supply their own STUN/TURN servers
// instead of the bundled public defaults, and toggle relay-only privacy mode.
// Free / power-user feature, hidden behind an explicit "Advanced" entry point.
//
// All input is validated through src/network/iceServers.js before it can reach
// RTCPeerConnection. Persistence is opt-in and encrypted at rest (see
// src/network/iceSettingsStore.js).
import {
    parseIceServersInput,
    listHasTurn,
    ICE_LIMITS
} from '../../network/iceServers.js';

const React = window.React;

const PLACEHOLDER = [
    '# One URL per line, e.g.:',
    'stun:stun.example.com:3478',
    'turn:turn.example.com:3478?transport=udp',
    '',
    '# Or paste JSON for servers with credentials:',
    '[{"urls":"turns:turn.example.com:5349","username":"user","credential":"secret"}]'
].join('\n');

async function testIceServers(servers, timeoutMs = 6000) {
    const found = { host: 0, srflx: 0, relay: 0 };
    if (typeof RTCPeerConnection === 'undefined') {
        return { ...found, error: 'WebRTC is not available in this browser' };
    }
    let pc;
    try {
        pc = new RTCPeerConnection({ iceServers: servers });
    } catch (error) {
        return { ...found, error: error.message || 'Invalid server configuration' };
    }

    return new Promise((resolve) => {
        let settled = false;
        const finish = () => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            try { pc.close(); } catch { /* noop */ }
            resolve(found);
        };
        const timer = setTimeout(finish, timeoutMs);

        pc.onicecandidate = (event) => {
            if (!event.candidate) { finish(); return; }
            const c = event.candidate.candidate || '';
            if (/ typ host/.test(c)) found.host++;
            else if (/ typ srflx/.test(c)) found.srflx++;
            else if (/ typ relay/.test(c)) found.relay++;
        };

        try {
            pc.createDataChannel('securebit-ice-test');
            pc.createOffer()
                .then((offer) => pc.setLocalDescription(offer))
                .catch(() => finish());
        } catch {
            finish();
        }
    });
}

const IceServerSettings = ({ isOpen, onClose, initial, hasSaved, onApply, onForget }) => {
    if (!isOpen) return null;

    const [useCustom, setUseCustom] = React.useState(initial?.useCustom || false);
    const [serversText, setServersText] = React.useState(initial?.serversText || '');
    const [relayOnly, setRelayOnly] = React.useState(initial?.privacyMode === 'relay-only');
    const [persist, setPersist] = React.useState(initial?.persisted || false);
    const [testState, setTestState] = React.useState('idle'); // idle | running | done
    const [testResult, setTestResult] = React.useState(null);

    const parsed = useCustom ? parseIceServersInput(serversText) : { servers: [], errors: [], warnings: [] };
    const hasTurn = listHasTurn(parsed.servers);
    const canApply = !useCustom || (parsed.servers.length > 0 && parsed.errors.length === 0);

    const handleTest = async () => {
        setTestState('running');
        setTestResult(null);
        const result = await testIceServers(parsed.servers);
        setTestResult(result);
        setTestState('done');
    };

    const handleApply = () => {
        if (!canApply) return;
        onApply(
            {
                useCustom,
                servers: useCustom ? parsed.servers : [],
                privacyMode: relayOnly ? 'relay-only' : 'standard',
                serversText
            },
            persist
        );
    };

    const handleForget = async () => {
        if (onForget) await onForget();
        setPersist(false);
    };

    const labelCls = 'block text-sm font-medium text-primary';
    const descCls = 'block text-sm text-secondary';

    const children = [];

    // Header
    children.push(React.createElement('div', { key: 'header', className: 'flex items-center mb-4' }, [
        React.createElement('div', {
            key: 'icon',
            className: 'w-10 h-10 bg-purple-500/10 border border-purple-500/20 rounded-lg flex items-center justify-center mr-3'
        }, [React.createElement('i', { className: 'fas fa-network-wired accent-purple' })]),
        React.createElement('h3', { key: 'title', className: 'text-lg font-medium text-primary' }, 'Advanced network settings')
    ]));

    // Explainer
    children.push(React.createElement('p', { key: 'intro', className: 'text-sm text-secondary mb-4' },
        'By default SecureBit uses public STUN servers. You can supply your own STUN/TURN servers — useful if you self-host a TURN relay and do not want to rely on public infrastructure. Servers are configured locally on your side only; you do not need to share them with your peer.'
    ));

    // Mode radios
    children.push(React.createElement('div', { key: 'mode', className: 'space-y-2 mb-4' }, [
        React.createElement('label', { key: 'public', className: 'flex items-start gap-3' }, [
            React.createElement('input', {
                key: 'r', type: 'radio', name: 'ice-mode', checked: !useCustom,
                onChange: () => setUseCustom(false), className: 'mt-1'
            }),
            React.createElement('span', { key: 's' }, [
                React.createElement('span', { key: 't', className: labelCls }, 'Public servers (default)'),
                React.createElement('span', { key: 'd', className: descCls }, 'Zero-config. Good for most users.')
            ])
        ]),
        React.createElement('label', { key: 'custom', className: 'flex items-start gap-3' }, [
            React.createElement('input', {
                key: 'r', type: 'radio', name: 'ice-mode', checked: useCustom,
                onChange: () => setUseCustom(true), className: 'mt-1'
            }),
            React.createElement('span', { key: 's' }, [
                React.createElement('span', { key: 't', className: labelCls }, 'My own STUN/TURN servers'),
                React.createElement('span', { key: 'd', className: descCls }, `Up to ${ICE_LIMITS.MAX_SERVERS} servers.`)
            ])
        ])
    ]));

    // Textarea + validation (only in custom mode)
    if (useCustom) {
        children.push(React.createElement('textarea', {
            key: 'textarea',
            value: serversText,
            onChange: (e) => setServersText(e.target.value),
            placeholder: PLACEHOLDER,
            spellCheck: false,
            autoComplete: 'off',
            className: 'w-full h-36 mb-2 p-3 rounded-lg bg-black/30 border border-purple-500/20 text-sm text-primary font-mono'
        }));

        if (parsed.errors.length > 0) {
            children.push(React.createElement('ul', { key: 'errors', className: 'mb-2 text-sm text-red-400 list-disc pl-5' },
                parsed.errors.slice(0, 6).map((err, i) => React.createElement('li', { key: i }, err))
            ));
        }
        if (parsed.warnings.length > 0) {
            children.push(React.createElement('ul', { key: 'warnings', className: 'mb-2 text-sm text-yellow-400 list-disc pl-5' },
                parsed.warnings.slice(0, 6).map((w, i) => React.createElement('li', { key: i }, w))
            ));
        }
        if (parsed.servers.length > 0 && parsed.errors.length === 0) {
            children.push(React.createElement('p', { key: 'ok', className: 'mb-2 text-sm text-green-400' },
                `${parsed.servers.length} server(s) parsed${hasTurn ? ' (TURN present)' : ' (STUN only — does not hide IP)'}.`
            ));
        }

        // Privacy disclaimer about third-party relays
        children.push(React.createElement('p', { key: 'disclaimer', className: 'mb-3 text-xs text-secondary' },
            'Privacy note: a TURN relay sees the IP addresses and traffic timing of both peers (never your message contents, which stay end-to-end encrypted). Only a TURN server you trust or self-host improves privacy — pointing this at a random public relay does not. Prefer turns: (TLS).'
        ));

        // Test button + result
        children.push(React.createElement('div', { key: 'test', className: 'mb-3' }, [
            React.createElement('button', {
                key: 'btn',
                type: 'button',
                disabled: !canApply || testState === 'running',
                onClick: handleTest,
                className: 'px-3 py-2 text-sm rounded-lg border border-purple-500/30 text-primary disabled:opacity-50'
            }, testState === 'running' ? 'Testing…' : 'Test servers'),
            testState === 'done' && testResult ? React.createElement('span', {
                key: 'res',
                className: 'ml-3 text-sm ' + (testResult.error ? 'text-red-400' : 'text-secondary')
            }, testResult.error
                ? `Test failed: ${testResult.error}`
                : `STUN ${testResult.srflx > 0 ? 'OK' : 'none'} · TURN ${testResult.relay > 0 ? 'OK' : 'none'} · host ${testResult.host}`
            ) : null
        ]));
    }

    // Relay-only privacy toggle
    children.push(React.createElement('label', { key: 'relay', className: 'flex items-start gap-3 mb-3 rounded-lg border border-purple-500/20 bg-purple-500/10 p-3' }, [
        React.createElement('input', {
            key: 'i', type: 'checkbox', checked: relayOnly,
            onChange: (e) => setRelayOnly(e.target.checked), className: 'mt-1'
        }),
        React.createElement('span', { key: 's' }, [
            React.createElement('span', { key: 't', className: labelCls }, 'Relay-only mode (maximum privacy)'),
            React.createElement('span', { key: 'd', className: descCls }, 'Routes all traffic through TURN so your IP is not exposed to the peer. Requires a TURN server; connections cannot start without one.')
        ])
    ]));
    if (relayOnly && useCustom && !hasTurn) {
        children.push(React.createElement('p', { key: 'relaywarn', className: 'mb-3 text-sm text-yellow-400' },
            'Relay-only is enabled but no TURN server is configured. The connection will not be able to start.'
        ));
    }

    // Save on device
    children.push(React.createElement('label', { key: 'persist', className: 'flex items-start gap-3 mb-4' }, [
        React.createElement('input', {
            key: 'i', type: 'checkbox', checked: persist,
            onChange: (e) => setPersist(e.target.checked), className: 'mt-1'
        }),
        React.createElement('span', { key: 's' }, [
            React.createElement('span', { key: 't', className: labelCls }, 'Save on this device'),
            React.createElement('span', { key: 'd', className: descCls }, 'Stored encrypted in this browser. Leave off to use only for this session.')
        ])
    ]));

    // Action buttons
    const actions = [
        React.createElement('button', {
            key: 'cancel', type: 'button', onClick: onClose,
            className: 'px-4 py-2 text-sm rounded-lg border border-white/10 text-secondary'
        }, 'Cancel'),
        React.createElement('button', {
            key: 'apply', type: 'button', onClick: handleApply, disabled: !canApply,
            className: 'px-4 py-2 text-sm rounded-lg bg-purple-500/20 border border-purple-500/30 text-primary disabled:opacity-50'
        }, 'Apply')
    ];
    if (hasSaved) {
        actions.unshift(React.createElement('button', {
            key: 'forget', type: 'button', onClick: handleForget,
            className: 'px-4 py-2 text-sm rounded-lg border border-red-500/30 text-red-400 mr-auto'
        }, 'Forget saved'));
    }
    children.push(React.createElement('div', { key: 'actions', className: 'flex items-center gap-2 flex-wrap' }, actions));

    return React.createElement('div', {
        className: 'fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4',
        onClick: (e) => { if (e.target === e.currentTarget) onClose(); }
    }, [
        React.createElement('div', {
            key: 'modal',
            className: 'card-minimal rounded-xl p-6 max-w-lg w-full border-purple-500/20 max-h-[90vh] overflow-y-auto'
        }, children)
    ]);
};

window.IceServerSettings = IceServerSettings;

export { IceServerSettings, testIceServers };
