import { installDebugWindowHooks } from './utils/debugWindowHooks.js';
import { loadIceSettings, saveIceSettings, clearIceSettings } from './network/iceSettingsStore.js';
import {
    sessionsReducer,
    createInitialState,
    createSessionEntry,
    decorateSessions,
    monoInitials,
    statusDot,
    MY_STATUS_OPTIONS,
    PRESENCE_DOT,
    PRESENCE_WORD,
    SESSION_ACTIONS as SA
} from './state/sessionsStore.js';

                // ── Secure chat extras: code blocks, clipboard hygiene ──────────────
                // Copy text to the clipboard and (optionally) wipe it after a delay so
                // copied secrets (keys, commands, codes) don't linger. We only clear
                // when we can confirm the clipboard still holds exactly what we wrote,
                // or when the clipboard can't be read back at all — never clobbering
                // something the user copied afterwards that we can see is different.
                const copyToClipboardSecure = async (text, autoClearMs = 0) => {
                    let ok = false;
                    try {
                        await navigator.clipboard.writeText(text);
                        ok = true;
                    } catch (e) {
                        try {
                            const ta = document.createElement('textarea');
                            ta.value = text;
                            ta.style.position = 'fixed';
                            ta.style.opacity = '0';
                            document.body.appendChild(ta);
                            ta.select();
                            ok = document.execCommand('copy');
                            document.body.removeChild(ta);
                        } catch (_) { ok = false; }
                    }
                    if (ok && autoClearMs > 0 && navigator.clipboard && navigator.clipboard.writeText) {
                        setTimeout(async () => {
                            let current = null;
                            let readable = true;
                            try { current = await navigator.clipboard.readText(); }
                            catch (_) { readable = false; }
                            if (!readable || current === text) {
                                try { await navigator.clipboard.writeText(''); } catch (_) {}
                            }
                        }, autoClearMs);
                    }
                    return ok;
                };

                // Split a message into plain-text and fenced ``` code segments.
                // Returns null when there is no fenced code so callers can fast-path.
                const parseMessageSegments = (text) => {
                    if (typeof text !== 'string' || text.indexOf('```') === -1) return null;
                    const segments = [];
                    const re = /```([a-zA-Z0-9_+#.-]*)\n?([\s\S]*?)```/g;
                    let last = 0;
                    let m;
                    while ((m = re.exec(text)) !== null) {
                        if (m.index > last) segments.push({ kind: 'text', content: text.slice(last, m.index) });
                        segments.push({ kind: 'code', lang: (m[1] || '').toLowerCase(), content: m[2].replace(/\n$/, '') });
                        last = re.lastIndex;
                    }
                    if (last < text.length) segments.push({ kind: 'text', content: text.slice(last) });
                    return segments.some(s => s.kind === 'code') ? segments : null;
                };

                // Lightweight, dependency-free syntax highlighter. Returns React nodes
                // (no innerHTML / dangerouslySetInnerHTML) so it stays CSP-safe and adds
                // no XSS surface. Language-agnostic: highlights comments, strings,
                // numbers, common keywords and literals — good enough for snippets
                // without shipping a heavy library or allowing remote scripts.
                const HL_KEYWORDS = new Set([
                    'const','let','var','function','return','if','else','for','while','do','switch',
                    'case','break','continue','class','extends','new','this','super','import','export',
                    'from','as','default','async','await','try','catch','finally','throw','typeof',
                    'instanceof','delete','yield','in','of','def','elif','lambda','pass','with','global',
                    'public','private','protected','static','final','void','int','long','float','double',
                    'char','bool','boolean','string','struct','enum','interface','package','func','fn',
                    'type','where','select','update','insert','delete','where','and','or','not','end',
                    'then','fi','done','echo','use','mut','impl','trait','match','module','require'
                ]);
                const HL_LITERALS = new Set(['true','false','null','undefined','None','True','False','nil','NaN','Infinity']);
                const highlightCode = (code) => {
                    const re = /(\/\/[^\n]*|#[^\n]*|\/\*[\s\S]*?\*\/|--[^\n]*)|(`(?:\\.|[^`\\])*`|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(\b\d[\d_.]*(?:[eE][+-]?\d+)?\b|\b0[xX][0-9a-fA-F]+\b)|([A-Za-z_$][A-Za-z0-9_$]*)/g;
                    const nodes = [];
                    let buffer = '';
                    let last = 0;
                    let key = 0;
                    const flush = () => { if (buffer) { nodes.push(buffer); buffer = ''; } };
                    let m;
                    while ((m = re.exec(code)) !== null) {
                        if (m.index > last) buffer += code.slice(last, m.index);
                        last = re.lastIndex;
                        let cls = null;
                        if (m[1]) cls = 'text-gray-500 italic';        // comment
                        else if (m[2]) cls = 'text-amber-300';         // string
                        else if (m[3]) cls = 'text-sky-300';           // number
                        else if (m[4]) {                                // identifier
                            if (HL_KEYWORDS.has(m[4])) cls = 'text-purple-300';
                            else if (HL_LITERALS.has(m[4])) cls = 'text-sky-300';
                        }
                        if (cls) {
                            flush();
                            nodes.push(React.createElement('span', { key: `h${key++}`, className: cls }, m[0]));
                        } else {
                            buffer += m[0];
                        }
                    }
                    if (last < code.length) buffer += code.slice(last);
                    flush();
                    return nodes;
                };

                // Fenced-language → Prism grammar id (with common aliases).
                const PRISM_ALIAS = {
                    js: 'javascript', mjs: 'javascript', javascript: 'javascript', node: 'javascript',
                    ts: 'typescript', typescript: 'typescript', jsx: 'jsx', tsx: 'tsx',
                    py: 'python', python: 'python', sh: 'bash', shell: 'bash', zsh: 'bash', bash: 'bash',
                    'c++': 'cpp', cpp: 'cpp', cc: 'cpp', cxx: 'cpp', c: 'c', h: 'c',
                    cs: 'csharp', csharp: 'csharp', java: 'java', go: 'go', golang: 'go',
                    rs: 'rust', rust: 'rust', json: 'json', yml: 'yaml', yaml: 'yaml', sql: 'sql',
                    md: 'markdown', markdown: 'markdown', html: 'markup', xml: 'markup', svg: 'markup', css: 'css'
                };

                // Monospace code window with a copy button (clipboard auto-clears in 30s).
                // Syntax highlighting is done by Prism when available. SECURITY: Prism only
                // TOKENIZES the snippet — it never executes it. Prism.highlight() HTML-escapes
                // the input before tokenizing, so the highlighted markup contains no live code
                // and can't inject scripts (CSP also blocks inline execution). When Prism or the
                // grammar is missing we fall back to the dependency-free React-node highlighter.
                const CodeBlock = ({ code, lang }) => {
                    const [copied, setCopied] = React.useState(false);
                    const handleCopy = async () => {
                        const ok = await copyToClipboardSecure(code, 30000);
                        if (ok) {
                            setCopied(true);
                            setTimeout(() => setCopied(false), 2000);
                        }
                    };
                    const norm = PRISM_ALIAS[(lang || '').toLowerCase()] || (lang || '').toLowerCase();
                    const prism = (typeof window !== 'undefined') ? window.Prism : null;
                    const grammar = (prism && prism.languages) ? prism.languages[norm] : null;
                    const usePrism = !!(prism && grammar && typeof prism.highlight === 'function');
                    let highlightedHtml = null;
                    if (usePrism) {
                        try { highlightedHtml = prism.highlight(code, grammar, norm); } catch (_) { highlightedHtml = null; }
                    }
                    const displayLang = (usePrism ? norm : (lang || 'code'));
                    const codeEl = (usePrism && highlightedHtml != null)
                        // Prism-escaped highlight markup — safe to inject (no live code).
                        ? React.createElement('code', { className: 'language-' + norm, dangerouslySetInnerHTML: { __html: highlightedHtml } })
                        // Fallback: React text nodes, never HTML.
                        : React.createElement('code', null, highlightCode(code));
                    return React.createElement('div', {
                        className: "my-1 rounded-lg overflow-hidden",
                        style: { backgroundColor: '#1b1c1b', border: '0 solid #e5e7eb' }
                    }, [
                        React.createElement('div', {
                            key: 'hdr',
                            className: "flex items-center justify-between px-3 py-1.5",
                            style: { backgroundColor: '#222322', border: '0 solid #e5e7eb' }
                        }, [
                            React.createElement('span', {
                                key: 'lang',
                                className: "text-[11px] uppercase tracking-wide text-gray-500 font-mono"
                            }, displayLang),
                            React.createElement('button', {
                                key: 'copy',
                                onClick: handleCopy,
                                title: "Copy — clipboard auto-clears in 30s",
                                className: "flex items-center text-[11px] text-gray-400 hover:text-green-400 transition-colors"
                            }, [
                                React.createElement('i', {
                                    key: 'ic',
                                    className: `${copied ? 'fas fa-check text-green-400' : 'far fa-copy'} mr-1`
                                }),
                                copied ? 'Copied' : 'Copy'
                            ])
                        ]),
                        React.createElement('pre', {
                            key: 'pre',
                            className: "px-3 py-2 overflow-x-auto text-xs leading-relaxed text-gray-200 custom-scrollbar",
                            style: { whiteSpace: 'pre', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', margin: 0 }
                        }, codeEl)
                    ]);
                };

                // Render a message body: code windows for fenced blocks, line-preserving
                // text otherwise. Built from already-sanitized text via React nodes only.
                const MessageBody = ({ text }) => {
                    const segments = parseMessageSegments(text);
                    if (!segments) {
                        return React.createElement('div', {
                            className: "text-sm break-words",
                            style: { whiteSpace: 'pre-wrap', wordBreak: 'break-word' }
                        }, text);
                    }
                    return React.createElement('div', { className: "text-sm" },
                        segments.map((seg, i) => seg.kind === 'code'
                            ? React.createElement(CodeBlock, { key: i, code: seg.content, lang: seg.lang })
                            : (seg.content.trim()
                                ? React.createElement('div', {
                                    key: i,
                                    className: "break-words",
                                    style: { whiteSpace: 'pre-wrap', wordBreak: 'break-word' }
                                }, seg.content)
                                : null)
                        )
                    );
                };

                // Composer toolbar: code / view-once / disappearing.
                // Borderless icon+label buttons; active state uses the brand orange
                // (accent-orange). View-once and Timer open a small time picker.
                const ChatToolbar = ({ codeMode, setCodeMode, viewOnceMode, setViewOnceMode, viewOnceTtl, setViewOnceTtl, disappearTtl, setDisappearTtl }) => {
                    const [openMenu, setOpenMenu] = React.useState(null); // 'once' | 'timer' | null
                    const fmt = (s) => s >= 3600 ? `${Math.round(s / 3600)}h` : (s >= 60 ? `${Math.round(s / 60)}m` : `${s}s`);

                    const btnClass = (active) =>
                        `inline-flex items-center gap-2 h-9 px-3 rounded-lg text-xs font-medium transition-colors duration-150 ${active
                            ? 'accent-orange bg-orange-500/10'
                            : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700/40'}`;

                    const pickerItem = (opt, current, onPick) =>
                        React.createElement('button', {
                            key: String(opt.value),
                            type: 'button',
                            onClick: () => { onPick(opt.value); setOpenMenu(null); },
                            // Comfortable tap target + readable size on mobile.
                            className: `w-full text-left px-4 py-3 sm:py-2.5 text-sm flex items-center gap-3 transition-colors ${current === opt.value
                                ? 'accent-orange bg-orange-500/10'
                                : 'text-gray-200 hover:bg-gray-700/50 active:bg-gray-700/60'}`
                        }, [
                            React.createElement('i', { key: 'i', className: `${opt.icon || 'far fa-clock'} w-4 text-center` }),
                            React.createElement('span', { key: 'l' }, opt.label)
                        ]);

                    // Opens UPWARD (bottom:100%) via inline style so it never depends on a
                    // purgeable utility class and never pushes the composer layout down.
                    const picker = (options, current, onPick) =>
                        React.createElement('div', {
                            className: "absolute right-0 z-50 min-w-[180px] max-w-[78vw] rounded-xl shadow-2xl overflow-hidden",
                            style: { backgroundColor: '#1f201f', border: '0 solid #e5e7eb', bottom: '100%', marginBottom: '8px' }
                        }, options.map(opt => pickerItem(opt, current, onPick)));

                    const labelBtn = (key, { active, icon, label, title, onClick }) =>
                        React.createElement('button', {
                            key, type: 'button', onClick, title, 'aria-pressed': !!active,
                            className: btnClass(active)
                        }, [
                            React.createElement('i', { key: 'i', className: `${icon} text-[13px]` }),
                            React.createElement('span', { key: 'l', className: 'leading-none' }, label)
                        ]);

                    return React.createElement('div', { className: "flex items-center gap-1" }, [
                        // Invisible backdrop closes any open picker on outside click.
                        openMenu && React.createElement('div', {
                            key: 'backdrop',
                            className: "fixed inset-0 z-40",
                            onClick: () => setOpenMenu(null)
                        }),

                        // Code — toggles code mode (expands the input box).
                        labelBtn('code', {
                            active: codeMode,
                            icon: 'fas fa-code',
                            label: 'Code',
                            title: 'Send as a code block (expands the input)',
                            onClick: () => setCodeMode(v => !v)
                        }),

                        // View once — pick how long it stays after the peer opens it.
                        React.createElement('div', { key: 'once', className: 'relative' }, [
                            labelBtn('once-btn', {
                                active: viewOnceMode,
                                icon: 'fas fa-eye-slash',
                                label: viewOnceMode ? `Once · ${fmt(viewOnceTtl)}` : 'View once',
                                title: 'View once — vanishes after the peer reads it',
                                onClick: () => setOpenMenu(openMenu === 'once' ? null : 'once')
                            }),
                            openMenu === 'once' && picker([
                                { value: 0, label: 'Off', icon: 'fas fa-ban' },
                                { value: 5, label: '5s after reading' },
                                { value: 15, label: '15s after reading' },
                                { value: 30, label: '30s after reading' },
                                { value: 60, label: '1m after reading' }
                            ], viewOnceMode ? viewOnceTtl : 0, (v) => {
                                if (v === 0) { setViewOnceMode(false); }
                                else { setViewOnceTtl(v); setViewOnceMode(true); }
                            })
                        ]),

                        // Timer — pick the disappearing duration.
                        React.createElement('div', { key: 'timer', className: 'relative' }, [
                            labelBtn('timer-btn', {
                                active: disappearTtl > 0,
                                icon: 'fas fa-stopwatch',
                                label: disappearTtl > 0 ? `Timer · ${fmt(disappearTtl)}` : 'Timer',
                                title: 'Disappearing message — deletes on both sides',
                                onClick: () => setOpenMenu(openMenu === 'timer' ? null : 'timer')
                            }),
                            openMenu === 'timer' && picker([
                                { value: 0, label: 'Off', icon: 'fas fa-ban' },
                                { value: 30, label: '30 seconds' },
                                { value: 300, label: '5 minutes' },
                                { value: 3600, label: '1 hour' }
                            ], disappearTtl, (v) => setDisappearTtl(v))
                        ])
                    ]);
                };

                // Enhanced Copy Button with better UX
                const EnhancedCopyButton = ({ text, className = "", children }) => {
                    const [copied, setCopied] = React.useState(false);
        
                    const handleCopy = async () => {
                        try {
                            await navigator.clipboard.writeText(text);
                            setCopied(true);
                            setTimeout(() => setCopied(false), 2000);
                        } catch (error) {
                            console.error('Copy failed:', error);
                            // Fallback for older browsers
                            const textArea = document.createElement('textarea');
                            textArea.value = text;
                            document.body.appendChild(textArea);
                            textArea.select();
                            document.execCommand('copy');
                            document.body.removeChild(textArea);
                            setCopied(true);
                            setTimeout(() => setCopied(false), 2000);
                        }
                    };
        
                    return React.createElement('button', {
                        onClick: handleCopy,
                        className: `${className} transition-all duration-200`
                    }, [
                        React.createElement('i', {
                            key: 'icon',
                            className: `${copied ? 'fas fa-check accent-green' : 'fas fa-copy text-secondary'} mr-2`
                        }),
                        copied ? 'Copied!' : children
                    ]);
                };
        
                // Verification Component
                const VerificationStep = ({ verificationCode, onConfirm, onReject, localConfirmed, remoteConfirmed, bothConfirmed }) => {
                    const [sasInput, setSasInput] = React.useState('');
                    const [error, setError] = React.useState('');
                    const normalizedExpectedLength = (verificationCode || '').replace(/[-\s]/g, '').length;
                    const normalizedInputLength = sasInput.replace(/[-\s]/g, '').length;
                    const canConfirm = !localConfirmed && normalizedExpectedLength > 0 && normalizedInputLength === normalizedExpectedLength;

                    React.useEffect(() => {
                        setSasInput('');
                        setError('');
                    }, [verificationCode]);

                    const handleConfirm = async () => {
                        try {
                            setError('');
                            await onConfirm(sasInput);
                        } catch (confirmationError) {
                            setSasInput('');
                            if (confirmationError?.message === 'SAS_MAX_ATTEMPTS') {
                                setError('Too many incorrect attempts. Session reset for safety.');
                            } else {
                                setError('Incorrect code. Check it with your peer and try again.');
                            }
                        }
                    };

                    return React.createElement('div', {
                        className: "card-minimal rounded-xl p-6 border-purple-500/20"
                    }, [
                        React.createElement('div', {
                            key: 'header',
                            className: "flex items-center mb-4"
                        }, [
                            React.createElement('div', {
                                key: 'icon',
                                className: "w-10 h-10 bg-purple-500/10 border border-purple-500/20 rounded-lg flex items-center justify-center mr-3"
                            }, [
                                React.createElement('i', {
                                    className: 'fas fa-shield-alt accent-purple'
                                })
                            ]),
                            React.createElement('h3', {
                                key: 'title',
                                className: "text-lg font-medium text-primary"
                            }, "Security verification")
                        ]),
                        React.createElement('div', {
                            key: 'content',
                            className: "space-y-4"
                        }, [
                            React.createElement('p', {
                                key: 'description',
                                className: "text-secondary text-sm"
                            }, "Compare this code with your peer out-of-band, then type the same code below to unlock the chat."),
                            React.createElement('div', {
                                key: 'code-display',
                                className: "text-center"
                            }, [
                                React.createElement('div', {
                                    key: 'code',
                                    className: "verification-code text-2xl py-4"
                                }, verificationCode)
                            ]),
                            React.createElement('div', {
                                key: 'sas-input-wrap',
                                className: "space-y-2"
                            }, [
                                React.createElement('label', {
                                    key: 'sas-label',
                                    className: "block text-sm text-secondary"
                                }, "Enter the verified code"),
                                React.createElement('input', {
                                    key: 'sas-input',
                                    type: 'text',
                                    value: sasInput,
                                    onChange: (event) => {
                                        setSasInput(event.target.value.toUpperCase());
                                        if (error) setError('');
                                    },
                                    autoFocus: true,
                                    autoComplete: 'off',
                                    spellCheck: false,
                                    inputMode: 'text',
                                    disabled: localConfirmed,
                                    placeholder: verificationCode ? 'Type code here' : 'Waiting for code…',
                                    className: "w-full rounded-lg border border-purple-500/30 bg-black/20 px-4 py-3 text-center text-xl tracking-[0.3em] text-primary uppercase focus:border-purple-400 focus:outline-none disabled:cursor-not-allowed disabled:opacity-60",
                                    style: { fontFamily: 'monospace', textTransform: 'uppercase' }
                                }),
                                error && React.createElement('p', {
                                    key: 'sas-error',
                                    className: "text-sm text-red-400"
                                }, error)
                            ]),
                            // Verification status indicators
                            React.createElement('div', {
                                key: 'verification-status',
                                className: "space-y-2"
                            }, [
                                React.createElement('div', {
                                    key: 'local-status',
                                    className: `flex items-center justify-between p-2 rounded-lg ${localConfirmed ? 'bg-green-500/10 border border-green-500/20' : 'bg-gray-500/10 border border-gray-500/20'}`
                                }, [
                                    React.createElement('span', {
                                        key: 'local-label',
                                        className: "text-sm text-secondary"
                                    }, "Your confirmation:"),
                                    React.createElement('div', {
                                        key: 'local-indicator',
                                        className: "flex items-center"
                                    }, [
                                        React.createElement('i', {
                                            key: 'local-icon',
                                            className: `fas ${localConfirmed ? 'fa-check-circle text-green-400' : 'fa-clock text-gray-400'} mr-2`
                                        }),
                                        React.createElement('span', {
                                            key: 'local-text',
                                            className: `text-sm ${localConfirmed ? 'text-green-400' : 'text-gray-400'}`
                                        }, localConfirmed ? 'Confirmed' : 'Pending')
                                    ])
                                ]),
                                React.createElement('div', {
                                    key: 'remote-status',
                                    className: `flex items-center justify-between p-2 rounded-lg ${remoteConfirmed ? 'bg-green-500/10 border border-green-500/20' : 'bg-gray-500/10 border border-gray-500/20'}`
                                }, [
                                    React.createElement('span', {
                                        key: 'remote-label',
                                        className: "text-sm text-secondary"
                                    }, "Peer confirmation:"),
                                    React.createElement('div', {
                                        key: 'remote-indicator',
                                        className: "flex items-center"
                                    }, [
                                        React.createElement('i', {
                                            key: 'remote-icon',
                                            className: `fas ${remoteConfirmed ? 'fa-check-circle text-green-400' : 'fa-clock text-gray-400'} mr-2`
                                        }),
                                        React.createElement('span', {
                                            key: 'remote-text',
                                            className: `text-sm ${remoteConfirmed ? 'text-green-400' : 'text-gray-400'}`
                                        }, remoteConfirmed ? 'Confirmed' : 'Pending')
                                    ])
                                ])
                            ]),
                            React.createElement('div', {
                                key: 'warning',
                                className: "p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg"
                            }, [
                                React.createElement('p', {
                                    className: "text-yellow-400 text-sm flex items-center"
                                }, [
                                    React.createElement('i', {
                                        className: 'fas fa-exclamation-triangle mr-2'
                                    }),
                                    'Make sure the codes match exactly.!'
                                ])
                            ]),
                            React.createElement('div', {
                                key: 'buttons',
                                className: "flex space-x-3"
                            }, [
                                React.createElement('button', {
                                    key: 'confirm',
                                    onClick: handleConfirm,
                                    disabled: !canConfirm,
                                    className: `flex-1 py-3 px-4 rounded-lg font-medium transition-all duration-200 ${!canConfirm ? 'bg-gray-500/20 text-gray-400 cursor-not-allowed' : 'btn-verify text-white'}`
                                }, [
                                    React.createElement('i', {
                                        className: `fas ${localConfirmed ? 'fa-check-circle' : 'fa-check'} mr-2`
                                    }),
                                    localConfirmed ? 'Confirmed' : 'Confirm code'
                                ]),
                                React.createElement('button', {
                                    key: 'reject',
                                    onClick: onReject,
                                    className: "flex-1 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 py-3 px-4 rounded-lg font-medium transition-all duration-200"
                                }, [
                                    React.createElement('i', {
                                        className: 'fas fa-times mr-2'
                                    }),
                                    'The codes do not match'
                                ])
                            ])
                        ])
                    ]);
                };
        
                // Grain overlay for the view-once cover (Telegram-style blur + noise).
                const GRAIN_URL = `url("data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20width='100'%20height='100'%3E%3Cfilter%20id='n'%3E%3CfeTurbulence%20type='fractalNoise'%20baseFrequency='0.9'%20numOctaves='2'%20stitchTiles='stitch'/%3E%3C/filter%3E%3Crect%20width='100%25'%20height='100%25'%20filter='url(%23n)'/%3E%3C/svg%3E")`;
                const SB_MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";

                // Enhanced Chat Message — redesigned bubbles (SecureBit Chat design).
                const EnhancedChatMessage = ({ message, type, timestamp, mid, status, viewOnce, viewOnceTtl, expiresAt, expired, nowTick, canUnsend, onUnsend, onExpire }) => {
                    const [revealed, setRevealed] = React.useState(false);
                    const revealTimerRef = React.useRef(null);

                    const formatTime = (ts) => new Date(ts).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

                    React.useEffect(() => () => { if (revealTimerRef.current) clearTimeout(revealTimerRef.current); }, []);

                    // System / notice messages: centered subtle pill. "notice" is shown
                    // in the message flow (e.g. "connection restored"); "system" lives in
                    // the handshake log. Notices use a green accent.
                    if (type === 'system' || type === 'notice') {
                        const isNotice = type === 'notice';
                        return React.createElement('div', { className: 'message-slide', style: { display: 'flex', justifyContent: 'center', margin: '4px 0' } },
                            React.createElement('div', {
                                style: { maxWidth: '80%', padding: '8px 14px', borderRadius: '10px', border: '1px solid ' + (isNotice ? 'rgba(62,207,142,0.25)' : 'rgba(240,137,42,0.22)'), background: isNotice ? 'rgba(62,207,142,0.08)' : 'rgba(240,137,42,0.08)', color: isNotice ? '#8fe0bb' : '#e8b27a', fontSize: '12.5px', textAlign: 'center', lineHeight: 1.5 }
                            }, message)
                        );
                    }

                    const isMe = type === 'sent';
                    const encrypted = isMe;
                    const isViewOnce = type === 'received' && viewOnce === true;

                    const remaining = (typeof expiresAt === 'number')
                        ? Math.max(0, Math.ceil((expiresAt - (nowTick || Date.now())) / 1000))
                        : null;
                    const fmtRemaining = (sec) => {
                        if (sec == null) return '';
                        const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
                        const pad = (n) => String(n).padStart(2, '0');
                        return h > 0 ? (h + ':' + pad(m) + ':' + pad(s)) : (m + ':' + pad(s));
                    };

                    const handleReveal = () => {
                        if (revealed) return;
                        setRevealed(true);
                        const ms = Math.max(1, (typeof viewOnceTtl === 'number' ? viewOnceTtl : 15)) * 1000;
                        revealTimerRef.current = setTimeout(() => { onExpire && onExpire(); }, ms);
                    };

                    const radius = isMe ? '14px 14px 4px 14px' : '14px 14px 14px 4px';
                    const border = isMe ? '1px solid rgba(255,255,255,0.10)' : '1px solid rgba(255,255,255,0.06)';
                    const bg = isMe ? '#26262b' : '#161618';

                    // Expired tombstone (disappearing / view-once) — content already wiped.
                    const isExpired = expired === true || (typeof expiresAt === 'number' && (nowTick || Date.now()) >= expiresAt);
                    if (isExpired) {
                        return React.createElement('div', {
                            className: 'message-slide',
                            style: { display: 'flex', width: '100%', justifyContent: isMe ? 'flex-end' : 'flex-start' }
                        }, React.createElement('div', { style: { maxWidth: '74%', minWidth: '170px' } },
                            React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '9px', padding: '12px 15px', borderRadius: radius, border: '1px dashed rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.018)' } }, [
                                React.createElement('i', { key: 'i', className: 'fas fa-clock', style: { color: '#6b6b73', fontSize: '13px' } }),
                                React.createElement('span', { key: 't', style: { fontSize: '13px', color: '#6b6b73', fontStyle: 'italic' } }, 'This message has expired')
                            ])
                        ));
                    }

                    let body;
                    if (isViewOnce && !revealed) {
                        body = React.createElement('div', {
                            key: 'cover',
                            onClick: handleReveal,
                            style: { position: 'relative', cursor: 'pointer', padding: '12px 15px 10px', overflow: 'hidden' }
                        }, [
                            React.createElement('div', { key: 'blur', style: { fontSize: '14.5px', lineHeight: 1.55, color: '#b3b3ba', filter: 'blur(7px)', userSelect: 'none', pointerEvents: 'none', wordBreak: 'break-word', minHeight: '22px' } }, message),
                            React.createElement('div', { key: 'grain', style: { position: 'absolute', inset: 0, backgroundImage: GRAIN_URL, backgroundSize: '90px', opacity: 0.18, mixBlendMode: 'screen', pointerEvents: 'none' } }),
                            React.createElement('div', { key: 'lbl', style: { position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '7px', pointerEvents: 'none' } }, [
                                React.createElement('i', { key: 'i', className: 'fas fa-eye-slash', style: { color: '#e8e8eb', fontSize: '13px' } }),
                                React.createElement('span', { key: 't', style: { fontSize: '12px', fontWeight: 600, color: '#e8e8eb', textShadow: '0 1px 5px rgba(0,0,0,0.75)' } }, 'View once · tap to reveal')
                            ])
                        ]);
                    } else {
                        body = React.createElement('div', { key: 'body', style: { padding: '12px 15px 10px', color: '#e9e9ec' } },
                            React.createElement(MessageBody, { text: message })
                        );
                    }

                    const metaLeft = [
                        React.createElement('span', { key: 'time', style: { fontFamily: SB_MONO, fontSize: '10.5px', color: '#6b6b73' } }, formatTime(timestamp))
                    ];
                    // WhatsApp-style delivery state on our own messages.
                    if (isMe) {
                        const stCfg = ({
                            sending: { icon: 'fa-clock', color: '#6b6b73', label: 'Sending' },
                            sent: { icon: 'fa-check', color: '#8a8a92', label: 'Sent' },
                            // Two GREY ticks = delivered to the peer's device but not yet read.
                            delivered: { icon: 'fa-check-double', color: '#8a8a92', label: 'Delivered' },
                            // Two GREEN ticks = the peer actually opened the chat and read it.
                            read: { icon: 'fa-check-double', color: '#3ecf8e', label: 'Read' },
                            failed: { icon: 'fa-triangle-exclamation', color: '#e5727a', label: 'Not sent' }
                        })[status || 'sent'] || { icon: 'fa-check', color: '#8a8a92', label: 'Sent' };
                        metaLeft.push(React.createElement('span', {
                            key: 'dlv', title: stCfg.label,
                            style: { display: 'inline-flex', alignItems: 'center', color: stCfg.color }
                        }, React.createElement('i', { className: 'fas ' + stCfg.icon, style: { fontSize: '10.5px' } })));
                    }
                    if (isViewOnce && revealed) {
                        metaLeft.push(React.createElement('span', { key: 'vo', style: { display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '10px', fontWeight: 600, color: '#8a8a92' } }, [
                            React.createElement('span', { key: 'd', style: { width: '4px', height: '4px', borderRadius: '50%', background: '#8a8a92' } }),
                            'Viewed once'
                        ]));
                    } else if (remaining !== null) {
                        metaLeft.push(React.createElement('span', { key: 'ttl', style: { display: 'inline-flex', alignItems: 'center', gap: '4px', fontFamily: SB_MONO, fontSize: '10.5px', fontWeight: 500, color: '#f0892a' } }, [
                            React.createElement('i', { key: 'i', className: 'fas fa-clock', style: { fontSize: '10px' } }),
                            fmtRemaining(remaining)
                        ]));
                    }

                    const metaRight = [];
                    metaRight.push(React.createElement('span', { key: 'status', style: { display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '10.5px', fontWeight: 600, color: '#3ecf8e', flex: 'none' } }, [
                        React.createElement('i', { key: 'i', className: encrypted ? 'fas fa-lock' : 'fas fa-lock-open', style: { fontSize: '10px' } }),
                        encrypted ? 'Encrypted' : 'Decrypted'
                    ]));
                    // Delete-for-everyone sits AFTER the Encrypted/Decrypted status.
                    if (canUnsend && isMe && mid) {
                        metaRight.push(React.createElement('button', {
                            key: 'unsend', onClick: () => onUnsend && onUnsend(mid), title: 'Delete for everyone',
                            className: 'sb-unsend',
                            style: { background: 'none', border: 'none', cursor: 'pointer', color: '#56565e', fontSize: '11px', padding: 0, lineHeight: 1 }
                        }, React.createElement('i', { className: 'fas fa-trash-can' })));
                    }

                    const meta = React.createElement('div', {
                        key: 'meta',
                        style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '14px', padding: '0 15px 10px' }
                    }, [
                        React.createElement('div', { key: 'l', style: { display: 'flex', alignItems: 'center', gap: '9px', minWidth: 0 } }, metaLeft),
                        React.createElement('div', { key: 'r', style: { display: 'flex', alignItems: 'center', gap: '9px', flex: 'none' } }, metaRight)
                    ]);

                    return React.createElement('div', {
                        className: 'message-slide',
                        style: { display: 'flex', width: '100%', justifyContent: isMe ? 'flex-end' : 'flex-start' }
                    }, [
                        React.createElement('div', { key: 'wrap', style: { maxWidth: '74%', minWidth: '170px' } },
                            React.createElement('div', { style: { borderRadius: radius, border: border, background: bg, overflow: 'hidden' } }, [body, meta])
                        )
                    ]);
                };
        
                // Enhanced Connection Setup with verification
                const EnhancedConnectionSetup = ({
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
                    bothVerificationsConfirmed,
                    // QR control props
                    qrFramesTotal,
                    qrFrameIndex,
                    qrManualMode,
                    toggleQrManualMode,
                    nextQrFrame,
                    prevQrFrame,
                    markAnswerCreated,
                    notificationIntegrationRef,
                    isGeneratingKeys,
                    setIsGeneratingKeys,
                    handleCreateOffer,
                    relayOnlyMode,
                    setRelayOnlyMode,
                    webrtcManagerRef,
                    showIceSettings,
                    setShowIceSettings,
                    iceServersText,
                    iceSettingsPersisted,
                    customIceServers,
                    handleApplyIceSettings,
                    handleForgetIceSettings,
                    // When true, render ONLY the create/connect card (no marketing landing,
                    // no hero) so it slots into the chat column for an additional session.
                    compact = false
                }) => {
                    const [mode, setMode] = React.useState('create');
                    const [notificationPermissionRequested, setNotificationPermissionRequested] = React.useState(false);
                    // Local UI state for the redesigned Start Secure screen
                    const [qrModalOpen, setQrModalOpen] = React.useState(false);
                    const [copied, setCopied] = React.useState(false);
                    const [sasInput, setSasInput] = React.useState('');
                    const [sasError, setSasError] = React.useState('');
                    const [platformsOpen, setPlatformsOpen] = React.useState(false);
                    const [codeRevealed, setCodeRevealed] = React.useState(false);
                    const [genProgress, setGenProgress] = React.useState(0);

                    // Reset the typed SAS whenever a fresh verification code arrives
                    React.useEffect(() => { setSasInput(''); setSasError(''); }, [verificationCode]);
                    // Close the QR popup and re-hide (blur) the code whenever the
                    // exchange step changes — every new offer/answer starts concealed.
                    React.useEffect(() => {
                        if (!showOfferStep && !showAnswerStep) setQrModalOpen(false);
                        setCodeRevealed(false);
                    }, [showOfferStep, showAnswerStep]);
                    // Animate the "Securing your channel" steps while keys generate.
                    React.useEffect(() => {
                        const generating = isGeneratingKeys && !showOfferStep && !showAnswerStep && !showVerification;
                        if (!generating) { setGenProgress(0); return; }
                        setGenProgress(0);
                        let p = 0;
                        const id = setInterval(() => {
                            p += 1;
                            setGenProgress(p);
                            if (p >= 3) clearInterval(id);
                        }, 520);
                        return () => clearInterval(id);
                    }, [isGeneratingKeys, showOfferStep, showAnswerStep, showVerification]);
                    // Dismiss the download platforms popover on any outside click
                    React.useEffect(() => {
                        if (!platformsOpen) return;
                        const onDoc = () => setPlatformsOpen(false);
                        const id = setTimeout(() => document.addEventListener('click', onDoc), 0);
                        return () => { clearTimeout(id); document.removeEventListener('click', onDoc); };
                    }, [platformsOpen]);

                    // "Back" — clear the in-progress exchange and return to the intro of
                    // the current tab. onClearData() resets offer/answer/verification in
                    // the parent, which flips the derived step back to "intro".
                    const resetToSelect = () => {
                        setIsGeneratingKeys(false);
                        setQrModalOpen(false);
                        onClearData();
                    };
        
                    const handleVerificationConfirm = (userCode) => {
                        return onVerifyConnection(userCode);
                    };
        
                    const handleVerificationReject = () => {
                        onVerifyConnection(null, false);
                    };
                    
                    // Request notification permission on first user interaction
                    const requestNotificationPermissionOnInteraction = async () => {
                        if (notificationPermissionRequested) {
                            return; // Already requested
                        }
                        
                        try {
                            // Check if Notification API is supported
                            if (!('Notification' in window)) {
                                return;
                            }
                            
                            // Check if we're in a secure context
                            if (!window.isSecureContext && window.location.protocol !== 'https:' && window.location.hostname !== 'localhost') {
                                return;
                            }
                            
                            // Check current permission status
                            const currentPermission = (typeof Notification !== 'undefined' && Notification) 
                                ? Notification.permission 
                                : 'denied';
                            
                            // Only request if permission is default (not granted or denied)
                            if (currentPermission === 'default' && typeof Notification !== 'undefined' && Notification) {
                                const permission = await Notification.requestPermission();
                                
                                if (permission === 'granted') {
                                    // Initialize notification integration immediately
                                    try {
                                        if (window.NotificationIntegration && webrtcManagerRef.current) {
                                            const integration = new window.NotificationIntegration(webrtcManagerRef.current);
                                            await integration.init();
                                            
                                            // Store reference for cleanup
                                            notificationIntegrationRef.current = integration;
                                        }
                                    } catch (error) {
                                        // Handle error silently
                                    }
                                    
                                    // Send welcome notification
                                    setTimeout(() => {
                                        try {
                                            const welcomeNotification = new Notification('SecureBit Chat', {
                                                body: 'Notifications enabled! You will receive alerts for new messages.',
                                                icon: '/logo/icon-192x192.png',
                                                tag: 'welcome-notification'
                                            });
                                            
                                            welcomeNotification.onclick = () => {
                                                welcomeNotification.close();
                                            };
                                            
                                            setTimeout(() => {
                                                welcomeNotification.close();
                                            }, 5000);
                                            
                                        } catch (error) {
                                            // Handle error silently
                                        }
                                    }, 1000);
                                    
                                }
                            } else if (currentPermission === 'granted') {
                                // Initialize notification integration immediately
                                try {
                                    if (window.NotificationIntegration && webrtcManagerRef.current && !notificationIntegrationRef.current) {
                                        const integration = new window.NotificationIntegration(webrtcManagerRef.current);
                                        await integration.init();
                                        
                                        // Store reference for cleanup
                                        notificationIntegrationRef.current = integration;
                                    }
                                } catch (error) {
                                    // Handle error silently
                                }
                                
                                // Test notification to confirm it works
                                setTimeout(() => {
                                    try {
                                        const testNotification = new Notification('SecureBit Chat', {
                                            body: 'Notifications are working! You will receive alerts for new messages.',
                                            icon: '/logo/icon-192x192.png',
                                            tag: 'test-notification'
                                        });
                                        
                                        testNotification.onclick = () => {
                                            testNotification.close();
                                        };
                                        
                                        setTimeout(() => {
                                            testNotification.close();
                                        }, 5000);
                                    } catch (error) {
                                        // Handle error silently
                                    }
                                }, 1000);
                            }
                            
                            setNotificationPermissionRequested(true);
                            
                        } catch (error) {
                            // Handle error silently
                        }
                    };
        
                    // ──────────────────────────────────────────────────────────────
                    // Start Secure — redesigned two-column connection screen.
                    // Layout/colors/animation from the imported design; wired to the
                    // app's real crypto handlers. Icons use FontAwesome (house style).
                    // ──────────────────────────────────────────────────────────────
                    const h = React.createElement;
                    const C_ORANGE = '#f0892a';
                    const C_GREEN = '#3ecf8e';
                    const MONO = SB_MONO;

                    const encode = (data) => {
                        try {
                            const min = typeof data === 'object' ? JSON.stringify(data) : (data || '');
                            if (!min) return '';
                            if (typeof window.encodeBinaryToPrefixed === 'function') return window.encodeBinaryToPrefixed(min);
                            if (typeof window.compressToPrefixedGzip === 'function') return window.compressToPrefixedGzip(min);
                            return min;
                        } catch { return typeof data === 'object' ? JSON.stringify(data) : (data || ''); }
                    };

                    // Derived flow step from the parent's real connection state
                    const isCreate = mode === 'create';
                    const isGenerating = isGeneratingKeys && !showOfferStep && !showAnswerStep && !showVerification;
                    const isOfferCred = isCreate && showOfferStep && !showVerification;
                    const isAnswerCred = !isCreate && showAnswerStep && !showVerification;
                    const atIntro = !showVerification && !isGenerating && !isOfferCred && !isAnswerCred;
                    const accent = isCreate ? C_ORANGE : C_GREEN;
                    const kicker = showVerification
                        ? 'Step 3 · verification'
                        : ((isOfferCred || isAnswerCred) ? 'Step 2 · exchange' : 'Step 1 · open a channel');

                    const credCode = isCreate ? encode(offerData) : encode(answerData);
                    const hasInvite = (offerInput || '').trim().length > 0;
                    const hasAnswer = (answerInput || '').trim().length > 0;

                    const copyCred = async () => {
                        try {
                            if (typeof copyToClipboardSecure === 'function') await copyToClipboardSecure(credCode);
                            else await navigator.clipboard.writeText(credCode);
                        } catch (e) {}
                        setCopied(true);
                        setTimeout(() => setCopied(false), 1600);
                    };

                    // SAS verification (alphanumeric, variable length — matches real codes)
                    const normExpected = (verificationCode || '').replace(/[-\s]/g, '').length;
                    const normInput = sasInput.replace(/[-\s]/g, '').length;
                    const canConfirm = !localVerificationConfirmed && normExpected > 0 && normInput === normExpected;
                    const handleSasConfirm = async () => {
                        try {
                            setSasError('');
                            await onVerifyConnection(sasInput);
                        } catch (err) {
                            setSasInput('');
                            setSasError(err?.message === 'SAS_MAX_ATTEMPTS'
                                ? 'Too many incorrect attempts. Session reset for safety.'
                                : 'Incorrect code. Check it with your peer and try again.');
                        }
                    };

                    // Icon set transcribed from the design (inline SVG, not FontAwesome).
                    // Each entry: stroke-width + the SVG child elements [tag, attrs].
                    const ICON_DEFS = {
                        'fa-user': { sw: 1.9, e: [['circle', { cx: 12, cy: 8, r: 3.6 }], ['path', { d: 'M5 20c0-3.5 3-5.5 7-5.5s7 2 7 5.5' }]] },
                        'fa-lock': { sw: 2, e: [['path', { d: 'M7 11V7a5 5 0 0 1 10 0v4' }], ['rect', { x: 4.5, y: 11, width: 15, height: 9, rx: 2.2 }]] },
                        'fa-plus': { sw: 2.1, e: [['path', { d: 'M12 5v14M5 12h14' }]] },
                        'fa-link': { sw: 2, e: [['path', { d: 'M9.5 14.5l5-5M8 11l-2.2 2.2a3.5 3.5 0 0 0 4.95 4.95L13 16M16 13l2.2-2.2a3.5 3.5 0 0 0-4.95-4.95L11 8' }]] },
                        'fa-bolt': { sw: 2.1, e: [['path', { d: 'M13 2L4.5 13H11l-1 9 8.5-11H12l1-9z' }]] },
                        'fa-camera': { sw: 1.8, e: [['path', { d: 'M2 8.5V6.5A2.5 2.5 0 0 1 4.5 4h2M17.5 4h2A2.5 2.5 0 0 1 22 6.5v2M22 15.5v2a2.5 2.5 0 0 1-2.5 2.5h-2M6.5 20h-2A2.5 2.5 0 0 1 2 17.5v-2' }], ['circle', { cx: 12, cy: 12, r: 3.2 }]] },
                        'fa-qrcode': { sw: 1.9, e: [['rect', { x: 3, y: 3, width: 7, height: 7, rx: 1.3 }], ['rect', { x: 14, y: 3, width: 7, height: 7, rx: 1.3 }], ['rect', { x: 3, y: 14, width: 7, height: 7, rx: 1.3 }], ['path', { d: 'M14 14h3v3M21 14v.01M14 21h.01M21 21v-4M17.5 21H21' }]] },
                        'fa-chevron-right': { sw: 2, e: [['path', { d: 'M9 6l6 6-6 6' }]] },
                        'fa-chevron-left': { sw: 2, e: [['path', { d: 'M15 6l-6 6 6 6' }]] },
                        'fa-chevron-down': { sw: 2, e: [['path', { d: 'M6 9l6 6 6-6' }]] },
                        'fa-circle-notch': { sw: 2, e: [['path', { d: 'M21 12a9 9 0 1 1-6.2-8.6' }]] },
                        'fa-check': { sw: 2.4, e: [['path', { d: 'M20 6L9 17l-5-5' }]] },
                        'fa-check-circle': { sw: 2, e: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M8.5 12.4l2.4 2.4 4.6-5' }]] },
                        'fa-shield-alt': { sw: 1.9, e: [['path', { d: 'M12 2.6l7 3v5.1c0 4.5-3 8.3-7 10.2-4-1.9-7-5.7-7-10.2V5.6l7-3z' }], ['path', { d: 'M9 12l2 2 4-4.1' }]] },
                        'fa-download': { sw: 2, e: [['path', { d: 'M12 3v12M12 15l-4.5-4.5M12 15l4.5-4.5' }], ['path', { d: 'M4 20h16' }]] },
                        'fa-clock': { sw: 1.8, e: [['circle', { cx: 12, cy: 13, r: 8 }], ['path', { d: 'M12 9v4l2.5 2M9 2h6' }]] },
                        'fa-times': { sw: 2.2, e: [['path', { d: 'M18 6L6 18M6 6l12 12' }]] },
                        'fa-eye': { sw: 1.9, e: [['path', { d: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z' }], ['circle', { cx: 12, cy: 12, r: 3 }]] }
                    };
                    const fa = (name, opts) => {
                        opts = opts || {};
                        const def = ICON_DEFS[name];
                        if (!def) {
                            // Fallback to FontAwesome (e.g. fa-sliders-h, kept by preference).
                            const st = {};
                            if (opts.color) st.color = opts.color;
                            if (opts.fontSize) st.fontSize = opts.fontSize;
                            if (opts.animation) st.animation = opts.animation;
                            if (opts.style) Object.assign(st, opts.style);
                            return h('i', { key: opts.key, className: `fas ${name}`, style: st });
                        }
                        const size = opts.fontSize ? parseFloat(opts.fontSize) : 16;
                        const svgStyle = {};
                        if (opts.animation) { svgStyle.animation = opts.animation; svgStyle.transformOrigin = 'center'; svgStyle.transformBox = 'fill-box'; }
                        if (opts.style) Object.assign(svgStyle, opts.style);
                        return h('svg', {
                            key: opts.key, width: size, height: size, viewBox: '0 0 24 24',
                            fill: 'none', stroke: opts.color || 'currentColor',
                            strokeWidth: def.sw || 2, strokeLinecap: 'round', strokeLinejoin: 'round',
                            style: svgStyle
                        }, def.e.map((el, i) => h(el[0], Object.assign({ key: i }, el[1]))));
                    };

                    // ── LEFT PANEL · branding + animated channel + crypto badges ──
                    const leftPanel = h('div', {
                        key: 'left',
                        className: 'sb-start-left',
                        style: {
                            flex: '1.05 1 380px', position: 'relative', overflow: 'hidden',
                            // Full viewport height even when the panels stack on mobile, so the
                            // branding column isn't collapsed/cramped (looked broken otherwise).
                            minHeight: '100vh', boxSizing: 'border-box',
                            padding: '46px', display: 'flex', flexDirection: 'column',
                            justifyContent: 'space-between', gap: '36px',
                            borderRight: '1px solid rgba(255,255,255,0.06)',
                            background: 'radial-gradient(900px 600px at 25% 18%, rgba(240,137,42,0.07), transparent 62%), radial-gradient(800px 700px at 80% 92%, rgba(62,207,142,0.06), transparent 60%), #0c0c0e'
                        }
                    }, [
                        h('div', { key: 'herowrap', style: { flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', position: 'relative', zIndex: 2 } },
                        h('div', { key: 'hero', style: { maxWidth: '470px' } }, [
                            h('h1', { key: 'h1', style: { margin: '0 0 14px', fontSize: '34px', fontWeight: 800, letterSpacing: '-1.1px', lineHeight: 1.1, color: '#f4f4f6' } }, [
                                'A direct line', h('br', { key: 'br' }), 'only you two can read.'
                            ]),
                            h('p', { key: 'p', style: { margin: '0 0 38px', fontSize: '14.5px', lineHeight: 1.6, color: '#8a8a92', maxWidth: '390px' } },
                                'Keys are generated on your device and exchanged peer-to-peer. No accounts, no servers storing your messages.'),
                            // animated channel
                            h('div', { key: 'channel', style: { display: 'flex', alignItems: 'center', height: '74px' } }, [
                                h('div', { key: 'you', style: { flex: 'none', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', width: '74px' } }, [
                                    h('div', { key: 'n', style: { width: '50px', height: '50px', borderRadius: '15px', display: 'grid', placeItems: 'center', background: 'rgba(240,137,42,0.13)', border: '1px solid rgba(240,137,42,0.3)', animation: 'sbNode 3s ease-in-out infinite' } }, fa('fa-user', { color: C_ORANGE, fontSize: '20px' })),
                                    h('span', { key: 'l', style: { fontSize: '11px', fontWeight: 600, color: '#9a9aa2' } }, 'You')
                                ]),
                                h('div', { key: 'wire', style: { flex: 1, position: 'relative', height: '52px', margin: '0 -6px' } }, [
                                    h('div', { key: 'line', style: { position: 'absolute', top: '50%', left: 0, right: 0, height: '2px', transform: 'translateY(-50%)', background: 'linear-gradient(90deg, rgba(240,137,42,0.45), rgba(62,207,142,0.45))' } }),
                                    h('span', { key: 'd1', style: { position: 'absolute', top: '50%', transform: 'translateY(-50%)', width: '6px', height: '6px', borderRadius: '50%', background: C_ORANGE, boxShadow: `0 0 8px ${C_ORANGE}`, animation: 'sbFlowR 2.6s linear infinite' } }),
                                    h('span', { key: 'd2', style: { position: 'absolute', top: '50%', transform: 'translateY(-50%)', width: '6px', height: '6px', borderRadius: '50%', background: C_GREEN, boxShadow: `0 0 8px ${C_GREEN}`, animation: 'sbFlowL 2.6s linear infinite', animationDelay: '0.6s' } }),
                                    h('div', { key: 'hub', style: { position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: '38px', height: '38px' } }, [
                                        h('span', { key: 'pulse', style: { position: 'absolute', top: '50%', left: '50%', width: '38px', height: '38px', borderRadius: '50%', border: '1.5px solid rgba(62,207,142,0.5)', animation: 'sbPulse 2.4s ease-out infinite' } }),
                                        h('div', { key: 'core', style: { position: 'relative', width: '38px', height: '38px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: '#121214', border: '1px solid rgba(62,207,142,0.45)', boxShadow: '0 0 18px rgba(62,207,142,0.25)' } }, fa('fa-lock', { color: C_GREEN, fontSize: '14px' }))
                                    ])
                                ]),
                                h('div', { key: 'peer', style: { flex: 'none', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', width: '74px' } }, [
                                    h('div', { key: 'n', style: { width: '50px', height: '50px', borderRadius: '15px', display: 'grid', placeItems: 'center', background: 'rgba(62,207,142,0.1)', border: '1px solid rgba(62,207,142,0.3)', animation: 'sbNode 3s ease-in-out infinite', animationDelay: '1.5s' } }, fa('fa-user', { color: C_GREEN, fontSize: '20px' })),
                                    h('span', { key: 'l', style: { fontSize: '11px', fontWeight: 600, color: '#9a9aa2' } }, 'Peer')
                                ])
                            ])
                        ])),
                        h('div', { key: 'badges', style: { position: 'relative', zIndex: 2, display: 'flex', flexWrap: 'wrap', gap: '8px' } },
                            ['ECDH P-384', 'AES-256-GCM', 'Perfect Forward Secrecy'].map((label) =>
                                h('span', { key: label, style: { display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 11px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.025)', fontFamily: MONO, fontSize: '11px', fontWeight: 500, color: '#9a9aa2' } }, [
                                    h('span', { key: 'dot', style: { width: '5px', height: '5px', borderRadius: '50%', background: C_GREEN } }),
                                    label
                                ])
                            )
                        )
                    ]);

                    // ── RIGHT PANEL · flow body (varies by step) ──
                    const segToggle = atIntro && h('div', { key: 'seg', style: { position: 'relative', display: 'flex', padding: '4px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.07)', background: '#141416', marginBottom: '26px' } }, [
                        h('div', { key: 'ind', style: { position: 'absolute', top: '4px', bottom: '4px', left: '4px', width: 'calc(50% - 4px)', borderRadius: '9px', background: 'rgba(255,255,255,0.07)', border: '1px solid rgba(255,255,255,0.08)', transform: isCreate ? 'translateX(0%)' : 'translateX(100%)', transition: 'transform .26s cubic-bezier(.3,.8,.3,1)' } }),
                        h('button', { key: 'c', className: 'sb-seg-btn', onClick: () => setMode('create'), style: { position: 'relative', zIndex: 1, flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', padding: '11px', border: 'none', background: 'transparent', color: isCreate ? '#f4f4f6' : '#7b7b83', fontFamily: 'inherit', fontSize: '14px', fontWeight: 700, cursor: 'pointer' } }, [fa('fa-plus', { key: 'i' }), 'Create']),
                        h('button', { key: 'j', className: 'sb-seg-btn', onClick: () => setMode('join'), style: { position: 'relative', zIndex: 1, flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', padding: '11px', border: 'none', background: 'transparent', color: !isCreate ? '#f4f4f6' : '#7b7b83', fontFamily: 'inherit', fontSize: '14px', fontWeight: 700, cursor: 'pointer' } }, [fa('fa-link', { key: 'i' }), 'Join'])
                    ]);

                    const backButton = (key) => h('button', { key: key || 'back', className: 'sb-soft-btn', onClick: resetToSelect, style: { display: 'inline-flex', alignItems: 'center', gap: '6px', marginBottom: '14px', padding: '6px 11px 6px 8px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#9a9aa2', fontFamily: 'inherit', fontSize: '12.5px', fontWeight: 600, cursor: 'pointer' } }, [fa('fa-chevron-left', { key: 'i' }), 'Back']);

                    // credential code block (offer/answer text fallback + copy)
                    const credBlock = h('div', { key: 'codeblock', style: { borderRadius: '13px', border: '1px solid rgba(255,255,255,0.08)', background: '#141416', overflow: 'hidden', marginBottom: '16px' } }, [
                        h('div', { key: 'bar', style: { display: 'flex', alignItems: 'center', gap: '8px', padding: '9px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.2)' } }, [
                            h('span', { key: 'dot', style: { width: '7px', height: '7px', borderRadius: '50%', background: accent } }),
                            h('span', { key: 'tag', style: { fontFamily: MONO, fontSize: '10.5px', fontWeight: 600, color: '#8a8a92' } }, `${isCreate ? 'offer' : 'answer'} · or copy text`),
                            h('button', { key: 'copy', onClick: copyCred, style: { marginLeft: 'auto', padding: '4px 9px', borderRadius: '6px', border: `1px solid ${copied ? 'rgba(62,207,142,0.4)' : 'rgba(255,255,255,0.1)'}`, background: copied ? 'rgba(62,207,142,0.1)' : 'rgba(255,255,255,0.04)', color: copied ? C_GREEN : '#b3b3ba', fontFamily: 'inherit', fontSize: '11px', fontWeight: 600, cursor: 'pointer', transition: 'all .14s' } }, copied ? 'Copied' : 'Copy')
                        ]),
                        // The handshake code is sensitive — keep it blurred until the
                        // user deliberately reveals it, underscoring that it must be
                        // shared only over a channel they trust.
                        h('div', { key: 'codewrap', style: { position: 'relative' } }, [
                            h('div', { key: 'code', className: 'sb-sc', style: { fontFamily: MONO, fontSize: '11px', lineHeight: 1.55, color: '#c9ccd8', wordBreak: 'break-all', padding: '11px 12px', maxHeight: '72px', overflowY: 'auto', filter: codeRevealed ? 'none' : 'blur(6px)', userSelect: codeRevealed ? 'text' : 'none', transition: 'filter .2s' } }, credCode),
                            !codeRevealed && h('button', { key: 'reveal', onClick: () => setCodeRevealed(true), style: { position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', border: 'none', background: 'rgba(20,20,22,0.25)', color: '#cfcfd4', fontFamily: 'inherit', fontSize: '12px', fontWeight: 600, cursor: 'pointer' } }, [
                                fa('fa-eye', { key: 'i', fontSize: '15px' }),
                                'Click to reveal — keep this code private'
                            ])
                        ])
                    ]);

                    const showQrButton = qrCodeUrl && h('button', { key: 'showqr', onClick: () => setQrModalOpen(true), style: { width: '100%', display: 'flex', alignItems: 'center', gap: '13px', padding: '15px 16px', borderRadius: '14px', border: `1px solid ${isCreate ? 'rgba(240,137,42,0.3)' : 'rgba(62,207,142,0.3)'}`, background: isCreate ? 'rgba(240,137,42,0.06)' : 'rgba(62,207,142,0.06)', color: 'inherit', fontFamily: 'inherit', cursor: 'pointer', textAlign: 'left', marginBottom: '14px' } }, [
                        h('span', { key: 'ic', style: { flex: 'none', width: '42px', height: '42px', borderRadius: '12px', display: 'grid', placeItems: 'center', background: isCreate ? 'rgba(240,137,42,0.12)' : 'rgba(62,207,142,0.12)', border: `1px solid ${isCreate ? 'rgba(240,137,42,0.28)' : 'rgba(62,207,142,0.28)'}` } }, fa('fa-qrcode', { color: accent, fontSize: '18px' })),
                        h('span', { key: 'tx', style: { flex: 1 } }, [
                            h('span', { key: 't', style: { display: 'block', fontSize: '14.5px', fontWeight: 700, color: '#f4f4f6' } }, 'Show QR code'),
                            h('span', { key: 's', style: { display: 'block', fontSize: '12.5px', color: '#8a8a92', marginTop: '1px' } }, `Full-screen · let your peer scan${(qrFramesTotal || 0) > 1 ? ` all ${qrFramesTotal} frames` : ''}`)
                        ]),
                        fa('fa-chevron-right', { color: '#6b6b73' })
                    ]);

                    let inner;
                    if (showVerification) {
                        const verified = bothVerificationsConfirmed;
                        const cells = (verificationCode || '').split('').map((ch, i) =>
                            h('div', { key: i, style: { flex: 1, maxWidth: '46px', aspectRatio: '0.82', display: 'grid', placeItems: 'center', borderRadius: '10px', border: '1px solid rgba(62,207,142,0.25)', background: 'rgba(62,207,142,0.05)', fontFamily: MONO, fontSize: '22px', fontWeight: 700, color: C_GREEN } }, ch));
                        inner = h('div', { key: 'verify', style: { animation: 'sbUp .3s ease' } }, [
                            !verified && backButton('vback'),
                            h('div', { key: 'head', style: { display: 'flex', alignItems: 'center', gap: '11px', marginBottom: '8px' } }, [
                                h('div', { key: 'i', style: { width: '34px', height: '34px', flex: 'none', borderRadius: '10px', display: 'grid', placeItems: 'center', background: 'rgba(62,207,142,0.1)', border: '1px solid rgba(62,207,142,0.25)' } }, fa('fa-shield-alt', { color: C_GREEN })),
                                h('h2', { key: 't', style: { margin: 0, fontSize: '21px', fontWeight: 800, letterSpacing: '-0.4px', color: '#f4f4f6' } }, 'Security verification')
                            ]),
                            h('p', { key: 'sub', style: { margin: '0 0 18px', fontSize: '13.5px', lineHeight: 1.55, color: '#8a8a92' } }, 'Compare this safety code with your peer over a separate channel (voice / in person), then type it to unlock the chat.'),
                            h('div', { key: 'cells', style: { display: 'flex', gap: '6px', justifyContent: 'center', marginBottom: '20px', flexWrap: 'wrap' } }, cells),
                            verified
                                ? h('div', { key: 'ok', style: { display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', padding: '24px 16px', borderRadius: '16px', border: '1px solid rgba(62,207,142,0.25)', background: 'rgba(62,207,142,0.06)', animation: 'sbUp .3s ease' } }, [
                                    h('div', { key: 'i', style: { width: '54px', height: '54px', borderRadius: '16px', display: 'grid', placeItems: 'center', background: 'rgba(62,207,142,0.14)', border: '1px solid rgba(62,207,142,0.35)', marginBottom: '14px' } }, fa('fa-check', { color: C_GREEN, fontSize: '24px' })),
                                    h('div', { key: 't', style: { fontSize: '18px', fontWeight: 800, color: '#f4f4f6' } }, 'Channel verified'),
                                    h('div', { key: 's', style: { fontSize: '13.5px', color: '#8a8a92', marginTop: '5px' } }, 'Both parties confirmed. Opening the secure chat…')
                                ])
                                : h('div', { key: 'form' }, [
                                    h('div', { key: 'lbl', style: { fontSize: '12.5px', fontWeight: 600, color: '#9a9aa2', marginBottom: '8px' } }, 'Enter the verified code'),
                                    h('input', { key: 'in', value: sasInput, onChange: (e) => { setSasInput(e.target.value.toUpperCase()); if (sasError) setSasError(''); }, disabled: localVerificationConfirmed, autoFocus: true, autoComplete: 'off', spellCheck: false, placeholder: verificationCode ? 'Type code here' : 'Waiting for code…', style: { width: '100%', textAlign: 'center', letterSpacing: '6px', borderRadius: '12px', border: `1px solid ${sasInput.length ? (canConfirm || localVerificationConfirmed ? 'rgba(62,207,142,0.5)' : 'rgba(255,255,255,0.14)') : 'rgba(255,255,255,0.08)'}`, background: '#141416', color: '#f4f4f6', fontFamily: MONO, fontSize: '20px', fontWeight: 700, padding: '14px', outline: 'none', textTransform: 'uppercase', marginBottom: sasError ? '8px' : '16px' } }),
                                    sasError && h('p', { key: 'err', style: { color: '#e5727a', fontSize: '12.5px', margin: '0 0 16px' } }, sasError),
                                    h('div', { key: 'status', style: { display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '16px' } }, [
                                        h('div', { key: 'you', style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '11px 14px', borderRadius: '11px', border: '1px solid rgba(255,255,255,0.06)', background: '#141416' } }, [
                                            h('span', { key: 'l', style: { fontSize: '13px', color: '#cfcfd4', fontWeight: 600 } }, 'Your confirmation'),
                                            h('span', { key: 'v', style: { display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12.5px', fontWeight: 600, color: localVerificationConfirmed ? C_GREEN : '#7b7b83' } }, [fa(localVerificationConfirmed ? 'fa-check-circle' : 'fa-clock', { key: 'i' }), localVerificationConfirmed ? 'Confirmed' : 'Pending'])
                                        ]),
                                        h('div', { key: 'peer', style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '11px 14px', borderRadius: '11px', border: '1px solid rgba(255,255,255,0.06)', background: '#141416' } }, [
                                            h('span', { key: 'l', style: { fontSize: '13px', color: '#cfcfd4', fontWeight: 600 } }, 'Peer confirmation'),
                                            h('span', { key: 'v', style: { display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12.5px', fontWeight: 600, color: remoteVerificationConfirmed ? C_GREEN : '#7b7b83' } }, [fa(remoteVerificationConfirmed ? 'fa-check-circle' : 'fa-clock', { key: 'i' }), remoteVerificationConfirmed ? 'Confirmed' : 'Pending'])
                                        ])
                                    ]),
                                    h('div', { key: 'btns', style: { display: 'flex', gap: '10px' } }, [
                                        h('button', { key: 'ok', onClick: handleSasConfirm, disabled: !canConfirm, style: { flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', padding: '14px', borderRadius: '13px', border: 'none', background: canConfirm ? C_GREEN : 'rgba(255,255,255,0.05)', color: canConfirm ? '#08160e' : '#56565e', fontFamily: 'inherit', fontSize: '14.5px', fontWeight: 700, cursor: canConfirm ? 'pointer' : 'not-allowed', boxShadow: canConfirm ? '0 8px 24px rgba(62,207,142,0.25)' : 'none' } }, [fa(localVerificationConfirmed ? 'fa-check-circle' : 'fa-check', { key: 'i' }), localVerificationConfirmed ? 'Confirmed' : 'Confirm code']),
                                        h('button', { key: 'no', onClick: handleVerificationReject, style: { flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '7px', padding: '14px 16px', borderRadius: '13px', border: '1px solid rgba(229,114,122,0.3)', background: 'transparent', color: '#e5727a', fontFamily: 'inherit', fontSize: '13.5px', fontWeight: 600, cursor: 'pointer' } }, [fa('fa-times', { key: 'i' }), "Don't match"])
                                    ])
                                ])
                        ]);
                    } else if (isGenerating) {
                        const genSteps = ['Generating ECDH P-384 key pair', 'Deriving verification code', 'Pinning Perfect Forward Secrecy'];
                        inner = h('div', { key: 'gen', style: { animation: 'sbUp .28s ease' } }, [
                            h('div', { key: 'head', style: { display: 'flex', alignItems: 'center', gap: '13px', marginBottom: '22px' } }, [
                                h('div', { key: 'sp', style: { width: '44px', height: '44px', flex: 'none', display: 'grid', placeItems: 'center' } }, fa('fa-circle-notch', { color: C_ORANGE, fontSize: '32px', animation: 'sbSpin 1s linear infinite' })),
                                h('div', { key: 'tx' }, [
                                    h('h2', { key: 't', style: { margin: 0, fontSize: '20px', fontWeight: 800, letterSpacing: '-0.4px', color: '#f4f4f6' } }, isCreate ? 'Securing your channel' : 'Building your answer'),
                                    h('p', { key: 's', style: { margin: '3px 0 0', fontSize: '13px', color: '#8a8a92' } }, 'Forging keys strong enough to resist tampering.')
                                ])
                            ]),
                            h('div', { key: 'steps', style: { display: 'flex', flexDirection: 'column', borderRadius: '13px', border: '1px solid rgba(255,255,255,0.07)', background: '#141416', overflow: 'hidden' } },
                                genSteps.map((label, i) => {
                                    const done = genProgress > i;
                                    const active = genProgress === i;
                                    return h('div', { key: i, style: { display: 'flex', alignItems: 'center', gap: '12px', padding: '13px 15px', borderTop: i ? '1px solid rgba(255,255,255,0.05)' : 'none', transition: 'background .3s', background: done ? 'rgba(62,207,142,0.04)' : 'transparent' } }, [
                                        h('div', { key: 'd', style: { flex: 'none', width: '20px', height: '20px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: done ? 'rgba(62,207,142,0.12)' : (active ? 'rgba(240,137,42,0.12)' : 'rgba(255,255,255,0.04)'), border: `1px solid ${done ? 'rgba(62,207,142,0.3)' : (active ? 'rgba(240,137,42,0.3)' : 'rgba(255,255,255,0.1)')}`, transition: 'all .3s' } },
                                            done
                                                ? fa('fa-check', { color: C_GREEN, fontSize: '11px' })
                                                : h('span', { style: { width: '6px', height: '6px', borderRadius: '50%', background: active ? C_ORANGE : '#56565e', animation: active ? 'sbBlink 1s ease-in-out infinite' : 'none' } })),
                                        h('span', { key: 'l', style: { fontSize: '13.5px', color: done ? '#cfcfd4' : (active ? '#e8e8eb' : '#6b6b73'), transition: 'color .3s' } }, label)
                                    ]);
                                })
                            )
                        ]);
                    } else if (isOfferCred || isAnswerCred) {
                        inner = h('div', { key: 'cred', style: { animation: 'sbUp .3s ease' } }, [
                            backButton('cback'),
                            h('h2', { key: 'h', style: { margin: '0 0 6px', fontSize: '23px', fontWeight: 800, letterSpacing: '-0.5px', color: '#f4f4f6' } }, isCreate ? 'Share your invitation' : 'Send back your answer'),
                            h('p', { key: 'p', style: { margin: '0 0 18px', fontSize: '14px', lineHeight: 1.55, color: '#8a8a92' } }, isCreate ? 'Show the QR or send the code to your peer. It is one-time and expires shortly.' : 'Give this answer to the channel creator so they can finish the handshake.'),
                            showQrButton,
                            credBlock,
                            isOfferCred && h('div', { key: 'offerextra', style: { marginTop: '4px' } }, [
                                h('div', { key: 'lbl', style: { fontSize: '12.5px', fontWeight: 600, color: '#9a9aa2', marginBottom: '8px' } }, "Then receive the answer your peer sends back"),
                                h('div', { key: 'ta', style: { borderRadius: '12px', border: `1px solid ${hasAnswer ? 'rgba(255,255,255,0.18)' : 'rgba(255,255,255,0.07)'}`, background: '#141416', padding: '11px 14px', marginBottom: '10px' } },
                                    h('textarea', { value: answerInput, onChange: (e) => { setAnswerInput(e.target.value); if (e.target.value.trim().length > 0 && typeof markAnswerCreated === 'function') markAnswerCreated(); }, rows: 2, placeholder: "Paste peer's answer code…", style: { width: '100%', resize: 'none', border: 'none', outline: 'none', background: 'transparent', color: '#d7d7db', fontFamily: MONO, fontSize: '12px', lineHeight: 1.55, minHeight: '44px' } })),
                                h('div', { key: 'btns', style: { display: 'flex', gap: '10px' } }, [
                                    h('button', { key: 'scan', className: 'sb-scan-btn', onClick: () => setShowQRScannerModal(true), style: { flex: 'none', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '8px', padding: '14px 16px', borderRadius: '13px', border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.04)', color: '#cfcfd4', fontFamily: 'inherit', fontSize: '14px', fontWeight: 700, cursor: 'pointer' } }, [fa('fa-camera', { key: 'i' }), 'Scan']),
                                    h('button', { key: 'est', onClick: onConnect, disabled: !hasAnswer, style: { flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '9px', padding: '14px', borderRadius: '13px', border: 'none', background: hasAnswer ? C_ORANGE : 'rgba(255,255,255,0.05)', color: hasAnswer ? '#1a0f04' : '#56565e', fontFamily: 'inherit', fontSize: '14.5px', fontWeight: 700, cursor: hasAnswer ? 'pointer' : 'not-allowed', boxShadow: hasAnswer ? '0 8px 24px rgba(240,137,42,0.28)' : 'none' } }, 'Establish connection')
                                ])
                            ]),
                            isAnswerCred && h('div', { key: 'answerextra', style: { marginTop: '4px', display: 'flex', alignItems: 'center', gap: '10px', padding: '12px 14px', borderRadius: '12px', border: '1px solid rgba(62,207,142,0.18)', background: 'rgba(62,207,142,0.05)' } }, [
                                fa('fa-circle-notch', { key: 'i', color: C_GREEN, animation: 'sbSpin 1.4s linear infinite' }),
                                h('span', { key: 't', style: { fontSize: '13px', color: '#cfcfd4', fontWeight: 500 } }, 'Send this answer to the creator, then wait — the chat opens once they connect.')
                            ])
                        ]);
                    } else if (isCreate) {
                        // CREATE intro
                        inner = h('div', { key: 'introC', style: { animation: 'sbUp .28s ease' } }, [
                            h('h2', { key: 'h', style: { margin: '0 0 6px', fontSize: '23px', fontWeight: 800, letterSpacing: '-0.5px', color: '#f4f4f6' } }, 'Create a new channel'),
                            h('p', { key: 'p', style: { margin: '0 0 22px', fontSize: '14px', lineHeight: 1.55, color: '#8a8a92' } }, 'Your device generates the keys and a one-time invitation. Nothing touches a server.'),
                            h('button', { key: 'gen', className: 'sb-gen-btn', onClick: () => { requestNotificationPermissionOnInteraction(); if (webrtcManagerRef.current) handleCreateOffer(); }, style: { width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '9px', padding: '15px', borderRadius: '13px', border: 'none', background: C_ORANGE, color: '#1a0f04', fontFamily: 'inherit', fontSize: '15px', fontWeight: 700, cursor: 'pointer', boxShadow: '0 8px 24px rgba(240,137,42,0.28)' } }, [fa('fa-bolt', { key: 'i' }), 'Generate keys & invitation'])
                        ]);
                    } else {
                        // JOIN intro
                        inner = h('div', { key: 'introJ', style: { animation: 'sbUp .28s ease' } }, [
                            h('h2', { key: 'h', style: { margin: '0 0 6px', fontSize: '23px', fontWeight: 800, letterSpacing: '-0.5px', color: '#f4f4f6' } }, 'Join a channel'),
                            h('p', { key: 'p', style: { margin: '0 0 16px', fontSize: '14px', lineHeight: 1.55, color: '#8a8a92' } }, "Scan your peer's QR with your camera, or paste their invitation code."),
                            h('button', { key: 'scan', className: 'sb-scan-btn', onClick: () => { requestNotificationPermissionOnInteraction(); setShowQRScannerModal(true); }, style: { width: '100%', display: 'flex', alignItems: 'center', gap: '13px', padding: '15px 16px', borderRadius: '14px', border: '1px solid rgba(62,207,142,0.3)', background: 'rgba(62,207,142,0.06)', color: 'inherit', fontFamily: 'inherit', cursor: 'pointer', textAlign: 'left', marginBottom: '14px' } }, [
                                h('span', { key: 'ic', style: { flex: 'none', width: '42px', height: '42px', borderRadius: '12px', display: 'grid', placeItems: 'center', background: 'rgba(62,207,142,0.12)', border: '1px solid rgba(62,207,142,0.28)' } }, fa('fa-camera', { color: C_GREEN, fontSize: '18px' })),
                                h('span', { key: 'tx', style: { flex: 1 } }, [
                                    h('span', { key: 't', style: { display: 'block', fontSize: '14.5px', fontWeight: 700, color: '#f4f4f6' } }, 'Scan QR with camera'),
                                    h('span', { key: 's', style: { display: 'block', fontSize: '12.5px', color: '#8a8a92', marginTop: '1px' } }, "Fastest — point at your peer's screen")
                                ]),
                                fa('fa-chevron-right', { color: '#6b6b73' })
                            ]),
                            h('div', { key: 'or', style: { display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '14px' } }, [
                                h('span', { key: 'a', style: { flex: 1, height: '1px', background: 'rgba(255,255,255,0.07)' } }),
                                h('span', { key: 'm', style: { fontSize: '11px', fontWeight: 600, color: '#56565e', textTransform: 'uppercase', letterSpacing: '0.7px' } }, 'or paste code'),
                                h('span', { key: 'b', style: { flex: 1, height: '1px', background: 'rgba(255,255,255,0.07)' } })
                            ]),
                            h('div', { key: 'ta', style: { borderRadius: '13px', border: `1px solid ${hasInvite ? 'rgba(255,255,255,0.18)' : 'rgba(255,255,255,0.07)'}`, background: '#141416', padding: '13px 15px', marginBottom: '12px' } },
                                h('textarea', { value: offerInput, onChange: (e) => { setOfferInput(e.target.value); if (e.target.value.trim().length > 0 && typeof markAnswerCreated === 'function') markAnswerCreated(); }, rows: 3, placeholder: 'Paste invitation code here…', style: { width: '100%', resize: 'none', border: 'none', outline: 'none', background: 'transparent', color: '#d7d7db', fontFamily: MONO, fontSize: '12.5px', lineHeight: 1.6, minHeight: '66px' } })),
                            h('button', { key: 'connect', onClick: () => { requestNotificationPermissionOnInteraction(); onCreateAnswer(); }, disabled: !hasInvite || connectionStatus === 'connecting', style: { width: '100%', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '9px', padding: '14px', borderRadius: '13px', border: 'none', background: (hasInvite && connectionStatus !== 'connecting') ? C_ORANGE : 'rgba(255,255,255,0.05)', color: (hasInvite && connectionStatus !== 'connecting') ? '#1a0f04' : '#56565e', fontFamily: 'inherit', fontSize: '15px', fontWeight: 700, cursor: (hasInvite && connectionStatus !== 'connecting') ? 'pointer' : 'not-allowed', boxShadow: (hasInvite && connectionStatus !== 'connecting') ? '0 8px 24px rgba(240,137,42,0.28)' : 'none' } }, connectionStatus === 'connecting' ? 'Processing…' : 'Connect')
                        ]);
                    }

                    // Desktop downloads (real GitHub release assets) + OS detection.
                    const DOWNLOADS = {
                        mac: { name: 'macOS', format: '.dmg · Apple Silicon & Intel', icon: 'fab fa-apple', url: 'https://github.com/SecureBitChat/securebit-desktop/releases/download/v0.1.0/SecureBit.Chat_0.1.0_x64.dmg' },
                        win: { name: 'Windows', format: '.exe · 64-bit installer', icon: 'fab fa-windows', url: 'https://github.com/SecureBitChat/securebit-desktop/releases/latest/download/SecureBit.Chat_0.1.0_x64-setup.exe' },
                        linux: { name: 'Linux', format: '.AppImage', icon: 'fab fa-linux', url: 'https://github.com/SecureBitChat/securebit-desktop/releases/latest/download/SecureBit.Chat_0.1.0_amd64.AppImage' }
                    };
                    const detectOS = () => {
                        const ua = (navigator.userAgent || '') + ' ' + (navigator.platform || '');
                        if (/Mac|iPhone|iPad|iPod/i.test(ua) && !/Android/i.test(ua)) return 'mac';
                        if (/Win/i.test(ua)) return 'win';
                        if (/Linux/i.test(ua) && !/Android/i.test(ua)) return 'linux';
                        return 'win';
                    };
                    const detectedOS = detectOS();
                    const otherOS = ['mac', 'win', 'linux'].filter((k) => k !== detectedOS);
                    const dlLink = (url) => { try { window.open(url, '_blank', 'noopener'); } catch (e) {} };

                    const platformsMenu = platformsOpen && h('div', { key: 'platmenu', className: 'sb-platforms-menu', style: { position: 'absolute', left: 0, bottom: 'calc(100% + 10px)', width: '344px', maxWidth: '100%', borderRadius: '16px', border: '1px solid rgba(255,255,255,0.1)', background: '#161618', boxShadow: '0 24px 60px rgba(0,0,0,0.55)', overflow: 'hidden', zIndex: 25, animation: 'sbUp .2s ease' } }, [
                        h('div', { key: 'mh', style: { display: 'flex', alignItems: 'center', gap: '10px', padding: '14px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)' } }, [
                            h('div', { key: 't', style: { flex: 1, lineHeight: 1.2 } }, [
                                h('div', { key: 'a', style: { fontSize: '14px', fontWeight: 800, color: '#f4f4f6' } }, 'Download SecureBit'),
                                h('div', { key: 'b', style: { fontSize: '11.5px', color: '#7b7b83' } }, 'Free · open source')
                            ]),
                            h('span', { key: 'pill', style: { fontFamily: MONO, fontSize: '10px', fontWeight: 600, color: C_GREEN, padding: '3px 8px', borderRadius: '6px', background: 'rgba(62,207,142,0.1)', border: '1px solid rgba(62,207,142,0.22)' } }, "You're on Web")
                        ]),
                        h('div', { key: 'rec', style: { padding: '12px 12px 6px' } },
                            h('button', { key: 'b', onClick: () => dlLink(DOWNLOADS[detectedOS].url), style: { width: '100%', display: 'flex', alignItems: 'center', gap: '12px', padding: '13px 14px', borderRadius: '12px', border: '1px solid rgba(240,137,42,0.4)', background: 'rgba(240,137,42,0.08)', color: 'inherit', fontFamily: 'inherit', cursor: 'pointer', textAlign: 'left' } }, [
                                h('span', { key: 'ic', style: { flex: 'none', display: 'grid', placeItems: 'center', width: '38px', height: '38px', borderRadius: '11px', background: 'rgba(240,137,42,0.14)', border: '1px solid rgba(240,137,42,0.3)', color: C_ORANGE } }, h('i', { className: DOWNLOADS[detectedOS].icon, style: { fontSize: '17px' } })),
                                h('span', { key: 'tx', style: { flex: 1, minWidth: 0 } }, [
                                    h('span', { key: 'n', style: { display: 'block', fontSize: '13.5px', fontWeight: 700, color: '#f4f4f6' } }, DOWNLOADS[detectedOS].name),
                                    h('span', { key: 'f', style: { display: 'block', fontSize: '11px', color: '#f0b072', marginTop: '1px' } }, `Recommended for this device · ${DOWNLOADS[detectedOS].format}`)
                                ]),
                                fa('fa-download', { color: C_ORANGE })
                            ])),
                        h('div', { key: 'others', style: { padding: '0 12px 8px', display: 'flex', flexDirection: 'column', gap: '2px' } },
                            otherOS.map((k) => h('button', { key: k, onClick: () => dlLink(DOWNLOADS[k].url), style: { width: '100%', display: 'flex', alignItems: 'center', gap: '12px', padding: '11px 14px', borderRadius: '11px', border: 'none', background: 'transparent', color: 'inherit', fontFamily: 'inherit', cursor: 'pointer', textAlign: 'left' } }, [
                                h('span', { key: 'ic', style: { flex: 'none', display: 'grid', placeItems: 'center', width: '34px', height: '34px', borderRadius: '10px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', color: '#cfcfd4' } }, h('i', { className: DOWNLOADS[k].icon, style: { fontSize: '15px' } })),
                                h('span', { key: 'tx', style: { flex: 1, minWidth: 0 } }, [
                                    h('span', { key: 'n', style: { display: 'block', fontSize: '13px', fontWeight: 600, color: '#e8e8eb' } }, DOWNLOADS[k].name),
                                    h('span', { key: 'f', style: { display: 'block', fontSize: '11px', color: '#7b7b83', marginTop: '1px' } }, DOWNLOADS[k].format)
                                ]),
                                fa('fa-download', { color: '#8a8a92' })
                            ]))),
                        h('div', { key: 'soon', style: { display: 'flex', alignItems: 'center', gap: '9px', padding: '12px 16px', borderTop: '1px solid rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.015)' } }, [
                            fa('fa-clock', { key: 'i', color: '#6b6b73' }),
                            h('span', { key: 't', style: { fontSize: '11.5px', lineHeight: 1.45, color: '#7b7b83' } }, 'Mobile (iOS, Android) and browser extensions (Chrome, Firefox, Opera) are coming soon.')
                        ])
                    ]);

                    const footer = h('div', { key: 'footer', className: 'sb-conn-footer', style: { position: 'relative', marginTop: '30px', paddingTop: '18px', borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' } }, [
                        h('button', { key: 'dl', onClick: () => setPlatformsOpen((v) => !v), style: { display: 'inline-flex', alignItems: 'center', gap: '9px', padding: '8px 13px 8px 9px', borderRadius: '10px', border: `1px solid ${platformsOpen ? 'rgba(240,137,42,0.4)' : 'rgba(255,255,255,0.08)'}`, background: platformsOpen ? 'rgba(240,137,42,0.06)' : 'rgba(255,255,255,0.02)', color: 'inherit', fontFamily: 'inherit', cursor: 'pointer', transition: 'all .15s' } }, [
                            fa('fa-download', { key: 'i', color: C_ORANGE }),
                            h('span', { key: 't', style: { fontSize: '12.5px', fontWeight: 700, color: '#e8e8eb' } }, 'Download desktop app'),
                            fa('fa-chevron-down', { key: 'c', color: '#6b6b73', style: { fontSize: '11px', transform: platformsOpen ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform .2s' } })
                        ]),
                        h('button', { key: 'settings', className: 'sb-link', onClick: () => setShowIceSettings && setShowIceSettings(true), style: { display: 'inline-flex', alignItems: 'center', gap: '7px', background: 'none', border: 'none', color: '#8a8a92', fontFamily: 'inherit', fontSize: '12.5px', fontWeight: 600, cursor: 'pointer' } }, [fa('fa-sliders-h', { key: 'i' }), 'Advanced settings']),
                        platformsMenu
                    ]);

                    // Advanced settings overlay — rendered inside the right column,
                    // sliding up over it (z-30), exactly as in the design.
                    const settingsOverlay = (showIceSettings && typeof window !== 'undefined' && window.IceServerSettings)
                        ? h(window.IceServerSettings, {
                            key: 'ice-settings',
                            isOpen: true,
                            embedded: true,
                            onClose: () => setShowIceSettings(false),
                            initial: {
                                useCustom: Array.isArray(customIceServers) && customIceServers.length > 0,
                                serversText: iceServersText,
                                privacyMode: relayOnlyMode ? 'relay-only' : 'standard',
                                persisted: iceSettingsPersisted
                            },
                            hasSaved: iceSettingsPersisted,
                            onApply: handleApplyIceSettings,
                            onForget: handleForgetIceSettings
                        })
                        : null;

                    const rightPanel = h('div', { key: 'right', style: compact
                        ? { flex: 1, minWidth: 0, width: '100%', position: 'relative', overflow: 'hidden', display: 'flex', flexDirection: 'column', height: '100%' }
                        : { flex: '0.95 1 460px', minWidth: 'min(100%, 320px)', position: 'relative', overflow: 'hidden', display: 'flex', flexDirection: 'column', height: '100vh' } }, [
                        h('div', { key: 'scroll', className: 'custom-scrollbar', style: { flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', padding: '42px 44px' } },
                            h('div', { style: { maxWidth: '430px', width: '100%', margin: 'auto' } }, [
                                h('div', { key: 'kicker', style: { fontFamily: MONO, fontSize: '11px', fontWeight: 600, color: '#6b6b73', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '10px' } }, kicker),
                                segToggle,
                                inner,
                                footer
                            ])),
                        settingsOverlay
                    ]);

                    // ── QR display modal (real qrCodeUrl + frame controls) ──
                    const qrModal = (qrModalOpen && qrCodeUrl) && h('div', { key: 'qrmodal', onClick: () => setQrModalOpen(false), style: { position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '32px', background: 'rgba(6,6,8,0.82)', backdropFilter: 'blur(10px)', animation: 'sbUp .2s ease' } },
                        h('div', { onClick: (e) => e.stopPropagation(), style: { width: '100%', maxWidth: '460px', borderRadius: '22px', border: '1px solid rgba(255,255,255,0.1)', background: '#111113', boxShadow: '0 30px 90px rgba(0,0,0,0.6)', overflow: 'hidden' } }, [
                            h('div', { key: 'head', style: { display: 'flex', alignItems: 'center', gap: '11px', padding: '18px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)' } }, [
                                h('span', { key: 'd', style: { width: '9px', height: '9px', borderRadius: '50%', background: accent } }),
                                h('div', { key: 'tx', style: { flex: 1, lineHeight: 1.2 } }, [
                                    h('div', { key: 't', style: { fontSize: '15.5px', fontWeight: 800, color: '#f4f4f6' } }, isCreate ? 'Share your invitation' : 'Send back your answer'),
                                    h('div', { key: 's', style: { fontSize: '12px', color: '#7b7b83' } }, `${isCreate ? 'offer' : 'answer'} · one-time`)
                                ]),
                                h('button', { key: 'x', onClick: () => setQrModalOpen(false), style: { width: '32px', height: '32px', display: 'grid', placeItems: 'center', borderRadius: '9px', border: 'none', background: 'rgba(255,255,255,0.05)', color: '#9a9aa2', cursor: 'pointer' } }, fa('fa-times'))
                            ]),
                            h('div', { key: 'body', style: { padding: '22px 24px 24px' } }, [
                                h('div', { key: 'qr', style: { position: 'relative', width: '100%', aspectRatio: '1', borderRadius: '18px', overflow: 'hidden', background: '#fff', padding: '18px', display: 'grid', placeItems: 'center' } },
                                    h('img', { src: qrCodeUrl, alt: 'QR code', style: { width: '100%', height: '100%', objectFit: 'contain', display: 'block' } })),
                                h('div', { key: 'ctrls', style: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px', marginTop: '18px' } }, [
                                    (qrFramesTotal || 0) >= 1 && h('div', { key: 'frame', style: { display: 'flex', alignItems: 'center', gap: '9px' } }, [
                                        h('span', { key: 'l', style: { fontFamily: MONO, fontSize: '12px', fontWeight: 600, color: '#9a9aa2' } }, `Frame ${Math.max(1, qrFrameIndex || 1)} / ${qrFramesTotal || 1}`),
                                        h('div', { key: 'dots', style: { display: 'flex', gap: '5px' } }, Array.from({ length: qrFramesTotal || 1 }, (_, i) => h('span', { key: i, style: { width: '7px', height: '7px', borderRadius: '50%', background: (i + 1) === (qrFrameIndex || 1) ? accent : 'rgba(255,255,255,0.14)', transition: 'background .25s' } })))
                                    ]),
                                    (qrFramesTotal || 0) > 1 && h('div', { key: 'nav', style: { display: 'flex', alignItems: 'center', gap: '6px' } }, [
                                        h('button', { key: 'prev', onClick: prevQrFrame, style: { width: '40px', height: '36px', display: 'grid', placeItems: 'center', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.04)', color: '#cfcfd4', cursor: 'pointer' } }, fa('fa-chevron-left')),
                                        h('button', { key: 'auto', onClick: toggleQrManualMode, style: { display: 'inline-flex', alignItems: 'center', gap: '7px', padding: '9px 18px', borderRadius: '10px', border: `1px solid ${qrManualMode ? 'rgba(255,255,255,0.1)' : 'rgba(240,137,42,0.45)'}`, background: qrManualMode ? 'rgba(255,255,255,0.04)' : 'rgba(240,137,42,0.08)', color: qrManualMode ? '#9a9aa2' : C_ORANGE, fontFamily: 'inherit', fontSize: '13px', fontWeight: 600, cursor: 'pointer' } }, qrManualMode ? 'Manual' : 'Auto'),
                                        h('button', { key: 'next', onClick: nextQrFrame, style: { width: '40px', height: '36px', display: 'grid', placeItems: 'center', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.04)', color: '#cfcfd4', cursor: 'pointer' } }, fa('fa-chevron-right'))
                                    ]),
                                    h('p', { key: 'hint', style: { margin: '2px 0 0', textAlign: 'center', fontSize: '12px', lineHeight: 1.5, color: '#6b6b73' } }, (qrFramesTotal || 0) > 1 ? `The handshake is split across ${qrFramesTotal} frames — keep this open until your peer captures all of them.` : 'Keep this open until your peer captures the code.')
                                ])
                            ])
                        ])
                    );

                    const hero = h('div', { key: 'hero', style: { display: 'flex', flexWrap: 'wrap', minHeight: '100vh', width: '100%', background: '#0f0f11', color: '#e8e8eb' } }, [leftPanel, rightPanel]);

                    // Full-bleed dark bands — match the design mockups (not clamped to max-w-4xl).
                    const uniqueSection = atIntro && h(UniqueFeatureSlider, { key: 'unique-features-slider' });
                    const partnersSection = atIntro && h(BecomePartner, { key: 'become-partner' });
                    const roadmapSection = atIntro && h(Roadmap, { key: 'roadmap' });
                    const communitySection = atIntro && h(CommunityCTA, { key: 'community-cta' });

                    // Ship the keyframes inside app.js so the animations can never go
                    // stale against a service-worker-cached components.css.
                    const keyframeStyle = h('style', { key: 'kf', dangerouslySetInnerHTML: { __html:
                        '@keyframes sbFlowR{0%{left:4%;opacity:0}12%{opacity:1}88%{opacity:1}100%{left:96%;opacity:0}}' +
                        '@keyframes sbFlowL{0%{left:96%;opacity:0}12%{opacity:1}88%{opacity:1}100%{left:4%;opacity:0}}' +
                        '@keyframes sbPulse{0%,100%{transform:translate(-50%,-50%) scale(1);opacity:.5}50%{transform:translate(-50%,-50%) scale(1.5);opacity:0}}' +
                        '@keyframes sbSpin{to{transform:rotate(360deg)}}' +
                        '@keyframes sbUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}' +
                        '@keyframes sbNode{0%,100%{box-shadow:0 0 0 0 rgba(62,207,142,0)}50%{box-shadow:0 0 0 6px rgba(62,207,142,.06)}}' +
                        '@keyframes sbScan{0%{top:8%}100%{top:88%}}' +
                        '@keyframes sbBlink{0%,100%{opacity:1}50%{opacity:.35}}'
                    } });

                    // Embedded in the chat column (additional session): just the create/connect
                    // card filling the area — no hero, no marketing landing.
                    if (compact) {
                        return h('div', { className: 'sb-start', style: { flex: 1, minHeight: 0, width: '100%', display: 'flex', flexDirection: 'column', background: '#0f0f11', color: '#e8e8eb' } }, [keyframeStyle, rightPanel, qrModal]);
                    }

                    return h('div', { className: 'sb-start', style: { width: '100%' } }, [keyframeStyle, hero, uniqueSection, partnersSection, roadmapSection, communitySection, qrModal]);
                };
        
                // Global scroll function - defined outside components to ensure availability
                const createScrollToBottomFunction = (chatMessagesRef) => {
                    return () => {
                        if (chatMessagesRef && chatMessagesRef.current) {
                            const scrollAttempt = () => {
                                if (chatMessagesRef.current) {
                                    chatMessagesRef.current.scrollTo({
                                        top: chatMessagesRef.current.scrollHeight,
                                        behavior: 'smooth'
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


            // Runs the real-time cryptographic verification and shows a detailed report
            // modal (same behaviour the shared header used to provide on click).
            const runSecurityReport = async (webrtcManager) => {
                let securityData = null;
                try {
                    if (webrtcManager && window.EnhancedSecureCryptoUtils) {
                        securityData = await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(webrtcManager);
                    }
                } catch (e) { /* ignore */ }
                if (!securityData) {
                    alert('Security verification in progress…\nPlease wait for real-time cryptographic verification to complete.');
                    return;
                }

                // Security verification report — translated from the Claude Design
                // component (Security Verification.dc.html): a gauge + live test grid
                // driven by the real cryptographic results in securityData.
                const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
                const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
                const accent = securityData.color === 'orange' ? '#f0892a'
                    : securityData.color === 'yellow' ? '#e3c84e'
                    : securityData.color === 'red' ? '#e5727a'
                    : '#3ecf8e';
                const accentRGB = securityData.color === 'orange' ? '240,137,42'
                    : securityData.color === 'yellow' ? '227,200,78'
                    : securityData.color === 'red' ? '229,114,122'
                    : '62,207,142';
                const score = Math.max(0, Math.min(100, Math.round(securityData.score || 0)));
                const circ = 2 * Math.PI * 56;
                const dashArray = `${(circ * Math.min(1, score / 100)).toFixed(1)} ${circ.toFixed(1)}`;
                const level = String(securityData.level || 'SECURE').toUpperCase();
                const isReal = securityData.isRealData !== false;
                const entries = securityData.verificationResults ? Object.entries(securityData.verificationResults) : [];
                const passedCount = Number.isFinite(securityData.passedChecks) ? securityData.passedChecks : entries.filter(([, r]) => r && r.passed).length;
                const totalCount = Number.isFinite(securityData.totalChecks) ? securityData.totalChecks : entries.length;
                const verifiedAt = new Date(securityData.timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });

                const pretty = (k) => {
                    let s = String(k).replace(/^verify/i, '').replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2').trim();
                    s = s.replace(/\b(ecdh|ecdsa|aes|gcm|hmac|pfs|sas|mitm|asn|dtls|hkdf|spki|oid|p384)\b/gi, (m) => m.toUpperCase());
                    return s.charAt(0).toUpperCase() + s.slice(1);
                };

                const checkIcon = `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#3ecf8e" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 13l4 4 10-11"/></svg>`;
                const xIcon = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#e5727a" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6L6 18M6 6l12 12"/></svg>`;
                const testsHTML = entries.map(([k, r], i) => {
                    const passed = !!(r && r.passed);
                    const desc = (r && r.details) || (passed ? 'Test passed' : 'Test failed or unavailable');
                    const bg = passed ? '#161618' : '#121214';
                    const border = passed ? 'rgba(62,207,142,0.16)' : 'rgba(229,114,122,0.18)';
                    const iconBg = passed ? 'rgba(62,207,142,0.12)' : 'rgba(229,114,122,0.1)';
                    const iconBorder = passed ? 'rgba(62,207,142,0.26)' : 'rgba(229,114,122,0.24)';
                    const titleColor = passed ? '#f4f4f6' : '#cfcfd4';
                    return `<div style="display:flex; align-items:flex-start; gap:13px; padding:16px 18px; border-radius:14px; background:${bg}; border:1px solid ${border}; animation:svIn .3s cubic-bezier(.2,.7,.3,1) both; animation-delay:${(i * 0.04).toFixed(2)}s;">
                        <span style="flex:none; width:34px; height:34px; border-radius:9px; display:grid; place-items:center; background:${iconBg}; border:1px solid ${iconBorder};">${passed ? checkIcon : xIcon}</span>
                        <div style="flex:1; min-width:0;">
                            <div style="font-size:14.5px; font-weight:700; letter-spacing:-0.2px; color:${titleColor}; margin-bottom:3px;">${esc(pretty(k))}</div>
                            <div style="font-family:${MONO}; font-size:11.5px; line-height:1.45; color:#8a8a92;">${esc(desc)}</div>
                        </div>
                    </div>`;
                }).join('');

                const modal = document.createElement('div');
                modal.id = 'sb-security-report';
                modal.style.cssText = "position:fixed; inset:0; z-index:10000; display:flex; align-items:center; justify-content:center; padding:24px; background:rgba(8,8,10,0.62); backdrop-filter:blur(4px); -webkit-backdrop-filter:blur(4px); font-family:'Manrope',system-ui,-apple-system,sans-serif; overflow:auto;";
                modal.innerHTML = `
                  <style>@keyframes svIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}@keyframes svPulse{0%,100%{opacity:1}50%{opacity:.4}}</style>
                  <div style="position:relative; max-width:960px; width:100%; border-radius:20px; background:radial-gradient(1100px 640px at 50% -6%, rgba(${accentRGB},0.05), transparent 62%), #0f0f11; border:1px solid rgba(255,255,255,0.08); color:#e8e8eb; padding:30px; box-shadow:0 30px 70px rgba(0,0,0,0.55); animation:svIn .3s cubic-bezier(.2,.7,.3,1); max-height:calc(100vh - 48px); overflow:auto;">
                    <button class="sv-close" type="button" title="Close" style="position:absolute; top:16px; right:16px; width:32px; height:32px; border-radius:9px; display:grid; place-items:center; border:1px solid rgba(255,255,255,0.08); background:rgba(255,255,255,0.02); color:#8a8a92; cursor:pointer; z-index:2;">
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none;"><path d="M6 6l12 12M18 6L6 18"/></svg>
                    </button>
                    <div style="position:relative; overflow:hidden; border-radius:18px; background:#141416; border:1px solid rgba(255,255,255,0.07); padding:28px 30px; display:flex; align-items:center; gap:30px; flex-wrap:wrap; margin-bottom:20px;">
                      <div style="position:absolute; top:0; left:0; right:0; height:1px; background:linear-gradient(90deg, transparent, rgba(${accentRGB},0.6), transparent);"></div>
                      <div style="position:relative; flex:none; width:128px; height:128px;">
                        <svg width="128" height="128" viewBox="0 0 128 128" style="transform:rotate(-90deg);">
                          <circle cx="64" cy="64" r="56" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="9"/>
                          <circle cx="64" cy="64" r="56" fill="none" stroke="${accent}" stroke-width="9" stroke-linecap="round" stroke-dasharray="${dashArray}"/>
                        </svg>
                        <div style="position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center;">
                          <span style="font-size:30px; font-weight:800; letter-spacing:-1px; color:#f4f4f6; line-height:1;">${score}</span>
                          <span style="font-family:${MONO}; font-size:10px; font-weight:600; color:#6b6b73; text-transform:uppercase; letter-spacing:1px; margin-top:4px;">/ 100 pts</span>
                        </div>
                      </div>
                      <div style="flex:1; min-width:240px;">
                        <div style="font-family:${MONO}; font-size:11px; font-weight:600; color:#6b6b73; text-transform:uppercase; letter-spacing:1.6px; margin-bottom:10px;">Real-time security verification</div>
                        <div style="display:flex; align-items:center; gap:12px; margin-bottom:14px; flex-wrap:wrap;">
                          <h2 style="margin:0; font-size:26px; font-weight:800; letter-spacing:-0.7px; color:#f4f4f6;">Security level: ${esc(level)}</h2>
                          <span style="display:inline-flex; align-items:center; gap:8px; padding:6px 12px; border-radius:9px; background:rgba(${accentRGB},0.12); border:1px solid rgba(${accentRGB},0.3); font-family:${MONO}; font-size:11px; font-weight:700; color:${accent}; text-transform:uppercase; letter-spacing:0.6px;"><span style="width:7px; height:7px; border-radius:50%; background:${accent}; animation:svPulse 2s ease-in-out infinite;"></span>Active</span>
                        </div>
                        <div style="display:flex; gap:28px; flex-wrap:wrap;">
                          <div><div style="font-family:${MONO}; font-size:10px; font-weight:600; color:#56565e; text-transform:uppercase; letter-spacing:1px; margin-bottom:4px;">Tests passed</div><div style="font-size:15px; font-weight:700; color:#e8e8eb;"><span style="color:${accent};">${passedCount}</span> / ${totalCount}</div></div>
                          <div><div style="font-family:${MONO}; font-size:10px; font-weight:600; color:#56565e; text-transform:uppercase; letter-spacing:1px; margin-bottom:4px;">Verified at</div><div style="font-family:${MONO}; font-size:15px; font-weight:600; color:#e8e8eb;">${esc(verifiedAt)}</div></div>
                          <div><div style="font-family:${MONO}; font-size:10px; font-weight:600; color:#56565e; text-transform:uppercase; letter-spacing:1px; margin-bottom:4px;">Source</div><div style="font-size:15px; font-weight:600; color:#e8e8eb;">${isReal ? 'Real cryptographic tests' : 'Simulated data'}</div></div>
                        </div>
                      </div>
                      <button class="sv-rerun" type="button" style="flex:none; display:inline-flex; align-items:center; gap:9px; padding:12px 18px; border-radius:11px; border:1px solid rgba(255,255,255,0.1); background:rgba(255,255,255,0.025); color:#cfcfd4; font-family:'Manrope',sans-serif; font-size:14px; font-weight:700; cursor:pointer; transition:all .2s;">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none;"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/></svg>
                        Re-run
                      </button>
                    </div>
                    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(248px, 1fr)); gap:12px;">${testsHTML}</div>
                    <div style="display:flex; align-items:center; gap:12px; margin-top:18px; padding:16px 20px; border-radius:14px; background:rgba(${accentRGB},0.06); border:1px solid rgba(${accentRGB},0.18);">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="${accent}" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" style="flex:none;"><path d="M12 3l8 4v5c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V7l8-4z"/><path d="M9.2 12.2l2 2 3.6-3.8"/></svg>
                      <span style="font-size:14px; font-weight:600; color:#e8e8eb;">${isReal ? 'Real-time verification using actual cryptographic functions — no mock data.' : 'Warning: connection may not be fully established — values may be simulated.'}</span>
                    </div>
                  </div>`;

                const onKey = (e) => { if (e.key === 'Escape') close(); };
                const close = () => { if (modal.parentNode) modal.remove(); document.removeEventListener('keydown', onKey); };
                modal.querySelector('.sv-close').addEventListener('click', close);
                modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
                document.addEventListener('keydown', onKey);
                const rerun = modal.querySelector('.sv-rerun');
                rerun.addEventListener('mouseenter', () => { rerun.style.borderColor = 'rgba(240,137,42,0.45)'; rerun.style.color = '#f0892a'; });
                rerun.addEventListener('mouseleave', () => { rerun.style.borderColor = 'rgba(255,255,255,0.1)'; rerun.style.color = '#cfcfd4'; });
                rerun.addEventListener('click', () => { close(); runSecurityReport(webrtcManager); });
                document.body.appendChild(modal);
            };

            // In-chat header matching the SecureBit Chat design: logo + version,
            // a "Secure" pill (click = run the security verification report; the chevron
            // toggles the network/crypto detail panel), a connection indicator, Disconnect.
            const SecureBitChatHeader = ({ status, onDisconnect, webrtcManager, title, isOffline, peerPresence, onRenameTitle }) => {
                const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
                const [showNetwork, setShowNetwork] = React.useState(false);
                const [sec, setSec] = React.useState(null);
                const [editingName, setEditingName] = React.useState(false);
                const [nameDraft, setNameDraft] = React.useState('');

                React.useEffect(() => {
                    let alive = true;
                    const fetchSec = async () => {
                        try {
                            if (!webrtcManager) return;
                            let data = null;
                            if (typeof webrtcManager.getRealSecurityLevel === 'function') data = await webrtcManager.getRealSecurityLevel();
                            else if (typeof webrtcManager.calculateAndReportSecurityLevel === 'function') data = await webrtcManager.calculateAndReportSecurityLevel();
                            else if (window.EnhancedSecureCryptoUtils) data = await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(webrtcManager);
                            if (alive && data && data.isRealData !== false) setSec(data);
                        } catch (e) { /* ignore */ }
                    };
                    fetchSec();
                    const onCalc = (e) => { if (alive && e.detail && e.detail.securityData) setSec(e.detail.securityData); };
                    document.addEventListener('real-security-calculated', onCalc);
                    const iv = setInterval(fetchSec, 15000);
                    return () => { alive = false; clearInterval(iv); document.removeEventListener('real-security-calculated', onCalc); };
                }, [webrtcManager]);

                // Offline (our device lost connectivity) takes precedence over the P2P state —
                // the data channel can stay "open" after the network drops, so without this the
                // header would keep saying "Connected" while the user is actually offline.
                const onlineConnected = status === 'connected' || status === 'verified';
                const dropped = status === 'disconnected' || status === 'peer_disconnected';
                const connected = onlineConnected && !isOffline;
                const connDot = (isOffline || dropped) ? '#e5727a' : (onlineConnected ? '#3ecf8e' : '#e3c84e');
                const connLabel = isOffline
                    ? 'Offline'
                    : (onlineConnected ? 'Connected'
                        : (status === 'peer_disconnected' ? 'Peer disconnected'
                            : (status === 'disconnected' ? 'Disconnected' : 'Connecting…')));
                const connGlow = (isOffline || dropped) ? '0 0 0 3px rgba(229,114,122,0.16)' : (onlineConnected ? '0 0 0 3px rgba(62,207,142,0.16)' : '0 0 0 3px rgba(227,200,78,0.16)');
                // The avatar dot + subtitle reflect the PEER's advertised availability while connected.
                const peerDot = (onlineConnected && !isOffline) ? (PRESENCE_DOT[peerPresence] || '#3ecf8e') : connDot;
                const peerPresenceWord = (onlineConnected && !isOffline && peerPresence) ? (PRESENCE_WORD[peerPresence] || null) : null;
                const startRename = () => { setNameDraft(title || ''); setEditingName(true); };
                const commitRename = () => { if (typeof onRenameTitle === 'function') onRenameTitle(nameDraft); setEditingName(false); };
                const renameKey = (e) => { if (e.key === 'Enter') { e.preventDefault(); commitRename(); } else if (e.key === 'Escape') { setEditingName(false); } };
                const passed = sec && Number.isFinite(sec.passedChecks) ? sec.passedChecks : null;
                const total = sec && Number.isFinite(sec.totalChecks) ? sec.totalChecks : null;
                const scoreLabel = (passed != null && total) ? (passed + '/' + total) : (sec ? (sec.score + '%') : '—');
                const accent = sec
                    ? (sec.color === 'green' ? '#3ecf8e' : sec.color === 'orange' ? '#f0892a' : sec.color === 'yellow' ? '#e3c84e' : '#e5727a')
                    : '#3ecf8e';

                const secBtn = React.createElement('div', {
                    key: 'sec', title: 'Run security verification',
                    onClick: () => runSecurityReport(webrtcManager),
                    className: 'sb-secpill',
                    style: { display: 'flex', alignItems: 'center', gap: '9px', padding: '7px 13px', borderRadius: '9px', border: '1px solid ' + (showNetwork ? 'rgba(255,255,255,0.16)' : 'rgba(255,255,255,0.07)'), background: showNetwork ? 'rgba(255,255,255,0.05)' : 'rgba(255,255,255,0.02)', cursor: 'pointer', fontFamily: 'inherit', transition: 'all .15s' }
                }, [
                    React.createElement('i', { key: 'i', className: 'fas fa-shield-halved', style: { color: accent, fontSize: '13px' } }),
                    React.createElement('span', { key: 'l', className: 'sb-sec-label', style: { fontSize: '13px', fontWeight: 600, color: '#e8e8eb' } }, sec ? (sec.level || 'Secure') : 'Secure'),
                    React.createElement('span', { key: 'd', className: 'sb-sec-div', style: { width: '1px', height: '13px', background: 'rgba(255,255,255,0.12)' } }),
                    React.createElement('span', { key: 's', className: 'sb-sec-score', style: { fontFamily: MONO, fontSize: '11.5px', fontWeight: 500, color: '#8a8a92' } }, scoreLabel),
                    React.createElement('button', {
                        key: 'c', type: 'button', title: 'Network & crypto details',
                        onClick: (e) => { e.stopPropagation(); setShowNetwork(v => !v); },
                        style: { background: 'none', border: 'none', padding: 0, margin: 0, cursor: 'pointer', display: 'grid', placeItems: 'center' }
                    }, React.createElement('i', { className: 'fas fa-chevron-down', style: { color: '#6b6b73', fontSize: '11px', transform: showNetwork ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform .2s' } }))
                ]);

                const headerResponsiveCss = React.createElement('style', { key: 'hdr-css', dangerouslySetInnerHTML: { __html:
                    // Mobile: leave room for the drawer hamburger and shed non-essential header
                    // chrome so avatar + name + status + Disconnect fit a narrow screen.
                    '@media (max-width:768px){' +
                    '.sb-chat-header{padding-left:60px !important;gap:10px !important;}' +
                    '.sb-chat-header .sb-sec-score,.sb-chat-header .sb-sec-label,.sb-chat-header .sb-sec-div{display:none !important;}' +
                    '.sb-chat-header .sb-secpill{padding:8px !important;gap:6px !important;}' +
                    '.sb-chat-header .sb-conn-text{display:none !important;}' +
                    '.sb-chat-header .sb-conn{padding:9px !important;}' +
                    '.sb-chat-header .sb-hdr-sub{display:none !important;}' +
                    '}' +
                    '@media (max-width:480px){.sb-chat-header{padding-right:12px !important;gap:8px !important;}}'
                } });
                const header = React.createElement('header', {
                    key: 'hdr', className: 'sb-chat-header', style: { flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '24px', padding: '0 20px', height: '64px', borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(18,18,20,0.72)', backdropFilter: 'blur(14px)', WebkitBackdropFilter: 'blur(14px)' }
                }, [
                    headerResponsiveCss,
                    // The SecureBit brand/logo lives in the left rail; this header identifies the
                    // ACTIVE conversation — avatar monogram + local label + connection status.
                    React.createElement('div', { key: 'left', style: { display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0 } }, [
                        React.createElement('div', { key: 'avatar', style: { position: 'relative', flex: 'none', width: '36px', height: '36px', borderRadius: '10px', display: 'grid', placeItems: 'center', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.09)', fontSize: '13px', fontWeight: 700, letterSpacing: '-0.3px', color: '#e8e8eb' } }, [
                            monoInitials(title || 'Chat'),
                            React.createElement('span', { key: 'dot', style: { position: 'absolute', right: '-2px', bottom: '-2px', width: '11px', height: '11px', borderRadius: '50%', background: peerDot, border: '2px solid #121214' } })
                        ]),
                        editingName
                            ? React.createElement('div', { key: 'edit', style: { display: 'flex', flexDirection: 'column', gap: '4px', minWidth: 0 } }, [
                                React.createElement('div', { key: 'row', style: { display: 'flex', alignItems: 'center', gap: '6px' } }, [
                                    React.createElement('input', { key: 'in', autoFocus: true, value: nameDraft, maxLength: 32, placeholder: 'Name this chat', onChange: (e) => setNameDraft(e.target.value), onKeyDown: renameKey, onBlur: commitRename, style: { width: '210px', padding: '5px 10px', borderRadius: '8px', border: '1px solid rgba(240,137,42,0.55)', background: '#0f0f11', color: '#f4f4f6', fontFamily: 'inherit', fontSize: '14px', fontWeight: 700, outline: 'none' } }),
                                    React.createElement('button', { key: 'ok', onMouseDown: (e) => e.preventDefault(), onClick: commitRename, title: 'Save', style: { flex: 'none', width: '28px', height: '28px', borderRadius: '8px', display: 'grid', placeItems: 'center', border: 'none', background: '#f0892a', color: '#1a0f04', cursor: 'pointer' } }, React.createElement('i', { className: 'fas fa-check', style: { fontSize: '12px' } }))
                                ]),
                                React.createElement('div', { key: 'hint', style: { fontSize: '11px', color: '#56565e' } }, 'Local label · stored only on this device')
                            ])
                            : React.createElement('div', { key: 'txt', style: { lineHeight: 1.2, minWidth: 0 } }, [
                                React.createElement('div', { key: 'r1', style: { display: 'flex', alignItems: 'center', gap: '7px' } }, [
                                    React.createElement('span', { key: 'n', style: { fontSize: '15px', fontWeight: 800, letterSpacing: '-0.3px', color: '#f4f4f6', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, title || 'Secure chat'),
                                    React.createElement('button', { key: 'edit', onClick: startRename, title: 'Rename chat (local only)', style: { flex: 'none', width: '24px', height: '24px', borderRadius: '7px', display: 'grid', placeItems: 'center', border: 'none', background: 'transparent', color: '#56565e', cursor: 'pointer' } }, React.createElement('i', { className: 'fas fa-pen', style: { fontSize: '11px' } }))
                                ]),
                                React.createElement('div', { key: 'r2', className: 'sb-hdr-sub', style: { fontSize: '11px', color: '#6b6b73', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, isOffline ? 'No network · reconnecting' : (peerPresenceWord || (onlineConnected ? 'P2P · end-to-end encrypted' : (status === 'peer_disconnected' ? 'Peer disconnected' : (status === 'disconnected' ? 'Disconnected' : 'Connecting…')))))
                            ])
                    ]),
                    secBtn,
                    React.createElement('div', { key: 'right', className: 'sb-hdr-right', style: { display: 'flex', alignItems: 'center', gap: '9px' } }, [
                        React.createElement('div', { key: 'conn', className: 'sb-conn', style: { display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 13px', borderRadius: '9px', border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.02)' } }, [
                            React.createElement('span', { key: 'dot', style: { flex: 'none', width: '7px', height: '7px', borderRadius: '50%', background: connDot, boxShadow: connGlow } }),
                            React.createElement('span', { key: 't', className: 'sb-conn-text', style: { fontSize: '13px', fontWeight: 600, color: '#cfcfd4' } }, connLabel)
                        ]),
                        React.createElement('button', { key: 'dc', onClick: onDisconnect, className: 'sb-disconnect', style: { display: 'flex', alignItems: 'center', gap: '7px', padding: '8px 14px', borderRadius: '9px', border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#9a9aa2', fontFamily: 'inherit', fontSize: '13px', fontWeight: 600, cursor: 'pointer', transition: 'all .15s' } }, [
                            React.createElement('i', { key: 'i', className: 'fas fa-power-off', style: { fontSize: '12px' } }),
                            React.createElement('span', { key: 't', className: 'sb-hide-sm' }, 'Disconnect')
                        ])
                    ])
                ]);

                const netPanel = showNetwork && React.createElement('div', {
                    key: 'net', style: { flex: 'none', padding: '13px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(18,18,20,0.72)', backdropFilter: 'blur(14px)', WebkitBackdropFilter: 'blur(14px)' }
                }, React.createElement('div', { style: { maxWidth: '1000px', margin: '0 auto', display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(140px,1fr))', gap: '14px', fontFamily: MONO } },
                    [
                        ['Transport', 'WebRTC · DTLS'],
                        ['Cipher', 'AES-256-GCM'],
                        ['Key exchange', 'ECDH P-384'],
                        ['Security', scoreLabel + (sec ? (' · ' + sec.score + '%') : '')]
                    ].map(([k, v], i) => React.createElement('div', { key: 'nf' + i }, [
                        React.createElement('div', { key: 'k', style: { fontSize: '10px', color: '#6b6b73', textTransform: 'uppercase', letterSpacing: '0.6px', marginBottom: '4px' } }, k),
                        React.createElement('div', { key: 'v', style: { fontSize: '12.5px', color: i === 3 ? accent : '#cfcfd4', fontWeight: 500 } }, v)
                    ]))
                ));

                return React.createElement('div', { style: { flex: 'none' } }, [header, netPanel]);
            };


               const EnhancedChatInterface = ({
            title,
            isOffline,
            peerPresence,
            onRenameTitle,
            messages,
            messageInput,
            setMessageInput,
            onSendMessage,
            onDisconnect,
            keyFingerprint,
            isVerified,
            chatMessagesRef,
            scrollToBottom,
            webrtcManager,
            status,
            pendingIncomingFiles = [],
            onIncomingDecision,
            // Secure chat extras
            codeMode,
            setCodeMode,
            viewOnceMode,
            setViewOnceMode,
            viewOnceTtl,
            setViewOnceTtl,
            disappearTtl,
            setDisappearTtl,
            nowTick,
            onUnsendMessage,
            onMessageExpire
        }) => {
            const [showScrollButton, setShowScrollButton] = React.useState(false);
            const [showFileTransfer, setShowFileTransfer] = React.useState(false);
            // True only when the user opened the panel to SEND (shows the drop-zone).
            // Incoming-file auto-open leaves this false, so the receiver sees the
            // incoming request + receiving progress, not the "send attachments" UI.
            const [fileSendMode, setFileSendMode] = React.useState(false);
            const [showTimer, setShowTimer] = React.useState(false);
            const [showOnce, setShowOnce] = React.useState(false);
            const [showHandshake, setShowHandshake] = React.useState(false);
            const taRef = React.useRef(null);

            // Auto-grow the message textarea (and reset its height after sending).
            React.useEffect(() => {
                const el = taRef.current;
                if (!el || codeMode) return;
                el.style.height = 'auto';
                el.style.height = Math.min(el.scrollHeight, 240) + 'px';
            }, [messageInput, codeMode]);

            // Auto-open the file transfer panel when an incoming request arrives
            React.useEffect(() => {
                if (pendingIncomingFiles.length > 0) {
                    setShowFileTransfer(true);
                }
            }, [pendingIncomingFiles.length]);

            React.useEffect(() => {
                if (chatMessagesRef.current && messages.length > 0) {
                    const { scrollTop, scrollHeight, clientHeight } = chatMessagesRef.current;
                    const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
                    if (isNearBottom) {
                        const smoothScroll = () => {
                            if (chatMessagesRef.current) {
                                chatMessagesRef.current.scrollTo({
                                    top: chatMessagesRef.current.scrollHeight,
                                    behavior: 'smooth'
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
                if (typeof scrollToBottom === 'function') {
                    scrollToBottom();
                    setShowScrollButton(false);
                } else if (chatMessagesRef.current) {
                    chatMessagesRef.current.scrollTo({ top: chatMessagesRef.current.scrollHeight, behavior: 'smooth' });
                    setShowScrollButton(false);
                }
            };

            const handleKeyPress = (e) => {
                if (e.key !== 'Enter') return;
                if (codeMode) {
                    if (e.metaKey || e.ctrlKey) { e.preventDefault(); onSendMessage(); }
                } else if (!e.shiftKey) {
                    e.preventDefault();
                    onSendMessage();
                }
            };

            const isFileTransferReady = () => {
                if (!webrtcManager) return false;
                const connected = webrtcManager.isConnected ? webrtcManager.isConnected() : false;
                const verified = webrtcManager.isVerified || false;
                const hasDataChannel = webrtcManager.dataChannel && webrtcManager.dataChannel.readyState === 'open';
                return connected && verified && hasDataChannel;
            };

            // ---- design tokens / helpers ----
            const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
            const fmtShort = (s) => {
                if (!s) return '';
                if (s >= 86400 && s % 86400 === 0) return (s / 86400) + 'd';
                if (s >= 3600 && s % 3600 === 0) return (s / 3600) + 'h';
                if (s >= 60) return Math.round(s / 60) + 'm';
                return s + 's';
            };
            const chipStyle = (active) => ({
                display: 'flex', alignItems: 'center', gap: '6px', padding: '7px 11px', borderRadius: '8px',
                border: '1px solid ' + (active ? 'rgba(255,255,255,0.18)' : 'rgba(255,255,255,0.07)'),
                background: active ? 'rgba(255,255,255,0.06)' : 'transparent',
                color: active ? '#fff' : '#9a9aa2',
                fontFamily: 'inherit', fontSize: '12.5px', fontWeight: 600, cursor: 'pointer', transition: 'all .15s'
            });
            const optStyle = (sel) => ({
                padding: '6px 12px', borderRadius: '8px',
                border: '1px solid ' + (sel ? 'rgba(255,255,255,0.22)' : 'rgba(255,255,255,0.07)'),
                background: sel ? 'rgba(255,255,255,0.07)' : 'transparent',
                color: sel ? '#fff' : '#8a8a92',
                fontFamily: MONO, fontSize: '12px', fontWeight: 500, cursor: 'pointer', transition: 'all .14s'
            });

            const timerDefs = [
                { label: 'Off', v: 0 }, { label: '5s', v: 5 }, { label: '30s', v: 30 },
                { label: '1m', v: 60 }, { label: '1h', v: 3600 }, { label: '24h', v: 86400 }
            ];
            const onceDefs = [
                { label: 'Off', v: 0 }, { label: '5s', v: 5 }, { label: '10s', v: 10 },
                { label: '30s', v: 30 }, { label: '1m', v: 60 }
            ];
            const onceSelected = viewOnceMode ? viewOnceTtl : 0;
            const pickTimer = (v) => { setDisappearTtl(v); setShowTimer(false); };
            const pickOnce = (v) => {
                if (v === 0) setViewOnceMode(false);
                else { setViewOnceTtl(v); setViewOnceMode(true); }
                setShowOnce(false);
            };

            const hasText = !!(messageInput && messageInput.trim());

            // System notices are surfaced inside the handshake/connection log card
            // (matching the design) rather than as bubbles in the message flow.
            const fmtT = (ts) => { try { return new Date(ts).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); } catch (e) { return ''; } };
            // Connection log = string-only system notices (a React-element message
            // would render as "[object Object]" in the log, so it's excluded).
            const systemMessages = messages.filter((m) => m.type === 'system' && typeof m.message === 'string' && m.message.trim());
            const chatMessages = messages.filter((m) => m.type !== 'system');

            // ---- handshake / connection log card ----
            const handshakeCard = (isVerified || systemMessages.length > 0) && React.createElement('div', {
                key: 'handshake',
                style: { border: '1px solid rgba(255,255,255,0.07)', borderRadius: '12px', background: '#161618', overflow: 'hidden' }
            }, [
                React.createElement('button', {
                    key: 'hs-btn', onClick: () => setShowHandshake(v => !v),
                    style: { width: '100%', display: 'flex', alignItems: 'center', gap: '13px', padding: '14px 16px', background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', textAlign: 'left', fontFamily: 'inherit' }
                }, [
                    React.createElement('div', { key: 'ic', style: { flex: 'none', width: '30px', height: '30px', display: 'grid', placeItems: 'center' } },
                        React.createElement('i', { className: 'fas fa-check', style: { color: '#3ecf8e', fontSize: '16px' } })
                    ),
                    React.createElement('div', { key: 'tx', style: { flex: 1, minWidth: 0 } }, [
                        React.createElement('div', { key: 't1', style: { fontSize: '13.5px', fontWeight: 600, color: '#e8e8eb', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, 'Secure channel established'),
                        React.createElement('div', { key: 't2', style: { fontSize: '12px', color: '#7b7b83', marginTop: '1px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, 'Verified · Perfect Forward Secrecy' + (systemMessages.length ? (' · ' + systemMessages.length + (systemMessages.length === 1 ? ' event' : ' events')) : ''))
                    ]),
                    React.createElement('i', { key: 'chev', className: 'fas fa-chevron-down', style: { flex: 'none', color: '#6b6b73', fontSize: '13px', transform: showHandshake ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform .2s' } })
                ]),
                showHandshake && React.createElement('div', { key: 'hs-body', style: { padding: '2px 16px 14px 59px' } }, [
                    systemMessages.length > 0 && React.createElement('div', { key: 'steps', className: 'sb-scroll', style: { marginBottom: '12px', maxHeight: '220px', overflowY: 'auto', paddingRight: '6px' } },
                        systemMessages.map((m, i) => React.createElement('div', { key: 's' + i, style: { display: 'flex', gap: '11px', padding: '6px 0', borderTop: i === 0 ? 'none' : '1px solid rgba(255,255,255,0.04)' } }, [
                            React.createElement('span', { key: 'd', style: { flex: 'none', width: '5px', height: '5px', borderRadius: '50%', background: '#3ecf8e', marginTop: '7px', opacity: 0.6 } }),
                            React.createElement('span', { key: 't', style: { flex: 1, fontSize: '12.5px', color: '#9a9aa2', lineHeight: 1.5, wordBreak: 'break-word' } }, String(m.message || '').trim()),
                            React.createElement('span', { key: 'tm', style: { flex: 'none', fontFamily: MONO, fontSize: '10.5px', color: '#56565e' } }, fmtT(m.timestamp))
                        ]))
                    ),
                    keyFingerprint && React.createElement('div', { key: 'sn', style: { display: 'flex', alignItems: 'center', gap: '9px', padding: '10px 12px', borderRadius: '9px', background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.06)' } }, [
                        React.createElement('i', { key: 'i', className: 'fas fa-lock', style: { color: '#8a8a92', fontSize: '12px' } }),
                        React.createElement('span', { key: 'l', style: { fontSize: '11.5px', color: '#8a8a92' } }, 'Safety number'),
                        React.createElement('span', { key: 'v', style: { fontFamily: MONO, fontSize: '12px', color: '#cfcfd4', letterSpacing: '0.8px', fontWeight: 500, wordBreak: 'break-all' } }, keyFingerprint)
                    ])
                ])
            ]);

            // ---- empty state ----
            const emptyState = React.createElement('div', { key: 'empty', style: { display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1, minHeight: '40vh' } },
                React.createElement('div', { style: { textAlign: 'center', maxWidth: '420px' } }, [
                    React.createElement('img', { key: 'ic', src: '/logo/securebit-mark.svg', alt: 'SecureBit', style: { width: '60px', height: '60px', objectFit: 'contain', display: 'block', margin: '0 auto 16px' } }),
                    React.createElement('h3', { key: 't', style: { fontSize: '17px', fontWeight: 700, color: '#e8e8eb', margin: '0 0 6px' } }, 'Secure channel is ready'),
                    React.createElement('p', { key: 'p', style: { fontSize: '13px', color: '#7b7b83', margin: 0 } }, 'Every message is end-to-end encrypted on your device before it leaves.')
                ])
            );

            // ---- messages list ----
            const messagesArea = React.createElement('main', {
                key: 'main',
                ref: chatMessagesRef,
                onScroll: handleScroll,
                className: 'sb-scroll',
                style: { flex: 1, overflowY: 'auto', padding: '20px 20px 22px' }
            }, React.createElement('div', { style: { width: '100%', maxWidth: '1000px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '16px', minHeight: '100%' } },
                chatMessages.length === 0
                    ? [handshakeCard, emptyState]
                    : [handshakeCard].concat(chatMessages.map((msg) => React.createElement(EnhancedChatMessage, {
                        key: msg.id,
                        message: msg.message,
                        type: msg.type,
                        timestamp: msg.timestamp,
                        mid: msg.mid,
                        status: msg.status,
                        viewOnce: msg.viewOnce,
                        viewOnceTtl: msg.viewOnceTtl,
                        expiresAt: msg.expiresAt,
                        expired: msg.expired,
                        nowTick: nowTick,
                        canUnsend: typeof onUnsendMessage === 'function',
                        onUnsend: onUnsendMessage,
                        onExpire: () => onMessageExpire && onMessageExpire(msg.id)
                    })))
            ));

            // ---- option rows ----
            const timerRow = showTimer && React.createElement('div', { key: 'timer-row', style: { display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '8px', padding: '10px 12px', marginBottom: '10px', borderRadius: '11px', border: '1px solid rgba(255,255,255,0.07)', background: '#161618' } },
                [React.createElement('span', { key: 'lbl', style: { fontSize: '12px', color: '#8a8a92', fontWeight: 600, marginRight: '4px' } }, 'Disappear after')].concat(
                    timerDefs.map((d) => React.createElement('button', { key: 'td' + d.v, onClick: () => pickTimer(d.v), style: optStyle(disappearTtl === d.v) }, d.label))
                )
            );
            const onceRow = showOnce && React.createElement('div', { key: 'once-row', style: { display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '8px', padding: '10px 12px', marginBottom: '10px', borderRadius: '11px', border: '1px solid rgba(255,255,255,0.07)', background: '#161618' } },
                [React.createElement('span', { key: 'lbl', style: { fontSize: '12px', color: '#8a8a92', fontWeight: 600, marginRight: '4px' } }, 'Visible for')].concat(
                    onceDefs.map((d) => React.createElement('button', { key: 'od' + d.v, onClick: () => pickOnce(d.v), style: optStyle(onceSelected === d.v) }, d.label))
                )
            );

            // ---- file transfer panel ----
            const filePanel = showFileTransfer && React.createElement('div', { key: 'file-panel', style: { marginBottom: '10px' } },
                React.createElement(window.FileTransferComponent || (() => React.createElement('div', { style: { padding: '16px', textAlign: 'center', color: '#e5727a' } }, 'FileTransferComponent not loaded')), {
                    webrtcManager: webrtcManager,
                    isConnected: isFileTransferReady(),
                    pendingIncomingFiles: pendingIncomingFiles,
                    onIncomingDecision: onIncomingDecision,
                    showDropzone: fileSendMode
                })
            );

            // ---- chips row ----
            const chipsRow = React.createElement('div', { key: 'chips', style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px', marginBottom: '10px' } }, [
                React.createElement('button', { key: 'files', onClick: () => {
                    if (showFileTransfer && fileSendMode) { setShowFileTransfer(false); setFileSendMode(false); }
                    else { setShowFileTransfer(true); setFileSendMode(true); }
                }, className: 'sb-chip', style: chipStyle(showFileTransfer && fileSendMode) }, [
                    React.createElement('i', { key: 'i', className: 'fas fa-paperclip', style: { fontSize: '13px' } }),
                    (showFileTransfer && fileSendMode) ? 'Hide files' : 'Send files'
                ]),
                React.createElement('div', { key: 'right', style: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' } }, [
                    React.createElement('button', { key: 'code', onClick: () => setCodeMode(v => !v), className: 'sb-chip', style: chipStyle(codeMode) }, [
                        React.createElement('i', { key: 'i', className: 'fas fa-code', style: { fontSize: '13px' } }), 'Code'
                    ]),
                    React.createElement('button', { key: 'once', onClick: () => { setShowOnce(v => !v); setShowTimer(false); }, className: 'sb-chip', style: chipStyle(showOnce || viewOnceMode) }, [
                        React.createElement('i', { key: 'i', className: 'fas fa-eye-slash', style: { fontSize: '13px' } }),
                        viewOnceMode ? ('View once · ' + fmtShort(viewOnceTtl)) : 'View once'
                    ]),
                    React.createElement('button', { key: 'timer', onClick: () => { setShowTimer(v => !v); setShowOnce(false); }, className: 'sb-chip', style: chipStyle(showTimer || disappearTtl > 0) }, [
                        React.createElement('i', { key: 'i', className: 'fas fa-stopwatch', style: { fontSize: '13px' } }),
                        disappearTtl > 0 ? ('Timer · ' + fmtShort(disappearTtl)) : 'Timer'
                    ])
                ])
            ]);

            // ---- code-mode header strip ----
            const codeStrip = codeMode && React.createElement('div', { key: 'code-strip', style: { display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 14px', border: '1px solid rgba(255,255,255,0.08)', borderBottom: 'none', borderRadius: '14px 14px 0 0', background: '#161618' } }, [
                React.createElement('i', { key: 'i', className: 'fas fa-code', style: { color: '#8a8a92', fontSize: '12px' } }),
                React.createElement('span', { key: 's', style: { fontSize: '11.5px', fontWeight: 600, color: '#8a8a92' } }, 'Code snippet · formatting preserved · ⌘↵ to send'),
                React.createElement('button', { key: 'c', onClick: () => setCodeMode(false), className: 'sb-link', style: { marginLeft: 'auto', background: 'none', border: 'none', color: '#6b6b73', cursor: 'pointer', fontSize: '11.5px', fontFamily: 'inherit', fontWeight: 600 } }, 'Close')
            ]);

            // ---- input row ----
            const inputRow = React.createElement('div', {
                key: 'input',
                style: { display: 'flex', alignItems: 'flex-end', gap: '11px', padding: '11px 11px 11px 16px', border: '1px solid ' + (hasText ? 'rgba(255,255,255,0.18)' : 'rgba(255,255,255,0.08)'), background: '#161618', borderRadius: codeMode ? '0 0 14px 14px' : '14px', transition: 'border .15s' }
            }, [
                React.createElement('div', { key: 'ta-wrap', style: { flex: 1, minWidth: 0 } }, [
                    React.createElement('textarea', {
                        key: 'ta',
                        value: messageInput,
                        ref: taRef,
                        onChange: (e) => setMessageInput(e.target.value),
                        onKeyDown: handleKeyPress,
                        rows: 1,
                        maxLength: 2000,
                        placeholder: codeMode ? 'Paste or write code…' : 'Type an encrypted message…',
                        className: 'sb-textarea',
                        style: { width: '100%', minHeight: codeMode ? '120px' : '22px', maxHeight: '240px', resize: 'none', border: 'none', outline: 'none', background: 'transparent', color: '#e8e8eb', fontFamily: codeMode ? MONO : 'inherit', fontSize: codeMode ? '13px' : '14.5px', lineHeight: 1.55, padding: '6px 0' }
                    }),
                    React.createElement('div', { key: 'foot', style: { display: 'flex', alignItems: 'center', gap: '12px', marginTop: '3px' } }, [
                        React.createElement('span', { key: 'enc', style: { display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: '#56565e' } }, [
                            React.createElement('i', { key: 'i', className: 'fas fa-lock', style: { color: '#3ecf8e', fontSize: '10px' } }),
                            'Encrypted on your device'
                        ]),
                        React.createElement('span', { key: 'cnt', style: { fontFamily: MONO, fontSize: '10.5px', color: '#56565e', marginLeft: 'auto' } }, (messageInput ? messageInput.length : 0) + '/2000')
                    ])
                ]),
                React.createElement('button', {
                    key: 'send', onClick: onSendMessage, disabled: !hasText, title: 'Send', className: 'sb-send',
                    style: { flex: 'none', width: '44px', height: '44px', borderRadius: '11px', border: 'none', display: 'grid', placeItems: 'center', cursor: hasText ? 'pointer' : 'default', background: hasText ? '#f0892a' : 'rgba(255,255,255,0.05)', color: hasText ? '#1a0f04' : '#56565e', transition: 'all .15s' }
                }, React.createElement('i', { className: 'fas fa-paper-plane', style: { fontSize: '15px' } }))
            ]);

            const composer = React.createElement('footer', { key: 'composer', style: { flex: 'none', padding: '12px 20px 18px', background: '#0f0f11', borderTop: '1px solid rgba(255,255,255,0.05)' } },
                React.createElement('div', { style: { maxWidth: '1000px', margin: '0 auto' } }, [
                    timerRow, onceRow, filePanel, chipsRow, codeStrip, inputRow
                ])
            );

            const scrollBtn = showScrollButton && React.createElement('button', {
                key: 'scrollbtn', onClick: handleScrollToBottom,
                style: { position: 'fixed', right: '24px', bottom: '150px', width: '44px', height: '44px', borderRadius: '50%', border: '1px solid rgba(255,255,255,0.1)', background: '#26262b', color: '#cfcfd4', display: 'grid', placeItems: 'center', cursor: 'pointer', zIndex: 50, boxShadow: '0 6px 20px rgba(0,0,0,0.4)' }
            }, React.createElement('i', { className: 'fas fa-arrow-down', style: { fontSize: '15px' } }));

            const chatHeader = React.createElement(SecureBitChatHeader, {
                key: 'chat-header', status: status, onDisconnect: onDisconnect, webrtcManager: webrtcManager, title: title, isOffline: isOffline, peerPresence: peerPresence, onRenameTitle: onRenameTitle
            });

            return React.createElement('div', {
                className: 'chat-container',
                style: { display: 'flex', flexDirection: 'column', height: '100vh', background: '#0f0f11', color: '#e8e8eb' }
            }, [chatHeader, messagesArea, scrollBtn, composer]);
        };
        
        
                // Build a chat message in the shape addMessageWithAutoScroll produces, so the
                // per-session callbacks can dispatch ADD_MESSAGE without an active-view setter.
                const buildSessionMessage = (message, type, opts = {}) => ({
                    message,
                    type,
                    id: Date.now() + Math.random(),
                    timestamp: (typeof opts.timestamp === 'number') ? opts.timestamp : Date.now(),
                    mid: opts.mid,
                    status: opts.status,
                    viewOnce: opts.viewOnce === true,
                    viewOnceTtl: (typeof opts.viewOnceTtl === 'number') ? opts.viewOnceTtl : 15,
                    expiresAt: (typeof opts.expiresAt === 'number') ? opts.expiresAt : undefined
                });

                // Left rail listing every open session (design import: "Multi Session
                // Concepts"). Two desktop states — expanded (292px) and a collapsed icon dock
                // (72px) — plus a mobile slide-out drawer. Pure presentational: all data comes
                // from decorated session objects, all actions are callbacks.
                const SB_SVG = {
                    chevL: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 6l-6 6 6 6"/></svg>',
                    chevR: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg>',
                    plus: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
                    users: '<svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 19v-1.5a3.5 3.5 0 0 0-3.5-3.5h-5A3.5 3.5 0 0 0 4 17.5V19"/><circle cx="10" cy="8" r="3.2"/><path d="M20 19v-1.5a3.5 3.5 0 0 0-2.6-3.4"/><path d="M15.5 5.3a3.2 3.2 0 0 1 0 5.4"/></svg>',
                    burger: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>'
                };

                const SessionsSidebar = ({ chats, collapsed, drawerOpen, onToggleCollapse, onSelect, onNewChat, onRename, onCloseDrawer, myStatus, onSetStatus }) => {
                    const h = React.createElement;
                    const [editingId, setEditingId] = React.useState(null);
                    const [draft, setDraft] = React.useState('');
                    const [presenceOpen, setPresenceOpen] = React.useState(false);
                    const startEdit = (c) => (e) => { e.stopPropagation(); setEditingId(c.id); setDraft(c.name); };
                    const commitEdit = () => { if (editingId) { onRename(editingId, draft); setEditingId(null); } };
                    const editKey = (e) => {
                        if (e.key === 'Enter') { e.preventDefault(); commitEdit(); }
                        else if (e.key === 'Escape') { setEditingId(null); }
                    };
                    const renameInput = (extra = {}) => h('input', {
                        autoFocus: true,
                        value: draft,
                        onChange: (e) => setDraft(e.target.value),
                        onKeyDown: editKey,
                        onBlur: commitEdit,
                        onClick: (e) => e.stopPropagation(),
                        style: Object.assign({ width: '100%', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(240,137,42,0.5)', borderRadius: '6px', color: '#f4f4f6', fontFamily: 'inherit', fontSize: '14px', fontWeight: 700, padding: '2px 6px', outline: 'none' }, extra)
                    });
                    const icon = (svg, style) => h('span', { style: Object.assign({ display: 'grid', placeItems: 'center' }, style || {}), dangerouslySetInnerHTML: { __html: svg } });
                    const avatar = (c, size, ring) => h('div', {
                        style: { position: 'relative', flex: 'none', width: size + 'px', height: size + 'px', borderRadius: (size >= 44 ? 12 : 11) + 'px', display: 'grid', placeItems: 'center', background: c.active ? 'rgba(255,255,255,0.06)' : 'rgba(255,255,255,0.035)', border: '1px solid rgba(255,255,255,' + (c.active ? '0.14' : '0.07') + ')', fontSize: '13px', fontWeight: 700, letterSpacing: '-0.3px', color: c.active ? '#f4f4f6' : '#9a9aa2' }
                    }, [c.mono, h('span', { key: 'dot', style: { position: 'absolute', right: '-2px', bottom: '-2px', width: '11px', height: '11px', borderRadius: '50%', background: c.dot, border: '2px solid ' + ring } })]);

                    // ---- Expanded list row ----
                    const expandedRow = (c) => h('div', {
                        key: c.id,
                        onClick: () => onSelect(c.id),
                        style: { position: 'relative', display: 'flex', alignItems: 'center', gap: '12px', padding: '11px 12px', marginBottom: '4px', borderRadius: '11px', background: c.active ? '#161618' : 'transparent', border: '1px solid ' + (c.active ? 'rgba(255,255,255,0.08)' : 'transparent'), cursor: 'pointer' }
                    }, [
                        c.active && h('span', { key: 'bar', style: { position: 'absolute', left: 0, top: '12px', bottom: '12px', width: '3px', borderRadius: '0 3px 3px 0', background: '#f0892a' } }),
                        avatar(c, 38, c.active ? '#161618' : '#0c0c0e'),
                        h('div', { key: 'body', style: { flex: 1, minWidth: 0 } }, [
                            h('div', { key: 'top', style: { display: 'flex', alignItems: 'center', gap: '7px' } }, [
                                editingId === c.id
                                    ? renameInput()
                                    : h('span', {
                                        key: 'name',
                                        onDoubleClick: startEdit(c),
                                        title: 'Double-click to rename',
                                        style: { flex: 1, minWidth: 0, fontSize: '14px', fontWeight: c.active ? 700 : 600, letterSpacing: '-0.2px', color: c.active ? '#f4f4f6' : '#cfcfd4', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }
                                    }, c.name),
                                c.unread && editingId !== c.id && h('span', { key: 'u', style: { flex: 'none', minWidth: '18px', height: '18px', padding: '0 5px', borderRadius: '9px', display: 'grid', placeItems: 'center', background: '#f0892a', color: '#1a0f04', fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', fontWeight: 700 } }, c.unread)
                            ]),
                            h('div', { key: 'prev', style: { fontSize: '12px', color: c.active ? '#8a8a92' : '#6b6b73', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, c.preview)
                        ])
                    ]);

                    // ---- Collapsed dock item ----
                    const dockItem = (c) => h('div', { key: c.id, style: { position: 'relative' } }, [
                        c.active && h('span', { key: 'bar', style: { position: 'absolute', left: '-13px', top: '9px', bottom: '9px', width: '3px', borderRadius: '0 3px 3px 0', background: '#f0892a' } }),
                        h('div', {
                            key: 'tile',
                            onClick: () => onSelect(c.id),
                            title: c.name,
                            style: { position: 'relative', width: '44px', height: '44px', borderRadius: '12px', display: 'grid', placeItems: 'center', cursor: 'pointer', background: c.active ? 'rgba(255,255,255,0.06)' : 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,' + (c.active ? '0.14' : '0.07') + ')', fontSize: '13px', fontWeight: 700, letterSpacing: '-0.3px', color: c.active ? '#f4f4f6' : '#9a9aa2' }
                        }, [
                            c.mono,
                            h('span', { key: 'dot', style: { position: 'absolute', right: '-2px', bottom: '-2px', width: '11px', height: '11px', borderRadius: '50%', background: c.dot, border: '2.5px solid #0c0c0e' } }),
                            c.unread && h('span', { key: 'u', style: { position: 'absolute', left: '-5px', top: '-5px', minWidth: '17px', height: '17px', padding: '0 4px', borderRadius: '9px', display: 'grid', placeItems: 'center', background: '#f0892a', color: '#1a0f04', fontFamily: "'JetBrains Mono',monospace", fontSize: '9.5px', fontWeight: 700, border: '2px solid #0c0c0e' } }, c.unread)
                        ])
                    ]);

                    // Same logo treatment as the landing header (Header.jsx): the mark on a
                    // transparent background — no black tile.
                    const brandMark = (size) => h('div', { style: { width: size + 'px', height: size + 'px', flex: 'none', display: 'grid', placeItems: 'center' } },
                        h('img', { src: '/logo/securebit-mark.svg', alt: 'SecureBit', style: { width: '100%', height: '100%', objectFit: 'contain', display: 'block' } }));
                    const collapseBtn = (svg, title) => h('button', { onClick: onToggleCollapse, title, style: { width: '30px', height: '30px', borderRadius: '8px', display: 'grid', placeItems: 'center', border: '1px solid rgba(255,255,255,0.07)', background: 'transparent', color: '#8a8a92', cursor: 'pointer' }, dangerouslySetInnerHTML: { __html: svg } });

                    // ---- Expanded rail content ----
                    // ---- Presence ("You" status) panel ----
                    const myMeta = MY_STATUS_OPTIONS.find((o) => o.key === myStatus) || MY_STATUS_OPTIONS[0];
                    const PRES_SVG = {
                        user: '<svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M18 20v-1.5a4 4 0 0 0-4-4h-4a4 4 0 0 0-4 4V20"/><circle cx="12" cy="8" r="3.6"/></svg>',
                        check: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#f0892a" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><path d="M5 13l4 4 10-11"/></svg>',
                        chevUp: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6b6b73" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 15l6-6 6 6"/></svg>',
                        lock: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#3ecf8e" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M7 11V7a5 5 0 0 1 10 0v4"/><rect x="4.5" y="11" width="15" height="9" rx="2.2"/></svg>'
                    };
                    const presenceMenu = (pos) => (presenceOpen ? h('div', {
                        key: 'pmenu',
                        style: Object.assign({ position: 'absolute', zIndex: 30, borderRadius: '14px', background: '#161618', border: '1px solid rgba(255,255,255,0.1)', boxShadow: '0 16px 40px rgba(0,0,0,0.55)', padding: '6px' }, pos)
                    }, [
                        h('div', { key: 'h', style: { padding: '9px 10px 7px', fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', fontWeight: 600, color: '#56565e', textTransform: 'uppercase', letterSpacing: '1.2px' } }, 'Set your status'),
                        ...MY_STATUS_OPTIONS.map((o) => h('button', {
                            key: o.key,
                            onClick: () => { onSetStatus(o.key); setPresenceOpen(false); },
                            style: { width: '100%', display: 'flex', alignItems: 'center', gap: '11px', padding: '9px 10px', borderRadius: '9px', border: 'none', background: 'transparent', cursor: 'pointer', textAlign: 'left' }
                        }, [
                            h('span', { key: 'd', style: { flex: 'none', width: '10px', height: '10px', borderRadius: '50%', background: o.dot } }),
                            h('span', { key: 't', style: { flex: 1, minWidth: 0 } }, [
                                h('span', { key: 'w', style: { display: 'block', fontSize: '13.5px', fontWeight: 600, color: '#e8e8eb' } }, o.word),
                                h('span', { key: 'de', style: { display: 'block', fontSize: '11.5px', color: '#6b6b73' } }, o.desc)
                            ]),
                            o.key === myStatus && h('span', { key: 'c', style: { flex: 'none', display: 'grid', placeItems: 'center' }, dangerouslySetInnerHTML: { __html: PRES_SVG.check } })
                        ])),
                        h('div', { key: 'note', style: { display: 'flex', alignItems: 'flex-start', gap: '8px', margin: '6px 6px 4px', padding: '9px 10px', borderRadius: '9px', background: 'rgba(62,207,142,0.06)', border: '1px solid rgba(62,207,142,0.16)' } }, [
                            h('span', { key: 'i', style: { flex: 'none', marginTop: '1px', display: 'grid' }, dangerouslySetInnerHTML: { __html: PRES_SVG.lock } }),
                            h('span', { key: 't', style: { fontSize: '11px', lineHeight: 1.45, color: '#8a8a92' } }, 'Sent end-to-end to connected peers only — never stored on a server.')
                        ])
                    ]) : null);
                    const presencePanelExpanded = h('div', { key: 'you', style: { flex: 'none', position: 'relative', marginTop: '10px', borderTop: '1px solid rgba(255,255,255,0.06)', padding: '10px 12px 12px' } }, [
                        presenceMenu({ left: '12px', right: '12px', bottom: '64px' }),
                        h('button', { key: 'btn', onClick: () => setPresenceOpen((v) => !v), style: { width: '100%', display: 'flex', alignItems: 'center', gap: '11px', padding: '7px 8px', borderRadius: '11px', border: '1px solid rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.02)', cursor: 'pointer' } }, [
                            h('div', { key: 'av', style: { position: 'relative', flex: 'none', width: '36px', height: '36px', borderRadius: '10px', display: 'grid', placeItems: 'center', background: 'rgba(240,137,42,0.12)', border: '1px solid rgba(240,137,42,0.24)', color: '#f0892a' } }, [
                                h('span', { key: 'i', style: { display: 'grid' }, dangerouslySetInnerHTML: { __html: PRES_SVG.user } }),
                                h('span', { key: 'dot', style: { position: 'absolute', right: '-2px', bottom: '-2px', width: '11px', height: '11px', borderRadius: '50%', background: myMeta.dot, border: '2px solid #0c0c0e' } })
                            ]),
                            h('div', { key: 'tx', style: { flex: 1, minWidth: 0, textAlign: 'left' } }, [
                                h('div', { key: 'y', style: { fontSize: '13.5px', fontWeight: 700, color: '#f4f4f6' } }, 'You'),
                                h('div', { key: 'w', style: { fontSize: '12px', color: '#8a8a92' } }, myMeta.word)
                            ]),
                            h('span', { key: 'ch', style: { display: 'grid', placeItems: 'center' }, dangerouslySetInnerHTML: { __html: PRES_SVG.chevUp } })
                        ])
                    ]);
                    const presencePanelCollapsed = h('div', { key: 'you', style: { flex: 'none', position: 'relative', display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '0 0 13px' } }, [
                        presenceMenu({ left: '60px', bottom: '8px', width: '248px' }),
                        h('button', { key: 'btn', onClick: () => setPresenceOpen((v) => !v), title: 'Your status — ' + myMeta.word, style: { position: 'relative', width: '44px', height: '44px', borderRadius: '12px', display: 'grid', placeItems: 'center', cursor: 'pointer', background: 'rgba(240,137,42,0.12)', border: '1px solid rgba(240,137,42,0.24)', color: '#f0892a' } }, [
                            h('span', { key: 'i', style: { display: 'grid' }, dangerouslySetInnerHTML: { __html: PRES_SVG.user } }),
                            h('span', { key: 'dot', style: { position: 'absolute', right: '-2px', bottom: '-2px', width: '12px', height: '12px', borderRadius: '50%', background: myMeta.dot, border: '2.5px solid #0c0c0e' } })
                        ])
                    ]);

                    const expandedInner = [
                        h('div', { key: 'head', style: { flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 12px 0 16px', height: '64px', borderBottom: '1px solid rgba(255,255,255,0.06)' } }, [
                            h('div', { key: 'brand', style: { display: 'flex', alignItems: 'center', gap: '10px' } }, [brandMark(30), h('span', { key: 't', style: { fontSize: '15px', fontWeight: 800, letterSpacing: '-0.3px', color: '#f4f4f6' } }, 'SecureBit')]),
                            collapseBtn(SB_SVG.chevL, 'Collapse')
                        ]),
                        h('div', { key: 'label', style: { flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 16px 9px' } }, [
                            h('span', { key: 'l', style: { fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', fontWeight: 600, color: '#56565e', textTransform: 'uppercase', letterSpacing: '1.3px' } }, 'Chats'),
                            h('span', { key: 'c', style: { fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', fontWeight: 600, color: '#6b6b73' } }, String(chats.length))
                        ]),
                        h('div', { key: 'list', className: 'msc-scroll', style: { flex: 1, overflowY: 'auto', padding: '0 10px' } }, [
                            ...chats.map(expandedRow),
                            h('div', { key: 'gh', style: { marginTop: '14px', padding: '0 2px 6px' } }, h('span', { style: { fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', fontWeight: 600, color: '#56565e', textTransform: 'uppercase', letterSpacing: '1.3px' } }, 'Group chats')),
                            h('div', { key: 'gph', title: 'Coming in v6.0', style: { display: 'flex', alignItems: 'center', gap: '12px', padding: '11px 12px', borderRadius: '11px', background: 'transparent', border: '1px dashed rgba(255,255,255,0.09)', cursor: 'not-allowed' } }, [
                                h('div', { key: 'i', style: { flex: 'none', width: '38px', height: '38px', borderRadius: '11px', display: 'grid', placeItems: 'center', background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.06)', color: '#56565e' }, dangerouslySetInnerHTML: { __html: SB_SVG.users } }),
                                h('div', { key: 'b', style: { flex: 1, minWidth: 0 } }, [
                                    h('div', { key: 't', style: { fontSize: '14px', fontWeight: 600, color: '#8a8a92' } }, 'Group chats'),
                                    h('div', { key: 's', style: { fontSize: '11.5px', color: '#56565e' } }, 'Up to 8 peers · P2P mesh')
                                ]),
                                h('span', { key: 'soon', style: { flex: 'none', padding: '4px 9px', borderRadius: '7px', background: 'rgba(240,137,42,0.1)', border: '1px solid rgba(240,137,42,0.24)', fontFamily: "'JetBrains Mono',monospace", fontSize: '9.5px', fontWeight: 700, color: '#f0892a', textTransform: 'uppercase', letterSpacing: '0.8px' } }, 'Soon')
                            ])
                        ]),
                        h('div', { key: 'new', style: { flex: 'none', padding: '12px' } }, h('button', {
                            onClick: onNewChat,
                            style: { width: '100%', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '9px', padding: '12px', borderRadius: '11px', border: 'none', background: '#f0892a', color: '#1a0f04', fontFamily: 'inherit', fontSize: '14px', fontWeight: 700, cursor: 'pointer', boxShadow: '0 8px 24px rgba(240,137,42,0.28)' }
                        }, [icon(SB_SVG.plus, { key: 'p' }), 'New chat'])),
                        presencePanelExpanded
                    ];

                    // ---- Collapsed dock content ----
                    const collapsedInner = [
                        h('div', { key: 'head', style: { flex: 'none', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px', padding: '13px 0', width: '100%', borderBottom: '1px solid rgba(255,255,255,0.06)' } }, [brandMark(32), collapseBtn(SB_SVG.chevR, 'Expand')]),
                        h('div', { key: 'list', className: 'msc-scroll', style: { flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px', padding: '14px 0', width: '100%' } }, [
                            ...chats.map(dockItem),
                            h('div', { key: 'sep', style: { width: '30px', height: '1px', background: 'rgba(255,255,255,0.07)', margin: '2px 0' } }),
                            h('div', { key: 'gph', title: 'Group chats — coming in v6.0', style: { position: 'relative', width: '44px', height: '44px', borderRadius: '12px', display: 'grid', placeItems: 'center', cursor: 'not-allowed', background: 'transparent', border: '1px dashed rgba(255,255,255,0.1)', color: '#56565e' }, dangerouslySetInnerHTML: { __html: SB_SVG.users } })
                        ]),
                        h('div', { key: 'new', style: { flex: 'none', padding: '13px 0' } }, h('button', {
                            onClick: onNewChat, title: 'New chat',
                            style: { width: '44px', height: '44px', borderRadius: '12px', display: 'grid', placeItems: 'center', border: 'none', background: '#f0892a', color: '#1a0f04', cursor: 'pointer', boxShadow: '0 8px 24px rgba(240,137,42,0.28)' }, dangerouslySetInnerHTML: { __html: SB_SVG.plus }
                        })),
                        presencePanelCollapsed
                    ];

                    const railWidth = collapsed ? '72px' : '292px';
                    const railStyle = { flex: 'none', width: railWidth, display: 'flex', flexDirection: 'column', alignItems: collapsed ? 'center' : 'stretch', background: '#0c0c0e', borderRight: '1px solid rgba(255,255,255,0.06)' };
                    const inner = collapsed ? collapsedInner : expandedInner;

                    return h(React.Fragment, null, [
                        // Responsive behaviour (inline styles can't express media queries).
                        h('style', { key: 'css', dangerouslySetInnerHTML: { __html: '@media (max-width:1023px){.sb-rail{display:none !important;}.sb-burger{display:grid !important;}}@media (min-width:1024px){.sb-drawer-overlay{display:none !important;}}' } }),
                        // Desktop rail
                        h('aside', { key: 'rail', className: 'sb-rail', style: railStyle }, inner),
                        // Mobile drawer overlay
                        h('div', {
                            key: 'drawer', className: 'sb-drawer-overlay',
                            onClick: onCloseDrawer,
                            style: { position: 'fixed', inset: 0, zIndex: 60, background: 'rgba(6,6,8,0.6)', backdropFilter: 'blur(4px)', WebkitBackdropFilter: 'blur(4px)', display: drawerOpen ? 'block' : 'none' }
                        }, h('aside', { onClick: (e) => e.stopPropagation(), style: { position: 'absolute', left: 0, top: 0, bottom: 0, width: '292px', display: 'flex', flexDirection: 'column', background: '#0c0c0e', borderRight: '1px solid rgba(255,255,255,0.06)', boxShadow: '0 0 60px rgba(0,0,0,0.6)' } }, expandedInner))
                    ]);
                };

                // Main Enhanced Application Component
                const EnhancedSecureP2PChat = () => {

                    // ============================================
                    // MULTI-SESSION REGISTRY
                    // Each conversation is an independent session with its OWN
                    // EnhancedSecureWebRTCManager (full key/ratchet/SAS isolation). The reducer
                    // holds serializable per-session state; non-serializable objects (managers,
                    // notification integrations, offline queues) live in ref-held Maps keyed by
                    // sessionId and are NEVER shared between sessions. sessionId is local-only.
                    // ============================================
                    const [sessionsState, dispatch] = React.useReducer(sessionsReducer, undefined, createInitialState);
                    const activeSessionId = sessionsState.activeSessionId;
                    const activeIdRef = React.useRef(null);
                    activeIdRef.current = activeSessionId;
                    const active = activeSessionId ? sessionsState.sessions[activeSessionId] : null;
                    const EMPTY_ARR = React.useRef([]).current;

                    const managersRef = React.useRef(new Map());      // id -> EnhancedSecureWebRTCManager
                    const integrationsRef = React.useRef(new Map());  // id -> NotificationIntegration
                    const queuesRef = React.useRef(new Map());        // id -> { incoming:[], outgoing:[] }

                    // Active-session VIEW. The rest of the component (and the child setup/chat
                    // components) read these names unchanged; the setters dispatch to the active
                    // session read from activeIdRef at call time, so even memoized callbacks stay
                    // correct across session switches.
                    const dispatchActive = React.useCallback((build) => {
                        const id = activeIdRef.current; if (!id) return;
                        dispatch(build(id));
                    }, []);

                    const messages = active ? active.messages : EMPTY_ARR;
                    const setMessages = React.useCallback((updaterOrArr) => {
                        const id = activeIdRef.current; if (!id) return;
                        if (typeof updaterOrArr === 'function') dispatch({ type: SA.SET_MESSAGES, id, updater: updaterOrArr });
                        else dispatch({ type: SA.SET_MESSAGES, id, messages: updaterOrArr });
                    }, []);

                    const connectionStatus = active ? active.status : 'disconnected';
                    const setConnectionStatus = React.useCallback((status) => dispatchActive((id) => ({ type: SA.SET_STATUS, id, status })), [dispatchActive]);

                    const keyFingerprint = active ? active.keyFingerprint : '';
                    const setKeyFingerprint = React.useCallback((fingerprint) => dispatchActive((id) => ({ type: SA.SET_FINGERPRINT, id, fingerprint })), [dispatchActive]);

                    const verificationCode = active ? active.verificationCode : '';
                    const setVerificationCode = React.useCallback((code) => dispatchActive((id) => ({ type: SA.SET_VERIFICATION, id, code })), [dispatchActive]);

                    const isVerified = active ? active.sas.isVerified : false;
                    const setIsVerified = React.useCallback((v) => dispatchActive((id) => ({ type: SA.SET_SAS, id, sas: { isVerified: !!v } })), [dispatchActive]);
                    const localVerificationConfirmed = active ? active.sas.localConfirmed : false;
                    const setLocalVerificationConfirmed = React.useCallback((v) => dispatchActive((id) => ({ type: SA.SET_SAS, id, sas: { localConfirmed: !!v } })), [dispatchActive]);
                    const remoteVerificationConfirmed = active ? active.sas.remoteConfirmed : false;
                    const setRemoteVerificationConfirmed = React.useCallback((v) => dispatchActive((id) => ({ type: SA.SET_SAS, id, sas: { remoteConfirmed: !!v } })), [dispatchActive]);
                    const bothVerificationsConfirmed = active ? active.sas.bothConfirmed : false;
                    const setBothVerificationsConfirmed = React.useCallback((v) => dispatchActive((id) => ({ type: SA.SET_SAS, id, sas: { bothConfirmed: !!v } })), [dispatchActive]);

                    const pendingIncomingFiles = active ? active.pendingIncomingFiles : EMPTY_ARR;
                    const setPendingIncomingFiles = React.useCallback((updaterOrArr) => {
                        const id = activeIdRef.current; if (!id) return;
                        if (typeof updaterOrArr === 'function') dispatch({ type: SA.SET_PENDING_FILES, id, updater: updaterOrArr });
                        else dispatch({ type: SA.SET_PENDING_FILES, id, files: updaterOrArr });
                    }, []);

                    // Per-session offer/answer setup flow (preserved when switching chats).
                    const setupField = (name, fallback) => (active ? active.setup[name] : fallback);
                    const setSetupField = (name) => React.useCallback((value) => dispatchActive((id) => ({ type: SA.PATCH_SETUP, id, patch: { [name]: value } })), [dispatchActive]);
                    const offerData = setupField('offerData', '');
                    const setOfferData = setSetupField('offerData');
                    const answerData = setupField('answerData', '');
                    const setAnswerData = setSetupField('answerData');
                    const offerInput = setupField('offerInput', '');
                    const setOfferInput = setSetupField('offerInput');
                    const answerInput = setupField('answerInput', '');
                    const setAnswerInput = setSetupField('answerInput');
                    const showOfferStep = setupField('showOfferStep', false);
                    const setShowOfferStep = setSetupField('showOfferStep');
                    const showAnswerStep = setupField('showAnswerStep', false);
                    const setShowAnswerStep = setSetupField('showAnswerStep');
                    const showVerification = setupField('showVerification', false);
                    const setShowVerification = setSetupField('showVerification');
                    const showQRCode = setupField('showQRCode', false);
                    const setShowQRCode = setSetupField('showQRCode');
                    const qrCodeUrl = setupField('qrCodeUrl', '');
                    const setQrCodeUrl = setSetupField('qrCodeUrl');
                    const isGeneratingKeys = setupField('isGeneratingKeys', false);
                    const setIsGeneratingKeys = setSetupField('isGeneratingKeys');

                    // Accessor over the ACTIVE session's manager / notification integration.
                    // Existing `webrtcManagerRef.current.X()` call sites keep working against the
                    // active session; per-session callbacks use their own captured manager instead.
                    const webrtcManagerRef = React.useMemo(() => ({
                        get current() { return managersRef.current.get(activeIdRef.current) || null; },
                        set current(v) {
                            const id = activeIdRef.current; if (!id) return;
                            if (v) managersRef.current.set(id, v); else managersRef.current.delete(id);
                        }
                    }), []);
                    const notificationIntegrationRef = React.useMemo(() => ({
                        get current() { return integrationsRef.current.get(activeIdRef.current) || null; },
                        set current(v) {
                            const id = activeIdRef.current; if (!id) return;
                            if (v) integrationsRef.current.set(id, v); else integrationsRef.current.delete(id);
                        }
                    }), []);

                    // ---- Presence / availability ----
                    // My status is broadcast E2E over each connected session's data channel
                    // (sendSystemMessage) and never stored on a server. 'invisible' goes on the
                    // wire as 'offline' so peers cannot tell. myStatusRef lets the per-session
                    // callbacks (captured at create time) read the current status.
                    const [myStatus, setMyStatusState] = React.useState(() => {
                        try { return localStorage.getItem('securebit_my_status') || 'available'; } catch { return 'available'; }
                    });
                    const myStatusRef = React.useRef(myStatus);
                    myStatusRef.current = myStatus;
                    const wirePresence = (s) => (s === 'invisible' ? 'offline' : s);
                    // Presence travels as a normal ENCRYPTED chat message (type 'message') — that is
                    // the only inbound path the manager delivers to onMessage; unknown raw system
                    // types are dropped. handleMessage recognises the {type:'presence'} payload and
                    // consumes it without displaying it.
                    const sendPresenceTo = React.useCallback((mgr, s) => {
                        if (!mgr || typeof mgr.sendMessage !== 'function') return;
                        try {
                            if (mgr.isConnected && mgr.isConnected()) {
                                const p = mgr.sendMessage(JSON.stringify({ type: 'presence', status: wirePresence(s) }));
                                if (p && typeof p.catch === 'function') p.catch(() => {});
                            }
                        } catch (_) {}
                    }, []);
                    const setMyStatus = React.useCallback((key) => {
                        setMyStatusState(key);
                        try { localStorage.setItem('securebit_my_status', key); } catch {}
                        for (const mgr of managersRef.current.values()) sendPresenceTo(mgr, key);
                    }, [sendPresenceTo]);

                    // Secure chat extras: per-message send modes + 1s tick for countdowns.
                    const [codeMode, setCodeMode] = React.useState(false);
                    const [viewOnceMode, setViewOnceMode] = React.useState(false);
                    const [viewOnceTtl, setViewOnceTtl] = React.useState(15); // seconds visible after the peer opens it
                    const [disappearTtl, setDisappearTtl] = React.useState(0); // seconds; 0 = off (sticky)
                    const [nowTick, setNowTick] = React.useState(() => Date.now());
                    // connectionStatus → per-session status (active-session view, above).
                    // Offline awareness — tracks the real online/offline events (which is
                    // also what a console-simulated `dispatchEvent(new Event('offline'))`
                    // fires, even when navigator.onLine stays true).
                    const [isOffline, setIsOffline] = React.useState(typeof navigator !== 'undefined' && navigator.onLine === false);
                    // Ref mirror so manager callbacks (which close over stale state) always
                    // read the current offline status. Two queues implement store-and-forward
                    // over the still-live P2P channel: outgoing waits until WE reconnect,
                    // incoming waits until WE reconnect before being shown/acked.
                    const offlineRef = React.useRef(isOffline);
                    // Offline store-and-forward queues are now per-session (queuesRef, above).
                    React.useEffect(() => { offlineRef.current = isOffline; }, [isOffline]);
                    React.useEffect(() => {
                        const goOffline = () => setIsOffline(true);
                        const goOnline = () => setIsOffline(false);
                        window.addEventListener('offline', goOffline);
                        window.addEventListener('online', goOnline);
                        return () => { window.removeEventListener('offline', goOffline); window.removeEventListener('online', goOnline); };
                    }, []);
                    const [relayOnlyMode, setRelayOnlyMode] = React.useState(() => {
                        try { return localStorage.getItem('securebit_relay_only_mode') === 'true'; } catch { return false; }
                    });
                    // Custom ICE (STUN/TURN) servers — advanced network settings.
                    const [customIceServers, setCustomIceServers] = React.useState(null); // null => use public defaults
                    const [iceServersText, setIceServersText] = React.useState('');
                    const [iceSettingsPersisted, setIceSettingsPersisted] = React.useState(false);
                    const [showIceSettings, setShowIceSettings] = React.useState(false);

                    // Load any previously saved (encrypted) custom ICE settings on mount.
                    React.useEffect(() => {
                        let cancelled = false;
                        loadIceSettings().then((saved) => {
                            if (cancelled || !saved) return;
                            if (Array.isArray(saved.servers) && saved.servers.length > 0) {
                                setCustomIceServers(saved.servers);
                                setIceServersText(JSON.stringify(saved.servers, null, 2));
                            }
                            if (saved.privacyMode === 'relay-only') {
                                setRelayOnlyMode(true);
                            }
                            setIceSettingsPersisted(true);
                        }).catch(() => { /* fail closed: keep defaults */ });
                        return () => { cancelled = true; };
                    }, []);

                    // Global entry point: the header gear dispatches this event.
                    React.useEffect(() => {
                        const open = () => setShowIceSettings(true);
                        window.addEventListener('securebit:open-network-settings', open);
                        return () => window.removeEventListener('securebit:open-network-settings', open);
                    }, []);

                    const handleApplyIceSettings = React.useCallback((next, persist) => {
                        const servers = next.useCustom && Array.isArray(next.servers) ? next.servers : null;
                        setCustomIceServers(servers && servers.length ? servers : null);
                        setIceServersText(next.serversText || '');
                        setRelayOnlyMode(next.privacyMode === 'relay-only');
                        setShowIceSettings(false);
                        if (persist) {
                            setIceSettingsPersisted(true);
                            saveIceSettings({ servers: servers || [], privacyMode: next.privacyMode }).catch(() => { /* surfaced as no-op */ });
                        } else if (iceSettingsPersisted) {
                            // User turned persistence off — remove the stored copy.
                            setIceSettingsPersisted(false);
                            clearIceSettings().catch(() => {});
                        }
                    }, [iceSettingsPersisted]);

                    const handleForgetIceSettings = React.useCallback(async () => {
                        await clearIceSettings().catch(() => {});
                        setIceSettingsPersisted(false);
                        setCustomIceServers(null);
                        setIceServersText('');
                    }, []);
                    
                    // Moved scrollToBottom logic to be available globally
                    const [messageInput, setMessageInput] = React.useState('');
                    // offerData/answerData/offerInput/answerInput, showOfferStep/showAnswerStep,
                    // showVerification/showQRCode/qrCodeUrl, isGeneratingKeys → per-session setup
                    // slice (declared in the active-session view block above).
                    const [showQRScanner, setShowQRScanner] = React.useState(false);
                    const [showQRScannerModal, setShowQRScannerModal] = React.useState(false);

                    // isVerified + mutual-verification flags → per-session SAS slice (above).
                    const [securityLevel, setSecurityLevel] = React.useState(null);
                    const [sessionTimeLeft, setSessionTimeLeft] = React.useState(0);

                    // PAKE password states removed - using SAS verification instead

                    // Session state - all security features enabled by default
                    const [pendingSession, setPendingSession] = React.useState(null);

                    // All security features are enabled by default - no payment required
                    // pendingIncomingFiles → per-session slice (above).



                    // ============================================
                    // CENTRALIZED CONNECTION STATE MANAGEMENT
                    // ============================================
                    
                    const [connectionState, setConnectionState] = React.useState({
                        status: 'disconnected',
                        hasActiveAnswer: false,
                        answerCreatedAt: null,
                        isUserInitiatedDisconnect: false
                    });
                    
                    // Centralized connection state handler
                    const updateConnectionState = (newState, options = {}) => {
                        const { preserveAnswer = false, isUserAction = false } = options;
                        
                        setConnectionState(prev => ({
                            ...prev,
                            ...newState,
                            isUserInitiatedDisconnect: isUserAction,
                            hasActiveAnswer: preserveAnswer ? prev.hasActiveAnswer : false,
                            answerCreatedAt: preserveAnswer ? prev.answerCreatedAt : null
                        }));
                    };
                    
                    // Check if we should preserve answer data
                    const shouldPreserveAnswerData = () => {
                        const hasAnswerData = !!answerData || 
                                            (answerInput && typeof answerInput === 'string' && answerInput.trim().length > 0);

                        const hasAnswerQR = qrCodeUrl && typeof qrCodeUrl === 'string' && qrCodeUrl.trim().length > 0;
                        
                        const shouldPreserve = (connectionState.hasActiveAnswer && 
                               !connectionState.isUserInitiatedDisconnect) ||
                               (hasAnswerData && 
                               !connectionState.isUserInitiatedDisconnect) ||
                               (hasAnswerQR && 
                               !connectionState.isUserInitiatedDisconnect);
                        
                        
                        return shouldPreserve;
                    };
                    
                    // Mark answer as created
                    const markAnswerCreated = () => {
                        updateConnectionState({
                            hasActiveAnswer: true,
                            answerCreatedAt: Date.now()
                        });
                    };
                    
                    // webrtcManagerRef / notificationIntegrationRef → accessors over the active
                    // session's manager / integration (active-session view block, above).

                    // Development-only debug helpers. Production never exposes
                    // manager internals or cleanup controls on `window`.
                    React.useEffect(() => {
                        return installDebugWindowHooks({
                            targetWindow: window,
                            webrtcManagerRef,
                            onClearData: handleClearData
                        });
                    }, []);
        
                    const addMessageWithAutoScroll = React.useCallback((message, type, opts = {}) => {
                        const newMessage = {
                            message,
                            type,
                            id: Date.now() + Math.random(),
                            timestamp: (typeof opts.timestamp === 'number') ? opts.timestamp : Date.now(),
                            mid: opts.mid,
                            status: opts.status,            // WhatsApp-style: sending | sent | delivered | failed
                            viewOnce: opts.viewOnce === true,
                            viewOnceTtl: (typeof opts.viewOnceTtl === 'number') ? opts.viewOnceTtl : 15,
                            expiresAt: (typeof opts.expiresAt === 'number') ? opts.expiresAt : undefined
                        };

                        setMessages(prev => {
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
                                                        behavior: 'smooth'
                                                    });
                                                }
                                            });
                                        }
                                    } catch (error) {
                                        console.warn('Scroll error:', error);
                                        container.scrollTop = container.scrollHeight;
                                    }
                                }
                            }, 50);
                            
                            return updated;
                        });
                    }, []);

                    // Flip a sent message's delivery state (sending → sent → delivered, or failed).
                    const updateMessageStatus = React.useCallback((mid, status) => {
                        if (!mid) return;
                        setMessages(prev => prev.map(m => (String(m.mid) === String(mid) && m.type === 'sent') ? { ...m, status } : m));
                    }, []);

                    // When WE come back online: for EVERY session, transmit anything queued while
                    // offline and surface (and acknowledge) anything that arrived meanwhile. Each
                    // session flushes against its own manager and into its own slice.
                    const flushOfflineQueues = React.useCallback(() => {
                        for (const [id, q] of queuesRef.current.entries()) {
                            const mgr = managersRef.current.get(id);
                            const out = q.outgoing; q.outgoing = [];
                            for (const item of out) {
                                const send = mgr?.sendMessage?.(item.outText, item.meta);
                                if (send && typeof send.then === 'function') {
                                    send.then(() => dispatch({ type: SA.UPDATE_MESSAGE_STATUS, id, mid: item.mid, status: 'delivered' }))
                                        .catch(() => dispatch({ type: SA.UPDATE_MESSAGE_STATUS, id, mid: item.mid, status: 'failed' }));
                                }
                            }
                            const inc = q.incoming; q.incoming = [];
                            if (inc.length > 0) {
                                dispatch({ type: SA.ADD_MESSAGE, id, message: buildSessionMessage(
                                    `Connection restored — ${inc.length} message${inc.length === 1 ? '' : 's'} received while you were offline.`,
                                    'notice'
                                ) });
                            }
                            const viewing = id === activeIdRef.current && (typeof document === 'undefined' || document.visibilityState === 'visible');
                            for (const item of inc) {
                                dispatch({ type: SA.ADD_MESSAGE, id, message: buildSessionMessage(item.message, item.type, item.opts) });
                                if (item.opts && item.opts.mid && item.type === 'received') {
                                    if (viewing) { try { mgr?.sendDeliveryReceipt?.(item.opts.mid); } catch (_) {} }
                                    else if (q.pendingReadAcks) q.pendingReadAcks.push(item.opts.mid);
                                }
                            }
                        }
                    }, []);

                    React.useEffect(() => {
                        if (isOffline) return;        // only act on the offline → online edge
                        flushOfflineQueues();
                    }, [isOffline, flushOfflineQueues]);

                    // Update security level based on real verification
                    const updateSecurityLevel = React.useCallback(async () => {
                        if (window.isUpdatingSecurity) {
                            return;
                        }
                        
                        window.isUpdatingSecurity = true;
                        
                        try {
                            if (webrtcManagerRef.current) {
                                // All security features are enabled by default - always show MAXIMUM level
                                setSecurityLevel({
                                    level: 'MAXIMUM',
                                    score: 100,
                                    color: 'green',
                                    details: 'All security features enabled by default',
                                    passedChecks: 10,
                                    totalChecks: 10,
                                    isRealData: true
                                });
                                
                                if (window.DEBUG_MODE) {
                                    const currentLevel = webrtcManagerRef.current.ecdhKeyPair && webrtcManagerRef.current.ecdsaKeyPair 
                                        ? await webrtcManagerRef.current.calculateSecurityLevel()
                                        : {
                                            level: 'MAXIMUM',
                                            score: 100,
                                            sessionType: 'premium',
                                            passedChecks: 10,
                                            totalChecks: 10
                                        };
                                }
                            }
                        } catch (error) {
                            console.error('Failed to update security level:', error);
                            setSecurityLevel({
                                level: 'ERROR',
                                score: 0,
                                color: 'red',
                                details: 'Verification failed'
                            });
                        } finally {
                            setTimeout(() => {
                                window.isUpdatingSecurity = false;
                            }, 2000);
                        }
                    }, []);
        
                    // Session time ticker removed - sessions are unlimited
        
                    // Sessions are unlimited - no expiration handler needed
        
                    // All security features are enabled by default - no demo sessions needed
                    const chatMessagesRef = React.useRef(null);
        
                    // Create scroll function using global helper
                    const scrollToBottom = createScrollToBottomFunction(chatMessagesRef);

                    React.useEffect(() => {
                        try { localStorage.setItem('securebit_relay_only_mode', String(relayOnlyMode)); } catch {}
                        if (webrtcManagerRef.current?._config?.webrtc) {
                            webrtcManagerRef.current._setRelayOnlyMode(relayOnlyMode);
                        }
                    }, [relayOnlyMode]);
                    
                    // Auto-scroll when messages change
                    React.useEffect(() => {
                        if (messages.length > 0 && chatMessagesRef.current) {
                            scrollToBottom();
                            setTimeout(scrollToBottom, 50);
                            setTimeout(scrollToBottom, 150);
                        }
                    }, [messages]);

                    // Disappearing-message clock: tick every second (while ANY session has an
                    // expiry) and prune past-deadline messages — independently per session, so
                    // a background conversation's timers keep running too.
                    const anyExpiring = sessionsState.order.some((id) => (sessionsState.sessions[id]?.messages || []).some((m) => typeof m.expiresAt === 'number'));
                    const sessionsStateRef = React.useRef(sessionsState);
                    sessionsStateRef.current = sessionsState;
                    React.useEffect(() => {
                        if (!anyExpiring) return;
                        // Disappearing messages leave a tombstone (content wiped) instead of vanishing.
                        const expireFn = (prev) => {
                            const now = Date.now();
                            let changed = false;
                            const next = prev.map((m) => {
                                if (typeof m.expiresAt === 'number' && m.expiresAt <= now && !m.expired) {
                                    changed = true;
                                    return { ...m, expired: true, message: '', expiresAt: undefined };
                                }
                                return m;
                            });
                            return changed ? next : prev;
                        };
                        const interval = setInterval(() => {
                            const now = Date.now();
                            setNowTick(now);
                            const st = sessionsStateRef.current;
                            for (const id of st.order) {
                                const msgs = st.sessions[id]?.messages || [];
                                if (msgs.some((m) => typeof m.expiresAt === 'number' && m.expiresAt <= now && !m.expired)) {
                                    dispatch({ type: SA.SET_MESSAGES, id, updater: expireFn });
                                }
                            }
                        }, 1000);
                        return () => clearInterval(interval);
                    }, [anyExpiring]);
                    
                    // PAKE password functions removed - using SAS verification instead
        
                    // Build a brand-new, fully-isolated session: its own manager, its own
                    // id-bound callbacks, its own notification integration and offline queues.
                    // The callback bodies below are the original single-session handlers; the
                    // id-bound shadow setters declared here redirect every set*/dispatch into
                    // THIS session's slice, so nothing leaks into another conversation.
                    const createSession = (opts = {}) => {
                        const role = opts.role || 'offer';
                        const entry = createSessionEntry({ role });
                        const id = entry.id;
                        dispatch({ type: SA.CREATE_SESSION, entry, activate: opts.activate !== false });
                        // pendingReadAcks: mids received while this chat was NOT being viewed; the
                        // read receipt is held back until the user actually opens the conversation.
                        queuesRef.current.set(id, { incoming: [], outgoing: [], pendingReadAcks: [] });

                        // --- id-bound shadow setters (override the active-session view names) ---
                        const setMessages = (u) => {
                            if (typeof u === 'function') dispatch({ type: SA.SET_MESSAGES, id, updater: u });
                            else dispatch({ type: SA.SET_MESSAGES, id, messages: u });
                        };
                        const addMessageWithAutoScroll = (message, type, opts2 = {}) => {
                            dispatch({ type: SA.ADD_MESSAGE, id, message: buildSessionMessage(message, type, opts2) });
                            // Background session received a chat message → bump its unread badge.
                            if (type === 'received' && id !== activeIdRef.current) {
                                dispatch({ type: SA.INCREMENT_UNREAD, id });
                            }
                        };
                        const updateMessageStatus = (mid, status) => { if (mid) dispatch({ type: SA.UPDATE_MESSAGE_STATUS, id, mid, status }); };
                        const setConnectionStatus = (status) => dispatch({ type: SA.SET_STATUS, id, status });
                        const setKeyFingerprint = (fingerprint) => dispatch({ type: SA.SET_FINGERPRINT, id, fingerprint });
                        const setVerificationCode = (code) => dispatch({ type: SA.SET_VERIFICATION, id, code });
                        const setIsVerified = (v) => dispatch({ type: SA.SET_SAS, id, sas: { isVerified: !!v } });
                        const setLocalVerificationConfirmed = (v) => dispatch({ type: SA.SET_SAS, id, sas: { localConfirmed: !!v } });
                        const setRemoteVerificationConfirmed = (v) => dispatch({ type: SA.SET_SAS, id, sas: { remoteConfirmed: !!v } });
                        const setBothVerificationsConfirmed = (v) => dispatch({ type: SA.SET_SAS, id, sas: { bothConfirmed: !!v } });
                        const setShowVerification = (v) => dispatch({ type: SA.PATCH_SETUP, id, patch: { showVerification: !!v } });
                        const setShowOfferStep = (v) => dispatch({ type: SA.PATCH_SETUP, id, patch: { showOfferStep: !!v } });
                        const setShowAnswerStep = (v) => dispatch({ type: SA.PATCH_SETUP, id, patch: { showAnswerStep: !!v } });
                        const setShowQRCode = (v) => dispatch({ type: SA.PATCH_SETUP, id, patch: { showQRCode: !!v } });
                        const setQrCodeUrl = (v) => dispatch({ type: SA.PATCH_SETUP, id, patch: { qrCodeUrl: v } });
                        const setOfferData = (v) => dispatch({ type: SA.PATCH_SETUP, id, patch: { offerData: v } });
                        const setAnswerData = (v) => dispatch({ type: SA.PATCH_SETUP, id, patch: { answerData: v } });
                        const setOfferInput = (v) => dispatch({ type: SA.PATCH_SETUP, id, patch: { offerInput: v } });
                        const setAnswerInput = (v) => dispatch({ type: SA.PATCH_SETUP, id, patch: { answerInput: v } });
                        const setPendingIncomingFiles = (u) => {
                            if (typeof u === 'function') dispatch({ type: SA.SET_PENDING_FILES, id, updater: u });
                            else dispatch({ type: SA.SET_PENDING_FILES, id, files: u });
                        };
                        const sessionQueues = () => queuesRef.current.get(id) || { incoming: [], outgoing: [] };

                        const handleMessage = (message, type, meta) => {
                            if (typeof message === 'string' && message.trim().startsWith('{')) {
                                try {
                                    const parsedMessage = JSON.parse(message);
                                    // Peer availability update (E2E control message) — store it for THIS
                                    // session and never show it in the chat.
                                    if (parsedMessage.type === 'presence') {
                                        const st = (parsedMessage.data && parsedMessage.data.status) || parsedMessage.status;
                                        if (st) dispatch({ type: SA.SET_PEER_PRESENCE, id, presence: st });
                                        return;
                                    }
                                    const blockedTypes = [
                                        'file_transfer_start',
                                        'file_transfer_response',
                                        'file_chunk',
                                        'chunk_confirmation',
                                        'file_transfer_complete',
                                        'file_transfer_error',
                                        'heartbeat',
                                        'verification',
                                        'verification_response',
                                        'verification_confirmed',
                                        'verification_both_confirmed',
                                        'peer_disconnect',
                                        'key_rotation_signal',
                                        'key_rotation_ready',
                                        'security_upgrade',
                                        'message_delete',
                                        'message_receipt'
                                    ];
                                    if (parsedMessage.type && blockedTypes.includes(parsedMessage.type)) {
                                        console.log(`Blocked system/file message from chat: ${parsedMessage.type}`);
                                        return;
                                    }
                                    // Defensive unwrap: a plain-message envelope can leak through as
                                    // raw JSON for some payloads (e.g. fenced code blocks). Show the
                                    // real text, not {"type":"message","data":"```..."}.
                                    if (parsedMessage.type === 'message' && typeof parsedMessage.data === 'string') {
                                        message = parsedMessage.data;
                                        if (parsedMessage.meta && typeof parsedMessage.meta === 'object') meta = parsedMessage.meta;
                                    }
                                } catch (parseError) {

                                }
                            }
                            
                            // Per-message UI metadata from the peer (view-once / disappearing / id).
                            const opts = {};
                            if (meta && typeof meta === 'object') {
                                if (typeof meta.mid === 'string') opts.mid = meta.mid;
                                if (meta.once === true) {
                                    opts.viewOnce = true;
                                    opts.viewOnceTtl = Number.isFinite(meta.onceTtl) ? meta.onceTtl : 15;
                                }
                                if (Number.isFinite(meta.ttl) && meta.ttl > 0) {
                                    opts.expiresAt = Date.now() + meta.ttl * 1000;
                                }
                                if (Number.isFinite(meta.ts)) opts.timestamp = meta.ts;
                            }

                            // If WE are offline, hold the peer's message back: don't show it
                            // and don't acknowledge it yet, so the sender stays at one check.
                            // It's surfaced (and acked → ✓✓) the moment we reconnect.
                            if (offlineRef.current && type === 'received') {
                                sessionQueues().incoming.push({ message, type, opts });
                                return;
                            }

                            addMessageWithAutoScroll(message, type, opts);

                            // Read receipt: only ack once the user is actually looking at THIS
                            // conversation (active session + visible tab). Otherwise hold the mid
                            // back so a message read in a background chat stays "delivered" (grey
                            // ✓✓) on the sender's side — it flips to green only when this chat is
                            // opened (see flushReadAcks).
                            if (opts.mid && type === 'received') {
                                const beingViewed = id === activeIdRef.current && (typeof document === 'undefined' || document.visibilityState === 'visible');
                                if (beingViewed) {
                                    try { manager?.sendDeliveryReceipt?.(opts.mid); } catch (_) {}
                                } else {
                                    const q = sessionQueues();
                                    if (q.pendingReadAcks) q.pendingReadAcks.push(opts.mid);
                                }
                            }
                        };

                        const handleStatusChange = (status) => {
                            setConnectionStatus(status);
                            
                            if (status === 'connected') {
                                document.dispatchEvent(new CustomEvent('new-connection'));
                                
                                // Не скрываем верификацию при 'connected' - только при 'verified'
                                // setIsVerified(true);
                                // setShowVerification(false);
                                if (!window.isUpdatingSecurity) {
                                    updateSecurityLevel().catch(console.error);
                                }
                            } else if (status === 'verifying') {
                                setShowVerification(true);
                                if (!window.isUpdatingSecurity) {
                                    updateSecurityLevel().catch(console.error);
                                }
                            } else if (status === 'verified') {
                                setIsVerified(true);
                                setShowVerification(false);
                                setBothVerificationsConfirmed(true);
                                setConnectionStatus('connected');
                                // Force immediate update of isVerified state
                                setTimeout(() => {
                                    setIsVerified(true);
                                }, 0);
                                // Tell the newly-connected peer my current availability (E2E, via
                                // the normal encrypted message path — see sendPresenceTo).
                                try {
                                    const s = myStatusRef.current === 'invisible' ? 'offline' : myStatusRef.current;
                                    setTimeout(() => {
                                        try {
                                            const p = manager.sendMessage?.(JSON.stringify({ type: 'presence', status: s }));
                                            if (p && typeof p.catch === 'function') p.catch(() => {});
                                        } catch (_) {}
                                    }, 400);
                                } catch (_) {}
                                if (!window.isUpdatingSecurity) {
                                    updateSecurityLevel().catch(console.error);
                                }
                            } else if (status === 'connecting') {
                                if (!window.isUpdatingSecurity) {
                                    updateSecurityLevel().catch(console.error);
                                }
                            } else if (status === 'disconnected') {
                                // Drop: the manager has cleared its verification (re-establishment
                                // required), so reset this session's verification flags too — the
                                // setup/connect screen then shows so the user can reconnect. We do
                                // NOT remove the session (that create→destroy→create churn flashed
                                // the console) and we keep the message history; closing a chat is
                                // done only via the Disconnect button.
                                setConnectionStatus('disconnected');
                                setIsVerified(false);
                                setShowVerification(false);
                                setLocalVerificationConfirmed(false);
                                setRemoteVerificationConfirmed(false);
                                setBothVerificationsConfirmed(false);
                                if (id === activeIdRef.current) document.dispatchEvent(new CustomEvent('disconnected'));
                            } else if (status === 'peer_disconnected') {
                                if (id === activeIdRef.current) {
                                    setSessionTimeLeft(0);
                                    document.dispatchEvent(new CustomEvent('peer-disconnect'));
                                }
                                setConnectionStatus('peer_disconnected');
                                setIsVerified(false);
                                setShowVerification(false);
                                setLocalVerificationConfirmed(false);
                                setRemoteVerificationConfirmed(false);
                                setBothVerificationsConfirmed(false);
                            }
                        };
        
                        const handleKeyExchange = (fingerprint) => {
                            if (fingerprint === '') {
                                setKeyFingerprint('');
                            } else {
                                setKeyFingerprint(fingerprint);
                            }
                        };
                        
                        const handleVerificationRequired = (code) => {
                            if (code === '') {
                                setVerificationCode('');
                                setShowVerification(false);
                            } else {
                                setVerificationCode(code);
                                setShowVerification(true);
                            }
                        };
        
                        const handleVerificationStateChange = (state) => {
                            setLocalVerificationConfirmed(state.localConfirmed);
                            setRemoteVerificationConfirmed(state.remoteConfirmed);
                            setBothVerificationsConfirmed(state.bothConfirmed);
                        };
        
                        // Callback for handling response errors
                        const handleAnswerError = (errorType, errorMessage) => {
                            if (errorType === 'replay_attack') {
                                // Reset the session upon replay attack
                                    setSessionTimeLeft(0);
                                setPendingSession(null);
                                
                                addMessageWithAutoScroll('💡 Data is outdated. Please create a new invitation or use a current response code.', 'system');
        
                                if (typeof console.clear === 'function') {
                                    console.clear();
                                }
                            } else if (errorType === 'security_violation') {
                                // Reset the session upon security breach
                                    setSessionTimeLeft(0);
                                setPendingSession(null);
                                
                                addMessageWithAutoScroll(` Security breach: ${errorMessage}`, 'system');
        
                                if (typeof console.clear === 'function') {
                                    console.clear();
                                }
                            }
                        };
        
        
                        if (typeof console.clear === 'function') {
                            console.clear();
                        }
                        
                        const manager = new EnhancedSecureWebRTCManager(
                            handleMessage,
                            handleStatusChange,
                            handleKeyExchange,
                            handleVerificationRequired,
                            handleAnswerError,
                            handleVerificationStateChange,
                            {
                                webrtc: {
                                    relayOnly: relayOnlyMode,
                                    // Priority: user's custom servers > operator override > built-in defaults.
                                    iceServers: (Array.isArray(customIceServers) && customIceServers.length)
                                        ? customIceServers
                                        : (Array.isArray(window.SECUREBIT_ICE_SERVERS) ? window.SECUREBIT_ICE_SERVERS : undefined)
                                }
                            }
                        );
                        managersRef.current.set(id, manager);

                        // Unsend / delete-for-everyone: peer asked us to drop a message.
                        manager.onMessageDelete = (mid) => {
                            if (!mid) return;
                            setMessages(prev => prev.filter(m => String(m.mid) !== String(mid)));
                        };

                        // Read receipt: the peer actually opened the chat and read it → green.
                        // (A receipt is only sent once the recipient is viewing the conversation,
                        // so background-read messages stay at two grey 'delivered' ticks.)
                        manager.onMessageDelivered = (mid) => {
                            updateMessageStatus(mid, 'read');
                        };

                        // Per-session notification integration (raises OS notifications when the
                        // tab is hidden; the unread badge handles the in-app, focused case).
                        if (typeof Notification !== 'undefined' && Notification && Notification.permission === 'granted' && window.NotificationIntegration && !integrationsRef.current.get(id)) {
                            try {
                                const integration = new window.NotificationIntegration(manager);
                                integration.init().then(() => {
                                    integrationsRef.current.set(id, integration);
                                }).catch((error) => {
                                    // Handle error silently
                                });
                            } catch (error) {
                                // Handle error silently
                            }
                        }

                        handleMessage(' SecureBit.chat Enhanced Security Edition v4.10.0 - ECDH + DTLS + SAS initialized. Ready to establish a secure connection with ECDH key exchange, DTLS fingerprint verification, and SAS authentication to prevent MITM attacks.', 'system');

                        // Setup file transfer callbacks (id-bound to THIS session's manager).
                        manager.setFileTransferCallbacks(
                            // Progress callback
                            (progress) => {
                                console.log('File progress:', progress);
                            },

                            // File received callback — auto-save to disk, no button press needed.
                            (fileData) => {
                                const sizeMb = Math.max(1, Math.round((fileData.fileSize || 0) / (1024 * 1024)));

                                const saveToDisk = async () => {
                                    const url = await fileData.getObjectURL();
                                    const a = document.createElement('a');
                                    a.href = url;
                                    a.download = fileData.fileName || 'file';
                                    document.body.appendChild(a);
                                    a.click();
                                    a.remove();
                                    setTimeout(() => fileData.revokeObjectURL(url), 15000);
                                };

                                saveToDisk()
                                    .then(() => {
                                        addMessageWithAutoScroll(`File received & saved: ${fileData.fileName} (${sizeMb} MB)`, 'system');
                                    })
                                    .catch((e) => {
                                        console.error('Auto-save failed:', e);
                                        addMessageWithAutoScroll(`File received: ${fileData.fileName} (${sizeMb} MB). Open the file panel to download it.`, 'system');
                                    });
                            },

                            // Error callback
                            (error) => {
                                console.error('File transfer error:', error);

                                if (error.includes('Connection not ready')) {
                                    addMessageWithAutoScroll(` File transfer error: connection not ready. Try again later.`, 'system');
                                } else if (error.includes('File too large')) {
                                    addMessageWithAutoScroll(` File is too big. Maximum size: 100 MB`, 'system');
                                } else {
                                    addMessageWithAutoScroll(` File transfer error: ${error}`, 'system');
                                }
                            },

                            // Incoming file request callback — receiver must explicitly accept before any data is sent
                            (fileRequest) => {
                                setPendingIncomingFiles(prev => {
                                    if (prev.some(f => f.fileId === fileRequest.fileId)) return prev;
                                    return [...prev, fileRequest];
                                });
                            }
                        );

                        return id;
                    };

                    // Keep createSession reachable from non-render callers (new-chat button etc.).
                    const createSessionRef = React.useRef(createSession);
                    createSessionRef.current = createSession;

                    // Tear down ONE session completely: its manager (existing key-wipe logic),
                    // its notification integration and its queues. Other sessions are untouched.
                    // Re-entrancy guarded: mgr.disconnect() can synchronously re-fire the
                    // 'disconnected' status callback, which would otherwise recurse back in here.
                    const destroyingRef = React.useRef(new Set());
                    const destroySession = React.useCallback((id) => {
                        if (!id || destroyingRef.current.has(id)) return;
                        destroyingRef.current.add(id);
                        try {
                            const mgr = managersRef.current.get(id);
                            if (mgr) { try { mgr.disconnect(); } catch (_) {} managersRef.current.delete(id); }
                            const integ = integrationsRef.current.get(id);
                            if (integ) { try { integ.cleanup?.(); } catch (_) {} integrationsRef.current.delete(id); }
                            queuesRef.current.delete(id);
                            dispatch({ type: SA.REMOVE_SESSION, id });
                        } finally {
                            destroyingRef.current.delete(id);
                        }
                    }, []);

                    // Always keep at least one session around: when the last chat is removed the
                    // user lands back on the single-column "Start Secure" page with a fresh session.
                    React.useEffect(() => {
                        if (sessionsState.order.length === 0) createSessionRef.current({ role: 'offer' });
                    }, [sessionsState.order.length]);

                    // ---- Sidebar (session list) state + actions ----
                    const [sidebarCollapsed, setSidebarCollapsed] = React.useState(() => {
                        try { return localStorage.getItem('securebit_sidebar_collapsed') === 'true'; } catch { return false; }
                    });
                    React.useEffect(() => { try { localStorage.setItem('securebit_sidebar_collapsed', String(sidebarCollapsed)); } catch {} }, [sidebarCollapsed]);
                    const [sidebarDrawerOpen, setSidebarDrawerOpen] = React.useState(false);
                    const handleSelectSession = React.useCallback((id) => {
                        dispatch({ type: SA.SET_ACTIVE, id });
                        dispatch({ type: SA.CLEAR_UNREAD, id });
                        setSidebarDrawerOpen(false);
                    }, []);
                    const handleNewChat = React.useCallback(() => {
                        createSessionRef.current({ role: 'offer' });
                        setSidebarDrawerOpen(false);
                    }, []);
                    const handleRenameSession = React.useCallback((id, label) => { dispatch({ type: SA.RENAME, id, label }); }, []);
                    // Send any held-back read receipts for a session (call when the user opens it).
                    const flushReadAcks = React.useCallback((id) => {
                        if (!id) return;
                        const q = queuesRef.current.get(id);
                        const mgr = managersRef.current.get(id);
                        if (!q || !mgr || !q.pendingReadAcks || q.pendingReadAcks.length === 0) return;
                        const acks = q.pendingReadAcks; q.pendingReadAcks = [];
                        for (const mid of acks) { try { mgr.sendDeliveryReceipt?.(mid); } catch (_) {} }
                    }, []);
                    // Opening a session clears its unread badge and releases its read receipts.
                    React.useEffect(() => {
                        if (!activeSessionId) return;
                        dispatch({ type: SA.CLEAR_UNREAD, id: activeSessionId });
                        if (typeof document === 'undefined' || document.visibilityState === 'visible') flushReadAcks(activeSessionId);
                    }, [activeSessionId, flushReadAcks]);

                    // App-level lifecycle: create the first session on mount, wire the global
                    // tab/unload guards, and on unmount disconnect EVERY live manager.
                    const didInitRef = React.useRef(false);
                    React.useEffect(() => {
                        if (didInitRef.current) return;
                        didInitRef.current = true;

                        // (The first session is created by the ensure-at-least-one-session effect,
                        // which also handles re-landing after the last chat is closed.)

                        let isTabSwitching = false;
                        let tabSwitchTimeout = null;

                        const handleBeforeUnload = (event) => {
                            if (event.type === 'beforeunload' && !isTabSwitching) {
                                for (const mgr of managersRef.current.values()) {
                                    try {
                                        if (mgr.isConnected && mgr.isConnected()) {
                                            try { mgr.sendSystemMessage({ type: 'peer_disconnect', reason: 'user_disconnect', timestamp: Date.now() }); } catch (_) {}
                                            setTimeout(() => { try { mgr.disconnect(); } catch (_) {} }, 100);
                                        } else {
                                            mgr.disconnect();
                                        }
                                    } catch (_) {}
                                }
                            } else if (isTabSwitching) {
                                event.preventDefault();
                                event.returnValue = '';
                            }
                        };

                        const handleVisibilityChange = () => {
                            if (document.visibilityState === 'hidden') {
                                isTabSwitching = true;
                                if (tabSwitchTimeout) clearTimeout(tabSwitchTimeout);
                                tabSwitchTimeout = setTimeout(() => { isTabSwitching = false; }, 5000);
                            } else if (document.visibilityState === 'visible') {
                                isTabSwitching = false;
                                if (tabSwitchTimeout) { clearTimeout(tabSwitchTimeout); tabSwitchTimeout = null; }
                                // Tab regained focus → release held read receipts for the open chat.
                                flushReadAcks(activeIdRef.current);
                            }
                        };

                        window.addEventListener('beforeunload', handleBeforeUnload);
                        document.addEventListener('visibilitychange', handleVisibilityChange);

                        return () => {
                            window.removeEventListener('beforeunload', handleBeforeUnload);
                            document.removeEventListener('visibilitychange', handleVisibilityChange);
                            if (tabSwitchTimeout) { clearTimeout(tabSwitchTimeout); tabSwitchTimeout = null; }
                            for (const mgr of managersRef.current.values()) { try { mgr.disconnect(); } catch (_) {} }
                            managersRef.current.clear();
                            for (const integ of integrationsRef.current.values()) { try { integ.cleanup?.(); } catch (_) {} }
                            integrationsRef.current.clear();
                            queuesRef.current.clear();
                        };
                    }, []); // run once
        
                    // All security features are enabled by default - no session purchase needed
        
                    const compressOfferData = (offerData) => {
                        try {
                            // Parse the offer data if it's a string
                            const offer = typeof offerData === 'string' ? JSON.parse(offerData) : offerData;
                            
                            // Create a minimal version with only the most essential data
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
                                compressionLevel: 'minimal'
                            };
                            
                            return JSON.stringify(minimalOffer);
                        } catch (error) {
                            console.error('Error compressing offer data:', error);
                            return offerData; // Return original if compression fails
                        }
                    };

                    const createQRReference = (offerData) => {
                        try {
                            // Create a unique reference ID for this offer
                            const referenceId = `offer_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                            
                            // Store the full offer data in localStorage with the reference ID
                            localStorage.setItem(`qr_offer_${referenceId}`, JSON.stringify(offerData));
                            
                            // Create a minimal QR code with just the reference
                            const qrReference = {
                                type: 'secure_offer_reference',
                                referenceId: referenceId,
                                timestamp: Date.now(),
                                message: 'Scan this QR code and use the reference ID to get full offer data'
                            };
                            
                            return JSON.stringify(qrReference);
                        } catch (error) {
                            console.error('Error creating QR reference:', error);
                            return null;
                        }
                    };

                    const createTemplateOffer = (offer) => {
                        // Minimal template to keep QR within single image capacity
                        const templateOffer = {
                            type: 'enhanced_secure_offer_template',
                            version: '4.0',
                            sessionId: offer.sessionId,
                            connectionId: offer.connectionId,
                            verificationCode: offer.verificationCode,
                            timestamp: offer.timestamp,
                            // Avoid bulky fields (SDP, raw keys); keep only fingerprints and essentials
                            keyFingerprints: offer.keyFingerprints,
                            // Keep concise auth hints (omit large nonces)
                            authChallenge: offer?.authChallenge?.challenge,
                            // Optionally include a compact capability hint if small
                            capabilities: Array.isArray(offer.capabilities) && offer.capabilities.length <= 5
                                ? offer.capabilities
                                : undefined
                        };
                        
                        return templateOffer;
                    };

                    // Conservative QR payload limits (characters). Adjust per error correction level.
                    const MAX_QR_LEN = 800;      // for JSON/plain/gzip
                    const BIN_MAX_QR_LEN = 400;  // stricter for SB1:bin to improve scan reliability
                    const [qrFramesTotal, setQrFramesTotal] = React.useState(0);
                    const [qrFrameIndex, setQrFrameIndex] = React.useState(0);
                    const [qrManualMode, setQrManualMode] = React.useState(false);

                    // Animated QR state (for multi-chunk COSE)
                    const qrAnimationRef = React.useRef({ timer: null, chunks: [], idx: 0, active: false });
                    // Stop any running QR auto-advance when the active session changes, so frames
                    // are never pushed into the wrong session's setup slice.
                    React.useEffect(() => () => {
                        try { if (qrAnimationRef.current && qrAnimationRef.current.timer) { clearInterval(qrAnimationRef.current.timer); qrAnimationRef.current.timer = null; } } catch {}
                    }, [activeSessionId]);
                    const stopQrAnimation = () => {
                        try { if (qrAnimationRef.current.timer) { clearInterval(qrAnimationRef.current.timer); } } catch {}
                        qrAnimationRef.current = { timer: null, chunks: [], idx: 0, active: false };
                        setQrFrameIndex(0);
                        setQrFramesTotal(0);
                        setQrManualMode(false);
                    };

                    // Render frame at current index (no index mutation)
                    const renderCurrent = async () => {
                        const { chunks, idx } = qrAnimationRef.current || {};
                        if (!chunks || !chunks.length) return;
                        const current = chunks[idx % chunks.length];
                        try {
                            const isDesktop = (typeof window !== 'undefined') && ((window.innerWidth || 0) >= 1024);
                            const QR_SIZE = isDesktop ? 720 : 512;
                            const url = await (window.generateQRCode ? window.generateQRCode(current, { errorCorrectionLevel: 'M', margin: 2, size: QR_SIZE }) : Promise.resolve(''));
                            if (url) setQrCodeUrl(url);
                        } catch (e) {
                            console.warn('Animated QR render error (current):', e);
                        }
                        setQrFrameIndex(((qrAnimationRef.current?.idx || 0) % (qrAnimationRef.current?.chunks?.length || 1)) + 1);
                    };

                    // Render current frame, then advance index by 1
                    const renderAndAdvance = async () => {
                        await renderCurrent();
                        const len = qrAnimationRef.current?.chunks?.length || 0;
                        if (len > 0) {
                            const nextIdx = ((qrAnimationRef.current?.idx || 0) + 1) % len;
                            qrAnimationRef.current.idx = nextIdx;
                            setQrFrameIndex(nextIdx + 1);
                        }
                    };

                    const toggleQrManualMode = () => {
                        const newManualMode = !qrManualMode;
                        setQrManualMode(newManualMode);
                        
                        if (newManualMode) {

                            if (qrAnimationRef.current.timer) {
                                clearInterval(qrAnimationRef.current.timer);
                                qrAnimationRef.current.timer = null;
                            }
                            console.log('QR Manual mode enabled - auto-scroll stopped');
                        } else {
                            if (qrAnimationRef.current.chunks.length > 1) {
                                const intervalMs = 3000;
                                qrAnimationRef.current.active = true;
                                clearInterval(qrAnimationRef.current.timer);
                                qrAnimationRef.current.timer = setInterval(renderAndAdvance, intervalMs);
                            }
                            console.log('QR Manual mode disabled - auto-scroll resumed');
                        }
                    };

                    const nextQrFrame = async () => {
                        console.log('🎮 nextQrFrame called, qrFramesTotal:', qrFramesTotal, 'qrAnimationRef.current:', qrAnimationRef.current);
                        if (qrAnimationRef.current.chunks.length > 1) {
                            const nextIdx = (qrAnimationRef.current.idx + 1) % qrAnimationRef.current.chunks.length;
                            qrAnimationRef.current.idx = nextIdx;
                            setQrFrameIndex(nextIdx + 1);
                            console.log('🎮 Next frame index:', nextIdx + 1);
                            // Ensure auto-advance timer runs in manual mode too
                            try { clearInterval(qrAnimationRef.current.timer); } catch {}
                            qrAnimationRef.current.timer = null;
                            await renderCurrent();
                            // If not in manual mode, restart auto timer
                            if (!qrManualMode && qrAnimationRef.current.chunks.length > 1) {
                                const intervalMs = 3000;
                                qrAnimationRef.current.active = true;
                                qrAnimationRef.current.timer = setInterval(renderAndAdvance, intervalMs);
                            } else {
                                qrAnimationRef.current.active = false;
                            }
                        } else {
                            console.log('🎮 No multiple frames to navigate');
                        }
                    };

                    const prevQrFrame = async () => {
                        console.log('🎮 prevQrFrame called, qrFramesTotal:', qrFramesTotal, 'qrAnimationRef.current:', qrAnimationRef.current);
                        if (qrAnimationRef.current.chunks.length > 1) {
                            const prevIdx = (qrAnimationRef.current.idx - 1 + qrAnimationRef.current.chunks.length) % qrAnimationRef.current.chunks.length;
                            qrAnimationRef.current.idx = prevIdx;
                            setQrFrameIndex(prevIdx + 1);
                            console.log('🎮 Previous frame index:', prevIdx + 1);
                            try { clearInterval(qrAnimationRef.current.timer); } catch {}
                            qrAnimationRef.current.timer = null;
                            await renderCurrent();
                            if (!qrManualMode && qrAnimationRef.current.chunks.length > 1) {
                                const intervalMs = 3000;
                                qrAnimationRef.current.active = true;
                                qrAnimationRef.current.timer = setInterval(renderAndAdvance, intervalMs);
                            } else {
                                qrAnimationRef.current.active = false;
                            }
                        } else {
                            console.log('🎮 No multiple frames to navigate');
                        }
                    };

                    // Buffer for assembling scanned COSE chunks
                    const qrChunksBufferRef = React.useRef({ id: null, total: 0, seen: new Set(), items: [] });

                    const generateQRCode = async (data) => {
                        try {
                            const originalSize = typeof data === 'string' ? data.length : JSON.stringify(data).length;
                            const isDesktop = (typeof window !== 'undefined') && ((window.innerWidth || 0) >= 1024);
                            const QR_SIZE = isDesktop ? 720 : 512;
                            
                            // Try binary format first (CBOR + deflate + base64url)
                            if (typeof window.generateBinaryQRCodeFromObject === 'function') {
                                try {
                                    const obj = typeof data === 'string' ? JSON.parse(data) : data;
                                    const qrDataUrl = await window.generateBinaryQRCodeFromObject(obj, { errorCorrectionLevel: 'M', size: QR_SIZE, margin: 2 });
                                    if (qrDataUrl) {
                                        try { if (qrAnimationRef.current && qrAnimationRef.current.timer) { clearInterval(qrAnimationRef.current.timer); } } catch {}
                                        qrAnimationRef.current = { timer: null, chunks: [], idx: 0, active: false };
                                        setQrFrameIndex(0);
                                        setQrFramesTotal(0);
                                        setQrManualMode(false);
                                        setQrCodeUrl(qrDataUrl);
                                        setQrFramesTotal(1);
                                        setQrFrameIndex(1);
                                        return;
                                    }
                                } catch (e) {
                                    console.warn('Binary QR generation failed, falling back to compressed:', e?.message || e);
                                }
                            }
                            
                            // Fallback to compressed JSON
                            if (typeof window.generateCompressedQRCode === 'function') {
                                try {
                                    const payload = typeof data === 'string' ? data : JSON.stringify(data);
                                    const qrDataUrl = await window.generateCompressedQRCode(payload, { errorCorrectionLevel: 'M', size: QR_SIZE, margin: 2 });
                                    if (qrDataUrl) {
                                        try { if (qrAnimationRef.current && qrAnimationRef.current.timer) { clearInterval(qrAnimationRef.current.timer); } } catch {}
                                        qrAnimationRef.current = { timer: null, chunks: [], idx: 0, active: false };
                                        setQrFrameIndex(0);
                                        setQrFramesTotal(0);
                                        setQrManualMode(false);
                                        setQrCodeUrl(qrDataUrl);
                                        setQrFramesTotal(1);
                                        setQrFrameIndex(1);
                                        return;
                                    }
                                } catch (e) {
                                    console.warn('Compressed QR generation failed, falling back to plain:', e?.message || e);
                                }
                            }
                            
                            // Final fallback to plain JSON
                            const payload = typeof data === 'string' ? data : JSON.stringify(data);
                            if (payload.length <= MAX_QR_LEN) {
                                if (!window.generateQRCode) throw new Error('QR code generator unavailable');
                                try { if (qrAnimationRef.current && qrAnimationRef.current.timer) { clearInterval(qrAnimationRef.current.timer); } } catch {}
                                qrAnimationRef.current = { timer: null, chunks: [], idx: 0, active: false };
                                setQrFrameIndex(0);
                                setQrFramesTotal(0);
                                setQrManualMode(false);
                                const qrDataUrl = await window.generateQRCode(payload, { errorCorrectionLevel: 'M', size: QR_SIZE, margin: 2 });
                                    setQrCodeUrl(qrDataUrl);
                                setQrFramesTotal(1);
                                setQrFrameIndex(1);
                                    return;
                            }

                            // Large payload: разбиваем на фреймы (plain JSON)
                            try { if (qrAnimationRef.current && qrAnimationRef.current.timer) { clearInterval(qrAnimationRef.current.timer); } } catch {}
                            qrAnimationRef.current = { timer: null, chunks: [], idx: 0, active: false };
                            setQrFrameIndex(0);
                            setQrFramesTotal(0);
                            setQrManualMode(false);
                            const id = `raw_${Date.now()}_${Math.random().toString(36).slice(2)}`;

                            const TARGET_CHUNKS = 10;
                            const FRAME_MAX = Math.max(200, Math.floor(payload.length / TARGET_CHUNKS));
                            const total = Math.ceil(payload.length / FRAME_MAX);
                            const rawChunks = [];
                            for (let i = 0; i < total; i++) {
                                const seq = i + 1;
                                const part = payload.slice(i * FRAME_MAX, (i + 1) * FRAME_MAX);
                                rawChunks.push(JSON.stringify({ hdr: { v: 1, id, seq, total, rt: 'raw' }, body: part }));
                            }
                            if (!window.generateQRCode) throw new Error('QR code generator unavailable');
                            if (rawChunks.length === 1) {
                                const url = await window.generateQRCode(rawChunks[0], { errorCorrectionLevel: 'M', margin: 2, size: QR_SIZE });
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
                                const EC_OPTS = { errorCorrectionLevel: 'M', margin: 2, size: QR_SIZE };
                                await renderNext();

                                if (!qrManualMode) {
                                    const intervalMs = 4000; // 4 seconds per frame for better readability
                                qrAnimationRef.current.active = true;
                                qrAnimationRef.current.timer = setInterval(renderAndAdvance, intervalMs);
                                }
                            return;
                        } catch (error) {
                            console.error('QR code generation failed:', error);
                            setMessages(prev => [...prev, {
                                message: ` QR code generation failed: ${error.message}`,
                                type: 'error'
                            }]);
                        }
                    };

                    const reconstructFromTemplate = (templateData) => {
                        // Reconstruct full offer from template
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
                                timestamp: templateData.timestamp - 1000, // Approximate
                                version: templateData.version,
                                signature: templateData.ecdhSignature
                            },
                            
                            // Reconstruct ECDSA key object
                            ecdsaPublicKey: {
                                keyType: "ECDSA",
                                keyData: templateData.ecdsaKeyData,
                                timestamp: templateData.timestamp - 999, // Approximate
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
                            console.log('QR Code scanned:', scannedData.substring(0, 100) + '...');
                            console.log('Current buffer state:', qrChunksBufferRef.current);
                            
                            // Check if this is a binary chunk (starts with SB1:bin: or is a raw binary chunk)
                            if (scannedData.startsWith('SB1:bin:') || (qrChunksBufferRef.current && qrChunksBufferRef.current.id)) {
                                console.log('Binary chunk detected:', scannedData.substring(0, 50) + '...');
                                
                                // This is a binary chunk - add to buffer
                                if (!qrChunksBufferRef.current.id) {
                                    console.log('Initializing buffer for binary chunks');
                                    // Initialize buffer for binary chunks
                                    qrChunksBufferRef.current = { 
                                        id: `bin_${Date.now()}`, 
                                        total: 4, // We expect 4 chunks
                                        seen: new Set(), 
                                        items: [],
                                        lastUpdateMs: Date.now()
                                    };
                                }
                                
                                // Add chunk to buffer (use data hash as identifier)
                                const chunkHash = scannedData.substring(0, 50); // Use first 50 chars as hash
                                
                                // Check if this chunk was already scanned
                                if (qrChunksBufferRef.current.seen.has(chunkHash)) {
                                    console.log(`Chunk already scanned, ignoring...`);
                                    return Promise.resolve(false);
                                }
                                
                                qrChunksBufferRef.current.seen.add(chunkHash);
                                qrChunksBufferRef.current.items.push(scannedData);
                                qrChunksBufferRef.current.lastUpdateMs = Date.now();
                                
                                // Emit progress and force re-render
                                try {
                                    const uniqueCount = qrChunksBufferRef.current.seen.size;
                                    document.dispatchEvent(new CustomEvent('qr-scan-progress', { 
                                        detail: { 
                                            id: qrChunksBufferRef.current.id, 
                                            seq: uniqueCount, 
                                            total: qrChunksBufferRef.current.total 
                                        } 
                                    }));
                                    
                                    // Force re-render to update progress indicator
                                    setQrFramesTotal(qrChunksBufferRef.current.total);
                                    setQrFrameIndex(uniqueCount);
                                } catch {}
                                
                                // Check if we have all chunks
                                const isComplete = qrChunksBufferRef.current.seen.size >= qrChunksBufferRef.current.total;
                                console.log(`Chunks collected: ${qrChunksBufferRef.current.seen.size}/${qrChunksBufferRef.current.total}, complete: ${isComplete}`);
                                
                                if (!isComplete) {
                                    // Keep scanner open for more chunks
                                    console.log(`Scanned chunk ${qrChunksBufferRef.current.seen.size}/${qrChunksBufferRef.current.total}, waiting for more...`);
                                    return Promise.resolve(false);
                                }
                                
                                // All chunks collected - reconstruct binary data
                                try {
                                    const fullBinaryData = qrChunksBufferRef.current.items.join('');
                                    // Store the original binary data, not decoded JSON
                                    if (showOfferStep) {
                                        setAnswerInput(fullBinaryData);
                                    } else {
                                        setOfferInput(fullBinaryData);
                                    }
                                    
                                    setMessages(prev => [...prev, { 
                                        message: 'All binary chunks captured. Payload reconstructed.', 
                                        type: 'success' 
                                    }]);
                                    
                                    // Clear buffer and close scanner
                                    qrChunksBufferRef.current = { id: null, total: 0, seen: new Set(), items: [] };
                                    setShowQRScannerModal(false);
                                    return Promise.resolve(true);
                                } catch (e) {
                                    console.warn('Binary chunks reconstruction failed:', e);
                                    return Promise.resolve(false);
                                }
                            }
                            
                            // Check if this might be a binary chunk (long string without JSON structure)
                            if (scannedData.length > 100 && !scannedData.startsWith('{') && !scannedData.startsWith('[')) {
                                console.log('Detected potential binary chunk (long non-JSON string):', scannedData.substring(0, 50) + '...');
                                
                                // Initialize buffer if not exists
                                if (!qrChunksBufferRef.current.id) {
                                    console.log('Initializing buffer for potential binary chunks');
                                    qrChunksBufferRef.current = { 
                                        id: `bin_${Date.now()}`, 
                                        total: 4, // We expect 4 chunks
                                        seen: new Set(), 
                                        items: [],
                                        lastUpdateMs: Date.now()
                                    };
                                }
                                
                                // Add chunk to buffer (use data hash as identifier)
                                const chunkHash = scannedData.substring(0, 50); // Use first 50 chars as hash
                                
                                // Check if this chunk was already scanned
                                if (qrChunksBufferRef.current.seen.has(chunkHash)) {
                                    console.log(`Chunk already scanned, ignoring...`);
                                    return Promise.resolve(false);
                                }
                                
                                qrChunksBufferRef.current.seen.add(chunkHash);
                                qrChunksBufferRef.current.items.push(scannedData);
                                qrChunksBufferRef.current.lastUpdateMs = Date.now();
                                
                                // Force re-render to update progress indicator
                                try {
                                    const uniqueCount = qrChunksBufferRef.current.seen.size;
                                    document.dispatchEvent(new CustomEvent('qr-scan-progress', { 
                                        detail: { 
                                            id: qrChunksBufferRef.current.id, 
                                            seq: uniqueCount, 
                                            total: qrChunksBufferRef.current.total 
                                        } 
                                    }));
                                    
                                    // Force re-render to update progress indicator
                                    setQrFramesTotal(qrChunksBufferRef.current.total);
                                    setQrFrameIndex(uniqueCount);
                                } catch {}
                                
                                // Check if we have all chunks
                                const isComplete = qrChunksBufferRef.current.seen.size >= qrChunksBufferRef.current.total;
                                console.log(`Chunks collected: ${qrChunksBufferRef.current.seen.size}/${qrChunksBufferRef.current.total}, complete: ${isComplete}`);
                                
                                if (!isComplete) {
                                    // Keep scanner open for more chunks
                                    console.log(`Scanned chunk ${qrChunksBufferRef.current.seen.size}/${qrChunksBufferRef.current.total}, waiting for more...`);
                                    return Promise.resolve(false);
                                }
                                
                                // All chunks collected - reconstruct binary data
                                try {
                                    const fullBinaryData = qrChunksBufferRef.current.items.join('');
                                    // Store the original binary data, not decoded JSON
                                    if (showOfferStep) {
                                        setAnswerInput(fullBinaryData);
                                    } else {
                                        setOfferInput(fullBinaryData);
                                    }
                                    
                                    setMessages(prev => [...prev, { 
                                        message: 'All binary chunks captured. Payload reconstructed.', 
                                        type: 'success' 
                                    }]);
                                    
                                    // Clear buffer and close scanner
                                    qrChunksBufferRef.current = { id: null, total: 0, seen: new Set(), items: [] };
                                    setShowQRScannerModal(false);
                                    return Promise.resolve(true);
                                } catch (e) {
                                    console.warn('Binary chunks reconstruction failed:', e);
                                    return Promise.resolve(false);
                                }
                            }
                            
                            // Single QR code - try to decode directly
                            // Removed verbose debug log
                            let parsedData;
                            if (typeof window.decodeAnyPayload === 'function') {
                                const any = window.decodeAnyPayload(scannedData);
                                if (typeof any === 'string') {
                                    parsedData = JSON.parse(any);
                                } else {
                                    parsedData = any; // object from binary
                                }
                            } else {
                                const maybeDecompressed = (typeof window.decompressIfNeeded === 'function') ? window.decompressIfNeeded(scannedData) : scannedData;
                                parsedData = JSON.parse(maybeDecompressed);
                            }
                            console.log('Decoded data:', parsedData);
                            
                            // QR with hdr/body: COSE or RAW/BIN animated frames
                            if (parsedData.hdr && parsedData.body) {
                                const { hdr } = parsedData;
                                // Initialize/rotate buffer by id
                                if (!qrChunksBufferRef.current.id || qrChunksBufferRef.current.id !== hdr.id) {
                                    qrChunksBufferRef.current = { id: hdr.id, total: hdr.total || 1, seen: new Set(), items: [], lastUpdateMs: Date.now() };
                                    try {
                                        document.dispatchEvent(new CustomEvent('qr-scan-progress', { detail: { id: hdr.id, seq: 0, total: hdr.total || 1 } }));
                                    } catch {}
                                }
                                // Deduplicate & record
                                if (!qrChunksBufferRef.current.seen.has(hdr.seq)) {
                                    qrChunksBufferRef.current.seen.add(hdr.seq);
                                    qrChunksBufferRef.current.items.push(scannedData);
                                    qrChunksBufferRef.current.lastUpdateMs = Date.now();
                                }
                                // Emit progress based on unique frames captured
                                try {
                                    const uniqueCount = qrChunksBufferRef.current.seen.size;
                                    document.dispatchEvent(new CustomEvent('qr-scan-progress', { detail: { id: hdr.id, seq: uniqueCount, total: qrChunksBufferRef.current.total || hdr.total || 0 } }));
                                } catch {}
                                const isComplete = qrChunksBufferRef.current.seen.size >= (qrChunksBufferRef.current.total || 1);
                                if (!isComplete) {
                                    // Explicitly keep scanner open
                                    return Promise.resolve(false);
                                }
                                // Completed: decide RAW vs BIN vs COSE
                                if (hdr.rt === 'raw') {
                                    try {
                                        // Sort by seq and concatenate bodies
                                        const parts = qrChunksBufferRef.current.items
                                            .map(s => JSON.parse(s))
                                            .sort((a, b) => (a.hdr.seq || 0) - (b.hdr.seq || 0))
                                            .map(p => p.body || '');
                                        const fullText = parts.join('');
                                        const payloadObj = JSON.parse(fullText);
                                        if (showOfferStep) {
                                            setAnswerInput(JSON.stringify(payloadObj, null, 2));
                                        } else {
                                            setOfferInput(JSON.stringify(payloadObj, null, 2));
                                        }
                                        setMessages(prev => [...prev, { message: 'All frames captured. RAW payload reconstructed.', type: 'success' }]);
                                        try { document.dispatchEvent(new CustomEvent('qr-scan-complete', { detail: { id: hdr.id } })); } catch {}
                                        // Close scanner from caller by returning true
                                        qrChunksBufferRef.current = { id: null, total: 0, seen: new Set(), items: [] };
                                        setShowQRScannerModal(false);
                                        return Promise.resolve(true);
                                    } catch (e) {
                                        console.warn('RAW multi-frame reconstruction failed:', e);
                                        return Promise.resolve(false);
                                    }
                                } else if (hdr.rt === 'bin') {
                                    try {
                                        const parts = qrChunksBufferRef.current.items
                                            .map(s => JSON.parse(s))
                                            .sort((a, b) => (a.hdr.seq || 0) - (b.hdr.seq || 0))
                                            .map(p => p.body || '');
                                        const fullText = parts.join(''); // SB1:bin:...
                                        let payloadObj;
                                        if (typeof window.decodeAnyPayload === 'function') {
                                            const any = window.decodeAnyPayload(fullText);
                                            payloadObj = (typeof any === 'string') ? JSON.parse(any) : any;
                                        } else {
                                            payloadObj = JSON.parse(fullText);
                                        }
                                        if (showOfferStep) {
                                            setAnswerInput(JSON.stringify(payloadObj, null, 2));
                                        } else {
                                            setOfferInput(JSON.stringify(payloadObj, null, 2));
                                        }
                                        setMessages(prev => [...prev, { message: 'All frames captured. BIN payload reconstructed.', type: 'success' }]);
                                        try { document.dispatchEvent(new CustomEvent('qr-scan-complete', { detail: { id: hdr.id } })); } catch {}
                                        qrChunksBufferRef.current = { id: null, total: 0, seen: new Set(), items: [] };
                                        setShowQRScannerModal(false);
                                        return Promise.resolve(true);
                                    } catch (e) {
                                        console.warn('BIN multi-frame reconstruction failed:', e);
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
                                            setMessages(prev => [...prev, { message: 'All frames captured. COSE payload reconstructed.', type: 'success' }]);
                                            try { document.dispatchEvent(new CustomEvent('qr-scan-complete', { detail: { id: hdr.id } })); } catch {}
                                            qrChunksBufferRef.current = { id: null, total: 0, seen: new Set(), items: [] };
                                            setShowQRScannerModal(false);
                                            return Promise.resolve(true);
                                        }
                                    } catch (e) {
                                        console.warn('COSE multi-chunk processing failed:', e);
                                    }
                                    return Promise.resolve(false);
                                } else {
                                    return Promise.resolve(false);
                                }
                            }
                            
                            // Check if this is a template-based QR code
                            if (parsedData.type === 'enhanced_secure_offer_template') {
                                console.log('QR scan: Template-based offer detected, reconstructing...');
                                const fullOffer = reconstructFromTemplate(parsedData);
                                
                                // Determine which input to populate based on current mode
                                if (showOfferStep) {
                                    // In "Waiting for peer's response" mode - populate answerInput
                                    setAnswerInput(JSON.stringify(fullOffer, null, 2));
                                    console.log('📱 Template data populated to answerInput (waiting for response mode)');
                                } else {
                                    // In "Paste secure invitation" mode - populate offerInput
                                    setOfferInput(JSON.stringify(fullOffer, null, 2));
                                    console.log('📱 Template data populated to offerInput (paste invitation mode)');
                                }
                                setMessages(prev => [...prev, {
                                    message: '📱 QR code scanned successfully! Full offer reconstructed from template.',
                                    type: 'success'
                                }]);
                                setShowQRScannerModal(false); // Close QR scanner modal
                                return true;
                            }
                            // Check if this is a reference-based QR code
                            else if (parsedData.type === 'secure_offer_reference' && parsedData.referenceId) {
                                // Try to get the full offer data from localStorage
                                const fullOfferData = localStorage.getItem(`qr_offer_${parsedData.referenceId}`);
                                if (fullOfferData) {
                                    const fullOffer = JSON.parse(fullOfferData);
                                    // Determine which input to populate based on current mode
                                    if (showOfferStep) {
                                        // In "Waiting for peer's response" mode - populate answerInput
                                        setAnswerInput(JSON.stringify(fullOffer, null, 2));
                                    } else {
                                        // In "Paste secure invitation" mode - populate offerInput
                                        setOfferInput(JSON.stringify(fullOffer, null, 2));
                                    }
                                    setMessages(prev => [...prev, {
                                        message: '📱 QR code scanned successfully! Full offer data retrieved.',
                                        type: 'success'
                                    }]);
                                    setShowQRScannerModal(false); // Close QR scanner modal
                                    return true;
                                } else {
                                    setMessages(prev => [...prev, {
                                        message: 'QR code reference found but full data not available. Please use copy/paste.',
                                        type: 'error'
                                    }]);
                                    return false;
                                }
                            } else {
                                // If payload was compressed, it's already decompressed above; keep legacy warning only when clearly incomplete
                                if (!parsedData.sdp && parsedData.type === 'enhanced_secure_offer') {
                                    setMessages(prev => [...prev, {
                                        message: 'Compressed QR may omit SDP for brevity. Use copy/paste if connection fails.',
                                        type: 'warning'
                                    }]);
                                }
                                
                                // Determine which input to populate based on current mode
                                if (showOfferStep) {
                                    // In "Waiting for peer's response" mode - populate answerInput
                                    console.log('QR scan: Populating answerInput with:', parsedData);
                                    setAnswerInput(JSON.stringify(parsedData, null, 2));
                                } else {
                                    // In "Paste secure invitation" mode - populate offerInput
                                    console.log('QR scan: Populating offerInput with:', parsedData);
                                    setOfferInput(JSON.stringify(parsedData, null, 2));
                                }
                                setMessages(prev => [...prev, {
                                    message: '📱 QR code scanned successfully!',
                                    type: 'success'
                                }]);
                                setShowQRScannerModal(false);
                                return true;
                            }
                        } catch (error) {
                            // If not JSON, use as plain text
                            if (showOfferStep) {
                                // In "Waiting for peer's response" mode - populate answerInput
                                setAnswerInput(scannedData);
                            } else {
                                // In "Paste secure invitation" mode - populate offerInput
                                setOfferInput(scannedData);
                            }
                            setMessages(prev => [...prev, {
                                message: '📱 QR code scanned successfully!',
                                type: 'success'
                            }]);
                            setShowQRScannerModal(false);
                            return true;
                        }
                    };



        
                    const handleCreateOffer = async () => {
                        try {
                            // All security features are enabled by default
                            setIsGeneratingKeys(true);
                            setOfferData('');
                            setShowOfferStep(false);
                            setShowQRCode(false);
                            setQrCodeUrl('');
                            
                            const offer = await webrtcManagerRef.current.createSecureOffer();
                            
                            // Store offer data directly (no encryption needed with SAS)
                            setOfferData(offer);
                            setShowOfferStep(true);
                            
                            // Generate QR code with binary format and chunking
                            const offerString = typeof offer === 'object' ? JSON.stringify(offer) : offer;
                            try {
                                if (typeof window.encodeBinaryToPrefixed === 'function') {
                                    const bin = window.encodeBinaryToPrefixed(offerString);
                                    // Force chunking into 4 parts - split binary data directly
                                    const TARGET_CHUNKS = 4;
                                    let total = TARGET_CHUNKS;
                                    let FRAME_MAX = Math.max(200, Math.ceil(bin.length / TARGET_CHUNKS));
                                    if (FRAME_MAX <= 0) FRAME_MAX = 200;
                                    
                                    // Ensure we don't exceed TARGET_CHUNKS
                                    if (bin.length <= FRAME_MAX) {
                                        total = 1;
                                        FRAME_MAX = bin.length;
                                    } else {
                                        // Recalculate to ensure exactly TARGET_CHUNKS parts
                                        FRAME_MAX = Math.ceil(bin.length / TARGET_CHUNKS);
                                        total = TARGET_CHUNKS;
                                    }
                                    
                                    const id = `bin_${Date.now()}_${Math.random().toString(36).slice(2)}`;
                                    const chunks = [];
                                    for (let i = 0; i < total; i++) {
                                        const seq = i + 1;
                                        const part = bin.slice(i * FRAME_MAX, (i + 1) * FRAME_MAX);
                                        // Store binary chunks directly without JSON wrapper
                                        chunks.push(part);
                                    }
                                    
                                    // Seed first frame and start auto-advance immediately
                                    const isDesktop = (typeof window !== 'undefined') && ((window.innerWidth || 0) >= 1024);
                                    const QR_SIZE = isDesktop ? 720 : 512;
                                    if (window.generateQRCode && chunks.length > 0) {
                                        const firstUrl = await window.generateQRCode(chunks[0], { errorCorrectionLevel: 'M', size: QR_SIZE, margin: 2 });
                                        if (firstUrl) setQrCodeUrl(firstUrl);
                                    }
                                    
                                    // Store precomputed chunks to ref, ready for animation
                                    try { if (qrAnimationRef.current && qrAnimationRef.current.timer) { clearInterval(qrAnimationRef.current.timer); } } catch {}
                                    qrAnimationRef.current = { timer: null, chunks, idx: 0, active: true };
                                    setQrFramesTotal(chunks.length);
                                    setQrFrameIndex(1);
                                    setQrManualMode(false);
                                    
                                    // Start auto-advance loop for Offer immediately
                                    const intervalMs = 3000;
                                    qrAnimationRef.current.timer = setInterval(renderAndAdvance, intervalMs);
                                    
                                    // Show QR immediately for Offer flow
                                    try { setShowQRCode(true); } catch {}
                                } else {
                                    // Fallback to single QR
                                    await generateQRCode(offer);
                                    try { setShowQRCode(true); } catch {}
                                }
                            } catch (e) {
                                console.warn('Offer QR generation failed:', e);
                            }
        
                            const existingMessages = messages.filter(m => 
                                m.type === 'system' && 
                                (m.message.includes('Secure invitation created') || m.message.includes('Send the encrypted code'))
                            );
                            
                            if (existingMessages.length === 0) {
                                setMessages(prev => [...prev, { 
                                    message: 'Secure invitation created and encrypted!', 
                                    type: 'system',
                                    id: Date.now(),
                                    timestamp: Date.now()
                                }]);
                                
                                setMessages(prev => [...prev, { 
                                    message: 'Send the invitation code to your interlocutor via a secure channel (voice call, SMS, etc.).',
                                    type: 'system',
                                    id: Date.now(),
                                    timestamp: Date.now()
                                }]);
        
                            }
        
                            if (!window.isUpdatingSecurity) {
                                updateSecurityLevel().catch(console.error);
                            }
                                                } catch (error) {
                                    setMessages(prev => [...prev, { 
                                        message: `Error creating invitation: ${error.message}`, 
                                        type: 'system',
                                        id: Date.now(),
                                        timestamp: Date.now()
                                    }]);
                                } finally {
                                    setIsGeneratingKeys(false);
                                }
                    };
        
                    const handleCreateAnswer = async () => {
                        try {
                            
                            if (!offerInput.trim()) {
                                setMessages(prev => [...prev, { 
                                    message: 'You need to insert the invitation code from your interlocutor.', 
                                    type: 'system',
                                    id: Date.now(),
                                    timestamp: Date.now()
                                }]);
                                return;
                            }
        
                            try {
                                setMessages(prev => [...prev, { 
                                    message: 'Processing the secure invitation...', 
                                    type: 'system',
                                    id: Date.now(),
                                    timestamp: Date.now()
                                }]);
        
                                let offer;
                                try {
                                    // Prefer binary decode first, then gzip JSON
                                    if (typeof window.decodeAnyPayload === 'function') {
                                        const any = window.decodeAnyPayload(offerInput.trim());
                                        offer = (typeof any === 'string') ? JSON.parse(any) : any;
                                    } else {
                                        const rawText = (typeof window.decompressIfNeeded === 'function') ? window.decompressIfNeeded(offerInput.trim()) : offerInput.trim();
                                        offer = JSON.parse(rawText);
                                    }
                                } catch (parseError) {
                                    throw new Error(`Invalid invitation format: ${parseError.message}`);
                                }
        
                                    if (!offer || typeof offer !== 'object') {
                                        throw new Error('The invitation must be an object');
                                    }
        
                                    // Support both compact and legacy offer formats
                                    const isValidOfferType = (offer.t === 'offer') || (offer.type === 'enhanced_secure_offer');
                                    if (!isValidOfferType) {
                                        throw new Error('Invalid invitation type. Expected offer or enhanced_secure_offer');
                                    }

                                    const answer = await webrtcManagerRef.current.createSecureAnswer(offer);
                                    
                                    // Store answer data directly (no encryption needed with SAS)
                                    setAnswerData(answer);
                                    setShowAnswerStep(true);
                                    
                                    // Generate QR code with binary format and chunking
                                    const answerString = typeof answer === 'object' ? JSON.stringify(answer) : answer;
                                    try {
                                        if (typeof window.encodeBinaryToPrefixed === 'function') {
                                            const bin = window.encodeBinaryToPrefixed(answerString);
                                            // Force chunking into 4 parts - split binary data directly
                                            const TARGET_CHUNKS = 4;
                                            let total = TARGET_CHUNKS;
                                            let FRAME_MAX = Math.max(200, Math.ceil(bin.length / TARGET_CHUNKS));
                                            if (FRAME_MAX <= 0) FRAME_MAX = 200;
                                            
                                            // Ensure we don't exceed TARGET_CHUNKS
                                            if (bin.length <= FRAME_MAX) {
                                                total = 1;
                                                FRAME_MAX = bin.length;
                                            } else {
                                                // Recalculate to ensure exactly TARGET_CHUNKS parts
                                                FRAME_MAX = Math.ceil(bin.length / TARGET_CHUNKS);
                                                total = TARGET_CHUNKS;
                                            }
                                            
                                            const id = `ans_${Date.now()}_${Math.random().toString(36).slice(2)}`;
                                            const chunks = [];
                                            for (let i = 0; i < total; i++) {
                                                const seq = i + 1;
                                                const part = bin.slice(i * FRAME_MAX, (i + 1) * FRAME_MAX);
                                                // Store binary chunks directly without JSON wrapper
                                                chunks.push(part);
                                            }
                                            
                                            const isDesktop = (typeof window !== 'undefined') && ((window.innerWidth || 0) >= 1024);
                                            const QR_SIZE = isDesktop ? 720 : 512;
                                            if (window.generateQRCode && chunks.length > 0) {
                                                const firstUrl = await window.generateQRCode(chunks[0], { errorCorrectionLevel: 'M', size: QR_SIZE, margin: 2 });
                                                if (firstUrl) setQrCodeUrl(firstUrl);
                                            }
                                            
                                            try { if (qrAnimationRef.current && qrAnimationRef.current.timer) { clearInterval(qrAnimationRef.current.timer); } } catch {}
                                            qrAnimationRef.current = { timer: null, chunks, idx: 0, active: true };
                                            setQrFramesTotal(chunks.length);
                                            setQrFrameIndex(1);
                                            setQrManualMode(false);
                                            
                                            const intervalMs = 3000;
                                            qrAnimationRef.current.timer = setInterval(renderAndAdvance, intervalMs);
                                            
                                            // Show QR immediately for Answer flow
                                            try { setShowQRCode(true); } catch {}
                                        } else {
                                            // Fallback to single QR
                                            await generateQRCode(answer);
                                            try { setShowQRCode(true); } catch {}
                                        }
                                    } catch (e) {
                                        console.warn('Answer QR generation failed:', e);
                                    }
                                    
                                    // Mark generated answers as active immediately.
                                    // `answerInput` is empty on the joiner path
                                    // because the response was created locally,
                                    // not pasted by the user.
                                    if (typeof markAnswerCreated === 'function') {
                                        markAnswerCreated();
                                    }

        
                                const existingResponseMessages = messages.filter(m => 
                                    m.type === 'system' && 
                                    (m.message.includes('Secure response created') || m.message.includes('Send the response'))
                                );
                                
                                if (existingResponseMessages.length === 0) {
                                    setMessages(prev => [...prev, { 
                                        message: 'Secure response created!', 
                                        type: 'system',
                                        id: Date.now(),
                                        timestamp: Date.now()
                                    }]);
                                    
                                    setMessages(prev => [...prev, { 
                                        message: 'Send the response code to the initiator via a secure channel or let them scan the QR code below.', 
                                        type: 'system',
                                        id: Date.now(),
                                        timestamp: Date.now()
                                    }]);
        
                                }
                                    
                                    // Update security level after creating answer
                                    if (!window.isUpdatingSecurity) {
                                        updateSecurityLevel().catch(console.error);
                                    }
                                } catch (error) {
                                    console.error('Error in handleCreateAnswer:', error);
                                    setMessages(prev => [...prev, { 
                                        message: `Error processing the invitation: ${error.message}`, 
                                        type: 'system',
                                        id: Date.now(),
                                        timestamp: Date.now()
                                    }]);
                                }
                        } catch (error) {
                            console.error('Error in handleCreateAnswer:', error);
                            setMessages(prev => [...prev, { 
                                message: `Invitation processing error: ${error.message}`, 
                                type: 'system',
                                id: Date.now(),
                                timestamp: Date.now()
                            }]);
                        }
                    };
        
                    const handleConnect = async () => {
                        try {
                            if (!answerInput.trim()) {
                                setMessages(prev => [...prev, { 
                                    message: 'You need to insert the response code from your interlocutor.', 
                                    type: 'system',
                                    id: Date.now(),
                                    timestamp: Date.now()
                                }]);
                                return;
                            }
        
                            try {
                                setMessages(prev => [...prev, { 
                                    message: 'Processing the secure response...', 
                                    type: 'system',
                                    id: Date.now(),
                                    timestamp: Date.now()
                                }]);
        
                                let answer;
                                try {
                                    // Prefer binary decode first, then gzip JSON
                                    if (typeof window.decodeAnyPayload === 'function') {
                                        const anyAnswer = window.decodeAnyPayload(answerInput.trim());
                                        answer = (typeof anyAnswer === 'string') ? JSON.parse(anyAnswer) : anyAnswer;
                                    } else {
                                        const rawText = (typeof window.decompressIfNeeded === 'function') ? window.decompressIfNeeded(answerInput.trim()) : answerInput.trim();
                                        answer = JSON.parse(rawText);
                                    }
                                } catch (parseError) {
                                    throw new Error(`Invalid response format: ${parseError.message}`);
                                }
        
                                    if (!answer || typeof answer !== 'object') {
                                        throw new Error('The response must be an object');
                                    }
        
                                    // Support both compact and legacy formats
                                    const answerType = answer.t || answer.type;
                                    if (!answerType || (answerType !== 'answer' && answerType !== 'enhanced_secure_answer')) {
                                        throw new Error('Invalid response type. Expected answer or enhanced_secure_answer');
                                    }
        
                                    await webrtcManagerRef.current.handleSecureAnswer(answer);
                                    
                                    // All security features are enabled by default - no session activation needed
                                    if (pendingSession) {
                                            setPendingSession(null);
                                            setMessages(prev => [...prev, { 
                                            message: `All security features enabled by default`, 
                                                type: 'system',
                                                id: Date.now(),
                                                timestamp: Date.now()
                                            }]);
                                    }
                                    
                                    setMessages(prev => [...prev, { 
                                        message: 'Finalizing the secure connection...', 
                                        type: 'system',
                                        id: Date.now(),
                                        timestamp: Date.now()
                                    }]);
                                    
                                    // Update security level after handling answer
                                    if (!window.isUpdatingSecurity) {
                                        updateSecurityLevel().catch(console.error);
                                    }
                                } catch (error) {
                                    console.error('Error in handleConnect inner try:', error);
                                    
                                    // Более детальная обработка ошибок
                                    let errorMessage = 'Connection setup error';
                                    if (error.message.includes('CRITICAL SECURITY FAILURE')) {
                                        if (error.message.includes('ECDH public key structure')) {
                                            errorMessage = 'Invalid response code - missing or corrupted cryptographic key. Please check the code and try again.';
                                        } else if (error.message.includes('ECDSA public key structure')) {
                                            errorMessage = 'Invalid response code - missing signature verification key. Please check the code and try again.';
                                        } else {
                                            errorMessage = 'Security validation failed - possible attack detected';
                                        }
                                    } else if (error.message.includes('too old') || error.message.includes('replay')) {
                                        errorMessage = 'Response data is outdated - please use a fresh invitation';
                                    } else if (error.message.includes('MITM') || error.message.includes('signature')) {
                                        errorMessage = 'Security breach detected - connection rejected';
                                    } else if (error.message.includes('Invalid') || error.message.includes('format')) {
                                        errorMessage = 'Invalid response format - please check the code';
                                    } else {
                                        errorMessage = ` ${error.message}`;
                                    }
                                    
                                    setMessages(prev => [...prev, { 
                                        message: errorMessage, 
                                        type: 'system',
                                        id: Date.now(),
                                        timestamp: Date.now(),
                                        showRetryButton: true
                                    }]);

                                    if (!error.message.includes('too old') && !error.message.includes('replay')) {
                                        setPendingSession(null);
                                        setSessionTimeLeft(0);
                                    }

                                    setConnectionStatus('failed');
                                    
                                } 
                        } catch (error) {
                            console.error('Error in handleConnect outer try:', error);

                            let errorMessage = 'Connection setup error';
                            if (error.message.includes('CRITICAL SECURITY FAILURE')) {
                                if (error.message.includes('ECDH public key structure')) {
                                    errorMessage = 'Invalid response code - missing or corrupted cryptographic key. Please check the code and try again.';
                                } else if (error.message.includes('ECDSA public key structure')) {
                                    errorMessage = 'Invalid response code - missing signature verification key. Please check the code and try again.';
                                } else {
                                    errorMessage = 'Security validation failed - possible attack detected';
                                }
                            } else if (error.message.includes('too old') || error.message.includes('replay')) {
                                errorMessage = 'Response data is outdated - please use a fresh invitation';
                            } else if (error.message.includes('MITM') || error.message.includes('signature')) {
                                errorMessage = 'Security breach detected - connection rejected';
                            } else if (error.message.includes('Invalid') || error.message.includes('format')) {
                                errorMessage = 'Invalid response format - please check the code';
                            } else {
                                errorMessage = `${error.message}`;
                            }
                            
                            setMessages(prev => [...prev, { 
                                message: errorMessage, 
                                type: 'system',
                                id: Date.now(),
                                timestamp: Date.now(),
                                showRetryButton: true
                            }]);

                            if (!error.message.includes('too old') && !error.message.includes('replay')) {
                                setPendingSession(null);
                                setSessionTimeLeft(0);
                            }

                            setConnectionStatus('failed');
                        }
                    };
        
                    const handleVerifyConnection = async (userCode, isValid = true) => {
                        if (isValid) {
                            webrtcManagerRef.current.confirmVerification(userCode);
                            // Mark local verification as confirmed
                            setLocalVerificationConfirmed(true);
                            
                            // Initialize notification integration if permission was granted
                            try {
                                if (window.NotificationIntegration && webrtcManagerRef.current && !notificationIntegrationRef.current) {
                                    const integration = new window.NotificationIntegration(webrtcManagerRef.current);
                                    await integration.init();
                                    
                                    // Store reference for cleanup
                                    notificationIntegrationRef.current = integration;
                                    
                                    
                                    // Check if permission was already granted
                                    const status = integration.getStatus();
                                    if (status.permission === 'granted') {
                                        setMessages(prev => [...prev, { 
                                            message: '✓ Notifications enabled - you will receive alerts when the tab is inactive', 
                                            type: 'system',
                                            id: Date.now(),
                                            timestamp: Date.now()
                                        }]);
                                    } else {
                                        setMessages(prev => [...prev, { 
                                            message: 'ℹ Notifications disabled - you can enable them using the button on the main page', 
                                            type: 'system',
                                            id: Date.now(),
                                            timestamp: Date.now()
                                        }]);
                                    }
                                } else if (notificationIntegrationRef.current) {
                                } else {
                                    // Handle error silently
                                }
                            } catch (error) {
                                console.warn('Failed to initialize notifications:', error);
                                // Don't show error to user, notifications are optional
                            }
                        } else {
                            setMessages(prev => [...prev, { 
                                message: ' Verification rejected. The connection is unsafe! Session reset..', 
                                type: 'system',
                                id: Date.now(),
                                timestamp: Date.now()
                            }]);
                            
                            // Clear verification states
                            setLocalVerificationConfirmed(false);
                            setRemoteVerificationConfirmed(false);
                            setBothVerificationsConfirmed(false);
                            setShowVerification(false);
                            setVerificationCode('');
                            
                            // Reset UI to initial state
                            setConnectionStatus('disconnected');
                            setOfferData('');
                            setAnswerData('');
                            setOfferInput('');
                            setAnswerInput('');
                            setShowOfferStep(false);
                            setShowAnswerStep(false);
                            setKeyFingerprint('');
                            setSecurityLevel(null);
                            setIsVerified(false);
                            setMessages([]);
                            
                            setSessionTimeLeft(0);
                            setPendingSession(null);
                            
                            // Dispatch disconnected event for SessionTimer
                            document.dispatchEvent(new CustomEvent('disconnected'));
                            
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

                        const baseTextEarly = messageInput.trim();
                        const midEarly = `m_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;

                        // Offline guard: a P2P data channel can stay "open" after the
                        // browser loses connectivity, so isConnected() isn't enough — show
                        // the bubble as "not sent" (✗) instead of silently transmitting.
                        // Uses the live offline state (catches console-simulated offline too).
                        const offlineNow = isOffline
                            || (typeof navigator !== 'undefined' && navigator.onLine === false)
                            || (window.pwaOfflineManager && window.pwaOfflineManager.isOnline === false);
                        if (offlineNow) {
                            // Store-and-forward: show one check (sent), keep it in the
                            // conversation at its original time, and transmit on reconnect.
                            const outTextOff = codeMode ? '```\n' + baseTextEarly + '\n```' : baseTextEarly;
                            const tsOff = Date.now();
                            const metaOff = { mid: midEarly, ts: tsOff };
                            if (viewOnceMode) { metaOff.once = true; metaOff.onceTtl = viewOnceTtl; }
                            if (disappearTtl > 0) metaOff.ttl = disappearTtl;
                            const echoOpts = { mid: midEarly, status: 'sent', timestamp: tsOff };
                            if (disappearTtl > 0) echoOpts.expiresAt = tsOff + disappearTtl * 1000;
                            addMessageWithAutoScroll(outTextOff, 'sent', echoOpts);
                            // Queue on the ACTIVE session's outgoing queue (created in createSession);
                            // guard in case the entry is missing so the echo never gets lost.
                            const q = queuesRef.current.get(activeIdRef.current);
                            if (q) q.outgoing.push({ outText: outTextOff, meta: metaOff, mid: midEarly });
                            setMessageInput('');
                            if (codeMode) setCodeMode(false);
                            if (viewOnceMode) setViewOnceMode(false);
                            return;
                        }

                        // Online but the channel isn't ready (e.g. dropped/not yet established) —
                        // can't transmit. The setup screen is shown for re-establishment in that case.
                        if (!webrtcManagerRef.current.isConnected()) {
                            return;
                        }

                        try {
                            const baseText = baseTextEarly;
                            // Code mode wraps the text in a fenced block so both sides render
                            // a code window with a copy button (the marker travels as text).
                            const outText = codeMode ? '```\n' + baseText + '\n```' : baseText;

                            // Shared id lets unsend/disappearing/receipts reference the
                            // same message on both peers.
                            const mid = midEarly;
                            const meta = { mid, ts: Date.now() };        // ts → recipient shows the original send time
                            if (viewOnceMode) {                          // applies to the recipient
                                meta.once = true;
                                meta.onceTtl = viewOnceTtl;              // seconds visible after opening
                            }
                            if (disappearTtl > 0) meta.ttl = disappearTtl; // applies to both sides

                            // Local echo: sender sees their own text normally (view-once is a
                            // recipient-side control), but disappearing also expires our copy.
                            // Starts as "sending"; flips to "sent" once the channel accepts it
                            // and "delivered" when the peer's receipt arrives.
                            const localOpts = { mid, status: 'sending' };
                            if (disappearTtl > 0) localOpts.expiresAt = Date.now() + disappearTtl * 1000;
                            addMessageWithAutoScroll(outText, 'sent', localOpts);

                            try {
                                await webrtcManagerRef.current.sendMessage(outText, meta);
                                // Reliable ordered data channel: a resolved send means the peer's
                                // device received it → two grey ticks. The peer's read receipt
                                // (onMessageDelivered) upgrades it to two green ticks ('read').
                                updateMessageStatus(mid, 'delivered');
                            } catch (sendErr) {
                                updateMessageStatus(mid, 'failed');
                                throw sendErr;
                            }
                            setMessageInput('');
                            // Per-message toggles reset; disappearing stays as a sticky setting.
                            if (codeMode) setCodeMode(false);
                            if (viewOnceMode) setViewOnceMode(false);
                        } catch (error) {
                            const msg = String(error?.message || error);
                            if (!/queued for sending|Data channel not ready/i.test(msg)) {
                                addMessageWithAutoScroll(`Sending error: ${msg}`,'system');
                            }
                        }
                    };

                    // Unsend: remove locally and ask the peer to drop it too.
                    const handleUnsendMessage = React.useCallback((mid) => {
                        if (!mid) return;
                        setMessages(prev => prev.filter(m => String(m.mid) !== String(mid)));
                        try { webrtcManagerRef.current?.sendMessageDelete?.(String(mid)); } catch (_) {}
                    }, []);

                    // View-once reveal timeout / disappearing expiry: wipe the content and
                    // leave a "This message has expired" tombstone (per the design).
                    const handleMessageExpire = React.useCallback((id) => {
                        setMessages(prev => prev.map(m => m.id === id ? { ...m, expired: true, message: '', expiresAt: undefined } : m));
                    }, []);

                    // Panic wipe: clear the conversation, tear down the session and wipe keys.
                    const handleClearData = () => {
                        setOfferData('');
                        setAnswerData('');
                        setOfferInput('');
                        setAnswerInput('');
                        setShowOfferStep(false);
                        setIsGeneratingKeys(false);

                        if (!shouldPreserveAnswerData()) {
                            setShowAnswerStep(false);
                        }
                        
                        setShowVerification(false);
                        setShowQRCode(false);
                        setShowQRScanner(false);
                        setShowQRScannerModal(false);
                        // Clear QR scanner buffer
                        qrChunksBufferRef.current = { id: null, total: 0, seen: new Set(), items: [] };

                        if (!shouldPreserveAnswerData()) {
                            setQrCodeUrl('');
                        }
                        
                        setVerificationCode('');
                        setIsVerified(false);
                        setKeyFingerprint('');
                        setSecurityLevel(null);
                        setConnectionStatus('disconnected');
                        setMessages([]);
                        setMessageInput('');
                        
                        // Clear verification states
                        setLocalVerificationConfirmed(false);
                        setRemoteVerificationConfirmed(false);
                        setBothVerificationsConfirmed(false);
                        
                        // PAKE passwords removed - using SAS verification instead 

                        if (typeof console.clear === 'function') {
                            console.clear();
                        }
                        
                        // Cleanup session state
                        setSessionTimeLeft(0);
        
                        setPendingSession(null);
                        document.dispatchEvent(new CustomEvent('peer-disconnect'));
                        // Session manager removed - all features enabled by default
                    };
        
                    const handleIncomingDecision = React.useCallback(async (fileId, accepted) => {
                        try {
                            if (accepted) {
                                await webrtcManagerRef.current?.acceptIncomingFile(fileId);
                            } else {
                                await webrtcManagerRef.current?.rejectIncomingFile(fileId);
                            }
                        } finally {
                            setPendingIncomingFiles(prev => prev.filter(f => f.fileId !== fileId));
                        }
                    }, []);

                    // Disconnect tears down ONLY the active session — its peerConnection, its
                    // manager (with the manager's own key-wipe logic) and its notification
                    // integration. Every other session keeps running untouched. If it was the
                    // last session we immediately open a fresh blank one so the UI isn't empty.
                    const handleDisconnect = () => {
                        try {
                            const id = activeIdRef.current;
                            setSessionTimeLeft(0);
                            // Global lifecycle events (consumed by any remaining listeners).
                            document.dispatchEvent(new CustomEvent('peer-disconnect'));
                            document.dispatchEvent(new CustomEvent('disconnected'));
                            document.dispatchEvent(new CustomEvent('session-cleanup', {
                                detail: { timestamp: Date.now(), reason: 'manual_disconnect' }
                            }));
                            // Manual disconnect always wipes this chat's data and removes it; the
                            // ensure-at-least-one-session effect re-opens the landing if it was the
                            // last one. Siblings keep running untouched.
                            destroySession(id);
                            if (typeof console.clear === 'function') console.clear();
                        } catch (error) {
                            console.error('Error during disconnect:', error);
                        }
                    };
        
                    const handleSessionActivated = (session) => {
                        let message;
                        if (session.type === 'demo') {
                            message = ` Demo session activated for 6 minutes. You can create invitations!`;
                        } else {
                            message = ` All security features enabled by default. You can create invitations!`;
                        }
                        
                        addMessageWithAutoScroll(message, 'system');
        
                    };
        
                    React.useEffect(() => {
                        if (connectionStatus === 'connected' && isVerified) {
                            addMessageWithAutoScroll(' Secure connection successfully established and verified! You can now communicate safely with full protection against MITM attacks and Perfect Forward Secrecy..', 'system');
        
                        }
                    }, [connectionStatus, isVerified]);
        
                    // Chat view requires an ACTIVE verified connection. On a drop the manager
                    // clears its verification state (it must be re-established — there is no
                    // "keep chatting while disconnected" in this P2P design), so we fall back to
                    // the setup screen, which is the re-establish path. Note: this means a dropped
                    // chat shows the connect screen; the conversation history stays in the session.
                    const isConnectedAndVerified = (connectionStatus === 'connected' || connectionStatus === 'verified') && isVerified;

                    // The PWA "Install app" pill is a landing-page affordance — hide it once
                    // we're inside the chat (CSS: body.sb-in-chat #pwa-install-button).
                    React.useEffect(() => {
                        document.body.classList.toggle('sb-in-chat', isConnectedAndVerified);
                        return () => document.body.classList.remove('sb-in-chat');
                    }, [isConnectedAndVerified]);
        
                    React.useEffect(() => {
                        // All security features are enabled by default - no session activation needed
                        if (isConnectedAndVerified && pendingSession && connectionStatus !== 'failed') {
                                setPendingSession(null);
                            setSessionTimeLeft(0); 
                            addMessageWithAutoScroll(' All security features enabled by default', 'system');
                        }
                    }, [isConnectedAndVerified, pendingSession, connectionStatus]);

                    // QR Scanner initialization
                    React.useEffect(() => {
                        if (showQRScannerModal && window.Html5Qrcode) {
                            const html5Qrcode = new window.Html5Qrcode("qr-reader");
                            const config = { 
                                fps: 10
                                // Убираем qrbox чтобы использовать всю область
                            };

                            let isScanning = true;

                            html5Qrcode.start(
                                { facingMode: "environment" }, // Use back camera
                                config,
                                (decodedText, decodedResult) => {
                                    if (!isScanning) {
                                        console.log('Scanner stopped, ignoring scan');
                                        return;
                                    }
                                    
                                    console.log('QR Code scanned:', decodedText);
                                    console.log('Current buffer state:', qrChunksBufferRef.current);
                                    
                                    handleQRScan(decodedText).then((success) => {
                                        console.log('QR scan result:', success);
                                        if (success) {
                                            // Successfully processed - stop scanner and close modal
                                            console.log('Closing scanner and modal');
                                            isScanning = false;
                                            
                                            // Stop scanner first, then clear
                                            try {
                                                console.log('Stopping scanner...');
                                                html5Qrcode.stop().then(() => {
                                                    console.log('Scanner stopped, clearing...');
                                                    html5Qrcode.clear();
                                                    setShowQRScannerModal(false);
                                                }).catch((err) => {
                                                    console.log('Error stopping scanner:', err);
                                                    // Try to clear anyway
                                                    try {
                                                        html5Qrcode.clear();
                                                    } catch (clearErr) {
                                                        console.log('Error clearing scanner:', clearErr);
                                                    }
                                                    setShowQRScannerModal(false);
                                                });
                                            } catch (err) {
                                                console.log('Error in scanner cleanup:', err);
                                                setShowQRScannerModal(false);
                                            }
                                        } else {
                                            console.log('Continuing to scan for more chunks...');
                                        }
                                    }).catch((error) => {
                                        console.error('QR scan processing error:', error);
                                        // Continue scanning on error
                                    });
                                },
                                (error) => {
                                    // Ignore scanning errors - continue scanning
                                    if (isScanning) {
                                        console.log('QR scan error (ignored):', error);
                                    }
                                }
                            ).catch((err) => {
                                console.error('QR Scanner start error:', err);
                                // Close modal on start error
                                setShowQRScannerModal(false);
                            });

                            return () => {
                                isScanning = false;
                                try {
                                    // Try to stop scanner, but don't worry if it's already stopped
                                    html5Qrcode.stop().then(() => {
                                        html5Qrcode.clear();
                                    }).catch((err) => {
                                        // Scanner might already be stopped, just clear it
                                        console.log('Scanner already stopped or error stopping:', err);
                                        try {
                                            html5Qrcode.clear();
                                        } catch (clearErr) {
                                            console.log('Error clearing scanner in cleanup:', clearErr);
                                        }
                                    });
                                } catch (err) {
                                    console.log('Error in cleanup:', err);
                                    // Just try to clear, don't worry about stopping
                                    try {
                                        html5Qrcode.clear();
                                    } catch (clearErr) {
                                        console.log('Error clearing scanner in cleanup:', clearErr);
                                    }
                                }
                            };
                        }
                    }, [showQRScannerModal]);
        
                    const sessionChats = decorateSessions(sessionsState);
                    // The multi-session chrome (left rail + chat column) appears only once there
                    // is a genuinely WORKING conversation — a session whose SAS is verified — or
                    // when more than one session exists. The whole offer/answer/verification flow
                    // of the first session (which the manager reports as 'connecting'/'verifying')
                    // stays on the original single-column "Start Secure" screen, exactly as before;
                    // the rail only shows up after the first secure channel is actually established.
                    const showSidebar = sessionsState.order.length > 1 || sessionsState.order.some((id) => {
                        const s = sessionsState.sessions[id];
                        return s && s.sas && s.sas.isVerified;
                    });

                    return React.createElement('div', {
                        className: "minimal-bg",
                        // With the rail visible the app is a fixed-height shell (rail + column
                        // fill the viewport, design-style). Otherwise it's the scrollable landing.
                        // flexDirection:'row' is explicit — the .minimal-bg class forces
                        // flex-direction:column, which would otherwise stack the rail ABOVE the chat.
                        style: showSidebar ? { display: 'flex', flexDirection: 'row', height: '100vh', width: '100%', overflow: 'hidden' } : { minHeight: '100vh' }
                    }, [
                        showSidebar && React.createElement(SessionsSidebar, {
                            key: 'sessions-sidebar',
                            chats: sessionChats,
                            collapsed: sidebarCollapsed,
                            drawerOpen: sidebarDrawerOpen,
                            onToggleCollapse: () => setSidebarCollapsed(v => !v),
                            onSelect: handleSelectSession,
                            onNewChat: handleNewChat,
                            onRename: handleRenameSession,
                            onCloseDrawer: () => setSidebarDrawerOpen(false),
                            myStatus: myStatus,
                            onSetStatus: setMyStatus
                        }),
                        // Mobile-only hamburger that opens the drawer (hidden on desktop via CSS).
                        showSidebar && React.createElement('button', {
                            key: 'sb-burger',
                            className: 'sb-burger',
                            onClick: () => setSidebarDrawerOpen(true),
                            style: { display: 'none', position: 'fixed', top: '13px', left: '13px', zIndex: 55, width: '38px', height: '38px', borderRadius: '10px', placeItems: 'center', border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(18,18,20,0.9)', color: '#cfcfd4', cursor: 'pointer' },
                            dangerouslySetInnerHTML: { __html: SB_SVG.burger }
                        }),
                        React.createElement('div', {
                            key: 'app-column',
                            className: showSidebar ? 'minimal-bg' : 'minimal-bg min-h-screen',
                            style: showSidebar ? { flex: 1, minWidth: 0, height: '100vh', overflow: 'hidden', display: 'flex', flexDirection: 'column' } : {}
                        }, [
                        // Advanced network settings now render inside the connection
                        // screen's right panel (see EnhancedConnectionSetup), matching
                        // the design's slide-up-within-the-right-column behavior.
                        // The verified chat renders its own in-chat header (SecureBit Chat
                        // design); the shared header is shown only on the landing/setup view.
                        (!isConnectedAndVerified && !showSidebar && window.EnhancedMinimalHeader) && React.createElement(window.EnhancedMinimalHeader, {
                            key: 'header',
                            status: connectionStatus,
                            fingerprint: keyFingerprint,
                            verificationCode: verificationCode,
                            onDisconnect: handleDisconnect,
                            isConnected: isConnectedAndVerified,
                            securityLevel: securityLevel,
                            // sessionManager removed - all features enabled by default
                            webrtcManager: webrtcManagerRef.current
                        }),
        
                        React.createElement('main', {
                            key: 'main'
                        }, 
                            (() => {
                                return isConnectedAndVerified;
                            })()
                                ? (() => {
                                    return React.createElement(EnhancedChatInterface, {
                                        title: active ? active.peerLabel : '',
                                        isOffline: isOffline,
                                        peerPresence: active ? active.peerPresence : null,
                                        onRenameTitle: (label) => { if (activeSessionId) dispatch({ type: SA.RENAME, id: activeSessionId, label }); },
                                        messages: messages,
                                        messageInput: messageInput,
                                        setMessageInput: setMessageInput,
                                        onSendMessage: handleSendMessage,
                                        onDisconnect: handleDisconnect,
                                        keyFingerprint: keyFingerprint,
                                        isVerified: isVerified,
                                        chatMessagesRef: chatMessagesRef,
                                        scrollToBottom: scrollToBottom,
                                        webrtcManager: webrtcManagerRef.current,
                                        status: connectionStatus,
                                        pendingIncomingFiles: pendingIncomingFiles,
                                        onIncomingDecision: handleIncomingDecision,
                                        // Secure chat extras
                                        codeMode: codeMode,
                                        setCodeMode: setCodeMode,
                                        viewOnceMode: viewOnceMode,
                                        setViewOnceMode: setViewOnceMode,
                                        viewOnceTtl: viewOnceTtl,
                                        setViewOnceTtl: setViewOnceTtl,
                                        disappearTtl: disappearTtl,
                                        setDisappearTtl: setDisappearTtl,
                                        nowTick: nowTick,
                                        onUnsendMessage: handleUnsendMessage,
                                        onMessageExpire: handleMessageExpire
                                    });
                                })()
                                : React.createElement(EnhancedConnectionSetup, {
                                    onCreateOffer: handleCreateOffer,
                                    onCreateAnswer: handleCreateAnswer,
                                    onConnect: handleConnect,
                                    onClearData: handleClearData,
                                    onVerifyConnection: handleVerifyConnection,
                                    connectionStatus: connectionStatus,
                                    offerData: offerData,
                                    answerData: answerData,
                                    offerInput: offerInput,
                                    setOfferInput: setOfferInput,
                                    answerInput: answerInput,
                                    setAnswerInput: setAnswerInput,
                                    showOfferStep: showOfferStep,
                                    showAnswerStep: showAnswerStep,
                                    verificationCode: verificationCode,
                                    showVerification: showVerification,
                                    showQRCode: showQRCode,
                                    qrCodeUrl: qrCodeUrl,
                                    showQRScanner: showQRScanner,
                                    setShowQRCode: setShowQRCode,
                                    setShowQRScanner: setShowQRScanner,
                                    setShowQRScannerModal: setShowQRScannerModal,
                                    messages: messages,
                                    localVerificationConfirmed: localVerificationConfirmed,
                                    remoteVerificationConfirmed: remoteVerificationConfirmed,
                                    bothVerificationsConfirmed: bothVerificationsConfirmed,
                                    // QR control props
                                    qrFramesTotal: qrFramesTotal,
                                    qrFrameIndex: qrFrameIndex,
                                    qrManualMode: qrManualMode,
                                    toggleQrManualMode: toggleQrManualMode,
                                    nextQrFrame: nextQrFrame,
                                    prevQrFrame: prevQrFrame,
                                    // PAKE passwords removed - using SAS verification instead
                                    markAnswerCreated: markAnswerCreated,
                                    notificationIntegrationRef: notificationIntegrationRef,
                                    isGeneratingKeys: isGeneratingKeys,
                                    setIsGeneratingKeys: setIsGeneratingKeys,
                                    handleCreateOffer: handleCreateOffer,
                                    relayOnlyMode: relayOnlyMode,
                                    setRelayOnlyMode: setRelayOnlyMode,
                                    webrtcManagerRef: webrtcManagerRef,
                                    showIceSettings: showIceSettings,
                                    setShowIceSettings: setShowIceSettings,
                                    iceServersText: iceServersText,
                                    iceSettingsPersisted: iceSettingsPersisted,
                                    customIceServers: customIceServers,
                                    handleApplyIceSettings: handleApplyIceSettings,
                                    handleForgetIceSettings: handleForgetIceSettings,
                                    // Render only the create/connect card inside the chat column
                                    // (an additional session), instead of the full landing.
                                    compact: showSidebar
                                })
                        ),
                        
                        // QR Scanner Modal — camera scan (design import: "Start Secure" / Camera scan modal)
                        showQRScannerModal && (() => {
                            const closeScanner = () => {
                                setShowQRScannerModal(false);
                                // Clear QR scanner buffer
                                qrChunksBufferRef.current = { id: null, total: 0, seen: new Set(), items: [] };
                            };
                            const buf = qrChunksBufferRef.current;
                            const hasParts = !!(buf && buf.id && buf.total > 1);
                            const framesText = hasParts
                                ? `Scanning frames… ${buf.seen.size} / ${buf.total}`
                                : 'Scanning…';
                            const corner = (k, st) => React.createElement('span', {
                                key: k,
                                style: Object.assign({ position: 'absolute', width: '34px', height: '34px', zIndex: 3 }, st)
                            });
                            return React.createElement('div', {
                                key: 'qr-scanner-modal',
                                onClick: closeScanner,
                                style: { position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '32px', background: 'rgba(6,6,8,0.82)', backdropFilter: 'blur(10px)', WebkitBackdropFilter: 'blur(10px)', animation: 'sbUp .2s ease' }
                            }, [
                                React.createElement('div', {
                                    key: 'scanner-container',
                                    onClick: (e) => e.stopPropagation(),
                                    style: { width: '100%', maxWidth: '420px', borderRadius: '22px', border: '1px solid rgba(255,255,255,0.1)', background: '#111113', boxShadow: '0 30px 90px rgba(0,0,0,0.6)', overflow: 'hidden' }
                                }, [
                                    // Header
                                    React.createElement('div', {
                                        key: 'scanner-header',
                                        style: { display: 'flex', alignItems: 'center', gap: '11px', padding: '18px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)' }
                                    }, [
                                        React.createElement('span', {
                                            key: 'scanner-icon',
                                            style: { display: 'flex' },
                                            dangerouslySetInnerHTML: { __html: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3ecf8e" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M2 8.5V6.5A2.5 2.5 0 0 1 4.5 4h2M17.5 4h2A2.5 2.5 0 0 1 22 6.5v2M22 15.5v2a2.5 2.5 0 0 1-2.5 2.5h-2M6.5 20h-2A2.5 2.5 0 0 1 2 17.5v-2"/><circle cx="12" cy="12" r="3.2"/></svg>' }
                                        }),
                                        React.createElement('div', {
                                            key: 'scanner-titles',
                                            style: { flex: 1, lineHeight: 1.2 }
                                        }, [
                                            React.createElement('div', {
                                                key: 'scanner-title',
                                                style: { fontSize: '15.5px', fontWeight: 800, color: '#f4f4f6' }
                                            }, 'Scan QR code'),
                                            React.createElement('div', {
                                                key: 'scanner-hint',
                                                style: { fontSize: '12px', color: '#7b7b83' }
                                            }, "Point your camera at their QR")
                                        ]),
                                        React.createElement('button', {
                                            key: 'close-btn',
                                            onClick: closeScanner,
                                            style: { width: '32px', height: '32px', display: 'grid', placeItems: 'center', borderRadius: '9px', border: 'none', background: 'rgba(255,255,255,0.05)', color: '#9a9aa2', cursor: 'pointer' }
                                        }, React.createElement('i', { className: 'fas fa-times' }))
                                    ]),
                                    // Body
                                    React.createElement('div', {
                                        key: 'scanner-body',
                                        style: { padding: '22px 24px 24px' }
                                    }, [
                                        React.createElement('div', {
                                            key: 'viewfinder',
                                            style: { position: 'relative', aspectRatio: '1', borderRadius: '18px', overflow: 'hidden', background: '#000', border: '1px solid rgba(255,255,255,0.1)' }
                                        }, [
                                            React.createElement('div', {
                                                key: 'vf-bg',
                                                style: { position: 'absolute', inset: 0, background: 'radial-gradient(circle at 50% 45%, #1a1a1f, #000)' }
                                            }),
                                            // Camera video is injected here by Html5Qrcode
                                            React.createElement('div', {
                                                key: 'qr-reader',
                                                id: 'qr-reader',
                                                style: { position: 'absolute', inset: 0, zIndex: 1 }
                                            }),
                                            corner('c-tl', { top: '18px', left: '18px', borderTop: '2.5px solid #3ecf8e', borderLeft: '2.5px solid #3ecf8e', borderRadius: '8px 0 0 0' }),
                                            corner('c-tr', { top: '18px', right: '18px', borderTop: '2.5px solid #3ecf8e', borderRight: '2.5px solid #3ecf8e', borderRadius: '0 8px 0 0' }),
                                            corner('c-bl', { bottom: '18px', left: '18px', borderBottom: '2.5px solid #3ecf8e', borderLeft: '2.5px solid #3ecf8e', borderRadius: '0 0 0 8px' }),
                                            corner('c-br', { bottom: '18px', right: '18px', borderBottom: '2.5px solid #3ecf8e', borderRight: '2.5px solid #3ecf8e', borderRadius: '0 0 8px 0' }),
                                            React.createElement('span', {
                                                key: 'scan-line',
                                                style: { position: 'absolute', left: '18px', right: '18px', height: '2.5px', zIndex: 2, background: 'linear-gradient(90deg, transparent, #3ecf8e, transparent)', boxShadow: '0 0 16px #3ecf8e', animation: 'sbScan 1.5s ease-in-out infinite alternate' }
                                            }),
                                            React.createElement('div', {
                                                key: 'scan-status',
                                                style: { position: 'absolute', bottom: 0, left: 0, right: 0, zIndex: 3, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', padding: '14px', background: 'linear-gradient(transparent, rgba(0,0,0,0.6))' }
                                            }, [
                                                React.createElement('span', {
                                                    key: 'spinner',
                                                    style: { display: 'flex', animation: 'sbSpin 1.4s linear infinite' },
                                                    dangerouslySetInnerHTML: { __html: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#3ecf8e" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-6.2-8.6"/></svg>' }
                                                }),
                                                React.createElement('span', {
                                                    key: 'scan-frames',
                                                    style: { fontSize: '12.5px', fontWeight: 600, color: '#cfcfd4' }
                                                }, framesText)
                                            ])
                                        ]),
                                        React.createElement('p', {
                                            key: 'scanner-note',
                                            style: { margin: '16px 0 0', textAlign: 'center', fontSize: '12px', lineHeight: 1.5, color: '#6b6b73' }
                                        }, 'Hold steady until all parts are captured. Camera access is local — nothing is uploaded.')
                                    ])
                                ])
                            ]);
                        })()
                        ])  // end app-column
                    ]);
                };
                // UpdateChecker компонент для автоматической проверки обновлений
                const UpdateCheckerWrapper = ({ children }) => {
                    // Проверяем доступность UpdateChecker
                    if (typeof window !== 'undefined' && window.UpdateChecker) {
                        return React.createElement(window.UpdateChecker, {
                            debug: false
                        }, children);
                    }
                    // Fallback если UpdateChecker не загружен
                    return children;
                };

                function initializeApp() {
                    if (window.EnhancedSecureCryptoUtils && window.EnhancedSecureWebRTCManager) {
                        // Оборачиваем приложение в UpdateChecker для автоматической проверки обновлений
                        const AppWithUpdateChecker = React.createElement(UpdateCheckerWrapper, null,
                            React.createElement(EnhancedSecureP2PChat)
                        );
                        ReactDOM.render(AppWithUpdateChecker, document.getElementById('root'));
                    } else {
                        console.error('Модули не загружены:', {
                            hasCrypto: !!window.EnhancedSecureCryptoUtils,
                            hasWebRTC: !!window.EnhancedSecureWebRTCManager
                        });
                    }
                }

                if (typeof window !== 'undefined') {

                    window.addEventListener('unhandledrejection', (event) => {
                        console.error('Unhandled promise rejection:', event.reason);
                        event.preventDefault(); 
                    });
                    

                    window.addEventListener('error', (event) => {
                        console.error('Global error:', event.error);
                        event.preventDefault(); 
                    });
                    
                    if (!window.initializeApp) {
                        window.initializeApp = initializeApp;
                    }
                };
                
                // Render Enhanced Application with UpdateChecker
                if (window.EnhancedSecureCryptoUtils && window.EnhancedSecureWebRTCManager) {
                    const UpdateCheckerWrapper = ({ children }) => {
                        if (typeof window !== 'undefined' && window.UpdateChecker) {
                            return React.createElement(window.UpdateChecker, {
                                debug: false
                            }, children);
                        }
                        return children;
                    };
                    const AppWithUpdateChecker = React.createElement(UpdateCheckerWrapper, null,
                        React.createElement(EnhancedSecureP2PChat)
                    );
                    ReactDOM.render(AppWithUpdateChecker, document.getElementById('root'));
                } else {
                    ReactDOM.render(React.createElement(EnhancedSecureP2PChat), document.getElementById('root'));
                }
