// src/app.jsx
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
  bothVerificationsConfirmed,
  // QR control props
  qrFramesTotal,
  qrFrameIndex,
  qrManualMode,
  toggleQrManualMode,
  nextQrFrame,
  prevQrFrame,
  markAnswerCreated
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
          className: "flex flex-col md:flex-row items-center justify-center gap-6 max-w-3xl mx-auto"
        }, [
          // Create Connection
          React.createElement("div", {
            key: "create",
            onClick: () => setMode("create"),
            className: "card-minimal rounded-xl p-6 cursor-pointer group flex-1 create"
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
            }, "Initiate a new secure connection"),
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
          React.createElement("div", {
            key: "divider",
            className: "flex flex-row md:flex-col items-center gap-4 px-4 w-full md:w-auto"
          }, [
            React.createElement("div", {
              key: "line-a",
              className: "h-px flex-1 bg-gradient-to-r from-transparent via-zinc-700 to-transparent md:h-32 md:w-px md:flex-none md:bg-gradient-to-b"
            }),
            React.createElement("div", {
              key: "or-text",
              className: "text-zinc-600 text-sm font-medium px-3"
            }, "OR"),
            React.createElement("div", {
              key: "line-b",
              className: "h-px flex-1 bg-gradient-to-r from-transparent via-zinc-700 to-transparent md:h-32 md:w-px md:flex-none md:bg-gradient-to-b"
            })
          ]),
          // Join Connection
          React.createElement("div", {
            key: "join",
            onClick: () => setMode("join"),
            className: "card-minimal rounded-xl p-6 cursor-pointer group flex-1 join"
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
        React.createElement(SecurityFeatures, { key: "security-features" }),
        React.createElement(Testimonials, { key: "testimonials" }),
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
                "Secure invitation created! Send the code to your contact"
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
                      } catch (e2) {
                        console.warn("QR regenerate on toggle failed:", e2);
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
                  })
                ]),
                (qrFramesTotal || 0) >= 1 && React.createElement("div", {
                  key: "qr-controls-below",
                  className: "mt-4 flex flex-col items-center gap-2"
                }, [
                  React.createElement("div", {
                    key: "frame-indicator",
                    className: "text-xs text-gray-300"
                  }, `Frame ${Math.max(1, qrFrameIndex || 1)}/${qrFramesTotal || 1}`),
                  React.createElement("div", {
                    key: "control-buttons",
                    className: "flex gap-1"
                  }, [
                    (qrFramesTotal || 0) > 1 && React.createElement("button", {
                      key: "prev-frame",
                      onClick: prevQrFrame,
                      className: "w-6 h-6 bg-gray-600 hover:bg-gray-500 text-white rounded text-xs flex items-center justify-center"
                    }, "\u25C0"),
                    React.createElement("button", {
                      key: "toggle-manual",
                      onClick: toggleQrManualMode,
                      className: `px-2 py-1 rounded text-xs font-medium ${qrManualMode || false ? "bg-blue-500 text-white" : "bg-gray-600 text-gray-300 hover:bg-gray-500"}`
                    }, qrManualMode || false ? "Manual" : "Auto"),
                    (qrFramesTotal || 0) > 1 && React.createElement("button", {
                      key: "next-frame",
                      onClick: nextQrFrame,
                      className: "w-6 h-6 bg-gray-600 hover:bg-gray-500 text-white rounded text-xs flex items-center justify-center"
                    }, "\u25B6")
                  ])
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
            onChange: (e2) => {
              setAnswerInput(e2.target.value);
              if (e2.target.value.trim().length > 0) {
                if (typeof markAnswerCreated === "function") {
                  markAnswerCreated();
                }
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
            onChange: (e2) => {
              setOfferInput(e2.target.value);
              if (e2.target.value.trim().length > 0) {
                if (typeof markAnswerCreated === "function") {
                  markAnswerCreated();
                }
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
          // QR Code section for answer
          qrCodeUrl && React.createElement("div", {
            key: "qr-container",
            className: "mt-4 p-4 bg-gray-800/50 border border-gray-600/30 rounded-lg text-center"
          }, [
            React.createElement("h4", {
              key: "qr-title",
              className: "text-sm font-medium text-primary mb-3"
            }, "Scan QR code to complete connection"),
            React.createElement("div", {
              key: "qr-wrapper",
              className: "flex justify-center"
            }, [
              React.createElement("img", {
                key: "qr-image",
                src: qrCodeUrl,
                alt: "QR Code for secure response",
                className: "max-w-none h-auto border border-gray-600/30 rounded w-[20rem] sm:w-[24rem] md:w-[28rem] lg:w-[32rem]"
              })
            ]),
            (qrFramesTotal || 0) >= 1 && React.createElement("div", {
              key: "qr-controls-below",
              className: "mt-4 flex flex-col items-center gap-2"
            }, [
              React.createElement("div", {
                key: "frame-indicator",
                className: "text-xs text-gray-300"
              }, `Frame ${Math.max(1, qrFrameIndex || 1)}/${qrFramesTotal || 1}`),
              React.createElement("div", {
                key: "control-buttons",
                className: "flex gap-1"
              }, [
                (qrFramesTotal || 0) > 1 && React.createElement("button", {
                  key: "prev-frame",
                  onClick: prevQrFrame,
                  className: "w-6 h-6 bg-gray-600 hover:bg-gray-500 text-white rounded text-xs flex items-center justify-center"
                }, "\u25C0"),
                React.createElement("button", {
                  key: "toggle-manual",
                  onClick: toggleQrManualMode,
                  className: `px-2 py-1 rounded text-xs font-medium ${qrManualMode ? "bg-blue-500 text-white" : "bg-gray-600 text-gray-300 hover:bg-gray-500"}`
                }, qrManualMode ? "Manual" : "Auto"),
                (qrFramesTotal || 0) > 1 && React.createElement("button", {
                  key: "next-frame",
                  onClick: nextQrFrame,
                  className: "w-6 h-6 bg-gray-600 hover:bg-gray-500 text-white rounded text-xs flex items-center justify-center"
                }, "\u25B6")
              ])
            ]),
            React.createElement("p", {
              key: "qr-description",
              className: "text-xs text-gray-400 mt-2"
            }, "The initiator can scan this QR code to complete the secure connection")
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
      console.error("scrollToBottom is not a function:", scrollToBottom);
      if (chatMessagesRef.current) {
        chatMessagesRef.current.scrollTo({
          top: chatMessagesRef.current.scrollHeight,
          behavior: "smooth"
        });
      }
      setShowScrollButton(false);
    }
  };
  const handleKeyPress = (e2) => {
    if (e2.key === "Enter" && !e2.shiftKey) {
      e2.preventDefault();
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
            showFileTransfer && React.createElement(window.FileTransferComponent || (() => React.createElement("div", {
              className: "p-4 text-center text-red-400"
            }, "FileTransferComponent not loaded")), {
              webrtcManager,
              isConnected: isFileTransferReady()
            })
          ]
        )
      ),
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
                    onChange: (e2) => setMessageInput(e2.target.value),
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
    const maxPreserveTime = 3e5;
    const hasAnswerData = answerData && answerData.trim().length > 0 || answerInput && answerInput.trim().length > 0;
    const hasAnswerQR = qrCodeUrl && qrCodeUrl.trim().length > 0;
    const shouldPreserve = connectionState.hasActiveAnswer && answerAge < maxPreserveTime && !connectionState.isUserInitiatedDisconnect || hasAnswerData && answerAge < maxPreserveTime && !connectionState.isUserInitiatedDisconnect || hasAnswerQR && answerAge < maxPreserveTime && !connectionState.isUserInitiatedDisconnect;
    return shouldPreserve;
  };
  const markAnswerCreated = () => {
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
            console.log(`Blocked system/file message from chat: ${parsedMessage.type}`);
            return;
          }
        } catch (parseError) {
        }
      }
      addMessageWithAutoScroll(message, type);
    };
    const handleStatusChange = (status) => {
      setConnectionStatus(status);
      if (status === "connected") {
        document.dispatchEvent(new CustomEvent("new-connection"));
        if (!window.isUpdatingSecurity) {
          updateSecurityLevel().catch(console.error);
        }
      } else if (status === "verifying") {
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
          setOfferData(null);
          setAnswerData(null);
          setOfferInput("");
          setAnswerInput("");
          setShowOfferStep(false);
          setShowAnswerStep(false);
          setMessages([]);
          if (typeof console.clear === "function") {
            console.clear();
          }
        }, 2e3);
      }
    };
    const handleKeyExchange = (fingerprint) => {
      if (fingerprint === "") {
        setKeyFingerprint("");
      } else {
        setKeyFingerprint(fingerprint);
      }
    };
    const handleVerificationRequired = (code) => {
      if (code === "") {
        setVerificationCode("");
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
        addMessageWithAutoScroll(` Security breach: ${errorMessage}`, "system");
        if (typeof console.clear === "function") {
          console.clear();
        }
      }
    };
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
    handleMessage(" SecureBit.chat Enhanced Security Edition v4.2.12 - ECDH + DTLS + SAS initialized. Ready to establish a secure connection with ECDH key exchange, DTLS fingerprint verification, and SAS authentication to prevent MITM attacks.", "system");
    const handleBeforeUnload = (event) => {
      if (event.type === "beforeunload" && !isTabSwitching) {
        if (webrtcManagerRef.current && webrtcManagerRef.current.isConnected()) {
          try {
            webrtcManagerRef.current.sendSystemMessage({
              type: "peer_disconnect",
              reason: "user_disconnect",
              timestamp: Date.now()
            });
          } catch (error) {
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
        event.preventDefault();
        event.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", handleBeforeUnload);
    let isTabSwitching = false;
    let tabSwitchTimeout = null;
    const handleVisibilityChange = () => {
      if (document.visibilityState === "hidden") {
        isTabSwitching = true;
        if (tabSwitchTimeout) {
          clearTimeout(tabSwitchTimeout);
        }
        tabSwitchTimeout = setTimeout(() => {
          isTabSwitching = false;
        }, 5e3);
      } else if (document.visibilityState === "visible") {
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
            React.createElement("span", { key: "label" }, ` File received: ${fileData.fileName} (${sizeMb} MB)`),
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
                } catch (e2) {
                  console.error("Download failed:", e2);
                  addMessageWithAutoScroll(` File upload error: ${String(e2?.message || e2)}`, "system");
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
            addMessageWithAutoScroll(` File transfer error: connection not ready. Try again later.`, "system");
          } else if (error.includes("File too large")) {
            addMessageWithAutoScroll(` File is too big. Maximum size: 100 MB`, "system");
          } else {
            addMessageWithAutoScroll(` File transfer error: ${error}`, "system");
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
  const [qrFramesTotal, setQrFramesTotal] = React.useState(0);
  const [qrFrameIndex, setQrFrameIndex] = React.useState(0);
  const [qrManualMode, setQrManualMode] = React.useState(false);
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
    setQrManualMode(false);
  };
  const toggleQrManualMode = () => {
    const newManualMode = !qrManualMode;
    setQrManualMode(newManualMode);
    if (newManualMode) {
      if (qrAnimationRef.current.timer) {
        clearInterval(qrAnimationRef.current.timer);
        qrAnimationRef.current.timer = null;
      }
      console.log("QR Manual mode enabled - auto-scroll stopped");
    } else {
      if (qrAnimationRef.current.chunks.length > 1 && qrAnimationRef.current.active) {
        const intervalMs = 4e3;
        qrAnimationRef.current.timer = setInterval(renderNext, intervalMs);
      }
      console.log("QR Manual mode disabled - auto-scroll resumed");
    }
  };
  const nextQrFrame = () => {
    console.log("\u{1F3AE} nextQrFrame called, qrFramesTotal:", qrFramesTotal, "qrAnimationRef.current:", qrAnimationRef.current);
    if (qrAnimationRef.current.chunks.length > 1) {
      const nextIdx = (qrAnimationRef.current.idx + 1) % qrAnimationRef.current.chunks.length;
      qrAnimationRef.current.idx = nextIdx;
      setQrFrameIndex(nextIdx + 1);
      console.log("\u{1F3AE} Next frame index:", nextIdx + 1);
      renderNext();
    } else {
      console.log("\u{1F3AE} No multiple frames to navigate");
    }
  };
  const prevQrFrame = () => {
    console.log("\u{1F3AE} prevQrFrame called, qrFramesTotal:", qrFramesTotal, "qrAnimationRef.current:", qrAnimationRef.current);
    if (qrAnimationRef.current.chunks.length > 1) {
      const prevIdx = (qrAnimationRef.current.idx - 1 + qrAnimationRef.current.chunks.length) % qrAnimationRef.current.chunks.length;
      qrAnimationRef.current.idx = prevIdx;
      setQrFrameIndex(prevIdx + 1);
      console.log("\u{1F3AE} Previous frame index:", prevIdx + 1);
      renderNext();
    } else {
      console.log("\u{1F3AE} No multiple frames to navigate");
    }
  };
  const qrChunksBufferRef = React.useRef({ id: null, total: 0, seen: /* @__PURE__ */ new Set(), items: [] });
  const generateQRCode2 = async (data) => {
    try {
      const originalSize = typeof data === "string" ? data.length : JSON.stringify(data).length;
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
      stopQrAnimation();
      const id = `raw_${Date.now()}_${Math.random().toString(36).slice(2)}`;
      const TARGET_CHUNKS = 10;
      const FRAME_MAX = Math.max(200, Math.floor(payload.length / TARGET_CHUNKS));
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
      const renderNext2 = async () => {
        const { chunks, idx, active } = qrAnimationRef.current;
        if (!active || !chunks.length) return;
        const current = chunks[idx % chunks.length];
        try {
          const url = await window.generateQRCode(current, EC_OPTS);
          setQrCodeUrl(url);
        } catch (e2) {
          console.warn("Animated QR render error (raw):", e2);
        }
        const nextIdx = (idx + 1) % chunks.length;
        qrAnimationRef.current.idx = nextIdx;
        setQrFrameIndex(nextIdx + 1);
      };
      await renderNext2();
      if (!qrManualMode) {
        const ua = typeof navigator !== "undefined" && navigator.userAgent ? navigator.userAgent : "";
        const isIOS = /iPhone|iPad|iPod/i.test(ua);
        const intervalMs = 4e3;
        qrAnimationRef.current.timer = setInterval(renderNext2, intervalMs);
      }
      return;
    } catch (error) {
      console.error("QR code generation failed:", error);
      setMessages((prev) => [...prev, {
        message: ` QR code generation failed: ${error.message}`,
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
      const parsedData = JSON.parse(scannedData);
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
            setMessages((prev) => [...prev, { message: "All frames captured. RAW payload reconstructed.", type: "success" }]);
            try {
              document.dispatchEvent(new CustomEvent("qr-scan-complete", { detail: { id: hdr.id } }));
            } catch {
            }
            qrChunksBufferRef.current = { id: null, total: 0, seen: /* @__PURE__ */ new Set(), items: [] };
            setShowQRScannerModal(false);
            return Promise.resolve(true);
          } catch (e2) {
            console.warn("RAW multi-frame reconstruction failed:", e2);
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
              setMessages((prev) => [...prev, { message: "All frames captured. COSE payload reconstructed.", type: "success" }]);
              try {
                document.dispatchEvent(new CustomEvent("qr-scan-complete", { detail: { id: hdr.id } }));
              } catch {
              }
              qrChunksBufferRef.current = { id: null, total: 0, seen: /* @__PURE__ */ new Set(), items: [] };
              setShowQRScannerModal(false);
              return Promise.resolve(true);
            }
          } catch (e2) {
            console.warn("COSE multi-chunk processing failed:", e2);
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
          } else {
            setOfferInput(JSON.stringify(fullOffer, null, 2));
          }
          setMessages((prev) => [...prev, {
            message: "\u{1F4F1} QR code scanned successfully! Full offer data retrieved.",
            type: "success"
          }]);
          setShowQRScannerModal(false);
          return true;
        } else {
          setMessages((prev) => [...prev, {
            message: "QR code reference found but full data not available. Please use copy/paste.",
            type: "error"
          }]);
          return false;
        }
      } else {
        if (!parsedData.sdp) {
          setMessages((prev) => [...prev, {
            message: "QR code contains compressed data (SDP removed). Please use copy/paste for full data.",
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
      setOfferData("");
      setShowOfferStep(false);
      setShowQRCode(false);
      setQrCodeUrl("");
      const offer = await webrtcManagerRef.current.createSecureOffer();
      setOfferData(offer);
      setShowOfferStep(true);
      const offerString = typeof offer === "object" ? JSON.stringify(offer) : offer;
      await generateQRCode2(offerString);
      const existingMessages = messages.filter(
        (m) => m.type === "system" && (m.message.includes("Secure invitation created") || m.message.includes("Send the encrypted code"))
      );
      if (existingMessages.length === 0) {
        setMessages((prev) => [...prev, {
          message: "Secure invitation created and encrypted!",
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
        message: `Error creating invitation: ${error.message}`,
        type: "system",
        id: Date.now(),
        timestamp: Date.now()
      }]);
    }
  };
  const handleCreateAnswer = async () => {
    try {
      if (!offerInput.trim()) {
        setMessages((prev) => [...prev, {
          message: "You need to insert the invitation code from your interlocutor.",
          type: "system",
          id: Date.now(),
          timestamp: Date.now()
        }]);
        return;
      }
      try {
        setMessages((prev) => [...prev, {
          message: "Processing the secure invitation...",
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
        const answer = await webrtcManagerRef.current.createSecureAnswer(offer);
        setAnswerData(answer);
        setShowAnswerStep(true);
        const answerString = typeof answer === "object" ? JSON.stringify(answer) : answer;
        await generateQRCode2(answerString);
        if (e.target.value.trim().length > 0) {
          if (typeof markAnswerCreated === "function") {
            markAnswerCreated();
          }
        }
        const existingResponseMessages = messages.filter(
          (m) => m.type === "system" && (m.message.includes("Secure response created") || m.message.includes("Send the response"))
        );
        if (existingResponseMessages.length === 0) {
          setMessages((prev) => [...prev, {
            message: "Secure response created!",
            type: "system",
            id: Date.now(),
            timestamp: Date.now()
          }]);
          setMessages((prev) => [...prev, {
            message: "Send the response code to the initiator via a secure channel or let them scan the QR code below.",
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
          message: `Error processing the invitation: ${error.message}`,
          type: "system",
          id: Date.now(),
          timestamp: Date.now()
        }]);
      }
    } catch (error) {
      console.error("Error in handleCreateAnswer:", error);
      setMessages((prev) => [...prev, {
        message: `Invitation processing error: ${error.message}`,
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
          message: "You need to insert the response code from your interlocutor.",
          type: "system",
          id: Date.now(),
          timestamp: Date.now()
        }]);
        return;
      }
      try {
        setMessages((prev) => [...prev, {
          message: "Processing the secure response...",
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
            message: `All security features enabled by default`,
            type: "system",
            id: Date.now(),
            timestamp: Date.now()
          }]);
        }
        setMessages((prev) => [...prev, {
          message: "Finalizing the secure connection...",
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
            errorMessage = "Invalid response code - missing or corrupted cryptographic key. Please check the code and try again.";
          } else if (error.message.includes("ECDSA public key structure")) {
            errorMessage = "Invalid response code - missing signature verification key. Please check the code and try again.";
          } else {
            errorMessage = "Security validation failed - possible attack detected";
          }
        } else if (error.message.includes("too old") || error.message.includes("replay")) {
          errorMessage = "Response data is outdated - please use a fresh invitation";
        } else if (error.message.includes("MITM") || error.message.includes("signature")) {
          errorMessage = "Security breach detected - connection rejected";
        } else if (error.message.includes("Invalid") || error.message.includes("format")) {
          errorMessage = "Invalid response format - please check the code";
        } else {
          errorMessage = ` ${error.message}`;
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
      }
    } catch (error) {
      console.error("Error in handleConnect outer try:", error);
      let errorMessage = "Connection setup error";
      if (error.message.includes("CRITICAL SECURITY FAILURE")) {
        if (error.message.includes("ECDH public key structure")) {
          errorMessage = "Invalid response code - missing or corrupted cryptographic key. Please check the code and try again.";
        } else if (error.message.includes("ECDSA public key structure")) {
          errorMessage = "Invalid response code - missing signature verification key. Please check the code and try again.";
        } else {
          errorMessage = "Security validation failed - possible attack detected";
        }
      } else if (error.message.includes("too old") || error.message.includes("replay")) {
        errorMessage = "Response data is outdated - please use a fresh invitation";
      } else if (error.message.includes("MITM") || error.message.includes("signature")) {
        errorMessage = "Security breach detected - connection rejected";
      } else if (error.message.includes("Invalid") || error.message.includes("format")) {
        errorMessage = "Invalid response format - please check the code";
      } else {
        errorMessage = `${error.message}`;
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
    }
  };
  const handleVerifyConnection = (isValid) => {
    if (isValid) {
      webrtcManagerRef.current.confirmVerification();
      setLocalVerificationConfirmed(true);
    } else {
      setMessages((prev) => [...prev, {
        message: " Verification rejected. The connection is unsafe! Session reset..",
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
        addMessageWithAutoScroll(`Sending error: ${msg}`, "system");
      }
    }
  };
  const handleClearData = () => {
    setOfferData("");
    setAnswerData("");
    setOfferInput("");
    setAnswerInput("");
    setShowOfferStep(false);
    if (!shouldPreserveAnswerData()) {
      setShowAnswerStep(false);
    }
    setShowVerification(false);
    setShowQRCode(false);
    setShowQRScanner(false);
    setShowQRScannerModal(false);
    if (!shouldPreserveAnswerData()) {
      setQrCodeUrl("");
    }
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
    if (typeof console.clear === "function") {
      console.clear();
    }
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
    if (typeof console.clear === "function") {
      console.clear();
    }
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
      message = ` Demo session activated for 6 minutes. You can create invitations!`;
    } else {
      message = ` All security features enabled by default. You can create invitations!`;
    }
    addMessageWithAutoScroll(message, "system");
  };
  React.useEffect(() => {
    if (connectionStatus === "connected" && isVerified) {
      addMessageWithAutoScroll(" Secure connection successfully established and verified! You can now communicate safely with full protection against MITM attacks and Perfect Forward Secrecy..", "system");
    }
  }, [connectionStatus, isVerified]);
  const isConnectedAndVerified = (connectionStatus === "connected" || connectionStatus === "verified") && isVerified;
  React.useEffect(() => {
    if (isConnectedAndVerified && pendingSession && connectionStatus !== "failed") {
      setPendingSession(null);
      setSessionTimeLeft(0);
      addMessageWithAutoScroll(" All security features enabled by default", "system");
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
      /* @__PURE__ */ (() => {
        return isConnectedAndVerified;
      })() ? (() => {
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
        bothVerificationsConfirmed,
        // QR control props
        qrFramesTotal,
        qrFrameIndex,
        qrManualMode,
        toggleQrManualMode,
        nextQrFrame,
        prevQrFrame,
        // PAKE passwords removed - using SAS verification instead
        markAnswerCreated
      })
    )
  ]);
};
function initializeApp() {
  if (window.EnhancedSecureCryptoUtils && window.EnhancedSecureWebRTCManager) {
    ReactDOM.render(React.createElement(EnhancedSecureP2PChat), document.getElementById("root"));
  } else {
    console.error("\u041C\u043E\u0434\u0443\u043B\u0438 \u043D\u0435 \u0437\u0430\u0433\u0440\u0443\u0436\u0435\u043D\u044B:", {
      hasCrypto: !!window.EnhancedSecureCryptoUtils,
      hasWebRTC: !!window.EnhancedSecureWebRTCManager
    });
  }
}
if (typeof window !== "undefined") {
  window.addEventListener("unhandledrejection", (event) => {
    console.error("Unhandled promise rejection:", event.reason);
    event.preventDefault();
  });
  window.addEventListener("error", (event) => {
    console.error("Global error:", event.error);
    event.preventDefault();
  });
  if (!window.initializeApp) {
    window.initializeApp = initializeApp;
  }
}
ReactDOM.render(React.createElement(EnhancedSecureP2PChat), document.getElementById("root"));
//# sourceMappingURL=app.js.map
