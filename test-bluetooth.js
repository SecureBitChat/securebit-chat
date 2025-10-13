// src/components/ui/BluetoothKeyTransfer.jsx
var BluetoothKeyTransfer = ({
  webrtcManager,
  onKeyReceived,
  onStatusChange,
  onAutoConnection,
  isVisible = false,
  onClose
}) => {
  const [bluetoothManager, setBluetoothManager] = React.useState(null);
  const [isSupported, setIsSupported] = React.useState(false);
  const [isAvailable, setIsAvailable] = React.useState(false);
  const [isScanning, setIsScanning] = React.useState(false);
  const [isAdvertising, setIsAdvertising] = React.useState(false);
  const [connectedDevices, setConnectedDevices] = React.useState([]);
  const [status, setStatus] = React.useState("idle");
  const [error, setError] = React.useState(null);
  const [logs, setLogs] = React.useState([]);
  React.useEffect(() => {
    if (isVisible && !bluetoothManager) {
      initializeBluetooth();
    }
  }, [isVisible]);
  React.useEffect(() => {
    return () => {
      if (bluetoothManager) {
        bluetoothManager.cleanup();
      }
    };
  }, [bluetoothManager]);
  const initializeBluetooth = async () => {
    try {
      const manager = new window.BluetoothKeyTransfer(
        webrtcManager,
        handleStatusChange,
        handleKeyReceived,
        handleError,
        handleAutoConnection
      );
      setBluetoothManager(manager);
      setTimeout(() => {
        setIsSupported(manager.isSupported);
        setIsAvailable(manager.isAvailable);
      }, 100);
    } catch (error2) {
      console.error("Failed to initialize Bluetooth manager:", error2);
      setError("Failed to initialize Bluetooth: " + error2.message);
    }
  };
  const handleStatusChange = (statusType, data) => {
    setStatus(statusType);
    addLog(`Status: ${statusType}`, data);
    switch (statusType) {
      case "bluetooth_ready":
        setIsSupported(data.supported);
        setIsAvailable(data.available);
        break;
      case "scanning_active":
        setIsScanning(true);
        break;
      case "scanning_stopped":
        setIsScanning(false);
        break;
      case "advertising_active":
        setIsAdvertising(true);
        break;
      case "advertising_stopped":
        setIsAdvertising(false);
        break;
      case "connected":
        setConnectedDevices((prev) => [...prev, {
          id: data.deviceId,
          name: data.deviceName,
          connected: true
        }]);
        break;
    }
    onStatusChange?.(statusType, data);
  };
  const handleKeyReceived = (keyData, deviceId) => {
    addLog("Key received from device", { deviceId });
    onKeyReceived?.(keyData, deviceId);
  };
  const handleError = (error2) => {
    console.error("Bluetooth error:", error2);
    setError(error2.message);
    addLog("Error", error2.message);
  };
  const handleAutoConnection = (connectionData) => {
    console.log("Auto connection completed:", connectionData);
    addLog("Auto Connection Completed", connectionData);
    onAutoConnection?.(connectionData);
  };
  const addLog = (message, data = null) => {
    const timestamp = (/* @__PURE__ */ new Date()).toLocaleTimeString();
    const logEntry = {
      timestamp,
      message,
      data: data ? JSON.stringify(data, null, 2) : null
    };
    setLogs((prev) => [...prev.slice(-9), logEntry]);
  };
  const startScanning = async () => {
    try {
      setError(null);
      await bluetoothManager.startScanning();
    } catch (error2) {
      setError("Failed to start scanning: " + error2.message);
    }
  };
  const stopScanning = async () => {
    try {
      await bluetoothManager.stopScanning();
    } catch (error2) {
      setError("Failed to stop scanning: " + error2.message);
    }
  };
  const startAdvertising = async () => {
    try {
      setError(null);
      if (!webrtcManager || !webrtcManager.ecdhKeyPair) {
        throw new Error("No public key available for advertising");
      }
      await bluetoothManager.startAdvertising(
        webrtcManager.ecdhKeyPair.publicKey,
        "SecureBit Device"
      );
    } catch (error2) {
      setError("Failed to start advertising: " + error2.message);
    }
  };
  const stopAdvertising = async () => {
    try {
      await bluetoothManager.stopAdvertising();
    } catch (error2) {
      setError("Failed to stop advertising: " + error2.message);
    }
  };
  const sendPublicKey = async (deviceId) => {
    try {
      setError(null);
      if (!webrtcManager || !webrtcManager.ecdhKeyPair) {
        throw new Error("No public key available for sending");
      }
      await bluetoothManager.sendPublicKey(
        webrtcManager.ecdhKeyPair.publicKey,
        deviceId
      );
    } catch (error2) {
      setError("Failed to send public key: " + error2.message);
    }
  };
  const clearLogs = () => {
    setLogs([]);
  };
  const startAutoConnection = async (deviceId) => {
    try {
      setError(null);
      await bluetoothManager.startAutoConnection(deviceId);
    } catch (error2) {
      setError("Failed to start auto connection: " + error2.message);
    }
  };
  const startAutoConnectionAsResponder = async (deviceId) => {
    try {
      setError(null);
      await bluetoothManager.startAutoConnectionAsResponder(deviceId);
    } catch (error2) {
      setError("Failed to start auto connection as responder: " + error2.message);
    }
  };
  if (!isVisible) return null;
  return React.createElement("div", {
    className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
  }, [
    React.createElement("div", {
      key: "modal",
      className: "bg-gray-900 rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-hidden"
    }, [
      // Header
      React.createElement("div", {
        key: "header",
        className: "flex items-center justify-between p-6 border-b border-gray-700"
      }, [
        React.createElement("div", {
          key: "title",
          className: "flex items-center space-x-3"
        }, [
          React.createElement("i", {
            key: "icon",
            className: "fas fa-bluetooth text-blue-400 text-xl"
          }),
          React.createElement("h2", {
            key: "text",
            className: "text-xl font-semibold text-white"
          }, "Bluetooth Key Transfer")
        ]),
        React.createElement("button", {
          key: "close",
          onClick: onClose,
          className: "text-gray-400 hover:text-white transition-colors"
        }, [
          React.createElement("i", {
            className: "fas fa-times text-xl"
          })
        ])
      ]),
      // Content
      React.createElement("div", {
        key: "content",
        className: "p-6 space-y-6 overflow-y-auto max-h-[calc(90vh-200px)]"
      }, [
        // Status Section
        React.createElement("div", {
          key: "status",
          className: "space-y-4"
        }, [
          React.createElement("h3", {
            key: "title",
            className: "text-lg font-medium text-white"
          }, "Bluetooth Status"),
          React.createElement("div", {
            key: "indicators",
            className: "grid grid-cols-2 gap-4"
          }, [
            React.createElement("div", {
              key: "support",
              className: "flex items-center space-x-2"
            }, [
              React.createElement("div", {
                className: `w-3 h-3 rounded-full ${isSupported ? "bg-green-500" : "bg-red-500"}`
              }),
              React.createElement("span", {
                className: "text-sm text-gray-300"
              }, "Bluetooth Supported")
            ]),
            React.createElement("div", {
              key: "availability",
              className: "flex items-center space-x-2"
            }, [
              React.createElement("div", {
                className: `w-3 h-3 rounded-full ${isAvailable ? "bg-green-500" : "bg-red-500"}`
              }),
              React.createElement("span", {
                className: "text-sm text-gray-300"
              }, "Bluetooth Available")
            ])
          ])
        ]),
        // Controls Section
        React.createElement("div", {
          key: "controls",
          className: "space-y-4"
        }, [
          React.createElement("h3", {
            key: "title",
            className: "text-lg font-medium text-white"
          }, "Key Exchange"),
          React.createElement("div", {
            key: "buttons",
            className: "grid grid-cols-1 sm:grid-cols-2 gap-4"
          }, [
            // Scanning Controls
            React.createElement("div", {
              key: "scanning",
              className: "space-y-2"
            }, [
              React.createElement("h4", {
                key: "title",
                className: "text-sm font-medium text-gray-300"
              }, "Discover Devices"),
              React.createElement("button", {
                key: "scan",
                onClick: isScanning ? stopScanning : startScanning,
                disabled: !isSupported || !isAvailable,
                className: `w-full px-4 py-2 rounded-lg font-medium transition-colors ${isScanning ? "bg-red-600 hover:bg-red-700 text-white" : "bg-blue-600 hover:bg-blue-700 text-white disabled:bg-gray-600 disabled:cursor-not-allowed"}`
              }, [
                React.createElement("i", {
                  key: "icon",
                  className: `fas ${isScanning ? "fa-stop" : "fa-search"} mr-2`
                }),
                isScanning ? "Stop Scanning" : "Start Scanning"
              ])
            ]),
            // Advertising Controls
            React.createElement("div", {
              key: "advertising",
              className: "space-y-2"
            }, [
              React.createElement("h4", {
                key: "title",
                className: "text-sm font-medium text-gray-300"
              }, "Share Your Key"),
              React.createElement("button", {
                key: "advertise",
                onClick: isAdvertising ? stopAdvertising : startAdvertising,
                disabled: !isSupported || !isAvailable,
                className: `w-full px-4 py-2 rounded-lg font-medium transition-colors ${isAdvertising ? "bg-red-600 hover:bg-red-700 text-white" : "bg-green-600 hover:bg-green-700 text-white disabled:bg-gray-600 disabled:cursor-not-allowed"}`
              }, [
                React.createElement("i", {
                  key: "icon",
                  className: `fas ${isAdvertising ? "fa-stop" : "fa-broadcast-tower"} mr-2`
                }),
                isAdvertising ? "Stop Sharing" : "Start Sharing"
              ])
            ])
          ])
        ]),
        // Connected Devices
        connectedDevices.length > 0 && React.createElement("div", {
          key: "devices",
          className: "space-y-4"
        }, [
          React.createElement("h3", {
            key: "title",
            className: "text-lg font-medium text-white"
          }, "Connected Devices"),
          React.createElement("div", {
            key: "list",
            className: "space-y-2"
          }, connectedDevices.map(
            (device) => React.createElement("div", {
              key: device.id,
              className: "flex items-center justify-between p-3 bg-gray-800 rounded-lg"
            }, [
              React.createElement("div", {
                key: "info",
                className: "flex items-center space-x-3"
              }, [
                React.createElement("i", {
                  key: "icon",
                  className: "fas fa-mobile-alt text-blue-400"
                }),
                React.createElement("span", {
                  key: "name",
                  className: "text-white"
                }, device.name)
              ]),
              React.createElement("div", {
                key: "buttons",
                className: "flex space-x-2"
              }, [
                React.createElement("button", {
                  key: "auto-connect",
                  onClick: () => startAutoConnection(device.id),
                  className: "px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded transition-colors"
                }, "Auto Connect"),
                React.createElement("button", {
                  key: "auto-respond",
                  onClick: () => startAutoConnectionAsResponder(device.id),
                  className: "px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded transition-colors"
                }, "Auto Respond"),
                React.createElement("button", {
                  key: "send",
                  onClick: () => sendPublicKey(device.id),
                  className: "px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors"
                }, "Send Key")
              ])
            ])
          ))
        ]),
        // Error Display
        error && React.createElement("div", {
          key: "error",
          className: "p-4 bg-red-900 border border-red-700 rounded-lg"
        }, [
          React.createElement("div", {
            key: "header",
            className: "flex items-center space-x-2 mb-2"
          }, [
            React.createElement("i", {
              key: "icon",
              className: "fas fa-exclamation-triangle text-red-400"
            }),
            React.createElement("h4", {
              key: "title",
              className: "text-red-400 font-medium"
            }, "Error")
          ]),
          React.createElement("p", {
            key: "message",
            className: "text-red-300 text-sm"
          }, error)
        ]),
        // Logs Section
        React.createElement("div", {
          key: "logs",
          className: "space-y-4"
        }, [
          React.createElement("div", {
            key: "header",
            className: "flex items-center justify-between"
          }, [
            React.createElement("h3", {
              key: "title",
              className: "text-lg font-medium text-white"
            }, "Activity Log"),
            React.createElement("button", {
              key: "clear",
              onClick: clearLogs,
              className: "text-sm text-gray-400 hover:text-white transition-colors"
            }, "Clear")
          ]),
          React.createElement(
            "div",
            {
              key: "log-list",
              className: "bg-gray-800 rounded-lg p-4 max-h-40 overflow-y-auto"
            },
            logs.length === 0 ? React.createElement("p", {
              key: "empty",
              className: "text-gray-400 text-sm text-center"
            }, "No activity yet") : logs.map(
              (log, index) => React.createElement("div", {
                key: index,
                className: "text-xs text-gray-300 mb-1"
              }, [
                React.createElement("span", {
                  key: "time",
                  className: "text-gray-500"
                }, `[${log.timestamp}] `),
                React.createElement("span", {
                  key: "message",
                  className: "text-gray-300"
                }, log.message),
                log.data && React.createElement("pre", {
                  key: "data",
                  className: "text-gray-400 mt-1 ml-4"
                }, log.data)
              ])
            )
          )
        ])
      ]),
      // Footer
      React.createElement("div", {
        key: "footer",
        className: "flex items-center justify-between p-6 border-t border-gray-700"
      }, [
        React.createElement("div", {
          key: "info",
          className: "text-sm text-gray-400"
        }, "Bluetooth key exchange provides secure device-to-device communication"),
        React.createElement("button", {
          key: "close-footer",
          onClick: onClose,
          className: "px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
        }, "Close")
      ])
    ])
  ]);
};
if (typeof window !== "undefined") {
  window.BluetoothKeyTransfer = BluetoothKeyTransfer;
}
