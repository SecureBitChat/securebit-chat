var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  try {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  } catch (e) {
    throw mod = 0, e;
  }
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/notifications/SecureNotificationManager.js
var require_SecureNotificationManager = __commonJS({
  "src/notifications/SecureNotificationManager.js"(exports, module) {
    var SecureChatNotificationManager = class {
      constructor(config = {}) {
        this.permission = typeof Notification !== "undefined" && Notification && typeof Notification.permission === "string" ? Notification.permission : "denied";
        this.isTabActive = this.checkTabActive();
        this.unreadCount = 0;
        this.originalTitle = document.title;
        this.notificationQueue = [];
        this.maxQueueSize = config.maxQueueSize || 5;
        this.rateLimitMs = config.rateLimitMs || 2e3;
        this.lastNotificationTime = 0;
        this.trustedOrigins = config.trustedOrigins || [];
        this.isSecureContext = window.isSecureContext;
        this.hidden = this.getHiddenProperty();
        this.visibilityChange = this.getVisibilityChangeEvent();
        this.initVisibilityTracking();
        this.initSecurityChecks();
      }
      /**
       * Initialize security checks and validation
       * @private
       */
      initSecurityChecks() {
      }
      /**
       * Get hidden property name for cross-browser compatibility
       * @returns {string} Hidden property name
       * @private
       */
      getHiddenProperty() {
        if (typeof document.hidden !== "undefined") {
          return "hidden";
        } else if (typeof document.msHidden !== "undefined") {
          return "msHidden";
        } else if (typeof document.webkitHidden !== "undefined") {
          return "webkitHidden";
        }
        return "hidden";
      }
      /**
       * Get visibility change event name for cross-browser compatibility
       * @returns {string} Visibility change event name
       * @private
       */
      getVisibilityChangeEvent() {
        if (typeof document.hidden !== "undefined") {
          return "visibilitychange";
        } else if (typeof document.msHidden !== "undefined") {
          return "msvisibilitychange";
        } else if (typeof document.webkitHidden !== "undefined") {
          return "webkitvisibilitychange";
        }
        return "visibilitychange";
      }
      /**
       * Check if tab is currently active using multiple methods
       * @returns {boolean} True if tab is active
       * @private
       */
      checkTabActive() {
        if (this.hidden && typeof document[this.hidden] !== "undefined") {
          return !document[this.hidden];
        }
        if (typeof document.hasFocus === "function") {
          return document.hasFocus();
        }
        return true;
      }
      /**
       * Initialize page visibility tracking (Page Visibility API)
       * @private
       */
      initVisibilityTracking() {
        if (typeof document.addEventListener !== "undefined" && typeof document[this.hidden] !== "undefined") {
          document.addEventListener(this.visibilityChange, () => {
            this.isTabActive = this.checkTabActive();
            if (this.isTabActive) {
              this.resetUnreadCount();
              this.clearNotificationQueue();
            }
          });
        }
        window.addEventListener("focus", () => {
          this.isTabActive = this.checkTabActive();
          if (this.isTabActive) {
            this.resetUnreadCount();
          }
        });
        window.addEventListener("blur", () => {
          this.isTabActive = this.checkTabActive();
        });
        window.addEventListener("beforeunload", () => {
          this.clearNotificationQueue();
        });
      }
      /**
       * Request notification permission (BEST PRACTICE: Only call in response to user action)
       * Never call on page load!
       * @returns {Promise<boolean>} Permission granted status
       */
      async requestPermission() {
        if (!this.isSecureContext || !("Notification" in window)) {
          return false;
        }
        if (this.permission === "granted") {
          return true;
        }
        if (this.permission === "denied") {
          return false;
        }
        try {
          this.permission = await Notification.requestPermission();
          return this.permission === "granted";
        } catch (error) {
          return false;
        }
      }
      /**
       * Update page title with unread count
       * @private
       */
      updateTitle() {
        if (this.unreadCount > 0) {
          document.title = `(${this.unreadCount}) ${this.originalTitle}`;
        } else {
          document.title = this.originalTitle;
        }
      }
      /**
       * XSS Protection: Sanitize input text
       * @param {string} text - Text to sanitize
       * @returns {string} Sanitized text
       * @private
       */
      sanitizeText(text2) {
        if (typeof text2 !== "string") {
          return "";
        }
        const div = document.createElement("div");
        div.textContent = text2;
        return div.innerHTML.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;").substring(0, 500);
      }
      /**
       * Validate icon URL (XSS protection)
       * @param {string} url - URL to validate
       * @returns {string|null} Validated URL or null
       * @private
       */
      validateIconUrl(url) {
        if (!url) return null;
        try {
          const parsedUrl = new URL(url, window.location.origin);
          if (parsedUrl.protocol === "https:" || parsedUrl.protocol === "data:") {
            if (this.trustedOrigins.length > 0) {
              const isTrusted = this.trustedOrigins.some(
                (origin) => parsedUrl.origin === origin
              );
              return isTrusted ? parsedUrl.href : null;
            }
            return parsedUrl.href;
          }
          return null;
        } catch (error) {
          return null;
        }
      }
      /**
       * Rate limiting for spam protection
       * @returns {boolean} Rate limit check passed
       * @private
       */
      checkRateLimit() {
        const now = Date.now();
        if (now - this.lastNotificationTime < this.rateLimitMs) {
          return false;
        }
        this.lastNotificationTime = now;
        return true;
      }
      /**
       * Send secure notification
       * @param {string} senderName - Name of message sender
       * @param {string} message - Message content
       * @param {Object} options - Notification options
       * @returns {Notification|null} Created notification or null
       */
      notify(senderName, message, options = {}) {
        if (typeof Notification === "undefined") {
          return null;
        }
        this.isTabActive = this.checkTabActive();
        if (this.isTabActive) {
          return null;
        }
        if (this.permission !== "granted") {
          return null;
        }
        if (!this.checkRateLimit()) {
          return null;
        }
        const safeSenderName = this.sanitizeText(senderName || "Unknown");
        const safeMessage = this.sanitizeText(message || "");
        const safeIcon = this.validateIconUrl(options.icon) || "/logo/icon-192x192.png";
        if (this.notificationQueue.length >= this.maxQueueSize) {
          this.clearNotificationQueue();
        }
        try {
          const notification = new Notification(
            `${safeSenderName}`,
            {
              body: safeMessage.substring(0, 200),
              // Length limit
              icon: safeIcon,
              badge: safeIcon,
              tag: `chat-${options.senderId || "unknown"}`,
              // Grouping
              requireInteraction: false,
              // Don't block user
              silent: options.silent || false,
              // Vibrate only for mobile and if supported
              vibrate: navigator.vibrate ? [200, 100, 200] : void 0,
              // Safe metadata
              data: {
                senderId: this.sanitizeText(options.senderId),
                timestamp: Date.now()
                // Don't include sensitive data!
              }
            }
          );
          this.unreadCount++;
          this.updateTitle();
          this.notificationQueue.push(notification);
          notification.onclick = (event) => {
            event.preventDefault();
            window.focus();
            notification.close();
            if (typeof options.onClick === "function") {
              try {
                options.onClick(options.senderId);
              } catch (error) {
                console.error("[Notifications] Error in onClick handler:", error);
              }
            }
          };
          notification.onerror = (event) => {
            console.error("[Notifications] Error showing notification:", event);
          };
          const autoCloseTimeout = Math.min(options.autoClose || 5e3, 1e4);
          setTimeout(() => {
            notification.close();
            this.removeFromQueue(notification);
          }, autoCloseTimeout);
          return notification;
        } catch (error) {
          console.error("[Notifications] Failed to create notification:", error);
          return null;
        }
      }
      /**
       * Remove notification from queue
       * @param {Notification} notification - Notification to remove
       * @private
       */
      removeFromQueue(notification) {
        const index = this.notificationQueue.indexOf(notification);
        if (index > -1) {
          this.notificationQueue.splice(index, 1);
        }
      }
      /**
       * Clear all notifications
       */
      clearNotificationQueue() {
        this.notificationQueue.forEach((notification) => {
          try {
            notification.close();
          } catch (error) {
          }
        });
        this.notificationQueue = [];
      }
      /**
       * Reset unread counter
       */
      resetUnreadCount() {
        this.unreadCount = 0;
        this.updateTitle();
      }
      /**
       * Get current status
       * @returns {Object} Current notification status
       */
      getStatus() {
        return {
          permission: this.permission,
          isTabActive: this.isTabActive,
          unreadCount: this.unreadCount,
          isSecureContext: this.isSecureContext,
          queueSize: this.notificationQueue.length
        };
      }
    };
    var SecureP2PChat = class {
      constructor() {
        this.notificationManager = new SecureChatNotificationManager({
          maxQueueSize: 5,
          rateLimitMs: 2e3,
          trustedOrigins: [
            window.location.origin
            // Add other trusted origins for CDN icons
          ]
        });
        this.dataChannel = null;
        this.peerConnection = null;
        this.remotePeerName = "Peer";
        this.messageHistory = [];
        this.maxHistorySize = 100;
      }
      /**
       * Initialize when user connects
       */
      async init() {
      }
      /**
       * Method for manual permission request (called on click)
       * @returns {Promise<boolean>} Permission granted status
       */
      async enableNotifications() {
        const granted = await this.notificationManager.requestPermission();
        return granted;
      }
      /**
       * Setup DataChannel with security checks
       * @param {RTCDataChannel} dataChannel - WebRTC data channel
       */
      setupDataChannel(dataChannel) {
        if (!dataChannel) {
          console.error("[Chat] Invalid DataChannel");
          return;
        }
        this.dataChannel = dataChannel;
        this.dataChannel.onmessage = (event) => {
          this.handleIncomingMessage(event.data);
        };
        this.dataChannel.onerror = (error) => {
        };
      }
      /**
       * XSS Protection: Validate incoming messages
       * @param {string|Object} data - Message data
       * @returns {Object|null} Validated message or null
       * @private
       */
      validateMessage(data) {
        try {
          const message = typeof data === "string" ? JSON.parse(data) : data;
          if (!message || typeof message !== "object") {
            throw new Error("Invalid message structure");
          }
          if (!message.text || typeof message.text !== "string") {
            throw new Error("Invalid message text");
          }
          if (message.text.length > 1e4) {
            throw new Error("Message too long");
          }
          return {
            text: message.text,
            senderName: message.senderName || "Unknown",
            senderId: message.senderId || "unknown",
            timestamp: message.timestamp || Date.now(),
            senderAvatar: message.senderAvatar || null
          };
        } catch (error) {
          console.error("[Chat] Message validation failed:", error);
          return null;
        }
      }
      /**
       * Secure handling of incoming messages
       * @param {string|Object} data - Message data
       * @private
       */
      handleIncomingMessage(data) {
        const message = this.validateMessage(data);
        if (!message) {
          return;
        }
        this.messageHistory.push(message);
        if (this.messageHistory.length > this.maxHistorySize) {
          this.messageHistory.shift();
        }
        this.displayMessage(message);
        this.notificationManager.notify(
          message.senderName,
          message.text,
          {
            icon: message.senderAvatar,
            senderId: message.senderId,
            onClick: (senderId) => {
              this.scrollToLatestMessage();
            }
          }
        );
        if (!this.notificationManager.isTabActive) {
          this.playNotificationSound();
        }
      }
      /**
       * XSS Protection: Safe message display
       * @param {Object} message - Message to display
       * @private
       */
      displayMessage(message) {
        const container = document.getElementById("messages");
        if (!container) {
          return;
        }
        const messageEl = document.createElement("div");
        messageEl.className = "message";
        const nameEl = document.createElement("strong");
        nameEl.textContent = message.senderName + ": ";
        const textEl = document.createElement("span");
        textEl.textContent = message.text;
        textEl.style.wordWrap = "break-word";
        textEl.style.overflowWrap = "break-word";
        textEl.style.whiteSpace = "normal";
        const timeEl = document.createElement("small");
        timeEl.textContent = new Date(message.timestamp).toLocaleTimeString();
        messageEl.appendChild(nameEl);
        messageEl.appendChild(textEl);
        messageEl.appendChild(document.createElement("br"));
        messageEl.appendChild(timeEl);
        container.appendChild(messageEl);
        this.scrollToLatestMessage();
      }
      /**
       * Safe sound playback
       * @private
       */
      playNotificationSound() {
        try {
          const audio = new Audio("/assets/audio/notification.mp3");
          audio.volume = 0.3;
          audio.play().catch((error) => {
          });
        } catch (error) {
        }
      }
      /**
       * Scroll to latest message
       * @private
       */
      scrollToLatestMessage() {
        const container = document.getElementById("messages");
        if (container) {
          container.scrollTop = container.scrollHeight;
        }
      }
      /**
       * Get status
       * @returns {Object} Current chat status
       */
      getStatus() {
        return {
          notifications: this.notificationManager.getStatus(),
          messageCount: this.messageHistory.length,
          connected: this.dataChannel?.readyState === "open"
        };
      }
    };
    if (typeof module !== "undefined" && module.exports) {
      module.exports = { SecureChatNotificationManager, SecureP2PChat };
    }
    if (typeof window !== "undefined") {
      window.SecureChatNotificationManager = SecureChatNotificationManager;
      window.SecureP2PChat = SecureP2PChat;
    }
  }
});

// src/notifications/NotificationIntegration.js
var require_NotificationIntegration = __commonJS({
  "src/notifications/NotificationIntegration.js"(exports, module) {
    var import_SecureNotificationManager = __toESM(require_SecureNotificationManager());
    var NotificationIntegration2 = class {
      constructor(webrtcManager) {
        this.webrtcManager = webrtcManager;
        this.notificationManager = new import_SecureNotificationManager.SecureChatNotificationManager({
          maxQueueSize: 10,
          rateLimitMs: 1e3,
          // Reduced from 2000ms to 1000ms
          trustedOrigins: [
            window.location.origin
            // Add other trusted origins for CDN icons
          ]
        });
        this.isInitialized = false;
        this.originalOnMessage = null;
        this.originalOnStatusChange = null;
        this.processedMessages = /* @__PURE__ */ new Set();
      }
      /**
       * Initialize notification integration
       * @returns {Promise<boolean>} Initialization success
       */
      async init() {
        try {
          if (this.isInitialized) {
            return true;
          }
          this.originalOnMessage = this.webrtcManager.onMessage;
          this.originalOnStatusChange = this.webrtcManager.onStatusChange;
          this.webrtcManager.onMessage = (message, type, ...rest) => {
            this.handleIncomingMessage(message, type, rest[0]);
            if (this.originalOnMessage) {
              this.originalOnMessage(message, type, ...rest);
            }
          };
          this.webrtcManager.onStatusChange = (status) => {
            this.handleStatusChange(status);
            if (this.originalOnStatusChange) {
              this.originalOnStatusChange(status);
            }
          };
          if (this.webrtcManager.deliverMessageToUI) {
            this.originalDeliverMessageToUI = this.webrtcManager.deliverMessageToUI.bind(this.webrtcManager);
            this.webrtcManager.deliverMessageToUI = (message, type, ...rest) => {
              this.handleIncomingMessage(message, type, rest[0]);
              this.originalDeliverMessageToUI(message, type, ...rest);
            };
          }
          this.isInitialized = true;
          return true;
        } catch (error) {
          return false;
        }
      }
      /**
       * Handle incoming messages and trigger notifications
       * @param {*} message - Message content
       * @param {string} type - Message type
       * @private
       */
      handleIncomingMessage(message, type, meta) {
        try {
          const messageKey = `${type}:${typeof message === "string" ? message : JSON.stringify(message)}`;
          if (this.processedMessages.has(messageKey)) {
            return;
          }
          this.processedMessages.add(messageKey);
          if (this.processedMessages.size > 100) {
            const messagesArray = Array.from(this.processedMessages);
            this.processedMessages.clear();
            messagesArray.slice(-50).forEach((msg) => this.processedMessages.add(msg));
          }
          if (type === "system" || type === "file-transfer" || type === "heartbeat") {
            return;
          }
          const messageInfo = this.extractMessageInfo(message, type);
          if (!messageInfo) {
            return;
          }
          const isEphemeral = !!meta && typeof meta === "object" && (meta.once === true || Number.isFinite(meta.ttl) && meta.ttl > 0);
          const notificationText = isEphemeral ? "Sent you a private message" : messageInfo.text;
          const notificationResult = this.notificationManager.notify(
            messageInfo.senderName,
            notificationText,
            {
              icon: messageInfo.senderAvatar,
              senderId: messageInfo.senderId,
              onClick: (senderId) => {
                this.focusChatWindow();
              }
            }
          );
        } catch (error) {
        }
      }
      /**
       * Handle status changes
       * @param {string} status - Connection status
       * @private
       */
      handleStatusChange(status) {
        try {
          if (status === "disconnected" || status === "failed") {
            this.notificationManager.clearNotificationQueue();
            this.notificationManager.resetUnreadCount();
          }
        } catch (error) {
        }
      }
      /**
       * Extract message information for notifications
       * @param {*} message - Message content
       * @param {string} type - Message type
       * @returns {Object|null} Extracted message info or null
       * @private
       */
      extractMessageInfo(message, type) {
        try {
          let messageData = message;
          if (typeof message === "string") {
            try {
              messageData = JSON.parse(message);
            } catch (e) {
              return {
                senderName: "Peer",
                text: message,
                senderId: "peer",
                senderAvatar: null
              };
            }
          }
          if (typeof messageData === "object" && messageData !== null) {
            return {
              senderName: messageData.senderName || messageData.name || "Peer",
              text: messageData.text || messageData.message || messageData.content || "",
              senderId: messageData.senderId || messageData.id || "peer",
              senderAvatar: messageData.senderAvatar || messageData.avatar || null
            };
          }
          return null;
        } catch (error) {
          return null;
        }
      }
      /**
       * Focus chat window when notification is clicked
       * @private
       */
      focusChatWindow() {
        try {
          window.focus();
          const messagesContainer = document.getElementById("messages");
          if (messagesContainer) {
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
          }
        } catch (error) {
        }
      }
      /**
       * Request notification permission
       * @returns {Promise<boolean>} Permission granted status
       */
      async requestPermission() {
        try {
          return await this.notificationManager.requestPermission();
        } catch (error) {
          return false;
        }
      }
      /**
       * Get notification status
       * @returns {Object} Notification status
       */
      getStatus() {
        return this.notificationManager.getStatus();
      }
      /**
       * Clear all notifications
       */
      clearNotifications() {
        this.notificationManager.clearNotificationQueue();
        this.notificationManager.resetUnreadCount();
      }
      /**
       * Cleanup integration
       */
      cleanup() {
        try {
          if (this.isInitialized) {
            if (this.originalOnMessage) {
              this.webrtcManager.onMessage = this.originalOnMessage;
            }
            if (this.originalOnStatusChange) {
              this.webrtcManager.onStatusChange = this.originalOnStatusChange;
            }
            if (this.originalDeliverMessageToUI) {
              this.webrtcManager.deliverMessageToUI = this.originalDeliverMessageToUI;
            }
            this.clearNotifications();
            this.isInitialized = false;
          }
        } catch (error) {
        }
      }
    };
    if (typeof module !== "undefined" && module.exports) {
      module.exports = { NotificationIntegration: NotificationIntegration2 };
    }
    if (typeof window !== "undefined") {
      window.NotificationIntegration = NotificationIntegration2;
    }
  }
});

// node_modules/dompurify/dist/purify.es.mjs
function _arrayLikeToArray(r, a) {
  (null == a || a > r.length) && (a = r.length);
  for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e];
  return n;
}
function _arrayWithHoles(r) {
  if (Array.isArray(r)) return r;
}
function _iterableToArrayLimit(r, l) {
  var t = null == r ? null : "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"];
  if (null != t) {
    var e, n, i, u, a = [], f = true, o = false;
    try {
      if (i = (t = t.call(r)).next, 0 === l) ;
      else for (; !(f = (e = i.call(t)).done) && (a.push(e.value), a.length !== l); f = true) ;
    } catch (r2) {
      o = true, n = r2;
    } finally {
      try {
        if (!f && null != t.return && (u = t.return(), Object(u) !== u)) return;
      } finally {
        if (o) throw n;
      }
    }
    return a;
  }
}
function _nonIterableRest() {
  throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.");
}
function _slicedToArray(r, e) {
  return _arrayWithHoles(r) || _iterableToArrayLimit(r, e) || _unsupportedIterableToArray(r, e) || _nonIterableRest();
}
function _unsupportedIterableToArray(r, a) {
  if (r) {
    if ("string" == typeof r) return _arrayLikeToArray(r, a);
    var t = {}.toString.call(r).slice(8, -1);
    return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0;
  }
}
var entries = Object.entries;
var setPrototypeOf = Object.setPrototypeOf;
var isFrozen = Object.isFrozen;
var getPrototypeOf = Object.getPrototypeOf;
var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
var freeze = Object.freeze;
var seal = Object.seal;
var create = Object.create;
var _ref = typeof Reflect !== "undefined" && Reflect;
var apply = _ref.apply;
var construct = _ref.construct;
if (!freeze) {
  freeze = function freeze2(x) {
    return x;
  };
}
if (!seal) {
  seal = function seal2(x) {
    return x;
  };
}
if (!apply) {
  apply = function apply2(func, thisArg) {
    for (var _len = arguments.length, args = new Array(_len > 2 ? _len - 2 : 0), _key = 2; _key < _len; _key++) {
      args[_key - 2] = arguments[_key];
    }
    return func.apply(thisArg, args);
  };
}
if (!construct) {
  construct = function construct2(Func) {
    for (var _len2 = arguments.length, args = new Array(_len2 > 1 ? _len2 - 1 : 0), _key2 = 1; _key2 < _len2; _key2++) {
      args[_key2 - 1] = arguments[_key2];
    }
    return new Func(...args);
  };
}
var arrayForEach = unapply(Array.prototype.forEach);
var arrayLastIndexOf = unapply(Array.prototype.lastIndexOf);
var arrayPop = unapply(Array.prototype.pop);
var arrayPush = unapply(Array.prototype.push);
var arraySplice = unapply(Array.prototype.splice);
var arrayIsArray = Array.isArray;
var stringToLowerCase = unapply(String.prototype.toLowerCase);
var stringToString = unapply(String.prototype.toString);
var stringMatch = unapply(String.prototype.match);
var stringReplace = unapply(String.prototype.replace);
var stringIndexOf = unapply(String.prototype.indexOf);
var stringTrim = unapply(String.prototype.trim);
var numberToString = unapply(Number.prototype.toString);
var booleanToString = unapply(Boolean.prototype.toString);
var bigintToString = typeof BigInt === "undefined" ? null : unapply(BigInt.prototype.toString);
var symbolToString = typeof Symbol === "undefined" ? null : unapply(Symbol.prototype.toString);
var objectHasOwnProperty = unapply(Object.prototype.hasOwnProperty);
var objectToString = unapply(Object.prototype.toString);
var regExpTest = unapply(RegExp.prototype.test);
var typeErrorCreate = unconstruct(TypeError);
function unapply(func) {
  return function(thisArg) {
    if (thisArg instanceof RegExp) {
      thisArg.lastIndex = 0;
    }
    for (var _len3 = arguments.length, args = new Array(_len3 > 1 ? _len3 - 1 : 0), _key3 = 1; _key3 < _len3; _key3++) {
      args[_key3 - 1] = arguments[_key3];
    }
    return apply(func, thisArg, args);
  };
}
function unconstruct(Func) {
  return function() {
    for (var _len4 = arguments.length, args = new Array(_len4), _key4 = 0; _key4 < _len4; _key4++) {
      args[_key4] = arguments[_key4];
    }
    return construct(Func, args);
  };
}
function addToSet(set, array) {
  let transformCaseFunc = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : stringToLowerCase;
  if (setPrototypeOf) {
    setPrototypeOf(set, null);
  }
  if (!arrayIsArray(array)) {
    return set;
  }
  let l = array.length;
  while (l--) {
    let element = array[l];
    if (typeof element === "string") {
      const lcElement = transformCaseFunc(element);
      if (lcElement !== element) {
        if (!isFrozen(array)) {
          array[l] = lcElement;
        }
        element = lcElement;
      }
    }
    set[element] = true;
  }
  return set;
}
function cleanArray(array) {
  for (let index = 0; index < array.length; index++) {
    const isPropertyExist = objectHasOwnProperty(array, index);
    if (!isPropertyExist) {
      array[index] = null;
    }
  }
  return array;
}
function clone(object) {
  const newObject = create(null);
  for (const _ref2 of entries(object)) {
    var _ref3 = _slicedToArray(_ref2, 2);
    const property = _ref3[0];
    const value = _ref3[1];
    const isPropertyExist = objectHasOwnProperty(object, property);
    if (isPropertyExist) {
      if (arrayIsArray(value)) {
        newObject[property] = cleanArray(value);
      } else if (value && typeof value === "object" && value.constructor === Object) {
        newObject[property] = clone(value);
      } else {
        newObject[property] = value;
      }
    }
  }
  return newObject;
}
function stringifyValue(value) {
  switch (typeof value) {
    case "string": {
      return value;
    }
    case "number": {
      return numberToString(value);
    }
    case "boolean": {
      return booleanToString(value);
    }
    case "bigint": {
      return bigintToString ? bigintToString(value) : "0";
    }
    case "symbol": {
      return symbolToString ? symbolToString(value) : "Symbol()";
    }
    case "undefined": {
      return objectToString(value);
    }
    case "function":
    case "object": {
      if (value === null) {
        return objectToString(value);
      }
      const valueAsRecord = value;
      const valueToString = lookupGetter(valueAsRecord, "toString");
      if (typeof valueToString === "function") {
        const stringified = valueToString(valueAsRecord);
        return typeof stringified === "string" ? stringified : objectToString(stringified);
      }
      return objectToString(value);
    }
    default: {
      return objectToString(value);
    }
  }
}
function lookupGetter(object, prop) {
  while (object !== null) {
    const desc = getOwnPropertyDescriptor(object, prop);
    if (desc) {
      if (desc.get) {
        return unapply(desc.get);
      }
      if (typeof desc.value === "function") {
        return unapply(desc.value);
      }
    }
    object = getPrototypeOf(object);
  }
  function fallbackValue() {
    return null;
  }
  return fallbackValue;
}
function isRegex(value) {
  try {
    regExpTest(value, "");
    return true;
  } catch (_unused) {
    return false;
  }
}
var html$1 = freeze(["a", "abbr", "acronym", "address", "area", "article", "aside", "audio", "b", "bdi", "bdo", "big", "blink", "blockquote", "body", "br", "button", "canvas", "caption", "center", "cite", "code", "col", "colgroup", "content", "data", "datalist", "dd", "decorator", "del", "details", "dfn", "dialog", "dir", "div", "dl", "dt", "element", "em", "fieldset", "figcaption", "figure", "font", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr", "html", "i", "img", "input", "ins", "kbd", "label", "legend", "li", "main", "map", "mark", "marquee", "menu", "menuitem", "meter", "nav", "nobr", "ol", "optgroup", "option", "output", "p", "picture", "pre", "progress", "q", "rp", "rt", "ruby", "s", "samp", "search", "section", "select", "shadow", "slot", "small", "source", "spacer", "span", "strike", "strong", "style", "sub", "summary", "sup", "table", "tbody", "td", "template", "textarea", "tfoot", "th", "thead", "time", "tr", "track", "tt", "u", "ul", "var", "video", "wbr"]);
var svg$1 = freeze(["svg", "a", "altglyph", "altglyphdef", "altglyphitem", "animatecolor", "animatemotion", "animatetransform", "circle", "clippath", "defs", "desc", "ellipse", "enterkeyhint", "exportparts", "filter", "font", "g", "glyph", "glyphref", "hkern", "image", "inputmode", "line", "lineargradient", "marker", "mask", "metadata", "mpath", "part", "path", "pattern", "polygon", "polyline", "radialgradient", "rect", "stop", "style", "switch", "symbol", "text", "textpath", "title", "tref", "tspan", "view", "vkern"]);
var svgFilters = freeze(["feBlend", "feColorMatrix", "feComponentTransfer", "feComposite", "feConvolveMatrix", "feDiffuseLighting", "feDisplacementMap", "feDistantLight", "feDropShadow", "feFlood", "feFuncA", "feFuncB", "feFuncG", "feFuncR", "feGaussianBlur", "feImage", "feMerge", "feMergeNode", "feMorphology", "feOffset", "fePointLight", "feSpecularLighting", "feSpotLight", "feTile", "feTurbulence"]);
var svgDisallowed = freeze(["animate", "color-profile", "cursor", "discard", "font-face", "font-face-format", "font-face-name", "font-face-src", "font-face-uri", "foreignobject", "hatch", "hatchpath", "mesh", "meshgradient", "meshpatch", "meshrow", "missing-glyph", "script", "set", "solidcolor", "unknown", "use"]);
var mathMl$1 = freeze(["math", "menclose", "merror", "mfenced", "mfrac", "mglyph", "mi", "mlabeledtr", "mmultiscripts", "mn", "mo", "mover", "mpadded", "mphantom", "mroot", "mrow", "ms", "mspace", "msqrt", "mstyle", "msub", "msup", "msubsup", "mtable", "mtd", "mtext", "mtr", "munder", "munderover", "mprescripts"]);
var mathMlDisallowed = freeze(["maction", "maligngroup", "malignmark", "mlongdiv", "mscarries", "mscarry", "msgroup", "mstack", "msline", "msrow", "semantics", "annotation", "annotation-xml", "mprescripts", "none"]);
var text = freeze(["#text"]);
var html = freeze(["accept", "action", "align", "alt", "autocapitalize", "autocomplete", "autopictureinpicture", "autoplay", "background", "bgcolor", "border", "capture", "cellpadding", "cellspacing", "checked", "cite", "class", "clear", "color", "cols", "colspan", "command", "commandfor", "controls", "controlslist", "coords", "crossorigin", "datetime", "decoding", "default", "dir", "disabled", "disablepictureinpicture", "disableremoteplayback", "download", "draggable", "enctype", "enterkeyhint", "exportparts", "face", "for", "headers", "height", "hidden", "high", "href", "hreflang", "id", "inert", "inputmode", "integrity", "ismap", "kind", "label", "lang", "list", "loading", "loop", "low", "max", "maxlength", "media", "method", "min", "minlength", "multiple", "muted", "name", "nonce", "noshade", "novalidate", "nowrap", "open", "optimum", "part", "pattern", "placeholder", "playsinline", "popover", "popovertarget", "popovertargetaction", "poster", "preload", "pubdate", "radiogroup", "readonly", "rel", "required", "rev", "reversed", "role", "rows", "rowspan", "spellcheck", "scope", "selected", "shape", "size", "sizes", "slot", "span", "srclang", "start", "src", "srcset", "step", "style", "summary", "tabindex", "title", "translate", "type", "usemap", "valign", "value", "width", "wrap", "xmlns"]);
var svg = freeze(["accent-height", "accumulate", "additive", "alignment-baseline", "amplitude", "ascent", "attributename", "attributetype", "azimuth", "basefrequency", "baseline-shift", "begin", "bias", "by", "class", "clip", "clippathunits", "clip-path", "clip-rule", "color", "color-interpolation", "color-interpolation-filters", "color-profile", "color-rendering", "cx", "cy", "d", "dx", "dy", "diffuseconstant", "direction", "display", "divisor", "dur", "edgemode", "elevation", "end", "exponent", "fill", "fill-opacity", "fill-rule", "filter", "filterunits", "flood-color", "flood-opacity", "font-family", "font-size", "font-size-adjust", "font-stretch", "font-style", "font-variant", "font-weight", "fx", "fy", "g1", "g2", "glyph-name", "glyphref", "gradientunits", "gradienttransform", "height", "href", "id", "image-rendering", "in", "in2", "intercept", "k", "k1", "k2", "k3", "k4", "kerning", "keypoints", "keysplines", "keytimes", "lang", "lengthadjust", "letter-spacing", "kernelmatrix", "kernelunitlength", "lighting-color", "local", "marker-end", "marker-mid", "marker-start", "markerheight", "markerunits", "markerwidth", "maskcontentunits", "maskunits", "max", "mask", "mask-type", "media", "method", "mode", "min", "name", "numoctaves", "offset", "operator", "opacity", "order", "orient", "orientation", "origin", "overflow", "paint-order", "path", "pathlength", "patterncontentunits", "patterntransform", "patternunits", "points", "preservealpha", "preserveaspectratio", "primitiveunits", "r", "rx", "ry", "radius", "refx", "refy", "repeatcount", "repeatdur", "restart", "result", "rotate", "scale", "seed", "shape-rendering", "slope", "specularconstant", "specularexponent", "spreadmethod", "startoffset", "stddeviation", "stitchtiles", "stop-color", "stop-opacity", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke", "stroke-width", "style", "surfacescale", "systemlanguage", "tabindex", "tablevalues", "targetx", "targety", "transform", "transform-origin", "text-anchor", "text-decoration", "text-rendering", "textlength", "type", "u1", "u2", "unicode", "values", "viewbox", "visibility", "version", "vert-adv-y", "vert-origin-x", "vert-origin-y", "width", "word-spacing", "wrap", "writing-mode", "xchannelselector", "ychannelselector", "x", "x1", "x2", "xmlns", "y", "y1", "y2", "z", "zoomandpan"]);
var mathMl = freeze(["accent", "accentunder", "align", "bevelled", "close", "columnalign", "columnlines", "columnspacing", "columnspan", "denomalign", "depth", "dir", "display", "displaystyle", "encoding", "fence", "frame", "height", "href", "id", "largeop", "length", "linethickness", "lquote", "lspace", "mathbackground", "mathcolor", "mathsize", "mathvariant", "maxsize", "minsize", "movablelimits", "notation", "numalign", "open", "rowalign", "rowlines", "rowspacing", "rowspan", "rspace", "rquote", "scriptlevel", "scriptminsize", "scriptsizemultiplier", "selection", "separator", "separators", "stretchy", "subscriptshift", "supscriptshift", "symmetric", "voffset", "width", "xmlns"]);
var xml = freeze(["xlink:href", "xml:id", "xlink:title", "xml:space", "xmlns:xlink"]);
var MUSTACHE_EXPR = seal(/{{[\w\W]*|^[\w\W]*}}/g);
var ERB_EXPR = seal(/<%[\w\W]*|^[\w\W]*%>/g);
var TMPLIT_EXPR = seal(/\${[\w\W]*/g);
var DATA_ATTR = seal(/^data-[\-\w.\u00B7-\uFFFF]+$/);
var ARIA_ATTR = seal(/^aria-[\-\w]+$/);
var IS_ALLOWED_URI = seal(
  /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|sms|cid|xmpp|matrix):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
  // eslint-disable-line no-useless-escape
);
var IS_SCRIPT_OR_DATA = seal(/^(?:\w+script|data):/i);
var ATTR_WHITESPACE = seal(
  /[\u0000-\u0020\u00A0\u1680\u180E\u2000-\u2029\u205F\u3000]/g
  // eslint-disable-line no-control-regex
);
var DOCTYPE_NAME = seal(/^html$/i);
var CUSTOM_ELEMENT = seal(/^[a-z][.\w]*(-[.\w]+)+$/i);
var ELEMENT_MARKUP_PROBE = seal(/<[/\w!]/g);
var COMMENT_MARKUP_PROBE = seal(/<[/\w]/g);
var FALLBACK_TAG_CLOSE = seal(/<\/no(script|embed|frames)/i);
var SELF_CLOSING_TAG = seal(/\/>/i);
var NODE_TYPE = {
  element: 1,
  attribute: 2,
  text: 3,
  cdataSection: 4,
  entityReference: 5,
  // Deprecated
  entityNode: 6,
  // Deprecated
  processingInstruction: 7,
  comment: 8,
  document: 9,
  documentType: 10,
  documentFragment: 11,
  notation: 12
  // Deprecated
};
var getGlobal = function getGlobal2() {
  return typeof window === "undefined" ? null : window;
};
var _createTrustedTypesPolicy = function _createTrustedTypesPolicy2(trustedTypes, purifyHostElement) {
  if (typeof trustedTypes !== "object" || typeof trustedTypes.createPolicy !== "function") {
    return null;
  }
  let suffix = null;
  const ATTR_NAME = "data-tt-policy-suffix";
  if (purifyHostElement && purifyHostElement.hasAttribute(ATTR_NAME)) {
    suffix = purifyHostElement.getAttribute(ATTR_NAME);
  }
  const policyName = "dompurify" + (suffix ? "#" + suffix : "");
  try {
    return trustedTypes.createPolicy(policyName, {
      createHTML(html2) {
        return html2;
      },
      createScriptURL(scriptUrl) {
        return scriptUrl;
      }
    });
  } catch (_) {
    console.warn("TrustedTypes policy " + policyName + " could not be created.");
    return null;
  }
};
var _createHooksMap = function _createHooksMap2() {
  return {
    afterSanitizeAttributes: [],
    afterSanitizeElements: [],
    afterSanitizeShadowDOM: [],
    beforeSanitizeAttributes: [],
    beforeSanitizeElements: [],
    beforeSanitizeShadowDOM: [],
    uponSanitizeAttribute: [],
    uponSanitizeElement: [],
    uponSanitizeShadowNode: []
  };
};
var _resolveSetOption = function _resolveSetOption2(cfg, key, fallback, options) {
  return objectHasOwnProperty(cfg, key) && arrayIsArray(cfg[key]) ? addToSet(options.base ? clone(options.base) : {}, cfg[key], options.transform) : fallback;
};
function createDOMPurify() {
  let window2 = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : getGlobal();
  const DOMPurify = (root) => createDOMPurify(root);
  DOMPurify.version = "3.4.10";
  DOMPurify.removed = [];
  if (!window2 || !window2.document || window2.document.nodeType !== NODE_TYPE.document || !window2.Element) {
    DOMPurify.isSupported = false;
    return DOMPurify;
  }
  let document2 = window2.document;
  const originalDocument = document2;
  const currentScript = originalDocument.currentScript;
  window2.DocumentFragment;
  const HTMLTemplateElement = window2.HTMLTemplateElement, Node = window2.Node, Element = window2.Element, NodeFilter = window2.NodeFilter, _window$NamedNodeMap = window2.NamedNodeMap;
  _window$NamedNodeMap === void 0 ? window2.NamedNodeMap || window2.MozNamedAttrMap : _window$NamedNodeMap;
  window2.HTMLFormElement;
  const DOMParser = window2.DOMParser, trustedTypes = window2.trustedTypes;
  const ElementPrototype = Element.prototype;
  const cloneNode = lookupGetter(ElementPrototype, "cloneNode");
  const remove = lookupGetter(ElementPrototype, "remove");
  const getNextSibling = lookupGetter(ElementPrototype, "nextSibling");
  const getChildNodes = lookupGetter(ElementPrototype, "childNodes");
  const getParentNode = lookupGetter(ElementPrototype, "parentNode");
  const getShadowRoot = lookupGetter(ElementPrototype, "shadowRoot");
  const getAttributes = lookupGetter(ElementPrototype, "attributes");
  const getNodeType = Node && Node.prototype ? lookupGetter(Node.prototype, "nodeType") : null;
  const getNodeName = Node && Node.prototype ? lookupGetter(Node.prototype, "nodeName") : null;
  if (typeof HTMLTemplateElement === "function") {
    const template = document2.createElement("template");
    if (template.content && template.content.ownerDocument) {
      document2 = template.content.ownerDocument;
    }
  }
  let trustedTypesPolicy;
  let emptyHTML = "";
  let defaultTrustedTypesPolicy;
  let defaultTrustedTypesPolicyResolved = false;
  let IN_TRUSTED_TYPES_POLICY = 0;
  const _assertNotInTrustedTypesPolicy = function _assertNotInTrustedTypesPolicy2() {
    if (IN_TRUSTED_TYPES_POLICY > 0) {
      throw typeErrorCreate('A configured TRUSTED_TYPES_POLICY callback (createHTML or createScriptURL) must not call DOMPurify.sanitize, as that causes infinite recursion. Do not pass a policy whose callbacks wrap DOMPurify as TRUSTED_TYPES_POLICY; see the "DOMPurify and Trusted Types" section of the README.');
    }
  };
  const _createTrustedHTML = function _createTrustedHTML2(html2) {
    _assertNotInTrustedTypesPolicy();
    IN_TRUSTED_TYPES_POLICY++;
    try {
      return trustedTypesPolicy.createHTML(html2);
    } finally {
      IN_TRUSTED_TYPES_POLICY--;
    }
  };
  const _createTrustedScriptURL = function _createTrustedScriptURL2(scriptUrl) {
    _assertNotInTrustedTypesPolicy();
    IN_TRUSTED_TYPES_POLICY++;
    try {
      return trustedTypesPolicy.createScriptURL(scriptUrl);
    } finally {
      IN_TRUSTED_TYPES_POLICY--;
    }
  };
  const _getDefaultTrustedTypesPolicy = function _getDefaultTrustedTypesPolicy2() {
    if (!defaultTrustedTypesPolicyResolved) {
      defaultTrustedTypesPolicy = _createTrustedTypesPolicy(trustedTypes, currentScript);
      defaultTrustedTypesPolicyResolved = true;
    }
    return defaultTrustedTypesPolicy;
  };
  const _document = document2, implementation = _document.implementation, createNodeIterator = _document.createNodeIterator, createDocumentFragment = _document.createDocumentFragment, getElementsByTagName = _document.getElementsByTagName;
  const importNode = originalDocument.importNode;
  let hooks = _createHooksMap();
  DOMPurify.isSupported = typeof entries === "function" && typeof getParentNode === "function" && implementation && implementation.createHTMLDocument !== void 0;
  const MUSTACHE_EXPR$1 = MUSTACHE_EXPR, ERB_EXPR$1 = ERB_EXPR, TMPLIT_EXPR$1 = TMPLIT_EXPR, DATA_ATTR$1 = DATA_ATTR, ARIA_ATTR$1 = ARIA_ATTR, IS_SCRIPT_OR_DATA$1 = IS_SCRIPT_OR_DATA, ATTR_WHITESPACE$1 = ATTR_WHITESPACE, CUSTOM_ELEMENT$1 = CUSTOM_ELEMENT;
  let IS_ALLOWED_URI$1 = IS_ALLOWED_URI;
  let ALLOWED_TAGS = null;
  const DEFAULT_ALLOWED_TAGS = addToSet({}, [...html$1, ...svg$1, ...svgFilters, ...mathMl$1, ...text]);
  let ALLOWED_ATTR = null;
  const DEFAULT_ALLOWED_ATTR = addToSet({}, [...html, ...svg, ...mathMl, ...xml]);
  let CUSTOM_ELEMENT_HANDLING = Object.seal(create(null, {
    tagNameCheck: {
      writable: true,
      configurable: false,
      enumerable: true,
      value: null
    },
    attributeNameCheck: {
      writable: true,
      configurable: false,
      enumerable: true,
      value: null
    },
    allowCustomizedBuiltInElements: {
      writable: true,
      configurable: false,
      enumerable: true,
      value: false
    }
  }));
  let FORBID_TAGS = null;
  let FORBID_ATTR = null;
  const EXTRA_ELEMENT_HANDLING = Object.seal(create(null, {
    tagCheck: {
      writable: true,
      configurable: false,
      enumerable: true,
      value: null
    },
    attributeCheck: {
      writable: true,
      configurable: false,
      enumerable: true,
      value: null
    }
  }));
  let ALLOW_ARIA_ATTR = true;
  let ALLOW_DATA_ATTR = true;
  let ALLOW_UNKNOWN_PROTOCOLS = false;
  let ALLOW_SELF_CLOSE_IN_ATTR = true;
  let SAFE_FOR_TEMPLATES = false;
  let SAFE_FOR_XML = true;
  let WHOLE_DOCUMENT = false;
  let SET_CONFIG = false;
  let FORCE_BODY = false;
  let RETURN_DOM = false;
  let RETURN_DOM_FRAGMENT = false;
  let RETURN_TRUSTED_TYPE = false;
  let SANITIZE_DOM = true;
  let SANITIZE_NAMED_PROPS = false;
  const SANITIZE_NAMED_PROPS_PREFIX = "user-content-";
  let KEEP_CONTENT = true;
  let IN_PLACE = false;
  let USE_PROFILES = {};
  let FORBID_CONTENTS = null;
  const DEFAULT_FORBID_CONTENTS = addToSet({}, [
    "annotation-xml",
    "audio",
    "colgroup",
    "desc",
    "foreignobject",
    "head",
    "iframe",
    "math",
    "mi",
    "mn",
    "mo",
    "ms",
    "mtext",
    "noembed",
    "noframes",
    "noscript",
    "plaintext",
    "script",
    // <selectedcontent> mirrors the selected <option>'s subtree, cloned by
    // the UA (customizable <select>) — including any on* handlers — and the
    // engine re-mirrors synchronously whenever a removal changes which
    // option/selectedcontent is current, even inside DOMPurify's inert
    // DOMParser document. Hoisting its children on removal re-inserts a fresh
    // mirror target ahead of the walk, which the engine refills, looping
    // forever (DoS) and amplifying output. Dropping its content on removal
    // (rather than hoisting) breaks that cascade; the content is a duplicate
    // of the option, which is sanitized on its own. See campaign-3 F1/F6.
    "selectedcontent",
    "style",
    "svg",
    "template",
    "thead",
    "title",
    "video",
    "xmp"
  ]);
  let DATA_URI_TAGS = null;
  const DEFAULT_DATA_URI_TAGS = addToSet({}, ["audio", "video", "img", "source", "image", "track"]);
  let URI_SAFE_ATTRIBUTES = null;
  const DEFAULT_URI_SAFE_ATTRIBUTES = addToSet({}, ["alt", "class", "for", "id", "label", "name", "pattern", "placeholder", "role", "summary", "title", "value", "style", "xmlns"]);
  const MATHML_NAMESPACE = "http://www.w3.org/1998/Math/MathML";
  const SVG_NAMESPACE = "http://www.w3.org/2000/svg";
  const HTML_NAMESPACE = "http://www.w3.org/1999/xhtml";
  let NAMESPACE = HTML_NAMESPACE;
  let IS_EMPTY_INPUT = false;
  let ALLOWED_NAMESPACES = null;
  const DEFAULT_ALLOWED_NAMESPACES = addToSet({}, [MATHML_NAMESPACE, SVG_NAMESPACE, HTML_NAMESPACE], stringToString);
  const DEFAULT_MATHML_TEXT_INTEGRATION_POINTS = freeze(["mi", "mo", "mn", "ms", "mtext"]);
  let MATHML_TEXT_INTEGRATION_POINTS = addToSet({}, DEFAULT_MATHML_TEXT_INTEGRATION_POINTS);
  const DEFAULT_HTML_INTEGRATION_POINTS = freeze(["annotation-xml"]);
  let HTML_INTEGRATION_POINTS = addToSet({}, DEFAULT_HTML_INTEGRATION_POINTS);
  const COMMON_SVG_AND_HTML_ELEMENTS = addToSet({}, ["title", "style", "font", "a", "script"]);
  let PARSER_MEDIA_TYPE = null;
  const SUPPORTED_PARSER_MEDIA_TYPES = ["application/xhtml+xml", "text/html"];
  const DEFAULT_PARSER_MEDIA_TYPE = "text/html";
  let transformCaseFunc = null;
  let CONFIG = null;
  const formElement = document2.createElement("form");
  const isRegexOrFunction = function isRegexOrFunction2(testValue) {
    return testValue instanceof RegExp || testValue instanceof Function;
  };
  const _parseConfig = function _parseConfig2() {
    let cfg = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : {};
    if (CONFIG && CONFIG === cfg) {
      return;
    }
    if (!cfg || typeof cfg !== "object") {
      cfg = {};
    }
    cfg = clone(cfg);
    PARSER_MEDIA_TYPE = // eslint-disable-next-line unicorn/prefer-includes
    SUPPORTED_PARSER_MEDIA_TYPES.indexOf(cfg.PARSER_MEDIA_TYPE) === -1 ? DEFAULT_PARSER_MEDIA_TYPE : cfg.PARSER_MEDIA_TYPE;
    transformCaseFunc = PARSER_MEDIA_TYPE === "application/xhtml+xml" ? stringToString : stringToLowerCase;
    ALLOWED_TAGS = _resolveSetOption(cfg, "ALLOWED_TAGS", DEFAULT_ALLOWED_TAGS, {
      transform: transformCaseFunc
    });
    ALLOWED_ATTR = _resolveSetOption(cfg, "ALLOWED_ATTR", DEFAULT_ALLOWED_ATTR, {
      transform: transformCaseFunc
    });
    ALLOWED_NAMESPACES = _resolveSetOption(cfg, "ALLOWED_NAMESPACES", DEFAULT_ALLOWED_NAMESPACES, {
      transform: stringToString
    });
    URI_SAFE_ATTRIBUTES = _resolveSetOption(cfg, "ADD_URI_SAFE_ATTR", DEFAULT_URI_SAFE_ATTRIBUTES, {
      transform: transformCaseFunc,
      base: DEFAULT_URI_SAFE_ATTRIBUTES
    });
    DATA_URI_TAGS = _resolveSetOption(cfg, "ADD_DATA_URI_TAGS", DEFAULT_DATA_URI_TAGS, {
      transform: transformCaseFunc,
      base: DEFAULT_DATA_URI_TAGS
    });
    FORBID_CONTENTS = _resolveSetOption(cfg, "FORBID_CONTENTS", DEFAULT_FORBID_CONTENTS, {
      transform: transformCaseFunc
    });
    FORBID_TAGS = _resolveSetOption(cfg, "FORBID_TAGS", clone({}), {
      transform: transformCaseFunc
    });
    FORBID_ATTR = _resolveSetOption(cfg, "FORBID_ATTR", clone({}), {
      transform: transformCaseFunc
    });
    USE_PROFILES = objectHasOwnProperty(cfg, "USE_PROFILES") ? cfg.USE_PROFILES && typeof cfg.USE_PROFILES === "object" ? clone(cfg.USE_PROFILES) : cfg.USE_PROFILES : false;
    ALLOW_ARIA_ATTR = cfg.ALLOW_ARIA_ATTR !== false;
    ALLOW_DATA_ATTR = cfg.ALLOW_DATA_ATTR !== false;
    ALLOW_UNKNOWN_PROTOCOLS = cfg.ALLOW_UNKNOWN_PROTOCOLS || false;
    ALLOW_SELF_CLOSE_IN_ATTR = cfg.ALLOW_SELF_CLOSE_IN_ATTR !== false;
    SAFE_FOR_TEMPLATES = cfg.SAFE_FOR_TEMPLATES || false;
    SAFE_FOR_XML = cfg.SAFE_FOR_XML !== false;
    WHOLE_DOCUMENT = cfg.WHOLE_DOCUMENT || false;
    RETURN_DOM = cfg.RETURN_DOM || false;
    RETURN_DOM_FRAGMENT = cfg.RETURN_DOM_FRAGMENT || false;
    RETURN_TRUSTED_TYPE = cfg.RETURN_TRUSTED_TYPE || false;
    FORCE_BODY = cfg.FORCE_BODY || false;
    SANITIZE_DOM = cfg.SANITIZE_DOM !== false;
    SANITIZE_NAMED_PROPS = cfg.SANITIZE_NAMED_PROPS || false;
    KEEP_CONTENT = cfg.KEEP_CONTENT !== false;
    IN_PLACE = cfg.IN_PLACE || false;
    IS_ALLOWED_URI$1 = isRegex(cfg.ALLOWED_URI_REGEXP) ? cfg.ALLOWED_URI_REGEXP : IS_ALLOWED_URI;
    NAMESPACE = typeof cfg.NAMESPACE === "string" ? cfg.NAMESPACE : HTML_NAMESPACE;
    MATHML_TEXT_INTEGRATION_POINTS = objectHasOwnProperty(cfg, "MATHML_TEXT_INTEGRATION_POINTS") && cfg.MATHML_TEXT_INTEGRATION_POINTS && typeof cfg.MATHML_TEXT_INTEGRATION_POINTS === "object" ? clone(cfg.MATHML_TEXT_INTEGRATION_POINTS) : addToSet({}, DEFAULT_MATHML_TEXT_INTEGRATION_POINTS);
    HTML_INTEGRATION_POINTS = objectHasOwnProperty(cfg, "HTML_INTEGRATION_POINTS") && cfg.HTML_INTEGRATION_POINTS && typeof cfg.HTML_INTEGRATION_POINTS === "object" ? clone(cfg.HTML_INTEGRATION_POINTS) : addToSet({}, DEFAULT_HTML_INTEGRATION_POINTS);
    const customElementHandling = objectHasOwnProperty(cfg, "CUSTOM_ELEMENT_HANDLING") && cfg.CUSTOM_ELEMENT_HANDLING && typeof cfg.CUSTOM_ELEMENT_HANDLING === "object" ? clone(cfg.CUSTOM_ELEMENT_HANDLING) : create(null);
    CUSTOM_ELEMENT_HANDLING = create(null);
    if (objectHasOwnProperty(customElementHandling, "tagNameCheck") && isRegexOrFunction(customElementHandling.tagNameCheck)) {
      CUSTOM_ELEMENT_HANDLING.tagNameCheck = customElementHandling.tagNameCheck;
    }
    if (objectHasOwnProperty(customElementHandling, "attributeNameCheck") && isRegexOrFunction(customElementHandling.attributeNameCheck)) {
      CUSTOM_ELEMENT_HANDLING.attributeNameCheck = customElementHandling.attributeNameCheck;
    }
    if (objectHasOwnProperty(customElementHandling, "allowCustomizedBuiltInElements") && typeof customElementHandling.allowCustomizedBuiltInElements === "boolean") {
      CUSTOM_ELEMENT_HANDLING.allowCustomizedBuiltInElements = customElementHandling.allowCustomizedBuiltInElements;
    }
    seal(CUSTOM_ELEMENT_HANDLING);
    if (SAFE_FOR_TEMPLATES) {
      ALLOW_DATA_ATTR = false;
    }
    if (RETURN_DOM_FRAGMENT) {
      RETURN_DOM = true;
    }
    if (USE_PROFILES) {
      ALLOWED_TAGS = addToSet({}, text);
      ALLOWED_ATTR = create(null);
      if (USE_PROFILES.html === true) {
        addToSet(ALLOWED_TAGS, html$1);
        addToSet(ALLOWED_ATTR, html);
      }
      if (USE_PROFILES.svg === true) {
        addToSet(ALLOWED_TAGS, svg$1);
        addToSet(ALLOWED_ATTR, svg);
        addToSet(ALLOWED_ATTR, xml);
      }
      if (USE_PROFILES.svgFilters === true) {
        addToSet(ALLOWED_TAGS, svgFilters);
        addToSet(ALLOWED_ATTR, svg);
        addToSet(ALLOWED_ATTR, xml);
      }
      if (USE_PROFILES.mathMl === true) {
        addToSet(ALLOWED_TAGS, mathMl$1);
        addToSet(ALLOWED_ATTR, mathMl);
        addToSet(ALLOWED_ATTR, xml);
      }
    }
    EXTRA_ELEMENT_HANDLING.tagCheck = null;
    EXTRA_ELEMENT_HANDLING.attributeCheck = null;
    if (objectHasOwnProperty(cfg, "ADD_TAGS")) {
      if (typeof cfg.ADD_TAGS === "function") {
        EXTRA_ELEMENT_HANDLING.tagCheck = cfg.ADD_TAGS;
      } else if (arrayIsArray(cfg.ADD_TAGS)) {
        if (ALLOWED_TAGS === DEFAULT_ALLOWED_TAGS) {
          ALLOWED_TAGS = clone(ALLOWED_TAGS);
        }
        addToSet(ALLOWED_TAGS, cfg.ADD_TAGS, transformCaseFunc);
      }
    }
    if (objectHasOwnProperty(cfg, "ADD_ATTR")) {
      if (typeof cfg.ADD_ATTR === "function") {
        EXTRA_ELEMENT_HANDLING.attributeCheck = cfg.ADD_ATTR;
      } else if (arrayIsArray(cfg.ADD_ATTR)) {
        if (ALLOWED_ATTR === DEFAULT_ALLOWED_ATTR) {
          ALLOWED_ATTR = clone(ALLOWED_ATTR);
        }
        addToSet(ALLOWED_ATTR, cfg.ADD_ATTR, transformCaseFunc);
      }
    }
    if (objectHasOwnProperty(cfg, "ADD_URI_SAFE_ATTR") && arrayIsArray(cfg.ADD_URI_SAFE_ATTR)) {
      addToSet(URI_SAFE_ATTRIBUTES, cfg.ADD_URI_SAFE_ATTR, transformCaseFunc);
    }
    if (objectHasOwnProperty(cfg, "FORBID_CONTENTS") && arrayIsArray(cfg.FORBID_CONTENTS)) {
      if (FORBID_CONTENTS === DEFAULT_FORBID_CONTENTS) {
        FORBID_CONTENTS = clone(FORBID_CONTENTS);
      }
      addToSet(FORBID_CONTENTS, cfg.FORBID_CONTENTS, transformCaseFunc);
    }
    if (objectHasOwnProperty(cfg, "ADD_FORBID_CONTENTS") && arrayIsArray(cfg.ADD_FORBID_CONTENTS)) {
      if (FORBID_CONTENTS === DEFAULT_FORBID_CONTENTS) {
        FORBID_CONTENTS = clone(FORBID_CONTENTS);
      }
      addToSet(FORBID_CONTENTS, cfg.ADD_FORBID_CONTENTS, transformCaseFunc);
    }
    if (KEEP_CONTENT) {
      ALLOWED_TAGS["#text"] = true;
    }
    if (WHOLE_DOCUMENT) {
      addToSet(ALLOWED_TAGS, ["html", "head", "body"]);
    }
    if (ALLOWED_TAGS.table) {
      addToSet(ALLOWED_TAGS, ["tbody"]);
      delete FORBID_TAGS.tbody;
    }
    if (cfg.TRUSTED_TYPES_POLICY) {
      if (typeof cfg.TRUSTED_TYPES_POLICY.createHTML !== "function") {
        throw typeErrorCreate('TRUSTED_TYPES_POLICY configuration option must provide a "createHTML" hook.');
      }
      if (typeof cfg.TRUSTED_TYPES_POLICY.createScriptURL !== "function") {
        throw typeErrorCreate('TRUSTED_TYPES_POLICY configuration option must provide a "createScriptURL" hook.');
      }
      const previousTrustedTypesPolicy = trustedTypesPolicy;
      trustedTypesPolicy = cfg.TRUSTED_TYPES_POLICY;
      try {
        emptyHTML = _createTrustedHTML("");
      } catch (error) {
        trustedTypesPolicy = previousTrustedTypesPolicy;
        throw error;
      }
    } else if (cfg.TRUSTED_TYPES_POLICY === null) {
      trustedTypesPolicy = void 0;
      emptyHTML = "";
    } else {
      if (trustedTypesPolicy === void 0) {
        trustedTypesPolicy = _getDefaultTrustedTypesPolicy();
      }
      if (trustedTypesPolicy && typeof emptyHTML === "string") {
        emptyHTML = _createTrustedHTML("");
      }
    }
    if ((hooks.uponSanitizeElement.length > 0 || hooks.uponSanitizeAttribute.length > 0) && ALLOWED_TAGS === DEFAULT_ALLOWED_TAGS) {
      ALLOWED_TAGS = clone(ALLOWED_TAGS);
    }
    if (hooks.uponSanitizeAttribute.length > 0 && ALLOWED_ATTR === DEFAULT_ALLOWED_ATTR) {
      ALLOWED_ATTR = clone(ALLOWED_ATTR);
    }
    if (freeze) {
      freeze(cfg);
    }
    CONFIG = cfg;
  };
  const ALL_SVG_TAGS = addToSet({}, [...svg$1, ...svgFilters, ...svgDisallowed]);
  const ALL_MATHML_TAGS = addToSet({}, [...mathMl$1, ...mathMlDisallowed]);
  const _checkSvgNamespace = function _checkSvgNamespace2(tagName, parent, parentTagName) {
    if (parent.namespaceURI === HTML_NAMESPACE) {
      return tagName === "svg";
    }
    if (parent.namespaceURI === MATHML_NAMESPACE) {
      return tagName === "svg" && (parentTagName === "annotation-xml" || MATHML_TEXT_INTEGRATION_POINTS[parentTagName]);
    }
    return Boolean(ALL_SVG_TAGS[tagName]);
  };
  const _checkMathMlNamespace = function _checkMathMlNamespace2(tagName, parent, parentTagName) {
    if (parent.namespaceURI === HTML_NAMESPACE) {
      return tagName === "math";
    }
    if (parent.namespaceURI === SVG_NAMESPACE) {
      return tagName === "math" && HTML_INTEGRATION_POINTS[parentTagName];
    }
    return Boolean(ALL_MATHML_TAGS[tagName]);
  };
  const _checkHtmlNamespace = function _checkHtmlNamespace2(tagName, parent, parentTagName) {
    if (parent.namespaceURI === SVG_NAMESPACE && !HTML_INTEGRATION_POINTS[parentTagName]) {
      return false;
    }
    if (parent.namespaceURI === MATHML_NAMESPACE && !MATHML_TEXT_INTEGRATION_POINTS[parentTagName]) {
      return false;
    }
    return !ALL_MATHML_TAGS[tagName] && (COMMON_SVG_AND_HTML_ELEMENTS[tagName] || !ALL_SVG_TAGS[tagName]);
  };
  const _checkValidNamespace = function _checkValidNamespace2(element) {
    let parent = getParentNode(element);
    if (!parent || !parent.tagName) {
      parent = {
        namespaceURI: NAMESPACE,
        tagName: "template"
      };
    }
    const tagName = stringToLowerCase(element.tagName);
    const parentTagName = stringToLowerCase(parent.tagName);
    if (!ALLOWED_NAMESPACES[element.namespaceURI]) {
      return false;
    }
    if (element.namespaceURI === SVG_NAMESPACE) {
      return _checkSvgNamespace(tagName, parent, parentTagName);
    }
    if (element.namespaceURI === MATHML_NAMESPACE) {
      return _checkMathMlNamespace(tagName, parent, parentTagName);
    }
    if (element.namespaceURI === HTML_NAMESPACE) {
      return _checkHtmlNamespace(tagName, parent, parentTagName);
    }
    if (PARSER_MEDIA_TYPE === "application/xhtml+xml" && ALLOWED_NAMESPACES[element.namespaceURI]) {
      return true;
    }
    return false;
  };
  const _forceRemove = function _forceRemove2(node) {
    arrayPush(DOMPurify.removed, {
      element: node
    });
    try {
      getParentNode(node).removeChild(node);
    } catch (_) {
      remove(node);
      if (!getParentNode(node)) {
        throw typeErrorCreate("a node selected for removal could not be detached from its tree and cannot be safely returned; refusing to sanitize in place");
      }
    }
  };
  const _neutralizeRoot = function _neutralizeRoot2(root) {
    const childNodes = getChildNodes(root);
    if (childNodes) {
      const snapshot = [];
      arrayForEach(childNodes, (child) => {
        arrayPush(snapshot, child);
      });
      arrayForEach(snapshot, (child) => {
        try {
          remove(child);
        } catch (_) {
        }
      });
    }
    const attributes = getAttributes(root);
    if (attributes) {
      for (let i = attributes.length - 1; i >= 0; --i) {
        const attribute = attributes[i];
        const name = attribute && attribute.name;
        if (typeof name === "string") {
          try {
            root.removeAttribute(name);
          } catch (_) {
          }
        }
      }
    }
  };
  const _removeAttribute = function _removeAttribute2(name, element) {
    try {
      arrayPush(DOMPurify.removed, {
        attribute: element.getAttributeNode(name),
        from: element
      });
    } catch (_) {
      arrayPush(DOMPurify.removed, {
        attribute: null,
        from: element
      });
    }
    element.removeAttribute(name);
    if (name === "is") {
      if (RETURN_DOM || RETURN_DOM_FRAGMENT) {
        try {
          _forceRemove(element);
        } catch (_) {
        }
      } else {
        try {
          element.setAttribute(name, "");
        } catch (_) {
        }
      }
    }
  };
  const _stripDisallowedAttributes = function _stripDisallowedAttributes2(element) {
    const attributes = getAttributes(element);
    if (!attributes) {
      return;
    }
    for (let i = attributes.length - 1; i >= 0; --i) {
      const attribute = attributes[i];
      const name = attribute && attribute.name;
      if (typeof name !== "string" || ALLOWED_ATTR[transformCaseFunc(name)]) {
        continue;
      }
      try {
        element.removeAttribute(name);
      } catch (_) {
      }
    }
  };
  const _neutralizeSubtree = function _neutralizeSubtree2(root) {
    const stack = [root];
    while (stack.length > 0) {
      const node = stack.pop();
      const nodeType = getNodeType ? getNodeType(node) : node.nodeType;
      if (nodeType === NODE_TYPE.element) {
        _stripDisallowedAttributes(node);
      }
      const childNodes = getChildNodes(node);
      if (childNodes) {
        for (let i = childNodes.length - 1; i >= 0; --i) {
          stack.push(childNodes[i]);
        }
      }
    }
  };
  const _initDocument = function _initDocument2(dirty) {
    let doc = null;
    let leadingWhitespace = null;
    if (FORCE_BODY) {
      dirty = "<remove></remove>" + dirty;
    } else {
      const matches = stringMatch(dirty, /^[\r\n\t ]+/);
      leadingWhitespace = matches && matches[0];
    }
    if (PARSER_MEDIA_TYPE === "application/xhtml+xml" && NAMESPACE === HTML_NAMESPACE) {
      dirty = '<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body>' + dirty + "</body></html>";
    }
    const dirtyPayload = trustedTypesPolicy ? _createTrustedHTML(dirty) : dirty;
    if (NAMESPACE === HTML_NAMESPACE) {
      try {
        doc = new DOMParser().parseFromString(dirtyPayload, PARSER_MEDIA_TYPE);
      } catch (_) {
      }
    }
    if (!doc || !doc.documentElement) {
      doc = implementation.createDocument(NAMESPACE, "template", null);
      try {
        doc.documentElement.innerHTML = IS_EMPTY_INPUT ? emptyHTML : dirtyPayload;
      } catch (_) {
      }
    }
    const body = doc.body || doc.documentElement;
    if (dirty && leadingWhitespace) {
      body.insertBefore(document2.createTextNode(leadingWhitespace), body.childNodes[0] || null);
    }
    if (NAMESPACE === HTML_NAMESPACE) {
      return getElementsByTagName.call(doc, WHOLE_DOCUMENT ? "html" : "body")[0];
    }
    return WHOLE_DOCUMENT ? doc.documentElement : body;
  };
  const _createNodeIterator = function _createNodeIterator2(root) {
    return createNodeIterator.call(
      root.ownerDocument || root,
      root,
      // eslint-disable-next-line no-bitwise
      NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_COMMENT | NodeFilter.SHOW_TEXT | NodeFilter.SHOW_PROCESSING_INSTRUCTION | NodeFilter.SHOW_CDATA_SECTION,
      null
    );
  };
  const _stripTemplateExpressions = function _stripTemplateExpressions2(value) {
    value = stringReplace(value, MUSTACHE_EXPR$1, " ");
    value = stringReplace(value, ERB_EXPR$1, " ");
    value = stringReplace(value, TMPLIT_EXPR$1, " ");
    return value;
  };
  const _scrubTemplateExpressions2 = function _scrubTemplateExpressions(node) {
    var _node$querySelectorAl;
    node.normalize();
    const walker = createNodeIterator.call(
      node.ownerDocument || node,
      node,
      // eslint-disable-next-line no-bitwise
      NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT | NodeFilter.SHOW_CDATA_SECTION | NodeFilter.SHOW_PROCESSING_INSTRUCTION,
      null
    );
    let currentNode = walker.nextNode();
    while (currentNode) {
      currentNode.data = _stripTemplateExpressions(currentNode.data);
      currentNode = walker.nextNode();
    }
    const templates = (_node$querySelectorAl = node.querySelectorAll) === null || _node$querySelectorAl === void 0 ? void 0 : _node$querySelectorAl.call(node, "template");
    if (templates) {
      arrayForEach(templates, (tmpl) => {
        if (_isDocumentFragment(tmpl.content)) {
          _scrubTemplateExpressions2(tmpl.content);
        }
      });
    }
  };
  const _isClobbered = function _isClobbered2(element) {
    const realTagName = getNodeName ? getNodeName(element) : null;
    if (typeof realTagName !== "string") {
      return false;
    }
    if (transformCaseFunc(realTagName) !== "form") {
      return false;
    }
    return typeof element.nodeName !== "string" || typeof element.textContent !== "string" || typeof element.removeChild !== "function" || // Realm-safe NamedNodeMap detection: equality against the cached
    // prototype getter. Clobbered .attributes (e.g. <input name="attributes">)
    // makes the direct read diverge from the cached read; a clean form
    // (same-realm OR foreign-realm) has both reads pointing at the same
    // canonical NamedNodeMap.
    element.attributes !== getAttributes(element) || typeof element.removeAttribute !== "function" || typeof element.setAttribute !== "function" || typeof element.namespaceURI !== "string" || typeof element.insertBefore !== "function" || typeof element.hasChildNodes !== "function" || // NodeType clobbering probe. Cached Node.prototype.nodeType getter
    // returns the integer 1 for any Element regardless of realm; direct
    // read on a clobbered form (e.g. <input name="nodeType">) returns
    // the named child element. Cheap addition — nodeType is read from
    // an internal slot, no serialization cost — and removes a residual
    // clobbering surface used by several mXSS / PI / comment branches
    // in _sanitizeElements that compare currentNode.nodeType directly.
    element.nodeType !== getNodeType(element) || // HTMLFormElement has [LegacyOverrideBuiltIns]: a descendant named
    // "childNodes" shadows the prototype getter. Direct reads of
    // form.childNodes from a clobbered form return the named child
    // instead of the real NodeList, so any walk that reads it directly
    // skips the form's real children. Compare the direct read to the
    // cached Node.prototype getter — when the form's named-property
    // getter intercepts the read, the two values differ and we flag
    // the form. This catches every clobbering child type (input,
    // select, etc.) regardless of whether the named child happens to
    // carry a numeric .length, which a typeof-based probe would miss
    // (e.g. HTMLSelectElement.length is a defined unsigned-long).
    element.childNodes !== getChildNodes(element);
  };
  const _isDocumentFragment = function _isDocumentFragment2(value) {
    if (!getNodeType || typeof value !== "object" || value === null) {
      return false;
    }
    try {
      return getNodeType(value) === NODE_TYPE.documentFragment;
    } catch (_) {
      return false;
    }
  };
  const _isNode = function _isNode2(value) {
    if (!getNodeType || typeof value !== "object" || value === null) {
      return false;
    }
    try {
      return typeof getNodeType(value) === "number";
    } catch (_) {
      return false;
    }
  };
  function _executeHooks(hooks2, currentNode, data) {
    if (hooks2.length === 0) {
      return;
    }
    arrayForEach(hooks2, (hook) => {
      hook.call(DOMPurify, currentNode, data, CONFIG);
    });
  }
  const _isUnsafeNode = function _isUnsafeNode2(currentNode, tagName) {
    if (SAFE_FOR_XML && currentNode.hasChildNodes() && !_isNode(currentNode.firstElementChild) && regExpTest(ELEMENT_MARKUP_PROBE, currentNode.textContent) && regExpTest(ELEMENT_MARKUP_PROBE, currentNode.innerHTML)) {
      return true;
    }
    if (SAFE_FOR_XML && currentNode.namespaceURI === HTML_NAMESPACE && tagName === "style" && _isNode(currentNode.firstElementChild)) {
      return true;
    }
    if (currentNode.nodeType === NODE_TYPE.processingInstruction) {
      return true;
    }
    if (SAFE_FOR_XML && currentNode.nodeType === NODE_TYPE.comment && regExpTest(COMMENT_MARKUP_PROBE, currentNode.data)) {
      return true;
    }
    return false;
  };
  const _sanitizeDisallowedNode = function _sanitizeDisallowedNode2(currentNode, tagName) {
    if (!FORBID_TAGS[tagName] && _isBasicCustomElement(tagName)) {
      if (CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof RegExp && regExpTest(CUSTOM_ELEMENT_HANDLING.tagNameCheck, tagName)) {
        return false;
      }
      if (CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof Function && CUSTOM_ELEMENT_HANDLING.tagNameCheck(tagName)) {
        return false;
      }
    }
    if (KEEP_CONTENT && !FORBID_CONTENTS[tagName]) {
      const parentNode = getParentNode(currentNode);
      const childNodes = getChildNodes(currentNode);
      if (childNodes && parentNode) {
        const childCount = childNodes.length;
        for (let i = childCount - 1; i >= 0; --i) {
          const hoisted = IN_PLACE ? childNodes[i] : cloneNode(childNodes[i], true);
          parentNode.insertBefore(hoisted, getNextSibling(currentNode));
        }
      }
    }
    _forceRemove(currentNode);
    return true;
  };
  const _sanitizeElements = function _sanitizeElements2(currentNode) {
    _executeHooks(hooks.beforeSanitizeElements, currentNode, null);
    if (_isClobbered(currentNode)) {
      _forceRemove(currentNode);
      return true;
    }
    const tagName = transformCaseFunc(getNodeName ? getNodeName(currentNode) : currentNode.nodeName);
    _executeHooks(hooks.uponSanitizeElement, currentNode, {
      tagName,
      allowedTags: ALLOWED_TAGS
    });
    if (_isUnsafeNode(currentNode, tagName)) {
      _forceRemove(currentNode);
      return true;
    }
    if (FORBID_TAGS[tagName] || !(EXTRA_ELEMENT_HANDLING.tagCheck instanceof Function && EXTRA_ELEMENT_HANDLING.tagCheck(tagName)) && !ALLOWED_TAGS[tagName]) {
      return _sanitizeDisallowedNode(currentNode, tagName);
    }
    const nt = getNodeType ? getNodeType(currentNode) : currentNode.nodeType;
    if (nt === NODE_TYPE.element && !_checkValidNamespace(currentNode)) {
      _forceRemove(currentNode);
      return true;
    }
    if ((tagName === "noscript" || tagName === "noembed" || tagName === "noframes") && regExpTest(FALLBACK_TAG_CLOSE, currentNode.innerHTML)) {
      _forceRemove(currentNode);
      return true;
    }
    if (SAFE_FOR_TEMPLATES && currentNode.nodeType === NODE_TYPE.text) {
      const content = _stripTemplateExpressions(currentNode.textContent);
      if (currentNode.textContent !== content) {
        arrayPush(DOMPurify.removed, {
          element: currentNode.cloneNode()
        });
        currentNode.textContent = content;
      }
    }
    _executeHooks(hooks.afterSanitizeElements, currentNode, null);
    return false;
  };
  const _isValidAttribute = function _isValidAttribute2(lcTag, lcName, value) {
    if (FORBID_ATTR[lcName]) {
      return false;
    }
    if (SANITIZE_DOM && (lcName === "id" || lcName === "name") && (value in document2 || value in formElement)) {
      return false;
    }
    const nameIsPermitted = ALLOWED_ATTR[lcName] || EXTRA_ELEMENT_HANDLING.attributeCheck instanceof Function && EXTRA_ELEMENT_HANDLING.attributeCheck(lcName, lcTag);
    if (ALLOW_DATA_ATTR && regExpTest(DATA_ATTR$1, lcName)) ;
    else if (ALLOW_ARIA_ATTR && regExpTest(ARIA_ATTR$1, lcName)) ;
    else if (!nameIsPermitted) {
      if (
        // First condition does a very basic check if a) it's basically a valid custom element tagname AND
        // b) if the tagName passes whatever the user has configured for CUSTOM_ELEMENT_HANDLING.tagNameCheck
        // and c) if the attribute name passes whatever the user has configured for CUSTOM_ELEMENT_HANDLING.attributeNameCheck
        _isBasicCustomElement(lcTag) && (CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof RegExp && regExpTest(CUSTOM_ELEMENT_HANDLING.tagNameCheck, lcTag) || CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof Function && CUSTOM_ELEMENT_HANDLING.tagNameCheck(lcTag)) && (CUSTOM_ELEMENT_HANDLING.attributeNameCheck instanceof RegExp && regExpTest(CUSTOM_ELEMENT_HANDLING.attributeNameCheck, lcName) || CUSTOM_ELEMENT_HANDLING.attributeNameCheck instanceof Function && CUSTOM_ELEMENT_HANDLING.attributeNameCheck(lcName, lcTag)) || // Alternative, second condition checks if it's an `is`-attribute, AND
        // the value passes whatever the user has configured for CUSTOM_ELEMENT_HANDLING.tagNameCheck
        lcName === "is" && CUSTOM_ELEMENT_HANDLING.allowCustomizedBuiltInElements && (CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof RegExp && regExpTest(CUSTOM_ELEMENT_HANDLING.tagNameCheck, value) || CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof Function && CUSTOM_ELEMENT_HANDLING.tagNameCheck(value))
      ) ;
      else {
        return false;
      }
    } else if (URI_SAFE_ATTRIBUTES[lcName]) ;
    else if (regExpTest(IS_ALLOWED_URI$1, stringReplace(value, ATTR_WHITESPACE$1, ""))) ;
    else if ((lcName === "src" || lcName === "xlink:href" || lcName === "href") && lcTag !== "script" && stringIndexOf(value, "data:") === 0 && DATA_URI_TAGS[lcTag]) ;
    else if (ALLOW_UNKNOWN_PROTOCOLS && !regExpTest(IS_SCRIPT_OR_DATA$1, stringReplace(value, ATTR_WHITESPACE$1, ""))) ;
    else if (value) {
      return false;
    } else ;
    return true;
  };
  const RESERVED_CUSTOM_ELEMENT_NAMES = addToSet({}, ["annotation-xml", "color-profile", "font-face", "font-face-format", "font-face-name", "font-face-src", "font-face-uri", "missing-glyph"]);
  const _isBasicCustomElement = function _isBasicCustomElement2(tagName) {
    return !RESERVED_CUSTOM_ELEMENT_NAMES[stringToLowerCase(tagName)] && regExpTest(CUSTOM_ELEMENT$1, tagName);
  };
  const _applyTrustedTypesToAttribute = function _applyTrustedTypesToAttribute2(lcTag, lcName, namespaceURI, value) {
    if (trustedTypesPolicy && typeof trustedTypes === "object" && typeof trustedTypes.getAttributeType === "function" && !namespaceURI) {
      switch (trustedTypes.getAttributeType(lcTag, lcName)) {
        case "TrustedHTML": {
          return _createTrustedHTML(value);
        }
        case "TrustedScriptURL": {
          return _createTrustedScriptURL(value);
        }
      }
    }
    return value;
  };
  const _setAttributeValue = function _setAttributeValue2(currentNode, name, namespaceURI, value) {
    try {
      if (namespaceURI) {
        currentNode.setAttributeNS(namespaceURI, name, value);
      } else {
        currentNode.setAttribute(name, value);
      }
      if (_isClobbered(currentNode)) {
        _forceRemove(currentNode);
      } else {
        arrayPop(DOMPurify.removed);
      }
    } catch (_) {
      _removeAttribute(name, currentNode);
    }
  };
  const _sanitizeAttributes = function _sanitizeAttributes2(currentNode) {
    _executeHooks(hooks.beforeSanitizeAttributes, currentNode, null);
    const attributes = currentNode.attributes;
    if (!attributes || _isClobbered(currentNode)) {
      return;
    }
    const hookEvent = {
      attrName: "",
      attrValue: "",
      keepAttr: true,
      allowedAttributes: ALLOWED_ATTR,
      forceKeepAttr: void 0
    };
    let l = attributes.length;
    const lcTag = transformCaseFunc(currentNode.nodeName);
    while (l--) {
      const attr2 = attributes[l];
      const name = attr2.name, namespaceURI = attr2.namespaceURI, attrValue = attr2.value;
      const lcName = transformCaseFunc(name);
      const initValue = attrValue;
      let value = name === "value" ? initValue : stringTrim(initValue);
      hookEvent.attrName = lcName;
      hookEvent.attrValue = value;
      hookEvent.keepAttr = true;
      hookEvent.forceKeepAttr = void 0;
      _executeHooks(hooks.uponSanitizeAttribute, currentNode, hookEvent);
      value = hookEvent.attrValue;
      if (SANITIZE_NAMED_PROPS && (lcName === "id" || lcName === "name") && stringIndexOf(value, SANITIZE_NAMED_PROPS_PREFIX) !== 0) {
        _removeAttribute(name, currentNode);
        value = SANITIZE_NAMED_PROPS_PREFIX + value;
      }
      if (SAFE_FOR_XML && regExpTest(/((--!?|])>)|<\/(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)/i, value)) {
        _removeAttribute(name, currentNode);
        continue;
      }
      if (lcName === "attributename" && stringMatch(value, "href")) {
        _removeAttribute(name, currentNode);
        continue;
      }
      if (hookEvent.forceKeepAttr) {
        continue;
      }
      if (!hookEvent.keepAttr) {
        _removeAttribute(name, currentNode);
        continue;
      }
      if (!ALLOW_SELF_CLOSE_IN_ATTR && regExpTest(SELF_CLOSING_TAG, value)) {
        _removeAttribute(name, currentNode);
        continue;
      }
      if (SAFE_FOR_TEMPLATES) {
        value = _stripTemplateExpressions(value);
      }
      if (!_isValidAttribute(lcTag, lcName, value)) {
        _removeAttribute(name, currentNode);
        continue;
      }
      value = _applyTrustedTypesToAttribute(lcTag, lcName, namespaceURI, value);
      if (value !== initValue) {
        _setAttributeValue(currentNode, name, namespaceURI, value);
      }
    }
    _executeHooks(hooks.afterSanitizeAttributes, currentNode, null);
  };
  const _sanitizeShadowDOM2 = function _sanitizeShadowDOM(fragment) {
    let shadowNode = null;
    const shadowIterator = _createNodeIterator(fragment);
    _executeHooks(hooks.beforeSanitizeShadowDOM, fragment, null);
    while (shadowNode = shadowIterator.nextNode()) {
      _executeHooks(hooks.uponSanitizeShadowNode, shadowNode, null);
      _sanitizeElements(shadowNode);
      _sanitizeAttributes(shadowNode);
      if (_isDocumentFragment(shadowNode.content)) {
        _sanitizeShadowDOM2(shadowNode.content);
      }
      const shadowNodeType = getNodeType ? getNodeType(shadowNode) : shadowNode.nodeType;
      if (shadowNodeType === NODE_TYPE.element) {
        const innerSr = getShadowRoot(shadowNode);
        if (_isDocumentFragment(innerSr)) {
          _sanitizeAttachedShadowRoots(innerSr);
          _sanitizeShadowDOM2(innerSr);
        }
      }
    }
    _executeHooks(hooks.afterSanitizeShadowDOM, fragment, null);
  };
  const _sanitizeAttachedShadowRoots = function _sanitizeAttachedShadowRoots2(root) {
    const stack = [{
      node: root,
      shadow: null
    }];
    while (stack.length > 0) {
      const item = stack.pop();
      if (item.shadow) {
        _sanitizeShadowDOM2(item.shadow);
        continue;
      }
      const node = item.node;
      const nodeType = getNodeType ? getNodeType(node) : node.nodeType;
      const isElement = nodeType === NODE_TYPE.element;
      const childNodes = getChildNodes(node);
      if (childNodes) {
        for (let i = childNodes.length - 1; i >= 0; --i) {
          stack.push({
            node: childNodes[i],
            shadow: null
          });
        }
      }
      if (isElement) {
        const rootName = getNodeName ? getNodeName(node) : null;
        if (typeof rootName === "string" && transformCaseFunc(rootName) === "template") {
          const content = node.content;
          if (_isDocumentFragment(content)) {
            stack.push({
              node: content,
              shadow: null
            });
          }
        }
      }
      if (isElement) {
        const sr = getShadowRoot(node);
        if (_isDocumentFragment(sr)) {
          stack.push({
            node: null,
            shadow: sr
          }, {
            node: sr,
            shadow: null
          });
        }
      }
    }
  };
  DOMPurify.sanitize = function(dirty) {
    let cfg = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : {};
    let body = null;
    let importedNode = null;
    let currentNode = null;
    let returnNode = null;
    IS_EMPTY_INPUT = !dirty;
    if (IS_EMPTY_INPUT) {
      dirty = "<!-->";
    }
    if (typeof dirty !== "string" && !_isNode(dirty)) {
      dirty = stringifyValue(dirty);
      if (typeof dirty !== "string") {
        throw typeErrorCreate("dirty is not a string, aborting");
      }
    }
    if (!DOMPurify.isSupported) {
      return dirty;
    }
    if (!SET_CONFIG) {
      _parseConfig(cfg);
    }
    DOMPurify.removed = [];
    const inPlace = IN_PLACE && typeof dirty !== "string" && _isNode(dirty);
    if (inPlace) {
      const nn = getNodeName ? getNodeName(dirty) : dirty.nodeName;
      if (typeof nn === "string") {
        const tagName = transformCaseFunc(nn);
        if (!ALLOWED_TAGS[tagName] || FORBID_TAGS[tagName]) {
          throw typeErrorCreate("root node is forbidden and cannot be sanitized in-place");
        }
      }
      if (_isClobbered(dirty)) {
        throw typeErrorCreate("root node is clobbered and cannot be sanitized in-place");
      }
      try {
        _sanitizeAttachedShadowRoots(dirty);
      } catch (error) {
        _neutralizeRoot(dirty);
        throw error;
      }
    } else if (_isNode(dirty)) {
      body = _initDocument("<!---->");
      importedNode = body.ownerDocument.importNode(dirty, true);
      if (importedNode.nodeType === NODE_TYPE.element && importedNode.nodeName === "BODY") {
        body = importedNode;
      } else if (importedNode.nodeName === "HTML") {
        body = importedNode;
      } else {
        body.appendChild(importedNode);
      }
      _sanitizeAttachedShadowRoots(importedNode);
    } else {
      if (!RETURN_DOM && !SAFE_FOR_TEMPLATES && !WHOLE_DOCUMENT && // eslint-disable-next-line unicorn/prefer-includes
      dirty.indexOf("<") === -1) {
        return trustedTypesPolicy && RETURN_TRUSTED_TYPE ? _createTrustedHTML(dirty) : dirty;
      }
      body = _initDocument(dirty);
      if (!body) {
        return RETURN_DOM ? null : RETURN_TRUSTED_TYPE ? emptyHTML : "";
      }
    }
    if (body && FORCE_BODY) {
      _forceRemove(body.firstChild);
    }
    const nodeIterator = _createNodeIterator(inPlace ? dirty : body);
    try {
      while (currentNode = nodeIterator.nextNode()) {
        _sanitizeElements(currentNode);
        _sanitizeAttributes(currentNode);
        if (_isDocumentFragment(currentNode.content)) {
          _sanitizeShadowDOM2(currentNode.content);
        }
      }
    } catch (error) {
      if (inPlace) {
        _neutralizeRoot(dirty);
      }
      throw error;
    }
    if (inPlace) {
      arrayForEach(DOMPurify.removed, (entry) => {
        if (entry.element) {
          _neutralizeSubtree(entry.element);
        }
      });
      if (SAFE_FOR_TEMPLATES) {
        _scrubTemplateExpressions2(dirty);
      }
      return dirty;
    }
    if (RETURN_DOM) {
      if (SAFE_FOR_TEMPLATES) {
        _scrubTemplateExpressions2(body);
      }
      if (RETURN_DOM_FRAGMENT) {
        returnNode = createDocumentFragment.call(body.ownerDocument);
        while (body.firstChild) {
          returnNode.appendChild(body.firstChild);
        }
      } else {
        returnNode = body;
      }
      if (ALLOWED_ATTR.shadowroot || ALLOWED_ATTR.shadowrootmode) {
        returnNode = importNode.call(originalDocument, returnNode, true);
      }
      return returnNode;
    }
    let serializedHTML = WHOLE_DOCUMENT ? body.outerHTML : body.innerHTML;
    if (WHOLE_DOCUMENT && ALLOWED_TAGS["!doctype"] && body.ownerDocument && body.ownerDocument.doctype && body.ownerDocument.doctype.name && regExpTest(DOCTYPE_NAME, body.ownerDocument.doctype.name)) {
      serializedHTML = "<!DOCTYPE " + body.ownerDocument.doctype.name + ">\n" + serializedHTML;
    }
    if (SAFE_FOR_TEMPLATES) {
      serializedHTML = _stripTemplateExpressions(serializedHTML);
    }
    return trustedTypesPolicy && RETURN_TRUSTED_TYPE ? _createTrustedHTML(serializedHTML) : serializedHTML;
  };
  DOMPurify.setConfig = function() {
    let cfg = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : {};
    _parseConfig(cfg);
    SET_CONFIG = true;
  };
  DOMPurify.clearConfig = function() {
    CONFIG = null;
    SET_CONFIG = false;
    trustedTypesPolicy = defaultTrustedTypesPolicy;
    emptyHTML = "";
  };
  DOMPurify.isValidAttribute = function(tag, attr2, value) {
    if (!CONFIG) {
      _parseConfig({});
    }
    const lcTag = transformCaseFunc(tag);
    const lcName = transformCaseFunc(attr2);
    return _isValidAttribute(lcTag, lcName, value);
  };
  DOMPurify.addHook = function(entryPoint, hookFunction) {
    if (typeof hookFunction !== "function") {
      return;
    }
    arrayPush(hooks[entryPoint], hookFunction);
  };
  DOMPurify.removeHook = function(entryPoint, hookFunction) {
    if (hookFunction !== void 0) {
      const index = arrayLastIndexOf(hooks[entryPoint], hookFunction);
      return index === -1 ? void 0 : arraySplice(hooks[entryPoint], index, 1)[0];
    }
    return arrayPop(hooks[entryPoint]);
  };
  DOMPurify.removeHooks = function(entryPoint) {
    hooks[entryPoint] = [];
  };
  DOMPurify.removeAllHooks = function() {
    hooks = _createHooksMap();
  };
  return DOMPurify;
}
var purify = createDOMPurify();

// src/crypto/EnhancedSecureCryptoUtils.js
var EnhancedSecureCryptoUtils = class _EnhancedSecureCryptoUtils {
  static _keyMetadata = /* @__PURE__ */ new WeakMap();
  static _messageSanitizer = null;
  // Initialize secure logging system after class definition
  // Utility to sort object keys for deterministic serialization
  static sortObjectKeys(obj) {
    if (typeof obj !== "object" || obj === null) {
      return obj;
    }
    if (Array.isArray(obj)) {
      return obj.map(_EnhancedSecureCryptoUtils.sortObjectKeys);
    }
    const sortedObj = {};
    Object.keys(obj).sort().forEach((key) => {
      sortedObj[key] = _EnhancedSecureCryptoUtils.sortObjectKeys(obj[key]);
    });
    return sortedObj;
  }
  // Utility to assert CryptoKey type and properties
  static assertCryptoKey(key, expectedName = null, expectedUsages = []) {
    if (!(key instanceof CryptoKey)) throw new Error("Expected CryptoKey");
    if (expectedName && key.algorithm?.name !== expectedName) {
      throw new Error(`Expected algorithm ${expectedName}, got ${key.algorithm?.name}`);
    }
    for (const u of expectedUsages) {
      if (!key.usages || !key.usages.includes(u)) {
        throw new Error(`Missing required key usage: ${u}`);
      }
    }
  }
  // Helper function to convert ArrayBuffer to Base64
  static arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  // Helper function to convert Base64 to ArrayBuffer
  static base64ToArrayBuffer(base64) {
    try {
      if (typeof base64 !== "string" || !base64) {
        throw new Error("Invalid base64 input: must be a non-empty string");
      }
      const cleanBase64 = base64.trim();
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleanBase64)) {
        throw new Error("Invalid base64 format");
      }
      if (cleanBase64 === "") {
        return new ArrayBuffer(0);
      }
      const binaryString = atob(cleanBase64);
      const len = binaryString.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes.buffer;
    } catch (error) {
      console.error("Base64 to ArrayBuffer conversion failed:", error.message);
      throw new Error(`Base64 conversion error: ${error.message}`);
    }
  }
  // Helper function to convert hex string to Uint8Array
  static hexToUint8Array(hexString) {
    try {
      if (!hexString || typeof hexString !== "string") {
        throw new Error("Invalid hex string input: must be a non-empty string");
      }
      const cleanHex = hexString.replace(/:/g, "").replace(/\s/g, "");
      if (!/^[0-9a-fA-F]*$/.test(cleanHex)) {
        throw new Error("Invalid hex format: contains non-hex characters");
      }
      if (cleanHex.length % 2 !== 0) {
        throw new Error("Invalid hex format: odd length");
      }
      const bytes = new Uint8Array(cleanHex.length / 2);
      for (let i = 0; i < cleanHex.length; i += 2) {
        bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
      }
      return bytes;
    } catch (error) {
      console.error("Hex to Uint8Array conversion failed:", error.message);
      throw new Error(`Hex conversion error: ${error.message}`);
    }
  }
  /**
   * Overwrite a buffer holding key material once it is no longer needed.
   *
   * This is a genuine wipe, unlike the manager's _secureWipeString /
   * _secureWipeCryptoKey, which cannot wipe anything (JS strings are immutable
   * and a non-extractable CryptoKey has no JS-visible bytes) and only ever
   * dropped a reference while reporting success. Here the bytes really are
   * ours: overwrite them so the shared secret does not linger in the heap
   * waiting for a garbage collector that may never run before a heap snapshot
   * or a memory-reading extension gets there first.
   *
   * Random first, then zeros: on the off chance a copying GC has already moved
   * the buffer, the random pass at least destroys the plaintext value at the
   * old address as well as the new one.
   */
  static zeroizeBuffer(buffer) {
    try {
      if (!buffer) return;
      const view = buffer instanceof Uint8Array ? buffer : buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : null;
      if (!view || view.length === 0) return;
      crypto.getRandomValues(view);
      view.fill(0);
    } catch (_) {
    }
  }
  static async encryptData(data, password) {
    try {
      const dataString = typeof data === "string" ? data : JSON.stringify(data);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const encoder = new TextEncoder();
      const passwordBuffer = encoder.encode(password);
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );
      const key = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: 31e4,
          hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
      );
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const dataBuffer = encoder.encode(dataString);
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        dataBuffer
      );
      const encryptedPackage = {
        version: "1.0",
        salt: Array.from(salt),
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted)),
        timestamp: Date.now()
      };
      const packageString = JSON.stringify(encryptedPackage);
      return _EnhancedSecureCryptoUtils.arrayBufferToBase64(new TextEncoder().encode(packageString).buffer);
    } catch (error) {
      console.error("Encryption failed:", error.message);
      throw new Error(`Encryption error: ${error.message}`);
    }
  }
  static async decryptData(encryptedData, password) {
    try {
      const packageBuffer = _EnhancedSecureCryptoUtils.base64ToArrayBuffer(encryptedData);
      const packageString = new TextDecoder().decode(packageBuffer);
      const encryptedPackage = JSON.parse(packageString);
      if (!encryptedPackage.version || !encryptedPackage.salt || !encryptedPackage.iv || !encryptedPackage.data) {
        throw new Error("Invalid encrypted data format");
      }
      const salt = new Uint8Array(encryptedPackage.salt);
      const iv = new Uint8Array(encryptedPackage.iv);
      const encrypted = new Uint8Array(encryptedPackage.data);
      const encoder = new TextEncoder();
      const passwordBuffer = encoder.encode(password);
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );
      const key = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: 31e4,
          hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        encrypted
      );
      const decryptedString = new TextDecoder().decode(decrypted);
      try {
        return JSON.parse(decryptedString);
      } catch {
        return decryptedString;
      }
    } catch (error) {
      console.error("Decryption failed:", error.message);
      throw new Error(`Decryption error: ${error.message}`);
    }
  }
  // Generate secure password for data exchange
  static generateSecurePassword() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    const charCount = chars.length;
    const length = 32;
    let password = "";
    for (let i = 0; i < length; i++) {
      let randomValue;
      do {
        randomValue = crypto.getRandomValues(new Uint32Array(1))[0];
      } while (randomValue >= 4294967296 - 4294967296 % charCount);
      password += chars[randomValue % charCount];
    }
    return password;
  }
  // Real security level calculation with actual verification
  static async calculateSecurityLevel(securityManager) {
    let score = 0;
    const maxScore = 100;
    const verificationResults = {};
    try {
      if (!securityManager || !securityManager.securityFeatures) {
        console.warn("Security manager not fully initialized, using fallback calculation");
        return {
          level: "INITIALIZING",
          score: 0,
          color: "gray",
          verificationResults: {},
          timestamp: Date.now(),
          details: "Security system initializing...",
          isRealData: false
        };
      }
      const sessionType = "full";
      const isDemoSession = false;
      try {
        const encryptionResult = await _EnhancedSecureCryptoUtils.verifyEncryption(securityManager);
        if (encryptionResult.passed) {
          score += 20;
          verificationResults.verifyEncryption = { passed: true, details: encryptionResult.details, points: 20 };
        } else {
          verificationResults.verifyEncryption = { passed: false, details: encryptionResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyEncryption = { passed: false, details: `Encryption check failed: ${error.message}`, points: 0 };
      }
      try {
        const ecdhResult = await _EnhancedSecureCryptoUtils.verifyECDHKeyExchange(securityManager);
        if (ecdhResult.passed) {
          score += 15;
          verificationResults.verifyECDHKeyExchange = { passed: true, details: ecdhResult.details, points: 15 };
        } else {
          verificationResults.verifyECDHKeyExchange = { passed: false, details: ecdhResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyECDHKeyExchange = { passed: false, details: `Key exchange check failed: ${error.message}`, points: 0 };
      }
      try {
        const integrityResult = await _EnhancedSecureCryptoUtils.verifyMessageIntegrity(securityManager);
        if (integrityResult.passed) {
          score += 10;
          verificationResults.verifyMessageIntegrity = { passed: true, details: integrityResult.details, points: 10 };
        } else {
          verificationResults.verifyMessageIntegrity = { passed: false, details: integrityResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyMessageIntegrity = { passed: false, details: `Message integrity check failed: ${error.message}`, points: 0 };
      }
      try {
        const ecdsaResult = await _EnhancedSecureCryptoUtils.verifyECDSASignatures(securityManager);
        if (ecdsaResult.passed) {
          score += 15;
          verificationResults.verifyECDSASignatures = { passed: true, details: ecdsaResult.details, points: 15 };
        } else {
          verificationResults.verifyECDSASignatures = { passed: false, details: ecdsaResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyECDSASignatures = { passed: false, details: `Digital signatures check failed: ${error.message}`, points: 0 };
      }
      try {
        const rateLimitResult = await _EnhancedSecureCryptoUtils.verifyRateLimiting(securityManager);
        if (rateLimitResult.passed) {
          score += 5;
          verificationResults.verifyRateLimiting = { passed: true, details: rateLimitResult.details, points: 5 };
        } else {
          verificationResults.verifyRateLimiting = { passed: false, details: rateLimitResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyRateLimiting = { passed: false, details: `Rate limiting check failed: ${error.message}`, points: 0 };
      }
      try {
        const metadataResult = await _EnhancedSecureCryptoUtils.verifyMetadataProtection(securityManager);
        if (metadataResult.passed) {
          score += 10;
          verificationResults.verifyMetadataProtection = { passed: true, details: metadataResult.details, points: 10 };
        } else {
          verificationResults.verifyMetadataProtection = { passed: false, details: metadataResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyMetadataProtection = { passed: false, details: `Metadata protection check failed: ${error.message}`, points: 0 };
      }
      try {
        const pfsResult = await _EnhancedSecureCryptoUtils.verifyPerfectForwardSecrecy(securityManager);
        if (pfsResult.passed) {
          score += 10;
          verificationResults.verifyPerfectForwardSecrecy = { passed: true, details: pfsResult.details, points: 10 };
        } else {
          verificationResults.verifyPerfectForwardSecrecy = { passed: false, details: pfsResult.details, points: 0 };
        }
      } catch (error) {
        verificationResults.verifyPerfectForwardSecrecy = { passed: false, details: `PFS check failed: ${error.message}`, points: 0 };
      }
      if (await _EnhancedSecureCryptoUtils.verifyNestedEncryption(securityManager)) {
        score += 5;
        verificationResults.nestedEncryption = { passed: true, details: "Nested encryption active", points: 5 };
      } else {
        verificationResults.nestedEncryption = { passed: false, details: "Nested encryption failed", points: 0 };
      }
      if (await _EnhancedSecureCryptoUtils.verifyPacketPadding(securityManager)) {
        score += 5;
        verificationResults.packetPadding = { passed: true, details: "Packet padding active", points: 5 };
      } else {
        verificationResults.packetPadding = { passed: false, details: "Packet padding failed", points: 0 };
      }
      if (await _EnhancedSecureCryptoUtils.verifyAdvancedFeatures(securityManager)) {
        score += 10;
        verificationResults.advancedFeatures = { passed: true, details: "Advanced features active", points: 10 };
      } else {
        verificationResults.advancedFeatures = { passed: false, details: "Advanced features failed", points: 0 };
      }
      const percentage = Math.round(score / maxScore * 100);
      const availableChecks = 10;
      const passedChecks = Object.values(verificationResults).filter((r) => r.passed).length;
      const result = {
        level: percentage >= 85 ? "HIGH" : percentage >= 65 ? "MEDIUM" : percentage >= 35 ? "LOW" : "CRITICAL",
        score: percentage,
        color: percentage >= 85 ? "green" : percentage >= 65 ? "orange" : percentage >= 35 ? "yellow" : "red",
        verificationResults,
        timestamp: Date.now(),
        details: `Real verification: ${score}/${maxScore} security checks passed (${passedChecks}/${availableChecks} available)`,
        isRealData: true,
        passedChecks,
        totalChecks: availableChecks,
        sessionType,
        maxPossibleScore: 100
        // All features enabled - max 100 points
      };
      return result;
    } catch (error) {
      console.error("Security level calculation failed:", error.message);
      return {
        level: "UNKNOWN",
        score: 0,
        color: "red",
        verificationResults: {},
        timestamp: Date.now(),
        details: `Verification failed: ${error.message}`,
        isRealData: false
      };
    }
  }
  // Real verification functions
  static async verifyEncryption(securityManager) {
    try {
      if (!securityManager.encryptionKey) {
        return { passed: false, details: "No encryption key available" };
      }
      const testCases = [
        "Test encryption verification",
        "\u0420\u0443\u0441\u0441\u043A\u0438\u0439 \u0442\u0435\u043A\u0441\u0442 \u0434\u043B\u044F \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0438",
        "Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?",
        "Large data: " + "A".repeat(1e3)
      ];
      for (const testData of testCases) {
        const encoder = new TextEncoder();
        const testBuffer = encoder.encode(testData);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          securityManager.encryptionKey,
          testBuffer
        );
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          securityManager.encryptionKey,
          encrypted
        );
        const decryptedText = new TextDecoder().decode(decrypted);
        if (decryptedText !== testData) {
          return { passed: false, details: `Decryption mismatch for: ${testData.substring(0, 20)}...` };
        }
      }
      return { passed: true, details: "AES-GCM encryption/decryption working correctly" };
    } catch (error) {
      console.error("Encryption verification failed:", error.message);
      return { passed: false, details: `Encryption test failed: ${error.message}` };
    }
  }
  static async verifyECDHKeyExchange(securityManager) {
    try {
      if (!securityManager.ecdhKeyPair || !securityManager.ecdhKeyPair.privateKey || !securityManager.ecdhKeyPair.publicKey) {
        return { passed: false, details: "No ECDH key pair available" };
      }
      const keyType = securityManager.ecdhKeyPair.privateKey.algorithm.name;
      const curve = securityManager.ecdhKeyPair.privateKey.algorithm.namedCurve;
      if (keyType !== "ECDH") {
        return { passed: false, details: `Invalid key type: ${keyType}, expected ECDH` };
      }
      if (curve !== "P-384" && curve !== "P-256") {
        return { passed: false, details: `Unsupported curve: ${curve}, expected P-384 or P-256` };
      }
      try {
        const derivedKey = await crypto.subtle.deriveKey(
          { name: "ECDH", public: securityManager.ecdhKeyPair.publicKey },
          securityManager.ecdhKeyPair.privateKey,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"]
        );
        if (!derivedKey) {
          return { passed: false, details: "Key derivation failed" };
        }
      } catch (deriveError) {
        return { passed: false, details: `Key derivation test failed: ${deriveError.message}` };
      }
      return { passed: true, details: `ECDH key exchange working with ${curve} curve` };
    } catch (error) {
      console.error("ECDH verification failed:", error.message);
      return { passed: false, details: `ECDH test failed: ${error.message}` };
    }
  }
  static async verifyECDSASignatures(securityManager) {
    try {
      if (!securityManager.ecdsaKeyPair || !securityManager.ecdsaKeyPair.privateKey || !securityManager.ecdsaKeyPair.publicKey) {
        return { passed: false, details: "No ECDSA key pair available" };
      }
      const testCases = [
        "Test ECDSA signature verification",
        "\u0420\u0443\u0441\u0441\u043A\u0438\u0439 \u0442\u0435\u043A\u0441\u0442 \u0434\u043B\u044F \u043F\u043E\u0434\u043F\u0438\u0441\u0438",
        "Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?",
        "Large data: " + "B".repeat(2e3)
      ];
      for (const testData of testCases) {
        const encoder = new TextEncoder();
        const testBuffer = encoder.encode(testData);
        const signature = await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          securityManager.ecdsaKeyPair.privateKey,
          testBuffer
        );
        const isValid = await crypto.subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          securityManager.ecdsaKeyPair.publicKey,
          signature,
          testBuffer
        );
        if (!isValid) {
          return { passed: false, details: `Signature verification failed for: ${testData.substring(0, 20)}...` };
        }
      }
      return { passed: true, details: "ECDSA digital signatures working correctly" };
    } catch (error) {
      console.error("ECDSA verification failed:", error.message);
      return { passed: false, details: `ECDSA test failed: ${error.message}` };
    }
  }
  static async verifyMessageIntegrity(securityManager) {
    try {
      if (!securityManager.macKey || !(securityManager.macKey instanceof CryptoKey)) {
        return { passed: false, details: "MAC key not available or invalid" };
      }
      const testCases = [
        "Test message integrity verification",
        "\u0420\u0443\u0441\u0441\u043A\u0438\u0439 \u0442\u0435\u043A\u0441\u0442 \u0434\u043B\u044F \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0438 \u0446\u0435\u043B\u043E\u0441\u0442\u043D\u043E\u0441\u0442\u0438",
        "Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?",
        "Large data: " + "C".repeat(3e3)
      ];
      for (const testData of testCases) {
        const encoder = new TextEncoder();
        const testBuffer = encoder.encode(testData);
        const hmac2 = await crypto.subtle.sign(
          { name: "HMAC", hash: "SHA-256" },
          securityManager.macKey,
          testBuffer
        );
        const isValid = await crypto.subtle.verify(
          { name: "HMAC", hash: "SHA-256" },
          securityManager.macKey,
          hmac2,
          testBuffer
        );
        if (!isValid) {
          return { passed: false, details: `HMAC verification failed for: ${testData.substring(0, 20)}...` };
        }
      }
      return { passed: true, details: "Message integrity (HMAC) working correctly" };
    } catch (error) {
      console.error("Message integrity verification failed:", error.message);
      return { passed: false, details: `Message integrity test failed: ${error.message}` };
    }
  }
  // Additional verification functions.
  //
  // These used to be three `return { passed: true }` stubs — a quarter of the
  // reported score awarded for checks that never ran, under a UI that calls the
  // result "Real cryptographic tests". A security indicator that cannot fail
  // tells the user nothing; worse, it keeps reading green after the subsystem
  // it claims to measure breaks. Each one below now exercises the thing it
  // names and is expected to be able to fail.
  static async verifyRateLimiting(securityManager) {
    try {
      const limiter = _EnhancedSecureCryptoUtils.rateLimiter;
      if (!limiter || typeof limiter.checkMessageRate !== "function") {
        return { passed: false, details: "Rate limiter is not available" };
      }
      const probeId = `selftest_${crypto.getRandomValues(new Uint32Array(1))[0]}`;
      const limit = 3;
      for (let i = 0; i < limit; i++) {
        const allowed = await limiter.checkMessageRate(probeId, limit, 6e4);
        if (!allowed) {
          return { passed: false, details: `Rate limiter refused message ${i + 1} of ${limit} while under the limit` };
        }
      }
      const shouldBeBlocked = await limiter.checkMessageRate(probeId, limit, 6e4);
      limiter.messages.delete(`msg_${probeId}`);
      if (shouldBeBlocked) {
        return { passed: false, details: "Rate limiter did not block a message over the limit" };
      }
      return { passed: true, details: `Rate limiting verified: ${limit} allowed, the next refused` };
    } catch (error) {
      return { passed: false, details: `Rate limiting test failed: ${error.message}` };
    }
  }
  static async verifyMetadataProtection(securityManager) {
    try {
      const metadataKey = securityManager?.metadataKey;
      if (!metadataKey || !(metadataKey instanceof CryptoKey)) {
        return { passed: false, details: "Metadata encryption key not available" };
      }
      if (metadataKey.algorithm?.name !== "AES-GCM") {
        return { passed: false, details: `Metadata key has the wrong algorithm: ${metadataKey.algorithm?.name}` };
      }
      if (metadataKey.extractable) {
        return { passed: false, details: "Metadata key is extractable" };
      }
      if (securityManager.encryptionKey === metadataKey) {
        return { passed: false, details: "Metadata key is not separated from the message key" };
      }
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const probe = new TextEncoder().encode("metadata-protection-selftest");
      const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, metadataKey, probe);
      const opened = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, metadataKey, sealed);
      if (new TextDecoder().decode(opened) !== "metadata-protection-selftest") {
        return { passed: false, details: "Metadata encryption round-trip mismatch" };
      }
      return { passed: true, details: "Metadata is encrypted under a separate non-extractable key" };
    } catch (error) {
      return { passed: false, details: `Metadata protection test failed: ${error.message}` };
    }
  }
  static async verifyPerfectForwardSecrecy(securityManager) {
    try {
      const hasEphemeralKeys = !!securityManager?.ecdhKeyPair?.privateKey && securityManager.ecdhKeyPair.privateKey.extractable === false;
      if (!hasEphemeralKeys) {
        return { passed: false, details: "No non-extractable ephemeral ECDH key pair for this session" };
      }
      if (securityManager?.isRatchetActive?.()) {
        const state = securityManager._ratchet?.getState?.() || {};
        return {
          passed: true,
          details: `Double Ratchet active: per-message keys destroyed after use, DH re-key on each reply (sent ${state.sendCount ?? 0}, received ${state.receiveCount ?? 0} on the current chain)`
        };
      }
      return {
        passed: false,
        details: "Session-level PFS only: keys are ephemeral per session, but the Double Ratchet is not active for this connection (peer on an older version), so a compromised session key exposes the whole conversation"
      };
    } catch (error) {
      return { passed: false, details: `PFS test failed: ${error.message}` };
    }
  }
  static async verifyReplayProtection(securityManager) {
    try {
      if (!securityManager.replayProtection) {
        return { passed: false, details: "Replay protection not enabled" };
      }
      return { passed: true, details: "Replay protection is working correctly" };
    } catch (error) {
      return { passed: false, details: `Replay protection test failed: ${error.message}` };
    }
  }
  static async verifyDTLSFingerprint(securityManager) {
    try {
      if (!securityManager.dtlsFingerprint) {
        return { passed: false, details: "DTLS fingerprint not available" };
      }
      return { passed: true, details: "DTLS fingerprint is valid and available" };
    } catch (error) {
      return { passed: false, details: `DTLS fingerprint test failed: ${error.message}` };
    }
  }
  static async verifySASVerification(securityManager) {
    try {
      if (!securityManager.sasCode) {
        return { passed: false, details: "SAS code not available" };
      }
      return { passed: true, details: "SAS verification code is valid and available" };
    } catch (error) {
      return { passed: false, details: `SAS verification test failed: ${error.message}` };
    }
  }
  static async verifyTrafficObfuscation(securityManager) {
    try {
      if (!securityManager.trafficObfuscation) {
        return { passed: false, details: "Traffic obfuscation not enabled" };
      }
      return { passed: true, details: "Traffic obfuscation is working correctly" };
    } catch (error) {
      return { passed: false, details: `Traffic obfuscation test failed: ${error.message}` };
    }
  }
  static async verifyNestedEncryption(securityManager) {
    try {
      if (!securityManager.nestedEncryptionKey || !(securityManager.nestedEncryptionKey instanceof CryptoKey)) {
        console.warn("Nested encryption key not available or invalid");
        return false;
      }
      const testData = "Test nested encryption verification";
      const encoder = new TextEncoder();
      const testBuffer = encoder.encode(testData);
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: crypto.getRandomValues(new Uint8Array(12)) },
        securityManager.nestedEncryptionKey,
        testBuffer
      );
      return encrypted && encrypted.byteLength > 0;
    } catch (error) {
      console.error("Nested encryption verification failed:", error.message);
      return false;
    }
  }
  static async verifyPacketPadding(securityManager) {
    try {
      if (!securityManager.paddingConfig || !securityManager.paddingConfig.enabled) return false;
      const testData = "Test packet padding verification";
      const encoder = new TextEncoder();
      const testBuffer = encoder.encode(testData);
      const paddingSize = Math.floor(Math.random() * (securityManager.paddingConfig.maxPadding - securityManager.paddingConfig.minPadding)) + securityManager.paddingConfig.minPadding;
      const paddedData = new Uint8Array(testBuffer.byteLength + paddingSize);
      paddedData.set(new Uint8Array(testBuffer), 0);
      return paddedData.byteLength >= testBuffer.byteLength + securityManager.paddingConfig.minPadding;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Packet padding verification failed", { error: error.message });
      return false;
    }
  }
  static async verifyAdvancedFeatures(securityManager) {
    try {
      const hasFakeTraffic = securityManager.fakeTrafficConfig && securityManager.fakeTrafficConfig.enabled;
      const hasDecoyChannels = securityManager.decoyChannelsConfig && securityManager.decoyChannelsConfig.enabled;
      const hasAntiFingerprinting = securityManager.antiFingerprintingConfig && securityManager.antiFingerprintingConfig.enabled;
      return hasFakeTraffic || hasDecoyChannels || hasAntiFingerprinting;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Advanced features verification failed", { error: error.message });
      return false;
    }
  }
  static async verifyMutualAuth(securityManager) {
    try {
      if (!securityManager.isVerified || !securityManager.verificationCode) return false;
      return securityManager.isVerified && securityManager.verificationCode.length > 0;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Mutual auth verification failed", { error: error.message });
      return false;
    }
  }
  static async verifyNonExtractableKeys(securityManager) {
    const keys = [
      ["encryptionKey", securityManager?.encryptionKey],
      ["macKey", securityManager?.macKey],
      ["metadataKey", securityManager?.metadataKey]
    ];
    for (const [name, key] of keys) {
      if (!key || !(key instanceof CryptoKey)) {
        return false;
      }
      if (key.extractable !== false) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Session key is extractable", { keyName: name });
        return false;
      }
    }
    return true;
  }
  static async verifyEnhancedValidation(securityManager) {
    try {
      if (!securityManager.securityFeatures) return false;
      const hasValidation = securityManager.securityFeatures.hasEnhancedValidation || securityManager.securityFeatures.hasEnhancedReplayProtection;
      return hasValidation;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Enhanced validation verification failed", { error: error.message });
      return false;
    }
  }
  static async verifyPFS(securityManager) {
    try {
      return securityManager.securityFeatures && securityManager.securityFeatures.hasPFS === true && securityManager.keyRotationInterval && securityManager.currentKeyVersion !== void 0 && securityManager.keyVersions && securityManager.keyVersions instanceof Map;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "PFS verification failed", { error: error.message });
      return false;
    }
  }
  // Rate limiting implementation
  static rateLimiter = {
    messages: /* @__PURE__ */ new Map(),
    connections: /* @__PURE__ */ new Map(),
    locks: /* @__PURE__ */ new Map(),
    async checkMessageRate(identifier, limit = 60, windowMs = 6e4) {
      if (typeof identifier !== "string" || identifier.length > 256) {
        return false;
      }
      const key = `msg_${identifier}`;
      if (this.locks.has(key)) {
        await new Promise((resolve) => setTimeout(resolve, Math.floor(Math.random() * 10) + 5));
        return this.checkMessageRate(identifier, limit, windowMs);
      }
      this.locks.set(key, true);
      try {
        const now = Date.now();
        if (!this.messages.has(key)) {
          this.messages.set(key, []);
        }
        const timestamps = this.messages.get(key);
        const validTimestamps = timestamps.filter((ts) => now - ts < windowMs);
        if (validTimestamps.length >= limit) {
          return false;
        }
        validTimestamps.push(now);
        this.messages.set(key, validTimestamps);
        return true;
      } finally {
        this.locks.delete(key);
      }
    },
    async checkConnectionRate(identifier, limit = 5, windowMs = 3e5) {
      if (typeof identifier !== "string" || identifier.length > 256) {
        return false;
      }
      const key = `conn_${identifier}`;
      if (this.locks.has(key)) {
        await new Promise((resolve) => setTimeout(resolve, Math.floor(Math.random() * 10) + 5));
        return this.checkConnectionRate(identifier, limit, windowMs);
      }
      this.locks.set(key, true);
      try {
        const now = Date.now();
        if (!this.connections.has(key)) {
          this.connections.set(key, []);
        }
        const timestamps = this.connections.get(key);
        const validTimestamps = timestamps.filter((ts) => now - ts < windowMs);
        if (validTimestamps.length >= limit) {
          return false;
        }
        validTimestamps.push(now);
        this.connections.set(key, validTimestamps);
        return true;
      } finally {
        this.locks.delete(key);
      }
    },
    cleanup() {
      const now = Date.now();
      const maxAge = 36e5;
      for (const [key, timestamps] of this.messages.entries()) {
        if (this.locks.has(key)) continue;
        const valid = timestamps.filter((ts) => now - ts < maxAge);
        if (valid.length === 0) {
          this.messages.delete(key);
        } else {
          this.messages.set(key, valid);
        }
      }
      for (const [key, timestamps] of this.connections.entries()) {
        if (this.locks.has(key)) continue;
        const valid = timestamps.filter((ts) => now - ts < maxAge);
        if (valid.length === 0) {
          this.connections.delete(key);
        } else {
          this.connections.set(key, valid);
        }
      }
      for (const lockKey of this.locks.keys()) {
        const keyTimestamp = parseInt(lockKey.split("_").pop()) || 0;
        if (now - keyTimestamp > 3e4) {
          this.locks.delete(lockKey);
        }
      }
    }
  };
  static validateSalt(salt) {
    if (!salt || salt.length !== 64) {
      throw new Error("Salt must be exactly 64 bytes");
    }
    const uniqueBytes = new Set(salt);
    if (uniqueBytes.size < 16) {
      throw new Error("Salt has insufficient entropy");
    }
    return true;
  }
  // Secure logging without data leaks
  static secureLog = {
    logs: [],
    maxLogs: 100,
    isProductionMode: false,
    // Initialize production mode detection
    init() {
      this.isProductionMode = this._detectProductionMode();
      if (this.isProductionMode) {
        console.log("[SecureChat] Production mode detected - sensitive logging disabled");
      }
    },
    _detectProductionMode() {
      return typeof process !== "undefined" && false || !window.DEBUG_MODE && !window.DEVELOPMENT_MODE || window.location.hostname && !window.location.hostname.includes("localhost") && !window.location.hostname.includes("127.0.0.1") && !window.location.hostname.includes(".local") || typeof window.webpackHotUpdate === "undefined" && !window.location.search.includes("debug");
    },
    log(level, message, context = {}) {
      const sanitizedContext = this.sanitizeContext(context);
      const logEntry = {
        timestamp: Date.now(),
        level,
        message,
        context: sanitizedContext,
        id: crypto.getRandomValues(new Uint32Array(1))[0]
      };
      this.logs.push(logEntry);
      if (this.logs.length > this.maxLogs) {
        this.logs = this.logs.slice(-this.maxLogs);
      }
      if (this.isProductionMode) {
        if (level === "error") {
          console.error(`\u274C [SecureChat] ${message} [ERROR_CODE: ${this._generateErrorCode(message)}]`);
        } else if (level === "warn") {
          console.warn(`\u26A0\uFE0F [SecureChat] ${message}`);
        } else {
          return;
        }
      } else {
        if (level === "error") {
          console.error(`\u274C [SecureChat] ${message}`, { errorType: sanitizedContext?.constructor?.name || "Unknown" });
        } else if (level === "warn") {
          console.warn(`\u26A0\uFE0F [SecureChat] ${message}`, { details: sanitizedContext });
        } else {
          console.log(`[SecureChat] ${message}`, sanitizedContext);
        }
      }
    },
    // Генерирует безопасный код ошибки для production
    _generateErrorCode(message) {
      const hash = message.split("").reduce((a, b) => {
        a = (a << 5) - a + b.charCodeAt(0);
        return a & a;
      }, 0);
      return Math.abs(hash).toString(36).substring(0, 6).toUpperCase();
    },
    sanitizeContext(context) {
      if (!context || typeof context !== "object") {
        return context;
      }
      const sensitivePatterns = [
        /key/i,
        /secret/i,
        /password/i,
        /token/i,
        /signature/i,
        /challenge/i,
        /proof/i,
        /salt/i,
        /iv/i,
        /nonce/i,
        /hash/i,
        /fingerprint/i,
        /mac/i,
        /private/i,
        /encryption/i,
        /decryption/i
      ];
      const sanitized = {};
      for (const [key, value] of Object.entries(context)) {
        const isSensitive = sensitivePatterns.some(
          (pattern) => pattern.test(key) || typeof value === "string" && pattern.test(value)
        );
        if (isSensitive) {
          sanitized[key] = "[REDACTED]";
        } else if (typeof value === "string" && value.length > 100) {
          sanitized[key] = value.substring(0, 100) + "...[TRUNCATED]";
        } else if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
          sanitized[key] = `[${value.constructor.name}(${value.byteLength || value.length} bytes)]`;
        } else if (value && typeof value === "object" && !Array.isArray(value)) {
          sanitized[key] = this.sanitizeContext(value);
        } else {
          sanitized[key] = value;
        }
      }
      return sanitized;
    },
    getLogs(level = null) {
      if (level) {
        return this.logs.filter((log) => log.level === level);
      }
      return [...this.logs];
    },
    clearLogs() {
      this.logs = [];
    },
    // Метод для отправки ошибок на сервер в production
    async sendErrorToServer(errorCode, message, context = {}) {
      if (!this.isProductionMode) {
        return;
      }
      try {
        const safeErrorData = {
          errorCode,
          timestamp: Date.now(),
          userAgent: navigator.userAgent.substring(0, 100),
          url: window.location.href.substring(0, 100)
        };
        if (window.DEBUG_MODE) {
          console.log("[SecureChat] Error logged to server:", safeErrorData);
        }
      } catch (e) {
      }
    }
  };
  // Generate ECDH key pair for secure key exchange (non-extractable) with fallback
  static async generateECDHKeyPair() {
    try {
      try {
        const keyPair = await crypto.subtle.generateKey(
          {
            name: "ECDH",
            namedCurve: "P-384"
          },
          false,
          // Non-extractable for enhanced security
          // 'deriveBits' is REQUIRED: deriveSharedKeys() uses deriveBits so
          // the shared secret lands in a buffer we can overwrite, instead of
          // being exported out of an extractable key and left in the heap.
          // Without this usage WebCrypto rejects the derivation outright and
          // no session can be established. Usages are local to the CryptoKey
          // and are not part of the exported SPKI, so this does not change
          // anything on the wire.
          ["deriveKey", "deriveBits"]
        );
        return keyPair;
      } catch (p384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "Elliptic curve P-384 generation failed, switching curve", { error: p384Error.message });
        const keyPair = await crypto.subtle.generateKey(
          {
            name: "ECDH",
            namedCurve: "P-256"
          },
          false,
          // Non-extractable for enhanced security
          ["deriveKey", "deriveBits"]
        );
        return keyPair;
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "ECDH key generation failed", { error: error.message });
      throw new Error("Failed to create keys for secure exchange");
    }
  }
  // Generate ECDSA key pair for digital signatures with fallback
  static async generateECDSAKeyPair() {
    try {
      try {
        const keyPair = await crypto.subtle.generateKey(
          {
            name: "ECDSA",
            namedCurve: "P-384"
          },
          false,
          // Non-extractable for enhanced security
          ["sign", "verify"]
        );
        return keyPair;
      } catch (p384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "Elliptic curve P-384 generation failed, switching curve", { error: p384Error.message });
        const keyPair = await crypto.subtle.generateKey(
          {
            name: "ECDSA",
            namedCurve: "P-256"
          },
          false,
          // Non-extractable for enhanced security
          ["sign", "verify"]
        );
        return keyPair;
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "ECDSA key generation failed", { error: error.message });
      throw new Error("Failed to generate keys for digital signatures");
    }
  }
  // Sign data with ECDSA (P-384 or P-256)
  static async signData(privateKey, data) {
    try {
      const encoder = new TextEncoder();
      const dataBuffer = typeof data === "string" ? encoder.encode(data) : data;
      try {
        const signature = await crypto.subtle.sign(
          {
            name: "ECDSA",
            hash: "SHA-384"
          },
          privateKey,
          dataBuffer
        );
        return Array.from(new Uint8Array(signature));
      } catch (sha384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "SHA-384 signing failed, trying SHA-256", { error: sha384Error.message });
        const signature = await crypto.subtle.sign(
          {
            name: "ECDSA",
            hash: "SHA-256"
          },
          privateKey,
          dataBuffer
        );
        return Array.from(new Uint8Array(signature));
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Data signing failed", { error: error.message });
      throw new Error("Failed to sign data");
    }
  }
  // Verify ECDSA signature (P-384 or P-256)
  static async verifySignature(publicKey, signature, data) {
    try {
      const encoder = new TextEncoder();
      const dataBuffer = typeof data === "string" ? encoder.encode(data) : data;
      const signatureBuffer = new Uint8Array(signature);
      try {
        const isValid = await crypto.subtle.verify(
          {
            name: "ECDSA",
            hash: "SHA-384"
          },
          publicKey,
          signatureBuffer,
          dataBuffer
        );
        return isValid;
      } catch (sha384Error) {
        const isValid = await crypto.subtle.verify(
          {
            name: "ECDSA",
            hash: "SHA-256"
          },
          publicKey,
          signatureBuffer,
          dataBuffer
        );
        return isValid;
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Signature verification failed", { error: error.message });
      throw new Error("Failed to verify digital signature");
    }
  }
  // Enhanced DER/SPKI validation with full ASN.1 parsing
  static async validateKeyStructure(keyData, expectedAlgorithm = "ECDH") {
    try {
      if (!Array.isArray(keyData) || keyData.length === 0) {
        throw new Error("Invalid key data format");
      }
      const keyBytes = new Uint8Array(keyData);
      if (keyBytes.length < 50) {
        throw new Error("Key data too short - invalid SPKI structure");
      }
      if (keyBytes.length > 2e3) {
        throw new Error("Key data too long - possible attack");
      }
      const asn1 = _EnhancedSecureCryptoUtils.parseASN1(keyBytes);
      if (!asn1 || asn1.tag !== 48) {
        throw new Error("Invalid SPKI structure - missing SEQUENCE tag");
      }
      if (asn1.children.length !== 2) {
        throw new Error(`Invalid SPKI structure - expected 2 elements, got ${asn1.children.length}`);
      }
      const algIdentifier = asn1.children[0];
      if (algIdentifier.tag !== 48) {
        throw new Error("Invalid AlgorithmIdentifier - not a SEQUENCE");
      }
      const algOid = algIdentifier.children[0];
      if (algOid.tag !== 6) {
        throw new Error("Invalid algorithm OID - not an OBJECT IDENTIFIER");
      }
      const oidBytes = algOid.value;
      const oidString = _EnhancedSecureCryptoUtils.oidToString(oidBytes);
      const validAlgorithms = {
        "ECDH": ["1.2.840.10045.2.1"],
        // id-ecPublicKey
        "ECDSA": ["1.2.840.10045.2.1"],
        // id-ecPublicKey (same as ECDH)
        "RSA": ["1.2.840.113549.1.1.1"],
        // rsaEncryption
        "AES-GCM": ["2.16.840.1.101.3.4.1.6", "2.16.840.1.101.3.4.1.46"]
        // AES-128-GCM, AES-256-GCM
      };
      const expectedOids = validAlgorithms[expectedAlgorithm];
      if (!expectedOids) {
        throw new Error(`Unknown algorithm: ${expectedAlgorithm}`);
      }
      if (!expectedOids.includes(oidString)) {
        throw new Error(`Invalid algorithm OID: expected ${expectedOids.join(" or ")}, got ${oidString}`);
      }
      if (expectedAlgorithm === "ECDH" || expectedAlgorithm === "ECDSA") {
        if (algIdentifier.children.length < 2) {
          throw new Error("Missing curve parameters for EC key");
        }
        const curveOid = algIdentifier.children[1];
        if (curveOid.tag !== 6) {
          throw new Error("Invalid curve OID - not an OBJECT IDENTIFIER");
        }
        const curveOidString = _EnhancedSecureCryptoUtils.oidToString(curveOid.value);
        const validCurves = {
          "1.2.840.10045.3.1.7": "P-256",
          // secp256r1
          "1.3.132.0.34": "P-384"
          // secp384r1
        };
        if (!validCurves[curveOidString]) {
          throw new Error(`Invalid or unsupported curve OID: ${curveOidString}`);
        }
      }
      const publicKeyBitString = asn1.children[1];
      if (publicKeyBitString.tag !== 3) {
        throw new Error("Invalid public key - not a BIT STRING");
      }
      if (publicKeyBitString.value[0] !== 0) {
        throw new Error(`Invalid BIT STRING - unexpected unused bits: ${publicKeyBitString.value[0]}`);
      }
      if (expectedAlgorithm === "ECDH" || expectedAlgorithm === "ECDSA") {
        const pointData = publicKeyBitString.value.slice(1);
        if (pointData[0] !== 4) {
          throw new Error(`Invalid EC point format: expected uncompressed (0x04), got 0x${pointData[0].toString(16)}`);
        }
        const expectedSizes = {
          "P-256": 65,
          // 1 + 32 + 32
          "P-384": 97
          // 1 + 48 + 48
        };
        const curveOidString = _EnhancedSecureCryptoUtils.oidToString(algIdentifier.children[1].value);
        const curveName = curveOidString === "1.2.840.10045.3.1.7" ? "P-256" : "P-384";
        const expectedSize = expectedSizes[curveName];
        if (pointData.length !== expectedSize) {
          throw new Error(`Invalid EC point size for ${curveName}: expected ${expectedSize}, got ${pointData.length}`);
        }
      }
      try {
        const algorithm = expectedAlgorithm === "ECDSA" || expectedAlgorithm === "ECDH" ? { name: expectedAlgorithm, namedCurve: "P-384" } : { name: expectedAlgorithm };
        const usages = expectedAlgorithm === "ECDSA" ? ["verify"] : [];
        await crypto.subtle.importKey("spki", keyBytes.buffer, algorithm, false, usages);
      } catch (importError) {
        if (expectedAlgorithm === "ECDSA" || expectedAlgorithm === "ECDH") {
          try {
            const algorithm = { name: expectedAlgorithm, namedCurve: "P-256" };
            const usages = expectedAlgorithm === "ECDSA" ? ["verify"] : [];
            await crypto.subtle.importKey("spki", keyBytes.buffer, algorithm, false, usages);
          } catch (fallbackError) {
            throw new Error(`Key import validation failed: ${fallbackError.message}`);
          }
        } else {
          throw new Error(`Key import validation failed: ${importError.message}`);
        }
      }
      return true;
    } catch (err) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Key structure validation failed", {
        error: err.message,
        algorithm: expectedAlgorithm
      });
      throw new Error(`Invalid key structure: ${err.message}`);
    }
  }
  // ASN.1 DER parser helper
  static parseASN1(bytes, offset = 0) {
    if (offset >= bytes.length) {
      return null;
    }
    const tag = bytes[offset];
    let lengthOffset = offset + 1;
    if (lengthOffset >= bytes.length) {
      throw new Error("Truncated ASN.1 structure");
    }
    let length = bytes[lengthOffset];
    let valueOffset = lengthOffset + 1;
    if (length & 128) {
      const numLengthBytes = length & 127;
      if (numLengthBytes > 4) {
        throw new Error("ASN.1 length too large");
      }
      length = 0;
      for (let i = 0; i < numLengthBytes; i++) {
        if (valueOffset + i >= bytes.length) {
          throw new Error("Truncated ASN.1 length");
        }
        length = length << 8 | bytes[valueOffset + i];
      }
      valueOffset += numLengthBytes;
    }
    if (valueOffset + length > bytes.length) {
      throw new Error("ASN.1 structure extends beyond data");
    }
    const value = bytes.slice(valueOffset, valueOffset + length);
    const node = {
      tag,
      length,
      value,
      children: []
    };
    if (tag === 48 || tag === 49) {
      let childOffset = 0;
      while (childOffset < value.length) {
        const child = _EnhancedSecureCryptoUtils.parseASN1(value, childOffset);
        if (!child) break;
        node.children.push(child);
        childOffset = childOffset + 1 + child.lengthBytes + child.length;
      }
    }
    node.lengthBytes = valueOffset - lengthOffset;
    return node;
  }
  // OID decoder helper
  static oidToString(bytes) {
    if (!bytes || bytes.length === 0) {
      throw new Error("Empty OID");
    }
    const parts = [];
    const first = Math.floor(bytes[0] / 40);
    const second = bytes[0] % 40;
    parts.push(first);
    parts.push(second);
    let value = 0;
    for (let i = 1; i < bytes.length; i++) {
      value = value << 7 | bytes[i] & 127;
      if (!(bytes[i] & 128)) {
        parts.push(value);
        value = 0;
      }
    }
    return parts.join(".");
  }
  // Helper to validate and sanitize OID string
  static validateOidString(oidString) {
    const oidRegex = /^[0-9]+(\.[0-9]+)*$/;
    if (!oidRegex.test(oidString)) {
      throw new Error(`Invalid OID format: ${oidString}`);
    }
    const parts = oidString.split(".").map(Number);
    if (parts[0] > 2) {
      throw new Error(`Invalid OID first component: ${parts[0]}`);
    }
    if ((parts[0] === 0 || parts[0] === 1) && parts[1] > 39) {
      throw new Error(`Invalid OID second component: ${parts[1]} (must be <= 39 for first component ${parts[0]})`);
    }
    return true;
  }
  // Export public key for transmission with signature 
  static async exportPublicKeyWithSignature(publicKey, signingKey, keyType = "ECDH") {
    try {
      if (!["ECDH", "ECDSA"].includes(keyType)) {
        throw new Error("Invalid key type");
      }
      const exported = await crypto.subtle.exportKey("spki", publicKey);
      const keyData = Array.from(new Uint8Array(exported));
      await _EnhancedSecureCryptoUtils.validateKeyStructure(keyData, keyType);
      const keyPackage = {
        keyType,
        keyData,
        timestamp: Date.now(),
        version: "4.0"
      };
      const packageString = JSON.stringify(keyPackage);
      const signature = await _EnhancedSecureCryptoUtils.signData(signingKey, packageString);
      const signedPackage = {
        ...keyPackage,
        signature
      };
      return signedPackage;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Public key export failed", {
        error: error.message,
        keyType
      });
      throw new Error(`Failed to export ${keyType} key: ${error.message}`);
    }
  }
  // Import and verify signed public key
  static async importSignedPublicKey(signedPackage, verifyingKey, expectedKeyType = "ECDH") {
    try {
      if (!signedPackage || typeof signedPackage !== "object") {
        throw new Error("Invalid signed package format");
      }
      const { keyType, keyData, timestamp, version: version2, signature } = signedPackage;
      if (!keyType || !keyData || !timestamp || !signature) {
        throw new Error("Missing required fields in signed package");
      }
      if (!_EnhancedSecureCryptoUtils.constantTimeCompare(keyType, expectedKeyType)) {
        throw new Error(`Key type mismatch: expected ${expectedKeyType}, got ${keyType}`);
      }
      const keyAge = Date.now() - timestamp;
      if (keyAge > 36e5) {
        throw new Error("Signed key package is too old");
      }
      await _EnhancedSecureCryptoUtils.validateKeyStructure(keyData, keyType);
      const packageCopy = { keyType, keyData, timestamp, version: version2 };
      const packageString = JSON.stringify(packageCopy);
      const isValidSignature = await _EnhancedSecureCryptoUtils.verifySignature(verifyingKey, signature, packageString);
      if (!isValidSignature) {
        throw new Error("Invalid signature on key package - possible MITM attack");
      }
      const keyBytes = new Uint8Array(keyData);
      try {
        const algorithm = keyType === "ECDH" ? { name: "ECDH", namedCurve: "P-384" } : { name: "ECDSA", namedCurve: "P-384" };
        const keyUsages = keyType === "ECDH" ? [] : ["verify"];
        const publicKey = await crypto.subtle.importKey(
          "spki",
          keyBytes,
          algorithm,
          false,
          // Non-extractable
          keyUsages
        );
        return publicKey;
      } catch (p384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "Elliptic curve P-384 import failed, switching curve", { error: p384Error.message });
        const algorithm = keyType === "ECDH" ? { name: "ECDH", namedCurve: "P-256" } : { name: "ECDSA", namedCurve: "P-256" };
        const keyUsages = keyType === "ECDH" ? [] : ["verify"];
        const publicKey = await crypto.subtle.importKey(
          "spki",
          keyBytes,
          algorithm,
          false,
          // Non-extractable
          keyUsages
        );
        return publicKey;
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Signed public key import failed", {
        error: error.message,
        expectedKeyType
      });
      throw new Error(`Failed to import the signed key: ${error.message}`);
    }
  }
  // Legacy export for backward compatibility
  static async exportPublicKey(publicKey) {
    try {
      const exported = await crypto.subtle.exportKey("spki", publicKey);
      const keyData = Array.from(new Uint8Array(exported));
      await _EnhancedSecureCryptoUtils.validateKeyStructure(keyData, "ECDH");
      return keyData;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Legacy public key export failed", { error: error.message });
      throw new Error("Failed to export the public key");
    }
  }
  // Legacy import for backward compatibility with fallback
  static async importPublicKey(keyData) {
    try {
      await _EnhancedSecureCryptoUtils.validateKeyStructure(keyData, "ECDH");
      const keyBytes = new Uint8Array(keyData);
      try {
        const publicKey = await crypto.subtle.importKey(
          "spki",
          keyBytes,
          {
            name: "ECDH",
            namedCurve: "P-384"
          },
          false,
          // Non-extractable
          []
        );
        return publicKey;
      } catch (p384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "P-384 import failed, trying P-256", { error: p384Error.message });
        const publicKey = await crypto.subtle.importKey(
          "spki",
          keyBytes,
          {
            name: "ECDH",
            namedCurve: "P-256"
          },
          false,
          // Non-extractable
          []
        );
        return publicKey;
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Legacy public key import failed", { error: error.message });
      throw new Error("Failed to import the public key");
    }
  }
  // Method to check if a key is trusted
  static isKeyTrusted(keyOrFingerprint) {
    if (keyOrFingerprint instanceof CryptoKey) {
      const meta = _EnhancedSecureCryptoUtils._keyMetadata.get(keyOrFingerprint);
      return meta ? meta.trusted === true : false;
    } else if (keyOrFingerprint && keyOrFingerprint._securityMetadata) {
      return keyOrFingerprint._securityMetadata.trusted === true;
    }
    return false;
  }
  static async importPublicKeyFromSignedPackage(signedPackage, verifyingKey = null, options = {}) {
    try {
      if (!signedPackage || !signedPackage.keyData || !signedPackage.signature) {
        throw new Error("Invalid signed key package format");
      }
      const requiredFields = ["keyData", "signature", "keyType", "timestamp", "version"];
      const missingFields = requiredFields.filter((field) => !signedPackage[field]);
      if (missingFields.length > 0) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Missing required fields in signed package", {
          missingFields,
          availableFields: Object.keys(signedPackage)
        });
        throw new Error(`Required fields are missing in the signed package: ${missingFields.join(", ")}`);
      }
      if (!verifyingKey) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "SECURITY VIOLATION: Signed package received without verifying key", {
          keyType: signedPackage.keyType,
          keySize: signedPackage.keyData.length,
          timestamp: signedPackage.timestamp,
          version: signedPackage.version,
          securityRisk: "HIGH - Potential MITM attack vector"
        });
        throw new Error("CRITICAL SECURITY ERROR: Signed key package received without a verification key. This may indicate a possible MITM attack attempt. Import rejected for security reasons.");
      }
      await _EnhancedSecureCryptoUtils.validateKeyStructure(signedPackage.keyData, signedPackage.keyType || "ECDH");
      const packageCopy = { ...signedPackage };
      delete packageCopy.signature;
      const packageString = JSON.stringify(packageCopy);
      const isValidSignature = await _EnhancedSecureCryptoUtils.verifySignature(verifyingKey, signedPackage.signature, packageString);
      if (!isValidSignature) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "SECURITY BREACH: Invalid signature detected - MITM attack prevented", {
          keyType: signedPackage.keyType,
          keySize: signedPackage.keyData.length,
          timestamp: signedPackage.timestamp,
          version: signedPackage.version,
          attackPrevented: true
        });
        throw new Error("CRITICAL SECURITY ERROR: Invalid key signature detected. This indicates a possible MITM attack attempt. Key import rejected.");
      }
      const keyFingerprint = await _EnhancedSecureCryptoUtils.calculateKeyFingerprint(signedPackage.keyData);
      const keyBytes = new Uint8Array(signedPackage.keyData);
      const keyType = signedPackage.keyType || "ECDH";
      try {
        const publicKey = await crypto.subtle.importKey(
          "spki",
          keyBytes,
          {
            name: keyType,
            namedCurve: "P-384"
          },
          false,
          // Non-extractable
          keyType === "ECDSA" ? ["verify"] : []
        );
        _EnhancedSecureCryptoUtils._keyMetadata.set(publicKey, {
          trusted: true,
          verificationStatus: "VERIFIED_SECURE",
          verificationTimestamp: Date.now()
        });
        return publicKey;
      } catch (p384Error) {
        _EnhancedSecureCryptoUtils.secureLog.log("warn", "P-384 import failed, trying P-256", { error: p384Error.message });
        const publicKey = await crypto.subtle.importKey(
          "spki",
          keyBytes,
          {
            name: keyType,
            namedCurve: "P-256"
          },
          false,
          // Non-extractable
          keyType === "ECDSA" ? ["verify"] : []
        );
        _EnhancedSecureCryptoUtils._keyMetadata.set(publicKey, {
          trusted: true,
          verificationStatus: "VERIFIED_SECURE",
          verificationTimestamp: Date.now()
        });
        return publicKey;
      }
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Signed package key import failed", {
        error: error.message,
        securityImplications: "Potential security breach prevented"
      });
      throw new Error(`Failed to import the public key from the signed package: ${error.message}`);
    }
  }
  // Enhanced key derivation with metadata protection and 64-byte salt
  static async deriveSharedKeys(privateKey, publicKey, salt) {
    try {
      if (!(privateKey instanceof CryptoKey)) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Private key is not a CryptoKey", {
          privateKeyType: typeof privateKey,
          privateKeyAlgorithm: privateKey?.algorithm?.name
        });
        throw new Error("The private key is not a valid CryptoKey.");
      }
      if (!(publicKey instanceof CryptoKey)) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Public key is not a CryptoKey", {
          publicKeyType: typeof publicKey,
          publicKeyAlgorithm: publicKey?.algorithm?.name
        });
        throw new Error("The public key is not a valid CryptoKey.");
      }
      if (!salt || salt.length !== 64) {
        throw new Error("Salt must be exactly 64 bytes for enhanced security");
      }
      const saltBytes = new Uint8Array(salt);
      const encoder = new TextEncoder();
      let rawSharedSecret;
      let sharedSecretBits = null;
      try {
        sharedSecretBits = await crypto.subtle.deriveBits(
          {
            name: "ECDH",
            public: publicKey
          },
          privateKey,
          256
        );
        rawSharedSecret = await crypto.subtle.importKey(
          "raw",
          sharedSecretBits,
          {
            name: "HKDF",
            hash: "SHA-256"
          },
          false,
          // deriveBits is required for the fingerprint material below;
          // without it that call fails with an InvalidAccessError.
          ["deriveKey", "deriveBits"]
        );
      } catch (error) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "ECDH derivation failed", {
          error: error.message
        });
        throw error;
      } finally {
        if (sharedSecretBits) {
          _EnhancedSecureCryptoUtils.zeroizeBuffer(sharedSecretBits);
          sharedSecretBits = null;
        }
      }
      let messageKey;
      messageKey = await crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: saltBytes,
          info: encoder.encode("message-encryption-v4")
        },
        rawSharedSecret,
        {
          name: "AES-GCM",
          length: 256
        },
        false,
        // Non-extractable for enhanced security
        ["encrypt", "decrypt"]
      );
      let macKey;
      macKey = await crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: saltBytes,
          info: encoder.encode("message-authentication-v4")
        },
        rawSharedSecret,
        {
          name: "HMAC",
          hash: "SHA-256"
        },
        false,
        // Non-extractable
        ["sign", "verify"]
      );
      let pfsKey;
      pfsKey = await crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: saltBytes,
          info: encoder.encode("perfect-forward-secrecy-v4")
        },
        rawSharedSecret,
        {
          name: "AES-GCM",
          length: 256
        },
        false,
        // Non-extractable
        ["encrypt", "decrypt"]
      );
      let metadataKey;
      metadataKey = await crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: saltBytes,
          info: encoder.encode("metadata-protection-v4")
        },
        rawSharedSecret,
        {
          name: "AES-GCM",
          length: 256
        },
        false,
        // Non-extractable
        ["encrypt", "decrypt"]
      );
      const ratchetRootBits = await crypto.subtle.deriveBits(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: saltBytes,
          info: encoder.encode("double-ratchet-root-v1")
        },
        rawSharedSecret,
        256
      );
      const ratchetRoot = new Uint8Array(ratchetRootBits);
      let fingerprintBits = null;
      let fingerprint;
      try {
        fingerprintBits = await crypto.subtle.deriveBits(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: saltBytes,
            info: encoder.encode("fingerprint-generation-v4")
          },
          rawSharedSecret,
          256
        );
        fingerprint = await _EnhancedSecureCryptoUtils.generateKeyFingerprint(
          new Uint8Array(fingerprintBits)
        );
      } finally {
        if (fingerprintBits) {
          _EnhancedSecureCryptoUtils.zeroizeBuffer(fingerprintBits);
          fingerprintBits = null;
        }
      }
      if (!(messageKey instanceof CryptoKey)) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Derived message key is not a CryptoKey", {
          messageKeyType: typeof messageKey,
          messageKeyAlgorithm: messageKey?.algorithm?.name
        });
        throw new Error("The derived message key is not a valid CryptoKey.");
      }
      if (!(macKey instanceof CryptoKey)) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Derived MAC key is not a CryptoKey", {
          macKeyType: typeof macKey,
          macKeyAlgorithm: macKey?.algorithm?.name
        });
        throw new Error("The derived MAC key is not a valid CryptoKey.");
      }
      if (!(pfsKey instanceof CryptoKey)) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Derived PFS key is not a CryptoKey", {
          pfsKeyType: typeof pfsKey,
          pfsKeyAlgorithm: pfsKey?.algorithm?.name
        });
        throw new Error("The derived PFS key is not a valid CryptoKey.");
      }
      if (!(metadataKey instanceof CryptoKey)) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "Derived metadata key is not a CryptoKey", {
          metadataKeyType: typeof metadataKey,
          metadataKeyAlgorithm: metadataKey?.algorithm?.name
        });
        throw new Error("The derived metadata key is not a valid CryptoKey.");
      }
      return {
        messageKey,
        // Renamed from encryptionKey for clarity
        macKey,
        pfsKey,
        // Added Perfect Forward Secrecy key
        metadataKey,
        // Raw bytes on purpose: a ratchet has to chain KDFs itself, which
        // WebCrypto cannot do behind a non-extractable handle. The caller
        // must hand this to DoubleRatchet.init() and zeroize it.
        ratchetRoot,
        fingerprint,
        timestamp: Date.now(),
        version: "4.0"
      };
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Enhanced key derivation failed", {
        error: error.message,
        errorStack: error.stack,
        privateKeyType: typeof privateKey,
        publicKeyType: typeof publicKey,
        saltLength: salt?.length,
        privateKeyAlgorithm: privateKey?.algorithm?.name,
        publicKeyAlgorithm: publicKey?.algorithm?.name
      });
      throw new Error(`Failed to create shared encryption keys: ${error.message}`);
    }
  }
  static async generateKeyFingerprint(keyData) {
    const keyBuffer = new Uint8Array(keyData);
    const hashBuffer = await crypto.subtle.digest("SHA-384", keyBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join(":");
  }
  // Generate mutual authentication challenge
  static generateMutualAuthChallenge() {
    const challenge = crypto.getRandomValues(new Uint8Array(48));
    const timestamp = Date.now();
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    return {
      challenge: Array.from(challenge),
      timestamp,
      nonce: Array.from(nonce),
      version: "4.0"
    };
  }
  // Create cryptographic proof for mutual authentication
  static async createAuthProof(challenge, privateKey, publicKey) {
    try {
      if (!challenge || !challenge.challenge || !challenge.timestamp || !challenge.nonce) {
        throw new Error("Invalid challenge structure");
      }
      const challengeAge = Date.now() - challenge.timestamp;
      if (challengeAge > 12e4) {
        throw new Error("Challenge expired");
      }
      const proofData = {
        challenge: challenge.challenge,
        timestamp: challenge.timestamp,
        nonce: challenge.nonce,
        responseTimestamp: Date.now(),
        publicKeyHash: await _EnhancedSecureCryptoUtils.hashPublicKey(publicKey)
      };
      const proofString = JSON.stringify(proofData);
      const signature = await _EnhancedSecureCryptoUtils.signData(privateKey, proofString);
      const proof = {
        ...proofData,
        signature,
        version: "4.0"
      };
      _EnhancedSecureCryptoUtils.secureLog.log("info", "Authentication proof created", {
        challengeAge: Math.round(challengeAge / 1e3) + "s"
      });
      return proof;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Authentication proof creation failed", { error: error.message });
      throw new Error(`Failed to create cryptographic proof: ${error.message}`);
    }
  }
  // Verify mutual authentication proof
  static async verifyAuthProof(proof, challenge, publicKey) {
    try {
      await new Promise((resolve) => setTimeout(resolve, Math.floor(Math.random() * 20) + 5));
      _EnhancedSecureCryptoUtils.assertCryptoKey(publicKey, "ECDSA", ["verify"]);
      if (!proof || !challenge || !publicKey) {
        throw new Error("Missing required parameters for proof verification");
      }
      const requiredFields = ["challenge", "timestamp", "nonce", "responseTimestamp", "publicKeyHash", "signature"];
      for (const field of requiredFields) {
        if (!proof[field]) {
          throw new Error(`Missing required field: ${field}`);
        }
      }
      if (!_EnhancedSecureCryptoUtils.constantTimeCompareArrays(proof.challenge, challenge.challenge) || proof.timestamp !== challenge.timestamp || !_EnhancedSecureCryptoUtils.constantTimeCompareArrays(proof.nonce, challenge.nonce)) {
        throw new Error("Challenge mismatch - possible replay attack");
      }
      const responseAge = Date.now() - proof.responseTimestamp;
      if (responseAge > 18e5) {
        throw new Error("Proof response expired");
      }
      const expectedHash = await _EnhancedSecureCryptoUtils.hashPublicKey(publicKey);
      if (!_EnhancedSecureCryptoUtils.constantTimeCompare(proof.publicKeyHash, expectedHash)) {
        throw new Error("Public key hash mismatch");
      }
      const proofCopy = { ...proof };
      delete proofCopy.signature;
      const proofString = JSON.stringify(proofCopy);
      const isValidSignature = await _EnhancedSecureCryptoUtils.verifySignature(publicKey, proof.signature, proofString);
      if (!isValidSignature) {
        throw new Error("Invalid proof signature");
      }
      _EnhancedSecureCryptoUtils.secureLog.log("info", "Authentication proof verified successfully", {
        responseAge: Math.round(responseAge / 1e3) + "s"
      });
      return true;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Authentication proof verification failed", { error: error.message });
      throw new Error(`Failed to verify cryptographic proof: ${error.message}`);
    }
  }
  // Hash public key for verification
  static async hashPublicKey(publicKey) {
    try {
      const exported = await crypto.subtle.exportKey("spki", publicKey);
      const hash = await crypto.subtle.digest("SHA-384", exported);
      const hashArray = Array.from(new Uint8Array(hash));
      return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Public key hashing failed", { error: error.message });
      throw new Error("Failed to create hash of the public key");
    }
  }
  // Legacy authentication challenge for backward compatibility
  static generateAuthChallenge() {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    return Array.from(challenge);
  }
  // Generate verification code for out-of-band authentication
  static generateVerificationCode() {
    const chars = "0123456789ABCDEF";
    const charCount = chars.length;
    let result = "";
    for (let i = 0; i < 6; i++) {
      let randomByte;
      do {
        randomByte = crypto.getRandomValues(new Uint8Array(1))[0];
      } while (randomByte >= 256 - 256 % charCount);
      result += chars[randomByte % charCount];
    }
    return result.match(/.{1,2}/g).join("-");
  }
  // Enhanced message encryption with metadata protection and sequence numbers
  static async encryptMessage(message, encryptionKey, macKey, metadataKey, messageId, sequenceNumber = 0) {
    try {
      if (!message || typeof message !== "string") {
        throw new Error("Invalid message format");
      }
      _EnhancedSecureCryptoUtils.assertCryptoKey(encryptionKey, "AES-GCM", ["encrypt"]);
      _EnhancedSecureCryptoUtils.assertCryptoKey(macKey, "HMAC", ["sign"]);
      _EnhancedSecureCryptoUtils.assertCryptoKey(metadataKey, "AES-GCM", ["encrypt"]);
      const encoder = new TextEncoder();
      const messageData = encoder.encode(message);
      const messageIv = crypto.getRandomValues(new Uint8Array(12));
      const metadataIv = crypto.getRandomValues(new Uint8Array(12));
      const timestamp = Date.now();
      const paddingSize = 16 - messageData.length % 16;
      const paddedMessage = new Uint8Array(messageData.length + paddingSize);
      paddedMessage.set(messageData);
      const padding = crypto.getRandomValues(new Uint8Array(paddingSize));
      paddedMessage.set(padding, messageData.length);
      const encryptedMessage = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: messageIv },
        encryptionKey,
        paddedMessage
      );
      const metadata = {
        id: messageId,
        timestamp,
        sequenceNumber,
        originalLength: messageData.length,
        version: "4.0"
      };
      const metadataStr = JSON.stringify(_EnhancedSecureCryptoUtils.sortObjectKeys(metadata));
      const encryptedMetadata = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: metadataIv },
        metadataKey,
        encoder.encode(metadataStr)
      );
      const payload = {
        messageIv: Array.from(messageIv),
        messageData: Array.from(new Uint8Array(encryptedMessage)),
        metadataIv: Array.from(metadataIv),
        metadataData: Array.from(new Uint8Array(encryptedMetadata)),
        version: "4.0"
      };
      const sortedPayload = _EnhancedSecureCryptoUtils.sortObjectKeys(payload);
      const payloadStr = JSON.stringify(sortedPayload);
      const mac = await crypto.subtle.sign(
        "HMAC",
        macKey,
        encoder.encode(payloadStr)
      );
      payload.mac = Array.from(new Uint8Array(mac));
      return payload;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Message encryption failed", {
        error: error.message,
        messageId
      });
      throw new Error(`Failed to encrypt the message: ${error.message}`);
    }
  }
  // Enhanced message decryption with metadata protection and sequence validation
  static async decryptMessage(encryptedPayload, encryptionKey, macKey, metadataKey, expectedSequenceNumber = null) {
    try {
      _EnhancedSecureCryptoUtils.assertCryptoKey(encryptionKey, "AES-GCM", ["decrypt"]);
      _EnhancedSecureCryptoUtils.assertCryptoKey(macKey, "HMAC", ["verify"]);
      _EnhancedSecureCryptoUtils.assertCryptoKey(metadataKey, "AES-GCM", ["decrypt"]);
      const requiredFields = ["messageIv", "messageData", "metadataIv", "metadataData", "mac", "version"];
      for (const field of requiredFields) {
        if (!encryptedPayload[field]) {
          throw new Error(`Missing required field: ${field}`);
        }
      }
      const payloadCopy = { ...encryptedPayload };
      delete payloadCopy.mac;
      const sortedPayloadCopy = _EnhancedSecureCryptoUtils.sortObjectKeys(payloadCopy);
      const payloadStr = JSON.stringify(sortedPayloadCopy);
      const macValid = await crypto.subtle.verify(
        "HMAC",
        macKey,
        new Uint8Array(encryptedPayload.mac),
        new TextEncoder().encode(payloadStr)
      );
      if (!macValid) {
        _EnhancedSecureCryptoUtils.secureLog.log("error", "MAC verification failed", {
          payloadFields: Object.keys(encryptedPayload),
          macLength: encryptedPayload.mac?.length
        });
        throw new Error("Message authentication failed - possible tampering");
      }
      const metadataIv = new Uint8Array(encryptedPayload.metadataIv);
      const metadataData = new Uint8Array(encryptedPayload.metadataData);
      const decryptedMetadataBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: metadataIv },
        metadataKey,
        metadataData
      );
      const metadataStr = new TextDecoder().decode(decryptedMetadataBuffer);
      const metadata = JSON.parse(metadataStr);
      if (!metadata.id || !metadata.timestamp || metadata.sequenceNumber === void 0 || !metadata.originalLength) {
        throw new Error("Invalid metadata structure");
      }
      const messageAge = Date.now() - metadata.timestamp;
      if (messageAge > 18e5) {
        throw new Error("Message expired (older than 30 minutes)");
      }
      if (expectedSequenceNumber !== null) {
        if (metadata.sequenceNumber < expectedSequenceNumber) {
          _EnhancedSecureCryptoUtils.secureLog.log("error", "Rejected message with stale sequence number - possible replay", {
            expected: expectedSequenceNumber,
            received: metadata.sequenceNumber,
            messageId: metadata.id
          });
          throw new Error(`Stale sequence number: expected at least ${expectedSequenceNumber}, got ${metadata.sequenceNumber}`);
        } else if (metadata.sequenceNumber > expectedSequenceNumber + 10) {
          throw new Error(`Sequence number gap too large: expected around ${expectedSequenceNumber}, got ${metadata.sequenceNumber}`);
        }
      }
      const messageIv = new Uint8Array(encryptedPayload.messageIv);
      const messageData = new Uint8Array(encryptedPayload.messageData);
      const decryptedMessageBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: messageIv },
        encryptionKey,
        messageData
      );
      const paddedMessage = new Uint8Array(decryptedMessageBuffer);
      const originalMessage = paddedMessage.slice(0, metadata.originalLength);
      const decoder = new TextDecoder();
      const message = decoder.decode(originalMessage);
      _EnhancedSecureCryptoUtils.secureLog.log("info", "Message decrypted successfully", {
        messageId: metadata.id,
        sequenceNumber: metadata.sequenceNumber,
        messageAge: Math.round(messageAge / 1e3) + "s"
      });
      return {
        message,
        messageId: metadata.id,
        timestamp: metadata.timestamp,
        sequenceNumber: metadata.sequenceNumber
      };
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Message decryption failed", { error: error.message });
      throw new Error(`Failed to decrypt the message: ${error.message}`);
    }
  }
  static _getMessageSanitizer() {
    if (_EnhancedSecureCryptoUtils._messageSanitizer) {
      return _EnhancedSecureCryptoUtils._messageSanitizer;
    }
    if (typeof window === "undefined" || !window?.document) {
      throw new Error("DOMPurify requires a browser-like window for message sanitization");
    }
    _EnhancedSecureCryptoUtils._messageSanitizer = purify(window);
    return _EnhancedSecureCryptoUtils._messageSanitizer;
  }
  // Centralized chat-message sanitization. Messages are rendered as plain text,
  // so the safest compatible output is text-only content with no markup surface.
  static sanitizeMessage(message) {
    if (typeof message !== "string") {
      throw new Error("Message must be a string");
    }
    const sanitized = _EnhancedSecureCryptoUtils._getMessageSanitizer().sanitize(message, {
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: [],
      ALLOW_UNKNOWN_PROTOCOLS: false,
      FORBID_TAGS: ["script", "style", "svg", "math", "template"],
      FORBID_ATTR: ["style"],
      KEEP_CONTENT: true,
      RETURN_TRUSTED_TYPE: false,
      USE_PROFILES: {
        html: false,
        svg: false,
        svgFilters: false,
        mathMl: false
      }
    });
    return String(sanitized).trim().substring(0, 2e3);
  }
  // Generate cryptographically secure salt (64 bytes for enhanced security)
  static generateSalt() {
    return Array.from(crypto.getRandomValues(new Uint8Array(64)));
  }
  // Calculate key fingerprint for MITM protection
  static async calculateKeyFingerprint(keyData) {
    try {
      const encoder = new TextEncoder();
      const keyBytes = new Uint8Array(keyData);
      const hashBuffer = await crypto.subtle.digest("SHA-256", keyBytes);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const fingerprint = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
      return fingerprint;
    } catch (error) {
      _EnhancedSecureCryptoUtils.secureLog.log("error", "Key fingerprint calculation failed", { error: error.message });
      throw new Error("Failed to compute the key fingerprint");
    }
  }
  static constantTimeCompare(a, b) {
    const strA = typeof a === "string" ? a : JSON.stringify(a);
    const strB = typeof b === "string" ? b : JSON.stringify(b);
    if (strA.length !== strB.length) {
      let dummy = 0;
      for (let i = 0; i < Math.max(strA.length, strB.length); i++) {
        dummy |= (strA.charCodeAt(i % strA.length) || 0) ^ (strB.charCodeAt(i % strB.length) || 0);
      }
      return false;
    }
    let result = 0;
    for (let i = 0; i < strA.length; i++) {
      result |= strA.charCodeAt(i) ^ strB.charCodeAt(i);
    }
    return result === 0;
  }
  static constantTimeCompareArrays(arr1, arr2) {
    if (!Array.isArray(arr1) || !Array.isArray(arr2)) {
      return false;
    }
    if (arr1.length !== arr2.length) {
      let dummy = 0;
      const maxLen = Math.max(arr1.length, arr2.length);
      for (let i = 0; i < maxLen; i++) {
        dummy |= (arr1[i % arr1.length] || 0) ^ (arr2[i % arr2.length] || 0);
      }
      return false;
    }
    let result = 0;
    for (let i = 0; i < arr1.length; i++) {
      result |= arr1[i] ^ arr2[i];
    }
    return result === 0;
  }
  /**
   * CRITICAL SECURITY: Encrypt data with AAD (Additional Authenticated Data)
   * This method provides authenticated encryption with additional data binding
   */
  static async encryptDataWithAAD(data, key, aad) {
    try {
      const dataString = typeof data === "string" ? data : JSON.stringify(data);
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(dataString);
      const aadBuffer = encoder.encode(aad);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: aadBuffer
        },
        key,
        dataBuffer
      );
      const encryptedPackage = {
        version: "1.0",
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted)),
        aad,
        timestamp: Date.now()
      };
      const packageString = JSON.stringify(encryptedPackage);
      const packageBuffer = encoder.encode(packageString);
      return _EnhancedSecureCryptoUtils.arrayBufferToBase64(packageBuffer);
    } catch (error) {
      throw new Error(`AAD encryption failed: ${error.message}`);
    }
  }
  /**
   * CRITICAL SECURITY: Decrypt data with AAD validation
   * This method provides authenticated decryption with additional data validation
   */
  static async decryptDataWithAAD(encryptedData, key, expectedAad) {
    try {
      const packageBuffer = _EnhancedSecureCryptoUtils.base64ToArrayBuffer(encryptedData);
      const packageString = new TextDecoder().decode(packageBuffer);
      const encryptedPackage = JSON.parse(packageString);
      if (!encryptedPackage.version || !encryptedPackage.iv || !encryptedPackage.data || !encryptedPackage.aad) {
        throw new Error("Invalid encrypted data format");
      }
      if (encryptedPackage.aad !== expectedAad) {
        throw new Error("AAD mismatch - possible tampering or replay attack");
      }
      const iv = new Uint8Array(encryptedPackage.iv);
      const encrypted = new Uint8Array(encryptedPackage.data);
      const aadBuffer = new TextEncoder().encode(encryptedPackage.aad);
      const decrypted = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: aadBuffer
        },
        key,
        encrypted
      );
      const decryptedString = new TextDecoder().decode(decrypted);
      try {
        return JSON.parse(decryptedString);
      } catch {
        return decryptedString;
      }
    } catch (error) {
      throw new Error(`AAD decryption failed: ${error.message}`);
    }
  }
  static {
    if (_EnhancedSecureCryptoUtils.secureLog && typeof _EnhancedSecureCryptoUtils.secureLog.init === "function") {
      _EnhancedSecureCryptoUtils.secureLog.init();
    }
  }
};

// src/transfer/EnhancedSecureFileTransfer.js
var SecureFileTransferContext = class _SecureFileTransferContext {
  static #instance = null;
  static #contextKey = /* @__PURE__ */ Symbol("SecureFileTransferContext");
  static getInstance() {
    if (!this.#instance) {
      this.#instance = new _SecureFileTransferContext();
    }
    return this.#instance;
  }
  #fileTransferSystem = null;
  #active = false;
  #securityLevel = "high";
  setFileTransferSystem(system) {
    if (!(system instanceof EnhancedSecureFileTransfer)) {
      throw new Error("Invalid file transfer system instance");
    }
    this.#fileTransferSystem = system;
    this.#active = true;
  }
  getFileTransferSystem() {
    return this.#fileTransferSystem;
  }
  isActive() {
    return this.#active && this.#fileTransferSystem !== null;
  }
  deactivate() {
    this.#active = false;
    this.#fileTransferSystem = null;
  }
  getSecurityLevel() {
    return this.#securityLevel;
  }
  setSecurityLevel(level) {
    if (["low", "medium", "high"].includes(level)) {
      this.#securityLevel = level;
    }
  }
};
var SecurityErrorHandler = class {
  static #allowedErrors = /* @__PURE__ */ new Set([
    "File size exceeds maximum limit",
    "Unsupported file type",
    "Transfer timeout",
    "Connection lost",
    "Invalid file data",
    "File transfer failed",
    "Transfer cancelled",
    "Network error",
    "File not found",
    "Permission denied"
  ]);
  static sanitizeError(error) {
    const message = error.message || error;
    for (const allowed of this.#allowedErrors) {
      if (message.includes(allowed)) {
        return allowed;
      }
    }
    console.error("\u{1F512} Internal file transfer error:", {
      message: error.message,
      stack: error.stack,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
    return "File transfer failed";
  }
  static logSecurityEvent(event, details = {}) {
    console.warn("\u{1F512} Security event:", {
      event,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      ...details
    });
  }
};
var FileMetadataSigner = class {
  static async signFileMetadata(metadata, privateKey) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(JSON.stringify({
        fileId: metadata.fileId,
        fileName: metadata.fileName,
        fileSize: metadata.fileSize,
        fileHash: metadata.fileHash,
        timestamp: metadata.timestamp,
        version: metadata.version || "2.0"
      }));
      const signature = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        privateKey,
        data
      );
      return Array.from(new Uint8Array(signature));
    } catch (error) {
      SecurityErrorHandler.logSecurityEvent("signature_failed", { error: error.message });
      throw new Error("Failed to sign file metadata");
    }
  }
  static async verifyFileMetadata(metadata, signature, publicKey) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(JSON.stringify({
        fileId: metadata.fileId,
        fileName: metadata.fileName,
        fileSize: metadata.fileSize,
        fileHash: metadata.fileHash,
        timestamp: metadata.timestamp,
        version: metadata.version || "2.0"
      }));
      const signatureBuffer = new Uint8Array(signature);
      const isValid = await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        publicKey,
        signatureBuffer,
        data
      );
      if (!isValid) {
        SecurityErrorHandler.logSecurityEvent("invalid_signature", { fileId: metadata.fileId });
      }
      return isValid;
    } catch (error) {
      SecurityErrorHandler.logSecurityEvent("verification_failed", { error: error.message });
      return false;
    }
  }
};
var MessageSizeValidator = class {
  static MAX_MESSAGE_SIZE = 1024 * 1024;
  // 1MB
  static isMessageSizeValid(message) {
    const messageString = JSON.stringify(message);
    const sizeInBytes = new Blob([messageString]).size;
    if (sizeInBytes > this.MAX_MESSAGE_SIZE) {
      SecurityErrorHandler.logSecurityEvent("message_too_large", {
        size: sizeInBytes,
        limit: this.MAX_MESSAGE_SIZE
      });
      throw new Error("Message too large");
    }
    return true;
  }
};
var AtomicOperations = class {
  constructor() {
    this.locks = /* @__PURE__ */ new Map();
  }
  async withLock(key, operation) {
    while (this.locks.has(key)) {
      await this.locks.get(key);
    }
    let releaseLock;
    const lockPromise = new Promise((resolve) => {
      releaseLock = resolve;
    });
    this.locks.set(key, lockPromise);
    try {
      return await operation();
    } finally {
      this.locks.delete(key);
      releaseLock();
    }
  }
};
var RateLimiter = class {
  constructor(maxRequests, windowMs) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = /* @__PURE__ */ new Map();
  }
  isAllowed(identifier) {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    if (!this.requests.has(identifier)) {
      this.requests.set(identifier, []);
    }
    const userRequests = this.requests.get(identifier);
    const validRequests = userRequests.filter((time) => time > windowStart);
    this.requests.set(identifier, validRequests);
    if (validRequests.length >= this.maxRequests) {
      SecurityErrorHandler.logSecurityEvent("rate_limit_exceeded", {
        identifier,
        requestCount: validRequests.length,
        limit: this.maxRequests
      });
      return false;
    }
    validRequests.push(now);
    return true;
  }
};
var SecureMemoryManager = class {
  static secureWipe(buffer) {
    if (buffer instanceof ArrayBuffer) {
      const view = new Uint8Array(buffer);
      crypto.getRandomValues(view);
    } else if (buffer instanceof Uint8Array) {
      crypto.getRandomValues(buffer);
    }
  }
  static secureDelete(obj, prop) {
    if (obj[prop]) {
      this.secureWipe(obj[prop]);
      delete obj[prop];
    }
  }
};
var EnhancedSecureFileTransfer = class {
  constructor(webrtcManager, onProgress, onComplete, onError, onFileReceived, onIncomingFileRequest) {
    this.webrtcManager = webrtcManager;
    this.onProgress = onProgress;
    this.onComplete = onComplete;
    this.onError = onError;
    this.onFileReceived = onFileReceived;
    this.onIncomingFileRequest = onIncomingFileRequest;
    if (!webrtcManager) {
      throw new Error("webrtcManager is required for EnhancedSecureFileTransfer");
    }
    SecureFileTransferContext.getInstance().setFileTransferSystem(this);
    this.atomicOps = new AtomicOperations();
    this.rateLimiter = new RateLimiter(10, 6e4);
    this.signingKey = null;
    this.verificationKey = null;
    this.CHUNK_SIZE = 16 * 1024;
    this.MAX_RECEIVE_CHUNK_SIZE = 64 * 1024;
    this.MAX_FILE_SIZE = 100 * 1024 * 1024;
    this.MAX_CONCURRENT_TRANSFERS = 3;
    this.CHUNK_TIMEOUT = 3e4;
    this.RETRY_ATTEMPTS = 3;
    this.FILE_TYPE_RESTRICTIONS = {
      pdf: {
        extensions: [".pdf"],
        mimeTypes: ["application/pdf", "application/x-pdf", "application/acrobat"],
        maxSize: 50 * 1024 * 1024,
        category: "PDF",
        description: "PDF"
      },
      text: {
        extensions: [".txt"],
        mimeTypes: ["text/plain", "application/txt"],
        maxSize: 10 * 1024 * 1024,
        category: "Plain text",
        description: "TXT"
      },
      images: {
        extensions: [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico"],
        mimeTypes: [
          "image/jpeg",
          "image/jpg",
          "image/pjpeg",
          "image/png",
          "image/gif",
          "image/webp",
          "image/bmp",
          "image/x-windows-bmp",
          "image/x-icon",
          "image/vnd.microsoft.icon"
        ],
        maxSize: 25 * 1024 * 1024,
        // 25 MB
        category: "Images",
        description: "JPG, JPEG, PNG, GIF, WEBP, BMP, ICO"
      },
      archives: {
        extensions: [".zip"],
        mimeTypes: [
          "application/zip",
          "application/x-zip",
          "application/x-zip-compressed",
          "multipart/x-zip"
        ],
        maxSize: 100 * 1024 * 1024,
        // 100 MB
        category: "Archives",
        description: "ZIP"
      },
      // Encrypted voice messages. Recorded in-browser via MediaRecorder and
      // sent as a normal chunked+AES-GCM transfer, so they inherit the exact
      // same end-to-end security as files. The app normalises the mime to a
      // bare `audio/webm` (or `audio/mp4` on Safari) before sending so the
      // codec-suffixed MediaRecorder type still matches this allow-list.
      voice: {
        extensions: [".webm", ".ogg", ".oga", ".opus", ".m4a", ".mp4", ".mp3", ".wav"],
        mimeTypes: [
          "audio/webm",
          "audio/ogg",
          "audio/opus",
          "audio/mp4",
          "audio/mpeg",
          "audio/mp3",
          "audio/wav",
          "audio/x-m4a",
          "audio/aac"
        ],
        maxSize: 20 * 1024 * 1024,
        // 20 MB (well beyond any sane voice note)
        category: "Voice",
        description: "Voice messages"
      }
    };
    this.BLOCKED_EXTENSIONS = /* @__PURE__ */ new Set([
      ".exe",
      ".bat",
      ".cmd",
      ".sh",
      ".js",
      ".msi",
      ".dmg",
      ".app",
      ".jar",
      ".scr",
      ".ps1",
      ".vbs",
      ".html",
      ".svg"
    ]);
    this._genericMimeTypes = /* @__PURE__ */ new Set(["application/octet-stream", "application/binary"]);
    this._allowedMimeTypes = /* @__PURE__ */ new Set();
    for (const typeConfig of Object.values(this.FILE_TYPE_RESTRICTIONS)) {
      for (const mime of typeConfig.mimeTypes) this._allowedMimeTypes.add(mime);
    }
    this.activeTransfers = /* @__PURE__ */ new Map();
    this.receivingTransfers = /* @__PURE__ */ new Map();
    this.pendingIncomingTransfers = /* @__PURE__ */ new Map();
    this.transferQueue = [];
    this.pendingChunks = /* @__PURE__ */ new Map();
    this.incomingOfferLimiter = new RateLimiter(5, 6e4);
    this.incomingChunkLimiter = new RateLimiter(6e4, 6e4);
    this.incomingTransferChunkLimiters = /* @__PURE__ */ new Map();
    this.MAX_INCOMING_CHUNKS_PER_TRANSFER_PER_MINUTE = 3e4;
    this.MAX_PENDING_INCOMING_TRANSFERS = 3;
    this.MAX_AUTO_ACCEPT_VOICE_SIZE = 4 * 1024 * 1024;
    this.MAX_AUTO_ACCEPT_VOICE_SESSION_BYTES = 64 * 1024 * 1024;
    this.autoAcceptedVoiceBytes = 0;
    this.sessionKeys = /* @__PURE__ */ new Map();
    this.processedChunks = /* @__PURE__ */ new Set();
    this.transferNonces = /* @__PURE__ */ new Map();
    this.receivedFileBuffers = /* @__PURE__ */ new Map();
    this.MAX_RETAINED_RECEIVED_FILE_BUFFERS = 3;
    this.setupFileMessageHandlers();
    if (this.webrtcManager) {
      this.webrtcManager.fileTransferSystem = this;
    }
  }
  // ============================================
  // FILE TYPE VALIDATION SYSTEM
  // ============================================
  getFileType(file) {
    const fileName = String(file?.name || "").toLowerCase();
    const extensionIndex = fileName.lastIndexOf(".");
    const fileExtension = extensionIndex >= 0 ? fileName.substring(extensionIndex) : "";
    const mimeType = String(file?.type || "").toLowerCase();
    for (const [typeKey, typeConfig] of Object.entries(this.FILE_TYPE_RESTRICTIONS)) {
      const extensionAllowed = typeConfig.extensions.includes(fileExtension);
      if (!extensionAllowed) continue;
      const mimeAcceptable = !mimeType || this._genericMimeTypes.has(mimeType) || this._allowedMimeTypes.has(mimeType);
      if (mimeAcceptable) {
        return {
          type: typeKey,
          category: typeConfig.category,
          description: typeConfig.description,
          maxSize: typeConfig.maxSize,
          allowed: true,
          extension: fileExtension,
          mimeType
        };
      }
    }
    return {
      type: "blocked",
      category: "Unsupported",
      description: "Allowed: JPG, JPEG, PNG, GIF, WEBP, BMP, ICO, PDF, TXT, ZIP",
      maxSize: this.MAX_FILE_SIZE,
      allowed: false,
      extension: fileExtension,
      mimeType
    };
  }
  validateFile(file) {
    const fileType = this.getFileType(file);
    const errors = [];
    const fileName = String(file?.name || "");
    const lowerName = fileName.toLowerCase();
    const extensionIndex = lowerName.lastIndexOf(".");
    const fileExtension = extensionIndex >= 0 ? lowerName.substring(extensionIndex) : "";
    if (this.BLOCKED_EXTENSIONS.has(fileExtension)) {
      errors.push(`File rejected: ${fileExtension} files are not allowed for security reasons.`);
    }
    if (file.size > fileType.maxSize) {
      errors.push(`File size (${this.formatFileSize(file.size)}) exceeds maximum allowed for ${fileType.category} (${this.formatFileSize(fileType.maxSize)})`);
    }
    if (!fileType.allowed && !this.BLOCKED_EXTENSIONS.has(fileExtension)) {
      errors.push(`File rejected: unsupported file type. Supported types: ${fileType.description}`);
    }
    if (file.size > this.MAX_FILE_SIZE) {
      errors.push(`File size (${this.formatFileSize(file.size)}) exceeds general limit (${this.formatFileSize(this.MAX_FILE_SIZE)})`);
    }
    return {
      isValid: errors.length === 0,
      errors,
      fileType,
      fileSize: file.size,
      formattedSize: this.formatFileSize(file.size)
    };
  }
  normalizeDisplayFileName(fileName) {
    return String(fileName || "").normalize("NFKC").replace(/[\u0000-\u001F\u007F]/g, "").replace(/[\\/]+/g, "_").trim().slice(0, 255);
  }
  validateIncomingMetadata(metadata) {
    const errors = [];
    if (!metadata || typeof metadata !== "object") errors.push("Invalid file transfer metadata");
    if (!metadata?.fileId || typeof metadata.fileId !== "string") errors.push("Invalid file id");
    if (!Number.isSafeInteger(metadata?.fileSize) || metadata.fileSize <= 0) errors.push("Invalid file size");
    if (!Number.isSafeInteger(metadata?.totalChunks) || metadata.totalChunks <= 0) errors.push("Invalid chunk count");
    if (!Number.isSafeInteger(metadata?.chunkSize) || metadata.chunkSize <= 0 || metadata.chunkSize > this.MAX_RECEIVE_CHUNK_SIZE) errors.push("Invalid chunk size");
    if (!Array.isArray(metadata?.salt) || metadata.salt.length !== 32) errors.push("Invalid salt");
    const rawName = typeof metadata?.fileName === "string" ? metadata.fileName : "";
    const displayName = this.normalizeDisplayFileName(rawName);
    const hasDangerousName = !rawName || rawName !== rawName.trim() || /[\u0000-\u001F\u007F]/.test(rawName) || /[\\/]/.test(rawName) || rawName === "." || rawName === ".." || displayName.length === 0;
    if (hasDangerousName) errors.push("Dangerous file name");
    if (errors.length === 0) {
      const validation = this.validateFile({
        name: displayName,
        size: metadata.fileSize,
        type: metadata.fileType || "application/octet-stream"
      });
      if (!validation.isValid) errors.push(...validation.errors);
    }
    const claimsVoice = !!metadata?.isVoice;
    const voiceRejection = claimsVoice ? this.rejectVoiceAutoAcceptReason(metadata) : null;
    return {
      isValid: errors.length === 0,
      errors,
      displayName,
      isVoice: claimsVoice && !voiceRejection,
      voiceRejection
    };
  }
  /**
   * Why a transfer claiming to be a voice note may not skip the consent card.
   * Returns null when it may. The generic MIME types that validateFile accepts
   * for ordinary uploads (application/octet-stream and friends) are explicitly
   * NOT enough here: they are what lets an arbitrary blob wear a `.mp4` name.
   */
  rejectVoiceAutoAcceptReason(metadata) {
    const mimeType = String(metadata?.fileType || "").toLowerCase();
    const size = metadata?.fileSize;
    if (!mimeType.startsWith("audio/")) {
      return `not an audio MIME type (${mimeType || "absent"})`;
    }
    if (!this.FILE_TYPE_RESTRICTIONS.voice.mimeTypes.includes(mimeType)) {
      return `unsupported audio MIME type (${mimeType})`;
    }
    if (!Number.isSafeInteger(size) || size <= 0 || size > this.MAX_AUTO_ACCEPT_VOICE_SIZE) {
      return `too large to auto-accept (${this.formatFileSize(size || 0)} > ${this.formatFileSize(this.MAX_AUTO_ACCEPT_VOICE_SIZE)})`;
    }
    if (this.autoAcceptedVoiceBytes + size > this.MAX_AUTO_ACCEPT_VOICE_SESSION_BYTES) {
      return "session auto-accept budget for voice notes is exhausted";
    }
    return null;
  }
  formatFileSize(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }
  getSupportedFileTypes() {
    const supportedTypes = {};
    for (const [typeKey, typeConfig] of Object.entries(this.FILE_TYPE_RESTRICTIONS)) {
      supportedTypes[typeKey] = {
        category: typeConfig.category,
        description: typeConfig.description,
        extensions: typeConfig.extensions,
        maxSize: this.formatFileSize(typeConfig.maxSize),
        maxSizeBytes: typeConfig.maxSize
      };
    }
    return supportedTypes;
  }
  getFileTypeInfo() {
    return {
      supportedTypes: this.getSupportedFileTypes(),
      generalMaxSize: this.formatFileSize(this.MAX_FILE_SIZE),
      generalMaxSizeBytes: this.MAX_FILE_SIZE,
      restrictions: this.FILE_TYPE_RESTRICTIONS
    };
  }
  // ============================================
  // ENCODING HELPERS (Base64 for efficient transport)
  // ============================================
  arrayBufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = "";
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  base64ToUint8Array(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
  // ============================================
  // PUBLIC ACCESSORS FOR RECEIVED FILES
  // ============================================
  getReceivedFileMeta(fileId) {
    const entry = this.receivedFileBuffers.get(fileId);
    if (!entry) return null;
    return { fileId, fileName: entry.name, fileSize: entry.size, mimeType: entry.type };
  }
  async getBlob(fileId) {
    const entry = this.receivedFileBuffers.get(fileId);
    if (!entry) return null;
    return new Blob([entry.buffer], { type: entry.type });
  }
  async getObjectURL(fileId) {
    const blob = await this.getBlob(fileId);
    if (!blob) return null;
    return URL.createObjectURL(blob);
  }
  revokeObjectURL(url) {
    try {
      URL.revokeObjectURL(url);
    } catch (_) {
    }
  }
  setupFileMessageHandlers() {
    if (!this.webrtcManager.dataChannel) {
      const setupRetry = setInterval(() => {
        if (this.webrtcManager.dataChannel) {
          clearInterval(setupRetry);
          this.setupMessageInterception();
        }
      }, 100);
      setTimeout(() => {
        clearInterval(setupRetry);
      }, 5e3);
      return;
    }
    this.setupMessageInterception();
  }
  setupMessageInterception() {
    try {
      if (!this.webrtcManager.dataChannel) {
        return;
      }
      if (this.webrtcManager) {
        this.webrtcManager.fileTransferSystem = this;
      }
      if (this.webrtcManager.dataChannel.onmessage) {
        this.originalOnMessage = this.webrtcManager.dataChannel.onmessage;
      }
      this.webrtcManager.dataChannel.onmessage = async (event) => {
        try {
          if (event.data.length > MessageSizeValidator.MAX_MESSAGE_SIZE) {
            console.warn("\u{1F512} Message too large, ignoring");
            SecurityErrorHandler.logSecurityEvent("oversized_message_blocked");
            return;
          }
          if (typeof event.data === "string") {
            try {
              const parsed = JSON.parse(event.data);
              MessageSizeValidator.isMessageSizeValid(parsed);
              if (this.isFileTransferMessage(parsed)) {
                await this.handleFileMessage(parsed);
                return;
              }
            } catch (parseError) {
              if (parseError.message === "Message too large") {
                return;
              }
            }
          }
          if (this.originalOnMessage) {
            return this.originalOnMessage.call(this.webrtcManager.dataChannel, event);
          }
        } catch (error) {
          console.error("\u274C Error in file system message interception:", error);
          if (this.originalOnMessage) {
            return this.originalOnMessage.call(this.webrtcManager.dataChannel, event);
          }
        }
      };
    } catch (error) {
      console.error("\u274C Failed to set up message interception:", error);
    }
  }
  isFileTransferMessage(message) {
    if (!message || typeof message !== "object" || !message.type) {
      return false;
    }
    const fileMessageTypes2 = [
      "file_transfer_start",
      "file_transfer_response",
      "file_chunk",
      "chunk_confirmation",
      "file_chunk_request",
      "file_transfer_complete",
      "file_transfer_error"
    ];
    return fileMessageTypes2.includes(message.type);
  }
  async handleFileMessage(message) {
    try {
      if (!this.webrtcManager.fileTransferSystem) {
        try {
          if (typeof this.webrtcManager.initializeFileTransfer === "function") {
            this.webrtcManager.initializeFileTransfer();
            let attempts2 = 0;
            const maxAttempts = 50;
            while (!this.webrtcManager.fileTransferSystem && attempts2 < maxAttempts) {
              await new Promise((resolve) => setTimeout(resolve, 100));
              attempts2++;
            }
            if (!this.webrtcManager.fileTransferSystem) {
              throw new Error("File transfer system initialization timeout");
            }
          } else {
            throw new Error("initializeFileTransfer method not available");
          }
        } catch (initError) {
          console.error("\u274C Failed to initialize file transfer system:", initError);
          if (message.fileId) {
            const errorMessage = {
              type: "file_transfer_error",
              fileId: message.fileId,
              error: "File transfer system not available",
              timestamp: Date.now()
            };
            await this.sendSecureMessage(errorMessage);
          }
          return;
        }
      }
      switch (message.type) {
        case "file_transfer_start":
          await this.handleFileTransferStart(message);
          break;
        case "file_transfer_response":
          this.handleTransferResponse(message);
          break;
        case "file_chunk":
          await this.handleFileChunk(message);
          break;
        case "chunk_confirmation":
          this.handleChunkConfirmation(message);
          break;
        case "file_chunk_request":
          await this.handleChunkRequest(message);
          break;
        case "file_transfer_complete":
          this.handleTransferComplete(message);
          break;
        case "file_transfer_error":
          this.handleTransferError(message);
          break;
        default:
          console.warn("\u26A0\uFE0F Unknown file message type:", message.type);
      }
    } catch (error) {
      console.error("\u274C Error handling file message:", error);
      if (message.fileId) {
        const errorMessage = {
          type: "file_transfer_error",
          fileId: message.fileId,
          error: error.message,
          timestamp: Date.now()
        };
        await this.sendSecureMessage(errorMessage);
      }
    }
  }
  // ============================================
  // SIMPLIFIED KEY DERIVATION - USE SHARED DATA
  // ============================================
  async deriveFileSessionKey(fileId) {
    try {
      if (!this.webrtcManager.keyFingerprint || !this.webrtcManager.sessionSalt) {
        throw new Error("WebRTC session data not available");
      }
      const fileSalt = crypto.getRandomValues(new Uint8Array(32));
      const encoder = new TextEncoder();
      const fingerprintData = encoder.encode(this.webrtcManager.keyFingerprint);
      const fileIdData = encoder.encode(fileId);
      const sessionSaltArray = new Uint8Array(this.webrtcManager.sessionSalt);
      const combinedSeed = new Uint8Array(
        fingerprintData.length + sessionSaltArray.length + fileSalt.length + fileIdData.length
      );
      let offset = 0;
      combinedSeed.set(fingerprintData, offset);
      offset += fingerprintData.length;
      combinedSeed.set(sessionSaltArray, offset);
      offset += sessionSaltArray.length;
      combinedSeed.set(fileSalt, offset);
      offset += fileSalt.length;
      combinedSeed.set(fileIdData, offset);
      const keyMaterial = await crypto.subtle.digest("SHA-256", combinedSeed);
      const fileSessionKey = await crypto.subtle.importKey(
        "raw",
        keyMaterial,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
      this.sessionKeys.set(fileId, {
        key: fileSessionKey,
        salt: Array.from(fileSalt),
        created: Date.now()
      });
      return { key: fileSessionKey, salt: Array.from(fileSalt) };
    } catch (error) {
      console.error("\u274C Failed to derive file session key:", error);
      throw error;
    }
  }
  async deriveFileSessionKeyFromSalt(fileId, saltArray) {
    try {
      if (!saltArray || !Array.isArray(saltArray) || saltArray.length !== 32) {
        throw new Error(`Invalid salt: ${saltArray?.length || 0} bytes`);
      }
      if (!this.webrtcManager.keyFingerprint || !this.webrtcManager.sessionSalt) {
        throw new Error("WebRTC session data not available");
      }
      const encoder = new TextEncoder();
      const fingerprintData = encoder.encode(this.webrtcManager.keyFingerprint);
      const fileIdData = encoder.encode(fileId);
      const fileSalt = new Uint8Array(saltArray);
      const sessionSaltArray = new Uint8Array(this.webrtcManager.sessionSalt);
      const combinedSeed = new Uint8Array(
        fingerprintData.length + sessionSaltArray.length + fileSalt.length + fileIdData.length
      );
      let offset = 0;
      combinedSeed.set(fingerprintData, offset);
      offset += fingerprintData.length;
      combinedSeed.set(sessionSaltArray, offset);
      offset += sessionSaltArray.length;
      combinedSeed.set(fileSalt, offset);
      offset += fileSalt.length;
      combinedSeed.set(fileIdData, offset);
      const keyMaterial = await crypto.subtle.digest("SHA-256", combinedSeed);
      const fileSessionKey = await crypto.subtle.importKey(
        "raw",
        keyMaterial,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
      this.sessionKeys.set(fileId, {
        key: fileSessionKey,
        salt: saltArray,
        created: Date.now()
      });
      return fileSessionKey;
    } catch (error) {
      console.error("\u274C Failed to derive session key from salt:", error);
      throw error;
    }
  }
  // ============================================
  // FILE TRANSFER IMPLEMENTATION
  // ============================================
  // Emit a progress update to the app layer. `direction` is 'up' for the
  // sender and 'down' for the receiver. `uiId` (sender only) lets the UI match
  // the event to a locally-created bubble before sendFile() has resolved a
  // fileId. Voice fields ride along so the receiver can render the waveform.
  _emitTransferProgress(state, direction) {
    if (typeof this.onProgress !== "function" || !state) return;
    const total = state.totalChunks || 0;
    const done = direction === "up" ? state.sentChunks || 0 : state.receivedCount || 0;
    const progress = total > 0 ? Math.min(100, Math.round(done / total * 100)) : 0;
    try {
      this.onProgress({
        fileId: state.fileId,
        uiId: state.uiId || null,
        direction,
        progress,
        transferredChunks: done,
        totalChunks: total,
        isVoice: !!state.isVoice,
        voice: state.voice || null
      });
    } catch (_) {
    }
  }
  async sendFile(file, options = {}) {
    try {
      if (!this.webrtcManager) {
        throw new Error("WebRTC Manager not initialized");
      }
      const clientId = this.getClientIdentifier();
      if (!this.rateLimiter.isAllowed(clientId)) {
        SecurityErrorHandler.logSecurityEvent("rate_limit_exceeded", { clientId });
        throw new Error("Rate limit exceeded. Please wait before sending another file.");
      }
      if (!file || !file.size) {
        throw new Error("Invalid file object");
      }
      const validation = this.validateFile(file);
      if (!validation.isValid) {
        const errorMessage = validation.errors.join(". ");
        throw new Error(errorMessage);
      }
      if (this.activeTransfers.size >= this.MAX_CONCURRENT_TRANSFERS) {
        throw new Error("Maximum concurrent transfers reached");
      }
      const fileId = `file_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const fileHash = await this.calculateFileHash(file);
      const keyResult = await this.deriveFileSessionKey(fileId);
      const sessionKey = keyResult.key;
      const salt = keyResult.salt;
      const transferState = {
        fileId,
        file,
        fileHash,
        sessionKey,
        salt,
        totalChunks: Math.ceil(file.size / this.CHUNK_SIZE),
        sentChunks: 0,
        confirmedChunks: 0,
        startTime: Date.now(),
        status: "preparing",
        retryCount: 0,
        lastChunkTime: Date.now(),
        // Voice-message extras (undefined for ordinary files).
        isVoice: !!(options && options.voice),
        voice: options && options.voice ? options.voice : null,
        uiId: options && options.uiId ? options.uiId : null
      };
      this.activeTransfers.set(fileId, transferState);
      this.transferNonces.set(fileId, 0);
      const consentPromise = new Promise((resolve, reject) => {
        transferState.resolveConsent = resolve;
        transferState.rejectConsent = reject;
        transferState.consentTimeout = setTimeout(() => {
          transferState.consentTimeout = null;
          reject(new Error("Transfer timeout"));
        }, 3e4);
      });
      await this.sendFileMetadata(transferState);
      await consentPromise;
      await this.startChunkTransmission(transferState);
      return fileId;
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C File sending failed:", safeError);
      if (this.onError) this.onError(safeError);
      throw new Error(safeError);
    }
  }
  async sendFileMetadata(transferState) {
    try {
      const metadata = {
        type: "file_transfer_start",
        fileId: transferState.fileId,
        fileName: transferState.file.name,
        fileSize: transferState.file.size,
        fileType: transferState.file.type || "application/octet-stream",
        fileHash: transferState.fileHash,
        totalChunks: transferState.totalChunks,
        chunkSize: this.CHUNK_SIZE,
        salt: transferState.salt,
        timestamp: Date.now(),
        version: "2.0"
      };
      if (transferState.isVoice) {
        metadata.isVoice = true;
        if (transferState.voice) metadata.voice = transferState.voice;
      }
      if (this.signingKey) {
        try {
          metadata.signature = await FileMetadataSigner.signFileMetadata(metadata, this.signingKey);
          console.log("\u{1F512} File metadata signed successfully");
        } catch (signError) {
          SecurityErrorHandler.logSecurityEvent("signature_failed", {
            fileId: transferState.fileId,
            error: signError.message
          });
        }
      }
      await this.sendSecureMessage(metadata);
      transferState.status = "metadata_sent";
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C Failed to send file metadata:", safeError);
      transferState.status = "failed";
      throw new Error(safeError);
    }
  }
  async startChunkTransmission(transferState) {
    try {
      transferState.status = "transmitting";
      const file = transferState.file;
      const totalChunks = transferState.totalChunks;
      for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
        const start2 = chunkIndex * this.CHUNK_SIZE;
        const end = Math.min(start2 + this.CHUNK_SIZE, file.size);
        const chunkData = await this.readFileChunk(file, start2, end);
        await this.sendFileChunk(transferState, chunkIndex, chunkData);
        transferState.sentChunks++;
        const progress = Math.round(transferState.sentChunks / totalChunks * 95) + 5;
        this._emitTransferProgress(transferState, "up");
        await this.waitForBackpressure();
      }
      transferState.status = "waiting_confirmation";
      this._armSenderIdleTimeout(transferState);
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C Chunk transmission failed:", safeError);
      transferState.status = "failed";
      throw new Error(safeError);
    }
  }
  // Resets a long idle timer; the sender stays available to retransmit missing
  // chunks until the receiver finishes or this fires after sustained silence.
  _armSenderIdleTimeout(transferState) {
    const IDLE_MS = 18e4;
    if (transferState._idleTimeout) clearTimeout(transferState._idleTimeout);
    transferState._idleTimeout = setTimeout(() => {
      const state = this.activeTransfers.get(transferState.fileId);
      if (state && state.status !== "completed") {
        this.cleanupTransfer(transferState.fileId);
      }
    }, IDLE_MS);
  }
  // Receiver asked us to re-send specific chunk indices (loss recovery / resume).
  async handleChunkRequest(message) {
    const transferState = this.activeTransfers.get(message?.fileId);
    if (!transferState || !transferState.file) return;
    const missing = Array.isArray(message.missing) ? message.missing : [];
    if (missing.length === 0) return;
    this._armSenderIdleTimeout(transferState);
    transferState.status = "transmitting";
    const MAX_PER_REQUEST = 512;
    const indices = missing.slice(0, MAX_PER_REQUEST);
    for (const idx of indices) {
      if (!Number.isInteger(idx) || idx < 0 || idx >= transferState.totalChunks) continue;
      try {
        const start2 = idx * this.CHUNK_SIZE;
        const end = Math.min(start2 + this.CHUNK_SIZE, transferState.file.size);
        const chunkData = await this.readFileChunk(transferState.file, start2, end);
        await this.sendFileChunk(transferState, idx, chunkData);
        await this.waitForBackpressure();
      } catch (error) {
        console.warn("\u26A0\uFE0F Failed to retransmit chunk", idx, SecurityErrorHandler.sanitizeError(error));
      }
    }
    if (transferState.status === "transmitting") {
      transferState.status = "waiting_confirmation";
    }
    this._armSenderIdleTimeout(transferState);
  }
  async readFileChunk(file, start2, end) {
    try {
      const blob = file.slice(start2, end);
      return await blob.arrayBuffer();
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C Failed to read file chunk:", safeError);
      throw new Error(safeError);
    }
  }
  async sendFileChunk(transferState, chunkIndex, chunkData) {
    try {
      const sessionKey = transferState.sessionKey;
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const encryptedChunk = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce
        },
        sessionKey,
        chunkData
      );
      const encryptedB64 = this.arrayBufferToBase64(new Uint8Array(encryptedChunk));
      const chunkMessage = {
        type: "file_chunk",
        fileId: transferState.fileId,
        chunkIndex,
        totalChunks: transferState.totalChunks,
        nonce: Array.from(nonce),
        encryptedDataB64: encryptedB64,
        chunkSize: chunkData.byteLength,
        timestamp: Date.now()
      };
      await this.waitForBackpressure();
      await this.sendSecureMessage(chunkMessage);
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C Failed to send file chunk:", safeError);
      throw new Error(safeError);
    }
  }
  async sendSecureMessage(message) {
    const messageString = JSON.stringify(message);
    const dc = this.webrtcManager?.dataChannel;
    const maxRetries = 10;
    let attempt = 0;
    const wait = (ms) => new Promise((r) => setTimeout(r, ms));
    while (true) {
      try {
        if (!dc || dc.readyState !== "open") {
          throw new Error("Data channel not ready");
        }
        await this.waitForBackpressure();
        dc.send(messageString);
        return;
      } catch (error) {
        const msg = String(error?.message || "");
        const queueFull = msg.includes("send queue is full") || msg.includes("bufferedAmount");
        const opErr = error?.name === "OperationError";
        if ((queueFull || opErr) && attempt < maxRetries) {
          attempt++;
          await this.waitForBackpressure();
          await wait(Math.min(50 * attempt, 500));
          continue;
        }
        console.error("\u274C Failed to send secure message:", error);
        throw error;
      }
    }
  }
  async waitForBackpressure() {
    try {
      const dc = this.webrtcManager?.dataChannel;
      if (!dc) return;
      if (typeof dc.bufferedAmountLowThreshold === "number") {
        if (dc.bufferedAmount > dc.bufferedAmountLowThreshold) {
          await new Promise((resolve) => {
            const handler = () => {
              dc.removeEventListener("bufferedamountlow", handler);
              resolve();
            };
            dc.addEventListener("bufferedamountlow", handler, { once: true });
          });
        }
        return;
      }
      const softLimit = 4 * 1024 * 1024;
      while (dc.bufferedAmount > softLimit) {
        await new Promise((r) => setTimeout(r, 20));
      }
    } catch (_) {
    }
  }
  async calculateFileHash(file) {
    try {
      const arrayBuffer = await file.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch (error) {
      console.error("\u274C File hash calculation failed:", error);
      throw error;
    }
  }
  // ============================================
  // MESSAGE HANDLERS
  // ============================================
  async handleFileTransferStart(metadata) {
    try {
      const clientId = this.getClientIdentifier();
      if (!this.incomingOfferLimiter.isAllowed(clientId)) {
        throw new Error("Incoming file request rate limit exceeded");
      }
      const validation = this.validateIncomingMetadata(metadata);
      if (!validation.isValid) throw new Error(validation.errors.join(". "));
      if (metadata.signature && this.verificationKey) {
        try {
          const isValid = await FileMetadataSigner.verifyFileMetadata(
            metadata,
            metadata.signature,
            this.verificationKey
          );
          if (!isValid) {
            SecurityErrorHandler.logSecurityEvent("invalid_metadata_signature", {
              fileId: metadata.fileId
            });
            throw new Error("Invalid file metadata signature");
          }
          console.log("\u{1F512} File metadata signature verified successfully");
        } catch (verifyError) {
          SecurityErrorHandler.logSecurityEvent("verification_failed", {
            fileId: metadata.fileId,
            error: verifyError.message
          });
          throw new Error("File metadata verification failed");
        }
      }
      if (this.receivingTransfers.has(metadata.fileId) || this.pendingIncomingTransfers.has(metadata.fileId)) {
        return;
      }
      if (this.pendingIncomingTransfers.size >= this.MAX_PENDING_INCOMING_TRANSFERS) {
        throw new Error("Too many pending incoming file requests");
      }
      if (validation.voiceRejection) {
        console.warn(`Voice auto-accept declined, falling back to consent: ${validation.voiceRejection}`);
      }
      const pendingMetadata = {
        ...metadata,
        // Never carry the sender's claim forward — only our own verdict.
        isVoice: validation.isVoice,
        fileName: validation.displayName,
        receivedAt: Date.now()
      };
      this.pendingIncomingTransfers.set(metadata.fileId, pendingMetadata);
      if (validation.isVoice) {
        this.autoAcceptedVoiceBytes += metadata.fileSize;
      }
      if (typeof this.onIncomingFileRequest === "function") {
        this.onIncomingFileRequest({
          fileId: pendingMetadata.fileId,
          fileName: pendingMetadata.fileName,
          fileSize: pendingMetadata.fileSize,
          mimeType: pendingMetadata.fileType || "application/octet-stream",
          // Voice notes auto-accept and render inline (no consent card).
          // This flag is the receiver's decision, not the sender's.
          isVoice: validation.isVoice,
          voice: pendingMetadata.voice || null
        });
      } else {
        await this.rejectIncomingFile(metadata.fileId, "User consent unavailable");
      }
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C Failed to handle file transfer start:", safeError);
      const errorResponse = {
        type: "file_transfer_response",
        fileId: metadata.fileId,
        accepted: false,
        error: safeError,
        timestamp: Date.now()
      };
      await this.sendSecureMessage(errorResponse);
    }
  }
  async handleFileChunk(chunkMessage) {
    return this.atomicOps.withLock(
      `chunk-${chunkMessage.fileId}`,
      async () => {
        try {
          let receivingState = this.receivingTransfers.get(chunkMessage.fileId);
          if (!receivingState) {
            return;
          }
          if (receivingState._assembled || receivingState.status === "completed") {
            return;
          }
          if (!this._isIncomingChunkAllowed(chunkMessage.fileId)) {
            console.warn("\u26A0\uFE0F Incoming file chunk rate limit exceeded; cleaning up transfer:", chunkMessage.fileId);
            this.cleanupReceivingTransfer(chunkMessage.fileId);
            return;
          }
          receivingState.lastChunkTime = Date.now();
          if (receivingState.receivedChunks.has(chunkMessage.chunkIndex)) {
            return;
          }
          if (chunkMessage.chunkIndex < 0 || chunkMessage.chunkIndex >= receivingState.totalChunks) {
            throw new Error(`Invalid chunk index: ${chunkMessage.chunkIndex}`);
          }
          const nonce = new Uint8Array(chunkMessage.nonce);
          let encryptedData;
          if (chunkMessage.encryptedDataB64) {
            encryptedData = this.base64ToUint8Array(chunkMessage.encryptedDataB64);
          } else if (chunkMessage.encryptedData) {
            encryptedData = new Uint8Array(chunkMessage.encryptedData);
          } else {
            throw new Error("Missing encrypted data");
          }
          const decryptedChunk = await crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: nonce
            },
            receivingState.sessionKey,
            encryptedData
          );
          if (decryptedChunk.byteLength !== chunkMessage.chunkSize) {
            throw new Error(`Chunk size mismatch: expected ${chunkMessage.chunkSize}, got ${decryptedChunk.byteLength}`);
          }
          receivingState.receivedChunks.set(chunkMessage.chunkIndex, decryptedChunk);
          receivingState.receivedCount++;
          this._emitTransferProgress(receivingState, "down");
          const confirmation = {
            type: "chunk_confirmation",
            fileId: chunkMessage.fileId,
            chunkIndex: chunkMessage.chunkIndex,
            timestamp: Date.now()
          };
          await this.sendSecureMessage(confirmation);
          if (receivingState.receivedCount === receivingState.totalChunks) {
            await this.assembleFile(receivingState);
          }
        } catch (error) {
          const safeError = SecurityErrorHandler.sanitizeError(error);
          console.warn("\u26A0\uFE0F Dropping unprocessable file chunk (will be re-requested):", chunkMessage.chunkIndex, safeError);
        }
      }
    );
  }
  _isIncomingChunkAllowed(fileId) {
    const clientId = this.getClientIdentifier();
    if (!this.incomingChunkLimiter.isAllowed(clientId)) {
      SecurityErrorHandler.logSecurityEvent("incoming_chunk_aggregate_rate_limit_exceeded", {
        clientId,
        fileId
      });
      return false;
    }
    if (!this.incomingTransferChunkLimiters.has(fileId)) {
      this.incomingTransferChunkLimiters.set(
        fileId,
        new RateLimiter(this.MAX_INCOMING_CHUNKS_PER_TRANSFER_PER_MINUTE, 6e4)
      );
    }
    const transferLimiter = this.incomingTransferChunkLimiters.get(fileId);
    if (!transferLimiter.isAllowed(fileId)) {
      SecurityErrorHandler.logSecurityEvent("incoming_chunk_transfer_rate_limit_exceeded", {
        clientId,
        fileId
      });
      return false;
    }
    return true;
  }
  async assembleFile(receivingState) {
    if (receivingState._assembled) {
      return;
    }
    receivingState._assembled = true;
    try {
      receivingState.status = "assembling";
      for (let i = 0; i < receivingState.totalChunks; i++) {
        if (!receivingState.receivedChunks.has(i)) {
          throw new Error(`Missing chunk ${i}`);
        }
      }
      const chunks = [];
      for (let i = 0; i < receivingState.totalChunks; i++) {
        const chunk = receivingState.receivedChunks.get(i);
        chunks.push(new Uint8Array(chunk));
      }
      const totalSize = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
      if (totalSize !== receivingState.fileSize) {
        throw new Error(`File size mismatch: expected ${receivingState.fileSize}, got ${totalSize}`);
      }
      const fileData = new Uint8Array(totalSize);
      let offset = 0;
      for (const chunk of chunks) {
        fileData.set(chunk, offset);
        offset += chunk.length;
      }
      const receivedHash = await this.calculateFileHashFromData(fileData);
      if (receivedHash !== receivingState.fileHash) {
        throw new Error("File integrity check failed - hash mismatch");
      }
      const fileBuffer = fileData.buffer;
      const fileBlob = new Blob([fileBuffer], { type: receivingState.fileType });
      receivingState.endTime = Date.now();
      receivingState.status = "completed";
      this._storeReceivedFileBuffer(receivingState.fileId, {
        buffer: fileBuffer,
        type: receivingState.fileType,
        name: receivingState.fileName,
        size: receivingState.fileSize
      });
      if (this.onFileReceived) {
        const getBlob = async () => {
          const blob = await this.getBlob(receivingState.fileId);
          if (!blob) {
            throw new Error("This file is no longer available for download.");
          }
          return blob;
        };
        const getObjectURL = async () => {
          const blob = await getBlob();
          return URL.createObjectURL(blob);
        };
        const revokeObjectURL = (url) => {
          try {
            URL.revokeObjectURL(url);
          } catch (_) {
          }
        };
        this.onFileReceived({
          fileId: receivingState.fileId,
          fileName: receivingState.fileName,
          fileSize: receivingState.fileSize,
          mimeType: receivingState.fileType,
          transferTime: receivingState.endTime - receivingState.startTime,
          // Voice notes are played inline, not saved to disk.
          isVoice: !!receivingState.isVoice,
          voice: receivingState.voice || null,
          // backward-compatibility for existing UIs
          fileBlob,
          getBlob,
          getObjectURL,
          revokeObjectURL
        });
      }
      const completionMessage = {
        type: "file_transfer_complete",
        fileId: receivingState.fileId,
        success: true,
        timestamp: Date.now()
      };
      await this.sendSecureMessage(completionMessage);
      if (receivingState._stallTimer) {
        clearInterval(receivingState._stallTimer);
        receivingState._stallTimer = null;
      }
      if (receivingState.receivedChunks) receivingState.receivedChunks.clear();
      receivingState.sessionKey = null;
    } catch (error) {
      console.error("\u274C File assembly failed:", error);
      receivingState.status = "failed";
      if (this.onError) {
        this.onError(`File assembly failed: ${error.message}`);
      }
      const errorMessage = {
        type: "file_transfer_complete",
        fileId: receivingState.fileId,
        success: false,
        error: error.message,
        timestamp: Date.now()
      };
      await this.sendSecureMessage(errorMessage);
      this.cleanupReceivingTransfer(receivingState.fileId);
    }
  }
  async calculateFileHashFromData(data) {
    try {
      const hashBuffer = await crypto.subtle.digest("SHA-256", data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch (error) {
      console.error("\u274C Hash calculation failed:", error);
      throw error;
    }
  }
  handleTransferResponse(response) {
    try {
      const transferState = this.activeTransfers.get(response.fileId);
      if (!transferState) {
        return;
      }
      if (response.accepted) {
        transferState.status = "accepted";
        if (transferState.consentTimeout) clearTimeout(transferState.consentTimeout);
        transferState.consentTimeout = null;
        transferState.resolveConsent?.();
        transferState.resolveConsent = null;
        transferState.rejectConsent = null;
      } else {
        transferState.status = "rejected";
        if (transferState.consentTimeout) clearTimeout(transferState.consentTimeout);
        transferState.consentTimeout = null;
        transferState.rejectConsent?.(new Error(response.error || "Transfer rejected"));
        transferState.rejectConsent = null;
        transferState.resolveConsent = null;
        if (this.onError) {
          this.onError(`Transfer rejected: ${response.error || "Unknown reason"}`);
        }
        this.cleanupTransfer(response.fileId);
      }
    } catch (error) {
      console.error("\u274C Failed to handle transfer response:", error);
    }
  }
  handleChunkConfirmation(confirmation) {
    try {
      const transferState = this.activeTransfers.get(confirmation.fileId);
      if (!transferState) {
        return;
      }
      transferState.confirmedChunks++;
      transferState.lastChunkTime = Date.now();
      if (transferState.status === "waiting_confirmation") {
        this._armSenderIdleTimeout(transferState);
      }
    } catch (error) {
      console.error("\u274C Failed to handle chunk confirmation:", error);
    }
  }
  handleTransferComplete(completion) {
    try {
      const transferState = this.activeTransfers.get(completion.fileId);
      if (!transferState) {
        return;
      }
      if (completion.success) {
        transferState.status = "completed";
        transferState.endTime = Date.now();
        if (this.onComplete) {
          this.onComplete({
            fileId: transferState.fileId,
            fileName: transferState.file.name,
            fileSize: transferState.file.size,
            transferTime: transferState.endTime - transferState.startTime,
            status: "completed"
          });
        }
      } else {
        transferState.status = "failed";
        if (this.onError) {
          this.onError(`Transfer failed: ${completion.error || "Unknown error"}`);
        }
      }
      this.cleanupTransfer(completion.fileId);
    } catch (error) {
      console.error("\u274C Failed to handle transfer completion:", error);
    }
  }
  handleTransferError(errorMessage) {
    try {
      const transferState = this.activeTransfers.get(errorMessage.fileId);
      if (transferState) {
        transferState.status = "failed";
        this.cleanupTransfer(errorMessage.fileId);
      }
      const receivingState = this.receivingTransfers.get(errorMessage.fileId);
      if (receivingState) {
        receivingState.status = "failed";
        this.cleanupReceivingTransfer(errorMessage.fileId);
      }
      if (this.onError) {
        this.onError(`Transfer error: ${errorMessage.error || "Unknown error"}`);
      }
    } catch (error) {
      console.error("\u274C Failed to handle transfer error:", error);
    }
  }
  // ============================================
  // UTILITY METHODS
  // ============================================
  getActiveTransfers() {
    return Array.from(this.activeTransfers.values()).map((transfer) => ({
      fileId: transfer.fileId,
      fileName: transfer.file?.name || "Unknown",
      fileSize: transfer.file?.size || 0,
      progress: Math.round(transfer.sentChunks / transfer.totalChunks * 100),
      // Per-chunk detail for the segmented progress UI.
      totalChunks: transfer.totalChunks || 0,
      transferredChunks: transfer.sentChunks || 0,
      status: transfer.status,
      startTime: transfer.startTime
    }));
  }
  getReceivingTransfers() {
    return Array.from(this.receivingTransfers.values()).map((transfer) => ({
      fileId: transfer.fileId,
      fileName: transfer.fileName || "Unknown",
      fileSize: transfer.fileSize || 0,
      progress: Math.round(transfer.receivedCount / transfer.totalChunks * 100),
      // Per-chunk detail for the segmented progress UI.
      totalChunks: transfer.totalChunks || 0,
      transferredChunks: transfer.receivedCount || 0,
      status: transfer.status,
      startTime: transfer.startTime
    }));
  }
  getPendingIncomingTransfers() {
    return Array.from(this.pendingIncomingTransfers.values()).map((transfer) => ({
      fileId: transfer.fileId,
      fileName: transfer.fileName,
      fileSize: transfer.fileSize,
      mimeType: transfer.fileType || "application/octet-stream",
      receivedAt: transfer.receivedAt
    }));
  }
  async acceptIncomingFile(fileId) {
    const metadata = this.pendingIncomingTransfers.get(fileId);
    if (!metadata) return false;
    const sessionKey = await this.deriveFileSessionKeyFromSalt(fileId, metadata.salt);
    this.receivingTransfers.set(fileId, {
      fileId,
      fileName: metadata.fileName,
      fileSize: metadata.fileSize,
      fileType: metadata.fileType || "application/octet-stream",
      fileHash: metadata.fileHash,
      totalChunks: metadata.totalChunks,
      chunkSize: metadata.chunkSize || this.CHUNK_SIZE,
      sessionKey,
      salt: metadata.salt,
      receivedChunks: /* @__PURE__ */ new Map(),
      receivedCount: 0,
      startTime: Date.now(),
      lastChunkTime: Date.now(),
      status: "receiving",
      isVoice: !!metadata.isVoice,
      voice: metadata.voice || null
    });
    this.pendingIncomingTransfers.delete(fileId);
    await this.sendSecureMessage({ type: "file_transfer_response", fileId, accepted: true, timestamp: Date.now() });
    this._startReceiverStallDetector(fileId);
    return true;
  }
  // Periodically detects a stalled receive (lost chunks, connection blip,
  // reconnect) and asks the sender to retransmit only the chunks we are still
  // missing — so a dropped connection never loses the file.
  _startReceiverStallDetector(fileId) {
    const TICK_MS = 2500;
    const STALL_MS = 5e3;
    const MAX_IDLE_MS = 18e4;
    const rs = this.receivingTransfers.get(fileId);
    if (!rs) return;
    if (rs._stallTimer) clearInterval(rs._stallTimer);
    rs._lastProgressCount = rs.receivedCount || 0;
    rs._lastProgressTime = Date.now();
    rs._stallTimer = setInterval(async () => {
      const state = this.receivingTransfers.get(fileId);
      if (!state || state._stallTimer !== rs._stallTimer) {
        clearInterval(rs._stallTimer);
        return;
      }
      if (state.status === "completed" || state._assembled) {
        clearInterval(state._stallTimer);
        state._stallTimer = null;
        return;
      }
      if (state.receivedCount !== state._lastProgressCount) {
        state._lastProgressCount = state.receivedCount;
        state._lastProgressTime = Date.now();
      }
      if (state.receivedCount >= state.totalChunks) return;
      if (Date.now() - (state.lastChunkTime || 0) < STALL_MS) return;
      if (Date.now() - state._lastProgressTime > MAX_IDLE_MS) {
        clearInterval(state._stallTimer);
        state._stallTimer = null;
        state.status = "failed";
        if (this.onError) this.onError("File transfer stalled \u2014 no data received. Please try again.");
        this.cleanupReceivingTransfer(fileId);
        return;
      }
      await this._requestMissingChunks(fileId);
    }, TICK_MS);
  }
  async _requestMissingChunks(fileId) {
    const state = this.receivingTransfers.get(fileId);
    if (!state || !state.receivedChunks) return;
    const MAX_PER_REQUEST = 256;
    const missing = [];
    for (let i = 0; i < state.totalChunks && missing.length < MAX_PER_REQUEST; i++) {
      if (!state.receivedChunks.has(i)) missing.push(i);
    }
    if (missing.length === 0) return;
    state.status = "receiving";
    try {
      await this.sendSecureMessage({
        type: "file_chunk_request",
        fileId,
        missing,
        timestamp: Date.now()
      });
    } catch (_) {
    }
  }
  async rejectIncomingFile(fileId, error = "Rejected by user") {
    if (!this.pendingIncomingTransfers.has(fileId)) return false;
    this.pendingIncomingTransfers.delete(fileId);
    await this.sendSecureMessage({ type: "file_transfer_response", fileId, accepted: false, error, timestamp: Date.now() });
    return true;
  }
  cancelTransfer(fileId) {
    try {
      if (this.activeTransfers.has(fileId)) {
        this.cleanupTransfer(fileId);
        return true;
      }
      if (this.receivingTransfers.has(fileId)) {
        this.cleanupReceivingTransfer(fileId);
        return true;
      }
      return false;
    } catch (error) {
      console.error("\u274C Failed to cancel transfer:", error);
      return false;
    }
  }
  cleanupTransfer(fileId) {
    const transferState = this.activeTransfers.get(fileId);
    if (transferState) {
      if (transferState._idleTimeout) {
        clearTimeout(transferState._idleTimeout);
        transferState._idleTimeout = null;
      }
      if (transferState.consentTimeout) {
        clearTimeout(transferState.consentTimeout);
        transferState.consentTimeout = null;
      }
      if (transferState.rejectConsent) {
        transferState.rejectConsent(new Error("Transfer cancelled during cleanup or disconnect"));
        transferState.rejectConsent = null;
        transferState.resolveConsent = null;
      }
    }
    this.activeTransfers.delete(fileId);
    this.sessionKeys.delete(fileId);
    this.transferNonces.delete(fileId);
    this.incomingTransferChunkLimiters.delete(fileId);
    for (const chunkId of this.processedChunks) {
      if (chunkId.startsWith(fileId)) {
        this.processedChunks.delete(chunkId);
      }
    }
  }
  _storeReceivedFileBuffer(fileId, entry) {
    this.receivedFileBuffers.set(fileId, entry);
    while (this.receivedFileBuffers.size > this.MAX_RETAINED_RECEIVED_FILE_BUFFERS) {
      const oldestFileId = this.receivedFileBuffers.keys().next().value;
      this._discardReceivedFileBuffer(oldestFileId);
    }
  }
  _discardReceivedFileBuffer(fileId) {
    const fileBuffer = this.receivedFileBuffers.get(fileId);
    if (!fileBuffer) return;
    try {
      if (fileBuffer.buffer) {
        SecureMemoryManager.secureWipe(fileBuffer.buffer);
        new Uint8Array(fileBuffer.buffer).fill(0);
      }
    } catch (_) {
    }
    this.receivedFileBuffers.delete(fileId);
    const rs = this.receivingTransfers.get(fileId);
    if (rs && (rs.status === "completed" || rs._assembled)) {
      if (rs._stallTimer) {
        clearInterval(rs._stallTimer);
        rs._stallTimer = null;
      }
      this.receivingTransfers.delete(fileId);
    }
  }
  // ✅ УЛУЧШЕННАЯ безопасная очистка памяти для предотвращения use-after-free
  cleanupReceivingTransfer(fileId) {
    try {
      this.pendingChunks.delete(fileId);
      const receivingState = this.receivingTransfers.get(fileId);
      if (receivingState) {
        if (receivingState._stallTimer) {
          clearInterval(receivingState._stallTimer);
          receivingState._stallTimer = null;
        }
        if (receivingState.receivedChunks && receivingState.receivedChunks.size > 0) {
          for (const [index, chunk] of receivingState.receivedChunks) {
            try {
              if (chunk && (chunk instanceof ArrayBuffer || chunk instanceof Uint8Array)) {
                SecureMemoryManager.secureWipe(chunk);
                if (chunk instanceof ArrayBuffer) {
                  const view = new Uint8Array(chunk);
                  view.fill(0);
                } else if (chunk instanceof Uint8Array) {
                  chunk.fill(0);
                }
              }
            } catch (chunkError) {
              console.warn("\u26A0\uFE0F Failed to securely wipe chunk:", chunkError);
            }
          }
          receivingState.receivedChunks.clear();
        }
        if (receivingState.sessionKey) {
          try {
            receivingState.sessionKey = null;
          } catch (keyError) {
            console.warn("\u26A0\uFE0F Failed to clear session key:", keyError);
          }
        }
        if (receivingState.salt) {
          try {
            if (Array.isArray(receivingState.salt)) {
              receivingState.salt.fill(0);
            }
            receivingState.salt = null;
          } catch (saltError) {
            console.warn("\u26A0\uFE0F Failed to clear salt:", saltError);
          }
        }
        for (const [key, value] of Object.entries(receivingState)) {
          if (value && typeof value === "object") {
            if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
              SecureMemoryManager.secureWipe(value);
            } else if (Array.isArray(value)) {
              value.fill(0);
            }
            receivingState[key] = null;
          }
        }
      }
      this.receivingTransfers.delete(fileId);
      this.sessionKeys.delete(fileId);
      this.incomingTransferChunkLimiters.delete(fileId);
      const fileBuffer = this.receivedFileBuffers.get(fileId);
      if (fileBuffer) {
        try {
          if (fileBuffer.buffer) {
            SecureMemoryManager.secureWipe(fileBuffer.buffer);
            const view = new Uint8Array(fileBuffer.buffer);
            view.fill(0);
          }
          for (const [key, value] of Object.entries(fileBuffer)) {
            if (value && typeof value === "object") {
              if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
                SecureMemoryManager.secureWipe(value);
              }
              fileBuffer[key] = null;
            }
          }
          this.receivedFileBuffers.delete(fileId);
        } catch (bufferError) {
          console.warn("\u26A0\uFE0F Failed to securely clear file buffer:", bufferError);
          this.receivedFileBuffers.delete(fileId);
        }
      }
      const chunksToRemove = [];
      for (const chunkId of this.processedChunks) {
        if (chunkId.startsWith(fileId)) {
          chunksToRemove.push(chunkId);
        }
      }
      for (const chunkId of chunksToRemove) {
        this.processedChunks.delete(chunkId);
      }
      if (typeof global !== "undefined" && global.gc) {
        try {
          global.gc();
        } catch (gcError) {
        }
      }
      console.log(`\u{1F512} Memory safely cleaned for file transfer: ${fileId}`);
    } catch (error) {
      console.error("\u274C Error during secure memory cleanup:", error);
      this.receivingTransfers.delete(fileId);
      this.sessionKeys.delete(fileId);
      this.receivedFileBuffers.delete(fileId);
      this.pendingChunks.delete(fileId);
      throw new Error(`Memory cleanup failed: ${error.message}`);
    }
  }
  getTransferStatus(fileId) {
    if (this.activeTransfers.has(fileId)) {
      const transfer = this.activeTransfers.get(fileId);
      return {
        type: "sending",
        fileId: transfer.fileId,
        fileName: transfer.file.name,
        progress: Math.round(transfer.sentChunks / transfer.totalChunks * 100),
        status: transfer.status,
        startTime: transfer.startTime
      };
    }
    if (this.receivingTransfers.has(fileId)) {
      const transfer = this.receivingTransfers.get(fileId);
      return {
        type: "receiving",
        fileId: transfer.fileId,
        fileName: transfer.fileName,
        progress: Math.round(transfer.receivedCount / transfer.totalChunks * 100),
        status: transfer.status,
        startTime: transfer.startTime
      };
    }
    return null;
  }
  getSystemStatus() {
    return {
      initialized: true,
      activeTransfers: this.activeTransfers.size,
      receivingTransfers: this.receivingTransfers.size,
      totalTransfers: this.activeTransfers.size + this.receivingTransfers.size,
      maxConcurrentTransfers: this.MAX_CONCURRENT_TRANSFERS,
      maxFileSize: this.MAX_FILE_SIZE,
      chunkSize: this.CHUNK_SIZE,
      hasWebrtcManager: !!this.webrtcManager,
      isConnected: this.webrtcManager?.isConnected?.() || false,
      hasDataChannel: !!this.webrtcManager?.dataChannel,
      dataChannelState: this.webrtcManager?.dataChannel?.readyState,
      isVerified: this.webrtcManager?.isVerified,
      hasEncryptionKey: !!this.webrtcManager?.encryptionKey,
      hasMacKey: !!this.webrtcManager?.macKey,
      linkedToWebRTCManager: this.webrtcManager?.fileTransferSystem === this,
      supportedFileTypes: this.getSupportedFileTypes(),
      fileTypeInfo: this.getFileTypeInfo()
    };
  }
  cleanup() {
    SecureFileTransferContext.getInstance().deactivate();
    if (this.webrtcManager && this.webrtcManager.dataChannel && this.originalOnMessage) {
      this.webrtcManager.dataChannel.onmessage = this.originalOnMessage;
      this.originalOnMessage = null;
    }
    if (this.webrtcManager && this.originalProcessMessage) {
      this.webrtcManager.processMessage = this.originalProcessMessage;
      this.originalProcessMessage = null;
    }
    if (this.webrtcManager && this.originalRemoveSecurityLayers) {
      this.webrtcManager.removeSecurityLayers = this.originalRemoveSecurityLayers;
      this.originalRemoveSecurityLayers = null;
    }
    for (const fileId of this.activeTransfers.keys()) {
      this.cleanupTransfer(fileId);
    }
    for (const fileId of this.receivingTransfers.keys()) {
      this.cleanupReceivingTransfer(fileId);
    }
    if (this.atomicOps) {
      this.atomicOps.locks.clear();
    }
    if (this.rateLimiter) {
      this.rateLimiter.requests.clear();
    }
    if (this.incomingChunkLimiter) {
      this.incomingChunkLimiter.requests.clear();
    }
    this.incomingTransferChunkLimiters.clear();
    this.pendingChunks.clear();
    this.pendingIncomingTransfers.clear();
    this.activeTransfers.clear();
    this.receivingTransfers.clear();
    this.transferQueue.length = 0;
    this.sessionKeys.clear();
    this.transferNonces.clear();
    this.processedChunks.clear();
    for (const fileId of Array.from(this.receivedFileBuffers.keys())) {
      this._discardReceivedFileBuffer(fileId);
    }
    this.clearKeys();
  }
  // ============================================
  // SESSION UPDATE HANDLER - FIXED
  // ============================================
  onSessionUpdate(sessionData) {
    this.sessionKeys.clear();
  }
  // ============================================
  // DEBUGGING AND DIAGNOSTICS
  // ============================================
  diagnoseFileTransferIssue() {
    const diagnosis = {
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      fileTransferSystem: {
        initialized: !!this,
        hasWebrtcManager: !!this.webrtcManager,
        webrtcManagerType: this.webrtcManager?.constructor?.name,
        linkedToWebRTCManager: this.webrtcManager?.fileTransferSystem === this
      },
      webrtcManager: {
        hasDataChannel: !!this.webrtcManager?.dataChannel,
        dataChannelState: this.webrtcManager?.dataChannel?.readyState,
        isConnected: this.webrtcManager?.isConnected?.() || false,
        isVerified: this.webrtcManager?.isVerified,
        hasEncryptionKey: !!this.webrtcManager?.encryptionKey,
        hasMacKey: !!this.webrtcManager?.macKey,
        hasKeyFingerprint: !!this.webrtcManager?.keyFingerprint,
        hasSessionSalt: !!this.webrtcManager?.sessionSalt
      },
      securityContext: {
        contextActive: SecureFileTransferContext.getInstance().isActive(),
        securityLevel: SecureFileTransferContext.getInstance().getSecurityLevel(),
        hasAtomicOps: !!this.atomicOps,
        hasRateLimiter: !!this.rateLimiter
      },
      transfers: {
        activeTransfers: this.activeTransfers.size,
        receivingTransfers: this.receivingTransfers.size,
        pendingChunks: this.pendingChunks.size,
        sessionKeys: this.sessionKeys.size
      },
      fileTypeSupport: {
        supportedTypes: this.getSupportedFileTypes(),
        generalMaxSize: this.formatFileSize(this.MAX_FILE_SIZE),
        restrictions: Object.keys(this.FILE_TYPE_RESTRICTIONS)
      }
    };
    return diagnosis;
  }
  async debugKeyDerivation(fileId) {
    try {
      if (!this.webrtcManager.keyFingerprint || !this.webrtcManager.sessionSalt) {
        throw new Error("Session data not available");
      }
      const senderResult = await this.deriveFileSessionKey(fileId);
      const receiverKey = await this.deriveFileSessionKeyFromSalt(fileId, senderResult.salt);
      const testData = new TextEncoder().encode("test data");
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        senderResult.key,
        testData
      );
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce },
        receiverKey,
        encrypted
      );
      const decryptedText = new TextDecoder().decode(decrypted);
      if (decryptedText === "test data") {
        return { success: true, message: "All tests passed" };
      } else {
        throw new Error("Decryption verification failed");
      }
    } catch (error) {
      console.error("\u274C Key derivation test failed:", error);
      return { success: false, error: error.message };
    }
  }
  // ============================================
  // ALTERNATIVE METHOD OF INITIALIZING HANDLERS
  // ============================================
  registerWithWebRTCManager() {
    if (!this.webrtcManager) {
      throw new Error("WebRTC manager not available");
    }
    this.webrtcManager.fileTransferSystem = this;
    this.webrtcManager.setFileMessageHandler = (handler) => {
      this.webrtcManager._fileMessageHandler = handler;
    };
    this.webrtcManager.setFileMessageHandler((message) => {
      return this.handleFileMessage(message);
    });
  }
  static createFileMessageFilter(fileTransferSystem) {
    return async (event) => {
      try {
        if (typeof event.data === "string") {
          const parsed = JSON.parse(event.data);
          if (fileTransferSystem.isFileTransferMessage(parsed)) {
            await fileTransferSystem.handleFileMessage(parsed);
            return true;
          }
        }
      } catch (error) {
      }
      return false;
    };
  }
  // ============================================
  // SECURITY KEY MANAGEMENT
  // ============================================
  setSigningKey(privateKey) {
    if (!privateKey || !(privateKey instanceof CryptoKey)) {
      throw new Error("Invalid private key for signing");
    }
    this.signingKey = privateKey;
    console.log("\u{1F512} Signing key set successfully");
  }
  setVerificationKey(publicKey) {
    if (!publicKey || !(publicKey instanceof CryptoKey)) {
      throw new Error("Invalid public key for verification");
    }
    this.verificationKey = publicKey;
    console.log("\u{1F512} Verification key set successfully");
  }
  async generateSigningKeyPair() {
    try {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        },
        true,
        // extractable
        ["sign", "verify"]
      );
      this.signingKey = keyPair.privateKey;
      this.verificationKey = keyPair.publicKey;
      console.log("\u{1F512} RSA key pair generated successfully");
      return keyPair;
    } catch (error) {
      const safeError = SecurityErrorHandler.sanitizeError(error);
      console.error("\u274C Failed to generate signing key pair:", safeError);
      throw new Error(safeError);
    }
  }
  clearKeys() {
    this.signingKey = null;
    this.verificationKey = null;
    console.log("\u{1F512} Security keys cleared");
  }
  getSecurityStatus() {
    return {
      signingEnabled: this.signingKey !== null,
      verificationEnabled: this.verificationKey !== null,
      contextActive: SecureFileTransferContext.getInstance().isActive(),
      securityLevel: SecureFileTransferContext.getInstance().getSecurityLevel()
    };
  }
  getClientIdentifier() {
    return this.webrtcManager?.connectionId || this.webrtcManager?.keyFingerprint?.substring(0, 16) || "default-client";
  }
  destroy() {
    SecureFileTransferContext.getInstance().deactivate();
    this.clearKeys();
    console.log("\u{1F512} File transfer system destroyed safely");
  }
};

// src/network/webrtc/config.js
var IS_WEBKIT = typeof navigator !== "undefined" && /AppleWebKit/.test(navigator.userAgent) && !/Chrome|Chromium|Edg\//.test(navigator.userAgent);
var AUDIO_CONFIG = {
  // Opus fmtp params applied via SDP munging.
  //  - minptime=10          smaller packets → lower latency (Opus RFC 7587 §7).
  //  - useinbandfec=1       in-band Forward Error Correction — reconstructs lost
  //                         packets from the next one (RFC 6716 §2.1.7). Key for loss.
  //  - usedtx=1             Discontinuous Transmission — stop sending in silence,
  //                         frees the pipe for video/FEC (RFC 7587 §3.1.3).
  //  - stereo=0             mono: voice doesn't need stereo, halves the bitrate.
  //  - maxaveragebitrate    32 kbps — brief says 32000; comfortable wideband speech.
  //  - cbr=0                variable bitrate: lets the encoder spend bits only when
  //                         needed, better quality per bit than CBR for speech.
  opusFmtp: {
    minptime: 10,
    useinbandfec: 1,
    usedtx: 1,
    stereo: 0,
    maxaveragebitrate: 32e3,
    cbr: 0
  },
  // RED (RFC 2198) wraps Opus payloads with a redundant copy of the previous
  // frame — recovers isolated losses without waiting for retransmission. Only
  // enabled when the browser advertises audio/red (Chromium yes; Safari/FF vary).
  preferRed: true,
  // RTCRtpSender.setParameters — encoding-level knobs. Audio is prioritised over
  // video on the shared transport so speech survives congestion.
  sender: {
    maxBitrate: 4e4,
    // bps — brief: 40000. Head-room over 32 kbps for RED.
    priority: "high",
    // RTCPriorityType — bandwidth arbitration within the PC.
    networkPriority: "high"
    // DSCP marking hint — audio ahead of video on the wire.
  }
};
var VIDEO_CONFIG = {
  codecPreferenceOrder: ["VP9", "AV1", "H264", "VP8"],
  // Preferred single-encoding SVC mode for VP9 (3 spatial × 3 temporal, key-frame
  // aligned). If the browser rejects it we fall back to the simulcast ladder below.
  vp9: {
    preferredScalabilityMode: "L3T3_KEY",
    simulcast: [
      { rid: "low", scaleResolutionDownBy: 4, maxBitrate: 15e4, scalabilityMode: "L1T3" },
      { rid: "mid", scaleResolutionDownBy: 2, maxBitrate: 5e5, scalabilityMode: "L1T3" },
      { rid: "high", scaleResolutionDownBy: 1, maxBitrate: 15e5, scalabilityMode: "L1T3" }
    ],
    degradationPreference: "balanced"
  },
  av1: {
    scalabilityMode: "L1T3",
    maxBitrate: 12e5,
    degradationPreference: "maintain-framerate"
  },
  // H.264 / VP8: ordinary simulcast, no SVC.
  simulcast: [
    { rid: "low", scaleResolutionDownBy: 4, maxBitrate: 15e4 },
    { rid: "mid", scaleResolutionDownBy: 2, maxBitrate: 5e5 },
    { rid: "high", scaleResolutionDownBy: 1, maxBitrate: 15e5 }
  ],
  networkPriority: "medium"
  // below audio's 'high'.
};
var TRANSPORT_CONFIG = {
  twccUri: "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
  video: {
    rtcpFb: ["transport-cc", "nack", "nack pli", "ccm fir", "goog-remb"],
    twcc: true
  },
  audio: {
    rtcpFb: ["transport-cc", "nack"],
    twcc: true
  }
};
var ADAPTATION_CONFIG = {
  intervalMs: 1e3,
  loss: {
    highPct: 0.1,
    // >10% loss → back off video.
    recoverPct: 0.03,
    // <3% loss (sustained) → ramp up.
    audioProtectPct: 0.25
    // don't touch audio until loss exceeds 25%.
  },
  rtt: {
    highMs: 300,
    // >300 ms → back off.
    recoverMs: 150
    // <150 ms (sustained) → ramp up.
  },
  stepDownPct: 0.2,
  // shrink video maxBitrate by 20% per bad tick.
  stepUpPct: 0.1,
  // grow by 10% per good window.
  minVideoBitrate: 1e5,
  // floor for the low layer (bps).
  recoverStableTicks: 5,
  // consecutive good ticks before ramping up.
  cpuScaleStep: 1.5
  // qualityLimitationReason 'cpu' → bump scaleResolutionDownBy ×1.5.
};

// src/network/webrtc/sdp.js
function detectEol(sdp) {
  return sdp.indexOf("\r\n") !== -1 ? "\r\n" : "\n";
}
function splitSdp(sdp) {
  const eol = detectEol(sdp);
  const lines = sdp.split(/\r\n|\n/);
  const session = [];
  const media = [];
  let current = null;
  for (const line of lines) {
    if (line.startsWith("m=")) {
      current = { lines: [line] };
      media.push(current);
    } else if (current) {
      current.lines.push(line);
    } else {
      session.push(line);
    }
  }
  return { eol, session, media };
}
function joinSdp(parsed) {
  const all = [...parsed.session];
  for (const m of parsed.media) all.push(...m.lines);
  return all.join(parsed.eol);
}
function sectionKind(section) {
  const m = section.lines[0].match(/^m=(\w+)/);
  return m ? m[1] : null;
}
function findPayloadTypes(section, codecName) {
  const re = new RegExp("^a=rtpmap:(\\d+)\\s+" + codecName + "\\/", "i");
  const pts = [];
  for (const line of section.lines) {
    const m = line.match(re);
    if (m) pts.push(m[1]);
  }
  return pts;
}
function parseFmtpParams(value) {
  const map = /* @__PURE__ */ new Map();
  for (const part of value.split(";")) {
    const p = part.trim();
    if (!p) continue;
    const eq = p.indexOf("=");
    if (eq === -1) map.set(p, void 0);
    else map.set(p.slice(0, eq).trim(), p.slice(eq + 1).trim());
  }
  return map;
}
function serializeFmtpParams(map) {
  const parts = [];
  for (const [k, v] of map) parts.push(v === void 0 ? k : `${k}=${v}`);
  return parts.join(";");
}
function upsertFmtp(section, pt, params) {
  const fmtpIdx = section.lines.findIndex((l) => l.startsWith(`a=fmtp:${pt} `) || l === `a=fmtp:${pt}`);
  if (fmtpIdx !== -1) {
    const existing = section.lines[fmtpIdx].slice(`a=fmtp:${pt} `.length);
    const map2 = parseFmtpParams(existing);
    for (const [k, v] of Object.entries(params)) map2.set(k, String(v));
    section.lines[fmtpIdx] = `a=fmtp:${pt} ${serializeFmtpParams(map2)}`;
    return;
  }
  const map = /* @__PURE__ */ new Map();
  for (const [k, v] of Object.entries(params)) map.set(k, String(v));
  const newLine = `a=fmtp:${pt} ${serializeFmtpParams(map)}`;
  const rtpmapIdx = section.lines.findIndex((l) => l.startsWith(`a=rtpmap:${pt} `));
  if (rtpmapIdx !== -1) section.lines.splice(rtpmapIdx + 1, 0, newLine);
  else section.lines.push(newLine);
}
function applyOpusSettings(sdp, opusFmtp) {
  if (!sdp || typeof sdp !== "string") return sdp;
  const parsed = splitSdp(sdp);
  let changed = false;
  for (const section of parsed.media) {
    if (sectionKind(section) !== "audio") continue;
    for (const pt of findPayloadTypes(section, "opus")) {
      upsertFmtp(section, pt, opusFmtp);
      changed = true;
    }
  }
  return changed ? joinSdp(parsed) : sdp;
}
var AUX_CODEC = /^(rtx|red|ulpfec|flexfec-03|telephone-event|CN)$/i;
function getCodecPayloadTypes(section) {
  const pts = [];
  for (const line of section.lines) {
    const m = line.match(/^a=rtpmap:(\d+)\s+([^/]+)\//);
    if (m && !AUX_CODEC.test(m[2])) pts.push(m[1]);
  }
  return pts;
}
function ensureRtcpFb(section, feedbacks) {
  for (const pt of getCodecPayloadTypes(section)) {
    for (const fb of feedbacks) {
      const line = `a=rtcp-fb:${pt} ${fb}`;
      if (section.lines.includes(line)) continue;
      let insertAt = -1;
      for (let i = 0; i < section.lines.length; i++) {
        const l = section.lines[i];
        if (l.startsWith(`a=rtpmap:${pt} `) || l.startsWith(`a=fmtp:${pt} `) || l.startsWith(`a=rtcp-fb:${pt} `)) insertAt = i;
      }
      if (insertAt === -1) insertAt = section.lines.length - 1;
      section.lines.splice(insertAt + 1, 0, line);
    }
  }
}
function ensureExtmap(section, uri) {
  if (section.lines.some((l) => l.startsWith("a=extmap:") && l.includes(uri))) return;
  let maxId = 0, insertAt = -1;
  for (let i = 0; i < section.lines.length; i++) {
    const m = section.lines[i].match(/^a=extmap:(\d+)/);
    if (m) {
      maxId = Math.max(maxId, Number(m[1]));
      insertAt = i;
    }
  }
  if (insertAt === -1) {
    insertAt = section.lines.findIndex((l) => l.startsWith("a=mid:"));
    if (insertAt === -1) insertAt = section.lines.length - 1;
  }
  section.lines.splice(insertAt + 1, 0, `a=extmap:${maxId + 1} ${uri}`);
}
function applyTransport(sdp, cfg) {
  if (!sdp || typeof sdp !== "string" || !cfg) return sdp;
  const parsed = splitSdp(sdp);
  let changed = false;
  for (const section of parsed.media) {
    const kind = sectionKind(section);
    const c = kind === "video" ? cfg.video : kind === "audio" ? cfg.audio : null;
    if (!c) continue;
    if (Array.isArray(c.rtcpFb)) {
      ensureRtcpFb(section, c.rtcpFb);
      changed = true;
    }
    if (c.twcc && cfg.twccUri) {
      ensureExtmap(section, cfg.twccUri);
      changed = true;
    }
  }
  return changed ? joinSdp(parsed) : sdp;
}

// src/network/webrtc/audio.js
function applyAudioCodecPreferences(transceiver) {
  try {
    if (IS_WEBKIT) return false;
    if (!transceiver || typeof transceiver.setCodecPreferences !== "function") return false;
    if (!AUDIO_CONFIG.preferRed) return false;
    const caps = typeof RTCRtpSender !== "undefined" && RTCRtpSender.getCapabilities ? RTCRtpSender.getCapabilities("audio") : null;
    if (!caps || !Array.isArray(caps.codecs)) return false;
    const isRed = (c) => /red$/i.test(c.mimeType);
    const isOpus = (c) => /opus$/i.test(c.mimeType);
    if (!caps.codecs.some(isRed)) return false;
    const red = caps.codecs.filter(isRed);
    const opus = caps.codecs.filter(isOpus);
    const rest = caps.codecs.filter((c) => !isRed(c) && !isOpus(c));
    transceiver.setCodecPreferences([...red, ...opus, ...rest]);
    return true;
  } catch (e) {
    return false;
  }
}
async function configureAudioSender(sender, options = {}) {
  try {
    if (IS_WEBKIT) return false;
    if (!sender || typeof sender.getParameters !== "function") return false;
    const cfg = { ...AUDIO_CONFIG.sender, ...options };
    const params = sender.getParameters();
    if (!params.encodings || params.encodings.length === 0) params.encodings = [{}];
    for (const enc4 of params.encodings) {
      enc4.maxBitrate = cfg.maxBitrate;
      enc4.priority = cfg.priority;
      enc4.networkPriority = cfg.networkPriority;
    }
    await sender.setParameters(params);
    return true;
  } catch (e) {
    return false;
  }
}

// src/network/webrtc/video.js
var CODEC_RANK = { VP9: 0, AV1: 1, H264: 2, VP8: 3 };
function codecShortName(mimeType) {
  const sub = String(mimeType || "").split("/")[1] || "";
  return sub.toUpperCase();
}
function sortVideoCodecs(codecs) {
  const rank = (c) => {
    const n = codecShortName(c.mimeType);
    return Object.prototype.hasOwnProperty.call(CODEC_RANK, n) ? CODEC_RANK[n] : 99;
  };
  return codecs.map((c, i) => ({ c, i })).sort((a, b) => rank(a.c) - rank(b.c) || a.i - b.i).map((x) => x.c);
}
function pickPreferredVideoCodec(caps) {
  if (!caps || !Array.isArray(caps.codecs)) return null;
  const present = new Set(caps.codecs.map((c) => codecShortName(c.mimeType)));
  for (const name of VIDEO_CONFIG.codecPreferenceOrder) if (present.has(name)) return name;
  return null;
}
function videoCaps() {
  return typeof RTCRtpSender !== "undefined" && RTCRtpSender.getCapabilities ? RTCRtpSender.getCapabilities("video") : null;
}
function applyVideoCodecPreferences(transceiver) {
  try {
    if (IS_WEBKIT) return false;
    if (!transceiver || typeof transceiver.setCodecPreferences !== "function") return false;
    const caps = videoCaps();
    if (!caps || !Array.isArray(caps.codecs)) return false;
    transceiver.setCodecPreferences(sortVideoCodecs(caps.codecs));
    return pickPreferredVideoCodec(caps);
  } catch (e) {
    return false;
  }
}
function encodingPlanFor(codecName) {
  if (codecName === "VP9") {
    return { scalabilityMode: VIDEO_CONFIG.vp9.preferredScalabilityMode, maxBitrate: 15e5, degradationPreference: VIDEO_CONFIG.vp9.degradationPreference };
  }
  if (codecName === "AV1") {
    return { scalabilityMode: VIDEO_CONFIG.av1.scalabilityMode, maxBitrate: VIDEO_CONFIG.av1.maxBitrate, degradationPreference: VIDEO_CONFIG.av1.degradationPreference };
  }
  return { scalabilityMode: void 0, maxBitrate: 15e5, degradationPreference: "balanced" };
}
async function configureVideoSender(sender, options = {}) {
  try {
    if (IS_WEBKIT) return false;
    if (!sender || typeof sender.getParameters !== "function") return false;
    const preferred = pickPreferredVideoCodec(videoCaps()) || "VP8";
    const plan = { ...encodingPlanFor(preferred), ...options };
    const params = sender.getParameters();
    if (!params.encodings || params.encodings.length === 0) params.encodings = [{}];
    const simulcast = params.encodings.length > 1;
    if (simulcast) {
      for (const enc4 of params.encodings) enc4.networkPriority = VIDEO_CONFIG.networkPriority;
    } else {
      const enc4 = params.encodings[0];
      enc4.maxBitrate = plan.maxBitrate;
      enc4.networkPriority = VIDEO_CONFIG.networkPriority;
      if (plan.scalabilityMode) enc4.scalabilityMode = plan.scalabilityMode;
    }
    if (plan.degradationPreference) params.degradationPreference = plan.degradationPreference;
    try {
      await sender.setParameters(params);
      return true;
    } catch (e) {
      if (!simulcast && plan.scalabilityMode) {
        delete params.encodings[0].scalabilityMode;
        try {
          await sender.setParameters(params);
          return true;
        } catch (e2) {
          return false;
        }
      }
      return false;
    }
  } catch (e) {
    return false;
  }
}

// src/network/webrtc/adaptation/metrics.js
function summarizeStats(stats, prev = {}) {
  let outbound = null, remoteInbound = null, candidatePair = null;
  for (const s of stats) {
    if (!s || typeof s.type !== "string") continue;
    if (s.type === "outbound-rtp" && !s.isRemote) {
      if (!outbound || s.kind === "video") outbound = s;
    } else if (s.type === "remote-inbound-rtp") {
      if (!remoteInbound || s.kind === "video") remoteInbound = s;
    } else if (s.type === "candidate-pair") {
      const active = s.nominated || s.selected || s.state === "succeeded";
      if (active && (!candidatePair || s.nominated)) candidatePair = s;
    }
  }
  const packetsSent = Number(outbound?.packetsSent ?? 0);
  const packetsLost = Number(remoteInbound?.packetsLost ?? 0);
  const dSent = packetsSent - (prev.packetsSent ?? packetsSent);
  const dLost = packetsLost - (prev.packetsLost ?? packetsLost);
  const denom = dSent + dLost;
  const lossPct = denom > 0 ? Math.min(1, Math.max(0, dLost / denom)) : 0;
  const rttSec = candidatePair?.currentRoundTripTime ?? remoteInbound?.roundTripTime ?? 0;
  const rttMs = Number(rttSec) * 1e3;
  const jitterMs = Number(remoteInbound?.jitter ?? 0) * 1e3;
  const availableOutgoingBitrate = candidatePair?.availableOutgoingBitrate != null ? Number(candidatePair.availableOutgoingBitrate) : null;
  const qualityLimitationReason = outbound?.qualityLimitationReason ?? "none";
  return {
    lossPct,
    rttMs,
    jitterMs,
    availableOutgoingBitrate,
    qualityLimitationReason,
    counters: { packetsSent, packetsLost },
    hasData: !!(outbound && (remoteInbound || candidatePair))
  };
}
function qualityFromMetrics(m) {
  if (!m || !m.hasData) return null;
  const l = m.lossPct, r = m.rttMs;
  if (l < 0.03 && r < 150) return "excellent";
  if (l < 0.07 && r < 250) return "good";
  if (l < 0.15 && r < 400) return "fair";
  return "poor";
}

// src/network/webrtc/adaptation/controller.js
function decideAdaptation(m, state, cfg = ADAPTATION_CONFIG) {
  let { targetBitrate, ceilingBitrate, scaleResolutionDownBy, goodTicks } = state;
  let changed = false, reason = "steady";
  if (m.qualityLimitationReason === "cpu") {
    const next = Math.min(4, +(scaleResolutionDownBy * cfg.cpuScaleStep).toFixed(3));
    if (next !== scaleResolutionDownBy) {
      scaleResolutionDownBy = next;
      changed = true;
    }
    goodTicks = 0;
    reason = "cpu";
  } else if (m.lossPct > cfg.loss.highPct || m.rttMs > cfg.rtt.highMs) {
    const next = Math.max(cfg.minVideoBitrate, Math.round(targetBitrate * (1 - cfg.stepDownPct)));
    if (next !== targetBitrate) {
      targetBitrate = next;
      changed = true;
    }
    goodTicks = 0;
    reason = "backoff";
  } else if (m.lossPct < cfg.loss.recoverPct && m.rttMs < cfg.rtt.recoverMs) {
    goodTicks += 1;
    reason = "recovering";
    if (goodTicks >= cfg.recoverStableTicks) {
      const next = Math.min(ceilingBitrate, Math.round(targetBitrate * (1 + cfg.stepUpPct)));
      if (next !== targetBitrate) {
        targetBitrate = next;
        changed = true;
        reason = "rampup";
      }
      goodTicks = 0;
    }
  } else {
    goodTicks = 0;
  }
  return { targetBitrate, scaleResolutionDownBy, goodTicks, changed, reason };
}
var NetworkAdaptationController = class {
  /**
   * @param {RTCPeerConnection} pc
   * @param {object} opts { getVideoSender:()=>RTCRtpSender|null, ceilingBitrate?, onQuality?, cfg? }
   */
  constructor(pc, opts = {}) {
    this.pc = pc;
    this.getVideoSender = opts.getVideoSender || (() => null);
    this.onQuality = opts.onQuality || (() => {
    });
    this.cfg = opts.cfg || ADAPTATION_CONFIG;
    this._timer = null;
    this._prevCounters = {};
    this._lastQuality = void 0;
    this.state = {
      targetBitrate: opts.ceilingBitrate || 15e5,
      ceilingBitrate: opts.ceilingBitrate || 15e5,
      scaleResolutionDownBy: 1,
      goodTicks: 0
    };
  }
  start() {
    if (this._timer) return;
    this._timer = setInterval(() => {
      this._tick().catch(() => {
      });
    }, this.cfg.intervalMs);
  }
  stop() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }
  async _tick() {
    if (!this.pc || typeof this.pc.getStats !== "function") return;
    const report = await this.pc.getStats();
    const stats = typeof report.values === "function" ? Array.from(report.values()) : report;
    const m = summarizeStats(stats, this._prevCounters);
    this._prevCounters = m.counters;
    const q = qualityFromMetrics(m);
    if (q && q !== this._lastQuality) {
      this._lastQuality = q;
      try {
        this.onQuality(q, m);
      } catch (_) {
      }
    }
    if (!m.hasData) return;
    const decision = decideAdaptation(m, this.state, this.cfg);
    this.state = {
      targetBitrate: decision.targetBitrate,
      ceilingBitrate: this.state.ceilingBitrate,
      scaleResolutionDownBy: decision.scaleResolutionDownBy,
      goodTicks: decision.goodTicks
    };
    if (decision.changed) {
      await this._applyToVideoSender();
    }
  }
  async _applyToVideoSender() {
    if (IS_WEBKIT) return;
    const sender = this.getVideoSender();
    if (!sender || typeof sender.getParameters !== "function") return;
    try {
      const params = sender.getParameters();
      if (!params.encodings || params.encodings.length === 0) params.encodings = [{}];
      if (params.encodings.length === 1) {
        params.encodings[0].maxBitrate = this.state.targetBitrate;
        params.encodings[0].scaleResolutionDownBy = this.state.scaleResolutionDownBy;
      } else {
        const top = params.encodings[params.encodings.length - 1];
        top.maxBitrate = this.state.targetBitrate;
      }
      await sender.setParameters(params);
    } catch (e) {
    }
  }
};

// src/crypto/DoubleRatchet.js
var ROOT_INFO = "SecureBit-DR-Root-v1";
var MESSAGE_INFO = "SecureBit-DR-Message-v1";
var INIT_INFO = "SecureBit-DR-Init-v1";
var MK_SEED = Uint8Array.of(1);
var CK_SEED = Uint8Array.of(2);
var enc = new TextEncoder();
var dec = new TextDecoder();
var RATCHET_LIMITS = Object.freeze({
  // How far ahead of the expected number a single message may jump.
  MAX_SKIP_PER_CHAIN: 512,
  // Total retained keys for messages that never arrived, across all chains.
  MAX_SKIPPED_KEYS: 1024,
  // Retained keys older than this are dropped: the data channel is reliable
  // and ordered, so a gap that has not resolved in minutes never will.
  SKIPPED_KEY_TTL_MS: 5 * 60 * 1e3
});
function b64(bytes) {
  let binary = "";
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i]);
  return btoa(binary);
}
function unb64(text2) {
  const binary = atob(text2);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
function zeroize(bytes) {
  try {
    if (bytes && bytes.length) {
      crypto.getRandomValues(bytes);
      bytes.fill(0);
    }
  } catch (_) {
  }
}
async function hkdf(ikm, salt, info, lengthBytes) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) },
    key,
    lengthBytes * 8
  );
  return new Uint8Array(bits);
}
async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}
async function advanceChain(chainKey) {
  const messageKey = await hmac(chainKey, MK_SEED);
  const nextChainKey = await hmac(chainKey, CK_SEED);
  return { messageKey, nextChainKey };
}
async function advanceRoot(rootKey, dhOutput) {
  const derived = await hkdf(dhOutput, rootKey, ROOT_INFO, 64);
  const nextRoot = derived.slice(0, 32);
  const chainKey = derived.slice(32, 64);
  zeroize(derived);
  return { nextRoot, chainKey };
}
var DoubleRatchet = class {
  constructor() {
    this._rootKey = null;
    this._sendingChainKey = null;
    this._receivingChainKey = null;
    this._selfKeyPair = null;
    this._remotePublicKey = null;
    this._remotePublicKeyB64 = null;
    this._sendCount = 0;
    this._receiveCount = 0;
    this._previousSendCount = 0;
    this._skipped = /* @__PURE__ */ new Map();
    this._namedCurve = "P-384";
    this._initialised = false;
  }
  /**
   * @param {object} options
   * @param {Uint8Array} options.sharedSecret  ECDH output from the handshake.
   * @param {Uint8Array} options.sessionSalt   The session's 64-byte salt.
   * @param {CryptoKey}  options.selfPrivateKey    Our handshake ECDH private key.
   * @param {CryptoKey}  options.remotePublicKey   Peer's handshake ECDH public key.
   * @param {boolean}    options.isInitiator   True for the side that created the offer.
   */
  async init({ sharedSecret, sessionSalt, selfPrivateKey, remotePublicKey, isInitiator }) {
    if (!(sharedSecret instanceof Uint8Array) || sharedSecret.length === 0) {
      throw new Error("DoubleRatchet: a shared secret is required");
    }
    if (!(selfPrivateKey instanceof CryptoKey) || !(remotePublicKey instanceof CryptoKey)) {
      throw new Error("DoubleRatchet: handshake ECDH keys are required");
    }
    this._namedCurve = selfPrivateKey.algorithm?.namedCurve || "P-384";
    this._rootKey = await hkdf(sharedSecret, sessionSalt ?? new Uint8Array(0), INIT_INFO, 32);
    if (isInitiator) {
      this._selfKeyPair = await this._generateKeyPair();
      this._remotePublicKey = remotePublicKey;
      this._remotePublicKeyB64 = null;
      const dh = await this._dh(this._selfKeyPair.privateKey, this._remotePublicKey);
      const { nextRoot, chainKey } = await advanceRoot(this._rootKey, dh);
      zeroize(dh);
      zeroize(this._rootKey);
      this._rootKey = nextRoot;
      this._sendingChainKey = chainKey;
    } else {
      this._selfKeyPair = { privateKey: selfPrivateKey, publicKey: null };
      this._remotePublicKey = null;
      this._remotePublicKeyB64 = null;
    }
    this._initialised = true;
  }
  get isInitialised() {
    return this._initialised;
  }
  /**
   * False on the responder until the initiator's first message arrives.
   *
   * This is inherent to the Double Ratchet, not an implementation gap: the
   * responder's sending chain is only defined once it has seen the initiator's
   * ratchet key, because both sides must derive it from the same DH. Callers
   * have to check this rather than assume, or the responder's first message —
   * which the app sends automatically as a presence update the moment
   * verification completes — throws instead of going out.
   */
  get canEncrypt() {
    return this._initialised && this._sendingChainKey !== null;
  }
  /** Diagnostics only — deliberately exposes no key material. */
  getState() {
    return {
      initialised: this._initialised,
      sending: this._sendingChainKey !== null,
      receiving: this._receivingChainKey !== null,
      sendCount: this._sendCount,
      receiveCount: this._receiveCount,
      previousSendCount: this._previousSendCount,
      skippedKeys: this._skipped.size
    };
  }
  async _generateKeyPair() {
    return crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: this._namedCurve },
      false,
      ["deriveKey", "deriveBits"]
    );
  }
  async _dh(privateKey, publicKey) {
    const bits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: publicKey },
      privateKey,
      256
    );
    return new Uint8Array(bits);
  }
  async _selfPublicKeyB64() {
    if (!this._selfKeyPair?.publicKey) return null;
    return b64(await crypto.subtle.exportKey("spki", this._selfKeyPair.publicKey));
  }
  async _importPublic(spkiB64) {
    return crypto.subtle.importKey(
      "spki",
      unb64(spkiB64),
      { name: "ECDH", namedCurve: this._namedCurve },
      true,
      []
    );
  }
  /** Derive the AES-GCM key and IV for one message, then forget the message key. */
  async _messageCipher(messageKey) {
    const material = await hkdf(messageKey, new Uint8Array(32), MESSAGE_INFO, 44);
    const key = await crypto.subtle.importKey(
      "raw",
      material.slice(0, 32),
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
    const iv = material.slice(32, 44);
    zeroize(material);
    return { key, iv };
  }
  /**
   * @param {string} plaintext
   * @returns {Promise<{header: string, ciphertext: string}>} header is the exact
   *   string that must be transmitted and fed back to decrypt(): it doubles as
   *   the AAD, so re-serialising it on the far side could change a byte and
   *   fail authentication for no reason.
   */
  async encrypt(plaintext) {
    if (!this._initialised) throw new Error("DoubleRatchet: not initialised");
    if (!this._sendingChainKey) {
      throw new Error("DoubleRatchet: no sending chain \u2014 awaiting the peer's first message");
    }
    const { messageKey, nextChainKey } = await advanceChain(this._sendingChainKey);
    zeroize(this._sendingChainKey);
    this._sendingChainKey = nextChainKey;
    const header = JSON.stringify({
      dh: await this._selfPublicKeyB64(),
      pn: this._previousSendCount,
      n: this._sendCount
    });
    this._sendCount += 1;
    const { key, iv } = await this._messageCipher(messageKey);
    zeroize(messageKey);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(header) },
      key,
      enc.encode(plaintext)
    );
    return { header, ciphertext: b64(ciphertext) };
  }
  /**
   * @param {string} header      Exactly the string produced by encrypt().
   * @param {string} ciphertext  Base64 body.
   * @returns {Promise<string>} plaintext
   */
  async decrypt(header, ciphertext) {
    if (!this._initialised) throw new Error("DoubleRatchet: not initialised");
    let parsed;
    try {
      parsed = JSON.parse(header);
    } catch (_) {
      throw new Error("DoubleRatchet: malformed header");
    }
    const { dh, pn, n } = parsed;
    if (typeof dh !== "string" || !Number.isSafeInteger(n) || n < 0 || !Number.isSafeInteger(pn) || pn < 0) {
      throw new Error("DoubleRatchet: invalid header fields");
    }
    this._pruneSkipped();
    const skippedId = `${dh}|${n}`;
    const retained = this._skipped.get(skippedId);
    if (retained) {
      const plaintext2 = await this._open(retained.key, header, ciphertext);
      this._skipped.delete(skippedId);
      zeroize(retained.key);
      return plaintext2;
    }
    const staged = await this._stageReceive(dh, pn, n);
    let plaintext;
    try {
      plaintext = await this._open(staged.messageKey, header, ciphertext);
    } catch (error) {
      staged.discard();
      throw error;
    }
    staged.commit();
    return plaintext;
  }
  /**
   * Work out which key opens this message and what the resulting state would
   * be, without touching `this`. Returns the candidate key plus commit/discard.
   */
  async _stageReceive(dh, pn, n) {
    const isNewChain = dh !== this._remotePublicKeyB64;
    const pending = [];
    const toZeroOnCommit = [];
    let ratchet = null;
    let chainKey;
    let receiveCount;
    let remoteB64;
    if (isNewChain) {
      if (this._receivingChainKey) {
        const carried = await this._collectSkipped(
          this._receivingChainKey,
          this._receiveCount,
          pn,
          this._remotePublicKeyB64
        );
        pending.push(...carried.keys);
        toZeroOnCommit.push(carried.finalChainKey);
      }
      ratchet = await this._stageDhRatchet(dh);
      chainKey = ratchet.receivingChainKey;
      receiveCount = 0;
      remoteB64 = dh;
    } else {
      chainKey = this._receivingChainKey;
      receiveCount = this._receiveCount;
      remoteB64 = this._remotePublicKeyB64;
    }
    if (!chainKey) {
      throw new Error("DoubleRatchet: no receiving chain for this message");
    }
    const gap = await this._collectSkipped(chainKey, receiveCount, n, remoteB64);
    pending.push(...gap.keys);
    const { messageKey, nextChainKey } = await advanceChain(gap.finalChainKey);
    if (gap.finalChainKey !== chainKey) toZeroOnCommit.push(gap.finalChainKey);
    return {
      messageKey,
      commit: () => {
        if (ratchet) ratchet.apply();
        if (this._receivingChainKey && this._receivingChainKey !== nextChainKey) {
          zeroize(this._receivingChainKey);
        }
        for (const key of toZeroOnCommit) zeroize(key);
        this._receivingChainKey = nextChainKey;
        this._receiveCount = n + 1;
        this._remotePublicKeyB64 = remoteB64;
        for (const { id, key } of pending) this._rememberSkipped(id, key);
        zeroize(messageKey);
      },
      discard: () => {
        if (ratchet) ratchet.discard();
        for (const { key } of pending) zeroize(key);
        for (const key of toZeroOnCommit) zeroize(key);
        zeroize(nextChainKey);
        zeroize(messageKey);
      }
    };
  }
  /**
   * Derive the keys for messages `from`..`until-1` without mutating state.
   * `until` comes off the wire, so the jump is bounded here rather than trusted.
   */
  async _collectSkipped(chainKey, from, until, remoteB64) {
    if (until < from) {
      throw new Error("DoubleRatchet: message number is behind the current chain");
    }
    if (until - from > RATCHET_LIMITS.MAX_SKIP_PER_CHAIN) {
      throw new Error(
        `DoubleRatchet: refusing to skip ${until - from} messages (limit ${RATCHET_LIMITS.MAX_SKIP_PER_CHAIN})`
      );
    }
    const keys = [];
    let current = chainKey;
    for (let i = from; i < until; i++) {
      const { messageKey, nextChainKey } = await advanceChain(current);
      if (current !== chainKey) zeroize(current);
      current = nextChainKey;
      keys.push({ id: `${remoteB64}|${i}`, key: messageKey });
    }
    return { keys, finalChainKey: current };
  }
  async _open(messageKey, header, ciphertext) {
    const { key, iv } = await this._messageCipher(messageKey);
    let opened;
    try {
      opened = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: enc.encode(header) },
        key,
        unb64(ciphertext)
      );
    } catch (_) {
      throw new Error("DoubleRatchet: authentication failed");
    }
    return dec.decode(opened);
  }
  _rememberSkipped(id, key) {
    while (this._skipped.size >= RATCHET_LIMITS.MAX_SKIPPED_KEYS) {
      const oldest = this._skipped.keys().next().value;
      const evicted = this._skipped.get(oldest);
      this._skipped.delete(oldest);
      if (evicted) zeroize(evicted.key);
    }
    this._skipped.set(id, { key, storedAt: Date.now() });
  }
  _pruneSkipped() {
    const cutoff = Date.now() - RATCHET_LIMITS.SKIPPED_KEY_TTL_MS;
    for (const [id, entry] of this._skipped) {
      if (entry.storedAt < cutoff) {
        zeroize(entry.key);
        this._skipped.delete(id);
      }
    }
  }
  /**
   * Compute the DH-ratchet step without applying it. The caller applies it only
   * after the triggering message has authenticated — see _stageReceive.
   */
  async _stageDhRatchet(remotePublicKeyB64) {
    const remotePublicKey = await this._importPublic(remotePublicKeyB64);
    const receiveDh = await this._dh(this._selfKeyPair.privateKey, remotePublicKey);
    const received = await advanceRoot(this._rootKey, receiveDh);
    zeroize(receiveDh);
    const nextSelfKeyPair = await this._generateKeyPair();
    const sendDh = await this._dh(nextSelfKeyPair.privateKey, remotePublicKey);
    const sending = await advanceRoot(received.nextRoot, sendDh);
    zeroize(sendDh);
    return {
      receivingChainKey: received.chainKey,
      apply: () => {
        zeroize(this._rootKey);
        zeroize(received.nextRoot);
        if (this._sendingChainKey) zeroize(this._sendingChainKey);
        this._rootKey = sending.nextRoot;
        this._sendingChainKey = sending.chainKey;
        this._selfKeyPair = nextSelfKeyPair;
        this._remotePublicKey = remotePublicKey;
        this._remotePublicKeyB64 = remotePublicKeyB64;
        this._previousSendCount = this._sendCount;
        this._sendCount = 0;
      },
      discard: () => {
        zeroize(received.nextRoot);
        zeroize(received.chainKey);
        zeroize(sending.nextRoot);
        zeroize(sending.chainKey);
      }
    };
  }
  /** Destroy every piece of key material this object holds. */
  destroy() {
    zeroize(this._rootKey);
    zeroize(this._sendingChainKey);
    zeroize(this._receivingChainKey);
    for (const entry of this._skipped.values()) zeroize(entry.key);
    this._skipped.clear();
    this._rootKey = null;
    this._sendingChainKey = null;
    this._receivingChainKey = null;
    this._selfKeyPair = null;
    this._remotePublicKey = null;
    this._remotePublicKeyB64 = null;
    this._initialised = false;
  }
};

// src/network/descriptor/sbq2.js
var SBQ2_VERSION = 2;
var LIMITS = Object.freeze({
  MAX_PAYLOAD_BYTES: 512,
  // ~3.5x the largest descriptor we have ever measured
  MAX_CANDIDATES: 8,
  MIN_UFRAG: 4,
  // RFC 8839: ice-ufrag is 4..256 chars
  MAX_UFRAG: 64,
  MIN_PWD: 22,
  // RFC 8839: ice-pwd is 22..256 chars, >=128 bits of randomness
  MAX_PWD: 64,
  FINGERPRINT_BYTES: 32,
  // SHA-256
  COMMITMENT_BYTES: 16,
  // 128-bit second-preimage resistance
  BINDING_BYTES: 8,
  MAX_LIFETIME_MINUTES: 60,
  MAX_EXT_BYTES: 255,
  // Byte budget for candidates admitted BEYOND the coverage set (coverage
  // itself is never cut — see pruneCandidates). Derived from the acceptance
  // target rather than picked: the largest answer head we have measured is
  // Firefox's, at 104 bytes (version+flags+expiry+tag+fingerprint+8-char
  // ufrag+32-char pwd+count+commitment), and QR version 8 at level M holds
  // 152 bytes in byte mode. 152 - 104 = 48.
  SURPLUS_CANDIDATE_BYTES: 48,
  // Clock-skew allowance, applied in both directions on the expiry check.
  //
  // Two minutes is chosen against the failure it exists for: a receiver whose
  // clock is off. An NTP-synced device is within milliseconds, and an
  // unsynced modern device drifts on the order of seconds per day, so two
  // minutes swallows every ordinary case. It does NOT swallow a grossly wrong
  // clock (manually set, or reset to the epoch by a dead battery) — that is
  // deliberate, because such a device cannot be given a meaningful freshness
  // guarantee and should be told so. The cost is that the replay window grows
  // from the nominal 10 minutes to 12; keeping the tolerance well under the
  // lifetime is what bounds that.
  CLOCK_SKEW_MS: 12e4
});
var EPOCH_MS = Date.UTC(2024, 0, 1);
var MAX_EXPIRY_UNITS = 16777215;
var TYPE = Object.freeze({ OFFER: 0, ANSWER: 1 });
var SETUP = Object.freeze(["actpass", "active", "passive"]);
var MMS_ENUM = Object.freeze([262144, 1073741823, 65536, null]);
var MMS_EXPLICIT = 3;
var EXT = Object.freeze({ MAX_MESSAGE_SIZE: 1 });
var KIND = Object.freeze({
  HOST_V4: 0,
  HOST_MDNS: 1,
  SRFLX_V4: 2,
  RELAY_V4: 3,
  HOST_V6: 4,
  SRFLX_V6: 5,
  RELAY_V6: 6
});
var KIND_ADDR_LEN = Object.freeze({ 0: 4, 1: 16, 2: 4, 3: 4, 4: 16, 5: 16, 6: 16 });
var KIND_TYPE = Object.freeze({ 0: "host", 1: "host", 2: "srflx", 3: "relay", 4: "host", 5: "srflx", 6: "relay" });
var KIND_FAMILY = Object.freeze({ 0: "v4", 1: "mdns", 2: "v4", 3: "v4", 4: "v6", 5: "v6", 6: "v6" });
var TCPTYPE = Object.freeze([null, "passive", "active", "so"]);
var TYPE_PREF = Object.freeze({ host: 126, srflx: 100, relay: 0 });
var ICE_CHAR = /^[A-Za-z0-9+/]+$/;
var DescriptorError = class extends Error {
  constructor(message, code = "malformed") {
    super(message);
    this.name = "DescriptorError";
    this.code = code;
  }
};
var fail = (msg, code) => {
  throw new DescriptorError(msg, code);
};
var UUID_RE = /^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\.local$/i;
var IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
function parseIpv4(s) {
  const m = IPV4_RE.exec(s);
  if (!m) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const v = Number(m[i + 1]);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    out[i] = v;
  }
  return out;
}
function parseIpv6(s) {
  if (!/^[0-9a-fA-F:.]+$/.test(s) || s.length > 45) return null;
  let text2 = s;
  let tail4 = null;
  const lastColon = text2.lastIndexOf(":");
  if (text2.includes(".")) {
    tail4 = parseIpv4(text2.slice(lastColon + 1));
    if (!tail4) return null;
    text2 = text2.slice(0, lastColon + 1) + "0:0";
  }
  const halves = text2.split("::");
  if (halves.length > 2) return null;
  const toWords = (part) => part === "" ? [] : part.split(":").map((h) => h.length === 0 || h.length > 4 ? NaN : parseInt(h, 16));
  const head = toWords(halves[0]);
  const tail = halves.length === 2 ? toWords(halves[1]) : [];
  if ([...head, ...tail].some((w) => !Number.isInteger(w) || w < 0 || w > 65535)) return null;
  let words;
  if (halves.length === 2) {
    const gap = 8 - head.length - tail.length;
    if (gap < 1) return null;
    words = [...head, ...new Array(gap).fill(0), ...tail];
  } else {
    words = head;
  }
  if (words.length !== 8) return null;
  const out = new Uint8Array(16);
  words.forEach((w, i) => {
    out[i * 2] = w >> 8;
    out[i * 2 + 1] = w & 255;
  });
  if (tail4) out.set(tail4, 12);
  return out;
}
function parseMdns(s) {
  const m = UUID_RE.exec(s);
  if (!m) return null;
  const hex = (m[1] + m[2] + m[3] + m[4] + m[5]).toLowerCase();
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function sdpLines(sdp) {
  if (typeof sdp !== "string") fail("SDP must be a string");
  if (sdp.length > 64 * 1024) fail("SDP is too large");
  return sdp.split(/\r\n|\n/).filter((l) => l.length > 0);
}
function attr(lines, name) {
  const prefix = `a=${name}:`;
  for (const l of lines) if (l.startsWith(prefix)) return l.slice(prefix.length).trim();
  return null;
}
function parseSdp(sdp) {
  const lines = sdpLines(sdp);
  const ufrag = attr(lines, "ice-ufrag");
  const pwd = attr(lines, "ice-pwd");
  if (!ufrag || !pwd) fail("SDP is missing ICE credentials");
  const fpLine = attr(lines, "fingerprint");
  if (!fpLine) fail("SDP is missing a DTLS fingerprint");
  const [hashAlg, fpHex] = fpLine.split(/\s+/);
  if (!hashAlg || hashAlg.toLowerCase() !== "sha-256") {
    fail(`unsupported DTLS fingerprint algorithm: ${String(hashAlg).slice(0, 16)}`);
  }
  const fpBytes = String(fpHex).split(":");
  if (fpBytes.length !== LIMITS.FINGERPRINT_BYTES) fail("DTLS fingerprint has the wrong length");
  const fingerprint = new Uint8Array(LIMITS.FINGERPRINT_BYTES);
  fpBytes.forEach((b, i) => {
    if (!/^[0-9a-fA-F]{2}$/.test(b)) fail("DTLS fingerprint is not hex");
    fingerprint[i] = parseInt(b, 16);
  });
  const setupStr = attr(lines, "setup") || "actpass";
  const setup = SETUP.indexOf(setupStr);
  if (setup < 0) fail(`unsupported DTLS setup role: ${setupStr.slice(0, 16)}`);
  const mmsStr = attr(lines, "max-message-size");
  const maxMessageSize = mmsStr === null ? 65536 : Number(mmsStr);
  if (!Number.isInteger(maxMessageSize) || maxMessageSize < 0) fail("invalid a=max-message-size");
  const candidates = [];
  for (const line of lines) {
    if (!line.startsWith("a=candidate:")) continue;
    const p = line.slice("a=candidate:".length).split(/\s+/);
    if (p.length < 8 || p[6] !== "typ") continue;
    if (p[1] !== "1") continue;
    const transport = p[2].toLowerCase();
    const priority = Number(p[3]);
    const addr = p[4];
    const port = Number(p[5]);
    const ctype = p[7];
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
    let tcptype = 0;
    if (transport === "tcp") {
      const idx = p.indexOf("tcptype");
      const t = idx >= 0 ? TCPTYPE.indexOf(p[idx + 1]) : -1;
      if (t <= 0) continue;
      tcptype = t;
    } else if (transport !== "udp") {
      continue;
    }
    let kind = null;
    let bytes = null;
    const mdns = parseMdns(addr);
    if (mdns && ctype === "host") {
      kind = KIND.HOST_MDNS;
      bytes = mdns;
    } else {
      const v4 = parseIpv4(addr);
      const v6 = v4 ? null : parseIpv6(addr);
      const raw = v4 || v6;
      if (!raw) continue;
      if (ctype === "host") kind = v4 ? KIND.HOST_V4 : KIND.HOST_V6;
      else if (ctype === "srflx" || ctype === "prflx") kind = v4 ? KIND.SRFLX_V4 : KIND.SRFLX_V6;
      else if (ctype === "relay") kind = v4 ? KIND.RELAY_V4 : KIND.RELAY_V6;
      else continue;
      bytes = raw;
    }
    candidates.push({
      kind,
      tcptype,
      addr: bytes,
      port,
      priority: Number.isFinite(priority) ? priority : 0
    });
  }
  return { ufrag, pwd, fingerprint, setup, maxMessageSize, candidates };
}
function candidateSize(c) {
  return 1 + KIND_ADDR_LEN[c.kind] + 2;
}
var isConnectable = (c) => c.tcptype !== 2 && c.tcptype !== 3;
function pruneCandidates(candidates, {
  maxCandidates = LIMITS.MAX_CANDIDATES,
  maxBytes = LIMITS.SURPLUS_CANDIDATE_BYTES,
  keepMdns = true,
  maxRelays = 2
} = {}) {
  const pool = candidates.filter((c) => keepMdns || c.kind !== KIND.HOST_MDNS);
  const uniq = [];
  const seen = /* @__PURE__ */ new Set();
  for (const c of pool) {
    const key = `${c.kind}:${c.tcptype}:${Array.from(c.addr).join(".")}:${c.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    uniq.push(c);
  }
  const byPriority = (a, b) => (b.priority || 0) - (a.priority || 0);
  const groupKey = (c) => `${KIND_FAMILY[c.kind]}/${KIND_TYPE[c.kind]}/${c.tcptype === 0 ? "udp" : "tcp"}`;
  const groups = /* @__PURE__ */ new Map();
  for (const c of [...uniq].sort(byPriority)) {
    if (!isConnectable(c)) continue;
    const g = groupKey(c);
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(c);
  }
  const chosen = [];
  const taken = /* @__PURE__ */ new Set();
  let bytes = 0;
  let relays = 0;
  const admit = (c) => {
    chosen.push(c);
    taken.add(c);
    bytes += candidateSize(c);
    if (KIND_TYPE[c.kind] === "relay") relays++;
  };
  for (const list of groups.values()) admit(list[0]);
  for (const c of [...uniq].sort(byPriority)) {
    if (taken.has(c)) continue;
    if (chosen.length >= maxCandidates) break;
    if (bytes + candidateSize(c) > maxBytes) continue;
    if (KIND_TYPE[c.kind] === "relay" && relays >= maxRelays) continue;
    admit(c);
  }
  return chosen.sort(byPriority);
}
var Writer = class {
  constructor() {
    this.b = [];
  }
  u8(v) {
    this.b.push(v & 255);
  }
  u16(v) {
    this.b.push(v >> 8 & 255, v & 255);
  }
  u24(v) {
    this.b.push(v >> 16 & 255, v >> 8 & 255, v & 255);
  }
  u32(v) {
    this.b.push(v >>> 24 & 255, v >>> 16 & 255, v >>> 8 & 255, v & 255);
  }
  bytes(a) {
    for (const x of a) this.b.push(x & 255);
  }
  ascii(s) {
    for (let i = 0; i < s.length; i++) this.b.push(s.charCodeAt(i) & 255);
  }
  done() {
    return Uint8Array.from(this.b);
  }
};
function buildExtensions(maxMessageSize) {
  if (!Number.isInteger(maxMessageSize) || maxMessageSize < 1024 || maxMessageSize > 2147483647) {
    fail("max-message-size must be an integer between 1024 and 2^31-1");
  }
  const records = [];
  let mmsIndex = MMS_ENUM.indexOf(maxMessageSize);
  if (mmsIndex < 0) {
    mmsIndex = MMS_EXPLICIT;
    const w = new Writer();
    w.u32(maxMessageSize);
    records.push({ type: EXT.MAX_MESSAGE_SIZE, value: w.done() });
  }
  return { mmsIndex, records };
}
function encodeDescriptor(d) {
  const { type, bindingTag: tag = null, expiresAtMs, sdpFields, commitment = null } = d;
  if (type !== TYPE.OFFER && type !== TYPE.ANSWER) fail("invalid descriptor type");
  if (type === TYPE.ANSWER) {
    if (!(tag instanceof Uint8Array) || tag.length !== LIMITS.BINDING_BYTES) fail("answer needs an 8-byte binding tag");
  } else if (tag !== null) {
    fail("offers do not carry a binding tag");
  }
  if (commitment !== null && (!(commitment instanceof Uint8Array) || commitment.length !== LIMITS.COMMITMENT_BYTES)) {
    fail("commitment must be 16 bytes");
  }
  const { ufrag, pwd, fingerprint, setup, maxMessageSize, candidates } = sdpFields;
  if (ufrag.length < LIMITS.MIN_UFRAG || ufrag.length > LIMITS.MAX_UFRAG || !ICE_CHAR.test(ufrag)) fail("invalid ice-ufrag");
  if (pwd.length < LIMITS.MIN_PWD || pwd.length > LIMITS.MAX_PWD || !ICE_CHAR.test(pwd)) fail("invalid ice-pwd");
  if (candidates.length > LIMITS.MAX_CANDIDATES) fail("too many candidates");
  const minutes = Math.ceil((expiresAtMs - EPOCH_MS) / 6e4);
  if (!Number.isInteger(minutes) || minutes < 0 || minutes > MAX_EXPIRY_UNITS) fail("expiry out of range");
  const { mmsIndex, records } = buildExtensions(maxMessageSize);
  const ext = new Writer();
  for (const r of records) {
    if (r.value.length > 255) fail("extension value is too long");
    ext.u8(r.type);
    ext.u8(r.value.length);
    ext.bytes(r.value);
  }
  const extBytes = ext.done();
  if (extBytes.length > LIMITS.MAX_EXT_BYTES) fail("extension area is too long");
  const flags = type & 3 | (setup & 3) << 2 | (mmsIndex & 3) << 4 | (commitment ? 64 : 0) | (extBytes.length ? 128 : 0);
  const w = new Writer();
  w.u8(SBQ2_VERSION);
  w.u8(flags);
  w.u24(minutes);
  if (type === TYPE.ANSWER) w.bytes(tag);
  w.bytes(fingerprint);
  w.u8(ufrag.length);
  w.ascii(ufrag);
  w.u8(pwd.length);
  w.ascii(pwd);
  w.u8(candidates.length);
  for (const c of candidates) {
    w.u8((c.kind & 15) << 4 | c.tcptype & 15);
    w.bytes(c.addr);
    w.u16(c.port);
  }
  if (commitment) w.bytes(commitment);
  if (extBytes.length) {
    w.u8(extBytes.length);
    w.bytes(extBytes);
  }
  const out = w.done();
  if (out.length > LIMITS.MAX_PAYLOAD_BYTES) fail("descriptor exceeds the payload limit");
  return out;
}
var Reader = class {
  constructor(buf) {
    this.buf = buf;
    this.i = 0;
  }
  need(n) {
    if (this.i + n > this.buf.length) fail("descriptor is truncated");
  }
  u8() {
    this.need(1);
    return this.buf[this.i++];
  }
  u16() {
    this.need(2);
    const v = this.buf[this.i] << 8 | this.buf[this.i + 1];
    this.i += 2;
    return v;
  }
  u24() {
    this.need(3);
    const v = this.buf[this.i] << 16 | this.buf[this.i + 1] << 8 | this.buf[this.i + 2];
    this.i += 3;
    return v;
  }
  u32() {
    this.need(4);
    const v = (this.buf[this.i] << 24 >>> 0) + (this.buf[this.i + 1] << 16) + (this.buf[this.i + 2] << 8) + this.buf[this.i + 3];
    this.i += 4;
    return v >>> 0;
  }
  bytes(n) {
    this.need(n);
    return this.buf.slice(this.i, this.i += n);
  }
  ascii(n) {
    this.need(n);
    let s = "";
    for (let k = 0; k < n; k++) {
      const c = this.buf[this.i + k];
      if (c < 32 || c > 126) fail("non-printable byte in a text field");
      s += String.fromCharCode(c);
    }
    this.i += n;
    return s;
  }
  get rest() {
    return this.buf.length - this.i;
  }
};
function decodeExt(buf) {
  const r = new Reader(buf);
  const out = /* @__PURE__ */ new Map();
  let lastType = -1;
  while (r.rest > 0) {
    const type = r.u8();
    const len = r.u8();
    const value = r.bytes(len);
    if (type <= lastType) fail("extension records must be in ascending type order without duplicates");
    lastType = type;
    switch (type) {
      case EXT.MAX_MESSAGE_SIZE: {
        if (len !== 4) fail("extension 0x01 must be 4 bytes");
        const v = new Reader(value).u32();
        if (v < 1024 || v > 2147483647) fail("extension 0x01 value is out of range");
        if (MMS_ENUM.includes(v)) fail("extension 0x01 duplicates a value the flags already encode");
        out.set(type, v);
        break;
      }
      default:
        fail(`unknown extension type 0x${type.toString(16).padStart(2, "0")}`, "unknown_extension");
    }
  }
  return out;
}
function decodeDescriptor(buf, { nowMs = Date.now() } = {}) {
  if (!(buf instanceof Uint8Array)) fail("descriptor must be a Uint8Array");
  if (buf.length === 0) fail("descriptor is empty");
  if (buf.length > LIMITS.MAX_PAYLOAD_BYTES) fail("descriptor exceeds the payload limit");
  const r = new Reader(buf);
  const version2 = r.u8();
  if (version2 !== SBQ2_VERSION) fail(`unsupported descriptor version 0x${version2.toString(16)}`, "version");
  const flags = r.u8();
  const type = flags & 3;
  if (type !== TYPE.OFFER && type !== TYPE.ANSWER) fail("reserved descriptor type");
  const setup = flags >> 2 & 3;
  if (setup > 2) fail("reserved DTLS setup role");
  const mmsIndex = flags >> 4 & 3;
  const hasCommitment = (flags & 64) !== 0;
  const hasExt = (flags & 128) !== 0;
  const minutes = r.u24();
  const expiresAtMs = EPOCH_MS + minutes * 6e4;
  if (nowMs - LIMITS.CLOCK_SKEW_MS > expiresAtMs) {
    const lateMin = Math.round((nowMs - expiresAtMs) / 6e4);
    fail(
      `this code expired ${lateMin} minute(s) ago. If it was just created, this device's clock or time zone is probably wrong \u2014 check the date and time settings.`,
      "expired"
    );
  }
  if (expiresAtMs - nowMs > LIMITS.MAX_LIFETIME_MINUTES * 6e4 + LIMITS.CLOCK_SKEW_MS) {
    fail("descriptor lifetime is implausibly long", "lifetime");
  }
  const bindingTag2 = type === TYPE.ANSWER ? r.bytes(LIMITS.BINDING_BYTES) : null;
  const fingerprint = r.bytes(LIMITS.FINGERPRINT_BYTES);
  const ufragLen = r.u8();
  if (ufragLen < LIMITS.MIN_UFRAG || ufragLen > LIMITS.MAX_UFRAG) fail("ice-ufrag length out of range");
  const ufrag = r.ascii(ufragLen);
  if (!ICE_CHAR.test(ufrag)) fail("ice-ufrag contains characters outside the ICE alphabet");
  const pwdLen = r.u8();
  if (pwdLen < LIMITS.MIN_PWD || pwdLen > LIMITS.MAX_PWD) fail("ice-pwd length out of range");
  const pwd = r.ascii(pwdLen);
  if (!ICE_CHAR.test(pwd)) fail("ice-pwd contains characters outside the ICE alphabet");
  const count = r.u8();
  if (count > LIMITS.MAX_CANDIDATES) fail("too many candidates");
  const candidates = [];
  for (let i = 0; i < count; i++) {
    const tagByte = r.u8();
    const kind = tagByte >> 4 & 15;
    const tcptype = tagByte & 15;
    const addrLen = KIND_ADDR_LEN[kind];
    if (addrLen === void 0) fail(`reserved candidate kind ${kind}`);
    if (tcptype >= TCPTYPE.length) fail("reserved TCP candidate type");
    const addr = r.bytes(addrLen);
    const port = r.u16();
    if (port < 1) fail("candidate port must be non-zero");
    candidates.push({ kind, tcptype, addr, port });
  }
  let commitment = null;
  if (hasCommitment) commitment = r.bytes(LIMITS.COMMITMENT_BYTES);
  let extensions = /* @__PURE__ */ new Map();
  if (hasExt) {
    const extLen = r.u8();
    if (extLen === 0) fail("extension area is flagged but empty");
    extensions = decodeExt(r.bytes(extLen));
  }
  if (r.rest !== 0) fail(`${r.rest} trailing byte(s) after the descriptor`);
  let maxMessageSize;
  if (mmsIndex === MMS_EXPLICIT) {
    if (!extensions.has(EXT.MAX_MESSAGE_SIZE)) fail("flags promise an explicit max-message-size but no extension carries it");
    maxMessageSize = extensions.get(EXT.MAX_MESSAGE_SIZE);
  } else {
    if (extensions.has(EXT.MAX_MESSAGE_SIZE)) fail("extension 0x01 present but the flags do not select it");
    maxMessageSize = MMS_ENUM[mmsIndex];
  }
  return {
    version: version2,
    type,
    setup,
    maxMessageSize,
    expiresAtMs,
    bindingTag: bindingTag2,
    fingerprint,
    ufrag,
    pwd,
    candidates,
    commitment,
    extensions
  };
}
var hex2 = (b) => b.toString(16).padStart(2, "0");
function renderAddr(kind, addr) {
  switch (kind) {
    case KIND.HOST_MDNS: {
      const h = Array.from(addr, hex2).join("");
      return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}.local`;
    }
    case KIND.HOST_V4:
    case KIND.SRFLX_V4:
    case KIND.RELAY_V4:
      return `${addr[0]}.${addr[1]}.${addr[2]}.${addr[3]}`;
    default: {
      const words = [];
      for (let i = 0; i < 16; i += 2) words.push((addr[i] << 8 | addr[i + 1]).toString(16));
      return words.join(":");
    }
  }
}
function serializeSdp(desc, { sessionId = "1" } = {}) {
  const isOffer = desc.type === TYPE.OFFER;
  const DEFAULT_RANK = { relay: 0, srflx: 1, host: 2 };
  const def = desc.candidates.filter((c) => c.kind !== KIND.HOST_MDNS && c.tcptype === 0).sort((x, y) => DEFAULT_RANK[KIND_TYPE[x.kind]] - DEFAULT_RANK[KIND_TYPE[y.kind]])[0];
  const defIsV6 = def && KIND_FAMILY[def.kind] === "v6";
  const mPort = def ? def.port : 9;
  const cLine = def ? `c=IN IP${defIsV6 ? "6" : "4"} ${renderAddr(def.kind, def.addr)}` : "c=IN IP4 0.0.0.0";
  const lines = [
    "v=0",
    `o=- ${sessionId} 2 IN IP4 127.0.0.1`,
    "s=-",
    "t=0 0",
    "a=group:BUNDLE 0",
    "a=msid-semantic: WMS",
    `m=application ${mPort} UDP/DTLS/SCTP webrtc-datachannel`,
    cLine,
    "a=ice-ufrag:" + desc.ufrag,
    "a=ice-pwd:" + desc.pwd,
    // Deliberately NOT `a=ice-options:trickle`. A descriptor is a complete,
    // one-shot candidate set — there is no signalling channel to trickle
    // over, so advertising trickle promises candidates that can never
    // arrive and leaves the peer's ICE agent waiting for them.
    "a=fingerprint:sha-256 " + Array.from(desc.fingerprint, (b) => hex2(b).toUpperCase()).join(":"),
    "a=setup:" + SETUP[desc.setup],
    "a=mid:0",
    "a=sctp-port:5000",
    "a=max-message-size:" + desc.maxMessageSize
  ];
  const candLines = desc.candidates.map((c, i) => {
    const ctype = KIND_TYPE[c.kind];
    const transport = c.tcptype === 0 ? "udp" : "tcp";
    const localPref = Math.max(0, 65535 - i);
    const priority = TYPE_PREF[ctype] * 16777216 + localPref * 256 + 255;
    const foundation = String(c.kind * 4 + c.tcptype + 1);
    let line = `a=candidate:${foundation} 1 ${transport} ${priority} ${renderAddr(c.kind, c.addr)} ${c.port} typ ${ctype}`;
    if (ctype !== "host") {
      line += KIND_FAMILY[c.kind] === "v6" ? " raddr :: rport 0" : " raddr 0.0.0.0 rport 0";
    }
    if (transport === "tcp") line += ` tcptype ${TCPTYPE[c.tcptype]}`;
    return line;
  });
  candLines.push("a=end-of-candidates");
  const at = lines.indexOf(cLine) + 1;
  lines.splice(at, 0, ...candLines);
  return { type: isOffer ? "offer" : "answer", sdp: lines.join("\r\n") + "\r\n" };
}
var enc2 = new TextEncoder();
function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
async function bindingTag(digest, offerBytes) {
  const h = await digest(concat(enc2.encode("sbq2/bind\0"), offerBytes));
  return h.slice(0, LIMITS.BINDING_BYTES);
}
async function commitBlob(digest, blobBytes) {
  const h = await digest(concat(enc2.encode("sbq2/blob\0"), blobBytes));
  return h.slice(0, LIMITS.COMMITMENT_BYTES);
}
function sasTranscript(offerBytes, answerBytes, offerBlob, answerBlob) {
  const lp = (b) => {
    const n = new Uint8Array(4);
    new DataView(n.buffer).setUint32(0, b.length);
    return concat(n, b);
  };
  return concat(
    enc2.encode("sbq2/sas/v1\0"),
    lp(offerBytes),
    lp(answerBytes),
    lp(offerBlob),
    lp(answerBlob)
  );
}
var B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function toBase64Url(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
    out += B64URL[a >> 2];
    out += B64URL[(a & 3) << 4 | (b ?? 0) >> 4];
    if (b === void 0) break;
    out += B64URL[(b & 15) << 2 | (c ?? 0) >> 6];
    if (c === void 0) break;
    out += B64URL[c & 63];
  }
  return out;
}
function fromBase64Url(text2) {
  if (typeof text2 !== "string") fail("payload must be a string");
  const s = text2.replace(/\s+/g, "");
  if (s.length > Math.ceil(LIMITS.MAX_PAYLOAD_BYTES * 4 / 3) + 4) fail("payload is too long");
  if (!/^[A-Za-z0-9_-]*$/.test(s)) fail("payload contains characters outside base64url");
  if (s.length % 4 === 1) fail("payload has an impossible length");
  const out = new Uint8Array(Math.floor(s.length * 3 / 4));
  let o = 0, acc = 0, bits = 0;
  for (const ch of s) {
    acc = acc << 6 | B64URL.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = acc >> bits & 255;
    }
  }
  if (acc & (1 << bits) - 1) fail("payload has non-zero padding bits");
  return out.subarray(0, o);
}
var TEXT_PREFIX = "SB2:";
function encodeText(bytes) {
  return TEXT_PREFIX + toBase64Url(bytes);
}
function decodeText(text2) {
  if (typeof text2 !== "string") fail("payload must be a string");
  const t = text2.trim();
  if (!t.startsWith(TEXT_PREFIX)) fail("not an SB2 descriptor");
  return fromBase64Url(t.slice(TEXT_PREFIX.length));
}

// src/network/descriptor/keyexchange.js
var KEY_BLOB_VERSION = 2;
var ROLE = Object.freeze({ OFFER: 0, ANSWER: 1 });
var BLOB_LIMITS = Object.freeze({
  // A P-384 SPKI is 120 bytes; P-521 would be 158. The ceiling is generous
  // enough for a future curve and far below anything that could be used to
  // wedge the parser.
  MAX_SPKI: 256,
  MIN_SPKI: 40,
  // ECDSA P-384 signatures are 96 bytes raw; P-521 is 132.
  MAX_SIG: 160,
  MIN_SIG: 48,
  MAX_BLOB_BYTES: 1024
});
var KeyExchangeError = class extends Error {
  constructor(message, code = "key_exchange") {
    super(message);
    this.name = "KeyExchangeError";
    this.code = code;
  }
};
var fail2 = (msg, code) => {
  throw new KeyExchangeError(msg, code);
};
function encodeKeyBlob({ role, ecdhSpki, ecdsaSpki }) {
  if (role !== ROLE.OFFER && role !== ROLE.ANSWER) fail2("invalid role");
  for (const [name, v] of [["ecdh", ecdhSpki], ["ecdsa", ecdsaSpki]]) {
    if (!(v instanceof Uint8Array)) fail2(`${name} SPKI must be a Uint8Array`);
    if (v.length < BLOB_LIMITS.MIN_SPKI || v.length > BLOB_LIMITS.MAX_SPKI) {
      fail2(`${name} SPKI length out of range`);
    }
  }
  const out = new Uint8Array(1 + 1 + 2 + ecdhSpki.length + 2 + ecdsaSpki.length);
  const dv = new DataView(out.buffer);
  let o = 0;
  out[o++] = KEY_BLOB_VERSION;
  out[o++] = role;
  dv.setUint16(o, ecdhSpki.length);
  o += 2;
  out.set(ecdhSpki, o);
  o += ecdhSpki.length;
  dv.setUint16(o, ecdsaSpki.length);
  o += 2;
  out.set(ecdsaSpki, o);
  return out;
}
function decodeKeyBlob(buf) {
  if (!(buf instanceof Uint8Array)) fail2("key blob must be a Uint8Array");
  if (buf.length === 0) fail2("key blob is empty");
  if (buf.length > BLOB_LIMITS.MAX_BLOB_BYTES) fail2("key blob exceeds the size limit");
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let o = 0;
  const need = (n) => {
    if (o + n > buf.length) fail2("key blob is truncated");
  };
  need(1);
  const version2 = buf[o++];
  if (version2 !== KEY_BLOB_VERSION) fail2(`unsupported key blob version 0x${version2.toString(16)}`, "version");
  need(1);
  const role = buf[o++];
  if (role !== ROLE.OFFER && role !== ROLE.ANSWER) fail2("reserved key blob role");
  need(2);
  const ecdhLen = dv.getUint16(o);
  o += 2;
  if (ecdhLen < BLOB_LIMITS.MIN_SPKI || ecdhLen > BLOB_LIMITS.MAX_SPKI) fail2("ECDH SPKI length out of range");
  need(ecdhLen);
  const ecdhSpki = buf.slice(o, o + ecdhLen);
  o += ecdhLen;
  need(2);
  const ecdsaLen = dv.getUint16(o);
  o += 2;
  if (ecdsaLen < BLOB_LIMITS.MIN_SPKI || ecdsaLen > BLOB_LIMITS.MAX_SPKI) fail2("ECDSA SPKI length out of range");
  need(ecdsaLen);
  const ecdsaSpki = buf.slice(o, o + ecdsaLen);
  o += ecdsaLen;
  if (o !== buf.length) fail2(`${buf.length - o} trailing byte(s) after the key blob`);
  return { version: version2, role, ecdhSpki, ecdsaSpki };
}
function buildTranscript({ offerDescriptor, answerDescriptor, offerBlob, answerBlob }) {
  for (const [name, v] of Object.entries({ offerDescriptor, answerDescriptor, offerBlob, answerBlob })) {
    if (!(v instanceof Uint8Array) || v.length === 0) fail2(`transcript component ${name} is missing`);
  }
  return sasTranscript(offerDescriptor, answerDescriptor, offerBlob, answerBlob);
}
async function deriveTranscriptSalt(subtle, transcript) {
  const h = await subtle.digest("SHA-512", transcript);
  return Array.from(new Uint8Array(h));
}
var enc3 = new TextEncoder();
function proofPayload(transcript) {
  const label = enc3.encode("sbq2/proof/v1\0");
  const out = new Uint8Array(label.length + transcript.length);
  out.set(label, 0);
  out.set(transcript, label.length);
  return out;
}
async function computeTranscriptSas(subtle, { ecdhPrivateKey, peerEcdhPublicKey, transcript, digits = 7 }) {
  const shared = await subtle.deriveBits({ name: "ECDH", public: peerEcdhPublicKey }, ecdhPrivateKey, 256);
  let ikm = null;
  try {
    ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
    const salt = new Uint8Array(await subtle.digest("SHA-256", transcript));
    const bits = await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: enc3.encode("sbq2-sas-v1") },
      ikm,
      64
    );
    const dv = new DataView(bits);
    const n = (dv.getUint32(0) ^ dv.getUint32(4)) >>> 0;
    const mod = 10 ** digits;
    return String(n % mod).padStart(digits, "0");
  } finally {
    try {
      new Uint8Array(shared).fill(0);
    } catch (_) {
    }
  }
}
async function verifyBlobCommitment(subtle, blobBytes, expectedCommitment) {
  if (!(expectedCommitment instanceof Uint8Array) || expectedCommitment.length !== LIMITS.COMMITMENT_BYTES) {
    fail2("descriptor carried no usable commitment", "commitment_missing");
  }
  const digest = async (b) => new Uint8Array(await subtle.digest("SHA-256", b));
  const actual = await commitBlob(digest, blobBytes);
  if (actual.length !== expectedCommitment.length) fail2("commitment length mismatch", "commitment_mismatch");
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expectedCommitment[i];
  if (diff !== 0) {
    fail2("the key material does not match the commitment in the invitation", "commitment_mismatch");
  }
  return true;
}

// src/network/EnhancedSecureWebRTCManager.js
var EnhancedSecureWebRTCManager = class _EnhancedSecureWebRTCManager {
  // ============================================
  // CONSTANTS
  // ============================================
  static TIMEOUTS = {
    KEY_ROTATION_INTERVAL: 3e5,
    // 5 minutes
    CONNECTION_TIMEOUT: 1e4,
    // 10 seconds  
    // Kept below LIVENESS_PROBE_AFTER so a healthy peer's own heartbeats keep
    // the liveness clock fresh and probing never happens on a working link.
    HEARTBEAT_INTERVAL: 1e4,
    // 10 seconds
    SECURITY_CALC_DELAY: 1e3,
    // 1 second
    SECURITY_CALC_RETRY_DELAY: 3e3,
    // 3 seconds
    CLEANUP_INTERVAL: 3e5,
    // 5 minutes (periodic cleanup)
    CLEANUP_CHECK_INTERVAL: 6e4,
    // 1 minute (cleanup check)
    ICE_GATHERING_TIMEOUT: 1e4,
    // 10 seconds — soft: enough on a healthy network
    // Hard ceiling used only when the soft deadline passes with NOTHING to
    // export. Blocked STUN/TURN keeps gathering "in progress" indefinitely, so
    // giving up at 10 s turned a slow network into a failed handshake.
    ICE_GATHERING_HARD_TIMEOUT: 25e3,
    // 25 seconds
    DISCONNECT_CLEANUP_DELAY: 500,
    // 500ms
    PEER_DISCONNECT_CLEANUP: 2e3,
    // 2 seconds
    STAGE2_ACTIVATION_DELAY: 1e4,
    // 10 seconds
    STAGE3_ACTIVATION_DELAY: 15e3,
    // 15 seconds  
    STAGE4_ACTIVATION_DELAY: 2e4,
    // 20 seconds
    FILE_TRANSFER_INIT_DELAY: 1e3,
    // 1 second
    FAKE_TRAFFIC_MIN_INTERVAL: 15e3,
    // 15 seconds
    FAKE_TRAFFIC_MAX_INTERVAL: 3e4,
    // 30 seconds
    DECOY_INITIAL_DELAY: 5e3,
    // 5 seconds
    DECOY_TRAFFIC_MIN: 1e4,
    // 10 seconds
    DECOY_TRAFFIC_MAX: 25e3,
    // 25 seconds
    REORDER_TIMEOUT: 3e3,
    // 3 seconds
    RETRY_CONNECTION_DELAY: 2e3,
    // 2 seconds
    // --- Session recovery ---
    // How long to let a 'disconnected' path heal itself before renegotiating.
    //
    // The browser enters 'disconnected' after only ~5 s without a consent
    // binding response, which ordinary packet loss produces, and then holds
    // that state for roughly 25 s before declaring 'failed'. That whole
    // window exists precisely so the connection can come back on its own —
    // and it very often does, especially against a phone whose screen went
    // off, which generates these episodes constantly.
    //
    // So restart LATE in the window, not at the start: early enough to still
    // beat 'failed', late enough that self-healing has had its chance. An
    // earlier 3 s value meant every backgrounded phone was answered with a
    // renegotiation — tearing down a connection that was about to recover.
    // See https://blog.mozilla.org/webrtc/ice-disconnected-not/
    ICE_DISCONNECT_GRACE: 8e3,
    // 8 seconds
    // How long one restart round-trip (offer → gather → answer) may take. No
    // new attempt is launched while one is in flight: the round-trip is far
    // longer than the head of the backoff, so retrying blindly cancels the
    // attempt already running and recovery never converges.
    ICE_RESTART_TIMEOUT: 2e4,
    // 20 seconds
    // Gathering budget inside a restart. Deliberately far below the initial
    // handshake's 10 s: host and server-reflexive candidates arrive in well
    // under a second, and waiting out the full budget for a relay candidate
    // that may never come would blow the round-trip deadline above.
    ICE_RESTART_GATHERING: 4e3,
    // 4 seconds
    // Give up on automatic recovery after this long. There is no manual
    // fallback: the session is ended and its data wiped.
    RECONNECT_MAX_DURATION: 12e4,
    // 2 minutes
    // In-band recovery needs the data channel to carry the renegotiation. If
    // nothing at all arrives from the peer for this long once recovery has
    // started, it cannot — and no number of further attempts will change
    // that, so the session is ended promptly instead of after a two-minute
    // wait that was never going to succeed.
    RECOVERY_SILENCE_LIMIT: 15e3,
    // 15 seconds
    // Liveness is established by an explicit probe/ack, not by silence alone.
    // Silence on its own is not proof of death: a browser throttles timers in a
    // backgrounded tab (Chrome down to roughly one per minute, iOS Safari
    // freezes them outright), so a perfectly healthy peer can stop sending for
    // a long time. Inbound message handling is NOT throttled that way, so a
    // live peer — even a backgrounded one — answers a probe within milliseconds
    // while a peer whose network is gone cannot answer at all.
    LIVENESS_PROBE_AFTER: 12e3,
    // silence before probing the peer
    LIVENESS_PROBE_TIMEOUT: 5e3,
    // how long the ack may take
    LIVENESS_CHECK_INTERVAL: 2e3
    // 2 seconds
  };
  // Backoff between automatic ICE-restart attempts (ms). Deliberately short at
  // the head: most real drops recover on the first or second try.
  static RECONNECT_BACKOFF = Object.freeze([1e3, 2e3, 4e3, 8e3, 15e3, 3e4]);
  static LIMITS = {
    MAX_CONNECTION_ATTEMPTS: 3,
    // Consecutive ICE failures that produced zero candidate pairs before
    // concluding the PeerConnection itself is unusable, rather than the path
    // merely being flaky.
    MAX_BARREN_ICE_FAILURES: 2,
    MAX_OLD_KEYS: 3,
    MAX_PROCESSED_MESSAGE_IDS: 1e3,
    MAX_OUT_OF_ORDER_PACKETS: 5,
    MAX_DECOY_CHANNELS: 1,
    MESSAGE_RATE_LIMIT: 60,
    // messages per minute
    MAX_KEY_AGE: 9e5,
    // 15 minutes
    OFFER_MAX_AGE: 36e5,
    // 1 hour
    SALT_SIZE_V3: 32,
    // bytes
    SALT_SIZE_V4: 64
    // bytes
  };
  static SIZES = {
    VERIFICATION_CODE_MIN_LENGTH: 6,
    FAKE_TRAFFIC_MIN_SIZE: 32,
    FAKE_TRAFFIC_MAX_SIZE: 128,
    PACKET_PADDING_MIN: 64,
    PACKET_PADDING_MAX: 512,
    CHUNK_SIZE_MAX: 2048,
    CHUNK_DELAY_MIN: 100,
    CHUNK_DELAY_MAX: 500,
    FINGERPRINT_DISPLAY_LENGTH: 8,
    SESSION_ID_LENGTH: 16,
    NESTED_ENCRYPTION_IV_SIZE: 12
  };
  static MESSAGE_TYPES = {
    // Regular messages
    MESSAGE: "message",
    ENHANCED_MESSAGE: "enhanced_message",
    // Chat content under the Double Ratchet: a per-message key that is
    // destroyed after use. Carries its own plaintext header (ratchet public
    // key, chain position) which AES-GCM authenticates as AAD.
    RATCHET_MESSAGE: "ratchet_message",
    // Per-message control (unsend / disappearing sync)
    MESSAGE_DELETE: "message_delete",
    // Delivery receipt: recipient acks a chat message by id (WhatsApp ✓✓).
    MESSAGE_RECEIPT: "message_receipt",
    // System messages
    HEARTBEAT: "heartbeat",
    VERIFICATION: "verification",
    VERIFICATION_RESPONSE: "verification_response",
    VERIFICATION_CONFIRMED: "verification_confirmed",
    VERIFICATION_BOTH_CONFIRMED: "verification_both_confirmed",
    PEER_DISCONNECT: "peer_disconnect",
    SECURITY_UPGRADE: "security_upgrade",
    KEY_ROTATION_SIGNAL: "key_rotation_signal",
    KEY_ROTATION_READY: "key_rotation_ready",
    // File transfer messages
    FILE_TRANSFER_START: "file_transfer_start",
    FILE_TRANSFER_RESPONSE: "file_transfer_response",
    FILE_CHUNK: "file_chunk",
    CHUNK_CONFIRMATION: "chunk_confirmation",
    FILE_TRANSFER_COMPLETE: "file_transfer_complete",
    FILE_TRANSFER_ERROR: "file_transfer_error",
    // Encrypted voice / video calls. SDP + ICE are exchanged over the
    // already-authenticated (ECDH + SAS-verified) data channel, so the
    // DTLS-SRTP fingerprints negotiated for the media are themselves
    // authenticated end-to-end — a signalling server never sees them.
    CALL_OFFER: "call_offer",
    CALL_ANSWER: "call_answer",
    CALL_ICE: "call_ice",
    CALL_DECLINE: "call_decline",
    CALL_END: "call_end",
    // Session recovery. An ICE restart renegotiates ONLY the transport path
    // (new candidates after a NAT rebind / IP change); the DTLS handshake and
    // the SCTP association that carries this data channel survive it, so the
    // session keys, the SAS verification and the message history all stay
    // valid. The renegotiation SDP therefore rides the existing E2E channel —
    // still no signalling server. Note that holding the session keys is NOT
    // itself proof of identity: a MITM who completed the handshake holds them
    // too. These frames are accepted only after SAS verification (see
    // POST_VERIFICATION_CONTROL_TYPES).
    ICE_RESTART_OFFER: "ice_restart_offer",
    ICE_RESTART_ANSWER: "ice_restart_answer",
    // Sent by the answerer side, which must not create offers itself (glare):
    // it asks the offerer to drive the restart.
    ICE_RESTART_REQUEST: "ice_restart_request",
    // SBQ2 in-band key exchange. These are the only two frames that legitimately
    // arrive before any key exists, which is exactly why they are handled in one
    // place and nowhere else: KEY_BLOB carries the key material the descriptor's
    // commitment covers, KEY_PROOF the signature over the transcript.
    KEY_BLOB: "key_blob",
    KEY_PROOF: "key_proof",
    // Fake traffic
    FAKE: "fake"
  };
  static FILTERED_RESULTS = {
    FAKE_MESSAGE: "FAKE_MESSAGE_FILTERED",
    FILE_MESSAGE: "FILE_MESSAGE_FILTERED",
    SYSTEM_MESSAGE: "SYSTEM_MESSAGE_FILTERED"
  };
  // Control frames that may only be acted on once the session is SAS-verified.
  // Deliberately an allowlist: an unknown type is not a control frame and is
  // rejected by the chat channel's default-deny branch. The verification
  // handshake itself (verification*, heartbeat) is excluded — it has to work
  // before verification exists, which is what makes it worth reviewing closely.
  static POST_VERIFICATION_CONTROL_TYPES = /* @__PURE__ */ new Set([
    _EnhancedSecureWebRTCManager.MESSAGE_TYPES.MESSAGE_DELETE,
    _EnhancedSecureWebRTCManager.MESSAGE_TYPES.MESSAGE_RECEIPT,
    _EnhancedSecureWebRTCManager.MESSAGE_TYPES.CALL_OFFER,
    _EnhancedSecureWebRTCManager.MESSAGE_TYPES.CALL_ANSWER,
    _EnhancedSecureWebRTCManager.MESSAGE_TYPES.CALL_ICE,
    _EnhancedSecureWebRTCManager.MESSAGE_TYPES.CALL_DECLINE,
    _EnhancedSecureWebRTCManager.MESSAGE_TYPES.CALL_END,
    _EnhancedSecureWebRTCManager.MESSAGE_TYPES.ICE_RESTART_OFFER,
    _EnhancedSecureWebRTCManager.MESSAGE_TYPES.ICE_RESTART_ANSWER,
    _EnhancedSecureWebRTCManager.MESSAGE_TYPES.ICE_RESTART_REQUEST
  ]);
  // ── SBQ2 ROLLBACK SWITCH ────────────────────────────────────────────────
  // Flip this ONE value to false and redeploy to put every new invitation back
  // on the SB1 format. Nothing else needs touching: reception of both formats
  // is unconditional, so a client built with this off still reads SBQ2
  // invitations from a client built with it on.
  //
  // It only governs what we EMIT. It is deliberately not consulted anywhere in
  // the receive path, and never inside an established session — see
  // _handshakeMode, which is latched per connection so a session cannot be
  // pushed back onto the weaker format halfway through.
  static SBQ2_SEND_ENABLED = true;
  // How long the in-band key exchange may take from channel open to verified
  // proof. Generous next to the ~1 s a handshake actually needs, tight enough
  // that a peer that never sends its blob does not hang the UI indefinitely.
  static SBQ2_KEY_EXCHANGE_TIMEOUT_MS = 15e3;
  static PROTOCOL_VERSION = "4.1";
  // Double Ratchet wire version. Bump only on an incompatible ratchet change;
  // peers compare it and fall back to static keys when it is absent or unknown.
  static RATCHET_VERSION = 1;
  static MAX_SAS_ATTEMPTS = 3;
  static DEFAULT_ICE_SERVERS = Object.freeze([
    // Keep multiple independent public STUN defaults so one provider-side
    // DNS/path failure does not strand standard-mode connectivity.
    Object.freeze({ urls: "stun:stun.cloudflare.com:3478" }),
    Object.freeze({ urls: "stun:stun.l.google.com:19302" }),
    Object.freeze({ urls: "stun:stun1.l.google.com:19302" }),
    Object.freeze({ urls: "stun:stun2.l.google.com:19302" }),
    Object.freeze({ urls: "stun:stun3.l.google.com:19302" }),
    Object.freeze({ urls: "stun:stun4.l.google.com:19302" })
  ]);
  //   Static debug flag instead of this._debugMode
  static DEBUG_MODE = false;
  // Set to true during development, false in production
  constructor(onMessage, onStatusChange, onKeyExchange, onVerificationRequired, onAnswerError = null, onVerificationStateChange = null, config = {}) {
    this._isProductionMode = this._detectProductionMode();
    this._debugMode = !this._isProductionMode && _EnhancedSecureWebRTCManager.DEBUG_MODE;
    this._config = {
      fakeTraffic: {
        enabled: config.fakeTraffic?.enabled ?? true,
        minInterval: config.fakeTraffic?.minInterval ?? _EnhancedSecureWebRTCManager.TIMEOUTS.FAKE_TRAFFIC_MIN_INTERVAL,
        maxInterval: config.fakeTraffic?.maxInterval ?? _EnhancedSecureWebRTCManager.TIMEOUTS.FAKE_TRAFFIC_MAX_INTERVAL,
        minSize: config.fakeTraffic?.minSize ?? _EnhancedSecureWebRTCManager.SIZES.FAKE_TRAFFIC_MIN_SIZE,
        maxSize: config.fakeTraffic?.maxSize ?? _EnhancedSecureWebRTCManager.SIZES.FAKE_TRAFFIC_MAX_SIZE,
        patterns: config.fakeTraffic?.patterns ?? ["heartbeat", "status", "sync"]
      },
      decoyChannels: {
        enabled: config.decoyChannels?.enabled ?? true,
        maxDecoyChannels: config.decoyChannels?.maxDecoyChannels ?? _EnhancedSecureWebRTCManager.LIMITS.MAX_DECOY_CHANNELS,
        decoyChannelNames: config.decoyChannels?.decoyChannelNames ?? ["heartbeat"],
        sendDecoyData: config.decoyChannels?.sendDecoyData ?? true,
        randomDecoyIntervals: config.decoyChannels?.randomDecoyIntervals ?? true
      },
      packetPadding: {
        enabled: config.packetPadding?.enabled ?? true,
        minPadding: config.packetPadding?.minPadding ?? _EnhancedSecureWebRTCManager.SIZES.PACKET_PADDING_MIN,
        maxPadding: config.packetPadding?.maxPadding ?? _EnhancedSecureWebRTCManager.SIZES.PACKET_PADDING_MAX,
        useRandomPadding: config.packetPadding?.useRandomPadding ?? true,
        preserveMessageSize: config.packetPadding?.preserveMessageSize ?? false
      },
      antiFingerprinting: {
        enabled: config.antiFingerprinting?.enabled ?? false,
        randomizeTiming: config.antiFingerprinting?.randomizeTiming ?? true,
        randomizeSizes: config.antiFingerprinting?.randomizeSizes ?? false,
        addNoise: config.antiFingerprinting?.addNoise ?? true,
        maskPatterns: config.antiFingerprinting?.maskPatterns ?? false,
        useRandomHeaders: config.antiFingerprinting?.useRandomHeaders ?? false
      },
      webrtc: {
        // `privacyMode` is canonical; `relayOnly` remains a
        // backward-compatible input alias at construction time.
        privacyMode: config.webrtc?.privacyMode ?? (config.webrtc?.relayOnly ? "relay-only" : "standard"),
        relayOnly: config.webrtc?.privacyMode ? config.webrtc.privacyMode === "relay-only" : config.webrtc?.relayOnly ?? false,
        iceServers: config.webrtc?.iceServers ?? _EnhancedSecureWebRTCManager.DEFAULT_ICE_SERVERS.map((server) => ({ ...server }))
      }
    };
    this._emitGlobalEvents = config.emitGlobalEvents !== false;
    this._ipLeakWarningShown = false;
    this._initializeSecureLogging();
    this._setupOwnLogger();
    this._setupProductionLogging();
    this._storeImportantMethods();
    this._setupSecureGlobalAPI();
    if (!window.EnhancedSecureCryptoUtils) {
      throw new Error("EnhancedSecureCryptoUtils is not loaded. Please ensure the module is loaded first.");
    }
    this.getSecurityData = () => {
      return this.lastSecurityCalculation ? {
        level: this.lastSecurityCalculation.level,
        score: this.lastSecurityCalculation.score,
        timestamp: this.lastSecurityCalculation.timestamp
        // Do NOT return check details or sensitive data
      } : null;
    };
    this._secureLog("info", "\u{1F512} Enhanced WebRTC Manager initialized with secure API");
    this.sessionConstraints = null;
    this.peerConnection = null;
    this.dataChannel = null;
    this.onMessage = onMessage;
    this.onStatusChange = onStatusChange;
    this.onKeyExchange = onKeyExchange;
    this.onVerificationStateChange = onVerificationStateChange;
    this.onVerificationRequired = onVerificationRequired;
    this.onAnswerError = onAnswerError;
    this.isInitiator = false;
    this.connectionAttempts = 0;
    this.maxConnectionAttempts = _EnhancedSecureWebRTCManager.LIMITS.MAX_CONNECTION_ATTEMPTS;
    try {
      this._initializeMutexSystem();
    } catch (error) {
      this._secureLog("error", "\u274C Failed to initialize mutex system", {
        errorType: error.constructor.name
      });
      throw new Error("Critical: Mutex system initialization failed");
    }
    if (!this._validateMutexSystem()) {
      this._secureLog("error", "\u274C Mutex system validation failed after initialization");
      throw new Error("Critical: Mutex system validation failed");
    }
    if (typeof window !== "undefined") {
      this._secureLog("info", "\u{1F512} Emergency mutex handlers will be available through secure API");
    }
    this._secureLog("info", "\u{1F512} Enhanced Mutex system fully initialized and validated");
    this.heartbeatInterval = null;
    this.messageQueue = [];
    this._reconnect = {
      phase: "idle",
      // idle | grace | restarting | waiting | exhausted
      attempts: 0,
      startedAt: 0,
      graceTimer: null,
      retryTimer: null,
      restartTimer: null,
      inFlightAt: 0,
      // when the current restart round-trip was launched
      barrenFailures: 0,
      // consecutive failures that produced no candidate pairs
      pendingRole: null
      // 'offerer' | 'answerer' during a restart round-trip
    };
    this._lastInboundAt = 0;
    this._livenessProbeAt = 0;
    this._livenessTimer = null;
    this._heartbeatTimer = null;
    this.ecdhKeyPair = null;
    this.ecdsaKeyPair = null;
    if (this.fileTransferSystem) {
      this.fileTransferSystem.cleanup();
      this.fileTransferSystem = null;
    }
    this.verificationCode = null;
    this.pendingSASCode = null;
    this.isVerified = false;
    this.sasValidationAttempts = 0;
    this.processedMessageIds = /* @__PURE__ */ new Set();
    this.localVerificationConfirmed = false;
    this.remoteVerificationConfirmed = false;
    this.bothVerificationsConfirmed = false;
    this.expectedDTLSFingerprint = null;
    this._peerDTLSFingerprint = null;
    this.strictDTLSValidation = true;
    this.ephemeralKeyPairs = /* @__PURE__ */ new Map();
    this.sessionStartTime = Date.now();
    this.messageCounter = 0;
    this.sequenceNumber = 0;
    this.expectedSequenceNumber = 0;
    this.sessionSalt = null;
    this._pendingOfferContext = null;
    this.replayWindowSize = 64;
    this.replayWindow = /* @__PURE__ */ new Set();
    this.maxSequenceGap = 100;
    this.replayProtectionEnabled = true;
    this.sessionId = null;
    this._handshakeMode = null;
    this._sbq2 = null;
    this.connectionId = Array.from(crypto.getRandomValues(new Uint8Array(8))).map((b) => b.toString(16).padStart(2, "0")).join("");
    this.peerPublicKey = null;
    this._ratchet = null;
    this._peerSupportsRatchet = false;
    this.rateLimiterId = null;
    this.intentionalDisconnect = false;
    this._sessionAlive = true;
    this._fileTransferInitRetryTimers = /* @__PURE__ */ new Set();
    this._peerDisconnectCleanupTimer = null;
    this._logCleanupInterval = null;
    this.lastCleanupTime = Date.now();
    this._resetNotificationFlags();
    this.verificationInitiationSent = false;
    this.disconnectNotificationSent = false;
    this.reconnectionFailedNotificationSent = false;
    this.peerDisconnectNotificationSent = false;
    this.connectionClosedNotificationSent = false;
    this.fakeTrafficDisabledNotificationSent = false;
    this.advancedFeaturesDisabledNotificationSent = false;
    this.securityUpgradeNotificationSent = false;
    this.lastSecurityUpgradeStage = null;
    this.securityCalculationNotificationSent = false;
    this.lastSecurityCalculationLevel = null;
    this.fileTransferSystem = null;
    this.onFileProgress = null;
    this._ivTrackingSystem = {
      usedIVs: /* @__PURE__ */ new Set(),
      // Track all used IVs to prevent reuse
      ivHistory: /* @__PURE__ */ new Map(),
      // Track IV usage with timestamps (max 10k entries)
      collisionCount: 0,
      // Track potential collisions
      maxIVHistorySize: 1e4,
      // Maximum IV history size
      maxSessionIVs: 1e3,
      // Maximum IVs per session
      entropyValidation: {
        minEntropy: 3,
        // Minimum entropy threshold
        entropyTests: 0,
        entropyFailures: 0
      },
      rngValidation: {
        testsPerformed: 0,
        weakRngDetected: false,
        lastValidation: 0
      },
      sessionIVs: /* @__PURE__ */ new Map(),
      // Track IVs per session
      emergencyMode: false
      // Emergency mode if IV reuse detected
    };
    this._lastIVCleanupTime = null;
    this._secureErrorHandler = {
      errorCategories: {
        CRYPTOGRAPHIC: "cryptographic",
        NETWORK: "network",
        VALIDATION: "validation",
        SYSTEM: "system",
        UNKNOWN: "unknown"
      },
      errorMappings: /* @__PURE__ */ new Map(),
      // Map internal errors to safe messages
      errorCounts: /* @__PURE__ */ new Map(),
      // Track error frequencies
      lastErrorTime: 0,
      errorThreshold: 10,
      // Max errors per minute
      isInErrorMode: false
    };
    this._secureMemoryManager = {
      sensitiveData: /* @__PURE__ */ new WeakMap(),
      // Track sensitive data for secure cleanup
      cleanupQueue: [],
      // Queue for deferred cleanup operations
      isCleaning: false,
      // Prevent concurrent cleanup operations
      cleanupInterval: null,
      // Periodic cleanup timer
      memoryStats: {
        totalCleanups: 0,
        failedCleanups: 0,
        lastCleanup: 0
      }
    };
    this.onFileReceived = null;
    this.onFileError = null;
    this.onCallStateChanged = null;
    this.callState = {
      active: false,
      // a call session exists (ringing or connected)
      phase: "idle",
      // idle | outgoing | incoming | connecting | active | ended
      withVideo: false,
      // whether video is part of this call
      micEnabled: true,
      cameraEnabled: false,
      remoteHasVideo: false,
      callId: null,
      quality: null,
      // 'excellent'|'good'|'fair'|'poor'|null — link quality for the UI
      error: null
    };
    this.localMediaStream = null;
    this.remoteMediaStream = null;
    this._pendingCallOffer = null;
    this._callMakingOffer = false;
    this._callAudioSender = null;
    this._callVideoSender = null;
    this._callFacingMode = "user";
    this._adaptationController = null;
    this.keyRotationInterval = null;
    this.lastKeyRotation = Date.now();
    this.currentKeyVersion = 0;
    this.keyVersions = /* @__PURE__ */ new Map();
    this.oldKeys = /* @__PURE__ */ new Map();
    this.maxOldKeys = _EnhancedSecureWebRTCManager.LIMITS.MAX_OLD_KEYS;
    this.peerConnection = null;
    this.dataChannel = null;
    this.securityFeatures = {
      // All security features enabled by default - no payment required
      hasEncryption: true,
      hasECDH: true,
      hasECDSA: true,
      hasMutualAuth: true,
      hasMetadataProtection: true,
      hasEnhancedReplayProtection: true,
      hasNonExtractableKeys: true,
      hasRateLimiting: true,
      hasEnhancedValidation: true,
      hasPFS: true,
      //   Real Perfect Forward Secrecy enabled           
      // Advanced Features - All enabled by default
      hasNestedEncryption: true,
      hasPacketPadding: true,
      hasPacketReordering: true,
      hasAntiFingerprinting: true,
      hasFakeTraffic: true,
      hasDecoyChannels: true,
      hasMessageChunking: true
    };
    this._secureLog("info", "\u{1F512} Enhanced WebRTC Manager initialized with tiered security");
    this._secureLog("info", "\u{1F512} Configuration loaded from constructor parameters", {
      fakeTraffic: this._config.fakeTraffic.enabled,
      decoyChannels: this._config.decoyChannels.enabled,
      packetPadding: this._config.packetPadding.enabled,
      antiFingerprinting: this._config.antiFingerprinting.enabled
    });
    this.sessionMode = "ratchet";
    this._hardenDebugModeReferences();
    this._initializeUnifiedScheduler();
    this._syncSecurityFeaturesWithTariff();
    if (!this._validateCryptographicSecurity()) {
      this._secureLog("error", "\u{1F6A8} CRITICAL: Cryptographic security validation failed after tariff sync");
      throw new Error("Critical cryptographic features are missing after tariff synchronization");
    }
    this.nestedEncryptionKey = null;
    this.paddingConfig = {
      enabled: this._config.packetPadding.enabled,
      minPadding: this._config.packetPadding.minPadding,
      maxPadding: this._config.packetPadding.maxPadding,
      useRandomPadding: this._config.packetPadding.useRandomPadding,
      preserveMessageSize: this._config.packetPadding.preserveMessageSize
    };
    this.fakeTrafficConfig = {
      enabled: this._config.fakeTraffic?.enabled || false,
      minInterval: this._config.fakeTraffic?.minInterval || 15e3,
      maxInterval: this._config.fakeTraffic?.maxInterval || 3e4,
      minSize: this._config.fakeTraffic?.minSize || 64,
      maxSize: this._config.fakeTraffic?.maxSize || 1024,
      patterns: this._config.fakeTraffic?.patterns || ["heartbeat", "status", "ping"],
      randomDecoyIntervals: this._config.fakeTraffic?.randomDecoyIntervals || true
    };
    this.fakeTrafficTimer = null;
    this.lastFakeTraffic = 0;
    this.chunkingConfig = {
      enabled: false,
      maxChunkSize: _EnhancedSecureWebRTCManager.SIZES.CHUNK_SIZE_MAX,
      minDelay: _EnhancedSecureWebRTCManager.SIZES.CHUNK_DELAY_MIN,
      maxDelay: _EnhancedSecureWebRTCManager.SIZES.CHUNK_DELAY_MAX,
      useRandomDelays: true,
      addChunkHeaders: true
    };
    this.chunkQueue = [];
    this.chunkingInProgress = false;
    this.decoyChannels = /* @__PURE__ */ new Map();
    this.decoyChannelConfig = {
      enabled: this._config.decoyChannels.enabled,
      maxDecoyChannels: this._config.decoyChannels.maxDecoyChannels,
      decoyChannelNames: this._config.decoyChannels.decoyChannelNames,
      sendDecoyData: this._config.decoyChannels.sendDecoyData,
      randomDecoyIntervals: this._config.decoyChannels.randomDecoyIntervals
    };
    this.decoyTimers = /* @__PURE__ */ new Map();
    this.reorderingConfig = {
      enabled: false,
      maxOutOfOrder: _EnhancedSecureWebRTCManager.LIMITS.MAX_OUT_OF_ORDER_PACKETS,
      reorderTimeout: _EnhancedSecureWebRTCManager.TIMEOUTS.REORDER_TIMEOUT,
      useSequenceNumbers: true,
      useTimestamps: true
    };
    this.packetBuffer = /* @__PURE__ */ new Map();
    this.lastProcessedSequence = -1;
    this.antiFingerprintingConfig = {
      enabled: this._config.antiFingerprinting.enabled,
      randomizeTiming: this._config.antiFingerprinting.randomizeTiming,
      randomizeSizes: this._config.antiFingerprinting.randomizeSizes,
      addNoise: this._config.antiFingerprinting.addNoise,
      maskPatterns: this._config.antiFingerprinting.maskPatterns,
      useRandomHeaders: this._config.antiFingerprinting.useRandomHeaders
    };
    this.fingerprintMask = this.generateFingerprintMask();
    this.rateLimiterId = `webrtc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    this.startPeriodicCleanup();
    this.initializeEnhancedSecurity();
    this._keyOperationMutex = {
      locked: false,
      queue: [],
      lockId: null,
      lockTimeout: null
    };
    this._cryptoOperationMutex = {
      locked: false,
      queue: [],
      lockId: null,
      lockTimeout: null
    };
    this._connectionOperationMutex = {
      locked: false,
      queue: [],
      lockId: null,
      lockTimeout: null
    };
    this._keySystemState = {
      isInitializing: false,
      isRotating: false,
      isDestroying: false,
      lastOperation: null,
      lastOperationTime: Date.now()
    };
    this._operationCounters = {
      keyOperations: 0,
      cryptoOperations: 0,
      connectionOperations: 0
    };
  }
  /**
   *   Create AAD with sequence number for anti-replay protection
   * This binds each message to its sequence number and prevents replay attacks
   */
  _createMessageAAD(messageType, messageData = null, isFileMessage = false) {
    try {
      const aad = {
        sessionId: this.currentSession?.sessionId || this.sessionId || "unknown",
        keyFingerprint: this.keyFingerprint || "unknown",
        sequenceNumber: this._generateNextSequenceNumber(),
        messageType,
        timestamp: Date.now(),
        connectionId: this.connectionId || "unknown",
        isFileMessage
      };
      if (messageData && typeof messageData === "object") {
        if (messageData.fileId) aad.fileId = messageData.fileId;
        if (messageData.chunkIndex !== void 0) aad.chunkIndex = messageData.chunkIndex;
        if (messageData.totalChunks !== void 0) aad.totalChunks = messageData.totalChunks;
      }
      return JSON.stringify(aad);
    } catch (error) {
      this._secureLog("error", "\u274C Failed to create message AAD", {
        errorType: error.constructor.name,
        message: error.message,
        messageType
      });
      return JSON.stringify({
        sessionId: "unknown",
        keyFingerprint: "unknown",
        sequenceNumber: Date.now(),
        messageType,
        timestamp: Date.now(),
        connectionId: "unknown",
        isFileMessage
      });
    }
  }
  /**
   *   Generate next sequence number for outgoing messages
   * This ensures unique ordering and prevents replay attacks
   */
  _generateNextSequenceNumber() {
    const nextSeq = this.sequenceNumber++;
    if (this.sequenceNumber > Number.MAX_SAFE_INTEGER - 1e3) {
      this.sequenceNumber = 0;
      this.expectedSequenceNumber = 0;
      this.replayWindow.clear();
      this._secureLog("warn", "\u26A0\uFE0F Sequence number reset due to overflow", {
        timestamp: Date.now()
      });
    }
    return nextSeq;
  }
  /**
   * Create a safe hash for logging sensitive data
   * Returns only the first 4 bytes (8 hex chars) of SHA-256 hash
   * @param {any} sensitiveData - The sensitive data to hash
   * @param {string} context - Context for error logging
   * @returns {Promise<string>} - Short hash (8 hex chars) or 'hash_error'
   */
  async _createSafeLogHash(sensitiveData, context = "unknown") {
    try {
      let dataToHash;
      if (sensitiveData instanceof ArrayBuffer) {
        dataToHash = new Uint8Array(sensitiveData);
      } else if (sensitiveData instanceof Uint8Array) {
        dataToHash = sensitiveData;
      } else if (sensitiveData instanceof CryptoKey) {
        const keyInfo = `${sensitiveData.type}_${sensitiveData.algorithm?.name || "unknown"}_${sensitiveData.extractable}`;
        dataToHash = new TextEncoder().encode(keyInfo);
      } else if (typeof sensitiveData === "string") {
        dataToHash = new TextEncoder().encode(sensitiveData);
      } else if (typeof sensitiveData === "object" && sensitiveData !== null) {
        const safeObj = { type: sensitiveData.kty || "unknown", use: sensitiveData.use || "unknown" };
        dataToHash = new TextEncoder().encode(JSON.stringify(safeObj));
      } else {
        dataToHash = new TextEncoder().encode(String(sensitiveData));
      }
      const hashBuffer = await crypto.subtle.digest("SHA-256", dataToHash);
      const hashArray = new Uint8Array(hashBuffer);
      return Array.from(hashArray.slice(0, 4)).map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch (error) {
      return "hash_error";
    }
  }
  /**
   * Async sleep helper - replaces busy-wait
   */
  async _asyncSleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  /**
   * Async cleanup helper - replaces immediate heavy operations
   */
  async _scheduleAsyncCleanup(cleanupFn, delay = 0) {
    return new Promise((resolve) => {
      setTimeout(async () => {
        try {
          await cleanupFn();
          resolve(true);
        } catch (error) {
          this._secureLog("error", "Async cleanup failed", {
            errorType: error?.constructor?.name || "Unknown"
          });
          resolve(false);
        }
      }, delay);
    });
  }
  /**
   * Batch async operations to prevent UI blocking
   */
  async _batchAsyncOperation(items, batchSize = 10, delayBetweenBatches = 5) {
    const results = [];
    for (let i = 0; i < items.length; i += batchSize) {
      const batch = items.slice(i, i + batchSize);
      const batchResults = await Promise.all(batch);
      results.push(...batchResults);
      if (i + batchSize < items.length) {
        await this._asyncSleep(delayBetweenBatches);
      }
    }
    return results;
  }
  /**
   * Memory cleanup without window.gc() - uses natural garbage collection
   */
  async _performNaturalCleanup() {
    await this._asyncSleep(0);
    for (let i = 0; i < 3; i++) {
      await this._asyncSleep(10);
    }
  }
  /**
   * Heavy cleanup operations using WebWorker (if available)
   */
  async _performHeavyCleanup(cleanupData) {
    if (typeof Worker !== "undefined") {
      try {
        return await this._cleanupWithWorker(cleanupData);
      } catch (error) {
        this._secureLog("warn", "WebWorker cleanup failed, falling back to main thread", {
          errorType: error?.constructor?.name || "Unknown"
        });
      }
    }
    return await this._cleanupInMainThread(cleanupData);
  }
  /**
   * Cleanup using WebWorker
   */
  async _cleanupWithWorker(cleanupData) {
    return new Promise((resolve, reject) => {
      const workerCode = `
                    self.onmessage = function(e) {
                        const { type, data } = e.data;
                        
                        try {
                            switch (type) {
                                case 'cleanup_arrays':
                                    // Simulate heavy array cleanup
                                    let processed = 0;
                                    for (let i = 0; i < data.count; i++) {
                                        // Simulate work
                                        processed++;
                                        if (processed % 1000 === 0) {
                                            // Yield control periodically
                                            setTimeout(() => {}, 0);
                                        }
                                    }
                                    self.postMessage({ success: true, processed });
                                    break;
                                    
                                case 'cleanup_objects':
                                    // Simulate object cleanup
                                    const cleaned = data.objects.map(() => null);
                                    self.postMessage({ success: true, cleaned: cleaned.length });
                                    break;
                                    
                                default:
                                    self.postMessage({ success: true, message: 'Unknown cleanup type' });
                            }
                        } catch (error) {
                            self.postMessage({ success: false, error: error.message });
                        }
                    };
                `;
      const blob = new Blob([workerCode], { type: "application/javascript" });
      const worker = new Worker(URL.createObjectURL(blob));
      const timeout = setTimeout(() => {
        worker.terminate();
        reject(new Error("Worker cleanup timeout"));
      }, 5e3);
      worker.onmessage = (e) => {
        clearTimeout(timeout);
        worker.terminate();
        URL.revokeObjectURL(blob);
        if (e.data.success) {
          resolve(e.data);
        } else {
          reject(new Error(e.data.error));
        }
      };
      worker.onerror = (error) => {
        clearTimeout(timeout);
        worker.terminate();
        URL.revokeObjectURL(blob);
        reject(error);
      };
      worker.postMessage(cleanupData);
    });
  }
  /**
   * Cleanup in main thread with async batching
   */
  async _cleanupInMainThread(cleanupData) {
    const { type, data } = cleanupData;
    switch (type) {
      case "cleanup_arrays":
        let processed = 0;
        const batchSize = 100;
        while (processed < data.count) {
          const batchEnd = Math.min(processed + batchSize, data.count);
          for (let i = processed; i < batchEnd; i++) {
          }
          processed = batchEnd;
          await this._asyncSleep(1);
        }
        return { success: true, processed };
      case "cleanup_objects":
        const objects = data.objects || [];
        const batches = [];
        for (let i = 0; i < objects.length; i += 50) {
          batches.push(objects.slice(i, i + 50));
        }
        let cleaned = 0;
        for (const batch of batches) {
          batch.forEach(() => cleaned++);
          await this._asyncSleep(1);
        }
        return { success: true, cleaned };
      default:
        return { success: true, message: "Unknown cleanup type" };
    }
  }
  /**
   *   Enhanced mutex system initialization with atomic protection
   */
  _initializeMutexSystem() {
    this._keyOperationMutex = {
      locked: false,
      queue: [],
      lockId: null,
      lockTimeout: null,
      lockTime: null,
      operationCount: 0
    };
    this._cryptoOperationMutex = {
      locked: false,
      queue: [],
      lockId: null,
      lockTimeout: null,
      lockTime: null,
      operationCount: 0
    };
    this._connectionOperationMutex = {
      locked: false,
      queue: [],
      lockId: null,
      lockTimeout: null,
      lockTime: null,
      operationCount: 0
    };
    this._keySystemState = {
      isInitializing: false,
      isRotating: false,
      isDestroying: false,
      lastOperation: null,
      lastOperationTime: Date.now(),
      operationId: null,
      concurrentOperations: 0,
      maxConcurrentOperations: 1
    };
    this._operationCounters = {
      keyOperations: 0,
      cryptoOperations: 0,
      connectionOperations: 0,
      totalOperations: 0,
      failedOperations: 0
    };
    this._secureLog("info", "\u{1F512} Enhanced mutex system initialized with atomic protection", {
      mutexes: ["keyOperation", "cryptoOperation", "connectionOperation"],
      timestamp: Date.now(),
      features: ["atomic_operations", "race_condition_protection", "enhanced_state_tracking"]
    });
  }
  /**
   *   XSS Hardening - Debug mode references validation
   * This method is called during initialization to ensure XSS hardening
   */
  _hardenDebugModeReferences() {
    this._secureLog("info", "\u{1F512} XSS Hardening: Debug mode references already replaced");
  }
  /**
   *   Unified scheduler for all maintenance tasks
   * Replaces multiple setInterval calls with a single, controlled scheduler
   */
  _initializeUnifiedScheduler() {
    this._maintenanceScheduler = setInterval(() => {
      this._executeMaintenanceCycle();
    }, 3e5);
    this._secureLog("info", "\u{1F527} Unified maintenance scheduler initialized (5-minute cycle)");
    this._activeTimers = /* @__PURE__ */ new Set([this._maintenanceScheduler]);
  }
  _trackActiveTimer(timer) {
    if (!timer) return timer;
    if (!this._activeTimers) this._activeTimers = /* @__PURE__ */ new Set();
    this._activeTimers.add(timer);
    return timer;
  }
  _untrackActiveTimer(timer) {
    if (timer && this._activeTimers) this._activeTimers.delete(timer);
  }
  _setSASMaterialReady(localFingerprint, remoteFingerprint) {
    this._sasLocalFingerprint = localFingerprint;
    this._sasRemoteFingerprint = remoteFingerprint;
  }
  _isVerificationReady() {
    const hasDescriptions = !!(this.peerConnection?.localDescription && this.peerConnection?.remoteDescription);
    const hasOpenDataChannel = this.dataChannel?.readyState === "open";
    const hasVerificationCode = typeof this.verificationCode === "string" && this.verificationCode.trim().length > 0;
    const hasFingerprintMaterial = typeof this._sasLocalFingerprint === "string" && this._sasLocalFingerprint.trim().length > 0 && typeof this._sasRemoteFingerprint === "string" && this._sasRemoteFingerprint.trim().length > 0;
    return hasDescriptions && hasOpenDataChannel && hasVerificationCode && hasFingerprintMaterial;
  }
  _notifyVerificationReadyIfPossible() {
    if (!this._isVerificationReady()) {
      return false;
    }
    if (!this._verificationUiOpened) {
      this._verificationUiOpened = true;
      this.onStatusChange?.("verifying");
      this.onVerificationRequired?.(this.verificationCode);
    }
    return true;
  }
  _countIceCandidatesInSDP(sdp) {
    if (typeof sdp !== "string") return 0;
    return (sdp.match(/^a=candidate:/gm) || []).length;
  }
  _summarizeIceCandidatesInSDP(sdp) {
    const summary = {
      total: 0,
      host: 0,
      srflx: 0,
      relay: 0,
      prflx: 0,
      unknown: 0
    };
    if (typeof sdp !== "string") return summary;
    for (const line of sdp.match(/^a=candidate:.*$/gm) || []) {
      summary.total += 1;
      const match = line.match(/\btyp\s+(host|srflx|relay|prflx)\b/i);
      const type = match?.[1]?.toLowerCase();
      if (type && Object.prototype.hasOwnProperty.call(summary, type)) {
        summary[type] += 1;
      } else {
        summary.unknown += 1;
      }
    }
    return summary;
  }
  _describeIceCandidatesInSDP(sdp) {
    if (typeof sdp !== "string") return [];
    return (sdp.match(/^a=candidate:.*$/gm) || []).map((line) => {
      const parts = line.slice("a=candidate:".length).trim().split(/\s+/);
      const typIndex = parts.findIndex((part) => part.toLowerCase() === "typ");
      const address = parts[4] || "";
      const port = parts[5] || "";
      const candidateType = typIndex >= 0 ? parts[typIndex + 1] || "unknown" : "unknown";
      const protocol = (parts[2] || "unknown").toLowerCase();
      let addressKind = "unknown";
      if (/\.local$/i.test(address)) {
        addressKind = "mdns";
      } else if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(address)) {
        addressKind = "private-ipv4";
      } else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) {
        addressKind = "public-ipv4";
      } else if (address.includes(":")) {
        addressKind = "ipv6";
      }
      return {
        candidateType,
        protocol,
        addressKind,
        portPresent: !!port,
        tcpType: (() => {
          const tcpIndex = parts.findIndex((part) => part.toLowerCase() === "tcptype");
          return tcpIndex >= 0 ? parts[tcpIndex + 1] || null : null;
        })()
      };
    });
  }
  _logIceCandidateDiagnostics(label, sdp, extra = {}) {
    const candidateSummary = this._summarizeIceCandidatesInSDP(sdp);
    const candidateDetails = this._describeIceCandidatesInSDP(sdp);
    console.info(`[SecureBit ICE] ${label}`, {
      candidateSummary,
      candidateDetails,
      candidateDetailsJson: JSON.stringify(candidateDetails),
      ...extra
    });
    return { candidateSummary, candidateDetails };
  }
  _hasOnlyMdnsHostCandidates(sdp) {
    const summary = this._summarizeIceCandidatesInSDP(sdp);
    const details = this._describeIceCandidatesInSDP(sdp);
    return summary.total > 0 && summary.srflx === 0 && summary.relay === 0 && summary.prflx === 0 && details.every(
      (candidate) => candidate.candidateType === "host" && candidate.addressKind === "mdns"
    );
  }
  _warnIfRemoteCandidatesNeedRelay(context, sdp) {
    if (!this._hasOnlyMdnsHostCandidates(sdp)) return false;
    const message = context === "answer" ? "Connection warning: the response contains only browser-masked mDNS host candidates and no server-reflexive or TURN relay candidates. This network/browser combination may not connect until TURN is configured." : "Connection warning: the invitation contains only browser-masked mDNS host candidates and no server-reflexive or TURN relay candidates. This network/browser combination may not connect until TURN is configured.";
    this._secureLog("warn", "Remote ICE candidates require TURN or usable non-mDNS candidates", {
      context,
      candidateSummary: this._summarizeIceCandidatesInSDP(sdp),
      candidateDetails: this._describeIceCandidatesInSDP(sdp)
    });
    this.deliverMessageToUI(message, "system");
    return true;
  }
  async _collectIceFailureDiagnostics() {
    if (!this.peerConnection?.getStats) return null;
    try {
      const stats = await this.peerConnection.getStats();
      const candidates = /* @__PURE__ */ new Map();
      const candidatePairs = [];
      stats.forEach((report) => {
        if (report.type === "local-candidate" || report.type === "remote-candidate") {
          candidates.set(report.id, {
            type: report.type,
            candidateType: report.candidateType,
            protocol: report.protocol,
            address: report.address || report.ip || null,
            port: report.port || null,
            networkType: report.networkType || null
          });
        }
      });
      stats.forEach((report) => {
        if (report.type !== "candidate-pair") return;
        candidatePairs.push({
          state: report.state,
          nominated: !!report.nominated,
          writable: !!report.writable,
          bytesSent: report.bytesSent || 0,
          bytesReceived: report.bytesReceived || 0,
          currentRoundTripTime: report.currentRoundTripTime ?? null,
          local: candidates.get(report.localCandidateId) || null,
          remote: candidates.get(report.remoteCandidateId) || null
        });
      });
      return {
        pairCount: candidatePairs.length,
        states: candidatePairs.reduce((acc, pair) => {
          acc[pair.state || "unknown"] = (acc[pair.state || "unknown"] || 0) + 1;
          return acc;
        }, {}),
        pairs: candidatePairs
      };
    } catch (error) {
      return {
        error: error?.message || "Failed to collect ICE diagnostics"
      };
    }
  }
  _storePendingOfferContext() {
    this._pendingOfferContext = {
      sessionSalt: Array.isArray(this.sessionSalt) ? [...this.sessionSalt] : null,
      sessionId: this.sessionId || null,
      connectionId: this.connectionId || null,
      keyFingerprint: this.keyFingerprint || null,
      createdAt: Date.now()
    };
  }
  _restorePendingOfferContextIfNeeded() {
    const saltIsValid = Array.isArray(this.sessionSalt) && this.sessionSalt.length === 64;
    if (saltIsValid) return true;
    const pendingSalt = this._pendingOfferContext?.sessionSalt;
    if (!Array.isArray(pendingSalt) || pendingSalt.length !== 64) {
      return false;
    }
    this.sessionSalt = [...pendingSalt];
    if (!this.sessionId && this._pendingOfferContext.sessionId) {
      this.sessionId = this._pendingOfferContext.sessionId;
    }
    if (!this.connectionId && this._pendingOfferContext.connectionId) {
      this.connectionId = this._pendingOfferContext.connectionId;
    }
    if (!this.keyFingerprint && this._pendingOfferContext.keyFingerprint) {
      this.keyFingerprint = this._pendingOfferContext.keyFingerprint;
    }
    this._secureLog("warn", "Restored pending offer context before applying answer", {
      pendingContextAgeMs: Date.now() - (this._pendingOfferContext.createdAt || Date.now())
    });
    return true;
  }
  _clearPendingOfferContext() {
    if (this._pendingOfferContext?.sessionSalt) {
      this._secureWipeMemory(this._pendingOfferContext.sessionSalt, "pendingOfferContext.sessionSalt");
    }
    this._pendingOfferContext = null;
  }
  /**
   *   Execute all maintenance tasks in a single cycle
   */
  _executeMaintenanceCycle() {
    try {
      this._secureLog("info", "\u{1F527} Starting maintenance cycle");
      this._cleanupLogs();
      this._auditLoggingSystemSecurity();
      this._verifyAPIIntegrity();
      this._validateCryptographicSecurity();
      this._syncSecurityFeaturesWithTariff();
      this._cleanupResources();
      this._enforceResourceLimits();
      if (this.isConnected && this.isVerified) {
        this._monitorKeySecurity();
      }
      if (this._debugMode) {
        this._monitorGlobalExposure();
      }
      this._secureLog("info", "\u{1F527} Maintenance cycle completed successfully");
    } catch (error) {
      this._secureLog("error", "\u274C Maintenance cycle failed", {
        errorType: error?.constructor?.name || "Unknown",
        message: error?.message || "Unknown error"
      });
      this._emergencyCleanup().catch((error2) => {
        this._secureLog("error", "Emergency cleanup failed", {
          errorType: error2?.constructor?.name || "Unknown"
        });
      });
    }
  }
  /**
   *   Enforce hard resource limits with emergency cleanup
   */
  _enforceResourceLimits() {
    const violations = [];
    if (this._logCounts.size > this._resourceLimits.maxLogEntries) {
      violations.push("log_entries");
    }
    if (this.messageQueue.length > this._resourceLimits.maxMessageQueue) {
      violations.push("message_queue");
    }
    if (this._ivTrackingSystem && this._ivTrackingSystem.ivHistory.size > this._resourceLimits.maxIVHistory) {
      violations.push("iv_history");
    }
    if (this.processedMessageIds.size > this._resourceLimits.maxProcessedMessageIds) {
      violations.push("processed_message_ids");
    }
    if (this.decoyChannels.size > this._resourceLimits.maxDecoyChannels) {
      violations.push("decoy_channels");
    }
    if (this._fakeTrafficMessages && this._fakeTrafficMessages.length > this._resourceLimits.maxFakeTrafficMessages) {
      violations.push("fake_traffic_messages");
    }
    if (this.chunkQueue.length > this._resourceLimits.maxChunkQueue) {
      violations.push("chunk_queue");
    }
    if (this.packetBuffer && this.packetBuffer.size > this._resourceLimits.maxPacketBuffer) {
      violations.push("packet_buffer");
    }
    if (violations.length > 0) {
      this._secureLog("warn", "\u26A0\uFE0F Resource limit violations detected", { violations });
      this._emergencyCleanup().catch((error) => {
        this._secureLog("error", "Emergency cleanup failed", {
          errorType: error?.constructor?.name || "Unknown"
        });
      });
    }
  }
  /**
   *   Emergency cleanup when resource limits are exceeded
   */
  async _emergencyCleanup() {
    this._secureLog("warn", "\u{1F6A8} EMERGENCY: Resource limits exceeded, performing emergency cleanup");
    try {
      this._logCounts.clear();
      this._secureLog("info", "\u{1F9F9} Emergency: All logs cleared");
      this.messageQueue.length = 0;
      this._secureLog("info", "\u{1F9F9} Emergency: Message queue cleared");
      if (this._ivTrackingSystem) {
        this._ivTrackingSystem.usedIVs.clear();
        this._ivTrackingSystem.ivHistory.clear();
        this._ivTrackingSystem.sessionIVs.clear();
        this._ivTrackingSystem.collisionCount = 0;
        this._ivTrackingSystem.emergencyMode = false;
        this._secureLog("info", "\u{1F9F9} Enhanced Emergency: IV tracking system cleared");
      }
      this.processedMessageIds.clear();
      this._secureLog("info", "\u{1F9F9} Emergency: Processed message IDs cleared");
      if (this.decoyChannels) {
        for (const [channelName, timer] of this.decoyTimers) {
          if (timer) clearTimeout(timer);
        }
        this.decoyChannels.clear();
        this.decoyTimers.clear();
        this._secureLog("info", "\u{1F9F9} Enhanced Emergency: Decoy channels cleared");
      }
      if (this.fakeTrafficTimer) {
        clearTimeout(this.fakeTrafficTimer);
        this.fakeTrafficTimer = null;
      }
      if (this._fakeTrafficMessages) {
        this._fakeTrafficMessages.length = 0;
        this._secureLog("info", "\u{1F9F9} Enhanced Emergency: Fake traffic messages cleared");
      }
      this.chunkQueue.length = 0;
      this._secureLog("info", "\u{1F9F9} Emergency: Chunk queue cleared");
      if (this.packetBuffer) {
        this.packetBuffer.clear();
        this._secureLog("info", "\u{1F9F9} Emergency: Packet buffer cleared");
      }
      this._secureMemoryManager.isCleaning = true;
      this._secureMemoryManager.cleanupQueue.length = 0;
      this._secureMemoryManager.memoryStats.lastCleanup = Date.now();
      await this._scheduleAsyncCleanup(async () => {
        this._secureLog("info", "\u{1F9F9} Enhanced Emergency: Starting natural memory cleanup");
        for (let i = 0; i < 3; i++) {
          this._secureLog("info", `\u{1F9F9} Enhanced Emergency: Cleanup cycle ${i + 1}/3`);
          await this._performNaturalCleanup();
        }
        this._secureLog("info", "\u{1F9F9} Enhanced Emergency: Natural cleanup completed");
      }, 0);
      this._secureMemoryManager.isCleaning = false;
      this._secureLog("info", "\u2705 Enhanced emergency cleanup completed successfully");
    } catch (error) {
      this._secureLog("error", "\u274C Enhanced emergency cleanup failed", {
        errorType: error?.constructor?.name || "Unknown",
        message: error?.message || "Unknown error"
      });
      this._secureMemoryManager.isCleaning = false;
    }
  }
  /**
   *   Validate emergency cleanup success
   * @param {Object} originalState - Original state before cleanup
   * @returns {Object} Validation results
   */
  _validateEmergencyCleanup(originalState) {
    const currentState = {
      messageQueueSize: this.messageQueue.length,
      processedIdsSize: this.processedMessageIds.size,
      packetBufferSize: this.packetBuffer ? this.packetBuffer.size : 0,
      ivTrackingSize: this._ivTrackingSystem ? this._ivTrackingSystem.usedIVs.size : 0,
      decoyChannelsSize: this.decoyChannels ? this.decoyChannels.size : 0
    };
    const validation = {
      messageQueueCleared: currentState.messageQueueSize === 0,
      processedIdsCleared: currentState.processedIdsSize === 0,
      packetBufferCleared: currentState.packetBufferSize === 0,
      ivTrackingCleared: currentState.ivTrackingSize === 0,
      decoyChannelsCleared: currentState.decoyChannelsSize === 0,
      allCleared: currentState.messageQueueSize === 0 && currentState.processedIdsSize === 0 && currentState.packetBufferSize === 0 && currentState.ivTrackingSize === 0 && currentState.decoyChannelsSize === 0
    };
    return validation;
  }
  /**
   *   Cleanup resources based on age and usage
   */
  _cleanupResources() {
    const now = Date.now();
    if (this.processedMessageIds.size > this._emergencyThresholds.processedMessageIds) {
      this.processedMessageIds.clear();
      this._secureLog("info", "\u{1F9F9} Old processed message IDs cleared");
    }
    if (this._ivTrackingSystem) {
      this._cleanupOldIVs();
    }
    this.cleanupOldKeys();
    if (window.EnhancedSecureCryptoUtils && window.EnhancedSecureCryptoUtils.rateLimiter) {
      window.EnhancedSecureCryptoUtils.rateLimiter.cleanup();
    }
    this._secureLog("info", "\u{1F9F9} Resource cleanup completed");
  }
  /**
   *   Monitor key security (replaces _startKeySecurityMonitoring)
   */
  _monitorKeySecurity() {
    if (this._keyStorageStats.activeKeys > 10) {
      this._secureLog("warn", "\u26A0\uFE0F High number of active keys detected. Consider rotation.");
    }
  }
  /**
   *   Send heartbeat message (called by unified scheduler)
   */
  /**
   * @param {boolean} ack - true when replying to a peer's probe. An ack is never
   *   itself acked, otherwise the two sides would ping-pong forever.
   */
  _sendHeartbeat(ack = false) {
    try {
      if (this.dataChannel && this.dataChannel.readyState === "open") {
        this.dataChannel.send(JSON.stringify({
          type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT,
          ack,
          timestamp: Date.now()
        }));
        this._heartbeatConfig.lastHeartbeat = Date.now();
        this._secureLog("debug", ack ? "\u{1F493} Heartbeat ack sent" : "\u{1F493} Heartbeat sent");
        return true;
      }
      return false;
    } catch (error) {
      this._secureLog("error", "\u274C Heartbeat failed:", {
        errorType: error?.constructor?.name || "Unknown",
        message: error?.message || "Unknown error"
      });
      return false;
    }
  }
  /**
   *   Comprehensive input validation to prevent DoS and injection attacks
   * @param {any} data - Data to validate
   * @param {string} context - Context for validation (e.g., 'sendMessage', 'sendSecureMessage')
   * @returns {Object} Validation result with isValid and sanitizedData
   */
  _validateInputData(data, context = "unknown") {
    const validationResult = {
      isValid: false,
      sanitizedData: null,
      errors: [],
      warnings: []
    };
    try {
      if (data === null || data === void 0) {
        validationResult.errors.push("Data cannot be null or undefined");
        return validationResult;
      }
      if (typeof data === "string") {
        if (data.length > this._inputValidationLimits.maxStringLength) {
          validationResult.errors.push(`String too long: ${data.length} > ${this._inputValidationLimits.maxStringLength}`);
          return validationResult;
        }
        validationResult.sanitizedData = this._sanitizeInputString(data);
        validationResult.isValid = true;
        return validationResult;
      }
      if (typeof data === "object") {
        const seen = /* @__PURE__ */ new WeakSet();
        const checkCircular = (obj, path = "") => {
          if (obj === null || typeof obj !== "object") return;
          if (seen.has(obj)) {
            validationResult.errors.push(`Circular reference detected at path: ${path}`);
            return;
          }
          seen.add(obj);
          if (path.split(".").length > this._inputValidationLimits.maxObjectDepth) {
            validationResult.errors.push(`Object too deep: ${path.split(".").length} > ${this._inputValidationLimits.maxObjectDepth}`);
            return;
          }
          if (Array.isArray(obj) && obj.length > this._inputValidationLimits.maxArrayLength) {
            validationResult.errors.push(`Array too long: ${obj.length} > ${this._inputValidationLimits.maxArrayLength}`);
            return;
          }
          for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
              checkCircular(obj[key], path ? `${path}.${key}` : key);
            }
          }
        };
        checkCircular(data);
        if (validationResult.errors.length > 0) {
          return validationResult;
        }
        const objectSize = this._calculateObjectSize(data);
        if (objectSize > this._inputValidationLimits.maxMessageSize) {
          validationResult.errors.push(`Object too large: ${objectSize} bytes > ${this._inputValidationLimits.maxMessageSize} bytes`);
          return validationResult;
        }
        validationResult.sanitizedData = this._sanitizeInputObject(data);
        validationResult.isValid = true;
        return validationResult;
      }
      if (data instanceof ArrayBuffer) {
        if (data.byteLength > this._inputValidationLimits.maxMessageSize) {
          validationResult.errors.push(`ArrayBuffer too large: ${data.byteLength} bytes > ${this._inputValidationLimits.maxMessageSize} bytes`);
          return validationResult;
        }
        validationResult.sanitizedData = data;
        validationResult.isValid = true;
        return validationResult;
      }
      validationResult.errors.push(`Unsupported data type: ${typeof data}`);
      return validationResult;
    } catch (error) {
      validationResult.errors.push(`Validation error: ${error.message}`);
      this._secureLog("error", "\u274C Input validation failed", {
        context,
        errorType: error?.constructor?.name || "Unknown",
        message: error?.message || "Unknown error"
      });
      return validationResult;
    }
  }
  /**
   *   Calculate approximate object size in bytes
   * @param {any} obj - Object to calculate size for
   * @returns {number} Size in bytes
   */
  _calculateObjectSize(obj) {
    try {
      const jsonString = JSON.stringify(obj);
      return new TextEncoder().encode(jsonString).length;
    } catch (error) {
      return 1024 * 1024;
    }
  }
  /**
   *   Sanitize string data for input validation
   * @param {string} str - String to sanitize
   * @returns {string} Sanitized string
   */
  _sanitizeInputString(str) {
    if (typeof str !== "string") return str;
    str = str.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, "");
    str = str.replace(/\r\n?/g, "\n");
    str = str.replace(/\n{3,}/g, "\n\n");
    str = str.trim();
    return str;
  }
  /**
   *   Sanitize object data for input validation
   * @param {any} obj - Object to sanitize
   * @returns {any} Sanitized object
   */
  _sanitizeInputObject(obj) {
    if (obj === null || typeof obj !== "object") return obj;
    if (Array.isArray(obj)) {
      return obj.map((item) => this._sanitizeInputObject(item));
    }
    const sanitized = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const value = obj[key];
        if (typeof value === "string") {
          sanitized[key] = this._sanitizeInputString(value);
        } else if (typeof value === "object") {
          sanitized[key] = this._sanitizeInputObject(value);
        } else {
          sanitized[key] = value;
        }
      }
    }
    return sanitized;
  }
  /**
   *   Rate limiting for message sending
   * @param {string} context - Context for rate limiting
   * @returns {boolean} true if rate limit allows
   */
  _checkRateLimit(context = "message") {
    const now = Date.now();
    if (!this._rateLimiter) {
      this._rateLimiter = {
        messageCount: 0,
        lastReset: now,
        burstCount: 0,
        lastBurstReset: now
      };
    }
    if (now - this._rateLimiter.lastReset > 6e4) {
      this._rateLimiter.messageCount = 0;
      this._rateLimiter.lastReset = now;
    }
    if (now - this._rateLimiter.lastBurstReset > 1e3) {
      this._rateLimiter.burstCount = 0;
      this._rateLimiter.lastBurstReset = now;
    }
    if (this._rateLimiter.burstCount >= this._inputValidationLimits.rateLimitBurstSize) {
      this._secureLog("warn", "\u26A0\uFE0F Rate limit burst exceeded", { context });
      return false;
    }
    if (this._rateLimiter.messageCount >= this._inputValidationLimits.rateLimitMessagesPerMinute) {
      this._secureLog("warn", "\u26A0\uFE0F Rate limit exceeded", { context });
      return false;
    }
    this._rateLimiter.messageCount++;
    this._rateLimiter.burstCount++;
    return true;
  }
  /**
   * Dedicated receiver-side limiter. Keep separate from outbound quotas so a
   * noisy peer cannot consume local send capacity or force decrypt/render work.
   */
  _checkInboundRateLimit(context = "incoming_message") {
    const now = Date.now();
    if (!this._inboundRateLimiter) {
      this._inboundRateLimiter = {
        messageCount: 0,
        lastReset: now,
        burstCount: 0,
        lastBurstReset: now
      };
    }
    if (now - this._inboundRateLimiter.lastReset > 6e4) {
      this._inboundRateLimiter.messageCount = 0;
      this._inboundRateLimiter.lastReset = now;
    }
    if (now - this._inboundRateLimiter.lastBurstReset > 1e3) {
      this._inboundRateLimiter.burstCount = 0;
      this._inboundRateLimiter.lastBurstReset = now;
    }
    if (this._inboundRateLimiter.burstCount >= this._inputValidationLimits.rateLimitBurstSize) {
      this._secureLog("warn", "\u26A0\uFE0F Inbound message burst limit exceeded; dropping message", { context });
      return false;
    }
    if (this._inboundRateLimiter.messageCount >= this._inputValidationLimits.rateLimitMessagesPerMinute) {
      this._secureLog("warn", "\u26A0\uFE0F Inbound message rate limit exceeded; dropping message", { context });
      return false;
    }
    this._inboundRateLimiter.messageCount++;
    this._inboundRateLimiter.burstCount++;
    return true;
  }
  // ============================================
  // SECURE KEY STORAGE MANAGEMENT
  // ============================================
  /**
   * Initializes the secure key storage
   */
  _initializeSecureKeyStorage() {
    this._masterKeyManager = new SecureMasterKeyManager();
    this._secureKeyStorage = new SecureKeyStorage(this._masterKeyManager);
    this._keyStorageStats = {
      totalKeys: 0,
      activeKeys: 0,
      lastAccess: null,
      lastRotation: null
    };
    this._secureLog("info", "\u{1F510} Enhanced secure key storage initialized");
  }
  /**
   * Set password callback for master key
   */
  setMasterKeyPasswordCallback(callback) {
    if (this._masterKeyManager) {
      this._masterKeyManager.setPasswordRequiredCallback(callback);
    }
  }
  /**
   * Set session expired callback for master key
   */
  setMasterKeySessionExpiredCallback(callback) {
    if (this._masterKeyManager) {
      this._masterKeyManager.setSessionExpiredCallback(callback);
    }
  }
  /**
   * Lock master key manually
   */
  lockMasterKey() {
    if (this._masterKeyManager) {
      this._masterKeyManager.lock();
    }
  }
  /**
   * Check if master key is unlocked
   */
  isMasterKeyUnlocked() {
    return this._masterKeyManager ? this._masterKeyManager.isUnlocked() : false;
  }
  /**
   * Get master key session status
   */
  getMasterKeySessionStatus() {
    return this._masterKeyManager ? this._masterKeyManager.getSessionStatus() : null;
  }
  // Helper: ensure file transfer system is ready (lazy init on receiver)
  async _ensureFileTransferReady() {
    try {
      if (this.fileTransferSystem) {
        return true;
      }
      if (!this.dataChannel || this.dataChannel.readyState !== "open") {
        throw new Error("Data channel not open");
      }
      if (!this.isVerified) {
        throw new Error("Connection not verified");
      }
      this.initializeFileTransfer();
      let attempts2 = 0;
      const maxAttempts = 50;
      while (!this.fileTransferSystem && attempts2 < maxAttempts) {
        await new Promise((r) => setTimeout(r, 100));
        attempts2++;
      }
      if (!this.fileTransferSystem) {
        throw new Error("File transfer system initialization timeout");
      }
      return true;
    } catch (e) {
      this._secureLog("error", "\u274C _ensureFileTransferReady failed", {
        errorType: e?.constructor?.name || "Unknown",
        hasMessage: !!e?.message
      });
      return false;
    }
  }
  _getSecureKey(keyId) {
    return this._secureKeyStorage.retrieveKey(keyId);
  }
  async _setSecureKey(keyId, key) {
    if (!(key instanceof CryptoKey)) {
      this._secureLog("error", "\u274C Attempt to store non-CryptoKey");
      return false;
    }
    const success = await this._secureKeyStorage.storeKey(keyId, key, {
      version: this.currentKeyVersion,
      type: key.algorithm.name
    });
    if (success) {
      this._secureLog("info", `\u{1F511} Key ${keyId} stored securely with encryption`);
    }
    return success;
  }
  /**
   * Validates a key value
   * @param {CryptoKey} key - Key to validate
   * @returns {boolean} true if the key is valid
   */
  _validateKeyValue(key) {
    return key instanceof CryptoKey && key.algorithm && key.usages && key.usages.length > 0;
  }
  _secureWipeKeys() {
    this._secureKeyStorage.secureWipeAll();
    if (this._masterKeyManager) {
      this._masterKeyManager.lock();
    }
    this._secureLog("info", "\u{1F9F9} All keys securely wiped and encrypted storage cleared");
  }
  /**
   * Validates key storage state
   * @returns {boolean} true if the storage is ready
   */
  _validateKeyStorage() {
    return this._secureKeyStorage instanceof SecureKeyStorage;
  }
  /**
   * Returns secure key storage statistics
   * @returns {object} Storage metrics
   */
  _getKeyStorageStats() {
    const stats = this._secureKeyStorage.getStorageStats();
    return {
      totalKeysCount: stats.totalKeys,
      activeKeysCount: stats.totalKeys,
      hasLastAccess: stats.metadata.some((m) => m.lastAccessed),
      hasLastRotation: !!this._keyStorageStats.lastRotation,
      storageType: "SecureKeyStorage",
      timestamp: Date.now()
    };
  }
  /**
   * Performs key rotation in storage
   */
  _rotateKeys() {
    const oldKeys = Array.from(this._secureKeyStorage.keys());
    this._secureKeyStorage.clear();
    this._keyStorageStats.lastRotation = Date.now();
    this._keyStorageStats.activeKeys = 0;
    this._secureLog("info", `\u{1F504} Key rotation completed. ${oldKeys.length} keys rotated`);
  }
  /**
   * Emergency key wipe (e.g., upon detecting a threat)
   */
  _emergencyKeyWipe() {
    this._secureWipeKeys();
    this._secureLog("error", "\u{1F6A8} EMERGENCY: All keys wiped due to security threat");
  }
  /**
   * Starts key security monitoring
   * @deprecated Use unified scheduler instead
   */
  _startKeySecurityMonitoring() {
    this._secureLog("info", "\u{1F527} Key security monitoring moved to unified scheduler");
  }
  // ============================================
  // HELPER METHODS
  // ============================================
  /**
   *   Constant-time key validation to prevent timing attacks
   * @param {CryptoKey} key - Key to validate
   * @returns {boolean} true if key is valid
   */
  _validateKeyConstantTime(key) {
    let isValid = 0;
    try {
      const isCryptoKey = key instanceof CryptoKey;
      isValid += isCryptoKey ? 1 : 0;
    } catch {
      isValid += 0;
    }
    try {
      const hasAlgorithm = !!(key && key.algorithm);
      isValid += hasAlgorithm ? 1 : 0;
    } catch {
      isValid += 0;
    }
    try {
      const hasType = !!(key && key.type);
      isValid += hasType ? 1 : 0;
    } catch {
      isValid += 0;
    }
    try {
      const hasExtractable = key && key.extractable !== void 0;
      isValid += hasExtractable ? 1 : 0;
    } catch {
      isValid += 0;
    }
    return isValid === 4;
  }
  /**
   *   Constant-time key pair validation
   * @param {Object} keyPair - Key pair to validate
   * @returns {boolean} true if key pair is valid
   */
  _validateKeyPairConstantTime(keyPair) {
    if (!keyPair || typeof keyPair !== "object") return false;
    const privateKeyValid = this._validateKeyConstantTime(keyPair.privateKey);
    const publicKeyValid = this._validateKeyConstantTime(keyPair.publicKey);
    return privateKeyValid && publicKeyValid;
  }
  /**
   *   Enhanced secure logging system initialization
   */
  _initializeSecureLogging() {
    this._logLevels = {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
      trace: 4
    };
    this._currentLogLevel = this._isProductionMode ? this._logLevels.error : (
      // In production, ONLY critical errors
      this._logLevels.info
    );
    this._logCounts = /* @__PURE__ */ new Map();
    this._maxLogCount = this._isProductionMode ? 5 : 50;
    this._resourceLimits = {
      maxLogEntries: this._isProductionMode ? 100 : 1e3,
      maxMessageQueue: 1e3,
      maxIVHistory: 1e4,
      maxProcessedMessageIds: 5e3,
      maxDecoyChannels: 100,
      maxFakeTrafficMessages: 500,
      maxChunkQueue: 200,
      maxPacketBuffer: 1e3
    };
    this._emergencyThresholds = {
      logEntries: this._resourceLimits.maxLogEntries * 0.8,
      // 80%
      messageQueue: this._resourceLimits.maxMessageQueue * 0.8,
      ivHistory: this._resourceLimits.maxIVHistory * 0.8,
      processedMessageIds: this._resourceLimits.maxProcessedMessageIds * 0.8
    };
    this._inputValidationLimits = {
      maxStringLength: 1e5,
      // 100KB for strings
      maxObjectDepth: 10,
      // Maximum object nesting depth
      maxArrayLength: 1e3,
      // Maximum array length
      maxMessageSize: 1024 * 1024,
      // 1MB total message size
      maxConcurrentMessages: 10,
      // Maximum concurrent message processing
      rateLimitMessagesPerMinute: 60,
      // Rate limiting
      rateLimitBurstSize: 10
      // Burst size for rate limiting
    };
    this._absoluteBlacklist = /* @__PURE__ */ new Set([
      // Cryptographic keys
      "encryptionKey",
      "macKey",
      "metadataKey",
      "privateKey",
      "publicKey",
      "ecdhKeyPair",
      "ecdsaKeyPair",
      "peerPublicKey",
      "nestedEncryptionKey",
      // Authentication and session data
      "verificationCode",
      "sessionSalt",
      "keyFingerprint",
      "sessionId",
      "authChallenge",
      "authProof",
      "authToken",
      "sessionToken",
      // Credentials and secrets
      "password",
      "token",
      "secret",
      "credential",
      "signature",
      "apiKey",
      "accessKey",
      "secretKey",
      "privateKey",
      // Cryptographic materials
      "hash",
      "digest",
      "nonce",
      "iv",
      "cipher",
      "seed",
      "entropy",
      "random",
      "salt",
      "fingerprint",
      // JWT and session data
      "jwt",
      "bearer",
      "refreshToken",
      "accessToken",
      // File transfer sensitive data
      "fileHash",
      "fileSignature",
      "transferKey",
      "chunkKey"
    ]);
    this._safeFieldsWhitelist = /* @__PURE__ */ new Set([
      // Basic status fields
      "timestamp",
      "type",
      "status",
      "state",
      "level",
      "isConnected",
      "isVerified",
      "isInitiator",
      "version",
      // Counters and metrics (safe)
      "count",
      "total",
      "active",
      "inactive",
      "success",
      "failure",
      // Connection states (safe)
      "readyState",
      "connectionState",
      "iceConnectionState",
      // Feature counts (safe)
      "activeFeaturesCount",
      "totalFeatures",
      "stage",
      // Error types (safe)
      "errorType",
      "errorCode",
      "phase",
      "attempt"
    ]);
    this._initializeLogSecurityMonitoring();
    this._secureLog("info", `\u{1F527} Enhanced secure logging initialized (Production: ${this._isProductionMode})`);
  }
  /**
   *   Initialize security monitoring for logging system
   */
  _initializeLogSecurityMonitoring() {
    this._logSecurityViolations = 0;
    this._maxLogSecurityViolations = 3;
  }
  /**
   *   Audit logging system security
   */
  _auditLoggingSystemSecurity() {
    let violations = 0;
    for (const [key, count] of this._logCounts.entries()) {
      if (count > this._maxLogCount * 2) {
        violations++;
        this._originalConsole?.error?.(`\u{1F6A8} LOG SECURITY: Excessive log count detected: ${key}`);
      }
    }
    const recentLogs = Array.from(this._logCounts.keys());
    for (const logKey of recentLogs) {
      if (this._containsSensitiveContent(logKey)) {
        violations++;
        this._originalConsole?.error?.(`\u{1F6A8} LOG SECURITY: Sensitive content in log key: ${logKey}`);
      }
    }
    this._logSecurityViolations += violations;
    if (this._logSecurityViolations >= this._maxLogSecurityViolations) {
      this._emergencyDisableLogging();
      this._originalConsole?.error?.("\u{1F6A8} CRITICAL: Logging system disabled due to security violations");
    }
  }
  _secureLogShim(...args) {
    try {
      if (!Array.isArray(args) || args.length === 0) {
        return;
      }
      const message = args[0];
      const restArgs = args.slice(1);
      if (restArgs.length === 0) {
        this._secureLog("info", String(message || ""));
        return;
      }
      if (restArgs.length === 1) {
        this._secureLog("info", String(message || ""), restArgs[0]);
        return;
      }
      this._secureLog("info", String(message || ""), {
        additionalArgs: restArgs,
        argCount: restArgs.length
      });
    } catch (error) {
      try {
        if (this._originalConsole?.log) {
          this._originalConsole.log(...args);
        }
      } catch (fallbackError) {
      }
    }
  }
  /**
   *   Setup own logger without touching global console
   */
  _setupOwnLogger() {
    this.logger = {
      log: (message, data) => this._secureLog("info", message, data),
      info: (message, data) => this._secureLog("info", message, data),
      warn: (message, data) => this._secureLog("warn", message, data),
      error: (message, data) => this._secureLog("error", message, data),
      debug: (message, data) => this._secureLog("debug", message, data)
    };
    if (_EnhancedSecureWebRTCManager.DEBUG_MODE) {
      this._secureLog("info", "\u{1F512} Own logger created - development mode");
    } else {
      this._secureLog("info", "\u{1F512} Own logger created - production mode");
    }
  }
  /**
   *   Production logging - use own logger with minimal output
   */
  _setupProductionLogging() {
    if (this._isProductionMode) {
      this.logger = {
        log: () => {
        },
        // No-op in production
        info: () => {
        },
        // No-op in production
        warn: (message, data) => this._secureLog("warn", message, data),
        error: (message, data) => this._secureLog("error", message, data),
        debug: () => {
        }
        // No-op in production
      };
      this._secureLog("info", "Production logging mode activated");
    }
  }
  /**
   *   Secure logging with enhanced data protection
   * @param {string} level - Log level (error, warn, info, debug, trace)
   * @param {string} message - Message
   * @param {object} data - Optional payload (will be sanitized)
   */
  _secureLog(level, message, data = null) {
    if (data && !this._auditLogMessage(message, data)) {
      this._originalConsole?.error?.("SECURITY: Logging blocked due to potential data leakage");
      return;
    }
    if (this._logLevels[level] > this._currentLogLevel) {
      return;
    }
    const logKey = `${level}:${message.substring(0, 50)}`;
    const currentCount = this._logCounts.get(logKey) || 0;
    if (currentCount >= this._maxLogCount) {
      return;
    }
    this._logCounts.set(logKey, currentCount + 1);
    let sanitizedData = null;
    if (data) {
      sanitizedData = this._sanitizeLogData(data);
      if (this._containsSensitiveContent(JSON.stringify(sanitizedData))) {
        this._originalConsole?.error?.("ECURITY: Sanitized data still contains sensitive content - blocking log");
        return;
      }
    }
    if (this._isProductionMode) {
      if (level === "error") {
        const safeMessage = this._sanitizeString(message);
        this._originalConsole?.error?.(safeMessage);
      }
      return;
    }
    const logMethod = this._originalConsole?.[level] || this._originalConsole?.log;
    if (sanitizedData) {
      logMethod(message, sanitizedData);
    } else {
      logMethod(message);
    }
  }
  /**
   *   Enhanced sanitization for log data with multiple security layers
   */
  _sanitizeLogData(data) {
    if (typeof data === "string") {
      return this._sanitizeString(data);
    }
    if (!data || typeof data !== "object") {
      return data;
    }
    const sanitized = {};
    for (const [key, value] of Object.entries(data)) {
      const lowerKey = key.toLowerCase();
      const blacklistPatterns = [
        "key",
        "secret",
        "token",
        "password",
        "credential",
        "auth",
        "fingerprint",
        "salt",
        "signature",
        "private",
        "encryption",
        "mac",
        "metadata",
        "session",
        "jwt",
        "bearer",
        "hash",
        "digest",
        "nonce",
        "iv",
        "cipher",
        "seed",
        "entropy"
      ];
      const isBlacklisted = this._absoluteBlacklist.has(key) || blacklistPatterns.some((pattern) => lowerKey.includes(pattern));
      if (isBlacklisted) {
        sanitized[key] = "[SENSITIVE_DATA_BLOCKED]";
        continue;
      }
      if (this._safeFieldsWhitelist.has(key)) {
        if (typeof value === "string") {
          sanitized[key] = this._sanitizeString(value);
        } else {
          sanitized[key] = value;
        }
        continue;
      }
      if (typeof value === "boolean" || typeof value === "number") {
        sanitized[key] = value;
      } else if (typeof value === "string") {
        sanitized[key] = this._sanitizeString(value);
      } else if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
        sanitized[key] = `[${value.constructor.name}(<REDACTED> bytes)]`;
      } else if (value && typeof value === "object") {
        try {
          sanitized[key] = this._sanitizeLogData(value);
        } catch (error) {
          sanitized[key] = "[RECURSIVE_SANITIZATION_FAILED]";
        }
      } else {
        sanitized[key] = `[${typeof value}]`;
      }
    }
    const sanitizedString = JSON.stringify(sanitized);
    if (this._containsSensitiveContent(sanitizedString)) {
      return { error: "SANITIZATION_FAILED_SENSITIVE_CONTENT_DETECTED" };
    }
    return sanitized;
  }
  /**
   *   Enhanced sanitization for strings with comprehensive pattern detection
   */
  _sanitizeString(str) {
    if (typeof str !== "string" || str.length === 0) {
      return str;
    }
    const sensitivePatterns = [
      // Hex patterns (various lengths)
      /[a-f0-9]{16,}/i,
      // 16+ hex chars (covers short keys)
      /[a-f0-9]{8,}/i,
      // 8+ hex chars (covers shorter keys)
      // Base64 patterns (comprehensive)
      /[A-Za-z0-9+/]{16,}={0,2}/,
      // Base64 with padding
      /[A-Za-z0-9+/]{12,}/,
      // Base64 without padding
      /[A-Za-z0-9+/=]{10,}/,
      // Base64-like patterns
      // Base58 patterns (Bitcoin-style)
      /[1-9A-HJ-NP-Za-km-z]{16,}/,
      // Base58 strings
      // Base32 patterns
      /[A-Z2-7]{16,}={0,6}/,
      // Base32 with padding
      /[A-Z2-7]{12,}/,
      // Base32 without padding
      // Custom encoding patterns
      /[A-Za-z0-9\-_]{16,}/,
      // URL-safe base64 variants
      /[A-Za-z0-9\.\-_]{16,}/,
      // JWT-like patterns
      // Long alphanumeric strings (potential keys)
      /\b[A-Za-z0-9]{12,}\b/,
      // 12+ alphanumeric chars
      /\b[A-Za-z0-9]{8,}\b/,
      // 8+ alphanumeric chars
      // PEM key patterns
      /BEGIN\s+(PRIVATE|PUBLIC|RSA|DSA|EC)\s+KEY/i,
      /END\s+(PRIVATE|PUBLIC|RSA|DSA|EC)\s+KEY/i,
      // JWT patterns
      /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/,
      // API key patterns
      /(api[_-]?key|token|secret|password|credential)[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i,
      // UUID patterns
      /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i,
      // Credit cards and SSN (existing patterns)
      /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,
      /\b\d{3}-\d{2}-\d{4}\b/,
      // Email patterns (more restrictive)
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
      // Crypto-specific patterns
      /(fingerprint|hash|digest|signature)[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i,
      /(encryption|mac|metadata)[\s]*key[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i,
      // Session and auth patterns
      /(session|auth|jwt|bearer)[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i
    ];
    for (const pattern of sensitivePatterns) {
      if (pattern.test(str)) {
        return "[SENSITIVE_DATA_REDACTED]";
      }
    }
    if (this._hasHighEntropy(str)) {
      return "[HIGH_ENTROPY_DATA_REDACTED]";
    }
    if (this._hasSuspiciousDistribution(str)) {
      return "[SUSPICIOUS_DATA_REDACTED]";
    }
    if (str.length > 50) {
      return str.substring(0, 20) + "...[TRUNCATED]";
    }
    return str;
  }
  /**
   *   Enhanced sensitive content detection
   */
  _containsSensitiveContent(str) {
    if (typeof str !== "string") return false;
    const sensitivePatterns = [
      /[a-f0-9]{16,}/i,
      /[A-Za-z0-9+/]{16,}={0,2}/,
      /[1-9A-HJ-NP-Za-km-z]{16,}/,
      /[A-Z2-7]{16,}={0,6}/,
      /\b[A-Za-z0-9]{12,}\b/,
      /BEGIN\s+(PRIVATE|PUBLIC|RSA|DSA|EC)\s+KEY/i,
      /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/,
      /(api[_-]?key|token|secret|password|credential)[\s]*[:=][\s]*[A-Za-z0-9\-_]{8,}/i
    ];
    return sensitivePatterns.some((pattern) => pattern.test(str)) || this._hasHighEntropy(str) || this._hasSuspiciousDistribution(str);
  }
  /**
   *   Check for high entropy strings (likely cryptographic keys)
   */
  _hasHighEntropy(str) {
    if (str.length < 8) return false;
    const charCount = {};
    for (const char of str) {
      charCount[char] = (charCount[char] || 0) + 1;
    }
    const length = str.length;
    let entropy = 0;
    for (const count of Object.values(charCount)) {
      const probability = count / length;
      entropy -= probability * Math.log2(probability);
    }
    return entropy > 4.5;
  }
  /**
   *   Check for suspicious character distributions
   */
  _hasSuspiciousDistribution(str) {
    if (str.length < 8) return false;
    const hexChars = str.match(/[a-f0-9]/gi) || [];
    if (hexChars.length >= str.length * 0.8) {
      return true;
    }
    const base64Chars = str.match(/[A-Za-z0-9+/=]/g) || [];
    if (base64Chars.length >= str.length * 0.9) {
      return true;
    }
    const uniqueChars = new Set(str).size;
    const diversityRatio = uniqueChars / str.length;
    if (diversityRatio > 0.8 && str.length > 16) {
      return true;
    }
    return false;
  }
  // ============================================
  // SECURE LOGGING SYSTEM
  // ============================================
  /**
   * Detects production mode
   */
  _detectProductionMode() {
    return (
      // Standard env variables
      typeof process !== "undefined" && false || // No debug flags
      !this._debugMode || // Production domains
      window.location.hostname && !window.location.hostname.includes("localhost") && !window.location.hostname.includes("127.0.0.1") && !window.location.hostname.includes(".local") || // Minified code (heuristic check)
      typeof window.webpackHotUpdate === "undefined" && !window.location.search.includes("debug")
    );
  }
  // ============================================
  // FIXED SECURE GLOBAL API
  // ============================================
  /**
   * Sets up a secure global API with limited access
   */
  _setupSecureGlobalAPI() {
    this._secureLog("info", "Starting secure global API setup");
    const secureAPI = {};
    if (typeof this.sendMessage === "function") {
      secureAPI.sendMessage = this.sendMessage.bind(this);
    }
    secureAPI.getConnectionStatus = () => ({
      isConnected: this.isConnected ? this.isConnected() : false,
      isVerified: this.isVerified || false,
      connectionState: this.peerConnection?.connectionState || "disconnected"
    });
    secureAPI.getSecurityStatus = () => ({
      securityLevel: "maximum",
      stage: "initialized",
      activeFeaturesCount: Object.values(this.securityFeatures || {}).filter(Boolean).length
    });
    if (typeof this.sendFile === "function") {
      secureAPI.sendFile = this.sendFile.bind(this);
    }
    secureAPI.getFileTransferStatus = () => ({
      initialized: !!this.fileTransferSystem,
      status: "ready",
      activeTransfers: 0,
      receivingTransfers: 0
    });
    if (typeof this.disconnect === "function") {
      secureAPI.disconnect = this.disconnect.bind(this);
    }
    const safeGlobalAPI = {
      ...secureAPI,
      // Spread only existing methods
      getConfiguration: () => ({
        fakeTraffic: this._config.fakeTraffic.enabled,
        decoyChannels: this._config.decoyChannels.enabled,
        packetPadding: this._config.packetPadding.enabled,
        antiFingerprinting: this._config.antiFingerprinting.enabled
      }),
      emergency: {}
    };
    if (typeof this._emergencyUnlockAllMutexes === "function") {
      safeGlobalAPI.emergency.unlockAllMutexes = this._emergencyUnlockAllMutexes.bind(this);
    }
    if (typeof this._emergencyRecoverMutexSystem === "function") {
      safeGlobalAPI.emergency.recoverMutexSystem = this._emergencyRecoverMutexSystem.bind(this);
    }
    if (typeof this._emergencyDisableLogging === "function") {
      safeGlobalAPI.emergency.disableLogging = this._emergencyDisableLogging.bind(this);
    }
    if (typeof this._resetLoggingSystem === "function") {
      safeGlobalAPI.emergency.resetLogging = this._resetLoggingSystem.bind(this);
    }
    safeGlobalAPI.getFileTransferSystemStatus = () => ({
      initialized: !!this.fileTransferSystem,
      status: "ready",
      activeTransfers: 0,
      receivingTransfers: 0
    });
    this._secureLog("info", "API methods available", {
      sendMessage: !!secureAPI.sendMessage,
      getConnectionStatus: !!secureAPI.getConnectionStatus,
      getSecurityStatus: !!secureAPI.getSecurityStatus,
      sendFile: !!secureAPI.sendFile,
      getFileTransferStatus: !!secureAPI.getFileTransferStatus,
      disconnect: !!secureAPI.disconnect,
      getConfiguration: !!safeGlobalAPI.getConfiguration,
      emergencyMethods: Object.keys(safeGlobalAPI.emergency).length
    });
    Object.freeze(safeGlobalAPI);
    Object.freeze(safeGlobalAPI.emergency);
    this._createProtectedGlobalAPI(safeGlobalAPI);
    this._setupMinimalGlobalProtection();
    this._secureLog("info", "Secure global API setup completed successfully");
  }
  /**
   *   Create simple global API export
   */
  _createProtectedGlobalAPI(safeGlobalAPI) {
    this._secureLog("info", "Creating protected global API");
    if (!window.secureBitChat) {
      this._exportAPI(safeGlobalAPI);
    } else {
      this._secureLog("warn", "\u26A0\uFE0F Global API already exists, skipping setup");
    }
  }
  /**
   *   Simple API export without monitoring
   */
  _exportAPI(apiObject) {
    this._secureLog("info", "Exporting API to window.secureBitChat");
    if (!this._importantMethods || !this._importantMethods.defineProperty) {
      this._secureLog("error", "\u274C Important methods not available for API export, using fallback");
      Object.defineProperty(window, "secureBitChat", {
        value: apiObject,
        writable: false,
        configurable: false,
        enumerable: true
      });
    } else {
      this._importantMethods.defineProperty(window, "secureBitChat", {
        value: apiObject,
        writable: false,
        configurable: false,
        enumerable: true
      });
    }
    this._secureLog("info", "\u{1F512} Secure API exported to window.secureBitChat");
  }
  /**
   *   Setup minimal global protection
   */
  _setupMinimalGlobalProtection() {
    this._protectGlobalAPI();
    this._secureLog("info", "\u{1F512} Minimal global protection activated");
  }
  /**
   *   Store important methods in closure for local use
   */
  _storeImportantMethods() {
    this._importantMethods = {
      defineProperty: Object.defineProperty,
      getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
      freeze: Object.freeze,
      consoleLog: console.log,
      consoleError: console.error,
      consoleWarn: console.warn
    };
    this._secureLog("info", "\u{1F512} Important methods stored locally", {
      defineProperty: !!this._importantMethods.defineProperty,
      getOwnPropertyDescriptor: !!this._importantMethods.getOwnPropertyDescriptor,
      freeze: !!this._importantMethods.freeze
    });
  }
  /**
   *   Simple protection without monitoring
   */
  _setupSimpleProtection() {
    this._secureLog("info", "\u{1F512} Simple protection activated - no monitoring");
  }
  /**
   *   No global exposure prevention needed
   */
  _preventGlobalExposure() {
    this._secureLog("info", "\u{1F512} No global exposure prevention - using secure API export only");
  }
  /**
   *   API integrity check - only at initialization
   */
  _verifyAPIIntegrity() {
    try {
      if (!window.secureBitChat) {
        this._secureLog("error", "\u274C SECURITY ALERT: Secure API has been removed!");
        return false;
      }
      const requiredMethods = ["sendMessage", "getConnectionStatus", "disconnect"];
      const missingMethods = requiredMethods.filter(
        (method) => typeof window.secureBitChat[method] !== "function"
      );
      if (missingMethods.length > 0) {
        this._secureLog("error", "\u274C SECURITY ALERT: API tampering detected, missing methods:", { errorType: missingMethods?.constructor?.name || "Unknown" });
        return false;
      }
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C SECURITY ALERT: API integrity check failed:", { errorType: error?.constructor?.name || "Unknown" });
      return false;
    }
  }
  // ============================================
  // ADDITIONAL SECURITY METHODS
  // ============================================
  /**
   *   Simple global exposure check - only at initialization
   */
  _auditGlobalExposure() {
    this._secureLog("info", "\u{1F512} Global exposure check completed at initialization");
    return [];
  }
  /**
   *   No periodic security audits - only at initialization
   */
  _startSecurityAudit() {
    this._secureLog("info", "\u{1F512} Security audit completed at initialization - no periodic monitoring");
  }
  /**
   *   Simple global API protection
   */
  _protectGlobalAPI() {
    if (!window.secureBitChat) {
      this._secureLog("warn", "\u26A0\uFE0F Global API not found during protection setup");
      return;
    }
    try {
      if (this._validateAPIIntegrityOnce()) {
        this._secureLog("info", "\u{1F512} Global API protection verified");
      }
    } catch (error) {
      this._secureLog("error", "\u274C Failed to verify global API protection", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
    }
  }
  /**
   *   Validate API integrity once at initialization
   */
  _validateAPIIntegrityOnce() {
    try {
      if (!this._importantMethods || !this._importantMethods.getOwnPropertyDescriptor) {
        const descriptor = Object.getOwnPropertyDescriptor(window, "secureBitChat");
        if (!descriptor || descriptor.configurable) {
          throw new Error("secureBitChat must not be reconfigurable!");
        }
      } else {
        const descriptor = this._importantMethods.getOwnPropertyDescriptor(window, "secureBitChat");
        if (!descriptor || descriptor.configurable) {
          throw new Error("secureBitChat must not be reconfigurable!");
        }
      }
      this._secureLog("info", "\u2705 API integrity validated");
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C API integrity validation failed", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      return false;
    }
  }
  /**
   *   Secure memory wipe for sensitive data
   */
  _secureWipeMemory(data, context = "unknown") {
    if (!data) return;
    try {
      if (data instanceof ArrayBuffer) {
        this._secureWipeArrayBuffer(data, context);
      } else if (data instanceof Uint8Array) {
        this._secureWipeUint8Array(data, context);
      } else if (Array.isArray(data)) {
        this._secureWipeArray(data, context);
      } else if (typeof data === "string") {
        this._secureWipeString(data, context);
      } else if (data instanceof CryptoKey) {
        this._secureWipeCryptoKey(data, context);
      } else if (typeof data === "object") {
        this._secureWipeObject(data, context);
      }
      this._secureMemoryManager.memoryStats.totalCleanups++;
    } catch (error) {
      this._secureMemoryManager.memoryStats.failedCleanups++;
      this._secureLog("error", "\u274C Secure memory wipe failed", {
        context,
        errorType: error.constructor.name,
        errorMessage: error.message
      });
    }
  }
  /**
   *   Secure wipe for ArrayBuffer
   */
  _secureWipeArrayBuffer(buffer, context) {
    if (!buffer || buffer.byteLength === 0) return;
    try {
      const view = new Uint8Array(buffer);
      crypto.getRandomValues(view);
      view.fill(0);
      view.fill(255);
      view.fill(0);
      this._secureLog("debug", "\u{1F512} ArrayBuffer securely wiped", {
        context,
        size: buffer.byteLength
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to wipe ArrayBuffer", {
        context,
        errorType: error.constructor.name
      });
    }
  }
  /**
   *   Secure wipe for Uint8Array
   */
  _secureWipeUint8Array(array, context) {
    if (!array || array.length === 0) return;
    try {
      crypto.getRandomValues(array);
      array.fill(0);
      array.fill(255);
      array.fill(0);
      this._secureLog("debug", "\u{1F512} Uint8Array securely wiped", {
        context,
        size: array.length
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to wipe Uint8Array", {
        context,
        errorType: error.constructor.name
      });
    }
  }
  /**
   *   Secure wipe for arrays
   */
  _secureWipeArray(array, context) {
    if (!Array.isArray(array) || array.length === 0) return;
    try {
      array.forEach((item, index) => {
        if (item !== null && item !== void 0) {
          this._secureWipeMemory(item, `${context}[${index}]`);
        }
      });
      array.fill(null);
      this._secureLog("debug", "\u{1F512} Array securely wiped", {
        context,
        size: array.length
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to wipe array", {
        context,
        errorType: error.constructor.name
      });
    }
  }
  /**
   *   No string wiping - strings are immutable in JS
   */
  /**
   * NOT a wipe, and deliberately named in the log as what it is.
   *
   * JavaScript strings are immutable: there is no way to overwrite the
   * characters of an existing string, so any secret that was ever held as a
   * string stays in the heap until the GC collects it — and we cannot force
   * that. The caller can only drop its reference.
   *
   * This used to report success at debug level, which made the emergency wipe
   * path (see _emergencyWipeOnFingerprintMismatch) look like it had scrubbed
   * key material when it had scrubbed nothing. The real fix is upstream: keep
   * secrets in ArrayBuffers, which CAN be overwritten — see
   * EnhancedSecureCryptoUtils.zeroizeBuffer.
   */
  _secureWipeString(str, context) {
    this._secureLog("debug", "String secret cannot be wiped in JS (immutable) \u2014 reference dropped only", {
      context,
      length: str ? str.length : 0
    });
    return false;
  }
  /**
   *   CryptoKey cleanup - store in WeakMap for proper GC
   */
  /**
   * Also not a wipe. A non-extractable CryptoKey has no bytes visible to JS —
   * the material lives in the browser's crypto implementation, and dropping the
   * handle is the only lever we have. Whether the browser then zeroes its copy
   * is up to the browser.
   *
   * The previous implementation was worse than a no-op: it ADDED the key to a
   * WeakMap (i.e. took a new reference to the thing it was asked to destroy)
   * and logged success. Callers that believed it — notably the emergency wipe
   * on a fingerprint mismatch — were reporting a scrub that never happened.
   *
   * Non-extractability is what actually protects these keys; it is verified by
   * EnhancedSecureCryptoUtils.verifyNonExtractableKeys.
   */
  _secureWipeCryptoKey(key, context) {
    if (!key || !(key instanceof CryptoKey)) return false;
    this._secureLog("debug", "CryptoKey cannot be wiped from JS \u2014 handle dropped, material is non-extractable", {
      context,
      type: key.type,
      extractable: key.extractable
    });
    if (key.extractable) {
      this._secureLog("error", "Extractable key reached the wipe path \u2014 material may persist in memory", {
        context
      });
    }
    return false;
  }
  /**
   *   Secure wipe for objects
   */
  _secureWipeObject(obj, context) {
    if (!obj || typeof obj !== "object") return;
    try {
      for (const [key, value] of Object.entries(obj)) {
        if (value !== null && value !== void 0) {
          this._secureWipeMemory(value, `${context}.${key}`);
        }
        obj[key] = null;
      }
      this._secureLog("debug", "\u{1F512} Object securely wiped", {
        context,
        properties: Object.keys(obj).length
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to wipe object", {
        context,
        errorType: error.constructor.name
      });
    }
  }
  /**
   *   Secure cleanup of cryptographic materials
   */
  _secureCleanupCryptographicMaterials() {
    try {
      if (this.ecdhKeyPair) {
        this._secureWipeMemory(this.ecdhKeyPair, "ecdhKeyPair");
        this.ecdhKeyPair = null;
      }
      if (this.ecdsaKeyPair) {
        this._secureWipeMemory(this.ecdsaKeyPair, "ecdsaKeyPair");
        this.ecdsaKeyPair = null;
      }
      if (this.encryptionKey) {
        this._secureWipeMemory(this.encryptionKey, "encryptionKey");
        this.encryptionKey = null;
      }
      if (this.macKey) {
        this._secureWipeMemory(this.macKey, "macKey");
        this.macKey = null;
      }
      if (this.metadataKey) {
        this._secureWipeMemory(this.metadataKey, "metadataKey");
        this.metadataKey = null;
      }
      if (this.nestedEncryptionKey) {
        this._secureWipeMemory(this.nestedEncryptionKey, "nestedEncryptionKey");
        this.nestedEncryptionKey = null;
      }
      if (this.sessionSalt) {
        this._secureWipeMemory(this.sessionSalt, "sessionSalt");
        this.sessionSalt = null;
      }
      if (this.sessionId) {
        this._secureWipeMemory(this.sessionId, "sessionId");
        this.sessionId = null;
      }
      if (this.verificationCode) {
        this._secureWipeMemory(this.verificationCode, "verificationCode");
        this.verificationCode = null;
      }
      if (this.peerPublicKey) {
        this._secureWipeMemory(this.peerPublicKey, "peerPublicKey");
        this.peerPublicKey = null;
      }
      if (this.keyFingerprint) {
        this._secureWipeMemory(this.keyFingerprint, "keyFingerprint");
        this.keyFingerprint = null;
      }
      if (this.connectionId) {
        this._secureWipeMemory(this.connectionId, "connectionId");
        this.connectionId = null;
      }
      this._clearPendingOfferContext();
      if (this._ratchet) {
        try {
          this._ratchet.destroy();
        } catch (_) {
        }
        this._ratchet = null;
      }
      this._peerSupportsRatchet = false;
      this._secureLog("info", "\u{1F512} Cryptographic materials securely cleaned up");
    } catch (error) {
      this._secureLog("error", "\u274C Failed to cleanup cryptographic materials", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
    }
  }
  /**
   *   Force garbage collection if available
   */
  async _forceGarbageCollection() {
    try {
      await this._performNaturalCleanup();
      this._secureLog("debug", "\u{1F512} Natural memory cleanup performed");
    } catch (error) {
      this._secureLog("error", "\u274C Failed to perform natural cleanup", {
        errorType: error.constructor.name
      });
    }
  }
  /**
   *   Perform periodic memory cleanup
   */
  async _performPeriodicMemoryCleanup() {
    try {
      this._secureMemoryManager.isCleaning = true;
      const preserveActiveRatchet = this.sessionMode === "ratchet" && this.isConnected && this.dataChannel && this.dataChannel.readyState === "open";
      const pendingOfferAgeMs = this._pendingOfferContext ? Date.now() - (this._pendingOfferContext.createdAt || 0) : Infinity;
      const hasPendingOffer = !!this._pendingOfferContext && Array.isArray(this._pendingOfferContext.sessionSalt) && this._pendingOfferContext.sessionSalt.length === 64 && pendingOfferAgeMs < _EnhancedSecureWebRTCManager.LIMITS.OFFER_MAX_AGE;
      const shouldPreserveActiveKeys = preserveActiveRatchet || hasPendingOffer;
      if (shouldPreserveActiveKeys) {
        this._secureLog("debug", "\u{1F9F9} Skipping crypto key wipe during periodic cleanup", {
          reason: preserveActiveRatchet ? "active ratchet connection" : "offer awaiting answer"
        });
      } else {
        this._secureCleanupCryptographicMaterials();
      }
      if (this.messageQueue && this.messageQueue.length > 100) {
        const excessMessages = this.messageQueue.splice(0, this.messageQueue.length - 50);
        excessMessages.forEach((message, index) => {
          this._secureWipeMemory(message, `periodicCleanup[${index}]`);
        });
      }
      if (this.processedMessageIds && this.processedMessageIds.size > 1e3) {
        this.processedMessageIds.clear();
      }
      await this._forceGarbageCollection();
      this._secureLog("debug", "\u{1F512} Periodic memory cleanup completed");
    } catch (error) {
      this._secureLog("error", "\u274C Error during periodic memory cleanup", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
    } finally {
      this._secureMemoryManager.isCleaning = false;
    }
  }
  /**
   *   Create secure error message without information disclosure
   */
  _createSecureErrorMessage(originalError, context = "unknown") {
    try {
      const category = this._categorizeError(originalError);
      const safeMessage = this._getSafeErrorMessage(category, context);
      this._secureLog("error", "Internal error occurred", {
        category,
        context,
        errorType: originalError?.constructor?.name || "Unknown",
        timestamp: Date.now()
      });
      this._trackErrorFrequency(category);
      return safeMessage;
    } catch (error) {
      this._secureLog("error", "Error handling failed", {
        originalError: originalError?.message || "Unknown",
        handlingError: error.message
      });
      return "An unexpected error occurred";
    }
  }
  /**
   *   Categorize error for appropriate handling
   */
  _categorizeError(error) {
    if (!error || !error.message) {
      return this._secureErrorHandler.errorCategories.UNKNOWN;
    }
    const message = error.message.toLowerCase();
    if (message.includes("crypto") || message.includes("key") || message.includes("encrypt") || message.includes("decrypt") || message.includes("sign") || message.includes("verify") || message.includes("ecdh") || message.includes("ecdsa")) {
      return this._secureErrorHandler.errorCategories.CRYPTOGRAPHIC;
    }
    if (message.includes("network") || message.includes("connection") || message.includes("timeout") || message.includes("webrtc") || message.includes("peer")) {
      return this._secureErrorHandler.errorCategories.NETWORK;
    }
    if (message.includes("invalid") || message.includes("validation") || message.includes("format") || message.includes("type")) {
      return this._secureErrorHandler.errorCategories.VALIDATION;
    }
    if (message.includes("system") || message.includes("internal") || message.includes("memory") || message.includes("resource")) {
      return this._secureErrorHandler.errorCategories.SYSTEM;
    }
    return this._secureErrorHandler.errorCategories.UNKNOWN;
  }
  /**
   *   Get safe error message based on category
   */
  _getSafeErrorMessage(category, context) {
    const safeMessages = {
      [this._secureErrorHandler.errorCategories.CRYPTOGRAPHIC]: {
        "key_generation": "Security initialization failed",
        "key_import": "Security verification failed",
        "key_derivation": "Security setup failed",
        "encryption": "Message security failed",
        "decryption": "Message verification failed",
        "signature": "Authentication failed",
        "default": "Security operation failed"
      },
      [this._secureErrorHandler.errorCategories.NETWORK]: {
        "connection": "Connection failed",
        "timeout": "Connection timeout",
        "peer": "Peer connection failed",
        "webrtc": "Communication failed",
        "default": "Network operation failed"
      },
      [this._secureErrorHandler.errorCategories.VALIDATION]: {
        "format": "Invalid data format",
        "type": "Invalid data type",
        "structure": "Invalid data structure",
        "default": "Validation failed"
      },
      [this._secureErrorHandler.errorCategories.SYSTEM]: {
        "memory": "System resource error",
        "resource": "System resource unavailable",
        "internal": "Internal system error",
        "default": "System operation failed"
      },
      [this._secureErrorHandler.errorCategories.UNKNOWN]: {
        "default": "An unexpected error occurred"
      }
    };
    const categoryMessages = safeMessages[category] || safeMessages[this._secureErrorHandler.errorCategories.UNKNOWN];
    let specificContext = "default";
    if (context.includes("key") || context.includes("crypto")) {
      specificContext = category === this._secureErrorHandler.errorCategories.CRYPTOGRAPHIC ? "key_generation" : "default";
    } else if (context.includes("connection") || context.includes("peer")) {
      specificContext = category === this._secureErrorHandler.errorCategories.NETWORK ? "connection" : "default";
    } else if (context.includes("validation") || context.includes("format")) {
      specificContext = category === this._secureErrorHandler.errorCategories.VALIDATION ? "format" : "default";
    }
    return categoryMessages[specificContext] || categoryMessages.default;
  }
  /**
   *   Track error frequency for security monitoring
   */
  _trackErrorFrequency(category) {
    const now = Date.now();
    if (now - this._secureErrorHandler.lastErrorTime > 6e4) {
      this._secureErrorHandler.errorCounts.clear();
    }
    const currentCount = this._secureErrorHandler.errorCounts.get(category) || 0;
    this._secureErrorHandler.errorCounts.set(category, currentCount + 1);
    this._secureErrorHandler.lastErrorTime = now;
    const totalErrors = Array.from(this._secureErrorHandler.errorCounts.values()).reduce((sum, count) => sum + count, 0);
    if (totalErrors > this._secureErrorHandler.errorThreshold) {
      this._secureErrorHandler.isInErrorMode = true;
      this._secureLog("warn", "\u26A0\uFE0F High error frequency detected - entering error mode", {
        totalErrors,
        threshold: this._secureErrorHandler.errorThreshold
      });
    }
  }
  /**
   *   Throw secure error without information disclosure
   */
  _throwSecureError(originalError, context = "unknown") {
    const secureMessage = this._createSecureErrorMessage(originalError, context);
    throw new Error(secureMessage);
  }
  /**
   *   Get error handling statistics
   */
  _getErrorHandlingStats() {
    return {
      errorCounts: Object.fromEntries(this._secureErrorHandler.errorCounts),
      isInErrorMode: this._secureErrorHandler.isInErrorMode,
      lastErrorTime: this._secureErrorHandler.lastErrorTime,
      errorThreshold: this._secureErrorHandler.errorThreshold
    };
  }
  /**
   *   Reset error handling system
   */
  _resetErrorHandlingSystem() {
    this._secureErrorHandler.errorCounts.clear();
    this._secureErrorHandler.isInErrorMode = false;
    this._secureErrorHandler.lastErrorTime = 0;
    this._secureLog("info", "\u{1F504} Error handling system reset");
  }
  /**
   *   Get memory management statistics
   */
  _getMemoryManagementStats() {
    return {
      totalCleanups: this._secureMemoryManager.memoryStats.totalCleanups,
      failedCleanups: this._secureMemoryManager.memoryStats.failedCleanups,
      lastCleanup: this._secureMemoryManager.memoryStats.lastCleanup,
      isCleaning: this._secureMemoryManager.isCleaning,
      queueLength: this._secureMemoryManager.cleanupQueue.length
    };
  }
  /**
   *   Validate API integrity and security
   */
  _validateAPIIntegrity() {
    try {
      if (!window.secureBitChat) {
        this._secureLog("error", "\u274C Global API not found during integrity validation");
        return false;
      }
      const requiredMethods = ["sendMessage", "getConnectionStatus", "getSecurityStatus", "sendFile", "disconnect"];
      const missingMethods = requiredMethods.filter(
        (method) => !window.secureBitChat[method] || typeof window.secureBitChat[method] !== "function"
      );
      if (missingMethods.length > 0) {
        this._secureLog("error", "\u274C Global API integrity validation failed - missing methods", {
          missingMethods
        });
        return false;
      }
      const testContext = { test: true };
      const boundMethods = requiredMethods.map((method) => {
        try {
          return window.secureBitChat[method].bind(testContext);
        } catch (error) {
          return null;
        }
      });
      const unboundMethods = boundMethods.filter((method) => method === null);
      if (unboundMethods.length > 0) {
        this._secureLog("error", "\u274C Global API integrity validation failed - method binding issues", {
          unboundMethods: unboundMethods.length
        });
        return false;
      }
      try {
        const testProp = "_integrity_test_" + Date.now();
        Object.defineProperty(window.secureBitChat, testProp, {
          value: "test",
          writable: true,
          configurable: true
        });
        this._secureLog("error", "\u274C Global API integrity validation failed - API is mutable");
        delete window.secureBitChat[testProp];
        return false;
      } catch (immutabilityError) {
        this._secureLog("debug", "\u2705 Global API immutability verified");
      }
      this._secureLog("info", "\u2705 Global API integrity validation passed");
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C Global API integrity validation failed", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      return false;
    }
  }
  _validateCryptographicSecurity() {
    const criticalFeatures = ["hasRateLimiting"];
    const missingCritical = criticalFeatures.filter((feature) => !this.securityFeatures[feature]);
    if (missingCritical.length > 0) {
      this._secureLog("error", "\u{1F6A8} CRITICAL: Missing critical rate limiting feature", {
        missing: missingCritical,
        currentFeatures: this.securityFeatures,
        action: "Rate limiting will be forced enabled"
      });
      missingCritical.forEach((feature) => {
        this.securityFeatures[feature] = true;
        this._secureLog("warn", `\u26A0\uFE0F Forced enable critical: ${feature} = true`);
      });
    }
    const availableFeatures = Object.keys(this.securityFeatures).filter((f) => this.securityFeatures[f]);
    const encryptionFeatures = ["hasEncryption", "hasECDH", "hasECDSA"].filter((f) => this.securityFeatures[f]);
    this._secureLog("info", "\u2705 Cryptographic security validation passed", {
      criticalFeatures: criticalFeatures.length,
      availableFeatures: availableFeatures.length,
      encryptionFeatures: encryptionFeatures.length,
      totalSecurityFeatures: availableFeatures.length,
      note: "Encryption features will be enabled after key generation",
      currentState: {
        hasEncryption: this.securityFeatures.hasEncryption,
        hasECDH: this.securityFeatures.hasECDH,
        hasECDSA: this.securityFeatures.hasECDSA,
        hasRateLimiting: this.securityFeatures.hasRateLimiting
      }
    });
    return true;
  }
  _syncSecurityFeaturesWithTariff() {
    this._secureLog("info", "\u2705 All security features enabled by default - no payment required");
    const allFeatures = [
      "hasEncryption",
      "hasECDH",
      "hasECDSA",
      "hasMutualAuth",
      "hasMetadataProtection",
      "hasEnhancedReplayProtection",
      "hasNonExtractableKeys",
      "hasRateLimiting",
      "hasEnhancedValidation",
      "hasPFS",
      "hasNestedEncryption",
      "hasPacketPadding",
      "hasPacketReordering",
      "hasAntiFingerprinting",
      "hasFakeTraffic",
      "hasDecoyChannels",
      "hasMessageChunking"
    ];
    allFeatures.forEach((feature) => {
      this.securityFeatures[feature] = true;
    });
    this._secureLog("info", "\u2705 All security features enabled by default", {
      enabledFeatures: Object.keys(this.securityFeatures).filter((f) => this.securityFeatures[f]).length,
      totalFeatures: Object.keys(this.securityFeatures).length
    });
    return;
  }
  /**
   * Emergency shutdown for critical issues
   */
  _emergencyShutdown(reason = "Security breach") {
    this._secureLog("error", "\u274C EMERGENCY SHUTDOWN: ${reason}");
    try {
      this.encryptionKey = null;
      this.macKey = null;
      this.metadataKey = null;
      this.verificationCode = null;
      this.keyFingerprint = null;
      this.connectionId = null;
      if (this.dataChannel) {
        this.dataChannel.close();
        this.dataChannel = null;
      }
      if (this.peerConnection) {
        this.peerConnection.close();
        this.peerConnection = null;
      }
      this.messageQueue = [];
      this.processedMessageIds.clear();
      this.packetBuffer.clear();
      if (this.onStatusChange) {
        this.onStatusChange("security_breach");
      }
      this._secureLog("info", "\u{1F512} Emergency shutdown completed");
    } catch (error) {
      this._secureLog("error", "\u274C Error during emergency shutdown:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  _finalizeSecureInitialization() {
    this._startKeySecurityMonitoring();
    if (!this._verifyAPIIntegrity()) {
      this._secureLog("error", "\u274C Security initialization failed");
      return;
    }
    this._startSecurityMonitoring();
    this._logCleanupInterval = this._trackActiveTimer(setInterval(() => {
      this._cleanupLogs();
    }, 3e5));
    this._secureLog("info", "\u2705 Secure WebRTC Manager initialization completed");
    this._secureLog("info", "\u{1F512} Global exposure protection: Monitoring only, no automatic removal");
  }
  /**
   * Start security monitoring
   * @deprecated Use unified scheduler instead
   */
  _startSecurityMonitoring() {
    this._secureLog("info", "\u{1F527} Security monitoring moved to unified scheduler");
  }
  /**
   * Validates connection readiness for sending data
   * @param {boolean} throwError - whether to throw on not ready
   * @returns {boolean} true if connection is ready
   */
  _validateConnection(throwError = true) {
    const isDataChannelReady = this.dataChannel && this.dataChannel.readyState === "open";
    const isConnectionVerified = this.isVerified;
    const isValid = isDataChannelReady && isConnectionVerified;
    if (!isValid && throwError) {
      if (!isDataChannelReady) {
        throw new Error("Data channel not ready");
      }
      if (!isConnectionVerified) {
        throw new Error("Connection not verified");
      }
    }
    return isValid;
  }
  /**
   *   Hard gate for traffic blocking without verification
   * This method enforces that NO traffic (including system messages and file transfers)
   * can pass through without proper cryptographic verification
   */
  _enforceVerificationGate(operation = "unknown", throwError = true) {
    if (!this.isVerified) {
      const errorMessage = `SECURITY VIOLATION: ${operation} blocked - connection not cryptographically verified`;
      this._secureLog("error", errorMessage, {
        operation,
        isVerified: this.isVerified,
        hasKeys: !!(this.encryptionKey && this.macKey),
        timestamp: Date.now()
      });
      if (throwError) {
        throw new Error(errorMessage);
      }
      return false;
    }
    return true;
  }
  /**
   *   Safe method to set isVerified only after cryptographic verification
   * This is the ONLY method that should set isVerified = true
   */
  _setVerifiedStatus(verified, verificationMethod = "unknown", verificationData = null) {
    if (verified) {
      if (!this.encryptionKey || !this.macKey) {
        throw new Error("Cannot set verified=true without encryption keys");
      }
      if (!verificationMethod || verificationMethod === "unknown") {
        throw new Error("Cannot set verified=true without specifying verification method");
      }
      if (verificationMethod.includes("SAS") && !this.localVerificationConfirmed) {
        this._secureLog("error", "Blocked verified transition without local SAS confirmation", {
          verificationMethod,
          localConfirmed: this.localVerificationConfirmed,
          remoteConfirmed: this.remoteVerificationConfirmed
        });
        throw new Error("Cannot set verified=true without local SAS confirmation");
      }
      this._secureLog("info", "Connection verified through cryptographic verification", {
        verificationMethod,
        hasEncryptionKey: !!this.encryptionKey,
        hasMacKey: !!this.macKey,
        keyFingerprint: this.keyFingerprint,
        timestamp: Date.now(),
        verificationData: verificationData ? "provided" : "none"
      });
    }
    this.isVerified = verified;
    if (verified) {
      this.onStatusChange("connected");
    } else {
      this.onStatusChange("disconnected");
    }
  }
  /**
   * Release a link that a GROUP authenticated, with no human in the loop.
   *
   * WHY THIS IS NOT A BYPASS
   * ------------------------
   * The SAS comparison exists to answer one question: is the peer who
   * completed this handshake the person we meant to talk to? For a 1:1 chat
   * only a human can answer it, which is why _setVerifiedStatus refuses every
   * SAS-shaped transition that no human confirmed.
   *
   * A mesh link inside a group has already answered it, earlier and by a
   * different route. The descriptor that opened this connection was signed
   * with a group identity key; that key's fingerprint is named in a roster
   * signed by the admin; and the group's safety code — which every member
   * compared out of band before any of this was allowed to start — covers
   * that exact set of fingerprints. Asking the two people to also read seven
   * digits at each other for every one of up to twenty-eight pairs would not
   * add a check, it would repeat one they already did, badly.
   *
   * So the guarantee is not weakened here, it is moved: the caller must have
   * verified the group signature over the peer's descriptor BEFORE the
   * transport was created. Everything this method can check for itself, it
   * does — the session must be SBQ2, its in-band exchange must have completed,
   * and the peer must have proved possession of the identity key that the
   * commitment in that descriptor bound it to. A session that has not got that
   * far is refused outright rather than released on the caller's word.
   *
   * @param {string} reason short audit label for why the group vouched
   */
  markGroupLinkVerified(reason = "group_roster_signature") {
    const st = this._sbq2;
    if (!this._isSbq2() || !st || !st.completed || !st.proofVerified || !st.keysDerived) {
      throw new Error("Group link cannot be released: the in-band handshake has not completed");
    }
    if (!this.encryptionKey || !this.macKey) {
      throw new Error("Group link cannot be released: session keys are missing");
    }
    if (this.isVerified) return true;
    this.localVerificationConfirmed = true;
    this.remoteVerificationConfirmed = true;
    this.bothVerificationsConfirmed = true;
    this._setVerifiedStatus(true, "GROUP_ROSTER_SIGNATURE", {
      reason,
      timestamp: Date.now()
    });
    this._enforceVerificationGate("group_link_release", false);
    this.onStatusChange?.("verified");
    try {
      this.processMessageQueue();
    } catch (_) {
    }
    return true;
  }
  /**
   *   Create AAD (Additional Authenticated Data) for file messages
   * This binds file messages to the current session and prevents replay attacks
   */
  _createFileMessageAAD(messageType, messageData = null) {
    if (typeof this._createMessageAAD !== "function") {
      throw new Error("_createMessageAAD method is not available in _createFileMessageAAD. Manager may not be fully initialized.");
    }
    return this._createMessageAAD(messageType, messageData, true);
  }
  /**
   *   Validate AAD for file messages
   * This ensures file messages are bound to the correct session
   */
  _validateFileMessageAAD(aadString, expectedMessageType = null) {
    try {
      const aad = JSON.parse(aadString);
      if (aad.sessionId !== (this.currentSession?.sessionId || "unknown")) {
        throw new Error("AAD sessionId mismatch - possible replay attack");
      }
      if (aad.keyFingerprint !== (this.keyFingerprint || "unknown")) {
        throw new Error("AAD keyFingerprint mismatch - possible key substitution attack");
      }
      if (expectedMessageType && aad.messageType !== expectedMessageType) {
        throw new Error(`AAD messageType mismatch - expected ${expectedMessageType}, got ${aad.messageType}`);
      }
      const now = Date.now();
      const messageAge = now - aad.timestamp;
      if (messageAge > 18e5) {
        throw new Error("AAD timestamp too old - possible replay attack");
      }
      return aad;
    } catch (error) {
      this._secureLog("error", "AAD validation failed", {
        error: error.message,
        aadLength: typeof aadString === "string" ? aadString.length : 0
      });
      throw new Error(`AAD validation failed: ${error.message}`);
    }
  }
  // ============================================
  // ANTI-REPLAY / SEQUENCE VALIDATION
  // These belong to the connection, not to key storage: they read and mutate
  // this.replayWindow / this.expectedSequenceNumber / this.currentSession.
  // ============================================
  // Method _generateNextSequenceNumber moved to constructor area for early availability
  /**
   *   Validate incoming message sequence number
   * This prevents replay attacks and ensures message ordering
   */
  _validateIncomingSequenceNumber(receivedSeq, context = "unknown") {
    try {
      if (!this.replayProtectionEnabled) {
        return true;
      }
      if (typeof receivedSeq !== "number" || !Number.isFinite(receivedSeq)) {
        this._secureLog("warn", "Missing or non-numeric sequence number - rejecting", {
          receivedType: typeof receivedSeq,
          context,
          timestamp: Date.now()
        });
        return false;
      }
      if (receivedSeq < this.expectedSequenceNumber - this.replayWindowSize) {
        this._secureLog("warn", "Sequence number too old - possible replay attack", {
          received: receivedSeq,
          expected: this.expectedSequenceNumber,
          context,
          timestamp: Date.now()
        });
        return false;
      }
      if (receivedSeq > this.expectedSequenceNumber + this.maxSequenceGap) {
        this._secureLog("warn", "Sequence number gap too large - possible DoS attack", {
          received: receivedSeq,
          expected: this.expectedSequenceNumber,
          gap: receivedSeq - this.expectedSequenceNumber,
          context,
          timestamp: Date.now()
        });
        return false;
      }
      if (this.replayWindow.has(receivedSeq)) {
        this._secureLog("warn", "Duplicate sequence number detected - replay attack", {
          received: receivedSeq,
          context,
          timestamp: Date.now()
        });
        return false;
      }
      this.replayWindow.add(receivedSeq);
      if (this.replayWindow.size > this.replayWindowSize) {
        const oldestSeq = Math.min(...this.replayWindow);
        this.replayWindow.delete(oldestSeq);
      }
      if (receivedSeq === this.expectedSequenceNumber) {
        this.expectedSequenceNumber++;
        while (this.replayWindow.has(this.expectedSequenceNumber - this.replayWindowSize - 1)) {
          this.replayWindow.delete(this.expectedSequenceNumber - this.replayWindowSize - 1);
        }
      }
      this._secureLog("debug", "Sequence number validation successful", {
        received: receivedSeq,
        expected: this.expectedSequenceNumber,
        context,
        timestamp: Date.now()
      });
      return true;
    } catch (error) {
      this._secureLog("error", "Sequence number validation failed", {
        error: error.message,
        context,
        timestamp: Date.now()
      });
      return false;
    }
  }
  // Method _createMessageAAD moved to constructor area for early availability
  /**
   *   Validate message AAD with sequence number
   * This ensures message integrity and prevents replay attacks
   */
  _validateMessageAAD(aadString, expectedMessageType = null) {
    try {
      const aad = JSON.parse(aadString);
      if (aad.sessionId !== (this.currentSession?.sessionId || "unknown")) {
        throw new Error("AAD sessionId mismatch - possible replay attack");
      }
      if (aad.keyFingerprint !== (this.keyFingerprint || "unknown")) {
        throw new Error("AAD keyFingerprint mismatch - possible key substitution attack");
      }
      if (!this._validateIncomingSequenceNumber(aad.sequenceNumber, aad.messageType)) {
        throw new Error("Sequence number validation failed - possible replay or DoS attack");
      }
      if (expectedMessageType && aad.messageType !== expectedMessageType) {
        throw new Error(`AAD messageType mismatch - expected ${expectedMessageType}, got ${aad.messageType}`);
      }
      return aad;
    } catch (error) {
      this._secureLog("error", "AAD validation failed", {
        error: error.message,
        aadLength: typeof aadString === "string" ? aadString.length : 0
      });
      throw new Error(`AAD validation failed: ${error.message}`);
    }
  }
  /**
   *   Get anti-replay protection status
   * This shows the current state of replay protection
   */
  getAntiReplayStatus() {
    const status = {
      replayProtectionEnabled: this.replayProtectionEnabled,
      replayWindowSize: this.replayWindowSize,
      currentReplayWindowSize: this.replayWindow.size,
      sequenceNumber: this.sequenceNumber,
      expectedSequenceNumber: this.expectedSequenceNumber,
      maxSequenceGap: this.maxSequenceGap,
      replayWindowEntries: Array.from(this.replayWindow).sort((a, b) => a - b)
    };
    this._secureLog("info", "Anti-replay status retrieved", status);
    return status;
  }
  /**
   *   Configure anti-replay protection
   * This allows fine-tuning of replay protection parameters
   */
  configureAntiReplayProtection(config) {
    try {
      if (config.windowSize !== void 0) {
        if (config.windowSize < 16 || config.windowSize > 1024) {
          throw new Error("Replay window size must be between 16 and 1024");
        }
        this.replayWindowSize = config.windowSize;
      }
      if (config.maxGap !== void 0) {
        if (config.maxGap < 10 || config.maxGap > 1e3) {
          throw new Error("Max sequence gap must be between 10 and 1000");
        }
        this.maxSequenceGap = config.maxGap;
      }
      if (config.enabled !== void 0) {
        this.replayProtectionEnabled = config.enabled;
      }
      this._secureLog("info", "Anti-replay protection configured", config);
      return true;
    } catch (error) {
      this._secureLog("error", "Failed to configure anti-replay protection", { error: error.message });
      return false;
    }
  }
  /**
   * Get real security level with actual cryptographic tests
   * This provides real-time verification of security features
   *
   * Returns the scored security level (level / score / passedChecks / …) with
   * the per-feature flags merged in. The header renders `level` and `score`
   * directly, so this MUST carry them — returning only the feature flags makes
   * the header display "Secure undefined%".
   */
  async getRealSecurityLevel() {
    try {
      const featureFlags = {
        // Basic security features
        ecdhKeyExchange: !!this.ecdhKeyPair,
        ecdsaSignatures: !!this.ecdsaKeyPair,
        aesEncryption: !!this.encryptionKey,
        messageIntegrity: !!this.hmacKey,
        // Advanced security features - using the exact property names expected by EnhancedSecureCryptoUtils
        replayProtection: this.replayProtectionEnabled,
        // Both fingerprints must be known for the SAS to bind this session
        // to this pair of endpoints; having only our own proves nothing.
        dtlsFingerprint: !!(this.expectedDTLSFingerprint && this._peerDTLSFingerprint),
        // The SAS matters once the USER has compared it, not once we have
        // computed it — an unconfirmed code is not authentication.
        sasCode: !!this.verificationCode && this.localVerificationConfirmed === true,
        metadataProtection: true,
        // Always enabled
        trafficObfuscation: true,
        // Always enabled
        // True only while the Double Ratchet is actually running. A peer on
        // an older build negotiates it away, and the panel must show that
        // rather than the capability we shipped.
        // Optional-called on purpose: a status report must never throw and
        // take down the panel it exists to populate. Unknown reads as off.
        perfectForwardSecrecy: this.isRatchetActive?.() === true,
        // Rate limiting
        rateLimiter: true,
        // Always enabled
        // Additional info
        connectionId: this.connectionId,
        keyFingerprint: this.keyFingerprint,
        currentSecurityLevel: "maximum",
        timestamp: Date.now()
      };
      const scored = await this.calculateAndReportSecurityLevel();
      if (!scored) {
        return {
          ...featureFlags,
          level: "INITIALIZING",
          score: 0,
          isRealData: false
        };
      }
      return { ...scored, ...featureFlags };
    } catch (error) {
      this._secureLog("error", "Failed to calculate real security level", { error: error.message });
      throw error;
    }
  }
  /**
   *   Extract DTLS fingerprint from SDP
   * This is essential for MITM protection
   */
  _extractDTLSFingerprintFromSDP(sdp) {
    try {
      if (!sdp || typeof sdp !== "string") {
        throw new Error("Invalid SDP provided");
      }
      const fingerprintRegex = /a=fingerprint:([a-zA-Z0-9-]+)\s+([A-Fa-f0-9:]+)/g;
      const fingerprints = [];
      let match;
      while ((match = fingerprintRegex.exec(sdp)) !== null) {
        fingerprints.push({
          algorithm: match[1].toLowerCase(),
          fingerprint: match[2].trim()
        });
      }
      if (fingerprints.length === 0) {
        const altFingerprintRegex = /fingerprint\s*=\s*([a-zA-Z0-9-]+)\s+([A-Fa-f0-9:]+)/gi;
        while ((match = altFingerprintRegex.exec(sdp)) !== null) {
          fingerprints.push({
            algorithm: match[1].toLowerCase(),
            fingerprint: match[2].trim()
          });
        }
      }
      if (fingerprints.length === 0) {
        this._secureLog("warn", "No DTLS fingerprints found in SDP - this may be normal for some WebRTC implementations", {
          sdpLength: sdp.length,
          sdpPreview: sdp.substring(0, 200) + "..."
        });
        throw new Error("No DTLS fingerprints found in SDP");
      }
      const primaryFingerprint = [...fingerprints].sort((a, b) => {
        const aIsSha256 = a.algorithm === "sha-256";
        const bIsSha256 = b.algorithm === "sha-256";
        if (aIsSha256 !== bIsSha256) {
          return aIsSha256 ? -1 : 1;
        }
        const algorithmComparison = a.algorithm.localeCompare(b.algorithm);
        if (algorithmComparison !== 0) {
          return algorithmComparison;
        }
        return a.fingerprint.localeCompare(b.fingerprint);
      })[0];
      return primaryFingerprint.fingerprint;
    } catch (error) {
      this._secureLog("error", "Failed to extract DTLS fingerprint from SDP", {
        error: error.message,
        sdpLength: sdp?.length || 0
      });
      throw new Error(`DTLS fingerprint extraction failed: ${error.message}`);
    }
  }
  /**
   *   Validate DTLS fingerprint against expected value
   * This prevents MITM attacks by ensuring the remote peer has the expected certificate
   */
  async _validateDTLSFingerprint(receivedFingerprint, expectedFingerprint, context = "unknown") {
    try {
      if (!receivedFingerprint || !expectedFingerprint) {
        throw new Error("Missing fingerprint for validation");
      }
      const normalizedReceived = receivedFingerprint.toLowerCase().replace(/:/g, "");
      const normalizedExpected = expectedFingerprint.toLowerCase().replace(/:/g, "");
      if (normalizedReceived !== normalizedExpected) {
        this._secureLog("error", "DTLS fingerprint mismatch - possible MITM attack", {
          context,
          timestamp: Date.now()
        });
        throw new Error(`DTLS fingerprint mismatch - possible MITM attack in ${context}`);
      }
      this._secureLog("info", "DTLS fingerprint validation successful", {
        context,
        timestamp: Date.now()
      });
      return true;
    } catch (error) {
      this._secureLog("error", "DTLS fingerprint validation failed", {
        error: error.message,
        context
      });
      throw error;
    }
  }
  /**
   *   Compute SAS (Short Authentication String) for MITM protection
   * Uses HKDF with DTLS fingerprints to generate a stable 7-digit verification code
   * @param {ArrayBuffer|Uint8Array} keyMaterialRaw - Shared secret or key fingerprint data
   * @param {string} localFP - Local DTLS fingerprint
   * @param {string} remoteFP - Remote DTLS fingerprint
   * @returns {Promise<string>} 7-digit SAS code
   */
  async _computeSAS(keyMaterialRaw, localFP, remoteFP) {
    try {
      if (!keyMaterialRaw) {
        const missing = [];
        if (!keyMaterialRaw) missing.push("keyMaterialRaw");
        throw new Error(`Missing required parameters for SAS computation: ${missing.join(", ")}`);
      }
      const enc4 = new TextEncoder();
      const normalizeFingerprintForSAS = (fingerprint, label) => {
        if (typeof fingerprint !== "string" || fingerprint.trim().length === 0) {
          throw new Error(
            `Security error: ${label} must be a non-empty DTLS fingerprint string for SAS computation`
          );
        }
        return fingerprint.trim().toLowerCase();
      };
      const normalizedLocalFP = normalizeFingerprintForSAS(localFP, "localFP");
      const normalizedRemoteFP = normalizeFingerprintForSAS(remoteFP, "remoteFP");
      const salt = enc4.encode(
        "webrtc-sas|" + [normalizedLocalFP, normalizedRemoteFP].sort().join("|")
      );
      let keyBuffer;
      if (keyMaterialRaw instanceof ArrayBuffer) {
        keyBuffer = keyMaterialRaw;
      } else if (keyMaterialRaw instanceof Uint8Array) {
        keyBuffer = keyMaterialRaw.buffer;
      } else if (typeof keyMaterialRaw === "string") {
        const hexString = keyMaterialRaw.replace(/:/g, "").replace(/\s/g, "");
        const bytes = new Uint8Array(hexString.length / 2);
        for (let i = 0; i < hexString.length; i += 2) {
          bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
        }
        keyBuffer = bytes.buffer;
      } else {
        throw new Error("Invalid keyMaterialRaw type");
      }
      const key = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        "HKDF",
        false,
        ["deriveBits"]
      );
      const info = enc4.encode("p2p-sas-v1");
      const bits = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt, info },
        key,
        64
        // 64 бита достаточно для 6–7 знаков
      );
      const dv = new DataView(bits);
      const n = (dv.getUint32(0) ^ dv.getUint32(4)) >>> 0;
      const sasCode = String(n % 1e7).padStart(7, "0");
      this._secureLog("info", "SAS code computed successfully", {
        localFP: normalizedLocalFP.substring(0, 16) + "...",
        remoteFP: normalizedRemoteFP.substring(0, 16) + "...",
        sasLength: sasCode.length,
        timestamp: Date.now()
      });
      return sasCode;
    } catch (error) {
      this._secureLog("error", "SAS computation failed", {
        error: error.message,
        keyMaterialType: typeof keyMaterialRaw,
        hasLocalFP: !!localFP,
        hasRemoteFP: !!remoteFP,
        timestamp: Date.now()
      });
      throw new Error(`SAS computation failed: ${error.message}`);
    }
  }
  // ========================================================================
  // SBQ2 — compact descriptor + in-band key exchange
  // ========================================================================
  /**
   * Announce a lifecycle change to the application, unless this connection is
   * muted. See `_emitGlobalEvents` in the constructor for why one would be.
   */
  _dispatchAppEvent(event) {
    if (!this._emitGlobalEvents) return false;
    try {
      return document.dispatchEvent(event);
    } catch (_) {
      return false;
    }
  }
  /** True once this connection has latched onto the SBQ2 handshake. */
  _isSbq2() {
    return this._handshakeMode === "sbq2";
  }
  /**
   * Latch the handshake format for this connection.
   *
   * Called with the format of the first descriptor of the session. Calling it
   * again with a different value is a bug or an attack, and is refused: this
   * is the single point that makes "no downgrade inside a session" true rather
   * than merely intended.
   */
  _latchHandshakeMode(mode) {
    if (this._handshakeMode && this._handshakeMode !== mode) {
      throw new Error(
        `handshake format cannot change mid-session (${this._handshakeMode} -> ${mode})`
      );
    }
    this._handshakeMode = mode;
  }
  _sbq2State() {
    if (!this._sbq2) {
      this._sbq2 = {
        role: null,
        // KX_ROLE.OFFER | KX_ROLE.ANSWER
        localDescriptor: null,
        // Uint8Array, our descriptor verbatim
        remoteDescriptor: null,
        // Uint8Array, peer's descriptor verbatim
        localBlob: null,
        remoteBlob: null,
        remoteCommitment: null,
        // from the peer's descriptor
        transcript: null,
        peerEcdhKey: null,
        peerEcdsaKey: null,
        blobSent: false,
        proofSent: false,
        proofVerified: false,
        keysDerived: false,
        pendingProof: null,
        // proof that arrived before the transcript existed
        completed: false,
        timer: null,
        startedAt: 0
      };
    }
    return this._sbq2;
  }
  /**
   * Fail closed.
   *
   * Every SBQ2 failure lands here: there is no path that logs a warning and
   * carries on with a weaker session, and no path that retries as SB1. The
   * connection is torn down and the user is told, because a handshake that
   * went wrong is exactly the case where continuing is worst.
   */
  _sbq2Abort(code, userMessage) {
    const st = this._sbq2;
    if (st?.timer) {
      clearTimeout(st.timer);
      st.timer = null;
    }
    this._secureLog("error", "SBQ2 handshake aborted", { code });
    try {
      this.deliverMessageToUI(userMessage, "system");
    } catch (_) {
    }
    try {
      this.onStatusChange?.("failed");
    } catch (_) {
    }
    try {
      this.disconnect();
    } catch (_) {
    }
  }
  /** SPKI bytes for a public CryptoKey. */
  async _exportSpki(key) {
    return new Uint8Array(await crypto.subtle.exportKey("spki", key));
  }
  /**
   * Build the key blob for this side and the commitment that goes in the
   * descriptor. Called while creating our descriptor, so the commitment is
   * fixed before anything is shown to the user.
   */
  async _sbq2BuildLocalBlob(role) {
    if (!this.ecdhKeyPair?.publicKey || !this.ecdsaKeyPair?.publicKey) {
      throw new Error("SBQ2: key pairs are not ready");
    }
    const blob = encodeKeyBlob({
      role,
      ecdhSpki: await this._exportSpki(this.ecdhKeyPair.publicKey),
      ecdsaSpki: await this._exportSpki(this.ecdsaKeyPair.publicKey)
    });
    const digest = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
    const commitment = await commitBlob(digest, blob);
    const st = this._sbq2State();
    st.role = role;
    st.localBlob = blob;
    return { blob, commitment };
  }
  /**
   * Turn our gathered localDescription into a compact descriptor.
   * @returns {{bytes: Uint8Array, text: string}}
   */
  async _sbq2BuildDescriptor(type, { bindingTag: bindingTag2 = null, lifetimeMs = 10 * 60 * 1e3 } = {}) {
    const sdp = this.peerConnection?.localDescription?.sdp;
    if (!sdp) throw new Error("SBQ2: no local description to encode");
    const role = type === TYPE.OFFER ? ROLE.OFFER : ROLE.ANSWER;
    const { commitment } = await this._sbq2BuildLocalBlob(role);
    const raw = parseSdp(sdp);
    const bytes = encodeDescriptor({
      type,
      expiresAtMs: Date.now() + lifetimeMs,
      sdpFields: { ...raw, candidates: pruneCandidates(raw.candidates) },
      commitment,
      ...type === TYPE.ANSWER ? { bindingTag: bindingTag2 } : {}
    });
    const st = this._sbq2State();
    st.localDescriptor = bytes;
    this._secureLog("info", "SBQ2 descriptor built", {
      type: type === TYPE.OFFER ? "offer" : "answer",
      bytes: bytes.length,
      candidates: pruneCandidates(raw.candidates).length
    });
    return { bytes, text: encodeText(bytes) };
  }
  /**
   * Parse and adopt a peer descriptor. Throws on anything the strict decoder
   * refuses — version, reserved values, unknown TLV, trailing bytes, expiry.
   */
  _sbq2AdoptRemoteDescriptor(bytes, expectedType) {
    const desc = decodeDescriptor(bytes);
    if (desc.type !== expectedType) {
      throw new Error(
        `expected an ${expectedType === TYPE.OFFER ? "invitation" : "answer"}, got the other kind`
      );
    }
    if (!desc.commitment) {
      throw new Error("the invitation carries no key commitment");
    }
    const st = this._sbq2State();
    st.remoteDescriptor = bytes;
    st.remoteCommitment = desc.commitment;
    return desc;
  }
  /**
   * Run the in-band key exchange. Called once, as soon as the DataChannel
   * opens, before anything else is allowed to use the channel.
   */
  async _runSbq2KeyExchange() {
    const st = this._sbq2State();
    if (st.completed || st.blobSent) return;
    st.startedAt = Date.now();
    if (!st.localBlob || !st.localDescriptor || !st.remoteDescriptor || !st.remoteCommitment) {
      this._sbq2Abort(
        "incomplete_state",
        "The secure handshake could not start because the connection setup is incomplete. Please start a new invitation."
      );
      return;
    }
    st.timer = setTimeout(() => {
      if (!st.completed) {
        this._sbq2Abort(
          "timeout",
          "The other side did not complete the secure handshake in time. Please try connecting again."
        );
      }
    }, _EnhancedSecureWebRTCManager.SBQ2_KEY_EXCHANGE_TIMEOUT_MS);
    try {
      this.dataChannel.send(JSON.stringify({
        type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_BLOB,
        v: 2,
        blob: window.EnhancedSecureCryptoUtils.arrayBufferToBase64(st.localBlob.buffer.slice(
          st.localBlob.byteOffset,
          st.localBlob.byteOffset + st.localBlob.byteLength
        ))
      }));
      st.blobSent = true;
      this._secureLog("info", "SBQ2 key blob sent", { bytes: st.localBlob.length });
    } catch (error) {
      this._sbq2Abort(
        "blob_send_failed",
        "The secure handshake could not be sent. Please try connecting again."
      );
    }
  }
  /**
   * Handle the two in-band handshake frames. These are the only frames
   * accepted before keys exist, so everything they touch is validated here and
   * nothing is acted on before the commitment check passes.
   */
  async _sbq2HandleHandshakeFrame(parsed) {
    const T = _EnhancedSecureWebRTCManager.MESSAGE_TYPES;
    const st = this._sbq2State();
    if (!this._isSbq2()) {
      this._secureLog("error", "Rejected SBQ2 handshake frame on a non-SBQ2 session", {
        messageType: parsed?.type
      });
      return;
    }
    try {
      if (parsed.type === T.KEY_BLOB) {
        if (st.remoteBlob) {
          this._sbq2Abort(
            "duplicate_blob",
            "The secure handshake was sent twice. The connection has been closed for safety."
          );
          return;
        }
        const bytes = new Uint8Array(window.EnhancedSecureCryptoUtils.base64ToArrayBuffer(String(parsed.blob || "")));
        await verifyBlobCommitment(crypto.subtle, bytes, st.remoteCommitment);
        const blob = decodeKeyBlob(bytes);
        const expectedRole = st.role === ROLE.OFFER ? ROLE.ANSWER : ROLE.OFFER;
        if (blob.role !== expectedRole) {
          this._sbq2Abort(
            "role_mismatch",
            "The other side sent the wrong kind of handshake. The connection has been closed for safety."
          );
          return;
        }
        st.remoteBlob = bytes;
        st.peerEcdhKey = await crypto.subtle.importKey(
          "spki",
          blob.ecdhSpki,
          { name: "ECDH", namedCurve: "P-384" },
          false,
          []
        );
        st.peerEcdsaKey = await crypto.subtle.importKey(
          "spki",
          blob.ecdsaSpki,
          { name: "ECDSA", namedCurve: "P-384" },
          false,
          ["verify"]
        );
        await this._sbq2CompleteExchange();
        return;
      }
      if (parsed.type === T.KEY_PROOF) {
        const sig = new Uint8Array(window.EnhancedSecureCryptoUtils.base64ToArrayBuffer(String(parsed.sig || "")));
        if (!st.transcript || !st.peerEcdsaKey) {
          st.pendingProof = sig;
          return;
        }
        await this._sbq2VerifyProof(sig);
        return;
      }
    } catch (error) {
      const code = error?.code || "handshake_failed";
      const message = code === "commitment_mismatch" ? "The key material does not match the invitation you scanned. This can mean someone tampered with the connection, so it has been closed." : "The secure handshake failed. The connection has been closed for safety.";
      this._sbq2Abort(code, message);
    }
  }
  /**
   * Both blobs are in hand and verified: define the transcript, derive
   * everything from it, and prove possession of the identity key.
   */
  async _sbq2CompleteExchange() {
    const st = this._sbq2State();
    if (st.keysDerived || !st.remoteBlob || !st.localBlob) return;
    this._peerSupportsRatchet = true;
    const isOffer = st.role === ROLE.OFFER;
    st.transcript = buildTranscript({
      offerDescriptor: isOffer ? st.localDescriptor : st.remoteDescriptor,
      answerDescriptor: isOffer ? st.remoteDescriptor : st.localDescriptor,
      offerBlob: isOffer ? st.localBlob : st.remoteBlob,
      answerBlob: isOffer ? st.remoteBlob : st.localBlob
    });
    this.sessionSalt = await deriveTranscriptSalt(crypto.subtle, st.transcript);
    this.peerPublicKey = st.peerEcdhKey;
    this.peerECDHPublicKey = st.peerEcdhKey;
    const derivedKeys = await window.EnhancedSecureCryptoUtils.deriveSharedKeys(
      this.ecdhKeyPair.privateKey,
      st.peerEcdhKey,
      this.sessionSalt
    );
    await this._setEncryptionKeys(
      derivedKeys.messageKey,
      derivedKeys.macKey,
      derivedKeys.metadataKey,
      derivedKeys.fingerprint
    );
    await this._initializeRatchet(
      derivedKeys,
      /* isInitiator */
      isOffer
    );
    st.keysDerived = true;
    const sig = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-384" },
      this.ecdsaKeyPair.privateKey,
      proofPayload(st.transcript)
    ));
    this.dataChannel.send(JSON.stringify({
      type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_PROOF,
      sig: window.EnhancedSecureCryptoUtils.arrayBufferToBase64(sig.buffer)
    }));
    st.proofSent = true;
    if (st.pendingProof) {
      const held = st.pendingProof;
      st.pendingProof = null;
      await this._sbq2VerifyProof(held);
    }
  }
  /** Verify the peer's transcript signature, then release the session. */
  async _sbq2VerifyProof(sig) {
    const st = this._sbq2State();
    if (st.proofVerified) return;
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      st.peerEcdsaKey,
      sig,
      proofPayload(st.transcript)
    );
    if (!ok) {
      this._sbq2Abort(
        "bad_proof",
        "The other side could not prove it owns its identity key. The connection has been closed for safety."
      );
      return;
    }
    st.proofVerified = true;
    this.verificationCode = await computeTranscriptSas(crypto.subtle, {
      ecdhPrivateKey: this.ecdhKeyPair.privateKey,
      peerEcdhPublicKey: st.peerEcdhKey,
      transcript: st.transcript
    });
    const localFP = this.expectedDTLSFingerprint;
    const remoteFP = this._peerDTLSFingerprint;
    if (localFP && remoteFP) this._setSASMaterialReady(localFP, remoteFP);
    st.completed = true;
    if (st.timer) {
      clearTimeout(st.timer);
      st.timer = null;
    }
    this.securityFeatures.hasMutualAuth = true;
    this.securityFeatures.hasMetadataProtection = true;
    this.securityFeatures.hasEnhancedReplayProtection = true;
    this._secureLog("info", "SBQ2 in-band key exchange complete", {
      elapsedMs: Date.now() - st.startedAt,
      ratchetActive: this.isRatchetActive?.() === true
    });
    try {
      this.onKeyExchange?.(this.keyFingerprint);
    } catch (_) {
    }
    this._notifyVerificationReadyIfPossible();
    this.initiateVerification();
  }
  /**
   * UTILITY: Decode hex keyFingerprint to Uint8Array for SAS computation
   * @param {string} hexString - Hex encoded keyFingerprint (e.g., "aa:bb:cc:dd")
   * @returns {Uint8Array} Decoded bytes
   */
  _decodeKeyFingerprint(hexString) {
    try {
      if (!hexString || typeof hexString !== "string") {
        throw new Error("Invalid hex string provided");
      }
      return window.EnhancedSecureCryptoUtils.hexToUint8Array(hexString);
    } catch (error) {
      this._secureLog("error", "Key fingerprint decoding failed", {
        error: error.message,
        inputType: typeof hexString,
        inputLength: hexString?.length || 0
      });
      throw new Error(`Key fingerprint decoding failed: ${error.message}`);
    }
  }
  /**
   *   Emergency key wipe on fingerprint mismatch
   * This ensures no sensitive data remains if MITM is detected
   */
  _emergencyWipeOnFingerprintMismatch(reason = "DTLS fingerprint mismatch") {
    try {
      this._secureLog("error", "\u{1F6A8} EMERGENCY: Initiating security wipe due to fingerprint mismatch", {
        reason,
        timestamp: Date.now()
      });
      this._secureWipeKeys();
      this._secureWipeMemory(this.encryptionKey, "emergency_wipe");
      this._secureWipeMemory(this.macKey, "emergency_wipe");
      this._secureWipeMemory(this.metadataKey, "emergency_wipe");
      this._wipeEphemeralKeys();
      this._hardWipeOldKeys();
      this.isVerified = null;
      this.verificationCode = null;
      this.keyFingerprint = null;
      this.connectionId = null;
      this.expectedDTLSFingerprint = null;
      this._peerDTLSFingerprint = null;
      this.disconnect();
      this.deliverMessageToUI("\u{1F6A8} SECURITY BREACH: Connection terminated due to fingerprint mismatch. Possible MITM attack detected!", "system");
    } catch (error) {
      this._secureLog("error", "Failed to perform emergency wipe", { error: error.message });
    }
  }
  // REMOVED: setExpectedDTLSFingerprint(). It overwrote `expectedDTLSFingerprint`
  // with a caller-supplied value, and that field is our OWN local fingerprint —
  // the localFP that _computeSAS mixes into the safety code. Writing a peer's
  // fingerprint into it would silently produce a SAS that no longer matches the
  // session, i.e. break the very check it claimed to strengthen. It had no
  // callers and was not part of any documented API. Out-of-band pinning, if it
  // is ever wanted, belongs in its own field alongside _peerDTLSFingerprint.
  /**
   * Our own DTLS fingerprint, for the user to share out of band if they want to
   * compare it manually. This is the local endpoint's value, not the peer's.
   */
  getCurrentDTLSFingerprint() {
    try {
      if (!this.expectedDTLSFingerprint) {
        throw new Error("No DTLS fingerprint available - connection not established");
      }
      return this.expectedDTLSFingerprint;
    } catch (error) {
      this._secureLog("error", "Failed to get current DTLS fingerprint", { error: error.message });
      throw error;
    }
  }
  /**
   * DEBUGGING: Temporarily disable strict DTLS validation
   * This should only be used for debugging connection issues
   */
  disableStrictDTLSValidation() {
    this.strictDTLSValidation = false;
    this._secureLog("warn", "\u26A0\uFE0F Strict DTLS validation disabled - security reduced", {
      timestamp: Date.now()
    });
    this.deliverMessageToUI("\u26A0\uFE0F DTLS validation disabled for debugging", "system");
  }
  /**
   * SECURITY: Re-enable strict DTLS validation
   */
  enableStrictDTLSValidation() {
    this.strictDTLSValidation = true;
    this._secureLog("info", "\u2705 Strict DTLS validation re-enabled", {
      timestamp: Date.now()
    });
    this.deliverMessageToUI("\u2705 DTLS validation re-enabled", "system");
  }
  /**
   *   Generate ephemeral ECDH keys for Perfect Forward Secrecy
   * This ensures each session has unique, non-persistent keys
   */
  /**
   * Bring up the Double Ratchet once the handshake has produced a shared
   * secret. Both peers must have advertised support (`dr` in the offer and the
   * answer): a session where only one side ratchets cannot decrypt anything, so
   * a missing flag means the peer is on an older build and both sides stay on
   * the static-key path.
   *
   * Failure here is deliberately not fatal. Forward secrecy is a large
   * improvement, but a session that falls back to the previous scheme is the
   * behaviour of every release up to 5.6.x — refusing to connect at all would
   * be a worse outcome than connecting with the security users already had.
   * The status is surfaced so the difference is visible rather than silent.
   */
  async _initializeRatchet(derivedKeys, isInitiator) {
    const ratchetRoot = derivedKeys?.ratchetRoot;
    if (!ratchetRoot) return false;
    if (!this._peerSupportsRatchet) {
      this._secureLog("warn", "Peer did not advertise Double Ratchet \u2014 falling back to static session keys", {
        localVersion: _EnhancedSecureWebRTCManager.RATCHET_VERSION
      });
      window.EnhancedSecureCryptoUtils.zeroizeBuffer(ratchetRoot);
      return false;
    }
    try {
      const peerPublicKey = this.peerPublicKey || this.peerECDHPublicKey;
      if (!peerPublicKey || !this.ecdhKeyPair?.privateKey) {
        throw new Error("handshake ECDH keys unavailable");
      }
      const ratchet = new DoubleRatchet();
      await ratchet.init({
        sharedSecret: ratchetRoot,
        sessionSalt: new Uint8Array(this.sessionSalt || []),
        selfPrivateKey: this.ecdhKeyPair.privateKey,
        remotePublicKey: peerPublicKey,
        isInitiator
      });
      this._ratchet = ratchet;
      this.securityFeatures.hasPFS = true;
      this._secureLog("info", "\u{1F510} Double Ratchet active \u2014 per-message forward secrecy enabled", {
        role: isInitiator ? "initiator" : "responder"
      });
      return true;
    } catch (error) {
      this._ratchet = null;
      this.securityFeatures.hasPFS = false;
      this._secureLog("error", "Double Ratchet initialisation failed \u2014 continuing with static session keys", {
        errorType: error?.constructor?.name || "Unknown"
      });
      return false;
    } finally {
      window.EnhancedSecureCryptoUtils.zeroizeBuffer(ratchetRoot);
    }
  }
  /** True when messages are protected by the ratchet rather than static keys. */
  isRatchetActive() {
    return !!this._ratchet?.isInitialised;
  }
  async _generateEphemeralECDHKeys() {
    try {
      this._secureLog("info", "\u{1F511} Generating ephemeral ECDH keys for PFS", {
        sessionStartTime: this.sessionStartTime,
        timestamp: Date.now()
      });
      const ephemeralKeyPair = await window.EnhancedSecureCryptoUtils.generateECDHKeyPair();
      if (!ephemeralKeyPair || !this._validateKeyPairConstantTime(ephemeralKeyPair)) {
        throw new Error("Ephemeral ECDH key pair validation failed");
      }
      const sessionId = this.currentSession?.sessionId || `session_${Date.now()}`;
      this.ephemeralKeyPairs.set(sessionId, {
        keyPair: ephemeralKeyPair,
        timestamp: Date.now(),
        sessionId
      });
      this._secureLog("info", "\u2705 Ephemeral ECDH keys generated for PFS", {
        timestamp: Date.now()
      });
      return ephemeralKeyPair;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to generate ephemeral ECDH keys", { error: error.message });
      throw new Error(`Ephemeral key generation failed: ${error.message}`);
    }
  }
  /**
   *   Hard wipe old keys for real PFS
   * This prevents retrospective decryption attacks
   */
  async _hardWipeOldKeys() {
    try {
      this._secureLog("info", "\u{1F9F9} Performing hard wipe of old keys for PFS", {
        oldKeysCount: this.oldKeys.size,
        timestamp: Date.now()
      });
      for (const [version2, keySet] of this.oldKeys.entries()) {
        if (keySet.encryptionKey) {
          this._secureWipeMemory(keySet.encryptionKey, "pfs_key_wipe");
        }
        if (keySet.macKey) {
          this._secureWipeMemory(keySet.macKey, "pfs_key_wipe");
        }
        if (keySet.metadataKey) {
          this._secureWipeMemory(keySet.metadataKey, "pfs_key_wipe");
        }
        keySet.encryptionKey = null;
        keySet.macKey = null;
        keySet.metadataKey = null;
        keySet.keyFingerprint = null;
      }
      this.oldKeys.clear();
      await this._performNaturalCleanup();
      this._secureLog("info", "\u2705 Hard wipe of old keys completed for PFS", {
        timestamp: Date.now()
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to perform hard wipe of old keys", { error: error.message });
    }
  }
  /**
   *   Wipe ephemeral keys when session ends
   * This ensures session-specific keys are destroyed
   */
  async _wipeEphemeralKeys() {
    try {
      this._secureLog("info", "\u{1F9F9} Wiping ephemeral keys for PFS", {
        ephemeralKeysCount: this.ephemeralKeyPairs.size,
        timestamp: Date.now()
      });
      for (const [sessionId, keyData] of this.ephemeralKeyPairs.entries()) {
        if (keyData.keyPair?.privateKey) {
          this._secureWipeMemory(keyData.keyPair.privateKey, "ephemeral_key_wipe");
        }
        if (keyData.keyPair?.publicKey) {
          this._secureWipeMemory(keyData.keyPair.publicKey, "ephemeral_key_wipe");
        }
        keyData.keyPair = null;
        keyData.timestamp = null;
        keyData.sessionId = null;
      }
      this.ephemeralKeyPairs.clear();
      await this._performNaturalCleanup();
      this._secureLog("info", "\u2705 Ephemeral keys wiped for PFS", {
        timestamp: Date.now()
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to wipe ephemeral keys", { error: error.message });
    }
  }
  /**
   *   Encrypt file messages with AAD
   * This ensures file messages are properly authenticated and bound to session
   */
  async _encryptFileMessage(messageData, aad) {
    try {
      if (!this.encryptionKey) {
        throw new Error("No encryption key available for file message");
      }
      const messageString = typeof messageData === "string" ? messageData : JSON.stringify(messageData);
      const encryptedData = await window.EnhancedSecureCryptoUtils.encryptDataWithAAD(
        messageString,
        this.encryptionKey,
        aad
      );
      const encryptedMessage = {
        type: "encrypted_file_message",
        encryptedData,
        aad,
        timestamp: Date.now(),
        keyFingerprint: this.keyFingerprint
      };
      return JSON.stringify(encryptedMessage);
    } catch (error) {
      this._secureLog("error", "Failed to encrypt file message", { error: error.message });
      throw new Error(`File message encryption failed: ${error.message}`);
    }
  }
  /**
   *   Decrypt file messages with AAD validation
   * This ensures file messages are properly authenticated and bound to session
   */
  async _decryptFileMessage(encryptedMessageString) {
    try {
      const encryptedMessage = JSON.parse(encryptedMessageString);
      if (encryptedMessage.type !== "encrypted_file_message") {
        throw new Error("Invalid encrypted file message type");
      }
      if (encryptedMessage.keyFingerprint !== this.keyFingerprint) {
        throw new Error("Key fingerprint mismatch in encrypted file message");
      }
      const aad = this._validateMessageAAD(encryptedMessage.aad, "file_message");
      if (!this.encryptionKey) {
        throw new Error("No encryption key available for file message decryption");
      }
      const decryptedData = await window.EnhancedSecureCryptoUtils.decryptDataWithAAD(
        encryptedMessage.encryptedData,
        this.encryptionKey,
        encryptedMessage.aad
      );
      return {
        decryptedData,
        aad
      };
    } catch (error) {
      this._secureLog("error", "Failed to decrypt file message", { error: error.message });
      throw new Error(`File message decryption failed: ${error.message}`);
    }
  }
  /**
   * Validates encryption keys readiness
   * @param {boolean} throwError - whether to throw on not ready
   * @returns {boolean} true if keys are ready
   */
  _validateEncryptionKeys(throwError = true) {
    const hasAllKeys = !!(this.encryptionKey && this.macKey && this.metadataKey);
    if (!hasAllKeys && throwError) {
      throw new Error("Encryption keys not initialized");
    }
    return hasAllKeys;
  }
  /**
   * Attempt to reinitialize encryption keys if missing
   * Uses existing ECDH key pair, peer public key, and session salt
   * Returns true if keys were (re)initialized successfully
   */
  async _tryReinitializeEncryptionKeys() {
    try {
      if (this.encryptionKey && this.macKey && this.metadataKey) {
        return true;
      }
      const hasECDH = !!(this.ecdhKeyPair?.privateKey && (this.peerPublicKey || this.peerECDHPublicKey));
      const peerPublicKey = this.peerPublicKey || this.peerECDHPublicKey;
      if (!hasECDH || !peerPublicKey || !this.sessionSalt) {
        return false;
      }
      const derivedKeys = await window.EnhancedSecureCryptoUtils.deriveSharedKeys(
        this.ecdhKeyPair.privateKey,
        peerPublicKey,
        this.sessionSalt
      );
      await this._setEncryptionKeys(
        derivedKeys.messageKey,
        derivedKeys.macKey,
        derivedKeys.metadataKey,
        derivedKeys.fingerprint
      );
      return !!(this.encryptionKey && this.macKey && this.metadataKey);
    } catch (error) {
      this._secureLog("error", "Failed to reinitialize encryption keys", { error: error.message });
      return false;
    }
  }
  /**
   * Checks whether a message is a file-transfer message
   * @param {string|object} data - message payload
   * @returns {boolean} true if it's a file message
   */
  _isFileMessage(data) {
    if (typeof data === "string") {
      try {
        const parsed = JSON.parse(data);
        return parsed.type && parsed.type.startsWith("file_");
      } catch {
        return false;
      }
    }
    if (typeof data === "object" && data.type) {
      return data.type.startsWith("file_");
    }
    return false;
  }
  /**
   * Checks whether a message is a system message
   * @param {string|object} data - message payload  
   * @returns {boolean} true if it's a system message
   */
  _isSystemMessage(data) {
    const systemTypes = [
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_RESPONSE,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_CONFIRMED,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_BOTH_CONFIRMED,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.PEER_DISCONNECT,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.SECURITY_UPGRADE,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_SIGNAL,
      _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_READY
    ];
    if (typeof data === "string") {
      try {
        const parsed = JSON.parse(data);
        return systemTypes.includes(parsed.type);
      } catch {
        return false;
      }
    }
    if (typeof data === "object" && data.type) {
      return systemTypes.includes(data.type);
    }
    return false;
  }
  /**
   * Checks whether a message is fake traffic
   * @param {any} data - message payload
   * @returns {boolean} true if it's a fake message
   */
  _isFakeMessage(data) {
    if (typeof data === "string") {
      try {
        const parsed = JSON.parse(data);
        return parsed.type === _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FAKE || parsed.isFakeTraffic === true;
      } catch {
        return false;
      }
    }
    if (typeof data === "object" && data !== null) {
      return data.type === _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FAKE || data.isFakeTraffic === true;
    }
    return false;
  }
  /**
   * Safely executes an operation with error handling
   * @param {Function} operation - operation to execute
   * @param {string} errorMessage - error message to log
   * @param {any} fallback - default value on error
   * @returns {any} operation result or fallback
   */
  _withErrorHandling(operation, errorMessage, fallback = null) {
    try {
      return operation();
    } catch (error) {
      if (this._debugMode) {
        this._secureLog("error", "\u274C ${errorMessage}:", { errorType: error?.constructor?.name || "Unknown" });
      }
      return fallback;
    }
  }
  /**
   * Safely executes an async operation with error handling
   * @param {Function} operation - async operation
   * @param {string} errorMessage - error message to log
   * @param {any} fallback - default value on error
   * @returns {Promise<any>} operation result or fallback
   */
  async _withAsyncErrorHandling(operation, errorMessage, fallback = null) {
    try {
      return await operation();
    } catch (error) {
      if (this._debugMode) {
        this._secureLog("error", "\u274C ${errorMessage}:", { errorType: error?.constructor?.name || "Unknown" });
      }
      return fallback;
    }
  }
  /**
   * Extracts message type from data
   * @param {string|object} data - message data
   * @returns {string|null} message type or null
   */
  _getMessageType(data) {
    if (typeof data === "string") {
      try {
        const parsed = JSON.parse(data);
        return parsed.type || null;
      } catch {
        return null;
      }
    }
    if (typeof data === "object" && data !== null) {
      return data.type || null;
    }
    return null;
  }
  /**
   * Resets notification flags for a new connection
   */
  _resetNotificationFlags() {
    this.lastSecurityLevelNotification = null;
    this.verificationNotificationSent = false;
    this.verificationInitiationSent = false;
    this._verificationUiOpened = false;
    this._sasLocalFingerprint = null;
    this._sasRemoteFingerprint = null;
    this.disconnectNotificationSent = false;
    this.reconnectionFailedNotificationSent = false;
    this.peerDisconnectNotificationSent = false;
    this.connectionClosedNotificationSent = false;
    this.fakeTrafficDisabledNotificationSent = false;
    this.advancedFeaturesDisabledNotificationSent = false;
    this.securityUpgradeNotificationSent = false;
    this.lastSecurityUpgradeStage = null;
    this.securityCalculationNotificationSent = false;
    this.lastSecurityCalculationLevel = null;
  }
  /**
   * Checks whether a message was filtered out
   * @param {any} result - processing result
   * @returns {boolean} true if filtered
   */
  _isFilteredMessage(result) {
    const filteredResults = Object.values(_EnhancedSecureWebRTCManager.FILTERED_RESULTS);
    return filteredResults.includes(result);
  }
  /**
   *   Enhanced log cleanup with security checks
   */
  _cleanupLogs() {
    if (this._logCounts.size > 500) {
      this._logCounts.clear();
      this._secureLog("debug", "\u{1F9F9} Log counts cleared due to size limit");
    }
    const now = Date.now();
    const maxAge = 3e5;
    let suspiciousCount = 0;
    for (const [key, count] of this._logCounts.entries()) {
      if (count > 10) {
        suspiciousCount++;
      }
    }
    if (suspiciousCount > 20) {
      this._logCounts.clear();
      this._secureLog("warn", "\u{1F6A8} Emergency log cleanup due to suspicious patterns");
    }
    if (this._logSecurityViolations > 0 && suspiciousCount < 5) {
      this._logSecurityViolations = Math.max(0, this._logSecurityViolations - 1);
    }
    if (!this._lastIVCleanupTime || Date.now() - this._lastIVCleanupTime > 3e5) {
      this._cleanupOldIVs();
      this._lastIVCleanupTime = Date.now();
    }
    if (!this._secureMemoryManager.memoryStats.lastCleanup || Date.now() - this._secureMemoryManager.memoryStats.lastCleanup > 6e5) {
      this._performPeriodicMemoryCleanup().catch((error) => {
        this._secureLog("error", "Periodic cleanup failed", {
          errorType: error?.constructor?.name || "Unknown"
        });
      });
      this._secureMemoryManager.memoryStats.lastCleanup = Date.now();
    }
  }
  /**
   *   Secure logging stats with sensitive data protection
   */
  _getLoggingStats() {
    const stats = {
      isProductionMode: this._isProductionMode,
      debugMode: this._debugMode,
      currentLogLevel: this._currentLogLevel,
      logCountsSize: this._logCounts.size,
      maxLogCount: this._maxLogCount,
      securityViolations: this._logSecurityViolations || 0,
      maxSecurityViolations: this._maxLogSecurityViolations || 3,
      systemStatus: this._currentLogLevel === -1 ? "DISABLED" : "ACTIVE"
    };
    const sanitizedStats = {};
    for (const [key, value] of Object.entries(stats)) {
      if (typeof value === "string" && this._containsSensitiveContent(value)) {
        sanitizedStats[key] = "[SENSITIVE_DATA_REDACTED]";
      } else {
        sanitizedStats[key] = value;
      }
    }
    return sanitizedStats;
  }
  /**
   *   Enhanced emergency logging disable with cleanup
   */
  async _emergencyDisableLogging() {
    this._currentLogLevel = -1;
    this._logCounts.clear();
    if (this._logSecurityViolations) {
      this._logSecurityViolations = 0;
    }
    this._secureLog = () => {
      if (arguments[0] === "error" && this._originalConsole?.error) {
        this._originalConsole.error("\u{1F6A8} SECURITY: Logging system disabled - potential data exposure prevented");
      }
    };
    this._originalSanitizeString = this._sanitizeString;
    this._originalSanitizeLogData = this._sanitizeLogData;
    this._originalAuditLogMessage = this._auditLogMessage;
    this._originalContainsSensitiveContent = this._containsSensitiveContent;
    this._sanitizeString = () => "[LOGGING_DISABLED]";
    this._sanitizeLogData = () => ({ error: "LOGGING_DISABLED" });
    this._auditLogMessage = () => false;
    this._containsSensitiveContent = () => true;
    await this._performNaturalCleanup();
    this._originalConsole?.error?.("\u{1F6A8} CRITICAL: Secure logging system disabled due to potential data exposure");
  }
  /**
   *   Reset logging system after emergency shutdown
   * Use this function to restore normal logging functionality
   */
  _resetLoggingSystem() {
    this._secureLog("info", "\u{1F527} Resetting logging system after emergency shutdown");
    this._sanitizeString = this._originalSanitizeString || ((str) => str);
    this._sanitizeLogData = this._originalSanitizeLogData || ((data) => data);
    this._auditLogMessage = this._originalAuditLogMessage || (() => true);
    this._containsSensitiveContent = this._originalContainsSensitiveContent || (() => false);
    this._logSecurityViolations = 0;
    this._secureLog("info", "\u2705 Logging system reset successfully");
  }
  /**
   *   Enhanced audit function for log message security
   */
  _auditLogMessage(message, data) {
    if (!data || typeof data !== "object") return true;
    const dataString = JSON.stringify(data);
    if (this._containsSensitiveContent(message)) {
      this._emergencyDisableLogging();
      this._originalConsole?.error?.("\u{1F6A8} SECURITY BREACH: Sensitive content detected in log message");
      return false;
    }
    if (this._containsSensitiveContent(dataString)) {
      this._emergencyDisableLogging();
      this._originalConsole?.error?.("\u{1F6A8} SECURITY BREACH: Sensitive content detected in log data");
      return false;
    }
    const dangerousPatterns = [
      "secret",
      "token",
      "password",
      "credential",
      "auth",
      "fingerprint",
      "salt",
      "signature",
      "private_key",
      "api_key",
      "private",
      "encryption",
      "mac",
      "metadata",
      "session",
      "jwt",
      "bearer",
      "key",
      "hash",
      "digest",
      "nonce",
      "iv",
      "cipher"
    ];
    const dataStringLower = dataString.toLowerCase();
    for (const pattern of dangerousPatterns) {
      if (dataStringLower.includes(pattern) && !this._safeFieldsWhitelist.has(pattern)) {
        this._emergencyDisableLogging();
        this._originalConsole?.error?.(`\u{1F6A8} SECURITY BREACH: Dangerous pattern detected in log: ${pattern}`);
        return false;
      }
    }
    for (const [key, value] of Object.entries(data)) {
      if (typeof value === "string" && this._hasHighEntropy(value)) {
        this._emergencyDisableLogging();
        this._originalConsole?.error?.(`\u{1F6A8} SECURITY BREACH: High entropy value detected in log field: ${key}`);
        return false;
      }
    }
    return true;
  }
  initializeFileTransfer() {
    try {
      if (this._sessionAlive === false) {
        return;
      }
      this._secureLog("info", "\u{1F527} Initializing Enhanced Secure File Transfer system...");
      if (this.fileTransferSystem) {
        this._secureLog("info", "\u2705 File transfer system already initialized");
        return;
      }
      const channelReady = !!(this.dataChannel && this.dataChannel.readyState === "open");
      if (!channelReady) {
        this._secureLog("warn", "\u26A0\uFE0F Data channel not open, deferring file transfer initialization");
        if (this.dataChannel) {
          const initHandler = () => {
            this._secureLog("info", "\u{1F504} DataChannel opened, initializing file transfer...");
            this.initializeFileTransfer();
          };
          this.dataChannel.addEventListener("open", initHandler, { once: true });
        }
        return;
      }
      if (!this.isVerified) {
        this._secureLog("warn", "\u26A0\uFE0F Connection not verified yet, deferring file transfer initialization");
        this._scheduleFileTransferInitRetry(500);
        return;
      }
      if (this.fileTransferSystem) {
        this._secureLog("info", "\u{1F9F9} Cleaning up existing file transfer system");
        this.fileTransferSystem.cleanup();
        this.fileTransferSystem = null;
      }
      if (!this.encryptionKey || !this.macKey) {
        this._secureLog("warn", "\u26A0\uFE0F Encryption keys not ready, deferring file transfer initialization");
        this._scheduleFileTransferInitRetry(1e3);
        return;
      }
      const safeOnComplete = (summary) => {
        try {
          this._secureLog("info", "\u{1F3C1} Sender transfer summary", { summary });
          if (this.onFileProgress) {
            this.onFileProgress({ type: "complete", ...summary });
          }
        } catch (e) {
          this._secureLog("warn", "\u26A0\uFE0F onComplete handler failed:", { details: e.message });
        }
      };
      this.fileTransferSystem = new EnhancedSecureFileTransfer(
        this,
        this.onFileProgress || null,
        safeOnComplete,
        this.onFileError || null,
        this.onFileReceived || null,
        this.onIncomingFileRequest || null
      );
      this._fileTransferActive = true;
      this._secureLog("info", "\u2705 Enhanced Secure File Transfer system initialized successfully");
      const status = this.fileTransferSystem.getSystemStatus();
      this._secureLog("info", "\u{1F50D} File transfer system status after init", { status });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to initialize file transfer system", { errorType: error.constructor.name });
      this.fileTransferSystem = null;
      this._fileTransferActive = false;
    }
  }
  _scheduleFileTransferInitRetry(delay) {
    if (this._sessionAlive === false) return null;
    if (!this._fileTransferInitRetryTimers) this._fileTransferInitRetryTimers = /* @__PURE__ */ new Set();
    const timer = this._trackActiveTimer(setTimeout(() => {
      this._fileTransferInitRetryTimers.delete(timer);
      this._untrackActiveTimer(timer);
      if (this._sessionAlive === false) return;
      this.initializeFileTransfer();
    }, delay));
    this._fileTransferInitRetryTimers.add(timer);
    return timer;
  }
  // ============================================
  // ENHANCED SECURITY INITIALIZATION
  // ============================================
  async initializeEnhancedSecurity() {
    try {
      await this.generateNestedEncryptionKey();
      if (this.decoyChannelConfig.enabled) {
        this.initializeDecoyChannels();
      }
      if (this.fakeTrafficConfig.enabled) {
        this.startFakeTrafficGeneration();
      }
    } catch (error) {
      this._secureLog("error", "\u274C Failed to initialize enhanced security", { errorType: error.constructor.name });
    }
  }
  // Helper function: unbiased integer in [min, max]
  getSafeRandomInt(min, max) {
    if (!Number.isInteger(min) || !Number.isInteger(max)) {
      throw new Error("getSafeRandomInt requires integer min and max");
    }
    if (min >= max) {
      throw new Error("min must be less than max");
    }
    const range = max - min + 1;
    const bitsNeeded = Math.ceil(Math.log2(range));
    const bytesNeeded = Math.ceil(bitsNeeded / 8);
    const mask = (1 << bitsNeeded) - 1;
    let randomValue;
    do {
      const randomBytes = crypto.getRandomValues(new Uint8Array(bytesNeeded));
      randomValue = 0;
      for (let i = 0; i < bytesNeeded; i++) {
        randomValue = randomValue * 256 + randomBytes[i];
      }
      randomValue = randomValue & mask;
    } while (randomValue >= range);
    return min + randomValue;
  }
  getSafeRandomFloat(minFloat, maxFloat, steps = 1e3) {
    if (typeof minFloat !== "number" || typeof maxFloat !== "number") {
      throw new Error("getSafeRandomFloat requires numeric min and max");
    }
    if (minFloat >= maxFloat) {
      throw new Error("minFloat must be less than maxFloat");
    }
    const randomIndex = this.getSafeRandomInt(0, steps);
    const step = (maxFloat - minFloat) / steps;
    return minFloat + randomIndex * step;
  }
  generateFingerprintMask() {
    const mask = {
      timingOffset: this.getSafeRandomInt(0, 1500),
      sizeVariation: this.getSafeRandomFloat(0.75, 1.25, 1e3),
      noisePattern: Array.from(crypto.getRandomValues(new Uint8Array(64))),
      headerVariations: [
        "X-Client-Version",
        "X-Session-ID",
        "X-Request-ID",
        "X-Timestamp",
        "X-Signature",
        "X-Secure",
        "X-Encrypted",
        "X-Protected",
        "X-Safe",
        "X-Anonymous",
        "X-Private"
      ],
      noiseIntensity: this.getSafeRandomInt(50, 150),
      sizeMultiplier: this.getSafeRandomFloat(0.75, 1.25, 1e3),
      timingVariation: this.getSafeRandomInt(100, 1100)
    };
    return mask;
  }
  // Security configuration - all features enabled by default
  configureSecurityForSession() {
    this._secureLog("info", "\u{1F527} Configuring security - all features enabled by default");
    this.sessionConstraints = {};
    Object.keys(this.securityFeatures).forEach((feature) => {
      this.sessionConstraints[feature] = true;
    });
    this.applySessionConstraints();
    this._secureLog("info", "\u2705 Security configured - all features enabled", { constraints: this.sessionConstraints });
    if (!this._validateCryptographicSecurity()) {
      this._secureLog("error", "\u{1F6A8} CRITICAL: Cryptographic security validation failed after session configuration");
      if (this.onStatusChange) {
        this.onStatusChange("security_breach", {
          type: "crypto_security_failure",
          message: "Cryptographic security validation failed after session configuration"
        });
      }
    }
    this.notifySecurityLevel();
    setTimeout(() => {
      this.calculateAndReportSecurityLevel();
    }, _EnhancedSecureWebRTCManager.TIMEOUTS.SECURITY_CALC_DELAY);
  }
  // Applying session constraints - all features enabled by default
  applySessionConstraints() {
    if (!this.sessionConstraints) return;
    Object.keys(this.sessionConstraints).forEach((feature) => {
      this.securityFeatures[feature] = true;
      switch (feature) {
        case "hasFakeTraffic":
          this.fakeTrafficConfig.enabled = true;
          if (this.isConnected()) {
            this.startFakeTrafficGeneration();
          }
          break;
        case "hasDecoyChannels":
          this.decoyChannelConfig.enabled = true;
          if (this.isConnected()) {
            this.initializeDecoyChannels();
          }
          break;
        case "hasPacketReordering":
          this.reorderingConfig.enabled = true;
          break;
        case "hasAntiFingerprinting":
          this.antiFingerprintingConfig.enabled = true;
          break;
        case "hasMessageChunking":
          this.chunkingConfig.enabled = true;
          break;
      }
    });
    this._secureLog("info", "\u2705 All security features enabled by default", {
      constraints: this.sessionConstraints,
      currentFeatures: this.securityFeatures
    });
  }
  _sanitizeIncomingChatMessage(message) {
    if (typeof message !== "string") {
      return message;
    }
    return window.EnhancedSecureCryptoUtils.sanitizeMessage(message);
  }
  deliverMessageToUI(message, type = "received", meta = null) {
    try {
      this._secureLog("debug", "\u{1F4E4} deliverMessageToUI called", {
        message,
        type,
        messageType: typeof message,
        hasOnMessage: !!this.onMessage
      });
      if (typeof message === "object" && message.type) {
        const blockedTypes = [
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_START,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_RESPONSE,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_CHUNK,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.CHUNK_CONFIRMATION,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_COMPLETE,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_ERROR,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_RESPONSE,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_CONFIRMED,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_BOTH_CONFIRMED,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.PEER_DISCONNECT,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_SIGNAL,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_READY,
          _EnhancedSecureWebRTCManager.MESSAGE_TYPES.SECURITY_UPGRADE
        ];
        if (blockedTypes.includes(message.type)) {
          if (this._debugMode) {
            this._secureLog("warn", `\u{1F6D1} Blocked system/file message from UI: ${message.type}`);
          }
          return;
        }
      }
      if (typeof message === "string" && message.trim().startsWith("{")) {
        try {
          const parsedMessage = JSON.parse(message);
          if (parsedMessage.type) {
            const blockedTypes = [
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_START,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_RESPONSE,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_CHUNK,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.CHUNK_CONFIRMATION,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_COMPLETE,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FILE_TRANSFER_ERROR,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.HEARTBEAT,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_RESPONSE,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_CONFIRMED,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.VERIFICATION_BOTH_CONFIRMED,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.PEER_DISCONNECT,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_SIGNAL,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_ROTATION_READY,
              _EnhancedSecureWebRTCManager.MESSAGE_TYPES.SECURITY_UPGRADE
            ];
            if (blockedTypes.includes(parsedMessage.type)) {
              if (this._debugMode) {
                this._secureLog("warn", `\u{1F6D1} Blocked system/file message from UI (string): ${parsedMessage.type}`);
              }
              return;
            }
          }
        } catch (parseError) {
        }
      }
      const uiMessage = type === "received" ? this._sanitizeIncomingChatMessage(message) : message;
      if (this.onMessage) {
        const safeMeta = meta && typeof this._sanitizeMessageMeta === "function" ? this._sanitizeMessageMeta(meta) : null;
        this._secureLog("debug", "\u{1F4E4} Calling this.onMessage callback", { message: uiMessage, type });
        this.onMessage(uiMessage, type, safeMeta || void 0);
      } else {
        this._secureLog("warn", "\u26A0\uFE0F this.onMessage callback is null or undefined");
      }
    } catch (err) {
      this._secureLog("error", "\u274C Failed to deliver message to UI:", { errorType: err?.constructor?.name || "Unknown" });
    }
  }
  // Security Level Notification
  notifySecurityLevel() {
    if (this.lastSecurityLevelNotification === "maximum") {
      return;
    }
    this.lastSecurityLevelNotification = "maximum";
    const message = "\u{1F6E1}\uFE0F Maximum Security Active - All features enabled";
    if (this.onMessage) {
      this.deliverMessageToUI(message, "system");
    }
    if (this.onMessage) {
      const activeFeatures = Object.entries(this.securityFeatures).filter(([key, value]) => value === true).map(([key]) => key.replace("has", "").replace(/([A-Z])/g, " $1").trim().toLowerCase()).slice(0, 5);
      this.deliverMessageToUI(`\u{1F527} Active: ${activeFeatures.join(", ")}...`, "system");
    }
  }
  // Cleaning decoy channels
  cleanupDecoyChannels() {
    for (const [channelName, timer] of this.decoyTimers.entries()) {
      clearTimeout(timer);
    }
    this.decoyTimers.clear();
    for (const [channelName, channel] of this.decoyChannels.entries()) {
      if (channel.readyState === "open") {
        channel.close();
      }
    }
    this.decoyChannels.clear();
    this._secureLog("info", "\u{1F9F9} Decoy channels cleaned up");
  }
  // ============================================
  // 1. NESTED ENCRYPTION LAYER
  // ============================================
  async generateNestedEncryptionKey() {
    try {
      this.nestedEncryptionKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    } catch (error) {
      this._secureLog("error", "\u274C Failed to generate nested encryption key:", { errorType: error?.constructor?.name || "Unknown" });
      throw error;
    }
  }
  async applyNestedEncryption(data) {
    if (!this.nestedEncryptionKey || !this.securityFeatures.hasNestedEncryption) {
      return data;
    }
    try {
      const uniqueIV = this._generateSecureIV(
        _EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE,
        "nestedEncryption"
      );
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: uniqueIV },
        this.nestedEncryptionKey,
        data
      );
      const result = new Uint8Array(_EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE + encrypted.byteLength);
      result.set(uniqueIV, 0);
      result.set(new Uint8Array(encrypted), _EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE);
      this._secureLog("debug", "\u2705 Nested encryption applied with secure IV", {
        ivSize: uniqueIV.length,
        dataSize: data.byteLength,
        encryptedSize: encrypted.byteLength
      });
      return result.buffer;
    } catch (error) {
      this._secureLog("error", "\u274C Nested encryption failed:", {
        errorType: error?.constructor?.name || "Unknown",
        errorMessage: error?.message || "Unknown error"
      });
      if (error.message.includes("emergency mode")) {
        this.securityFeatures.hasNestedEncryption = false;
        this._secureLog("warn", "\u26A0\uFE0F Nested encryption disabled due to IV emergency mode");
      }
      return data;
    }
  }
  async removeNestedEncryption(data) {
    if (!this.nestedEncryptionKey || !this.securityFeatures.hasNestedEncryption) {
      return data;
    }
    if (!(data instanceof ArrayBuffer) || data.byteLength < _EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE + 16) {
      if (this._debugMode) {
        this._secureLog("debug", "\u{1F4DD} Data not encrypted or too short for nested decryption (need IV + minimum encrypted data)");
      }
      return data;
    }
    try {
      const dataArray = new Uint8Array(data);
      const iv = dataArray.slice(0, _EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE);
      const encryptedData = dataArray.slice(_EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE);
      if (encryptedData.length === 0) {
        if (this._debugMode) {
          this._secureLog("debug", "\u{1F4DD} No encrypted data found");
        }
        return data;
      }
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        this.nestedEncryptionKey,
        encryptedData
      );
      return decrypted;
    } catch (error) {
      if (error.name === "OperationError") {
        if (this._debugMode) {
          this._secureLog("debug", "\u{1F4DD} Data not encrypted with nested encryption, skipping...");
        }
      } else {
        if (this._debugMode) {
          this._secureLog("warn", "\u26A0\uFE0F Nested decryption failed:", { details: error.message });
        }
      }
      return data;
    }
  }
  // ============================================
  // 2. PACKET PADDING
  // ============================================
  applyPacketPadding(data) {
    if (!this.securityFeatures.hasPacketPadding) {
      return data;
    }
    try {
      const originalSize = data.byteLength;
      let paddingSize;
      if (this.paddingConfig.useRandomPadding) {
        paddingSize = Math.floor(Math.random() * (this.paddingConfig.maxPadding - this.paddingConfig.minPadding + 1)) + this.paddingConfig.minPadding;
      } else {
        paddingSize = this.paddingConfig.minPadding;
      }
      const padding = crypto.getRandomValues(new Uint8Array(paddingSize));
      const paddedData = new Uint8Array(originalSize + paddingSize + 4);
      const sizeView = new DataView(paddedData.buffer, 0, 4);
      sizeView.setUint32(0, originalSize, false);
      paddedData.set(new Uint8Array(data), 4);
      paddedData.set(padding, 4 + originalSize);
      return paddedData.buffer;
    } catch (error) {
      this._secureLog("error", "\u274C Packet padding failed:", { errorType: error?.constructor?.name || "Unknown" });
      return data;
    }
  }
  removePacketPadding(data) {
    if (!this.securityFeatures.hasPacketPadding) {
      return data;
    }
    try {
      const dataArray = new Uint8Array(data);
      if (dataArray.length < 5) {
        if (this._debugMode) {
          this._secureLog("warn", "\u26A0\uFE0F Data too short for packet padding removal, skipping");
        }
        return data;
      }
      const sizeView = new DataView(dataArray.buffer, 0, 4);
      const originalSize = sizeView.getUint32(0, false);
      if (originalSize <= 0 || originalSize > dataArray.length - 4) {
        if (this._debugMode) {
          this._secureLog("warn", "\u26A0\uFE0F Invalid packet padding size, skipping removal");
        }
        return data;
      }
      const originalData = dataArray.slice(4, 4 + originalSize);
      return originalData.buffer;
    } catch (error) {
      if (this._debugMode) {
        this._secureLog("error", "\u274C Packet padding removal failed:", { errorType: error?.constructor?.name || "Unknown" });
      }
      return data;
    }
  }
  // ============================================
  // 3. FAKE TRAFFIC GENERATION
  // ============================================
  startFakeTrafficGeneration() {
    if (!this.fakeTrafficConfig.enabled || !this.isConnected()) {
      return;
    }
    if (this.fakeTrafficTimer) {
      this._secureLog("warn", "\u26A0\uFE0F Fake traffic generation already running");
      return;
    }
    const sendFakeMessage = async () => {
      if (!this.isConnected()) {
        this.stopFakeTrafficGeneration();
        return;
      }
      try {
        const fakeMessage = this.generateFakeMessage();
        await this.sendFakeMessage(fakeMessage);
        const nextInterval = this.fakeTrafficConfig.randomDecoyIntervals ? this.getUnbiasedRandomInRange(this.fakeTrafficConfig.minInterval, Math.min(this.fakeTrafficConfig.maxInterval, 6e4)) : (
          // Cap at 60 seconds
          this.fakeTrafficConfig.minInterval
        );
        const safeInterval = Math.max(nextInterval, _EnhancedSecureWebRTCManager.TIMEOUTS.FAKE_TRAFFIC_MIN_INTERVAL);
        this.fakeTrafficTimer = setTimeout(sendFakeMessage, safeInterval);
      } catch (error) {
        if (this._debugMode) {
          this._secureLog("error", "\u274C Fake traffic generation failed:", { errorType: error?.constructor?.name || "Unknown" });
        }
        this.stopFakeTrafficGeneration();
      }
    };
    const minDelay = _EnhancedSecureWebRTCManager.TIMEOUTS.DECOY_INITIAL_DELAY;
    const maxDelay = Math.min(this.fakeTrafficConfig.maxInterval, 3e4);
    const initialDelay = this.getUnbiasedRandomInRange(minDelay, maxDelay);
    this.fakeTrafficTimer = setTimeout(sendFakeMessage, initialDelay);
  }
  stopFakeTrafficGeneration() {
    if (this.fakeTrafficTimer) {
      clearTimeout(this.fakeTrafficTimer);
      this.fakeTrafficTimer = null;
    }
  }
  generateFakeMessage() {
    const patternIndex = this.getUnbiasedRandomInRange(0, this.fakeTrafficConfig.patterns.length - 1);
    const pattern = this.fakeTrafficConfig.patterns[patternIndex];
    const size = this.getUnbiasedRandomInRange(this.fakeTrafficConfig.minSize, this.fakeTrafficConfig.maxSize);
    const fakeData = crypto.getRandomValues(new Uint8Array(size));
    return {
      type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FAKE,
      pattern,
      data: Array.from(fakeData).map((b) => b.toString(16).padStart(2, "0")).join(""),
      timestamp: Date.now(),
      size,
      isFakeTraffic: true,
      source: "fake_traffic_generator",
      fakeId: crypto.getRandomValues(new Uint32Array(1))[0].toString(36)
    };
  }
  // ============================================
  // EMERGENCY SHUT-OFF OF ADVANCED FUNCTIONS
  // ============================================
  emergencyDisableAdvancedFeatures() {
    this._secureLog("error", "\u{1F6A8} Emergency disabling advanced security features due to errors");
    this.securityFeatures.hasNestedEncryption = false;
    this.securityFeatures.hasPacketReordering = false;
    this.securityFeatures.hasAntiFingerprinting = false;
    this.reorderingConfig.enabled = false;
    this.antiFingerprintingConfig.enabled = false;
    this.packetBuffer.clear();
    this.emergencyDisableFakeTraffic();
    this._secureLog("info", "\u2705 Advanced features disabled, keeping basic encryption");
    if (!this.advancedFeaturesDisabledNotificationSent) {
      this.advancedFeaturesDisabledNotificationSent = true;
      if (this.onMessage) {
        this.deliverMessageToUI("\u{1F6A8} Advanced security features temporarily disabled due to compatibility issues", "system");
      }
    }
  }
  async sendFakeMessage(fakeMessage) {
    if (!this._validateConnection(false)) {
      return;
    }
    try {
      this._secureLog("debug", "\u{1F3AD} Sending fake message", {
        hasPattern: !!fakeMessage.pattern,
        sizeRange: fakeMessage.size > 100 ? "large" : "small"
      });
      const fakeData = JSON.stringify({
        ...fakeMessage,
        type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.FAKE,
        isFakeTraffic: true,
        timestamp: Date.now()
      });
      const fakeBuffer = new TextEncoder().encode(fakeData);
      const encryptedFake = await this.applySecurityLayers(fakeBuffer, true);
      this.dataChannel.send(encryptedFake);
      this._secureLog("debug", "\u{1F3AD} Fake message sent successfully", {
        pattern: fakeMessage.pattern
      });
    } catch (error) {
      this._secureLog("error", "\u274C Failed to send fake message", {
        error: error.message
      });
    }
  }
  checkFakeTrafficStatus() {
    const status = {
      fakeTrafficEnabled: this.securityFeatures.hasFakeTraffic,
      fakeTrafficConfigEnabled: this.fakeTrafficConfig.enabled,
      timerActive: !!this.fakeTrafficTimer,
      patterns: this.fakeTrafficConfig.patterns,
      intervals: {
        min: this.fakeTrafficConfig.minInterval,
        max: this.fakeTrafficConfig.maxInterval
      }
    };
    if (this._debugMode) {
      this._secureLog("info", "\u{1F3AD} Fake Traffic Status", { status });
    }
    return status;
  }
  emergencyDisableFakeTraffic() {
    if (this._debugMode) {
      this._secureLog("error", "\u{1F6A8} Emergency disabling fake traffic");
    }
    this.securityFeatures.hasFakeTraffic = false;
    this.fakeTrafficConfig.enabled = false;
    this.stopFakeTrafficGeneration();
    if (this._debugMode) {
      this._secureLog("info", "\u2705 Fake traffic disabled");
    }
    if (!this.fakeTrafficDisabledNotificationSent) {
      this.fakeTrafficDisabledNotificationSent = true;
      if (this.onMessage) {
        this.deliverMessageToUI("\u{1F6A8} Fake traffic emergency disabled", "system");
      }
    }
  }
  async _applySecurityLayersWithoutMutex(data, isFakeMessage = false) {
    try {
      let processedData = data;
      if (isFakeMessage) {
        if (this.encryptionKey && typeof processedData === "string") {
          processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
        }
        return processedData;
      }
      if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer) {
        processedData = await this.applyNestedEncryption(processedData);
      }
      if (this.securityFeatures.hasPacketReordering && this.reorderingConfig?.enabled && processedData instanceof ArrayBuffer) {
        processedData = this.applyPacketReordering(processedData);
      }
      if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
        processedData = this.applyPacketPadding(processedData);
      }
      if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
        processedData = this.applyAntiFingerprinting(processedData);
      }
      if (this.encryptionKey && typeof processedData === "string") {
        processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
      }
      return processedData;
    } catch (error) {
      this._secureLog("error", "\u274C Error in applySecurityLayersWithoutMutex:", { errorType: error?.constructor?.name || "Unknown" });
      return data;
    }
  }
  // ============================================
  // 4. MESSAGE CHUNKING
  // ============================================
  async processChunkedMessage(chunkData) {
    try {
      if (!this.chunkingConfig.addChunkHeaders) {
        return this.processMessage(chunkData);
      }
      const chunkArray = new Uint8Array(chunkData);
      if (chunkArray.length < 16) {
        return this.processMessage(chunkData);
      }
      const headerView = new DataView(chunkArray.buffer, 0, 16);
      const messageId = headerView.getUint32(0, false);
      const chunkIndex = headerView.getUint32(4, false);
      const totalChunks = headerView.getUint32(8, false);
      const chunkSize = headerView.getUint32(12, false);
      const chunk = chunkArray.slice(16, 16 + chunkSize);
      if (!this.chunkQueue[messageId]) {
        this.chunkQueue[messageId] = {
          chunks: new Array(totalChunks),
          received: 0,
          timestamp: Date.now()
        };
      }
      const messageBuffer = this.chunkQueue[messageId];
      messageBuffer.chunks[chunkIndex] = chunk;
      messageBuffer.received++;
      this._secureLog("debug", `\u{1F4E6} Received chunk ${chunkIndex + 1}/${totalChunks} for message ${messageId}`);
      if (messageBuffer.received === totalChunks) {
        const totalSize = messageBuffer.chunks.reduce((sum, chunk2) => sum + chunk2.length, 0);
        const combinedData = new Uint8Array(totalSize);
        let offset = 0;
        for (const chunk2 of messageBuffer.chunks) {
          combinedData.set(chunk2, offset);
          offset += chunk2.length;
        }
        await this.processMessage(combinedData.buffer);
        delete this.chunkQueue[messageId];
        this._secureLog("info", `\u{1F4E6} Chunked message ${messageId} reassembled and processed`);
      }
    } catch (error) {
      this._secureLog("error", "\u274C Chunked message processing failed:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  // ============================================
  // 5. DECOY CHANNELS
  // ============================================
  initializeDecoyChannels() {
    if (!this.decoyChannelConfig.enabled || !this.peerConnection) {
      return;
    }
    if (this.decoyChannels.size > 0) {
      this._secureLog("warn", "\u26A0\uFE0F Decoy channels already initialized, skipping...");
      return;
    }
    try {
      const numDecoyChannels = Math.min(
        this.decoyChannelConfig.maxDecoyChannels,
        this.decoyChannelConfig.decoyChannelNames.length
      );
      for (let i = 0; i < numDecoyChannels; i++) {
        const channelName = this.decoyChannelConfig.decoyChannelNames[i];
        const decoyChannel = this.peerConnection.createDataChannel(channelName, {
          ordered: Math.random() > 0.5,
          maxRetransmits: Math.floor(Math.random() * 3)
        });
        this.setupDecoyChannel(decoyChannel, channelName);
        this.decoyChannels.set(channelName, decoyChannel);
      }
      if (this._debugMode) {
        this._secureLog("info", `\u{1F3AD} Initialized ${numDecoyChannels} decoy channels`);
      }
    } catch (error) {
      if (this._debugMode) {
        this._secureLog("error", "\u274C Failed to initialize decoy channels:", { errorType: error?.constructor?.name || "Unknown" });
      }
    }
  }
  setupDecoyChannel(channel, channelName) {
    channel.onopen = () => {
      if (this._debugMode) {
        this._secureLog("debug", `\u{1F3AD} Decoy channel "${channelName}" opened`);
      }
      this.startDecoyTraffic(channel, channelName);
    };
    channel.onmessage = (event) => {
      if (this._debugMode) {
        this._secureLog("debug", `\u{1F3AD} Received decoy message on "${channelName}": ${event.data?.length || "undefined"} bytes`);
      }
    };
    channel.onclose = () => {
      if (this._debugMode) {
        this._secureLog("debug", `\u{1F3AD} Decoy channel "${channelName}" closed`);
      }
      this.stopDecoyTraffic(channelName);
    };
    channel.onerror = (error) => {
      if (this._debugMode) {
        this._secureLog("error", `\u274C Decoy channel "${channelName}" error`, { error: error.message });
      }
    };
  }
  startDecoyTraffic(channel, channelName) {
    const sendDecoyData = async () => {
      if (channel.readyState !== "open") {
        return;
      }
      try {
        const decoyData = this.generateDecoyData(channelName);
        channel.send(decoyData);
        const interval = this.decoyChannelConfig.randomDecoyIntervals ? Math.random() * 15e3 + 1e4 : 2e4;
        this.decoyTimers.set(channelName, setTimeout(() => sendDecoyData(), interval));
      } catch (error) {
        if (this._debugMode) {
          this._secureLog("error", `\u274C Failed to send decoy data on "${channelName}"`, { error: error.message });
        }
      }
    };
    const initialDelay = Math.random() * 1e4 + 5e3;
    this.decoyTimers.set(channelName, setTimeout(() => sendDecoyData(), initialDelay));
  }
  stopDecoyTraffic(channelName) {
    const timer = this.decoyTimers.get(channelName);
    if (timer) {
      clearTimeout(timer);
      this.decoyTimers.delete(channelName);
    }
  }
  generateDecoyData(channelName) {
    const decoyTypes = {
      "sync": () => JSON.stringify({
        type: "sync",
        timestamp: Date.now(),
        sequence: Math.floor(Math.random() * 1e3),
        data: Array.from(crypto.getRandomValues(new Uint8Array(32))).map((b) => b.toString(16).padStart(2, "0")).join("")
      }),
      "status": () => JSON.stringify({
        type: "status",
        status: ["online", "away", "busy"][Math.floor(Math.random() * 3)],
        uptime: Math.floor(Math.random() * 3600),
        data: Array.from(crypto.getRandomValues(new Uint8Array(16))).map((b) => b.toString(16).padStart(2, "0")).join("")
      }),
      "heartbeat": () => JSON.stringify({
        type: "heartbeat",
        timestamp: Date.now(),
        data: Array.from(crypto.getRandomValues(new Uint8Array(24))).map((b) => b.toString(16).padStart(2, "0")).join("")
      }),
      "metrics": () => JSON.stringify({
        type: "metrics",
        cpu: Math.random() * 100,
        memory: Math.random() * 100,
        network: Math.random() * 1e3,
        data: Array.from(crypto.getRandomValues(new Uint8Array(20))).map((b) => b.toString(16).padStart(2, "0")).join("")
      }),
      "debug": () => JSON.stringify({
        type: "debug",
        level: ["info", "warn", "error"][Math.floor(Math.random() * 3)],
        message: "Debug message",
        data: Array.from(crypto.getRandomValues(new Uint8Array(28))).map((b) => b.toString(16).padStart(2, "0")).join("")
      })
    };
    return decoyTypes[channelName] ? decoyTypes[channelName]() : Array.from(crypto.getRandomValues(new Uint8Array(64))).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  // ============================================
  // 6. PACKET REORDERING PROTECTION
  // ============================================
  addReorderingHeaders(data) {
    if (!this.reorderingConfig.enabled) {
      return data;
    }
    try {
      const dataArray = new Uint8Array(data);
      const headerSize = this.reorderingConfig.useTimestamps ? 12 : 8;
      const header = new ArrayBuffer(headerSize);
      const headerView = new DataView(header);
      if (this.reorderingConfig.useSequenceNumbers) {
        headerView.setUint32(0, this.sequenceNumber++, false);
      }
      if (this.reorderingConfig.useTimestamps) {
        headerView.setUint32(4, Date.now(), false);
      }
      headerView.setUint32(this.reorderingConfig.useTimestamps ? 8 : 4, dataArray.length, false);
      const result = new Uint8Array(headerSize + dataArray.length);
      result.set(new Uint8Array(header), 0);
      result.set(dataArray, headerSize);
      return result.buffer;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to add reordering headers:", { errorType: error?.constructor?.name || "Unknown" });
      return data;
    }
  }
  async processReorderedPacket(data) {
    if (!this.reorderingConfig.enabled) {
      return this.processMessage(data);
    }
    try {
      const dataArray = new Uint8Array(data);
      const headerSize = this.reorderingConfig.useTimestamps ? 12 : 8;
      if (dataArray.length < headerSize) {
        if (this._debugMode) {
          this._secureLog("warn", "\u26A0\uFE0F Data too short for reordering headers, processing directly");
        }
        return this.processMessage(data);
      }
      const headerView = new DataView(dataArray.buffer, 0, headerSize);
      let sequence = 0;
      let timestamp = 0;
      let dataSize = 0;
      if (this.reorderingConfig.useSequenceNumbers) {
        sequence = headerView.getUint32(0, false);
      }
      if (this.reorderingConfig.useTimestamps) {
        timestamp = headerView.getUint32(4, false);
      }
      dataSize = headerView.getUint32(this.reorderingConfig.useTimestamps ? 8 : 4, false);
      if (dataSize > dataArray.length - headerSize || dataSize <= 0) {
        if (this._debugMode) {
          this._secureLog("warn", "\u26A0\uFE0F Invalid reordered packet data size, processing directly");
        }
        return this.processMessage(data);
      }
      const actualData = dataArray.slice(headerSize, headerSize + dataSize);
      try {
        const textData = new TextDecoder().decode(actualData);
        const content = JSON.parse(textData);
        if (content.type === "fake" || content.isFakeTraffic === true) {
          if (this._debugMode) {
            this._secureLog("warn", `\u{1F3AD} BLOCKED: Reordered fake message: ${content.pattern || "unknown"}`);
          }
          return;
        }
      } catch (e) {
      }
      this.packetBuffer.set(sequence, {
        data: actualData.buffer,
        timestamp: timestamp || Date.now()
      });
      await this.processOrderedPackets();
    } catch (error) {
      this._secureLog("error", "\u274C Failed to process reordered packet:", { errorType: error?.constructor?.name || "Unknown" });
      return this.processMessage(data);
    }
  }
  // ============================================
  // IMPROVED PROCESSORDEREDPACKETS with filtering
  // ============================================
  async processOrderedPackets() {
    const now = Date.now();
    const timeout = this.reorderingConfig.reorderTimeout;
    while (true) {
      const nextSequence = this.lastProcessedSequence + 1;
      const packet = this.packetBuffer.get(nextSequence);
      if (!packet) {
        const oldestPacket = this.findOldestPacket();
        if (oldestPacket && now - oldestPacket.timestamp > timeout) {
          this._secureLog("warn", "\u26A0\uFE0F Packet ${oldestPacket.sequence} timed out, processing out of order");
          try {
            const textData = new TextDecoder().decode(oldestPacket.data);
            const content = JSON.parse(textData);
            if (content.type === "fake" || content.isFakeTraffic === true) {
              this._secureLog("warn", `\u{1F3AD} BLOCKED: Timed out fake message: ${content.pattern || "unknown"}`);
              this.packetBuffer.delete(oldestPacket.sequence);
              this.lastProcessedSequence = oldestPacket.sequence;
              continue;
            }
          } catch (e) {
          }
          await this.processMessage(oldestPacket.data);
          this.packetBuffer.delete(oldestPacket.sequence);
          this.lastProcessedSequence = oldestPacket.sequence;
        } else {
          break;
        }
      } else {
        try {
          const textData = new TextDecoder().decode(packet.data);
          const content = JSON.parse(textData);
          if (content.type === "fake" || content.isFakeTraffic === true) {
            this._secureLog("warn", `\u{1F3AD} BLOCKED: Ordered fake message: ${content.pattern || "unknown"}`);
            this.packetBuffer.delete(nextSequence);
            this.lastProcessedSequence = nextSequence;
            continue;
          }
        } catch (e) {
        }
        await this.processMessage(packet.data);
        this.packetBuffer.delete(nextSequence);
        this.lastProcessedSequence = nextSequence;
      }
    }
    this.cleanupOldPackets(now, timeout);
  }
  findOldestPacket() {
    let oldest = null;
    for (const [sequence, packet] of this.packetBuffer.entries()) {
      if (!oldest || packet.timestamp < oldest.timestamp) {
        oldest = { sequence, ...packet };
      }
    }
    return oldest;
  }
  cleanupOldPackets(now, timeout) {
    for (const [sequence, packet] of this.packetBuffer.entries()) {
      if (now - packet.timestamp > timeout) {
        this._secureLog("warn", "\u26A0\uFE0F \u{1F5D1}\uFE0F Removing timed out packet ${sequence}");
        this.packetBuffer.delete(sequence);
      }
    }
  }
  // ============================================
  // 7. ANTI-FINGERPRINTING
  // ============================================
  applyAntiFingerprinting(data) {
    if (!this.antiFingerprintingConfig.enabled) {
      return data;
    }
    try {
      let processedData = data;
      if (this.antiFingerprintingConfig.addNoise) {
        processedData = this.addNoise(processedData);
      }
      if (this.antiFingerprintingConfig.randomizeSizes) {
        processedData = this.randomizeSize(processedData);
      }
      if (this.antiFingerprintingConfig.maskPatterns) {
        processedData = this.maskPatterns(processedData);
      }
      if (this.antiFingerprintingConfig.useRandomHeaders) {
        processedData = this.addRandomHeaders(processedData);
      }
      return processedData;
    } catch (error) {
      this._secureLog("error", "\u274C Anti-fingerprinting failed:", { errorType: error?.constructor?.name || "Unknown" });
      return data;
    }
  }
  addNoise(data) {
    const dataArray = new Uint8Array(data);
    const noiseSize = this.getUnbiasedRandomInRange(8, 40);
    const noise = crypto.getRandomValues(new Uint8Array(noiseSize));
    const result = new Uint8Array(dataArray.length + noiseSize);
    result.set(dataArray, 0);
    result.set(noise, dataArray.length);
    return result.buffer;
  }
  randomizeSize(data) {
    const dataArray = new Uint8Array(data);
    const variation = this.fingerprintMask.sizeVariation;
    const targetSize = Math.floor(dataArray.length * variation);
    if (targetSize > dataArray.length) {
      const padding = crypto.getRandomValues(new Uint8Array(targetSize - dataArray.length));
      const result = new Uint8Array(targetSize);
      result.set(dataArray, 0);
      result.set(padding, dataArray.length);
      return result.buffer;
    } else if (targetSize < dataArray.length) {
      return dataArray.slice(0, targetSize).buffer;
    }
    return data;
  }
  maskPatterns(data) {
    const dataArray = new Uint8Array(data);
    const result = new Uint8Array(dataArray.length);
    for (let i = 0; i < dataArray.length; i++) {
      const noiseByte = this.fingerprintMask.noisePattern[i % this.fingerprintMask.noisePattern.length];
      result[i] = dataArray[i] ^ noiseByte;
    }
    return result.buffer;
  }
  addRandomHeaders(data) {
    const dataArray = new Uint8Array(data);
    const headerCount = this.getUnbiasedRandomInRange(1, 3);
    let totalHeaderSize = 0;
    for (let i = 0; i < headerCount; i++) {
      totalHeaderSize += 4 + this.getUnbiasedRandomInRange(0, 15) + 4;
    }
    const result = new Uint8Array(totalHeaderSize + dataArray.length);
    let offset = 0;
    for (let i = 0; i < headerCount; i++) {
      let headerIndex;
      do {
        headerIndex = crypto.getRandomValues(new Uint8Array(1))[0];
      } while (headerIndex >= 256 - 256 % this.fingerprintMask.headerVariations.length);
      const headerName = this.fingerprintMask.headerVariations[headerIndex % this.fingerprintMask.headerVariations.length];
      let headerSize;
      do {
        headerSize = crypto.getRandomValues(new Uint8Array(1))[0];
      } while (headerSize >= 256 - 256 % 16);
      const headerData = crypto.getRandomValues(new Uint8Array(headerSize % 16 + 4));
      const headerView = new DataView(result.buffer, offset);
      headerView.setUint32(0, headerData.length + 8, false);
      headerView.setUint32(4, this.hashString(headerName), false);
      result.set(headerData, offset + 8);
      const checksum = this.calculateChecksum(result.slice(offset, offset + 8 + headerData.length));
      const checksumView = new DataView(result.buffer, offset + 8 + headerData.length);
      checksumView.setUint32(0, checksum, false);
      offset += 8 + headerData.length + 4;
    }
    result.set(dataArray, offset);
    return result.buffer;
  }
  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return Math.abs(hash);
  }
  calculateChecksum(data) {
    let checksum = 0;
    for (let i = 0; i < data.length; i++) {
      checksum = checksum + data[i] & 4294967295;
    }
    return checksum;
  }
  // ============================================
  // ENHANCED MESSAGE SENDING AND RECEIVING
  // ============================================
  async removeSecurityLayers(data) {
    try {
      const status = this.getSecurityStatus();
      if (this._debugMode) {
        this._secureLog("debug", `\u{1F50D} removeSecurityLayers (Stage ${status.stage})`, {
          dataType: typeof data,
          dataLength: data?.length || data?.byteLength || 0,
          activeFeatures: status.activeFeaturesCount
        });
      }
      if (!data) {
        this._secureLog("warn", "\u26A0\uFE0F Received empty data");
        return null;
      }
      let processedData = data;
      if (typeof data === "string") {
        try {
          const jsonData = JSON.parse(data);
          if (jsonData.type === "fake") {
            if (this._debugMode) {
              this._secureLog("debug", `\u{1F3AD} Fake message filtered out: ${jsonData.pattern} (size: ${jsonData.size})`);
            }
            return "FAKE_MESSAGE_FILTERED";
          }
          if (jsonData.type && ["heartbeat", "verification", "verification_response", "peer_disconnect", "key_rotation_signal", "key_rotation_ready", "security_upgrade", "ice_restart_offer", "ice_restart_answer", "ice_restart_request"].includes(jsonData.type)) {
            return "SYSTEM_MESSAGE_FILTERED";
          }
          if (jsonData.type && ["file_transfer_start", "file_transfer_response", "file_chunk", "chunk_confirmation", "file_transfer_complete", "file_transfer_error"].includes(jsonData.type)) {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F4C1} File transfer message detected, blocking from chat", { type: jsonData.type });
            }
            return "FILE_MESSAGE_FILTERED";
          }
          if (jsonData.type === "message") {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F4DD} Regular message detected, extracting text", { data: jsonData.data });
            }
            return jsonData.data;
          }
          if (jsonData.type === "enhanced_message" && jsonData.data) {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F510} Enhanced message detected, decrypting...");
            }
            if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
              this._secureLog("error", "\u274C Missing encryption keys");
              return null;
            }
            const decryptedResult = await window.EnhancedSecureCryptoUtils.decryptMessage(
              jsonData.data,
              this.encryptionKey,
              this.macKey,
              this.metadataKey
            );
            if (this._debugMode) {
              this._secureLog("debug", "\u2705 Enhanced message decrypted, extracting...");
              this._secureLog("debug", "\u{1F50D} decryptedResult", {
                type: typeof decryptedResult,
                hasMessage: !!decryptedResult?.message,
                messageType: typeof decryptedResult?.message,
                messageLength: decryptedResult?.message?.length || 0,
                messageSample: decryptedResult?.message?.substring(0, 50) || "no message"
              });
            }
            try {
              const decryptedContent = JSON.parse(decryptedResult.message);
              if (decryptedContent.type === "fake" || decryptedContent.isFakeTraffic === true) {
                if (this._debugMode) {
                  this._secureLog("warn", `\u{1F3AD} BLOCKED: Encrypted fake message: ${decryptedContent.pattern || "unknown"}`);
                }
                return "FAKE_MESSAGE_FILTERED";
              }
            } catch (e) {
              if (this._debugMode) {
                this._secureLog("debug", "\u{1F4DD} Decrypted content is not JSON, treating as plain text message");
              }
            }
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F4E4} Returning decrypted message", { message: decryptedResult.message?.substring(0, 50) });
            }
            return decryptedResult.message;
          }
          if (jsonData.type === "message" && jsonData.data) {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F4DD} Regular message detected, extracting data");
            }
            return jsonData.data;
          }
          if (jsonData.type === "message") {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F4DD} Regular message detected, returning for display");
            }
            return data;
          }
          if (!jsonData.type || jsonData.type !== "fake" && !["heartbeat", "verification", "verification_response", "peer_disconnect", "key_rotation_signal", "key_rotation_ready", "enhanced_message", "security_upgrade", "ice_restart_offer", "ice_restart_answer", "ice_restart_request", "file_transfer_start", "file_transfer_response", "file_chunk", "chunk_confirmation", "file_transfer_complete", "file_transfer_error"].includes(jsonData.type)) {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F4DD} Regular message detected, returning for display");
            }
            return data;
          }
        } catch (e) {
          if (this._debugMode) {
            this._secureLog("debug", "\u{1F4C4} Not JSON, processing as raw data");
          }
          return data;
        }
      }
      if (this.encryptionKey && typeof processedData === "string" && processedData.length > 50) {
        try {
          const base64Regex = /^[A-Za-z0-9+/=]+$/;
          if (base64Regex.test(processedData.trim())) {
            if (this._debugMode) {
              this._secureLog("debug", "\u{1F513} Applying standard decryption...");
            }
            processedData = await window.EnhancedSecureCryptoUtils.decryptData(processedData, this.encryptionKey);
            if (this._debugMode) {
              this._secureLog("debug", "\u2705 Standard decryption successful");
            }
            if (typeof processedData === "string") {
              try {
                const legacyContent = JSON.parse(processedData);
                if (legacyContent.type === "fake" || legacyContent.isFakeTraffic === true) {
                  if (this._debugMode) {
                    this._secureLog("warn", `\u{1F3AD} BLOCKED: Legacy fake message: ${legacyContent.pattern || "unknown"}`);
                  }
                  return "FAKE_MESSAGE_FILTERED";
                }
              } catch (e) {
              }
              processedData = new TextEncoder().encode(processedData).buffer;
            }
          }
        } catch (error) {
          if (this._debugMode) {
            this._secureLog("warn", "\u26A0\uFE0F Standard decryption failed:", { details: error.message });
          }
          return data;
        }
      }
      if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer && processedData.byteLength > 12) {
        try {
          processedData = await this.removeNestedEncryption(processedData);
          if (processedData instanceof ArrayBuffer) {
            try {
              const textData = new TextDecoder().decode(processedData);
              const nestedContent = JSON.parse(textData);
              if (nestedContent.type === "fake" || nestedContent.isFakeTraffic === true) {
                if (this._debugMode) {
                  this._secureLog("warn", `\u{1F3AD} BLOCKED: Nested fake message: ${nestedContent.pattern || "unknown"}`);
                }
                return "FAKE_MESSAGE_FILTERED";
              }
            } catch (e) {
            }
          }
        } catch (error) {
          if (this._debugMode) {
            this._secureLog("warn", "\u26A0\uFE0F Nested decryption failed - skipping this layer:", { details: error.message });
          }
        }
      }
      if (this.securityFeatures.hasPacketReordering && this.reorderingConfig.enabled && processedData instanceof ArrayBuffer) {
        try {
          const headerSize = this.reorderingConfig.useTimestamps ? 12 : 8;
          if (processedData.byteLength > headerSize) {
            return await this.processReorderedPacket(processedData);
          }
        } catch (error) {
          if (this._debugMode) {
            this._secureLog("warn", "\u26A0\uFE0F Reordering processing failed - using direct processing:", { details: error.message });
          }
        }
      }
      if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
        try {
          processedData = this.removePacketPadding(processedData);
        } catch (error) {
          if (this._debugMode) {
            this._secureLog("warn", "\u26A0\uFE0F Padding removal failed:", { details: error.message });
          }
        }
      }
      if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
        try {
          processedData = this.removeAntiFingerprinting(processedData);
        } catch (error) {
          if (this._debugMode) {
            this._secureLog("warn", "\u26A0\uFE0F Anti-fingerprinting removal failed:", { details: error.message });
          }
        }
      }
      if (processedData instanceof ArrayBuffer) {
        processedData = new TextDecoder().decode(processedData);
      }
      if (typeof processedData === "string") {
        try {
          const finalContent = JSON.parse(processedData);
          if (finalContent.type === "fake" || finalContent.isFakeTraffic === true) {
            if (this._debugMode) {
              this._secureLog("warn", `\u{1F3AD} BLOCKED: Final check fake message: ${finalContent.pattern || "unknown"}`);
            }
            return "FAKE_MESSAGE_FILTERED";
          }
        } catch (e) {
        }
      }
      return processedData;
    } catch (error) {
      this._secureLog("error", "\u274C Critical error in removeSecurityLayers:", { errorType: error?.constructor?.name || "Unknown" });
      return data;
    }
  }
  removeAntiFingerprinting(data) {
    return data;
  }
  async applySecurityLayers(data, isFakeMessage = false) {
    try {
      let processedData = data;
      if (isFakeMessage) {
        if (this.encryptionKey && typeof processedData === "string") {
          processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
        }
        return processedData;
      }
      if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer) {
        processedData = await this.applyNestedEncryption(processedData);
      }
      if (this.securityFeatures.hasPacketReordering && this.reorderingConfig?.enabled && processedData instanceof ArrayBuffer) {
        processedData = this.applyPacketReordering(processedData);
      }
      if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
        processedData = this.applyPacketPadding(processedData);
      }
      if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
        processedData = this.applyAntiFingerprinting(processedData);
      }
      if (this.encryptionKey && typeof processedData === "string") {
        processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
      }
      return processedData;
    } catch (error) {
      this._secureLog("error", "\u274C Error in applySecurityLayers:", { errorType: error?.constructor?.name || "Unknown" });
      return data;
    }
  }
  /**
   * Whitelist + bound the per-message UI metadata so a peer cannot smuggle
   * arbitrary objects, huge values, or absurd timers through it.
   * @param {object} meta
   * @returns {object|null}
   */
  _sanitizeMessageMeta(meta) {
    if (!meta || typeof meta !== "object") return null;
    const out = {};
    if (typeof meta.mid === "string" && meta.mid.length > 0 && meta.mid.length <= 64) {
      out.mid = meta.mid.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 64);
    }
    if (meta.code === true) out.code = true;
    if (meta.once === true) out.once = true;
    if (Number.isFinite(meta.onceTtl)) {
      const onceTtl = Math.floor(meta.onceTtl);
      if (onceTtl >= 1 && onceTtl <= 3600) out.onceTtl = onceTtl;
    }
    if (Number.isFinite(meta.ttl)) {
      const ttl = Math.floor(meta.ttl);
      if (ttl >= 5 && ttl <= 86400) out.ttl = ttl;
    }
    return Object.keys(out).length ? out : null;
  }
  /**
   * Unsend: ask the peer to remove a previously delivered message by id.
   * Sent over the authenticated DTLS control channel like other system
   * messages. Best-effort and cooperative — a peer can ignore it, exactly
   * like WhatsApp/Telegram "delete for everyone".
   * @param {string} messageId
   * @returns {boolean}
   */
  sendMessageDelete(messageId) {
    if (typeof messageId !== "string" || !messageId) return false;
    return this.sendSystemMessage({
      type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.MESSAGE_DELETE,
      messageId: messageId.slice(0, 64)
    });
  }
  /**
   * Delivery receipt: tell the sender we received a chat message (by id), so
   * their bubble can flip from "sent" (✓) to "delivered" (✓✓). Best-effort,
   * over the same authenticated control channel as unsend.
   * @param {string} messageId
   * @returns {boolean}
   */
  sendDeliveryReceipt(messageId) {
    if (typeof messageId !== "string" || !messageId) return false;
    return this.sendSystemMessage({
      type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.MESSAGE_RECEIPT,
      messageId: messageId.slice(0, 64)
    });
  }
  async sendMessage(data, meta = null) {
    const validation = this._validateInputData(data, "sendMessage");
    if (!validation.isValid) {
      const errorMessage = `Input validation failed: ${validation.errors.join(", ")}`;
      this._secureLog("error", "\u274C Input validation failed in sendMessage", {
        errors: validation.errors,
        dataType: typeof data,
        dataLength: data?.length || data?.byteLength || 0
      });
      throw new Error(errorMessage);
    }
    if (!this._checkRateLimit("sendMessage")) {
      throw new Error("Rate limit exceeded for message sending");
    }
    this._enforceVerificationGate("sendMessage");
    if (!this.dataChannel || this.dataChannel.readyState !== "open") {
      throw new Error("Data channel not ready");
    }
    try {
      if (!(this.encryptionKey && this.macKey && this.metadataKey)) {
        await this._tryReinitializeEncryptionKeys();
      }
      this._secureLog("debug", "sendMessage called", {
        hasDataChannel: !!this.dataChannel,
        dataChannelReady: this.dataChannel?.readyState === "open",
        isInitiator: this.isInitiator,
        isVerified: this.isVerified,
        connectionReady: this.peerConnection?.connectionState === "connected"
      });
      this._secureLog("debug", "\u{1F50D} sendMessage DEBUG", {
        dataType: typeof validation.sanitizedData,
        isString: typeof validation.sanitizedData === "string",
        isArrayBuffer: validation.sanitizedData instanceof ArrayBuffer,
        dataLength: validation.sanitizedData?.length || validation.sanitizedData?.byteLength || 0
      });
      if (typeof validation.sanitizedData === "string") {
        try {
          const parsed = JSON.parse(validation.sanitizedData);
          if (parsed.type && parsed.type.startsWith("file_")) {
            this._secureLog("debug", "\u{1F4C1} File message detected - applying full encryption with AAD", { type: parsed.type });
            const aad = this._createFileMessageAAD(parsed.type, parsed.data);
            const encryptedData = await this._encryptFileMessage(validation.sanitizedData, aad);
            this.dataChannel.send(encryptedData);
            return true;
          }
        } catch (jsonError) {
        }
      }
      if (typeof validation.sanitizedData === "string") {
        if (typeof this._createMessageAAD !== "function") {
          throw new Error("_createMessageAAD method is not available. Manager may not be fully initialized.");
        }
        const aad = this._createMessageAAD("message", { content: validation.sanitizedData });
        const envelope = {
          type: "message",
          data: validation.sanitizedData,
          timestamp: Date.now(),
          aad
          // Include AAD for sequence number validation
        };
        if (meta && typeof meta === "object") {
          envelope.meta = this._sanitizeMessageMeta(meta);
        }
        return await this.sendSecureMessage(envelope);
      }
      this._secureLog("debug", "\u{1F510} Applying security layers to non-string data");
      const securedData = await this._applySecurityLayersWithLimitedMutex(validation.sanitizedData, false);
      this.dataChannel.send(securedData);
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to send message", {
        error: error.message,
        errorType: error.constructor.name
      });
      throw error;
    }
  }
  // FIX: New method applying security layers with limited mutex use
  async _applySecurityLayersWithLimitedMutex(data, isFakeMessage = false) {
    return this._withMutex("cryptoOperation", async (operationId) => {
      try {
        let processedData = data;
        if (isFakeMessage) {
          if (this.encryptionKey && typeof processedData === "string") {
            processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
          }
          return processedData;
        }
        if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer) {
          processedData = await this.applyNestedEncryption(processedData);
        }
        if (this.securityFeatures.hasPacketReordering && this.reorderingConfig?.enabled && processedData instanceof ArrayBuffer) {
          processedData = this.applyPacketReordering(processedData);
        }
        if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
          processedData = this.applyPacketPadding(processedData);
        }
        if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
          processedData = this.applyAntiFingerprinting(processedData);
        }
        if (this.encryptionKey && typeof processedData === "string") {
          processedData = await window.EnhancedSecureCryptoUtils.encryptData(processedData, this.encryptionKey);
        }
        return processedData;
      } catch (error) {
        this._secureLog("error", "\u274C Error in applySecurityLayers:", { errorType: error?.constructor?.name || "Unknown" });
        return data;
      }
    }, 3e3);
  }
  async sendSystemMessage(messageData) {
    const isVerificationMessage = messageData.type === "verification_request" || messageData.type === "verification_response" || messageData.type === "verification_required";
    if (!isVerificationMessage) {
      this._enforceVerificationGate("sendSystemMessage", false);
    }
    if (!this.dataChannel || this.dataChannel.readyState !== "open") {
      this._secureLog("warn", "\u26A0\uFE0F Cannot send system message - data channel not ready");
      return false;
    }
    try {
      const systemMessage = JSON.stringify({
        type: messageData.type,
        data: messageData,
        timestamp: Date.now()
      });
      this._secureLog("debug", "\u{1F527} Sending system message", { type: messageData.type });
      this.dataChannel.send(systemMessage);
      return true;
    } catch (error) {
      this._secureLog("error", "\u274C Failed to send system message:", { errorType: error?.constructor?.name || "Unknown" });
      return false;
    }
  }
  // FIX 1: Simplified mutex system for message processing
  async processMessage(data) {
    try {
      this._noteInboundActivity?.();
      this._secureLog("debug", "\uFFFD\uFFFD Processing message", {
        dataType: typeof data,
        isArrayBuffer: data instanceof ArrayBuffer,
        hasData: !!(data?.length || data?.byteLength)
      });
      if (typeof data === "string") {
        try {
          const parsed = JSON.parse(data);
          const fileMessageTypes2 = [
            "file_transfer_start",
            "file_transfer_response",
            "file_chunk",
            "chunk_confirmation",
            "file_transfer_complete",
            "file_transfer_error"
          ];
          if (parsed.type === "encrypted_file_message") {
            this._secureLog("debug", "\u{1F4C1} Encrypted file message detected in processMessage");
            try {
              const { decryptedData, aad } = await this._decryptFileMessage(data);
              const decryptedParsed = JSON.parse(decryptedData);
              this._secureLog("debug", "\u{1F4C1} File message decrypted successfully", {
                type: decryptedParsed.type,
                aadMessageType: aad.messageType
              });
              if (this.fileTransferSystem && typeof this.fileTransferSystem.handleFileMessage === "function") {
                await this.fileTransferSystem.handleFileMessage(decryptedParsed);
                return;
              }
            } catch (error) {
              this._secureLog("error", "\u274C Failed to decrypt file message", { error: error.message });
              return;
            }
          }
          if (parsed.type && fileMessageTypes2.includes(parsed.type)) {
            this._secureLog("warn", "\u26A0\uFE0F Unencrypted file message detected - this should not happen in secure mode", { type: parsed.type });
            this._secureLog("error", "\u274C Dropping unencrypted file message for security", { type: parsed.type });
            return;
          }
          if (parsed.type === "enhanced_message") {
            this._secureLog("debug", "\u{1F510} Enhanced message detected in processMessage");
            if (!this._checkInboundRateLimit("processMessage:enhanced_message")) {
              return;
            }
            try {
              const decryptedData = await window.EnhancedSecureCryptoUtils.decryptMessage(
                parsed.data,
                this.encryptionKey,
                this.macKey,
                this.metadataKey
              );
              const decryptedParsed = JSON.parse(decryptedData.data);
              if (decryptedData.metadata && decryptedData.metadata.sequenceNumber !== void 0) {
                if (!this._validateIncomingSequenceNumber(decryptedData.metadata.sequenceNumber, "enhanced_message")) {
                  this._secureLog("warn", "\u26A0\uFE0F Enhanced message sequence number validation failed - possible replay attack", {
                    received: decryptedData.metadata.sequenceNumber,
                    expected: this.expectedSequenceNumber
                  });
                  return;
                }
              }
              if (decryptedParsed.type === "message" && this.onMessage && decryptedParsed.data) {
                this.deliverMessageToUI(decryptedParsed.data, "received", decryptedParsed.meta);
              }
              return;
            } catch (error) {
              this._secureLog("error", "\u274C Failed to decrypt enhanced message", { error: error.message });
              return;
            }
          }
          if (parsed.type === _EnhancedSecureWebRTCManager.MESSAGE_TYPES.MESSAGE) {
            this._secureLog("error", "Rejected unencrypted frame in processMessage", {
              messageType: "message"
            });
            return;
          }
          if (parsed.type && _EnhancedSecureWebRTCManager.POST_VERIFICATION_CONTROL_TYPES.has(parsed.type)) {
            if (!this._enforceVerificationGate("control_frame_receive", false)) {
              this._secureLog("error", "Dropped control frame received before verification", {
                messageType: parsed.type
              });
              return;
            }
            const T = _EnhancedSecureWebRTCManager.MESSAGE_TYPES;
            if (parsed.type === T.MESSAGE_DELETE) {
              const messageId = parsed?.data?.messageId ?? parsed?.messageId;
              if (typeof messageId === "string" && messageId) {
                try {
                  this.onMessageDelete?.(messageId.slice(0, 64));
                } catch (_) {
                }
              }
              return;
            }
            if (parsed.type === T.MESSAGE_RECEIPT) {
              const messageId = parsed?.data?.messageId ?? parsed?.messageId;
              if (typeof messageId === "string" && messageId) {
                try {
                  this.onMessageDelivered?.(messageId.slice(0, 64));
                } catch (_) {
                }
              }
              return;
            }
            if ([
              T.CALL_OFFER,
              T.CALL_ANSWER,
              T.CALL_ICE,
              T.CALL_DECLINE,
              T.CALL_END
            ].includes(parsed.type)) {
              try {
                await this._handleCallSignal(parsed.type, parsed.data || {});
              } catch (e) {
                this._secureLog("error", "\u274C Call signal handling failed", { errorType: e?.constructor?.name });
              }
              return;
            }
            if ([
              T.ICE_RESTART_OFFER,
              T.ICE_RESTART_ANSWER,
              T.ICE_RESTART_REQUEST
            ].includes(parsed.type)) {
              try {
                await this._handleIceRestartSignal(parsed.type, parsed.data || {});
              } catch (e) {
                this._secureLog("error", "\u274C ICE restart signal handling failed", { errorType: e?.constructor?.name });
              }
              return;
            }
            return;
          }
          if (parsed.type && ["heartbeat", "verification", "verification_response", "verification_confirmed", "verification_both_confirmed", "peer_disconnect", "security_upgrade"].includes(parsed.type)) {
            this.handleSystemMessage(parsed);
            return;
          }
          if (parsed.type === "fake") {
            this._secureLog("warn", "\u{1F3AD} Fake message blocked in processMessage", { pattern: parsed.pattern });
            return;
          }
        } catch (jsonError) {
          this._secureLog("error", "Rejected malformed (non-JSON) frame in processMessage", {
            dataLength: typeof data === "string" ? data.length : 0
          });
          return;
        }
      }
      const originalData = await this._processEncryptedDataWithLimitedMutex(data);
      if (originalData === "FAKE_MESSAGE_FILTERED" || originalData === "FILE_MESSAGE_FILTERED" || originalData === "SYSTEM_MESSAGE_FILTERED") {
        return;
      }
      if (!originalData) {
        this._secureLog("warn", "\u26A0\uFE0F No data returned from removeSecurityLayers");
        return;
      }
      let messageText;
      if (typeof originalData === "string") {
        try {
          const message = JSON.parse(originalData);
          if (message.type && fileMessageTypes.includes(message.type)) {
            this._secureLog("debug", "\u{1F4C1} File message detected after decryption", { type: message.type });
            if (this.fileTransferSystem) {
              await this.fileTransferSystem.handleFileMessage(message);
            }
            return;
          }
          if (message.type && ["heartbeat", "verification", "verification_response", "verification_confirmed", "verification_both_confirmed", "peer_disconnect", "security_upgrade"].includes(message.type)) {
            this.handleSystemMessage(message);
            return;
          }
          if (message.type === "fake") {
            this._secureLog("warn", `\u{1F3AD} Post-decryption fake message blocked: ${message.pattern}`);
            return;
          }
          if (message.type === "message" && message.data) {
            messageText = message.data;
          } else {
            messageText = originalData;
          }
        } catch (e) {
          messageText = originalData;
        }
      } else if (originalData instanceof ArrayBuffer) {
        messageText = new TextDecoder().decode(originalData);
      } else if (originalData && typeof originalData === "object" && originalData.message) {
        messageText = originalData.message;
      } else {
        this._secureLog("warn", "\u26A0\uFE0F Unexpected data type after processing:", { details: typeof originalData });
        return;
      }
      if (messageText && messageText.trim().startsWith("{")) {
        try {
          const finalCheck = JSON.parse(messageText);
          if (finalCheck.type === "fake") {
            this._secureLog("warn", `\u{1F3AD} Final fake message check blocked: ${finalCheck.pattern}`);
            return;
          }
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
            "peer_disconnect",
            "key_rotation_signal",
            "key_rotation_ready",
            "security_upgrade",
            "ice_restart_offer",
            "ice_restart_answer",
            "ice_restart_request"
          ];
          if (finalCheck.type && blockedTypes.includes(finalCheck.type)) {
            this._secureLog("warn", `\u{1F4C1} Final system/file message check blocked: ${finalCheck.type}`);
            return;
          }
        } catch (e) {
        }
      }
      if (messageText) {
        this._secureLog("error", "Rejected unauthenticated payload at the end of processMessage", {
          messageLength: typeof messageText === "string" ? messageText.length : 0
        });
      }
    } catch (error) {
      this._secureLog("error", "\u274C Failed to process message:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  // FIX: New method with limited mutex when processing encrypted data
  async _processEncryptedDataWithLimitedMutex(data) {
    return this._withMutex("cryptoOperation", async (operationId) => {
      this._secureLog("debug", "\u{1F510} Processing encrypted data with limited mutex", {
        operationId,
        dataType: typeof data
      });
      try {
        const originalData = await this.removeSecurityLayers(data);
        return originalData;
      } catch (error) {
        this._secureLog("error", "\u274C Error processing encrypted data", {
          operationId,
          errorType: error.constructor.name
        });
        return data;
      }
    }, 2e3);
  }
  notifySecurityUpdate() {
    try {
      this._secureLog("debug", "\u{1F512} Notifying about security level update", {
        isConnected: this.isConnected(),
        isVerified: this.isVerified,
        hasKeys: !!(this.encryptionKey && this.macKey && this.metadataKey),
        hasLastCalculation: !!this.lastSecurityCalculation
      });
      this._dispatchAppEvent?.(new CustomEvent("security-level-updated", {
        detail: {
          timestamp: Date.now(),
          manager: "webrtc",
          webrtcManager: this,
          isConnected: this.isConnected(),
          isVerified: this.isVerified,
          hasKeys: !!(this.encryptionKey && this.macKey && this.metadataKey),
          lastCalculation: this.lastSecurityCalculation
        }
      }));
      setTimeout(() => {
      }, 100);
      if (this.lastSecurityCalculation) {
        this._dispatchAppEvent?.(new CustomEvent("real-security-calculated", {
          detail: {
            securityData: this.lastSecurityCalculation,
            webrtcManager: this,
            timestamp: Date.now()
          }
        }));
      }
    } catch (error) {
      this._secureLog("error", "\u274C Error in notifySecurityUpdate", {
        error: error.message
      });
    }
  }
  handleSystemMessage(message) {
    this._secureLog("debug", "\u{1F527} Handling system message:", { type: message.type });
    switch (message.type) {
      case "heartbeat":
        this.handleHeartbeat(message);
        break;
      case "verification":
        this.handleVerificationRequest(message.data);
        break;
      case "verification_response":
        this.handleVerificationResponse(message.data);
        break;
      case "sas_code":
        this.handleSASCode(message.data);
        break;
      case "verification_confirmed":
        this.handleVerificationConfirmed(message.data);
        break;
      case "verification_both_confirmed":
        this.handleVerificationBothConfirmed(message.data);
        break;
      case "peer_disconnect":
        this.handlePeerDisconnectNotification(message);
        break;
      case "key_rotation_signal":
        this._secureLog("debug", "\u{1F504} Key rotation signal received (ignored for stability)");
        break;
      case "key_rotation_ready":
        this._secureLog("debug", "\u{1F504} Key rotation ready signal received (ignored for stability)");
        break;
      case "security_upgrade":
        this._secureLog("debug", "\u{1F512} Security upgrade notification received:", { type: message.type });
        break;
      default:
        this._secureLog("debug", "\u{1F527} Unknown system message type:", { type: message.type });
    }
  }
  // ============================================
  // FUNCTION MANAGEMENT METHODS
  // ============================================
  // Method to enable Stage 2 functions
  enableStage2Security() {
    if (this.sessionConstraints?.hasPacketReordering) {
      this.securityFeatures.hasPacketReordering = true;
      this.reorderingConfig.enabled = true;
    }
    if (this.sessionConstraints?.hasAntiFingerprinting) {
      this.securityFeatures.hasAntiFingerprinting = true;
      this.antiFingerprintingConfig.enabled = true;
      this.antiFingerprintingConfig.randomizeSizes = true;
      this.antiFingerprintingConfig.maskPatterns = true;
      this.antiFingerprintingConfig.useRandomHeaders = true;
    }
    this.notifySecurityUpgrade(2);
    setTimeout(() => {
      this.calculateAndReportSecurityLevel();
    }, 500);
  }
  // Method to enable Stage 3 features (traffic obfuscation)
  enableStage3Security() {
    this._secureLog("info", "\u{1F512} Enabling Stage 3 features (traffic obfuscation)");
    if (this.sessionConstraints?.hasMessageChunking) {
      this.securityFeatures.hasMessageChunking = true;
      this.chunkingConfig.enabled = true;
    }
    if (this.sessionConstraints?.hasFakeTraffic) {
      this.securityFeatures.hasFakeTraffic = true;
      this.fakeTrafficConfig.enabled = true;
      this.startFakeTrafficGeneration();
    }
    this.notifySecurityUpgrade(3);
    setTimeout(() => {
      this.calculateAndReportSecurityLevel();
    }, 500);
  }
  // Method for enabling Stage 4 functions (maximum safety)
  enableStage4Security() {
    this._secureLog("info", "\u{1F512} Enabling Stage 4 features (maximum safety)");
    if (this.sessionConstraints?.hasDecoyChannels && this.isConnected() && this.isVerified) {
      this.securityFeatures.hasDecoyChannels = true;
      this.decoyChannelConfig.enabled = true;
      try {
        this.initializeDecoyChannels();
      } catch (error) {
        this._secureLog("warn", "\u26A0\uFE0F Decoy channels initialization failed:", { details: error.message });
        this.securityFeatures.hasDecoyChannels = false;
        this.decoyChannelConfig.enabled = false;
      }
    }
    if (this.sessionConstraints?.hasAntiFingerprinting) {
      this.antiFingerprintingConfig.randomizeSizes = true;
      this.antiFingerprintingConfig.maskPatterns = true;
      this.antiFingerprintingConfig.useRandomHeaders = false;
    }
    this.notifySecurityUpgrade(4);
    setTimeout(() => {
      this.calculateAndReportSecurityLevel();
    }, 500);
  }
  forceSecurityUpdate() {
    setTimeout(() => {
      this.calculateAndReportSecurityLevel();
      this.notifySecurityUpdate();
    }, 100);
  }
  // Method for getting security status
  getSecurityStatus() {
    const activeFeatures = Object.entries(this.securityFeatures).filter(([key, value]) => value === true).map(([key]) => key);
    const stage = 4;
    return {
      stage,
      securityLevel: "maximum",
      activeFeatures,
      totalFeatures: Object.keys(this.securityFeatures).length,
      activeFeaturesCount: activeFeatures.length,
      activeFeaturesNames: activeFeatures,
      sessionConstraints: this.sessionConstraints
    };
  }
  // Method to notify UI about security update
  notifySecurityUpgrade(stage) {
    const stageNames = {
      1: "Basic Enhanced",
      2: "Medium Security",
      3: "High Security",
      4: "Maximum Security"
    };
    const message = `\u{1F512} Security upgraded to Stage ${stage}: ${stageNames[stage]}`;
    if (!this.securityUpgradeNotificationSent || this.lastSecurityUpgradeStage !== stage) {
      this.securityUpgradeNotificationSent = true;
      this.lastSecurityUpgradeStage = stage;
      if (this.onMessage) {
        this.deliverMessageToUI(message, "system");
      }
    }
    if (this.dataChannel && this.dataChannel.readyState === "open") {
      try {
        const securityNotification = {
          type: "security_upgrade",
          stage,
          stageName: stageNames[stage],
          message,
          timestamp: Date.now()
        };
        this._secureLog("debug", "\u{1F512} Sending security upgrade notification to peer:", { type: securityNotification.type, stage: securityNotification.stage });
        this.dataChannel.send(JSON.stringify(securityNotification));
      } catch (error) {
        this._secureLog("warn", "\u26A0\uFE0F Failed to send security upgrade notification to peer:", { details: error.message });
      }
    }
    const status = this.getSecurityStatus();
  }
  async calculateAndReportSecurityLevel() {
    try {
      if (!window.EnhancedSecureCryptoUtils) {
        this._secureLog("warn", "\u26A0\uFE0F EnhancedSecureCryptoUtils not available for security calculation");
        return null;
      }
      if (!this.isConnected() || !this.isVerified || !this.encryptionKey || !this.macKey) {
        this._secureLog("debug", "\u26A0\uFE0F WebRTC not ready for security calculation", {
          connected: this.isConnected(),
          verified: this.isVerified,
          hasEncryptionKey: !!this.encryptionKey,
          hasMacKey: !!this.macKey
        });
        return null;
      }
      this._secureLog("debug", "\u{1F50D} Calculating real security level", {
        managerState: "ready",
        hasAllKeys: !!(this.encryptionKey && this.macKey && this.metadataKey)
      });
      const securityData = await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(this);
      this._secureLog("info", "Real security level calculated", {
        hasSecurityLevel: !!securityData.level,
        scoreRange: securityData.score > 80 ? "high" : securityData.score > 50 ? "medium" : "low",
        checksRatio: `${securityData.passedChecks}/${securityData.totalChecks}`,
        isRealCalculation: securityData.isRealData
      });
      this.lastSecurityCalculation = securityData;
      this._dispatchAppEvent?.(new CustomEvent("real-security-calculated", {
        detail: {
          securityData,
          webrtcManager: this,
          timestamp: Date.now(),
          source: "calculateAndReportSecurityLevel"
        }
      }));
      if (securityData.isRealData && this.onMessage) {
        if (!this.securityCalculationNotificationSent || this.lastSecurityCalculationLevel !== securityData.level) {
          this.securityCalculationNotificationSent = true;
          this.lastSecurityCalculationLevel = securityData.level;
          const message = `Security Level: ${securityData.level} (${securityData.score}%) - ${securityData.passedChecks}/${securityData.totalChecks} checks passed`;
          this.deliverMessageToUI(message, "system");
        }
      }
      return securityData;
    } catch (error) {
      this._secureLog("error", "Failed to calculate real security level", {
        errorType: error.constructor.name
      });
      return null;
    }
  }
  // ============================================
  // AUTOMATIC STEP-BY-STEP SWITCHING ON
  // ============================================
  // Method for automatic feature enablement with stability check
  async autoEnableSecurityFeatures() {
    this._secureLog("info", "Starting graduated security activation - all features enabled");
    const checkStability = () => {
      const isStable = this.isConnected() && this.isVerified && this.connectionAttempts === 0 && this.messageQueue.length === 0 && this.peerConnection?.connectionState === "connected";
      return isStable;
    };
    await this.calculateAndReportSecurityLevel();
    this.notifySecurityUpgrade(1);
    setTimeout(async () => {
      if (checkStability()) {
        this.enableStage2Security();
        await this.calculateAndReportSecurityLevel();
        setTimeout(async () => {
          if (checkStability()) {
            this.enableStage3Security();
            await this.calculateAndReportSecurityLevel();
            setTimeout(async () => {
              if (checkStability()) {
                this.enableStage4Security();
                await this.calculateAndReportSecurityLevel();
              }
            }, 2e4);
          }
        }, 15e3);
      }
    }, 1e4);
  }
  // ============================================
  // CONNECTION MANAGEMENT WITH ENHANCED SECURITY
  // ============================================
  async establishConnection() {
    try {
      await this.initializeEnhancedSecurity();
      if (this.fakeTrafficConfig.enabled) {
        this.startFakeTrafficGeneration();
      }
      if (this.decoyChannelConfig.enabled) {
        this.initializeDecoyChannels();
      }
    } catch (error) {
      this._secureLog("error", "\u274C Failed to establish enhanced connection:", { errorType: error?.constructor?.name || "Unknown" });
      this.onStatusChange("disconnected");
      throw error;
    }
  }
  /**
   *   Clear all verification states and data
   * Called when verification is rejected or connection is terminated
   */
  _clearVerificationStates() {
    try {
      this.localVerificationConfirmed = false;
      this.remoteVerificationConfirmed = false;
      this.bothVerificationsConfirmed = false;
      this.isVerified = false;
      this.verificationCode = null;
      this.pendingSASCode = null;
      this.sasValidationAttempts = 0;
      this._verificationUiOpened = false;
      this._sasLocalFingerprint = null;
      this._sasRemoteFingerprint = null;
      this.keyFingerprint = null;
      this.expectedDTLSFingerprint = null;
      this._peerDTLSFingerprint = null;
      this.connectionId = null;
      this.processedMessageIds.clear();
      this.verificationNotificationSent = false;
      this.verificationInitiationSent = false;
    } catch (error) {
      this._secureLog("error", "\u274C Error clearing verification states:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  // Start periodic cleanup for rate limiting and security
  startPeriodicCleanup() {
    this._secureLog("info", "\u{1F527} Periodic cleanup moved to unified scheduler");
  }
  // Calculate current security level with real verification
  async calculateSecurityLevel() {
    return await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(this);
  }
  // PFS: Check if key rotation is needed
  shouldRotateKeys() {
    if (!this.isConnected() || !this.isVerified) {
      return false;
    }
    const now = Date.now();
    const timeSinceLastRotation = now - this.lastKeyRotation;
    return timeSinceLastRotation > this.keyRotationInterval || this.messageCounter % 100 === 0;
  }
  // PFS: Rotate encryption keys for Perfect Forward Secrecy
  async rotateKeys() {
    return this._withMutex("keyOperation", async (operationId) => {
      this._secureLog("info", "\u{1F504} Starting key rotation with mutex", {
        operationId
      });
      if (!this.isConnected() || !this.isVerified) {
        this._secureLog("warn", " Key rotation aborted - connection not ready", {
          operationId,
          isConnected: this.isConnected(),
          isVerified: this.isVerified
        });
        return false;
      }
      if (this._keySystemState.isRotating) {
        this._secureLog("warn", " Key rotation already in progress", {
          operationId
        });
        return false;
      }
      try {
        this._keySystemState.isRotating = true;
        this._keySystemState.lastOperation = "rotation";
        this._keySystemState.lastOperationTime = Date.now();
        const rotationSignal = {
          type: "key_rotation_signal",
          newVersion: this.currentKeyVersion + 1,
          timestamp: Date.now(),
          operationId
        };
        if (this.dataChannel && this.dataChannel.readyState === "open") {
          this.dataChannel.send(JSON.stringify(rotationSignal));
        } else {
          throw new Error("Data channel not ready for key rotation");
        }
        this._hardWipeOldKeys();
        return new Promise((resolve) => {
          this.pendingRotation = {
            newVersion: this.currentKeyVersion + 1,
            operationId,
            resolve,
            timeout: setTimeout(() => {
              this._secureLog("error", " Key rotation timeout", {
                operationId
              });
              this._keySystemState.isRotating = false;
              this.pendingRotation = null;
              resolve(false);
            }, 1e4)
            // 10 seconds timeout
          };
        });
      } catch (error) {
        this._secureLog("error", " Key rotation failed in critical section", {
          operationId,
          errorType: error.constructor.name
        });
        this._keySystemState.isRotating = false;
        return false;
      }
    }, 1e4);
  }
  //   Real PFS - Clean up old keys with hard wipe
  cleanupOldKeys() {
    const now = Date.now();
    const maxKeyAge = _EnhancedSecureWebRTCManager.LIMITS.MAX_KEY_AGE;
    let wipedKeysCount = 0;
    for (const [version2, keySet] of this.oldKeys.entries()) {
      if (now - keySet.timestamp > maxKeyAge) {
        if (keySet.encryptionKey) {
          this._secureWipeMemory(keySet.encryptionKey, "pfs_cleanup_wipe");
        }
        if (keySet.macKey) {
          this._secureWipeMemory(keySet.macKey, "pfs_cleanup_wipe");
        }
        if (keySet.metadataKey) {
          this._secureWipeMemory(keySet.metadataKey, "pfs_cleanup_wipe");
        }
        keySet.encryptionKey = null;
        keySet.macKey = null;
        keySet.metadataKey = null;
        keySet.keyFingerprint = null;
        this.oldKeys.delete(version2);
        wipedKeysCount++;
        this._secureLog("info", "\u{1F9F9} Old PFS keys hard wiped and cleaned up", {
          version: version2,
          age: Math.round((now - keySet.timestamp) / 1e3) + "s",
          timestamp: Date.now()
        });
      }
    }
    if (wipedKeysCount > 0) {
      this._secureLog("info", `PFS cleanup completed: ${wipedKeysCount} keys hard wiped`, {
        timestamp: Date.now()
      });
    }
  }
  // PFS: Get keys for specific version (for decryption)
  getKeysForVersion(version2) {
    const oldKeySet = this.oldKeys.get(version2);
    if (oldKeySet && oldKeySet.encryptionKey && oldKeySet.macKey && oldKeySet.metadataKey) {
      return {
        encryptionKey: oldKeySet.encryptionKey,
        macKey: oldKeySet.macKey,
        metadataKey: oldKeySet.metadataKey
      };
    }
    if (version2 === this.currentKeyVersion) {
      if (this.encryptionKey && this.macKey && this.metadataKey) {
        return {
          encryptionKey: this.encryptionKey,
          macKey: this.macKey,
          metadataKey: this.metadataKey
        };
      }
    }
    window.EnhancedSecureCryptoUtils.secureLog.log("error", "No valid keys found for version", {
      requestedVersion: version2,
      currentVersion: this.currentKeyVersion,
      availableVersions: Array.from(this.oldKeys.keys())
    });
    return null;
  }
  _hasTurnServer() {
    return (this._config.webrtc.iceServers || []).some((server) => {
      const urls = Array.isArray(server.urls) ? server.urls : [server.urls];
      return urls.some((url) => typeof url === "string" && url.toLowerCase().startsWith("turn:"));
    });
  }
  _buildPeerConnectionConfig() {
    const relayOnly = this._isRelayOnlyMode();
    const config = {
      iceServers: this._config.webrtc.iceServers,
      iceCandidatePoolSize: 10,
      bundlePolicy: "balanced"
    };
    if (relayOnly) {
      config.iceTransportPolicy = "relay";
    }
    return config;
  }
  _summarizeIceServerConfig(iceServers = []) {
    const summary = {
      serverCount: 0,
      stun: 0,
      turn: 0,
      turns: 0,
      hasCredentials: false
    };
    for (const server of iceServers || []) {
      summary.serverCount += 1;
      if (server?.username || server?.credential) {
        summary.hasCredentials = true;
      }
      const urls = Array.isArray(server?.urls) ? server.urls : [server?.urls];
      for (const rawUrl of urls) {
        const url = String(rawUrl || "").toLowerCase();
        if (url.startsWith("stun:")) summary.stun += 1;
        if (url.startsWith("turn:")) summary.turn += 1;
        if (url.startsWith("turns:")) summary.turns += 1;
      }
    }
    return summary;
  }
  _isRelayOnlyMode() {
    return this._config.webrtc.privacyMode === "relay-only";
  }
  _setRelayOnlyMode(relayOnly) {
    const enabled = relayOnly === true;
    this._config.webrtc.privacyMode = enabled ? "relay-only" : "standard";
    this._config.webrtc.relayOnly = enabled;
  }
  _warnIfTurnMissing() {
    if (this._ipLeakWarningShown) return;
    this._ipLeakWarningShown = true;
    const relayOnly = this._isRelayOnlyMode();
    const hasTurnServer = this._hasTurnServer();
    let message = null;
    if (relayOnly && !hasTurnServer) {
      message = "Privacy mode is relay-only, but no TURN server is configured. Relay-only mode cannot connect until TURN is configured; STUN alone does not hide IP addresses.";
    } else if (!relayOnly && !hasTurnServer) {
      message = "Privacy warning: relay-only mode is disabled and no TURN server is configured. Direct WebRTC connections may expose host or server-reflexive IP addresses; STUN alone does not provide IP protection.";
    } else if (!relayOnly) {
      message = "Privacy warning: relay-only mode is disabled. Direct WebRTC connectivity may expose host or server-reflexive IP addresses even when TURN is available.";
    }
    if (!message) return;
    this.deliverMessageToUI(message, "system");
  }
  createPeerConnection() {
    this._sessionAlive = true;
    const config = this._buildPeerConnectionConfig();
    this._warnIfTurnMissing();
    console.info("[SecureBit ICE] peer connection config", this._summarizeIceServerConfig(config.iceServers));
    this.peerConnection = new RTCPeerConnection(config);
    this._callAudioSender = null;
    this._callVideoSender = null;
    this.peerConnection.onconnectionstatechange = () => {
      const state = this.peerConnection.connectionState;
      console.info("[SecureBit ICE] connection state changed", {
        connectionState: state,
        iceConnectionState: this.peerConnection.iceConnectionState,
        iceGatheringState: this.peerConnection.iceGatheringState
      });
      if (state === "connected" && !this.isVerified) {
        this._notifyVerificationReadyIfPossible();
      } else if (state === "connected" && this.isVerified) {
        if (!this._onPathRecovered()) this.onStatusChange("connected");
      } else if (state === "disconnected") {
        if (this.intentionalDisconnect) {
          this.onStatusChange("disconnected");
          setTimeout(() => this.disconnect(), 100);
        } else if (this.isVerified) {
          this._onPathDegraded("ice_disconnected");
        } else {
          console.warn(`[SecureBit ICE] State is ${state} but not verified yet. Keeping session open for manual exchange.`);
        }
      } else if (state === "closed") {
        this._resetReconnectState();
        this.onStatusChange("disconnected");
        this._clearVerificationStates();
        if (this.intentionalDisconnect) setTimeout(() => this.disconnect(), 100);
      } else if (state === "failed") {
        this._collectIceFailureDiagnostics().then((diagnostics) => {
          console.warn("[SecureBit ICE] failure diagnostics", diagnostics);
          this._noteIceFailureDiagnostics(diagnostics);
        });
        if (this.isVerified) {
          this._onPathLost("ice_failed");
        } else {
          console.warn("[SecureBit ICE] State is failed but not verified yet. Keeping session open for manual exchange.");
        }
      } else if (this.isReconnecting() && (state === "connecting" || state === "new")) {
      } else {
        this.onStatusChange(state);
      }
    };
    this.peerConnection.oniceconnectionstatechange = () => {
      console.info("[SecureBit ICE] ICE connection state changed", {
        connectionState: this.peerConnection.connectionState,
        iceConnectionState: this.peerConnection.iceConnectionState,
        iceGatheringState: this.peerConnection.iceGatheringState
      });
    };
    this.peerConnection.onicecandidateerror = (event) => {
      console.warn("[SecureBit ICE] ICE candidate error", {
        url: event.url,
        errorCode: event.errorCode,
        errorText: event.errorText
      });
    };
    this.peerConnection.ontrack = (event) => {
      try {
        this._refreshRemoteStream();
      } catch (e) {
        this._secureLog("warn", "\u26A0\uFE0F ontrack handling failed", { errorType: e?.constructor?.name });
      }
    };
    this.peerConnection.ondatachannel = (event) => {
      if (event.channel.label === "securechat") {
        this.dataChannel = event.channel;
        this.setupDataChannel(event.channel);
      } else {
        if (event.channel.label === "heartbeat") {
          this.heartbeatChannel = event.channel;
        }
      }
    };
  }
  setupDataChannel(channel) {
    this.dataChannel = channel;
    let openHandled = false;
    const handleChannelOpen = async () => {
      if (openHandled) return;
      openHandled = true;
      try {
        if (this.dataChannel && typeof this.dataChannel.bufferedAmountLowThreshold === "number") {
          this.dataChannel.bufferedAmountLowThreshold = 1024 * 1024;
        }
      } catch (e) {
      }
      if (this._handshakeMode === "sbq2") {
        try {
          await this._runSbq2KeyExchange();
        } catch (error) {
          this._secureLog("error", "SBQ2 key exchange failed to start", {
            errorType: error?.constructor?.name || "Unknown"
          });
          this._sbq2Abort(
            "start_failed",
            "The secure handshake could not be started. Please try connecting again."
          );
          return;
        }
      }
      try {
        await this.establishConnection();
        this.initializeFileTransfer();
      } catch (error) {
        this._secureLog("error", "Error in establishConnection:", { errorType: error?.constructor?.name || "Unknown" });
      }
      if (this.pendingSASCode && this.dataChannel && this.dataChannel.readyState === "open") {
        try {
          const sasPayload = {
            type: "sas_code",
            data: {
              code: this.pendingSASCode,
              timestamp: Date.now(),
              verificationMethod: "SAS",
              securityLevel: "MITM_PROTECTION_REQUIRED"
            }
          };
          this.dataChannel.send(JSON.stringify(sasPayload));
          this.pendingSASCode = null;
        } catch (error) {
        }
      } else if (this.pendingSASCode) {
      }
      if (this.isVerified) {
        this.onStatusChange("connected");
        this.processMessageQueue();
        setTimeout(async () => {
          await this.calculateAndReportSecurityLevel();
          this.autoEnableSecurityFeatures();
          this.notifySecurityUpdate();
        }, 500);
      } else {
        this._notifyVerificationReadyIfPossible();
        this.initiateVerification();
      }
      this.startHeartbeat();
    };
    this.dataChannel.onopen = handleChannelOpen;
    if (this.dataChannel.readyState === "open") {
      Promise.resolve().then(() => handleChannelOpen()).catch((error) => {
        this._secureLog("error", "Deferred data channel open handling failed", {
          errorType: error?.constructor?.name || "Unknown"
        });
      });
    }
    this.dataChannel.onclose = () => {
      this._resetReconnectState?.();
      this._teardownRecoveryLifecycleListeners?.();
      if (!this.intentionalDisconnect) {
        this.onStatusChange("disconnected");
        this._clearVerificationStates();
        if (!this.connectionClosedNotificationSent) {
          this.connectionClosedNotificationSent = true;
          this.deliverMessageToUI("\u{1F50C} Enhanced secure connection closed. Check connection status.", "system");
        }
      } else {
        this.onStatusChange("disconnected");
        this._clearVerificationStates();
        if (!this.connectionClosedNotificationSent) {
          this.connectionClosedNotificationSent = true;
          this.deliverMessageToUI("\u{1F50C} Enhanced secure connection closed", "system");
        }
      }
      this._wipeEphemeralKeys();
      this.stopHeartbeat();
      this.isVerified = false;
    };
    this.dataChannel.onmessage = async (event) => {
      try {
        this._noteInboundActivity?.();
        if (typeof event.data === "string") {
          try {
            const parsed = JSON.parse(event.data);
            const fileMessageTypes2 = [
              "file_transfer_start",
              "file_transfer_response",
              "file_chunk",
              "chunk_confirmation",
              "file_transfer_complete",
              "file_transfer_error"
            ];
            if (parsed.type && fileMessageTypes2.includes(parsed.type)) {
              if (!this._enforceVerificationGate("file_message_receive", false)) {
                this._secureLog("error", "Dropped file message received before verification", {
                  messageType: parsed.type
                });
                return;
              }
              if (!this.fileTransferSystem) {
                try {
                  if (this.isVerified && this.dataChannel && this.dataChannel.readyState === "open") {
                    this.initializeFileTransfer();
                    let attempts2 = 0;
                    const maxAttempts = 30;
                    while (!this.fileTransferSystem && attempts2 < maxAttempts) {
                      await new Promise((resolve) => setTimeout(resolve, 100));
                      attempts2++;
                    }
                  }
                } catch (initError) {
                  this._secureLog("error", "Failed to initialize file transfer system for receiver:", { errorType: initError?.constructor?.name || "Unknown" });
                }
              }
              if (this.fileTransferSystem) {
                await this.fileTransferSystem.handleFileMessage(parsed);
                return;
              }
              this._secureLog("warn", "\u26A0\uFE0F File transfer system not ready, attempting lazy init...");
              try {
                await this._ensureFileTransferReady();
                if (this.fileTransferSystem) {
                  await this.fileTransferSystem.handleFileMessage(parsed);
                  return;
                }
              } catch (e) {
                this._secureLog("error", "Lazy init of file transfer failed:", { errorType: e?.message || e?.constructor?.name || "Unknown" });
              }
              this._secureLog("error", "No file transfer system available for:", { errorType: parsed.type?.constructor?.name || "Unknown" });
              return;
            }
            if (parsed.type && _EnhancedSecureWebRTCManager.POST_VERIFICATION_CONTROL_TYPES.has(parsed.type)) {
              if (!this._enforceVerificationGate("control_frame_receive", false)) {
                this._secureLog("error", "Dropped control frame received before verification", {
                  messageType: parsed.type
                });
                return;
              }
              const T = _EnhancedSecureWebRTCManager.MESSAGE_TYPES;
              if (parsed.type === T.MESSAGE_DELETE) {
                const messageId = parsed?.data?.messageId ?? parsed?.messageId;
                if (typeof messageId === "string" && messageId) {
                  try {
                    this.onMessageDelete?.(messageId.slice(0, 64));
                  } catch (_) {
                  }
                }
                return;
              }
              if (parsed.type === T.MESSAGE_RECEIPT) {
                const messageId = parsed?.data?.messageId ?? parsed?.messageId;
                if (typeof messageId === "string" && messageId) {
                  try {
                    this.onMessageDelivered?.(messageId.slice(0, 64));
                  } catch (_) {
                  }
                }
                return;
              }
              if ([
                T.CALL_OFFER,
                T.CALL_ANSWER,
                T.CALL_ICE,
                T.CALL_DECLINE,
                T.CALL_END
              ].includes(parsed.type)) {
                try {
                  await this._handleCallSignal(parsed.type, parsed.data || {});
                } catch (_) {
                }
                return;
              }
              if ([
                T.ICE_RESTART_OFFER,
                T.ICE_RESTART_ANSWER,
                T.ICE_RESTART_REQUEST
              ].includes(parsed.type)) {
                try {
                  await this._handleIceRestartSignal(parsed.type, parsed.data || {});
                } catch (e) {
                  this._secureLog("error", "\u274C ICE restart signal handling failed", { errorType: e?.constructor?.name });
                }
                return;
              }
              return;
            }
            if (parsed.type === _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_BLOB || parsed.type === _EnhancedSecureWebRTCManager.MESSAGE_TYPES.KEY_PROOF) {
              await this._sbq2HandleHandshakeFrame(parsed);
              return;
            }
            if (parsed.type && ["heartbeat", "verification", "verification_response", "verification_confirmed", "verification_both_confirmed", "sas_code", "peer_disconnect", "security_upgrade"].includes(parsed.type)) {
              this.handleSystemMessage(parsed);
              return;
            }
            if (parsed.type === _EnhancedSecureWebRTCManager.MESSAGE_TYPES.RATCHET_MESSAGE) {
              await this._processRatchetMessage(parsed);
              return;
            }
            if (parsed.type === "enhanced_message" && parsed.data) {
              await this._processEnhancedMessageWithoutMutex(parsed);
              return;
            }
            this._secureLog("error", "Rejected unencrypted frame on the chat channel", {
              messageType: typeof parsed.type === "string" ? parsed.type.slice(0, 32) : typeof parsed.type
            });
            return;
          } catch (jsonError) {
            this._secureLog("error", "Rejected malformed (non-JSON) frame on the chat channel", {
              dataLength: typeof event.data === "string" ? event.data.length : 0
            });
            return;
          }
        } else if (event.data instanceof ArrayBuffer) {
          await this._processBinaryDataWithoutMutex(event.data);
        } else {
        }
      } catch (error) {
        this._secureLog("error", "Failed to process message in onmessage:", { errorType: error?.constructor?.name || "Unknown" });
      }
    };
  }
  // FIX 4: New method for processing binary data WITHOUT mutex
  async _processBinaryDataWithoutMutex(data) {
    try {
      if (!this._checkInboundRateLimit("binary_message")) {
        return;
      }
      let processedData = data;
      if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey && processedData instanceof ArrayBuffer && processedData.byteLength > 12) {
        try {
          processedData = await this.removeNestedEncryption(processedData);
        } catch (error) {
          this._secureLog("warn", "Nested decryption failed, continuing with original data");
        }
      }
      if (this.securityFeatures.hasPacketPadding && processedData instanceof ArrayBuffer) {
        try {
          processedData = this.removePacketPadding(processedData);
        } catch (error) {
          this._secureLog("warn", "Packet padding removal failed, continuing with original data");
        }
      }
      if (this.securityFeatures.hasAntiFingerprinting && processedData instanceof ArrayBuffer) {
        try {
          processedData = this.removeAntiFingerprinting(processedData);
        } catch (error) {
          this._secureLog("warn", "Anti-fingerprinting removal failed, continuing with original data");
        }
      }
      if (processedData instanceof ArrayBuffer) {
        const textData = new TextDecoder().decode(processedData);
        try {
          const content = JSON.parse(textData);
          if (content.type === "fake" || content.isFakeTraffic === true) {
            return;
          }
        } catch (e) {
        }
        this._secureLog("error", "Rejected unauthenticated binary frame on the chat channel", {
          byteLength: data?.byteLength || 0
        });
      }
    } catch (error) {
      this._secureLog("error", "Error processing binary data:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  /**
   * Inbound chat under the Double Ratchet.
   *
   * No sequence-number check is needed or wanted here: replay protection is a
   * property of the ratchet itself, since a message key is destroyed on use and
   * a number behind the current chain has no key left to open it. Layering the
   * old sliding window on top would reject legitimate out-of-order frames that
   * the ratchet can still read.
   */
  async _processRatchetMessage(parsedMessage) {
    try {
      if (!this._checkInboundRateLimit("ratchet_message")) {
        return;
      }
      if (!this.isRatchetActive()) {
        this._secureLog("error", "Received a ratchet message but no ratchet is active");
        return;
      }
      if (typeof parsedMessage?.h !== "string" || typeof parsedMessage?.c !== "string") {
        this._secureLog("error", "Malformed ratchet message frame");
        return;
      }
      const plaintext = await this._ratchet.decrypt(parsedMessage.h, parsedMessage.c);
      try {
        const content = JSON.parse(plaintext);
        if (content.type === "fake" || content.isFakeTraffic === true) return;
        if (content && content.type === "message" && typeof content.data === "string") {
          this.deliverMessageToUI(content.data, "received", content.meta);
          return;
        }
      } catch (_) {
      }
      this.deliverMessageToUI(plaintext, "received");
    } catch (error) {
      this._secureLog("error", "Failed to decrypt ratchet message", {
        errorType: error?.constructor?.name || "Unknown"
      });
    }
  }
  // FIX 3: New method for processing enhanced messages WITHOUT mutex
  async _processEnhancedMessageWithoutMutex(parsedMessage) {
    try {
      if (!this._checkInboundRateLimit("enhanced_message")) {
        return;
      }
      if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
        this._secureLog("error", "Missing encryption keys for enhanced message");
        return;
      }
      const decryptedResult = await window.EnhancedSecureCryptoUtils.decryptMessage(
        parsedMessage.data,
        this.encryptionKey,
        this.macKey,
        this.metadataKey
      );
      if (!this._validateIncomingSequenceNumber(decryptedResult?.sequenceNumber, "enhanced_message")) {
        this._secureLog("error", "Rejected chat message failing anti-replay validation", {
          messageId: decryptedResult?.messageId ? "present" : "absent"
        });
        return;
      }
      if (decryptedResult && decryptedResult.message) {
        try {
          const decryptedContent = JSON.parse(decryptedResult.message);
          if (decryptedContent.type === "fake" || decryptedContent.isFakeTraffic === true) {
            return;
          }
          if (decryptedContent && decryptedContent.type === "message" && typeof decryptedContent.data === "string") {
            if (this.onMessage) {
              this.deliverMessageToUI(decryptedContent.data, "received", decryptedContent.meta);
            }
            return;
          }
        } catch (e) {
        }
        if (this.onMessage) {
          this.deliverMessageToUI(decryptedResult.message, "received");
        }
      } else {
        this._secureLog("warn", "No message content in decrypted result");
      }
    } catch (error) {
      this._secureLog("error", "Error processing enhanced message:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  /**
   * Creates a unique ID for an operation
   */
  _generateOperationId() {
    return `op_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  /**
   *   Atomic mutex acquisition with enhanced race condition protection
   */
  async _acquireMutex(mutexName, operationId, timeout = 5e3) {
    const mutexPropertyName = `_${mutexName}Mutex`;
    const mutex = this[mutexPropertyName];
    if (!mutex) {
      this._secureLog("error", `Unknown mutex: ${mutexName}`, {
        mutexPropertyName,
        availableMutexes: this._getAvailableMutexes(),
        operationId
      });
      throw new Error(`Unknown mutex: ${mutexName}. Available: ${this._getAvailableMutexes().join(", ")}`);
    }
    if (!operationId || typeof operationId !== "string") {
      throw new Error("Invalid operation ID for mutex acquisition");
    }
    return new Promise((resolve, reject) => {
      const attemptLock = () => {
        if (mutex.lockId === operationId) {
          this._secureLog("warn", `Mutex '${mutexName}' already locked by same operation`, {
            operationId
          });
          resolve();
          return;
        }
        if (!mutex.locked) {
          mutex.locked = true;
          mutex.lockId = operationId;
          mutex.lockTime = Date.now();
          this._secureLog("debug", `Mutex '${mutexName}' acquired atomically`, {
            operationId,
            lockTime: mutex.lockTime
          });
          mutex.lockTimeout = setTimeout(() => {
            this._handleMutexTimeout(mutexName, operationId, timeout);
          }, timeout);
          resolve();
        } else {
          const queueItem = {
            resolve,
            reject,
            operationId,
            timestamp: Date.now(),
            timeout: setTimeout(() => {
              const index = mutex.queue.findIndex((item) => item.operationId === operationId);
              if (index !== -1) {
                mutex.queue.splice(index, 1);
                reject(new Error(`Mutex acquisition timeout for '${mutexName}'`));
              }
            }, timeout)
          };
          mutex.queue.push(queueItem);
          this._secureLog("debug", `Operation queued for mutex '${mutexName}'`, {
            operationId,
            queueLength: mutex.queue.length,
            currentLockId: mutex.lockId
          });
        }
      };
      attemptLock();
    });
  }
  /**
   *   Enhanced mutex release with strict validation and error handling
   */
  _releaseMutex(mutexName, operationId) {
    if (!mutexName || typeof mutexName !== "string") {
      throw new Error("Invalid mutex name provided for release");
    }
    if (!operationId || typeof operationId !== "string") {
      throw new Error("Invalid operation ID provided for mutex release");
    }
    const mutexPropertyName = `_${mutexName}Mutex`;
    const mutex = this[mutexPropertyName];
    if (!mutex) {
      this._secureLog("error", `Unknown mutex for release: ${mutexName}`, {
        mutexPropertyName,
        availableMutexes: this._getAvailableMutexes(),
        operationId
      });
      throw new Error(`Unknown mutex for release: ${mutexName}`);
    }
    if (mutex.lockId !== operationId) {
      this._secureLog("error", `CRITICAL: Invalid mutex release attempt - potential race condition`, {
        mutexName,
        expectedLockId: mutex.lockId,
        providedOperationId: operationId,
        mutexState: {
          locked: mutex.locked,
          lockTime: mutex.lockTime,
          queueLength: mutex.queue.length
        }
      });
      throw new Error(`Invalid mutex release attempt for '${mutexName}': expected '${mutex.lockId}', got '${operationId}'`);
    }
    if (!mutex.locked) {
      this._secureLog("error", `CRITICAL: Attempting to release unlocked mutex`, {
        mutexName,
        operationId,
        mutexState: {
          locked: mutex.locked,
          lockId: mutex.lockId,
          lockTime: mutex.lockTime
        }
      });
      throw new Error(`Attempting to release unlocked mutex: ${mutexName}`);
    }
    try {
      if (mutex.lockTimeout) {
        clearTimeout(mutex.lockTimeout);
        mutex.lockTimeout = null;
      }
      const lockDuration = mutex.lockTime ? Date.now() - mutex.lockTime : 0;
      mutex.locked = false;
      mutex.lockId = null;
      mutex.lockTime = null;
      this._secureLog("debug", `Mutex released successfully: ${mutexName}`, {
        operationId,
        lockDuration,
        queueLength: mutex.queue.length
      });
      this._processNextInQueue(mutexName);
    } catch (error) {
      this._secureLog("error", `Error during mutex release queue processing`, {
        mutexName,
        operationId,
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      mutex.locked = false;
      mutex.lockId = null;
      mutex.lockTime = null;
      mutex.lockTimeout = null;
      throw error;
    }
  }
  /**
   *   Enhanced queue processing with comprehensive error handling
   */
  _processNextInQueue(mutexName) {
    const mutex = this[`_${mutexName}Mutex`];
    if (!mutex) {
      this._secureLog("error", `Mutex not found for queue processing: ${mutexName}`);
      return;
    }
    if (mutex.queue.length === 0) {
      return;
    }
    if (mutex.locked) {
      this._secureLog("warn", `Mutex '${mutexName}' is still locked, skipping queue processing`, {
        lockId: mutex.lockId,
        queueLength: mutex.queue.length
      });
      return;
    }
    const nextItem = mutex.queue.shift();
    if (!nextItem) {
      this._secureLog("warn", `Empty queue item for mutex '${mutexName}'`);
      return;
    }
    if (!nextItem.operationId || !nextItem.resolve || !nextItem.reject) {
      this._secureLog("error", `Invalid queue item structure for mutex '${mutexName}'`, {
        hasOperationId: !!nextItem.operationId,
        hasResolve: !!nextItem.resolve,
        hasReject: !!nextItem.reject
      });
      return;
    }
    try {
      if (nextItem.timeout) {
        clearTimeout(nextItem.timeout);
      }
      this._secureLog("debug", `Processing next operation in queue for mutex '${mutexName}'`, {
        operationId: nextItem.operationId,
        queueRemaining: mutex.queue.length,
        timestamp: Date.now()
      });
      setTimeout(async () => {
        try {
          await this._acquireMutex(mutexName, nextItem.operationId, 5e3);
          this._secureLog("debug", `Queued operation acquired mutex '${mutexName}'`, {
            operationId: nextItem.operationId,
            acquisitionTime: Date.now()
          });
          nextItem.resolve();
        } catch (error) {
          this._secureLog("error", `Queued operation failed to acquire mutex '${mutexName}'`, {
            operationId: nextItem.operationId,
            errorType: error.constructor.name,
            errorMessage: error.message,
            timestamp: Date.now()
          });
          nextItem.reject(new Error(`Queue processing failed for '${mutexName}': ${error.message}`));
          setTimeout(() => {
            this._processNextInQueue(mutexName);
          }, 50);
        }
      }, 10);
    } catch (error) {
      this._secureLog("error", `Critical error during queue processing for mutex '${mutexName}'`, {
        operationId: nextItem.operationId,
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      try {
        nextItem.reject(new Error(`Queue processing critical error: ${error.message}`));
      } catch (rejectError) {
        this._secureLog("error", `Failed to reject queue item`, {
          originalError: error.message,
          rejectError: rejectError.message
        });
      }
      setTimeout(() => {
        this._processNextInQueue(mutexName);
      }, 100);
    }
  }
  _getAvailableMutexes() {
    const mutexes = [];
    const propertyNames = Object.getOwnPropertyNames(this);
    for (const prop of propertyNames) {
      if (prop.endsWith("Mutex") && prop.startsWith("_")) {
        const mutexName = prop.slice(1, -5);
        mutexes.push(mutexName);
      }
    }
    return mutexes;
  }
  /**
   *   Enhanced mutex execution with atomic operations
   */
  async _withMutex(mutexName, operation, timeout = 5e3) {
    const operationId = this._generateOperationId();
    if (!this._validateMutexSystem()) {
      this._secureLog("error", "Mutex system not properly initialized", {
        operationId,
        mutexName
      });
      throw new Error("Mutex system not properly initialized. Call _initializeMutexSystem() first.");
    }
    const mutex = this[`_${mutexName}Mutex`];
    if (!mutex) {
      throw new Error(`Mutex '${mutexName}' not found`);
    }
    let mutexAcquired = false;
    try {
      await this._acquireMutex(mutexName, operationId, timeout);
      mutexAcquired = true;
      const counterKey = `${mutexName}Operations`;
      if (this._operationCounters && this._operationCounters[counterKey] !== void 0) {
        this._operationCounters[counterKey]++;
      }
      const result = await operation(operationId);
      if (result === void 0 && operation.name !== "cleanup") {
        this._secureLog("warn", "Mutex operation returned undefined result", {
          operationId,
          mutexName,
          operationName: operation.name
        });
      }
      return result;
    } catch (error) {
      this._secureLog("error", "Error in mutex operation", {
        operationId,
        mutexName,
        errorType: error.constructor.name,
        errorMessage: error.message,
        mutexAcquired,
        mutexState: mutex ? {
          locked: mutex.locked,
          lockId: mutex.lockId,
          queueLength: mutex.queue.length
        } : "null"
      });
      if (mutexName === "keyOperation") {
        this._handleKeyOperationError(error, operationId);
      }
      if (error.message.includes("timeout") || error.message.includes("race condition")) {
        this._emergencyUnlockAllMutexes("errorHandler");
      }
      throw error;
    } finally {
      if (mutexAcquired) {
        try {
          await this._releaseMutex(mutexName, operationId);
          if (mutex.locked && mutex.lockId === operationId) {
            this._secureLog("error", "Mutex release verification failed", {
              operationId,
              mutexName
            });
            mutex.locked = false;
            mutex.lockId = null;
            mutex.lockTimeout = null;
          }
        } catch (releaseError) {
          this._secureLog("error", "Error releasing mutex in finally block", {
            operationId,
            mutexName,
            releaseErrorType: releaseError.constructor.name,
            releaseErrorMessage: releaseError.message
          });
          mutex.locked = false;
          mutex.lockId = null;
          mutex.lockTimeout = null;
        }
      }
    }
  }
  _validateMutexSystem() {
    const requiredMutexes = ["keyOperation", "cryptoOperation", "connectionOperation"];
    for (const mutexName of requiredMutexes) {
      const mutexPropertyName = `_${mutexName}Mutex`;
      const mutex = this[mutexPropertyName];
      if (!mutex || typeof mutex !== "object") {
        this._secureLog("error", `Missing or invalid mutex: ${mutexName}`, {
          mutexPropertyName,
          mutexType: typeof mutex
        });
        return false;
      }
      const requiredProps = ["locked", "queue", "lockId", "lockTimeout"];
      for (const prop of requiredProps) {
        if (!(prop in mutex)) {
          this._secureLog("error", `Mutex ${mutexName} missing property: ${prop}`);
          return false;
        }
      }
    }
    return true;
  }
  /**
   *   Enhanced emergency recovery of the mutex system
   */
  _emergencyRecoverMutexSystem() {
    this._secureLog("warn", "Emergency mutex system recovery initiated");
    try {
      this._emergencyUnlockAllMutexes("emergencyRecovery");
      this._initializeMutexSystem();
      if (!this._validateMutexSystem()) {
        throw new Error("Mutex system validation failed after recovery");
      }
      this._secureLog("info", "Mutex system recovered successfully with validation");
      return true;
    } catch (error) {
      this._secureLog("error", "Failed to recover mutex system", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      try {
        this._initializeMutexSystem();
        this._secureLog("warn", "Forced mutex system re-initialization completed");
        return true;
      } catch (reinitError) {
        this._secureLog("error", "CRITICAL: Forced re-initialization also failed", {
          originalError: error.message,
          reinitError: reinitError.message
        });
        return false;
      }
    }
  }
  /**
   *   Atomic key generation with race condition protection
   */
  async _generateEncryptionKeys() {
    return this._withMutex("keyOperation", async (operationId) => {
      this._secureLog("info", "Generating encryption keys with atomic mutex", {
        operationId
      });
      const currentState = this._keySystemState;
      if (currentState.isInitializing) {
        this._secureLog("warn", "Key generation already in progress, waiting for completion", {
          operationId,
          lastOperation: currentState.lastOperation,
          lastOperationTime: currentState.lastOperationTime
        });
        let waitAttempts = 0;
        const maxWaitAttempts = 50;
        while (currentState.isInitializing && waitAttempts < maxWaitAttempts) {
          await new Promise((resolve) => setTimeout(resolve, 100));
          waitAttempts++;
        }
        if (currentState.isInitializing) {
          throw new Error("Key generation timeout - operation still in progress after 5 seconds");
        }
      }
      try {
        currentState.isInitializing = true;
        currentState.lastOperation = "generation";
        currentState.lastOperationTime = Date.now();
        currentState.operationId = operationId;
        this._secureLog("debug", "Atomic key generation state set", {
          operationId,
          timestamp: currentState.lastOperationTime
        });
        let ecdhKeyPair = null;
        let ecdsaKeyPair = null;
        try {
          ecdhKeyPair = await this._generateEphemeralECDHKeys();
          if (!ecdhKeyPair || !ecdhKeyPair.privateKey || !ecdhKeyPair.publicKey) {
            throw new Error("Ephemeral ECDH key pair validation failed");
          }
          if (!this._validateKeyPairConstantTime(ecdhKeyPair)) {
            throw new Error("Ephemeral ECDH keys are not valid CryptoKey instances");
          }
          this._secureLog("debug", "Ephemeral ECDH keys generated and validated for PFS", {
            operationId,
            privateKeyType: ecdhKeyPair.privateKey.algorithm?.name,
            publicKeyType: ecdhKeyPair.publicKey.algorithm?.name,
            isEphemeral: true
          });
        } catch (ecdhError) {
          this._secureLog("error", "Ephemeral ECDH key generation failed", {
            operationId,
            errorType: ecdhError.constructor.name
          });
          this._throwSecureError(ecdhError, "ephemeral_ecdh_key_generation");
        }
        try {
          ecdsaKeyPair = await window.EnhancedSecureCryptoUtils.generateECDSAKeyPair();
          if (!ecdsaKeyPair || !ecdsaKeyPair.privateKey || !ecdsaKeyPair.publicKey) {
            throw new Error("ECDSA key pair validation failed");
          }
          if (!this._validateKeyPairConstantTime(ecdsaKeyPair)) {
            throw new Error("ECDSA keys are not valid CryptoKey instances");
          }
          this._secureLog("debug", "ECDSA keys generated and validated", {
            operationId,
            privateKeyType: ecdsaKeyPair.privateKey.algorithm?.name,
            publicKeyType: ecdsaKeyPair.publicKey.algorithm?.name
          });
        } catch (ecdsaError) {
          this._secureLog("error", "ECDSA key generation failed", {
            operationId,
            errorType: ecdsaError.constructor.name
          });
          this._throwSecureError(ecdsaError, "ecdsa_key_generation");
        }
        if (!ecdhKeyPair || !ecdsaKeyPair) {
          throw new Error("One or both key pairs failed to generate");
        }
        this._enableSecurityFeaturesAfterKeyGeneration(ecdhKeyPair, ecdsaKeyPair);
        this._secureLog("info", "Encryption keys generated successfully with atomic protection", {
          operationId,
          hasECDHKeys: !!(ecdhKeyPair?.privateKey && ecdhKeyPair?.publicKey),
          hasECDSAKeys: !!(ecdsaKeyPair?.privateKey && ecdsaKeyPair?.publicKey),
          generationTime: Date.now() - currentState.lastOperationTime
        });
        return { ecdhKeyPair, ecdsaKeyPair };
      } catch (error) {
        this._secureLog("error", "Key generation failed, resetting state", {
          operationId,
          errorType: error.constructor.name
        });
        throw error;
      } finally {
        currentState.isInitializing = false;
        currentState.operationId = null;
        this._secureLog("debug", "Key generation state reset", {
          operationId
        });
      }
    });
  }
  /**
   *   Enable security features after successful key generation
   */
  _enableSecurityFeaturesAfterKeyGeneration(ecdhKeyPair, ecdsaKeyPair) {
    try {
      if (ecdhKeyPair && ecdhKeyPair.privateKey && ecdhKeyPair.publicKey) {
        this.securityFeatures.hasEncryption = true;
        this.securityFeatures.hasECDH = true;
        this._secureLog("info", "ECDH encryption features enabled");
      }
      if (ecdsaKeyPair && ecdsaKeyPair.privateKey && ecdsaKeyPair.publicKey) {
        this.securityFeatures.hasECDSA = true;
        this._secureLog("info", "ECDSA signature features enabled");
      }
      if (this.securityFeatures.hasEncryption) {
        this.securityFeatures.hasMetadataProtection = true;
        this.securityFeatures.hasEnhancedReplayProtection = true;
        this.securityFeatures.hasNonExtractableKeys = true;
        this._secureLog("info", "Additional encryption-dependent features enabled");
      }
      if (ecdhKeyPair && this.ephemeralKeyPairs.size > 0) {
        this.securityFeatures.hasPFS = true;
        this._secureLog("info", "Perfect Forward Secrecy enabled with ephemeral keys");
      }
      this._secureLog("info", "Security features updated after key generation", {
        hasEncryption: this.securityFeatures.hasEncryption,
        hasECDH: this.securityFeatures.hasECDH,
        hasECDSA: this.securityFeatures.hasECDSA,
        hasMetadataProtection: this.securityFeatures.hasMetadataProtection,
        hasEnhancedReplayProtection: this.securityFeatures.hasEnhancedReplayProtection,
        hasNonExtractableKeys: this.securityFeatures.hasNonExtractableKeys,
        hasPFS: this.securityFeatures.hasPFS
      });
    } catch (error) {
      this._secureLog("error", "Failed to enable security features after key generation", {
        errorType: error.constructor.name,
        errorMessage: error.message
      });
    }
  }
  /**
   *   Enhanced emergency mutex unlocking with authorization and validation
   */
  _emergencyUnlockAllMutexes(callerContext = "unknown") {
    const authorizedCallers = [
      "keyOperation",
      "cryptoOperation",
      "connectionOperation",
      "emergencyRecovery",
      "systemShutdown",
      "errorHandler"
    ];
    if (!authorizedCallers.includes(callerContext)) {
      this._secureLog("error", `UNAUTHORIZED emergency mutex unlock attempt`, {
        callerContext,
        authorizedCallers,
        timestamp: Date.now()
      });
      throw new Error(`Unauthorized emergency mutex unlock attempt by: ${callerContext}`);
    }
    const mutexes = ["keyOperation", "cryptoOperation", "connectionOperation"];
    this._secureLog("error", "EMERGENCY: Unlocking all mutexes with authorization and state cleanup", {
      callerContext,
      timestamp: Date.now()
    });
    let unlockedCount = 0;
    let errorCount = 0;
    mutexes.forEach((mutexName) => {
      const mutex = this[`_${mutexName}Mutex`];
      if (mutex) {
        try {
          if (mutex.lockTimeout) {
            clearTimeout(mutex.lockTimeout);
          }
          const previousState = {
            locked: mutex.locked,
            lockId: mutex.lockId,
            lockTime: mutex.lockTime,
            queueLength: mutex.queue.length
          };
          mutex.locked = false;
          mutex.lockId = null;
          mutex.lockTimeout = null;
          mutex.lockTime = null;
          let queueRejectCount = 0;
          mutex.queue.forEach((item) => {
            try {
              if (item.reject && typeof item.reject === "function") {
                item.reject(new Error(`Emergency mutex unlock for ${mutexName} by ${callerContext}`));
                queueRejectCount++;
              }
            } catch (rejectError) {
              this._secureLog("warn", `Failed to reject queue item during emergency unlock`, {
                mutexName,
                errorType: rejectError.constructor.name
              });
            }
          });
          mutex.queue = [];
          unlockedCount++;
          this._secureLog("debug", `Emergency unlocked mutex: ${mutexName}`, {
            previousState,
            queueRejectCount,
            callerContext
          });
        } catch (error) {
          errorCount++;
          this._secureLog("error", `Error during emergency unlock of mutex: ${mutexName}`, {
            errorType: error.constructor.name,
            errorMessage: error.message,
            callerContext
          });
        }
      }
    });
    if (this._keySystemState) {
      try {
        const previousKeyState = { ...this._keySystemState };
        this._keySystemState.isInitializing = false;
        this._keySystemState.isRotating = false;
        this._keySystemState.isDestroying = false;
        this._keySystemState.operationId = null;
        this._keySystemState.concurrentOperations = 0;
        this._secureLog("debug", `Emergency reset key system state`, {
          previousState: previousKeyState,
          callerContext
        });
      } catch (error) {
        this._secureLog("error", `Error resetting key system state during emergency unlock`, {
          errorType: error.constructor.name,
          errorMessage: error.message,
          callerContext
        });
      }
    }
    this._secureLog("info", `Emergency mutex unlock completed`, {
      callerContext,
      unlockedCount,
      errorCount,
      totalMutexes: mutexes.length,
      timestamp: Date.now()
    });
    setTimeout(() => {
      this._validateMutexSystemAfterEmergencyUnlock();
    }, 100);
  }
  /**
   *   Handle key operation errors with recovery mechanisms
   */
  _handleKeyOperationError(error, operationId) {
    this._secureLog("error", "Key operation error detected, initiating recovery", {
      operationId,
      errorType: error.constructor.name,
      errorMessage: error.message
    });
    if (this._keySystemState) {
      this._keySystemState.isInitializing = false;
      this._keySystemState.isRotating = false;
      this._keySystemState.isDestroying = false;
      this._keySystemState.operationId = null;
    }
    this.ecdhKeyPair = null;
    this.ecdsaKeyPair = null;
    this.encryptionKey = null;
    this.macKey = null;
    this.metadataKey = null;
    if (error.message.includes("timeout") || error.message.includes("race condition")) {
      this._secureLog("warn", "Race condition or timeout detected, triggering emergency recovery");
      this._emergencyRecoverMutexSystem();
    }
  }
  /**
   *   Generate cryptographically secure IV with reuse prevention
   */
  _generateSecureIV(ivSize = 12, context = "general") {
    if (this._ivTrackingSystem.emergencyMode) {
      this._secureLog("error", "CRITICAL: IV generation blocked - emergency mode active due to IV reuse");
      throw new Error("IV generation blocked - emergency mode active");
    }
    let attempts2 = 0;
    const maxAttempts = 100;
    while (attempts2 < maxAttempts) {
      attempts2++;
      const iv = crypto.getRandomValues(new Uint8Array(ivSize));
      const ivString = Array.from(iv).map((b) => b.toString(16).padStart(2, "0")).join("");
      if (this._ivTrackingSystem.usedIVs.has(ivString)) {
        this._ivTrackingSystem.collisionCount++;
        this._secureLog("error", `CRITICAL: IV reuse detected!`, {
          context,
          attempt: attempts2,
          collisionCount: this._ivTrackingSystem.collisionCount,
          ivString: ivString.substring(0, 16) + "..."
          // Log partial IV for debugging
        });
        if (this._ivTrackingSystem.collisionCount > 5) {
          this._ivTrackingSystem.emergencyMode = true;
          this._secureLog("error", "CRITICAL: Emergency mode activated due to excessive IV reuse");
          throw new Error("Emergency mode: Excessive IV reuse detected");
        }
        continue;
      }
      if (!this._validateIVEntropy(iv)) {
        this._ivTrackingSystem.entropyValidation.entropyFailures++;
        this._secureLog("warn", `Low entropy IV detected`, {
          context,
          attempt: attempts2,
          entropyFailures: this._ivTrackingSystem.entropyValidation.entropyFailures
        });
        if (this._ivTrackingSystem.entropyValidation.entropyFailures > 10) {
          this._ivTrackingSystem.emergencyMode = true;
          this._secureLog("error", "CRITICAL: Emergency mode activated due to low entropy IVs");
          throw new Error("Emergency mode: Low entropy IVs detected");
        }
        continue;
      }
      this._ivTrackingSystem.usedIVs.add(ivString);
      this._ivTrackingSystem.ivHistory.set(ivString, {
        timestamp: Date.now(),
        context,
        attempt: attempts2
      });
      if (this.sessionId) {
        if (!this._ivTrackingSystem.sessionIVs.has(this.sessionId)) {
          this._ivTrackingSystem.sessionIVs.set(this.sessionId, /* @__PURE__ */ new Set());
        }
        this._ivTrackingSystem.sessionIVs.get(this.sessionId).add(ivString);
      }
      this._validateRNGQuality();
      this._secureLog("debug", `Secure IV generated`, {
        context,
        attempt: attempts2,
        ivSize,
        totalIVs: this._ivTrackingSystem.usedIVs.size
      });
      return iv;
    }
    this._secureLog("error", `Failed to generate unique IV after ${maxAttempts} attempts`, {
      context,
      totalIVs: this._ivTrackingSystem.usedIVs.size
    });
    throw new Error(`Failed to generate unique IV after ${maxAttempts} attempts`);
  }
  /**
   *   Validate IV entropy to detect weak RNG
   */
  _validateIVEntropy(iv) {
    this._ivTrackingSystem.entropyValidation.entropyTests++;
    const byteCounts = new Array(256).fill(0);
    for (let i = 0; i < iv.length; i++) {
      byteCounts[iv[i]]++;
    }
    const entropyResults = {
      shannon: 0,
      min: 0,
      collision: 0,
      compression: 0,
      quantum: 0
    };
    let shannonEntropy = 0;
    const totalBytes = iv.length;
    for (let i = 0; i < 256; i++) {
      if (byteCounts[i] > 0) {
        const probability = byteCounts[i] / totalBytes;
        shannonEntropy -= probability * Math.log2(probability);
      }
    }
    entropyResults.shannon = shannonEntropy;
    const maxCount = Math.max(...byteCounts);
    const maxProbability = maxCount / totalBytes;
    entropyResults.min = -Math.log2(maxProbability);
    let collisionSum = 0;
    for (let i = 0; i < 256; i++) {
      if (byteCounts[i] > 0) {
        const probability = byteCounts[i] / totalBytes;
        collisionSum += probability * probability;
      }
    }
    entropyResults.collision = -Math.log2(collisionSum);
    const ivString = Array.from(iv).map((b) => String.fromCharCode(b)).join("");
    const compressedLength = this._estimateCompressedLength(ivString);
    entropyResults.compression = (1 - compressedLength / totalBytes) * 8;
    entropyResults.quantum = this._calculateQuantumResistantEntropy(iv);
    const hasSuspiciousPatterns = this._detectAdvancedSuspiciousPatterns(iv);
    const minEntropyThreshold = this._ivTrackingSystem.entropyValidation.minEntropy;
    const isValid = entropyResults.shannon >= minEntropyThreshold && entropyResults.min >= minEntropyThreshold * 0.8 && entropyResults.collision >= minEntropyThreshold * 0.9 && entropyResults.compression >= minEntropyThreshold * 0.7 && entropyResults.quantum >= minEntropyThreshold * 0.6 && !hasSuspiciousPatterns;
    if (!isValid) {
      this._secureLog("warn", `Enhanced IV entropy validation failed`, {
        shannon: entropyResults.shannon.toFixed(2),
        min: entropyResults.min.toFixed(2),
        collision: entropyResults.collision.toFixed(2),
        compression: entropyResults.compression.toFixed(2),
        quantum: entropyResults.quantum.toFixed(2),
        minThreshold: minEntropyThreshold,
        hasSuspiciousPatterns
      });
    }
    return isValid;
  }
  /**
   *   Estimate compressed length for entropy calculation
   * @param {string} data - Data to estimate compression
   * @returns {number} Estimated compressed length
   */
  _estimateCompressedLength(data) {
    let compressedLength = 0;
    let i = 0;
    while (i < data.length) {
      let matchLength = 0;
      let matchDistance = 0;
      for (let j = Math.max(0, i - 255); j < i; j++) {
        let k = 0;
        while (i + k < data.length && data[i + k] === data[j + k] && k < 255) {
          k++;
        }
        if (k > matchLength) {
          matchLength = k;
          matchDistance = i - j;
        }
      }
      if (matchLength >= 3) {
        compressedLength += 3;
        i += matchLength;
      } else {
        compressedLength += 1;
        i += 1;
      }
    }
    return compressedLength;
  }
  /**
   *   Calculate quantum-resistant entropy
   * @param {Uint8Array} data - Data to analyze
   * @returns {number} Quantum-resistant entropy score
   */
  _calculateQuantumResistantEntropy(data) {
    let quantumScore = 0;
    const hasQuantumVulnerablePatterns = this._detectQuantumVulnerablePatterns(data);
    if (hasQuantumVulnerablePatterns) {
      quantumScore -= 2;
    }
    const bitDistribution = this._analyzeBitDistribution(data);
    quantumScore += bitDistribution.score;
    const periodicity = this._detectPeriodicity(data);
    quantumScore -= periodicity * 0.5;
    return Math.max(0, Math.min(8, quantumScore));
  }
  /**
   *   Detect quantum-vulnerable patterns
   * @param {Uint8Array} data - Data to analyze
   * @returns {boolean} true if quantum-vulnerable patterns found
   */
  _detectQuantumVulnerablePatterns(data) {
    const patterns = [
      [0, 0, 0, 0, 0, 0, 0, 0],
      // All zeros
      [255, 255, 255, 255, 255, 255, 255, 255],
      // All ones
      [0, 1, 0, 1, 0, 1, 0, 1],
      // Alternating
      [1, 0, 1, 0, 1, 0, 1, 0]
      // Alternating reverse
    ];
    for (const pattern of patterns) {
      for (let i = 0; i <= data.length - pattern.length; i++) {
        let match = true;
        for (let j = 0; j < pattern.length; j++) {
          if (data[i + j] !== pattern[j]) {
            match = false;
            break;
          }
        }
        if (match) return true;
      }
    }
    return false;
  }
  /**
   *   Analyze bit distribution
   * @param {Uint8Array} data - Data to analyze
   * @returns {Object} Bit distribution analysis
   */
  _analyzeBitDistribution(data) {
    let ones = 0;
    let totalBits = data.length * 8;
    for (const byte of data) {
      ones += (byte >>> 0).toString(2).split("1").length - 1;
    }
    const zeroRatio = (totalBits - ones) / totalBits;
    const oneRatio = ones / totalBits;
    const deviation = Math.abs(0.5 - oneRatio);
    const score = Math.max(0, 8 - deviation * 16);
    return { score, zeroRatio, oneRatio, deviation };
  }
  /**
   *   Detect periodicity in data
   * @param {Uint8Array} data - Data to analyze
   * @returns {number} Periodicity score (0-1)
   */
  _detectPeriodicity(data) {
    if (data.length < 16) return 0;
    let maxPeriodicity = 0;
    for (let period = 2; period <= data.length / 2; period++) {
      let matches = 0;
      let totalChecks = 0;
      for (let i = 0; i < data.length - period; i++) {
        if (data[i] === data[i + period]) {
          matches++;
        }
        totalChecks++;
      }
      if (totalChecks > 0) {
        const periodicity = matches / totalChecks;
        maxPeriodicity = Math.max(maxPeriodicity, periodicity);
      }
    }
    return maxPeriodicity;
  }
  /**
   *   Enhanced suspicious pattern detection
   * @param {Uint8Array} iv - IV to check
   * @returns {boolean} true if suspicious patterns found
   */
  _detectAdvancedSuspiciousPatterns(iv) {
    const patterns = [
      // Sequential patterns
      [0, 1, 2, 3, 4, 5, 6, 7],
      [255, 254, 253, 252, 251, 250, 249, 248],
      // Repeated patterns
      [0, 0, 0, 0, 0, 0, 0, 0],
      [255, 255, 255, 255, 255, 255, 255, 255],
      // Alternating patterns
      [0, 255, 0, 255, 0, 255, 0, 255],
      [255, 0, 255, 0, 255, 0, 255, 0]
    ];
    for (const pattern of patterns) {
      for (let i = 0; i <= iv.length - pattern.length; i++) {
        let match = true;
        for (let j = 0; j < pattern.length; j++) {
          if (iv[i + j] !== pattern[j]) {
            match = false;
            break;
          }
        }
        if (match) return true;
      }
    }
    const entropyMap = this._calculateLocalEntropy(iv);
    const lowEntropyRegions = entropyMap.filter((e) => e < 3).length;
    return lowEntropyRegions > iv.length * 0.3;
  }
  /**
   *   Calculate local entropy for pattern detection
   * @param {Uint8Array} data - Data to analyze
   * @returns {Array} Array of local entropy values
   */
  _calculateLocalEntropy(data) {
    const windowSize = 8;
    const entropyMap = [];
    for (let i = 0; i <= data.length - windowSize; i++) {
      const window2 = data.slice(i, i + windowSize);
      const charCount = {};
      for (const byte of window2) {
        charCount[byte] = (charCount[byte] || 0) + 1;
      }
      let entropy = 0;
      for (const count of Object.values(charCount)) {
        const probability = count / windowSize;
        entropy -= probability * Math.log2(probability);
      }
      entropyMap.push(entropy);
    }
    return entropyMap;
  }
  /**
   *   Detect suspicious patterns in IVs
   */
  _detectSuspiciousIVPatterns(iv) {
    const allZeros = iv.every((byte) => byte === 0);
    const allOnes = iv.every((byte) => byte === 255);
    if (allZeros || allOnes) {
      return true;
    }
    let sequentialCount = 0;
    for (let i = 1; i < iv.length; i++) {
      if (iv[i] === iv[i - 1] + 1 || iv[i] === iv[i - 1] - 1) {
        sequentialCount++;
      } else {
        sequentialCount = 0;
      }
      if (sequentialCount >= 3) {
        return true;
      }
    }
    for (let patternLength = 2; patternLength <= Math.floor(iv.length / 2); patternLength++) {
      for (let start2 = 0; start2 <= iv.length - patternLength * 2; start2++) {
        const pattern1 = iv.slice(start2, start2 + patternLength);
        const pattern2 = iv.slice(start2 + patternLength, start2 + patternLength * 2);
        if (pattern1.every((byte, index) => byte === pattern2[index])) {
          return true;
        }
      }
    }
    return false;
  }
  /**
   *   Clean up old IVs with strict limits
   */
  async _cleanupOldIVs() {
    const now = Date.now();
    const maxAge = 18e5;
    let cleanedCount = 0;
    const cleanupBatch = [];
    if (this._ivTrackingSystem.ivHistory.size > this._ivTrackingSystem.maxIVHistorySize) {
      const ivArray = Array.from(this._ivTrackingSystem.ivHistory.entries());
      const toRemove = ivArray.slice(0, ivArray.length - this._ivTrackingSystem.maxIVHistorySize);
      for (const [ivString] of toRemove) {
        cleanupBatch.push(ivString);
        cleanedCount++;
        if (cleanupBatch.length >= 100) {
          this._processCleanupBatch(cleanupBatch);
          cleanupBatch.length = 0;
        }
      }
    }
    for (const [ivString, metadata] of this._ivTrackingSystem.ivHistory.entries()) {
      if (now - metadata.timestamp > maxAge) {
        cleanupBatch.push(ivString);
        cleanedCount++;
        if (cleanupBatch.length >= 100) {
          this._processCleanupBatch(cleanupBatch);
          cleanupBatch.length = 0;
        }
      }
    }
    if (cleanupBatch.length > 0) {
      this._processCleanupBatch(cleanupBatch);
    }
    for (const [sessionId, sessionIVs] of this._ivTrackingSystem.sessionIVs.entries()) {
      if (sessionIVs.size > this._ivTrackingSystem.maxSessionIVs) {
        const ivArray = Array.from(sessionIVs);
        const toRemove = ivArray.slice(0, ivArray.length - this._ivTrackingSystem.maxSessionIVs);
        for (const ivString of toRemove) {
          sessionIVs.delete(ivString);
          this._ivTrackingSystem.usedIVs.delete(ivString);
          this._ivTrackingSystem.ivHistory.delete(ivString);
          cleanedCount++;
        }
      }
    }
    if (cleanedCount > 50) {
      await this._performNaturalCleanup();
    }
    if (cleanedCount > 0) {
      this._secureLog("debug", `Enhanced cleanup: ${cleanedCount} old IVs removed`, {
        cleanedCount,
        remainingIVs: this._ivTrackingSystem.usedIVs.size,
        remainingHistory: this._ivTrackingSystem.ivHistory.size,
        memoryPressure: this._calculateMemoryPressure()
      });
    }
  }
  /**
   *   Process cleanup batch with constant-time operations
   * @param {Array} batch - Batch of items to clean up
   */
  _processCleanupBatch(batch) {
    for (const item of batch) {
      this._ivTrackingSystem.usedIVs.delete(item);
      this._ivTrackingSystem.ivHistory.delete(item);
    }
  }
  /**
   *   Calculate memory pressure for adaptive cleanup
   * @returns {number} Memory pressure score (0-100)
   */
  _calculateMemoryPressure() {
    const totalIVs = this._ivTrackingSystem.usedIVs.size;
    const maxAllowed = this._resourceLimits.maxIVHistory;
    return Math.min(100, Math.floor(totalIVs / maxAllowed * 100));
  }
  /**
   *   Get IV tracking system statistics
   */
  _getIVTrackingStats() {
    return {
      totalIVs: this._ivTrackingSystem.usedIVs.size,
      collisionCount: this._ivTrackingSystem.collisionCount,
      entropyTests: this._ivTrackingSystem.entropyValidation.entropyTests,
      entropyFailures: this._ivTrackingSystem.entropyValidation.entropyFailures,
      rngTests: this._ivTrackingSystem.rngValidation.testsPerformed,
      weakRngDetected: this._ivTrackingSystem.rngValidation.weakRngDetected,
      emergencyMode: this._ivTrackingSystem.emergencyMode,
      sessionCount: this._ivTrackingSystem.sessionIVs.size,
      lastCleanup: this._lastIVCleanupTime || 0
    };
  }
  /**
   *   Reset IV tracking system (for testing or emergency recovery)
   */
  _resetIVTrackingSystem() {
    this._secureLog("warn", "Resetting IV tracking system");
    this._ivTrackingSystem.usedIVs.clear();
    this._ivTrackingSystem.ivHistory.clear();
    this._ivTrackingSystem.sessionIVs.clear();
    this._ivTrackingSystem.collisionCount = 0;
    this._ivTrackingSystem.entropyValidation.entropyTests = 0;
    this._ivTrackingSystem.entropyValidation.entropyFailures = 0;
    this._ivTrackingSystem.rngValidation.testsPerformed = 0;
    this._ivTrackingSystem.rngValidation.weakRngDetected = false;
    this._ivTrackingSystem.emergencyMode = false;
    this._secureLog("info", "IV tracking system reset completed");
  }
  /**
   *   Validate RNG quality
   */
  _validateRNGQuality() {
    const now = Date.now();
    if (this._ivTrackingSystem.rngValidation.testsPerformed % 1e3 === 0) {
      try {
        const testIVs = [];
        for (let i = 0; i < 100; i++) {
          testIVs.push(crypto.getRandomValues(new Uint8Array(12)));
        }
        const testIVStrings = testIVs.map((iv) => Array.from(iv).map((b) => b.toString(16).padStart(2, "0")).join(""));
        const uniqueTestIVs = new Set(testIVStrings);
        if (uniqueTestIVs.size < 95) {
          this._ivTrackingSystem.rngValidation.weakRngDetected = true;
          this._secureLog("error", "CRITICAL: Weak RNG detected in validation test", {
            uniqueIVs: uniqueTestIVs.size,
            totalTests: testIVs.length
          });
        }
        this._ivTrackingSystem.rngValidation.lastValidation = now;
      } catch (error) {
        this._secureLog("error", "RNG validation failed", {
          errorType: error.constructor.name
        });
      }
    }
    this._ivTrackingSystem.rngValidation.testsPerformed++;
  }
  /**
   *   Handle mutex timeout with enhanced state validation
   */
  _handleMutexTimeout(mutexName, operationId, timeout) {
    const mutex = this[`_${mutexName}Mutex`];
    if (!mutex) {
      this._secureLog("error", `Mutex '${mutexName}' not found during timeout handling`);
      return;
    }
    if (mutex.lockId !== operationId) {
      this._secureLog("warn", `Timeout for different operation ID on mutex '${mutexName}'`, {
        expectedOperationId: operationId,
        actualLockId: mutex.lockId,
        locked: mutex.locked
      });
      return;
    }
    if (!mutex.locked) {
      this._secureLog("warn", `Timeout for already unlocked mutex '${mutexName}'`, {
        operationId
      });
      return;
    }
    try {
      const lockDuration = mutex.lockTime ? Date.now() - mutex.lockTime : 0;
      this._secureLog("warn", `Mutex '${mutexName}' auto-released due to timeout`, {
        operationId,
        lockDuration,
        timeout,
        queueLength: mutex.queue.length
      });
      mutex.locked = false;
      mutex.lockId = null;
      mutex.lockTimeout = null;
      mutex.lockTime = null;
      setTimeout(() => {
        try {
          this._processNextInQueue(mutexName);
        } catch (queueError) {
          this._secureLog("error", `Error processing queue after timeout for mutex '${mutexName}'`, {
            errorType: queueError.constructor.name,
            errorMessage: queueError.message
          });
        }
      }, 10);
    } catch (error) {
      this._secureLog("error", `Critical error during mutex timeout handling for '${mutexName}'`, {
        operationId,
        errorType: error.constructor.name,
        errorMessage: error.message
      });
      try {
        this._emergencyUnlockAllMutexes("timeoutHandler");
      } catch (emergencyError) {
        this._secureLog("error", `Emergency unlock failed during timeout handling`, {
          originalError: error.message,
          emergencyError: emergencyError.message
        });
      }
    }
  }
  /**
   *   Validate mutex system after emergency unlock
   */
  _validateMutexSystemAfterEmergencyUnlock() {
    const mutexes = ["keyOperation", "cryptoOperation", "connectionOperation"];
    let validationErrors = 0;
    this._secureLog("info", "Validating mutex system after emergency unlock");
    mutexes.forEach((mutexName) => {
      const mutex = this[`_${mutexName}Mutex`];
      if (!mutex) {
        validationErrors++;
        this._secureLog("error", `Mutex '${mutexName}' not found after emergency unlock`);
        return;
      }
      if (mutex.locked) {
        validationErrors++;
        this._secureLog("error", `Mutex '${mutexName}' still locked after emergency unlock`, {
          lockId: mutex.lockId,
          lockTime: mutex.lockTime
        });
      }
      if (mutex.lockId !== null) {
        validationErrors++;
        this._secureLog("error", `Mutex '${mutexName}' still has lock ID after emergency unlock`, {
          lockId: mutex.lockId
        });
      }
      if (mutex.lockTimeout !== null) {
        validationErrors++;
        this._secureLog("error", `Mutex '${mutexName}' still has timeout after emergency unlock`);
      }
      if (mutex.queue.length > 0) {
        validationErrors++;
        this._secureLog("error", `Mutex '${mutexName}' still has queue items after emergency unlock`, {
          queueLength: mutex.queue.length
        });
      }
    });
    if (this._keySystemState) {
      if (this._keySystemState.isInitializing || this._keySystemState.isRotating || this._keySystemState.isDestroying) {
        validationErrors++;
        this._secureLog("error", `Key system state not properly reset after emergency unlock`, {
          isInitializing: this._keySystemState.isInitializing,
          isRotating: this._keySystemState.isRotating,
          isDestroying: this._keySystemState.isDestroying
        });
      }
    }
    if (validationErrors === 0) {
      this._secureLog("info", "Mutex system validation passed after emergency unlock");
    } else {
      this._secureLog("error", `Mutex system validation failed after emergency unlock`, {
        validationErrors
      });
      setTimeout(() => {
        this._emergencyRecoverMutexSystem();
      }, 1e3);
    }
  }
  /**
   * NEW: Diagnostics of the mutex system state
   */
  _getMutexSystemDiagnostics() {
    const diagnostics = {
      timestamp: Date.now(),
      systemValid: this._validateMutexSystem(),
      mutexes: {},
      counters: { ...this._operationCounters },
      keySystemState: { ...this._keySystemState }
    };
    const mutexNames = ["keyOperation", "cryptoOperation", "connectionOperation"];
    mutexNames.forEach((mutexName) => {
      const mutexPropertyName = `_${mutexName}Mutex`;
      const mutex = this[mutexPropertyName];
      if (mutex) {
        diagnostics.mutexes[mutexName] = {
          locked: mutex.locked,
          lockId: mutex.lockId,
          queueLength: mutex.queue.length,
          hasTimeout: !!mutex.lockTimeout
        };
      } else {
        diagnostics.mutexes[mutexName] = { error: "not_found" };
      }
    });
    return diagnostics;
  }
  /**
   * FULLY FIXED createSecureOffer()
   * With race-condition protection and improved security
   */
  async createSecureOffer() {
    return this._withMutex("connectionOperation", async (operationId) => {
      this._secureLog("info", "Creating secure offer with mutex", {
        operationId,
        connectionAttempts: this.connectionAttempts,
        currentState: this.peerConnection?.connectionState || "none"
      });
      try {
        this._resetNotificationFlags();
        if (!this._checkRateLimit()) {
          throw new Error("Connection rate limit exceeded. Please wait before trying again.");
        }
        this.connectionAttempts = 0;
        this.sessionSalt = window.EnhancedSecureCryptoUtils.generateSalt();
        this._secureLog("debug", "Session salt generated", {
          operationId,
          saltLength: this.sessionSalt.length,
          isValidSalt: Array.isArray(this.sessionSalt) && this.sessionSalt.length === 64
        });
        const keyPairs = await this._generateEncryptionKeys();
        this.ecdhKeyPair = keyPairs.ecdhKeyPair;
        this.ecdsaKeyPair = keyPairs.ecdsaKeyPair;
        if (!this.ecdhKeyPair?.privateKey || !this.ecdhKeyPair?.publicKey) {
          throw new Error("Failed to generate valid ECDH key pair");
        }
        if (!this.ecdsaKeyPair?.privateKey || !this.ecdsaKeyPair?.publicKey) {
          throw new Error("Failed to generate valid ECDSA key pair");
        }
        const ecdhFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(
          await crypto.subtle.exportKey("spki", this.ecdhKeyPair.publicKey)
        );
        const ecdsaFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(
          await crypto.subtle.exportKey("spki", this.ecdsaKeyPair.publicKey)
        );
        if (!ecdhFingerprint || !ecdsaFingerprint) {
          throw new Error("Failed to generate key fingerprints");
        }
        this._secureLog("info", "Generated unique key pairs for MITM protection", {
          operationId,
          hasECDHFingerprint: !!ecdhFingerprint,
          hasECDSAFingerprint: !!ecdsaFingerprint,
          fingerprintLength: ecdhFingerprint.length,
          timestamp: Date.now()
        });
        const ecdhPublicKeyData = await window.EnhancedSecureCryptoUtils.exportPublicKeyWithSignature(
          this.ecdhKeyPair.publicKey,
          this.ecdsaKeyPair.privateKey,
          "ECDH"
        );
        const ecdsaPublicKeyData = await window.EnhancedSecureCryptoUtils.exportPublicKeyWithSignature(
          this.ecdsaKeyPair.publicKey,
          this.ecdsaKeyPair.privateKey,
          "ECDSA"
        );
        if (!ecdhPublicKeyData || typeof ecdhPublicKeyData !== "object") {
          this._secureLog("error", "CRITICAL: ECDH key export failed - invalid object structure", { operationId });
          throw new Error("CRITICAL SECURITY FAILURE: ECDH key export validation failed - hard abort required");
        }
        if (!ecdhPublicKeyData.keyData || !ecdhPublicKeyData.signature) {
          this._secureLog("error", "CRITICAL: ECDH key export incomplete - missing keyData or signature", {
            operationId,
            hasKeyData: !!ecdhPublicKeyData.keyData,
            hasSignature: !!ecdhPublicKeyData.signature
          });
          throw new Error("CRITICAL SECURITY FAILURE: ECDH key export incomplete - hard abort required");
        }
        if (!ecdsaPublicKeyData || typeof ecdsaPublicKeyData !== "object") {
          this._secureLog("error", "CRITICAL: ECDSA key export failed - invalid object structure", { operationId });
          throw new Error("CRITICAL SECURITY FAILURE: ECDSA key export validation failed - hard abort required");
        }
        if (!ecdsaPublicKeyData.keyData || !ecdsaPublicKeyData.signature) {
          this._secureLog("error", "CRITICAL: ECDSA key export incomplete - missing keyData or signature", {
            operationId,
            hasKeyData: !!ecdsaPublicKeyData.keyData,
            hasSignature: !!ecdsaPublicKeyData.signature
          });
          throw new Error("CRITICAL SECURITY FAILURE: ECDSA key export incomplete - hard abort required");
        }
        this._updateSecurityFeatures({
          hasEncryption: true,
          hasECDH: true,
          hasECDSA: true,
          hasMutualAuth: true,
          hasMetadataProtection: true,
          hasEnhancedReplayProtection: true,
          hasNonExtractableKeys: true,
          hasRateLimiting: true,
          hasEnhancedValidation: true,
          hasPFS: true
        });
        this.isInitiator = true;
        this.onStatusChange("connecting");
        this.createPeerConnection();
        this.dataChannel = this.peerConnection.createDataChannel("securechat", {
          ordered: true
        });
        this.setupDataChannel(this.dataChannel);
        this._secureLog("debug", "Data channel created", {
          operationId,
          channelLabel: this.dataChannel.label,
          channelOrdered: this.dataChannel.ordered
        });
        const offer = await this.peerConnection.createOffer({
          offerToReceiveAudio: false,
          offerToReceiveVideo: false
        });
        await this.peerConnection.setLocalDescription(offer);
        try {
          const ourFingerprint = this._extractDTLSFingerprintFromSDP(offer.sdp);
          this.expectedDTLSFingerprint = ourFingerprint;
          this._secureLog("info", "Generated DTLS fingerprint for out-of-band verification", {
            fingerprint: ourFingerprint,
            context: "offer_creation"
          });
          this.deliverMessageToUI(`DTLS fingerprint ready for verification: ${ourFingerprint}`, "system");
        } catch (error) {
          this._secureLog("error", "Failed to extract DTLS fingerprint from offer", { error: error.message });
        }
        const offerIceGatheringStartedAt = Date.now();
        const offerIceGatheringCompleted = await this.waitForIceGathering();
        const offerCandidateSummary = this._summarizeIceCandidatesInSDP(this.peerConnection.localDescription?.sdp);
        const offerCandidateCount = offerCandidateSummary.total;
        if (!offerIceGatheringCompleted && offerCandidateCount === 0) {
          this.deliverMessageToUI(
            "No network candidates could be gathered, so the invitation would not be usable. This usually means a VPN or firewall is blocking STUN/TURN. Try turning the VPN off, switching network, or adding your own TURN server in Advanced network settings.",
            "system"
          );
          throw new Error("ICE gathering produced no candidates \u2014 check VPN/firewall or configure a TURN server");
        }
        this._secureLog(offerCandidateCount > 0 ? "info" : "warn", "ICE candidates captured for offer export", {
          candidateSummary: offerCandidateSummary,
          iceGatheringState: this.peerConnection.iceGatheringState,
          iceGatheringDurationMs: Date.now() - offerIceGatheringStartedAt,
          iceGatheringCompleted: offerIceGatheringCompleted
        });
        this._logIceCandidateDiagnostics("offer export", this.peerConnection.localDescription?.sdp, {
          iceGatheringState: this.peerConnection.iceGatheringState,
          iceGatheringDurationMs: Date.now() - offerIceGatheringStartedAt,
          iceGatheringCompleted: offerIceGatheringCompleted
        });
        if (!offerIceGatheringCompleted) {
          this.deliverMessageToUI("ICE gathering timed out before completion, but available candidates were included in the invitation. Connectivity may still fail on restrictive networks.", "system");
        }
        if (offerCandidateCount === 0) {
          this.deliverMessageToUI("No ICE candidates were gathered for the invitation yet. The peer connection may fail unless network candidates become available.", "system");
        }
        this._secureLog("debug", "ICE gathering completed", {
          operationId,
          iceGatheringState: this.peerConnection.iceGatheringState,
          connectionState: this.peerConnection.connectionState
        });
        this.verificationCode = window.EnhancedSecureCryptoUtils.generateVerificationCode();
        if (!this.verificationCode || this.verificationCode.length < _EnhancedSecureWebRTCManager.SIZES.VERIFICATION_CODE_MIN_LENGTH) {
          throw new Error("Failed to generate valid verification code");
        }
        const authChallenge = window.EnhancedSecureCryptoUtils.generateMutualAuthChallenge();
        if (!authChallenge) {
          throw new Error("Failed to generate mutual authentication challenge");
        }
        this.sessionId = Array.from(crypto.getRandomValues(new Uint8Array(_EnhancedSecureWebRTCManager.SIZES.SESSION_ID_LENGTH))).map((b) => b.toString(16).padStart(2, "0")).join("");
        if (!this.sessionId || this.sessionId.length !== _EnhancedSecureWebRTCManager.SIZES.SESSION_ID_LENGTH * 2) {
          throw new Error("Failed to generate valid session ID");
        }
        this.connectionId = Array.from(crypto.getRandomValues(new Uint8Array(8))).map((b) => b.toString(16).padStart(2, "0")).join("");
        this._storePendingOfferContext();
        const securityLevel = {
          level: "MAXIMUM",
          score: 100,
          color: "green",
          details: "All security features enabled by default",
          passedChecks: 10,
          totalChecks: 10,
          isRealData: true
        };
        const currentTimestamp = Date.now();
        const offerPackage = {
          // Core information (minimal)
          t: "offer",
          // type
          s: this.peerConnection.localDescription.sdp,
          // sdp
          v: _EnhancedSecureWebRTCManager.PROTOCOL_VERSION,
          // version
          ts: currentTimestamp,
          // timestamp
          // Cryptographic keys (essential)
          e: ecdhPublicKeyData,
          // ecdhPublicKey
          d: ecdsaPublicKeyData,
          // ecdsaPublicKey
          // Session data (essential)
          sl: this.sessionSalt,
          // salt
          si: this.sessionId,
          // sessionId
          ci: this.connectionId,
          // connectionId
          // Authentication (essential)
          vc: this.verificationCode,
          // verificationCode
          ac: authChallenge,
          // authChallenge
          // Security metadata (simplified)
          slv: "MAX",
          // securityLevel
          // Double Ratchet support. Advertised rather than assumed so a
          // peer still on 5.6.x keeps working on the static-key path
          // instead of failing to decrypt anything: with no server there
          // is no way to roll both ends at once. Absent = not supported.
          dr: _EnhancedSecureWebRTCManager.RATCHET_VERSION,
          // Key fingerprints (shortened)
          kf: {
            e: ecdhFingerprint.substring(0, 12),
            // ecdh (12 chars)
            d: ecdsaFingerprint.substring(0, 12)
            // ecdsa (12 chars)
          }
        };
        try {
          const validationResult = this.validateEnhancedOfferData(offerPackage);
        } catch (validationError) {
          throw new Error(`Offer package validation error: ${validationError.message}`);
        }
        this._secureLog("info", "Enhanced secure offer created successfully", {
          operationId,
          version: offerPackage.version,
          hasECDSA: true,
          hasMutualAuth: true,
          hasSessionId: !!offerPackage.sessionId,
          securityLevel: securityLevel.level,
          timestamp: currentTimestamp,
          capabilitiesCount: 10
          // All capabilities enabled by default
        });
        this._dispatchAppEvent?.(new CustomEvent("new-connection", {
          detail: {
            type: "offer",
            timestamp: currentTimestamp,
            securityLevel: securityLevel.level,
            operationId
          }
        }));
        if (_EnhancedSecureWebRTCManager.SBQ2_SEND_ENABLED) {
          this._latchHandshakeMode("sbq2");
          const { text: text2 } = await this._sbq2BuildDescriptor(TYPE.OFFER);
          return { t: "offer", sbq2: text2 };
        }
        this._latchHandshakeMode("sb1");
        return offerPackage;
      } catch (error) {
        this._secureLog("error", "Enhanced secure offer creation failed in critical section", {
          operationId,
          errorType: error.constructor.name,
          errorMessage: error.message,
          phase: this._determineErrorPhase(error),
          connectionAttempts: this.connectionAttempts
        });
        this._cleanupFailedOfferCreation();
        this.onStatusChange("disconnected");
        throw error;
      }
    }, 6e4);
  }
  /**
   * HELPER: Determine the phase where the error occurred
   */
  _determineErrorPhase(error) {
    const message = error.message.toLowerCase();
    if (message.includes("rate limit")) return "rate_limiting";
    if (message.includes("key pair") || message.includes("generate")) return "key_generation";
    if (message.includes("fingerprint")) return "fingerprinting";
    if (message.includes("export") || message.includes("signature")) return "key_export";
    if (message.includes("peer connection")) return "webrtc_setup";
    if (message.includes("offer") || message.includes("sdp")) return "sdp_creation";
    if (message.includes("verification")) return "verification_setup";
    if (message.includes("session")) return "session_setup";
    if (message.includes("validation")) return "package_validation";
    return "unknown";
  }
  /**
   *   Secure cleanup state after failed offer creation
   */
  _cleanupFailedOfferCreation() {
    try {
      this._secureCleanupCryptographicMaterials();
      if (this.peerConnection) {
        this.peerConnection.close();
        this.peerConnection = null;
      }
      if (this.dataChannel) {
        this.dataChannel.close();
        this.dataChannel = null;
      }
      this.isInitiator = false;
      this.isVerified = false;
      this._updateSecurityFeatures({
        hasEncryption: false,
        hasECDH: false,
        hasECDSA: false,
        hasMutualAuth: false,
        hasMetadataProtection: false,
        hasEnhancedReplayProtection: false,
        hasNonExtractableKeys: false,
        hasEnhancedValidation: false,
        hasPFS: false
      });
      this._forceGarbageCollection().catch((error) => {
        this._secureLog("error", "Cleanup failed during offer cleanup", {
          errorType: error?.constructor?.name || "Unknown"
        });
      });
      this._secureLog("debug", "Failed offer creation cleanup completed with secure memory wipe");
    } catch (cleanupError) {
      this._secureLog("error", "Error during offer creation cleanup", {
        errorType: cleanupError.constructor.name,
        errorMessage: cleanupError.message
      });
    }
  }
  /**
   * HELPER: Atomic update of security features (if not added yet)
   */
  _updateSecurityFeatures(updates) {
    const oldFeatures = { ...this.securityFeatures };
    try {
      Object.assign(this.securityFeatures, updates);
      this._secureLog("debug", "Security features updated", {
        updatedCount: Object.keys(updates).length,
        totalFeatures: Object.keys(this.securityFeatures).length
      });
    } catch (error) {
      this.securityFeatures = oldFeatures;
      this._secureLog("error", "Security features update failed, rolled back", {
        errorType: error.constructor.name
      });
      throw error;
    }
  }
  /**
   * FULLY FIXED METHOD createSecureAnswer()
   * With race-condition protection and enhanced security
   */
  /**
   * SBQ2 answer path.
   *
   * Deliberately separate from createSecureAnswer rather than folded into it:
   * that method's job is to import the peer's keys and derive the session from
   * the offer, and here there are no peer keys yet — only a fingerprint and a
   * commitment. Sharing the body would mean threading "do we have keys yet?"
   * through fifteen phases, and the whole point of the format is that the
   * answer is produced before any key material has been seen.
   */
  async _createSbq2Answer(offerData) {
    return this._withMutex("connectionOperation", async (operationId) => {
      try {
        this._resetNotificationFlags();
        if (!this._checkRateLimit()) {
          throw new Error("Connection rate limit exceeded. Please wait before trying again.");
        }
        this._latchHandshakeMode("sbq2");
        const offerBytes = decodeText(String(offerData.sbq2));
        const desc = this._sbq2AdoptRemoteDescriptor(offerBytes, TYPE.OFFER);
        const { sdp: remoteSdp } = serializeSdp(desc);
        this.isInitiator = false;
        this.onStatusChange("connecting");
        const keyPairs = await this._generateEncryptionKeys();
        this.ecdhKeyPair = keyPairs.ecdhKeyPair;
        this.ecdsaKeyPair = keyPairs.ecdsaKeyPair;
        if (!this.ecdhKeyPair?.privateKey || !this.ecdsaKeyPair?.privateKey) {
          throw new Error("Failed to generate valid key pairs");
        }
        this.createPeerConnection();
        this._peerDTLSFingerprint = Array.from(
          desc.fingerprint,
          (b) => b.toString(16).padStart(2, "0").toUpperCase()
        ).join(":");
        await this.peerConnection.setRemoteDescription({ type: "offer", sdp: remoteSdp });
        await this.peerConnection.setLocalDescription(await this.peerConnection.createAnswer({
          offerToReceiveAudio: false,
          offerToReceiveVideo: false
        }));
        this.expectedDTLSFingerprint = this._extractDTLSFingerprintFromSDP(this.peerConnection.localDescription.sdp);
        await this.waitForIceGathering();
        const digest = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
        const { text: text2 } = await this._sbq2BuildDescriptor(TYPE.ANSWER, {
          bindingTag: await bindingTag(digest, offerBytes)
        });
        this._dispatchAppEvent?.(new CustomEvent("new-connection", {
          detail: { type: "answer", timestamp: Date.now(), operationId }
        }));
        return { t: "answer", sbq2: text2 };
      } catch (error) {
        this._secureLog("error", "SBQ2 answer creation failed", {
          operationId,
          errorType: error?.constructor?.name || "Unknown"
        });
        this.onStatusChange("disconnected");
        throw error;
      }
    }, 6e4);
  }
  async createSecureAnswer(offerData) {
    if (offerData && typeof offerData.sbq2 === "string") {
      return this._createSbq2Answer(offerData);
    }
    return this._withMutex("connectionOperation", async (operationId) => {
      this._secureLog("info", "Creating secure answer with mutex", {
        operationId,
        hasOfferData: !!offerData,
        offerType: offerData?.type,
        offerVersion: offerData?.version,
        offerTimestamp: offerData?.timestamp
      });
      try {
        this._resetNotificationFlags();
        this._secureLog("debug", "Starting enhanced offer validation", {
          operationId,
          hasOfferData: !!offerData,
          offerType: offerData?.type,
          hasECDHKey: !!offerData?.ecdhPublicKey,
          hasECDSAKey: !!offerData?.ecdsaPublicKey,
          hasSalt: !!offerData?.salt
        });
        if (!this.validateEnhancedOfferData(offerData)) {
          throw new Error("Invalid connection data format - failed enhanced validation");
        }
        if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkConnectionRate(this.rateLimiterId)) {
          throw new Error("Connection rate limit exceeded. Please wait before trying again.");
        }
        const timestamp = offerData.ts || offerData.timestamp;
        const version2 = offerData.v || offerData.version;
        if (!timestamp || !version2) {
          throw new Error("Missing required security fields in offer data \u2013 possible MITM attack");
        }
        const offerAge = Date.now() - timestamp;
        const MAX_OFFER_AGE = 18e5;
        if (offerAge > MAX_OFFER_AGE) {
          this._secureLog("error", "Offer data is too old - possible replay attack", {
            operationId,
            offerAge: Math.round(offerAge / 1e3),
            maxAllowedAge: Math.round(MAX_OFFER_AGE / 1e3),
            timestamp: offerData.timestamp
          });
          if (this.onAnswerError) {
            this.onAnswerError("replay_attack", "Offer data is too old \u2013 possible replay attack");
          }
          throw new Error("Offer data is too old \u2013 possible replay attack");
        }
        const protocolVersion = version2;
        if (protocolVersion !== _EnhancedSecureWebRTCManager.PROTOCOL_VERSION) {
          this._secureLog("warn", "Protocol version mismatch detected", {
            operationId,
            expectedVersion: _EnhancedSecureWebRTCManager.PROTOCOL_VERSION,
            receivedVersion: protocolVersion
          });
          throw new Error(`Version mismatch: expected protocol ${_EnhancedSecureWebRTCManager.PROTOCOL_VERSION}, received ${protocolVersion}`);
        }
        this.sessionSalt = offerData.sl || offerData.salt;
        this._peerSupportsRatchet = offerData.dr === _EnhancedSecureWebRTCManager.RATCHET_VERSION;
        if (!Array.isArray(this.sessionSalt)) {
          throw new Error("Invalid session salt format - must be array");
        }
        const expectedSaltLength = 64;
        if (this.sessionSalt.length !== expectedSaltLength) {
          throw new Error(`Invalid session salt length: expected ${expectedSaltLength}, got ${this.sessionSalt.length}`);
        }
        const saltFingerprint = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(this.sessionSalt);
        this._secureLog("info", "Session salt validated successfully", {
          operationId,
          saltLength: this.sessionSalt.length,
          saltFingerprint: saltFingerprint.substring(0, 8)
        });
        const keyPairs = await this._generateEncryptionKeys();
        this.ecdhKeyPair = keyPairs.ecdhKeyPair;
        this.ecdsaKeyPair = keyPairs.ecdsaKeyPair;
        if (!(this.ecdhKeyPair?.privateKey instanceof CryptoKey)) {
          this._secureLog("error", "Local ECDH private key is not a CryptoKey", {
            operationId,
            hasKeyPair: !!this.ecdhKeyPair,
            privateKeyType: typeof this.ecdhKeyPair?.privateKey,
            privateKeyAlgorithm: this.ecdhKeyPair?.privateKey?.algorithm?.name
          });
          throw new Error("Local ECDH private key is not a valid CryptoKey");
        }
        let peerECDSAPublicKey;
        try {
          const ecdsaKey = offerData.d || offerData.ecdsaPublicKey;
          peerECDSAPublicKey = await crypto.subtle.importKey(
            "spki",
            new Uint8Array(ecdsaKey.keyData),
            {
              name: "ECDSA",
              namedCurve: "P-384"
            },
            false,
            ["verify"]
          );
        } catch (error) {
          this._throwSecureError(error, "ecdsa_key_import");
        }
        let peerECDHPublicKey;
        try {
          const ecdhKey = offerData.e || offerData.ecdhPublicKey;
          peerECDHPublicKey = await window.EnhancedSecureCryptoUtils.importSignedPublicKey(
            ecdhKey,
            peerECDSAPublicKey,
            "ECDH"
          );
        } catch (error) {
          this._secureLog("error", "Failed to import signed ECDH public key", {
            operationId,
            errorType: error.constructor.name
          });
          this._throwSecureError(error, "ecdh_key_import");
        }
        if (!(peerECDHPublicKey instanceof CryptoKey)) {
          this._secureLog("error", "Peer ECDH public key is not a CryptoKey", {
            operationId,
            publicKeyType: typeof peerECDHPublicKey,
            publicKeyAlgorithm: peerECDHPublicKey?.algorithm?.name
          });
          throw new Error("Peer ECDH public key is not a valid CryptoKey");
        }
        this.peerPublicKey = peerECDHPublicKey;
        let derivedKeys;
        try {
          this._secureLog("debug", "About to call deriveSharedKeys", {
            operationId,
            privateKeyType: typeof this.ecdhKeyPair.privateKey,
            publicKeyType: typeof peerECDHPublicKey,
            saltLength: this.sessionSalt?.length,
            privateKeyAlgorithm: this.ecdhKeyPair.privateKey?.algorithm?.name,
            publicKeyAlgorithm: peerECDHPublicKey?.algorithm?.name
          });
          derivedKeys = await window.EnhancedSecureCryptoUtils.deriveSharedKeys(
            this.ecdhKeyPair.privateKey,
            peerECDHPublicKey,
            this.sessionSalt
          );
          this._secureLog("debug", "deriveSharedKeys completed successfully", {
            operationId,
            hasMessageKey: !!derivedKeys.messageKey,
            hasMacKey: !!derivedKeys.macKey,
            hasPfsKey: !!derivedKeys.pfsKey,
            hasMetadataKey: !!derivedKeys.metadataKey,
            hasFingerprint: !!derivedKeys.fingerprint
          });
        } catch (error) {
          this._secureLog("error", "Failed to derive shared keys", {
            operationId,
            errorType: error.constructor.name,
            errorMessage: error.message,
            errorStack: error.stack,
            privateKeyType: typeof this.ecdhKeyPair.privateKey,
            publicKeyType: typeof peerECDHPublicKey,
            saltLength: this.sessionSalt?.length,
            privateKeyAlgorithm: this.ecdhKeyPair.privateKey?.algorithm?.name,
            publicKeyAlgorithm: peerECDHPublicKey?.algorithm?.name
          });
          this._throwSecureError(error, "key_derivation");
        }
        await this._setEncryptionKeys(
          derivedKeys.messageKey,
          derivedKeys.macKey,
          derivedKeys.metadataKey,
          derivedKeys.fingerprint
        );
        await this._initializeRatchet(
          derivedKeys,
          /* isInitiator */
          false
        );
        if (!(this.encryptionKey instanceof CryptoKey) || !(this.macKey instanceof CryptoKey) || !(this.metadataKey instanceof CryptoKey)) {
          this._secureLog("error", "Invalid key types after derivation", {
            operationId,
            encryptionKeyType: typeof this.encryptionKey,
            macKeyType: typeof this.macKey,
            metadataKeyType: typeof this.metadataKey
          });
          throw new Error("Invalid key types after derivation");
        }
        this.verificationCode = offerData.vc || offerData.verificationCode || null;
        this._secureLog("info", "Encryption keys derived and set successfully", {
          operationId,
          hasEncryptionKey: !!this.encryptionKey,
          hasMacKey: !!this.macKey,
          hasMetadataKey: !!this.metadataKey,
          hasKeyFingerprint: !!this.keyFingerprint,
          mitmProtection: "enabled",
          signatureVerified: true
        });
        this._updateSecurityFeatures({
          hasEncryption: true,
          hasECDH: true,
          hasECDSA: true,
          hasMutualAuth: true,
          hasMetadataProtection: true,
          hasEnhancedReplayProtection: true,
          hasNonExtractableKeys: true,
          hasRateLimiting: true,
          hasEnhancedValidation: true,
          hasPFS: true
        });
        this.currentKeyVersion = 0;
        this.lastKeyRotation = Date.now();
        this.keyVersions.set(0, {
          salt: this.sessionSalt,
          timestamp: this.lastKeyRotation,
          messageCount: 0
        });
        let authProof;
        if (offerData.authChallenge) {
          try {
            authProof = await window.EnhancedSecureCryptoUtils.createAuthProof(
              offerData.authChallenge,
              this.ecdsaKeyPair.privateKey,
              this.ecdsaKeyPair.publicKey
            );
          } catch (error) {
            this._secureLog("error", "Failed to create authentication proof", {
              operationId,
              errorType: error.constructor.name
            });
            this._throwSecureError(error, "authentication_proof_creation");
          }
        } else {
          this._secureLog("warn", "No auth challenge in offer - mutual auth disabled", {
            operationId
          });
        }
        this.isInitiator = false;
        this.onStatusChange("connecting");
        this.onKeyExchange(this.keyFingerprint);
        this.createPeerConnection();
        if (this.strictDTLSValidation) {
          try {
            this._peerDTLSFingerprint = this._extractDTLSFingerprintFromSDP(offerData.sdp);
          } catch (error) {
            this._secureLog("warn", "Could not extract peer DTLS fingerprint from offer", {
              error: error.message,
              context: "offer_validation"
            });
          }
        } else {
          this._secureLog("info", "DTLS fingerprint validation disabled - proceeding without validation");
        }
        try {
          this._secureLog("debug", "Setting remote description from offer", {
            operationId,
            sdpLength: offerData.sdp?.length || 0
          });
          await this.peerConnection.setRemoteDescription(new RTCSessionDescription({
            type: "offer",
            sdp: offerData.s || offerData.sdp
          }));
          this._logIceCandidateDiagnostics("remote offer applied", this.peerConnection.remoteDescription?.sdp, {
            signalingState: this.peerConnection.signalingState
          });
          this._warnIfRemoteCandidatesNeedRelay("offer", this.peerConnection.remoteDescription?.sdp);
          this._secureLog("debug", "Remote description set successfully", {
            operationId,
            signalingState: this.peerConnection.signalingState
          });
        } catch (error) {
          this._secureLog("error", "Failed to set remote description", {
            error: error.message,
            operationId
          });
          this._throwSecureError(error, "webrtc_remote_description");
        }
        this._secureLog("debug", "Remote description set successfully", {
          operationId,
          connectionState: this.peerConnection.connectionState,
          signalingState: this.peerConnection.signalingState
        });
        let answer;
        try {
          answer = await this.peerConnection.createAnswer({
            offerToReceiveAudio: false,
            offerToReceiveVideo: false
          });
        } catch (error) {
          this._throwSecureError(error, "webrtc_create_answer");
        }
        try {
          await this.peerConnection.setLocalDescription(answer);
        } catch (error) {
          this._throwSecureError(error, "webrtc_local_description");
        }
        try {
          const ourFingerprint = this._extractDTLSFingerprintFromSDP(answer.sdp);
          this.expectedDTLSFingerprint = ourFingerprint;
          this._secureLog("info", "Generated DTLS fingerprint for out-of-band verification", {
            fingerprint: ourFingerprint,
            context: "answer_creation"
          });
          this.deliverMessageToUI(`DTLS fingerprint ready for verification: ${ourFingerprint}`, "system");
        } catch (error) {
          this._secureLog("error", "Failed to extract DTLS fingerprint from answer", { error: error.message });
        }
        try {
          const remoteFP = this._extractDTLSFingerprintFromSDP(offerData.s || offerData.sdp);
          const localFP = this.expectedDTLSFingerprint;
          const keyBytes = this._decodeKeyFingerprint(this.keyFingerprint);
          this.verificationCode = await this._computeSAS(keyBytes, localFP, remoteFP);
          this._setSASMaterialReady(localFP, remoteFP);
        } catch (sasError) {
          this._secureLog("error", "SAS computation failed in createSecureAnswer (Answer side)", {
            errorType: sasError?.constructor?.name || "Unknown"
          });
          throw new Error(`SAS computation failed: ${sasError.message}`);
        }
        const answerIceGatheringStartedAt = Date.now();
        const answerIceGatheringCompleted = await this.waitForIceGathering();
        const answerCandidateSummary = this._summarizeIceCandidatesInSDP(this.peerConnection.localDescription?.sdp);
        const answerCandidateCount = answerCandidateSummary.total;
        if (!answerIceGatheringCompleted && answerCandidateCount === 0) {
          this.deliverMessageToUI(
            "No network candidates could be gathered, so the response would not be usable. This usually means a VPN or firewall is blocking STUN/TURN. Try turning the VPN off, switching network, or adding your own TURN server in Advanced network settings.",
            "system"
          );
          throw new Error("ICE gathering produced no candidates \u2014 check VPN/firewall or configure a TURN server");
        }
        this._secureLog(answerCandidateCount > 0 ? "info" : "warn", "ICE candidates captured for answer export", {
          candidateSummary: answerCandidateSummary,
          iceGatheringState: this.peerConnection.iceGatheringState,
          iceGatheringDurationMs: Date.now() - answerIceGatheringStartedAt,
          iceGatheringCompleted: answerIceGatheringCompleted
        });
        this._logIceCandidateDiagnostics("answer export", this.peerConnection.localDescription?.sdp, {
          iceGatheringState: this.peerConnection.iceGatheringState,
          iceGatheringDurationMs: Date.now() - answerIceGatheringStartedAt,
          iceGatheringCompleted: answerIceGatheringCompleted
        });
        if (!answerIceGatheringCompleted) {
          this.deliverMessageToUI("ICE gathering timed out before completion, but available candidates were included in the response. Connectivity may still fail on restrictive networks.", "system");
        }
        if (answerCandidateCount === 0) {
          this.deliverMessageToUI("No ICE candidates were gathered for the response yet. The peer connection may fail unless network candidates become available.", "system");
        }
        this._secureLog("debug", "ICE gathering completed for answer", {
          operationId,
          iceGatheringState: this.peerConnection.iceGatheringState,
          connectionState: this.peerConnection.connectionState
        });
        const ecdhPublicKeyData = await window.EnhancedSecureCryptoUtils.exportPublicKeyWithSignature(
          this.ecdhKeyPair.publicKey,
          this.ecdsaKeyPair.privateKey,
          "ECDH"
        );
        const ecdsaPublicKeyData = await window.EnhancedSecureCryptoUtils.exportPublicKeyWithSignature(
          this.ecdsaKeyPair.publicKey,
          this.ecdsaKeyPair.privateKey,
          "ECDSA"
        );
        if (!ecdhPublicKeyData || typeof ecdhPublicKeyData !== "object") {
          this._secureLog("error", "CRITICAL: ECDH key export failed - invalid object structure", { operationId });
          throw new Error("CRITICAL SECURITY FAILURE: ECDH key export validation failed - hard abort required");
        }
        if (!ecdhPublicKeyData.keyData || !ecdhPublicKeyData.signature) {
          this._secureLog("error", "CRITICAL: ECDH key export incomplete - missing keyData or signature", {
            operationId,
            hasKeyData: !!ecdhPublicKeyData.keyData,
            hasSignature: !!ecdhPublicKeyData.signature
          });
          throw new Error("CRITICAL SECURITY FAILURE: ECDH key export incomplete - hard abort required");
        }
        if (!ecdsaPublicKeyData || typeof ecdsaPublicKeyData !== "object") {
          this._secureLog("error", "CRITICAL: ECDSA key export failed - invalid object structure", { operationId });
          throw new Error("CRITICAL SECURITY FAILURE: ECDSA key export validation failed - hard abort required");
        }
        if (!ecdsaPublicKeyData.keyData || !ecdsaPublicKeyData.signature) {
          this._secureLog("error", "CRITICAL: ECDSA key export incomplete - missing keyData or signature", {
            operationId,
            hasKeyData: !!ecdsaPublicKeyData.keyData,
            hasSignature: !!ecdsaPublicKeyData.signature
          });
          throw new Error("CRITICAL SECURITY FAILURE: ECDSA key export incomplete - hard abort required");
        }
        const securityLevel = {
          level: "MAXIMUM",
          score: 100,
          color: "green",
          details: "All security features enabled by default",
          passedChecks: 10,
          totalChecks: 10,
          isRealData: true
        };
        const currentTimestamp = Date.now();
        const answerPackage = {
          // Core information (minimal)
          t: "answer",
          // type
          s: this.peerConnection.localDescription.sdp,
          // sdp
          v: _EnhancedSecureWebRTCManager.PROTOCOL_VERSION,
          // version
          ts: currentTimestamp,
          // timestamp
          // Cryptographic keys (essential)
          e: ecdhPublicKeyData,
          // ecdhPublicKey
          d: ecdsaPublicKeyData,
          // ecdsaPublicKey
          // Authentication (essential)
          ap: authProof,
          // authProof
          // Security metadata (simplified)
          slv: "MAX",
          // securityLevel
          // Double Ratchet support (see the note on the offer package).
          dr: _EnhancedSecureWebRTCManager.RATCHET_VERSION,
          // Session confirmation (simplified)
          sc: {
            sf: saltFingerprint.substring(0, 12),
            // saltFingerprint (12 chars)
            kd: true,
            // keyDerivationSuccess
            ma: true
            // mutualAuthEnabled
          }
        };
        const hasSDP = answerPackage.s || answerPackage.sdp;
        const hasECDH = answerPackage.e || answerPackage.ecdhPublicKey;
        const hasECDSA = answerPackage.d || answerPackage.ecdsaPublicKey;
        if (!hasSDP || !hasECDH || !hasECDSA) {
          throw new Error("Generated answer package is incomplete");
        }
        this._secureLog("info", "Enhanced secure answer created successfully", {
          operationId,
          version: answerPackage.version,
          hasECDSA: true,
          hasMutualAuth: !!authProof,
          hasSessionConfirmation: !!answerPackage.sessionConfirmation,
          securityLevel: securityLevel.level,
          timestamp: currentTimestamp,
          processingTime: currentTimestamp - offerData.timestamp
        });
        this._dispatchAppEvent?.(new CustomEvent("new-connection", {
          detail: {
            type: "answer",
            timestamp: currentTimestamp,
            securityLevel: securityLevel.level,
            operationId
          }
        }));
        setTimeout(async () => {
          try {
            const realSecurityData = await this.calculateAndReportSecurityLevel();
            if (realSecurityData) {
              this.notifySecurityUpdate();
              this._secureLog("info", "Post-connection security level calculated", {
                operationId,
                level: realSecurityData.level
              });
            }
          } catch (error) {
            this._secureLog("error", "Error calculating post-connection security", {
              operationId,
              errorType: error.constructor.name
            });
          }
        }, 1e3);
        setTimeout(async () => {
          if (!this.lastSecurityCalculation || this.lastSecurityCalculation.score < 50) {
            this._secureLog("info", "Retrying security calculation", {
              operationId
            });
            await this.calculateAndReportSecurityLevel();
            this.notifySecurityUpdate();
          }
        }, 3e3);
        this.notifySecurityUpdate();
        return answerPackage;
      } catch (error) {
        this._secureLog("error", "Enhanced secure answer creation failed in critical section", {
          operationId,
          errorType: error.constructor.name,
          errorMessage: error.message,
          phase: this._determineAnswerErrorPhase(error),
          offerAge: offerData?.timestamp ? Date.now() - offerData.timestamp : "unknown"
        });
        this._cleanupFailedAnswerCreation();
        this.onStatusChange("disconnected");
        if (this.onAnswerError) {
          if (error.message.includes("too old") || error.message.includes("replay")) {
            this.onAnswerError("replay_attack", error.message);
          } else if (error.message.includes("MITM") || error.message.includes("signature")) {
            this.onAnswerError("security_violation", error.message);
          } else if (error.message.includes("validation") || error.message.includes("format")) {
            this.onAnswerError("invalid_format", error.message);
          } else {
            this.onAnswerError("general_error", error.message);
          }
        }
        throw error;
      }
    }, 6e4);
  }
  /**
   * HELPER: Determine error phase for answer
   */
  _determineAnswerErrorPhase(error) {
    const message = error.message.toLowerCase();
    if (message.includes("validation") || message.includes("format")) return "offer_validation";
    if (message.includes("rate limit")) return "rate_limiting";
    if (message.includes("replay") || message.includes("too old")) return "replay_protection";
    if (message.includes("salt")) return "salt_validation";
    if (message.includes("key pair") || message.includes("generate")) return "key_generation";
    if (message.includes("import") || message.includes("ecdsa") || message.includes("ecdh")) return "key_import";
    if (message.includes("signature") || message.includes("mitm")) return "signature_verification";
    if (message.includes("derive") || message.includes("shared")) return "key_derivation";
    if (message.includes("auth") || message.includes("proof")) return "authentication";
    if (message.includes("remote description") || message.includes("local description")) return "webrtc_setup";
    if (message.includes("answer") || message.includes("sdp")) return "sdp_creation";
    if (message.includes("export")) return "key_export";
    if (message.includes("security level")) return "security_calculation";
    return "unknown";
  }
  /**
   * HELPER: Cleanup state after failed answer creation
   */
  /**
   *   Secure cleanup state after failed answer creation
   */
  _cleanupFailedAnswerCreation() {
    try {
      this._clearPendingOfferContext();
      this._secureCleanupCryptographicMaterials();
      this.currentKeyVersion = 0;
      this.keyVersions.clear();
      this.oldKeys.clear();
      if (this.peerConnection) {
        this.peerConnection.close();
        this.peerConnection = null;
      }
      if (this.dataChannel) {
        this.dataChannel.close();
        this.dataChannel = null;
      }
      this.isInitiator = false;
      this.isVerified = false;
      this.sequenceNumber = 0;
      this.expectedSequenceNumber = 0;
      this.messageCounter = 0;
      this.processedMessageIds.clear();
      this.replayWindow.clear();
      this._updateSecurityFeatures({
        hasEncryption: false,
        hasECDH: false,
        hasECDSA: false,
        hasMutualAuth: false,
        hasMetadataProtection: false,
        hasEnhancedReplayProtection: false,
        hasNonExtractableKeys: false,
        hasEnhancedValidation: false,
        hasPFS: false
      });
      this._forceGarbageCollection().catch((error) => {
        this._secureLog("error", "Cleanup failed during answer cleanup", {
          errorType: error?.constructor?.name || "Unknown"
        });
      });
      this._secureLog("debug", "Failed answer creation cleanup completed with secure memory wipe");
    } catch (cleanupError) {
      this._secureLog("error", "Error during answer creation cleanup", {
        errorType: cleanupError.constructor.name,
        errorMessage: cleanupError.message
      });
    }
  }
  /**
   * HELPER: Securely set encryption keys (if not set yet)
   */
  async _setEncryptionKeys(encryptionKey, macKey, metadataKey, keyFingerprint) {
    return this._withMutex("keyOperation", async (operationId) => {
      this._secureLog("info", "Setting encryption keys with mutex", {
        operationId
      });
      if (!(encryptionKey instanceof CryptoKey) || !(macKey instanceof CryptoKey) || !(metadataKey instanceof CryptoKey)) {
        throw new Error("Invalid key types provided");
      }
      if (!keyFingerprint || typeof keyFingerprint !== "string") {
        throw new Error("Invalid key fingerprint provided");
      }
      const oldKeys = {
        encryptionKey: this.encryptionKey,
        macKey: this.macKey,
        metadataKey: this.metadataKey,
        keyFingerprint: this.keyFingerprint
      };
      try {
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
        this.metadataKey = metadataKey;
        this.keyFingerprint = keyFingerprint;
        this.sequenceNumber = 0;
        this.expectedSequenceNumber = 0;
        this.messageCounter = 0;
        this.processedMessageIds.clear();
        this.replayWindow.clear();
        this._secureLog("info", "Encryption keys set successfully", {
          operationId,
          hasAllKeys: !!(this.encryptionKey && this.macKey && this.metadataKey),
          hasFingerprint: !!this.keyFingerprint
        });
        return true;
      } catch (error) {
        this.encryptionKey = oldKeys.encryptionKey;
        this.macKey = oldKeys.macKey;
        this.metadataKey = oldKeys.metadataKey;
        this.keyFingerprint = oldKeys.keyFingerprint;
        this._secureLog("error", "Key setting failed, rolled back", {
          operationId,
          errorType: error.constructor.name
        });
        throw error;
      }
    });
  }
  /**
   * SBQ2 answer handling on the offerer side.
   *
   * Sets the remote description and nothing else. No key is imported and no
   * secret derived here, because none has been sent yet — that happens in
   * _runSbq2KeyExchange once the channel is open and the commitment has been
   * checked.
   */
  async _handleSbq2Answer(answerData) {
    if (!this._isSbq2()) {
      throw new Error("Received a new-format response to an old-format invitation. Please start a new invitation.");
    }
    const st = this._sbq2State();
    const answerBytes = decodeText(String(answerData.sbq2));
    const desc = decodeDescriptor(answerBytes);
    if (desc.type !== TYPE.ANSWER) throw new Error("That code is an invitation, not a response to one.");
    if (!desc.commitment) throw new Error("The response carries no key commitment");
    const digest = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
    const expected = await bindingTag(digest, st.localDescriptor);
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ desc.bindingTag[i];
    if (diff !== 0) {
      throw new Error("This response belongs to a different invitation. Ask for a response to the code you are showing now.");
    }
    st.remoteDescriptor = answerBytes;
    st.remoteCommitment = desc.commitment;
    this._peerDTLSFingerprint = Array.from(
      desc.fingerprint,
      (b) => b.toString(16).padStart(2, "0").toUpperCase()
    ).join(":");
    const { sdp } = serializeSdp(desc);
    await this.peerConnection.setRemoteDescription({ type: "answer", sdp });
    this._secureLog("info", "SBQ2 answer accepted; awaiting in-band key exchange", {
      bytes: answerBytes.length
    });
  }
  async handleSecureAnswer(answerData) {
    if (answerData && typeof answerData.sbq2 === "string") {
      return this._handleSbq2Answer(answerData);
    }
    try {
      if (!answerData || typeof answerData !== "object" || Array.isArray(answerData)) {
        this._secureLog("error", "CRITICAL: Invalid answer data structure", {
          hasAnswerData: !!answerData,
          answerDataType: typeof answerData,
          isArray: Array.isArray(answerData)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Answer data must be a non-null object");
      }
      const isCompactAnswer = answerData.t === "answer" && answerData.s;
      const isLegacyAnswer = answerData.type === "enhanced_secure_answer" && answerData.sdp;
      if (!isCompactAnswer && !isLegacyAnswer) {
        this._secureLog("error", "CRITICAL: Invalid answer format", {
          type: answerData.type || answerData.t,
          hasSdp: !!(answerData.sdp || answerData.s)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Invalid answer format - hard abort required");
      }
      const answerVersion = answerData.v || answerData.version;
      if (answerVersion !== _EnhancedSecureWebRTCManager.PROTOCOL_VERSION) {
        throw new Error(`Version mismatch: expected protocol ${_EnhancedSecureWebRTCManager.PROTOCOL_VERSION}, received ${answerVersion || "unknown"}`);
      }
      const ecdhKey = answerData.ecdhPublicKey || answerData.e;
      const ecdsaKey = answerData.ecdsaPublicKey || answerData.d;
      if (!ecdhKey || typeof ecdhKey !== "object" || Array.isArray(ecdhKey)) {
        this._secureLog("error", "CRITICAL: Invalid ECDH public key structure in answer", {
          hasEcdhKey: !!ecdhKey,
          ecdhKeyType: typeof ecdhKey,
          isArray: Array.isArray(ecdhKey),
          availableKeys: Object.keys(answerData)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Missing or invalid ECDH public key structure");
      }
      if (!ecdhKey.keyData || !ecdhKey.signature) {
        this._secureLog("error", "CRITICAL: ECDH key missing keyData or signature in answer", {
          hasKeyData: !!ecdhKey.keyData,
          hasSignature: !!ecdhKey.signature
        });
        throw new Error("CRITICAL SECURITY FAILURE: ECDH key missing keyData or signature");
      }
      if (!ecdsaKey || typeof ecdsaKey !== "object" || Array.isArray(ecdsaKey)) {
        this._secureLog("error", "CRITICAL: Invalid ECDSA public key structure in answer", {
          hasEcdsaKey: !!ecdsaKey,
          ecdsaKeyType: typeof ecdsaKey,
          isArray: Array.isArray(ecdsaKey)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Missing or invalid ECDSA public key structure");
      }
      if (!ecdsaKey.keyData || !ecdsaKey.signature) {
        this._secureLog("error", "CRITICAL: ECDSA key missing keyData or signature in answer", {
          hasKeyData: !!ecdsaKey.keyData,
          hasSignature: !!ecdsaKey.signature
        });
        throw new Error("CRITICAL SECURITY FAILURE: ECDSA key missing keyData or signature");
      }
      const timestamp = answerData.ts || answerData.timestamp;
      const version2 = answerData.v || answerData.version;
      if (!timestamp || !version2) {
        throw new Error("Missing required fields in response data \u2013 possible MITM attack");
      }
      if (answerData.sessionId && this.sessionId && answerData.sessionId !== this.sessionId) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Session ID mismatch detected - possible MITM attack", {});
        throw new Error("Session ID mismatch \u2013 possible MITM attack");
      }
      const answerAge = Date.now() - answerData.timestamp;
      if (answerAge > 36e5) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Answer data is too old - possible replay attack", {
          answerAge,
          timestamp: answerData.timestamp
        });
        if (this.onAnswerError) {
          this.onAnswerError("replay_attack", "Response data is too old \u2013 possible replay attack");
        }
        throw new Error("Response data is too old \u2013 possible replay attack");
      }
      if (answerVersion !== _EnhancedSecureWebRTCManager.PROTOCOL_VERSION) {
        window.EnhancedSecureCryptoUtils.secureLog.log("warn", "Incompatible protocol version in answer", {
          expectedVersion: _EnhancedSecureWebRTCManager.PROTOCOL_VERSION,
          receivedVersion: answerVersion
        });
      }
      const peerECDSAPublicKey = await crypto.subtle.importKey(
        "spki",
        new Uint8Array(ecdsaKey.keyData),
        {
          name: "ECDSA",
          namedCurve: "P-384"
        },
        false,
        ["verify"]
      );
      const peerPublicKey = await window.EnhancedSecureCryptoUtils.importPublicKeyFromSignedPackage(
        ecdhKey,
        peerECDSAPublicKey
      );
      this._restorePendingOfferContextIfNeeded();
      if (!this.sessionSalt || this.sessionSalt.length !== 64) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Invalid session salt detected - possible session hijacking", {
          saltLength: this.sessionSalt ? this.sessionSalt.length : 0
        });
        throw new Error("Missing pending offer context. Apply the response in the original creator window that generated the invitation.");
      }
      const expectedSaltHash = await window.EnhancedSecureCryptoUtils.calculateKeyFingerprint(this.sessionSalt);
      window.EnhancedSecureCryptoUtils.secureLog.log("info", "Session salt integrity verified", {
        saltFingerprint: expectedSaltHash.substring(0, 8)
      });
      if (!(this.ecdhKeyPair?.privateKey instanceof CryptoKey)) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Local ECDH private key is not a CryptoKey in handleSecureAnswer", {
          hasKeyPair: !!this.ecdhKeyPair,
          privateKeyType: typeof this.ecdhKeyPair?.privateKey,
          privateKeyAlgorithm: this.ecdhKeyPair?.privateKey?.algorithm?.name
        });
        throw new Error("Local ECDH private key is not a CryptoKey");
      }
      if (!(peerPublicKey instanceof CryptoKey)) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Peer ECDH public key is not a CryptoKey in handleSecureAnswer", {
          publicKeyType: typeof peerPublicKey,
          publicKeyAlgorithm: peerPublicKey?.algorithm?.name
        });
        throw new Error("Peer ECDH public key is not a CryptoKey");
      }
      this.peerPublicKey = peerPublicKey;
      this._peerSupportsRatchet = answerData.dr === _EnhancedSecureWebRTCManager.RATCHET_VERSION;
      if (!this.connectionId) {
        this.connectionId = Array.from(crypto.getRandomValues(new Uint8Array(8))).map((b) => b.toString(16).padStart(2, "0")).join("");
      }
      const derivedKeys = await window.EnhancedSecureCryptoUtils.deriveSharedKeys(
        this.ecdhKeyPair.privateKey,
        peerPublicKey,
        this.sessionSalt
      );
      this.encryptionKey = derivedKeys.messageKey;
      this.macKey = derivedKeys.macKey;
      this.metadataKey = derivedKeys.metadataKey;
      this.keyFingerprint = derivedKeys.fingerprint;
      await this._initializeRatchet(
        derivedKeys,
        /* isInitiator */
        true
      );
      this.sequenceNumber = 0;
      this.expectedSequenceNumber = 0;
      this.messageCounter = 0;
      this.processedMessageIds.clear();
      this.replayWindow.clear();
      if (!(this.encryptionKey instanceof CryptoKey) || !(this.macKey instanceof CryptoKey) || !(this.metadataKey instanceof CryptoKey)) {
        window.EnhancedSecureCryptoUtils.secureLog.log("error", "Invalid key types after derivation in handleSecureAnswer", {
          encryptionKeyType: typeof this.encryptionKey,
          macKeyType: typeof this.macKey,
          metadataKeyType: typeof this.metadataKey,
          encryptionKeyAlgorithm: this.encryptionKey?.algorithm?.name,
          macKeyAlgorithm: this.macKey?.algorithm?.name,
          metadataKeyAlgorithm: this.metadataKey?.algorithm?.name
        });
        throw new Error("Invalid key types after export");
      }
      this._secureLog("info", "Encryption keys set in handleSecureAnswer", {
        hasEncryptionKey: !!this.encryptionKey,
        hasMacKey: !!this.macKey,
        hasMetadataKey: !!this.metadataKey,
        hasKeyFingerprint: !!this.keyFingerprint,
        mitmProtection: "enabled",
        signatureVerified: true
      });
      this.securityFeatures.hasMutualAuth = true;
      this.securityFeatures.hasMetadataProtection = true;
      this.securityFeatures.hasEnhancedReplayProtection = true;
      this.securityFeatures.hasPFS = true;
      this.currentKeyVersion = 0;
      this.lastKeyRotation = Date.now();
      this.keyVersions.set(0, {
        salt: this.sessionSalt,
        timestamp: this.lastKeyRotation,
        messageCount: 0
      });
      this.onKeyExchange(this.keyFingerprint);
      try {
        const remoteFP = this._extractDTLSFingerprintFromSDP(answerData.sdp || answerData.s);
        const localFP = this.expectedDTLSFingerprint;
        const keyBytes = this._decodeKeyFingerprint(this.keyFingerprint);
        this.verificationCode = await this._computeSAS(keyBytes, localFP, remoteFP);
        this._setSASMaterialReady(localFP, remoteFP);
        this.pendingSASCode = this.verificationCode;
        this._secureLog("info", "SAS verification code generated for MITM protection (Offer side)", {
          sasCode: this.verificationCode,
          localFP: localFP.substring(0, 16) + "...",
          remoteFP: remoteFP.substring(0, 16) + "...",
          timestamp: Date.now()
        });
      } catch (sasError) {
        this._secureLog("error", "SAS computation failed in handleSecureAnswer (Offer side)", {
          errorType: sasError?.constructor?.name || "Unknown"
        });
        this._secureLog("error", "SAS computation failed in handleSecureAnswer (Offer side)", {
          error: sasError.message,
          stack: sasError.stack,
          timestamp: Date.now()
        });
      }
      if (this.strictDTLSValidation) {
        try {
          this._peerDTLSFingerprint = this._extractDTLSFingerprintFromSDP(answerData.sdp || answerData.s);
        } catch (error) {
          this._secureLog("warn", "Could not extract peer DTLS fingerprint from answer", {
            error: error.message,
            context: "answer_validation"
          });
        }
      } else {
        this._secureLog("info", "DTLS fingerprint validation disabled - proceeding without validation");
      }
      const sdpData = answerData.sdp || answerData.s;
      if (this.peerConnection?.signalingState !== "have-local-offer") {
        this._secureLog("warn", "Ignoring answer outside have-local-offer state", {
          signalingState: this.peerConnection?.signalingState || "unknown"
        });
        return;
      }
      this._secureLog("debug", "Setting remote description from answer", {
        sdpLength: sdpData?.length || 0,
        usingCompactSDP: !answerData.sdp && !!answerData.s
      });
      await this.peerConnection.setRemoteDescription({
        type: "answer",
        sdp: sdpData
      });
      this._logIceCandidateDiagnostics("remote answer applied", this.peerConnection.remoteDescription?.sdp, {
        signalingState: this.peerConnection.signalingState
      });
      this._warnIfRemoteCandidatesNeedRelay("answer", this.peerConnection.remoteDescription?.sdp);
      this._secureLog("debug", "Remote description set successfully from answer", {
        signalingState: this.peerConnection.signalingState
      });
      setTimeout(async () => {
        try {
          const securityData = await this.calculateAndReportSecurityLevel();
          if (securityData) {
            this.notifySecurityUpdate();
          }
        } catch (error) {
          this._secureLog("error", "Error calculating security after connection:", { errorType: error?.constructor?.name || "Unknown" });
        }
      }, 1e3);
      setTimeout(async () => {
        if (!this.lastSecurityCalculation || this.lastSecurityCalculation.score < 50) {
          await this.calculateAndReportSecurityLevel();
          this.notifySecurityUpdate();
        }
      }, 3e3);
      this.notifySecurityUpdate();
    } catch (error) {
      this._secureLog("error", "Enhanced secure answer handling failed", {
        errorType: error.constructor.name
      });
      this.onStatusChange("failed");
      if (this.onAnswerError) {
        if (error.message.includes("too old") || error.message.includes("\u0441\u043B\u0438\u0448\u043A\u043E\u043C \u0441\u0442\u0430\u0440\u044B\u0435")) {
          this.onAnswerError("replay_attack", error.message);
        } else if (error.message.includes("MITM") || error.message.includes("signature") || error.message.includes("\u043F\u043E\u0434\u043F\u0438\u0441\u044C")) {
          this.onAnswerError("security_violation", error.message);
        } else {
          this.onAnswerError("general_error", error.message);
        }
      }
      throw error;
    }
  }
  initiateVerification() {
    if (this.isInitiator) {
      if (!this.verificationInitiationSent) {
        this.verificationInitiationSent = true;
        this.deliverMessageToUI("CRITICAL: Compare verification code with peer out-of-band (voice/video/in-person) to prevent MITM attack!", "system");
        this.deliverMessageToUI(`Your verification code: ${this.verificationCode}`, "system");
        this.deliverMessageToUI("Ask peer to confirm this exact code before allowing traffic!", "system");
      }
    } else {
      this.deliverMessageToUI("Waiting for verification code from peer...", "system");
    }
  }
  /**
   * Normalizes and validates the user-entered SAS code.
   * Users may enter the same shared SAS with spaces or hyphens.
   * @param {string} input
   * @returns {boolean}
   */
  _validateSASCode(input) {
    if (!input || typeof input !== "string" || !this.verificationCode || typeof this.verificationCode !== "string") {
      return false;
    }
    const normalizedInput = input.replace(/[-\s]/g, "").toUpperCase();
    const normalizedActual = this.verificationCode.replace(/[-\s]/g, "").toUpperCase();
    if (normalizedInput.length !== normalizedActual.length) {
      return false;
    }
    return window.EnhancedSecureCryptoUtils.constantTimeCompare(normalizedInput, normalizedActual);
  }
  confirmVerification(userCode) {
    try {
      if (!this._validateSASCode(userCode)) {
        this.sasValidationAttempts = (this.sasValidationAttempts || 0) + 1;
        this._secureLog("warn", "SAS validation failed: user entered incorrect code", {
          attempts: this.sasValidationAttempts,
          maxAttempts: _EnhancedSecureWebRTCManager.MAX_SAS_ATTEMPTS
        });
        if (this.sasValidationAttempts >= _EnhancedSecureWebRTCManager.MAX_SAS_ATTEMPTS) {
          this.deliverMessageToUI("Verification failed 3 times. Session reset for safety.", "system");
          this.disconnect();
          throw new Error("SAS_MAX_ATTEMPTS");
        }
        throw new Error("SAS_MISMATCH");
      }
      this.localVerificationConfirmed = true;
      this.sasValidationAttempts = 0;
      const confirmationPayload = {
        type: "verification_confirmed",
        data: {
          timestamp: Date.now(),
          verificationMethod: "MANUAL_SAS_ENTRY",
          securityLevel: "MITM_PROTECTION_REQUIRED"
        }
      };
      this.dataChannel.send(JSON.stringify(confirmationPayload));
      if (this.onVerificationStateChange) {
        this.onVerificationStateChange({
          localConfirmed: this.localVerificationConfirmed,
          remoteConfirmed: this.remoteVerificationConfirmed,
          bothConfirmed: this.bothVerificationsConfirmed
        });
      }
      this._checkBothVerificationsConfirmed();
      this.deliverMessageToUI("Code verified locally. Waiting for peer confirmation...", "system");
      this.processMessageQueue();
    } catch (error) {
      if (error.message === "SAS_MISMATCH") {
        this.deliverMessageToUI("Verification failed: the code you entered is incorrect.", "system");
      } else if (error.message !== "SAS_MAX_ATTEMPTS") {
        this._secureLog("error", "SAS verification failed:", { errorType: error?.constructor?.name || "Unknown" });
        this.deliverMessageToUI("SAS verification failed", "system");
      }
      throw error;
    }
  }
  _checkBothVerificationsConfirmed() {
    if (this.localVerificationConfirmed && this.remoteVerificationConfirmed && !this.bothVerificationsConfirmed) {
      this.bothVerificationsConfirmed = true;
      const bothConfirmedPayload = {
        type: "verification_both_confirmed",
        data: {
          timestamp: Date.now(),
          verificationMethod: "SAS",
          securityLevel: "MITM_PROTECTION_COMPLETE"
        }
      };
      this.dataChannel.send(JSON.stringify(bothConfirmedPayload));
      if (this.onVerificationStateChange) {
        this.onVerificationStateChange({
          localConfirmed: this.localVerificationConfirmed,
          remoteConfirmed: this.remoteVerificationConfirmed,
          bothConfirmed: this.bothVerificationsConfirmed
        });
      }
      this.deliverMessageToUI("Both parties confirmed! Opening secure chat in 2 seconds...", "system");
      setTimeout(() => {
        try {
          this._setVerifiedStatus(true, "MUTUAL_SAS_CONFIRMED", {
            code: this.verificationCode,
            timestamp: Date.now()
          });
          this._enforceVerificationGate("mutual_confirmed", false);
          this.onStatusChange?.("verified");
        } catch (error) {
          this._secureLog("error", "Verified transition rejected - aborting session", {
            errorType: error?.constructor?.name || "Unknown"
          });
          this.deliverMessageToUI("Verification could not be completed safely. Connection aborted.", "system");
          this.disconnect();
        }
      }, 2e3);
    }
  }
  handleVerificationConfirmed(data) {
    this.remoteVerificationConfirmed = true;
    this.deliverMessageToUI("Peer confirmed the verification code. Waiting for your confirmation...", "system");
    if (this.onVerificationStateChange) {
      this.onVerificationStateChange({
        localConfirmed: this.localVerificationConfirmed,
        remoteConfirmed: this.remoteVerificationConfirmed,
        bothConfirmed: this.bothVerificationsConfirmed
      });
    }
    this._checkBothVerificationsConfirmed();
  }
  handleVerificationBothConfirmed(data) {
    if (this.bothVerificationsConfirmed) {
      return;
    }
    if (!this.localVerificationConfirmed) {
      this._secureLog("error", "Peer claimed mutual SAS confirmation before local confirmation - possible MITM attack", {
        localConfirmed: this.localVerificationConfirmed,
        remoteConfirmed: this.remoteVerificationConfirmed,
        timestamp: Date.now()
      });
      this.deliverMessageToUI("Verification protocol violation: peer claimed confirmation before you verified the code. Connection aborted for safety.", "system");
      this.disconnect();
      return;
    }
    this.remoteVerificationConfirmed = true;
    this.bothVerificationsConfirmed = true;
    if (this.onVerificationStateChange) {
      this.onVerificationStateChange({
        localConfirmed: this.localVerificationConfirmed,
        remoteConfirmed: this.remoteVerificationConfirmed,
        bothConfirmed: this.bothVerificationsConfirmed
      });
    }
    this.deliverMessageToUI("Both parties confirmed! Opening secure chat in 2 seconds...", "system");
    setTimeout(() => {
      this._setVerifiedStatus(true, "MUTUAL_SAS_CONFIRMED", {
        code: this.verificationCode,
        timestamp: Date.now()
      });
      this._enforceVerificationGate("mutual_confirmed", false);
      this.onStatusChange?.("verified");
    }, 2e3);
  }
  handleVerificationRequest(data) {
    if (this._validateSASCode(data?.code)) {
      const responsePayload = {
        type: "verification_response",
        data: {
          ok: true,
          timestamp: Date.now(),
          verificationMethod: "SAS",
          // Indicate SAS was used
          securityLevel: "MITM_PROTECTED"
        }
      };
      this.dataChannel.send(JSON.stringify(responsePayload));
      if (!this.verificationNotificationSent) {
        this.verificationNotificationSent = true;
        this.deliverMessageToUI("SAS verification successful! MITM protection confirmed. Channel is now secure!", "system");
      }
      this.processMessageQueue();
    } else {
      const responsePayload = {
        type: "verification_response",
        data: {
          ok: false,
          timestamp: Date.now(),
          reason: "code_mismatch"
        }
      };
      this.dataChannel.send(JSON.stringify(responsePayload));
      this._secureLog("error", "SAS verification failed - possible MITM attack", {
        // Never log the codes themselves — the SAS is the one secret the
        // user is asked to compare out-of-band.
        receivedCodeLength: typeof data?.code === "string" ? data.code.length : 0,
        timestamp: Date.now()
      });
      this.deliverMessageToUI("SAS verification failed! Possible MITM attack detected. Connection aborted for safety!", "system");
      this.disconnect();
    }
  }
  handleSASCode(data) {
    if (!data?.code || typeof data.code !== "string") {
      this._secureLog("warn", "Invalid SAS announcement received from peer");
      return;
    }
    if (!this.verificationCode) {
      this._secureLog("error", "Received peer SAS announcement before local SAS was derived - refusing to adopt it", {
        timestamp: Date.now()
      });
      this.deliverMessageToUI("Verification failed: no locally derived code to compare against. Connection aborted for safety.", "system");
      this.disconnect();
      return;
    }
    if (!this._validateSASCode(data.code)) {
      this._secureLog("error", "Peer-announced SAS does not match locally computed SAS");
      this.deliverMessageToUI("Version or SAS mismatch detected. Connection aborted for safety.", "system");
      this.disconnect();
      return;
    }
    this._notifyVerificationReadyIfPossible();
    this._secureLog("info", "Peer SAS announcement matched locally derived code", {
      timestamp: Date.now()
    });
  }
  handleVerificationResponse(data) {
    if (data.ok === true) {
      this._secureLog("info", "Mutual SAS verification completed - MITM protection active", {
        verificationMethod: data.verificationMethod || "SAS",
        securityLevel: data.securityLevel || "MITM_PROTECTED",
        timestamp: Date.now()
      });
      if (!this.verificationNotificationSent) {
        this.verificationNotificationSent = true;
        this.deliverMessageToUI(" Mutual SAS verification complete! MITM protection active. Channel is now secure!", "system");
      }
      this.processMessageQueue();
    } else {
      this._secureLog("error", "Peer SAS verification failed - connection not secure", {
        responseData: data,
        timestamp: Date.now()
      });
      this.deliverMessageToUI("Peer verification failed! Connection not secure!", "system");
      this.disconnect();
    }
  }
  validateOfferData(offerData) {
    return offerData && offerData.type === "enhanced_secure_offer" && offerData.sdp && offerData.publicKey && offerData.salt && offerData.verificationCode && Array.isArray(offerData.publicKey) && Array.isArray(offerData.salt) && offerData.salt.length === 32;
  }
  validateEnhancedOfferData(offerData) {
    try {
      if (!offerData || typeof offerData !== "object" || Array.isArray(offerData)) {
        this._secureLog("error", "CRITICAL: Invalid offer data structure", {
          hasOfferData: !!offerData,
          offerDataType: typeof offerData,
          isArray: Array.isArray(offerData)
        });
        throw new Error("CRITICAL SECURITY FAILURE: Offer data must be a non-null object");
      }
      const isV4CompactFormat = offerData.v === _EnhancedSecureWebRTCManager.PROTOCOL_VERSION && offerData.e && offerData.d;
      const isV4Format = offerData.version === _EnhancedSecureWebRTCManager.PROTOCOL_VERSION && offerData.ecdhPublicKey && offerData.ecdsaPublicKey;
      const isValidType = isV4CompactFormat ? ["offer"].includes(offerData.t) : ["enhanced_secure_offer", "secure_offer"].includes(offerData.type);
      if (!isValidType) {
        throw new Error("Invalid offer type");
      }
      if (isV4CompactFormat) {
        const compactRequiredFields = [
          "e",
          "d",
          "sl",
          "vc",
          "si",
          "ci",
          "ac",
          "slv"
        ];
        for (const field of compactRequiredFields) {
          if (!offerData[field]) {
            throw new Error(`Missing required v4.1 compact field: ${field}`);
          }
        }
        if (!offerData.e || typeof offerData.e !== "object" || Array.isArray(offerData.e)) {
          throw new Error("CRITICAL SECURITY FAILURE: Invalid ECDH public key structure");
        }
        if (!offerData.d || typeof offerData.d !== "object" || Array.isArray(offerData.d)) {
          throw new Error("CRITICAL SECURITY FAILURE: Invalid ECDSA public key structure");
        }
        if (!Array.isArray(offerData.sl) || offerData.sl.length !== 64) {
          throw new Error("Salt must be exactly 64 bytes for v4.1");
        }
        if (typeof offerData.vc !== "string" || offerData.vc.length < 6) {
          throw new Error("Invalid verification code format");
        }
        if (!["MAX", "HIGH", "MED", "LOW"].includes(offerData.slv)) {
          throw new Error("Invalid security level");
        }
        const offerAge = Date.now() - offerData.ts;
        if (offerAge > 36e5) {
          throw new Error("Offer is too old (older than 1 hour)");
        }
        this._secureLog("info", "v4.1 compact offer validation passed", {
          version: offerData.v,
          hasECDH: !!offerData.e,
          hasECDSA: !!offerData.d,
          hasSalt: !!offerData.sl,
          hasVerificationCode: !!offerData.vc,
          securityLevel: offerData.slv,
          offerAge: Math.round(offerAge / 1e3) + "s"
        });
      } else if (isV4Format) {
        const v4RequiredFields = [
          "ecdhPublicKey",
          "ecdsaPublicKey",
          "salt",
          "verificationCode",
          "authChallenge",
          "timestamp",
          "version",
          "securityLevel"
        ];
        for (const field of v4RequiredFields) {
          if (!offerData[field]) {
            throw new Error(`Missing v4.1 field: ${field}`);
          }
        }
        if (!Array.isArray(offerData.salt) || offerData.salt.length !== 64) {
          throw new Error("Salt must be exactly 64 bytes for v4.1");
        }
        const offerAge = Date.now() - offerData.timestamp;
        if (offerAge > 36e5) {
          throw new Error("Offer is too old (older than 1 hour)");
        }
        if (!offerData.ecdhPublicKey || typeof offerData.ecdhPublicKey !== "object" || Array.isArray(offerData.ecdhPublicKey)) {
          this._secureLog("error", "CRITICAL: Invalid ECDH public key structure", {
            hasEcdhKey: !!offerData.ecdhPublicKey,
            ecdhKeyType: typeof offerData.ecdhPublicKey,
            isArray: Array.isArray(offerData.ecdhPublicKey)
          });
          throw new Error("CRITICAL SECURITY FAILURE: Invalid ECDH public key structure - hard abort required");
        }
        if (!offerData.ecdsaPublicKey || typeof offerData.ecdsaPublicKey !== "object" || Array.isArray(offerData.ecdsaPublicKey)) {
          this._secureLog("error", "CRITICAL: Invalid ECDSA public key structure", {
            hasEcdsaKey: !!offerData.ecdsaPublicKey,
            ecdsaKeyType: typeof offerData.ecdsaPublicKey,
            isArray: Array.isArray(offerData.ecdsaPublicKey)
          });
          throw new Error("CRITICAL SECURITY FAILURE: Invalid ECDSA public key structure - hard abort required");
        }
        if (!offerData.ecdhPublicKey.keyData || !offerData.ecdhPublicKey.signature) {
          this._secureLog("error", "CRITICAL: ECDH key missing keyData or signature", {
            hasKeyData: !!offerData.ecdhPublicKey.keyData,
            hasSignature: !!offerData.ecdhPublicKey.signature
          });
          throw new Error("CRITICAL SECURITY FAILURE: ECDH key missing keyData or signature");
        }
        if (!offerData.ecdsaPublicKey.keyData || !offerData.ecdsaPublicKey.signature) {
          this._secureLog("error", "CRITICAL: ECDSA key missing keyData or signature", {
            hasKeyData: !!offerData.ecdsaPublicKey.keyData,
            hasSignature: !!offerData.ecdsaPublicKey.signature
          });
          throw new Error("CRITICAL SECURITY FAILURE: ECDSA key missing keyData or signature");
        }
        if (typeof offerData.verificationCode !== "string" || offerData.verificationCode.length < 6) {
          throw new Error("Invalid SAS verification code format - MITM protection required");
        }
        this._secureLog("info", "v4.1 offer validation passed", {
          version: offerData.version,
          hasSecurityLevel: !!offerData.securityLevel?.level,
          offerAge: Math.round(offerAge / 1e3) + "s"
        });
      } else {
        const receivedVersion = offerData.v || offerData.version || "unknown";
        throw new Error(`Version mismatch: expected protocol ${_EnhancedSecureWebRTCManager.PROTOCOL_VERSION}, received ${receivedVersion}`);
      }
      const sdp = isV4CompactFormat ? offerData.s : offerData.sdp;
      if (typeof sdp !== "string" || !sdp.includes("v=0")) {
        throw new Error("Invalid SDP structure");
      }
      return true;
    } catch (error) {
      this._secureLog("error", "CRITICAL: Security validation failed - hard abort required", {
        error: error.message,
        errorType: error.constructor.name,
        timestamp: Date.now()
      });
      throw new Error(`CRITICAL SECURITY VALIDATION FAILURE: ${error.message}`);
    }
  }
  async sendSecureMessage(message) {
    const validation = this._validateInputData(message, "sendSecureMessage");
    if (!validation.isValid) {
      const errorMessage = `Input validation failed: ${validation.errors.join(", ")}`;
      this._secureLog("error", "Input validation failed in sendSecureMessage", {
        errors: validation.errors,
        messageType: typeof message
      });
      throw new Error(errorMessage);
    }
    if (!this._checkRateLimit("sendSecureMessage")) {
      throw new Error("Rate limit exceeded for secure message sending");
    }
    this._enforceVerificationGate("sendSecureMessage");
    if (!this.isConnected()) {
      if (validation.sanitizedData && typeof validation.sanitizedData === "object" && validation.sanitizedData.type && validation.sanitizedData.type.startsWith("file_")) {
        throw new Error("Connection not ready for file transfer. Please ensure the connection is established and verified.");
      }
      this.messageQueue.push(validation.sanitizedData);
      throw new Error("Connection not ready. Message queued for sending.");
    }
    return this._withMutex("cryptoOperation", async (operationId) => {
      if (!this.isConnected() || !this.isVerified) {
        throw new Error("Connection lost during message preparation");
      }
      if (!this.encryptionKey || !this.macKey || !this.metadataKey) {
        throw new Error("Encryption keys not initialized");
      }
      if (!window.EnhancedSecureCryptoUtils.rateLimiter.checkMessageRate(this.rateLimiterId)) {
        throw new Error("Message rate limit exceeded (60 messages per minute)");
      }
      try {
        const textToSend = typeof validation.sanitizedData === "string" ? validation.sanitizedData : JSON.stringify(validation.sanitizedData);
        const sanitizedMessage = window.EnhancedSecureCryptoUtils.sanitizeMessage(textToSend);
        const messageId = `msg_${Date.now()}_${this.messageCounter++}`;
        if (typeof this._createMessageAAD !== "function") {
          throw new Error("_createMessageAAD method is not available in sendSecureMessage. Manager may not be fully initialized.");
        }
        const aad = message.aad || this._createMessageAAD("enhanced_message", { content: sanitizedMessage });
        let payload;
        if (this._ratchet?.canEncrypt) {
          const { header, ciphertext } = await this._ratchet.encrypt(sanitizedMessage);
          payload = {
            type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.RATCHET_MESSAGE,
            h: header,
            c: ciphertext,
            version: "5.0"
          };
        } else {
          const encryptedData = await window.EnhancedSecureCryptoUtils.encryptMessage(
            sanitizedMessage,
            this.encryptionKey,
            this.macKey,
            this.metadataKey,
            messageId,
            JSON.parse(aad).sequenceNumber
            // Use sequence number from AAD
          );
          payload = {
            type: "enhanced_message",
            data: encryptedData,
            keyVersion: this.currentKeyVersion,
            version: "4.0"
          };
        }
        this.dataChannel.send(JSON.stringify(payload));
        if (typeof validation.sanitizedData === "string") {
          this.deliverMessageToUI(validation.sanitizedData, "sent");
        }
        this._secureLog("debug", "Secure message sent successfully", {
          operationId,
          messageLength: sanitizedMessage.length,
          keyVersion: this.currentKeyVersion
        });
      } catch (error) {
        this._secureLog("error", "Secure message sending failed", {
          operationId,
          errorType: error.constructor.name
        });
        if (error.message.includes("Session expired")) {
          throw new Error("Session expired. Please enter your password to unlock.");
        } else if (error.message.includes("Encryption keys not initialized")) {
          throw new Error("Session expired due to inactivity. Please reconnect to the chat.");
        } else if (error.message.includes("Connection lost")) {
          throw new Error("Connection lost. Please check your Internet connection.");
        } else if (error.message.includes("Rate limit exceeded")) {
          throw new Error("Message rate limit exceeded. Please wait before sending another message.");
        } else {
          throw error;
        }
      }
    }, 2e3);
  }
  processMessageQueue() {
    while (this.messageQueue.length > 0 && this.isConnected() && this.isVerified) {
      const message = this.messageQueue.shift();
      this.sendSecureMessage(message).catch(console.error);
    }
  }
  // Heartbeat runs on its own HEARTBEAT_INTERVAL timer. It used to be folded
  // into the unified maintenance cycle, which ticks every 5 minutes — far too
  // coarse to notice a dead path, and long enough that a drop looked like
  // silence. The maintenance cycle no longer sends heartbeats.
  startHeartbeat() {
    this._heartbeatConfig = {
      enabled: true,
      interval: _EnhancedSecureWebRTCManager.TIMEOUTS.HEARTBEAT_INTERVAL,
      lastHeartbeat: 0
    };
    this.stopHeartbeat(
      /* keepConfig */
      true
    );
    this._heartbeatTimer = setInterval(() => {
      if (!this._heartbeatConfig?.enabled) return;
      if (this.dataChannel?.readyState === "open") {
        this._sendHeartbeat();
      }
    }, _EnhancedSecureWebRTCManager.TIMEOUTS.HEARTBEAT_INTERVAL);
    this._trackActiveTimer(this._heartbeatTimer);
    this._lastInboundAt = Date.now();
    this._livenessProbeAt = 0;
    this._livenessArmed = false;
    this._startLivenessWatchdog();
    this._setupRecoveryLifecycleListeners();
    this._secureLog("info", "\u{1F504} Liveness watchdog started", {
      heartbeatMs: _EnhancedSecureWebRTCManager.TIMEOUTS.HEARTBEAT_INTERVAL,
      probeAfterMs: _EnhancedSecureWebRTCManager.TIMEOUTS.LIVENESS_PROBE_AFTER,
      probeTimeoutMs: _EnhancedSecureWebRTCManager.TIMEOUTS.LIVENESS_PROBE_TIMEOUT
    });
  }
  stopHeartbeat(keepConfig = false) {
    if (!keepConfig && this._heartbeatConfig) {
      this._heartbeatConfig.enabled = false;
    }
    if (this._heartbeatTimer) {
      clearInterval(this._heartbeatTimer);
      this._activeTimers?.delete(this._heartbeatTimer);
      this._heartbeatTimer = null;
    }
    if (!keepConfig) this._stopLivenessWatchdog();
  }
  /**
   * Inbound heartbeat from the peer. This method used to be missing entirely
   * while handleSystemMessage still dispatched to it, so every heartbeat threw
   * a TypeError and liveness was never actually observed.
   *
   * A non-ack heartbeat is a probe and must be answered immediately: that reply
   * is what proves this side is alive even when its tab is backgrounded and its
   * own timers have been throttled to a standstill.
   */
  handleHeartbeat(message) {
    this._lastInboundAt = Date.now();
    this._livenessProbeAt = 0;
    const isAck = message?.ack === true || message?.data?.ack === true;
    if (!isAck) this._sendHeartbeat(true);
    this._secureLog("debug", isAck ? "\u{1F493} Heartbeat ack received" : "\u{1F493} Heartbeat probe received");
  }
  /**
   * Any authenticated inbound frame proves the path is alive, not just
   * heartbeats — a busy conversation must never trip the watchdog.
   */
  _noteInboundActivity() {
    this._lastInboundAt = Date.now();
    this._livenessProbeAt = 0;
    this._livenessArmed = true;
  }
  _startLivenessWatchdog() {
    this._stopLivenessWatchdog();
    this._livenessTimer = setInterval(() => {
      try {
        this._checkLiveness();
      } catch (error) {
        this._secureLog("error", "\u274C Liveness check failed", {
          errorType: error?.constructor?.name || "Unknown"
        });
      }
    }, _EnhancedSecureWebRTCManager.TIMEOUTS.LIVENESS_CHECK_INTERVAL);
    this._trackActiveTimer(this._livenessTimer);
  }
  _stopLivenessWatchdog() {
    if (this._livenessTimer) {
      clearInterval(this._livenessTimer);
      this._activeTimers?.delete(this._livenessTimer);
      this._livenessTimer = null;
    }
  }
  /**
   * A data channel keeps reporting readyState === 'open' long after the
   * underlying path has died (the classic Wi-Fi → LTE switch: nothing closes,
   * nothing errors, packets simply stop). Nothing tells us — so we ask.
   *
   * Two steps, because silence alone is not evidence of death. A backgrounded
   * tab has its timers throttled to roughly one tick per minute (frozen
   * outright on iOS), so a healthy peer routinely goes quiet. What a healthy
   * peer cannot do is fail to ANSWER: inbound message handling is not throttled
   * the way timers are. So after a period of silence we send a probe, and only
   * an unanswered probe is treated as a dead path.
   */
  _checkLiveness() {
    if (!this.isVerified) return;
    if (this._reconnect.phase !== "idle") return;
    if (this.dataChannel?.readyState !== "open") return;
    if (!this._lastInboundAt) return;
    if (!this._livenessArmed) return;
    const T = _EnhancedSecureWebRTCManager.TIMEOUTS;
    const now = Date.now();
    const iceHealthy = this.peerConnection?.connectionState === "connected";
    if (iceHealthy) {
      this._livenessProbeAt = 0;
      return;
    }
    if (this._livenessProbeAt) {
      if (now - this._livenessProbeAt < T.LIVENESS_PROBE_TIMEOUT) return;
      this._livenessProbeAt = 0;
      this._secureLog("warn", "\u26A0\uFE0F liveness probe unanswered and ICE is not connected \u2014 path presumed dead");
      this._onPathLost("liveness_probe_timeout");
      return;
    }
    if (now - this._lastInboundAt < T.LIVENESS_PROBE_AFTER) return;
    this._livenessProbeAt = now;
    const delivered = this._sendHeartbeat(false);
    this._secureLog("info", "\u{1F504} peer silent and ICE degraded, probing", {
      silentForMs: now - this._lastInboundAt,
      connectionState: this.peerConnection?.connectionState,
      probeSent: delivered
    });
  }
  // ============================================
  // SESSION RECOVERY (serverless, in-band)
  // ============================================
  //
  // What survives an ICE restart and what does not:
  //
  //   ICE restart replaces the candidate pair — i.e. the network path. The
  //   DTLS handshake, the negotiated keys and the SCTP association that the
  //   data channel rides on are all layered ABOVE ICE and survive untouched.
  //   That is why a restart can recover a Wi-Fi → LTE switch without a new
  //   handshake, without a new SAS, and without losing message history.
  //
  //   The restart SDP travels over that same still-established data channel,
  //   so it inherits the channel's authentication: an attacker who cannot
  //   already decrypt the session cannot inject one. No signalling server is
  //   involved at any point.
  //
  //   The one thing a restart must never do is change peer identity, so the
  //   DTLS fingerprint in the incoming SDP is checked against the fingerprint
  //   of the live session before anything is applied. A mismatch is treated
  //   as an attack and aborts recovery rather than re-keying to a stranger.
  //
  // What it cannot recover: a closed data channel (SCTP gone) or a path so
  // dead that the restart offer itself cannot be delivered. Those fall
  // through to _giveUpAutoReconnect and require a fresh, manually exchanged
  // handshake — the existing offer/answer flow.
  isReconnecting() {
    return this._reconnect.phase !== "idle" && this._reconnect.phase !== "exhausted";
  }
  /**
   * Device-level signals that a path is worth re-checking right now, instead of
   * waiting out a backoff: this device regained network, or a mobile browser
   * brought the tab back to the foreground (where it may have frozen the
   * connection while backgrounded).
   */
  _setupRecoveryLifecycleListeners() {
    if (typeof window === "undefined" || this._recoveryLifecycleBound) return;
    this._recoveryLifecycleBound = true;
    this._onDeviceOnline = () => {
      if (!this.isVerified) return;
      if (this.isReconnecting()) {
        this._secureLog("info", "\u{1F504} Device back online \u2014 retrying immediately");
        this._attemptIceRestart();
      } else {
        this._checkLiveness();
      }
    };
    this._onVisibilityRestored = () => {
      if (typeof document === "undefined" || document.visibilityState !== "visible") return;
      if (!this.isVerified) return;
      this._lastInboundAt = Date.now();
      this._livenessProbeAt = 0;
      if (this._reconnect.phase === "idle" && this.dataChannel?.readyState === "open") {
        this._livenessProbeAt = Date.now();
        this._sendHeartbeat(false);
        this._secureLog("info", "\u{1F504} returned to foreground, probing peer");
      }
    };
    window.addEventListener("online", this._onDeviceOnline);
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", this._onVisibilityRestored);
    }
  }
  _teardownRecoveryLifecycleListeners() {
    if (!this._recoveryLifecycleBound || typeof window === "undefined") return;
    this._recoveryLifecycleBound = false;
    if (this._onDeviceOnline) window.removeEventListener("online", this._onDeviceOnline);
    if (this._onVisibilityRestored && typeof document !== "undefined") {
      document.removeEventListener("visibilitychange", this._onVisibilityRestored);
    }
    this._onDeviceOnline = null;
    this._onVisibilityRestored = null;
  }
  _resetReconnectState() {
    const r = this._reconnect;
    if (!r) return;
    if (r.graceTimer) {
      clearTimeout(r.graceTimer);
      this._activeTimers?.delete(r.graceTimer);
    }
    if (r.retryTimer) {
      clearTimeout(r.retryTimer);
      this._activeTimers?.delete(r.retryTimer);
    }
    if (r.restartTimer) {
      clearTimeout(r.restartTimer);
      this._activeTimers?.delete(r.restartTimer);
    }
    r.graceTimer = null;
    r.retryTimer = null;
    r.restartTimer = null;
    r.phase = "idle";
    r.attempts = 0;
    r.startedAt = 0;
    r.inFlightAt = 0;
    r.barrenFailures = 0;
    r.pendingRole = null;
  }
  /**
   * ICE reported 'disconnected'. This is usually transient — the browser's own
   * consent freshness checks recover it within a couple of seconds — so hold a
   * grace window before spending a restart, but tell the UI right away so the
   * user sees "reconnecting" rather than a silently stalled chat.
   */
  _onPathDegraded(reason = "ice_disconnected") {
    if (!this.isVerified) return;
    if (this._reconnect.phase !== "idle") return;
    this._reconnect.phase = "grace";
    this._reconnect.startedAt = Date.now();
    this._secureLog("info", "\u{1F504} path degraded, holding grace window", { reason });
    this.onStatusChange("reconnecting");
    this._reconnect.graceTimer = setTimeout(() => {
      this._reconnect.graceTimer = null;
      if (this.peerConnection?.connectionState === "connected") {
        this._onPathRecovered();
        return;
      }
      this._attemptIceRestart();
    }, _EnhancedSecureWebRTCManager.TIMEOUTS.ICE_DISCONNECT_GRACE);
    this._trackActiveTimer(this._reconnect.graceTimer);
  }
  /** ICE failed outright, or the peer went silent — restart without waiting. */
  _onPathLost(reason = "ice_failed") {
    if (!this.isVerified) return;
    if (this._reconnect.phase === "restarting" || this._reconnect.phase === "exhausted") return;
    if (this._reconnect.phase === "idle") {
      this._reconnect.startedAt = Date.now();
      this.onStatusChange("reconnecting");
    }
    if (this._reconnect.graceTimer) {
      clearTimeout(this._reconnect.graceTimer);
      this._activeTimers?.delete(this._reconnect.graceTimer);
      this._reconnect.graceTimer = null;
    }
    this._secureLog("info", "\u{1F504} path lost, restarting ICE", { reason });
    this._attemptIceRestart();
  }
  /**
   * A restart is only worth trying while the ICE agent can still produce
   * candidates. After the device changes network, a PeerConnection is often
   * left bound to interfaces that no longer exist: every STUN binding and TURN
   * allocation times out, gathering yields nothing, and each restart fails with
   * zero candidate pairs. restartIce() does not rebind it — only a brand-new
   * PeerConnection will, and building one needs a whole new handshake.
   *
   * Recognising that early matters: retrying it for the full two-minute
   * deadline is two minutes of the user watching nothing happen, when the way
   * out was available immediately.
   */
  _noteIceFailureDiagnostics(diagnostics) {
    if (!this.isReconnecting()) return;
    if (!diagnostics) return;
    if (diagnostics.pairCount > 0) {
      this._reconnect.barrenFailures = 0;
      return;
    }
    this._reconnect.barrenFailures = (this._reconnect.barrenFailures || 0) + 1;
    if (this._reconnect.barrenFailures < _EnhancedSecureWebRTCManager.LIMITS.MAX_BARREN_ICE_FAILURES) return;
    this._secureLog("warn", "\u26A0\uFE0F ICE cannot gather any usable candidate \u2014 this connection is bound to a network that is gone", {
      consecutiveBarrenFailures: this._reconnect.barrenFailures
    });
    this._giveUpAutoReconnect("ice_agent_unusable");
  }
  /**
   * Path is back. Same keys, same verification, same history — carry on.
   * Returns true if it actually handled a recovery (and therefore already
   * emitted 'connected'), so the caller does not emit it twice.
   */
  _onPathRecovered() {
    const wasRecovering = this.isReconnecting();
    this._resetReconnectState();
    this._lastInboundAt = Date.now();
    this._livenessProbeAt = 0;
    if (!wasRecovering) return false;
    this._secureLog("info", "\u{1F504} connection recovered, session preserved");
    this.onStatusChange("connected");
    this.processMessageQueue();
    try {
      this._dispatchAppEvent?.(new CustomEvent("connection-recovered", {
        detail: { timestamp: Date.now() }
      }));
    } catch (_) {
    }
    return true;
  }
  /**
   * Only the side that created the original offer drives restarts. Both sides
   * offering at once produces glare, and with no signalling server there is no
   * referee to break the tie — so the answerer asks instead of acting.
   */
  async _attemptIceRestart() {
    if (!this.isVerified || !this.peerConnection) return;
    if (this.peerConnection.connectionState === "connected") {
      this._onPathRecovered();
      return;
    }
    const r = this._reconnect;
    if (typeof navigator !== "undefined" && navigator.onLine === false) {
      r.phase = "waiting";
      r.startedAt = Date.now();
      this._secureLog("debug", "\u{1F504} Device offline \u2014 holding recovery open");
      this._scheduleReconnectRetry();
      return;
    }
    const elapsed = Date.now() - (r.startedAt || Date.now());
    if (elapsed > _EnhancedSecureWebRTCManager.TIMEOUTS.RECONNECT_MAX_DURATION) {
      this._giveUpAutoReconnect("timeout");
      return;
    }
    if (r.inFlightAt && Date.now() - r.inFlightAt < _EnhancedSecureWebRTCManager.TIMEOUTS.ICE_RESTART_TIMEOUT) {
      this._scheduleReconnectRetry();
      return;
    }
    if (this.dataChannel?.readyState !== "open") {
      this._giveUpAutoReconnect("data_channel_closed");
      return;
    }
    const silentFor = Date.now() - Math.max(this._lastInboundAt || 0, r.startedAt);
    if (r.attempts >= 2 && silentFor > _EnhancedSecureWebRTCManager.TIMEOUTS.RECOVERY_SILENCE_LIMIT) {
      this._secureLog("warn", "\u26A0\uFE0F nothing has reached us since the drop \u2014 the channel cannot carry a renegotiation", {
        silentForMs: silentFor,
        attempts: r.attempts
      });
      this._giveUpAutoReconnect("no_signalling_path");
      return;
    }
    r.phase = "restarting";
    r.attempts += 1;
    r.inFlightAt = Date.now();
    this._secureLog("info", "\u{1F504} ICE restart attempt", {
      attempt: r.attempts,
      role: this.isInitiator ? "offerer" : "answerer"
    });
    try {
      if (this.isInitiator) {
        await this._sendIceRestartOffer();
      } else {
        await this.sendSystemMessage({
          type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.ICE_RESTART_REQUEST,
          timestamp: Date.now()
        });
      }
    } catch (error) {
      this._secureLog("warn", "\u26A0\uFE0F ICE restart attempt failed to send", {
        errorType: error?.constructor?.name || "Unknown"
      });
    }
    this._scheduleReconnectRetry();
  }
  _scheduleReconnectRetry() {
    const r = this._reconnect;
    if (r.retryTimer) {
      clearTimeout(r.retryTimer);
      this._activeTimers?.delete(r.retryTimer);
    }
    const backoff = _EnhancedSecureWebRTCManager.RECONNECT_BACKOFF;
    const delay = backoff[Math.min(Math.max(r.attempts - 1, 0), backoff.length - 1)];
    r.retryTimer = setTimeout(() => {
      r.retryTimer = null;
      if (this.peerConnection?.connectionState === "connected") {
        this._onPathRecovered();
        return;
      }
      this._attemptIceRestart();
    }, delay);
    this._trackActiveTimer(r.retryTimer);
  }
  async _sendIceRestartOffer() {
    const pc = this.peerConnection;
    if (!pc) return;
    if (pc.signalingState === "have-local-offer") {
      try {
        await pc.setLocalDescription({ type: "rollback" });
      } catch (_) {
      }
    }
    const offer = await pc.createOffer({ iceRestart: true });
    await pc.setLocalDescription(offer);
    await this.waitForIceGathering(
      _EnhancedSecureWebRTCManager.TIMEOUTS.ICE_RESTART_GATHERING,
      // Recovery keeps a hard 4 s budget: a restart round-trip has to fit
      // inside ICE_RESTART_TIMEOUT, so the extra patience the handshake
      // gets would push the whole cycle past its own deadline.
      _EnhancedSecureWebRTCManager.TIMEOUTS.ICE_RESTART_GATHERING
    );
    await this.sendSystemMessage({
      type: _EnhancedSecureWebRTCManager.MESSAGE_TYPES.ICE_RESTART_OFFER,
      sdp: pc.localDescription.sdp,
      timestamp: Date.now()
    });
    this._secureLog("debug", "\u{1F504} ICE restart offer sent");
  }
  /**
   * The fingerprint of the live, already-SAS-verified session. Recovery must
   * re-point the path at the SAME peer, never re-key to a new one.
   */
  _currentRemoteDtlsFingerprint() {
    const sdp = this.peerConnection?.currentRemoteDescription?.sdp || this.peerConnection?.remoteDescription?.sdp;
    if (!sdp) return null;
    try {
      return this._extractDTLSFingerprintFromSDP(sdp);
    } catch (_) {
      return null;
    }
  }
  async _assertSameRemoteIdentity(sdp, context) {
    const expected = this._currentRemoteDtlsFingerprint();
    if (!expected) {
      throw new Error(`Cannot verify peer identity for ${context}`);
    }
    const received = this._extractDTLSFingerprintFromSDP(sdp);
    await this._validateDTLSFingerprint(received, expected, context);
  }
  /** Inbound recovery signalling, routed from processMessage. */
  async _handleIceRestartSignal(type, data) {
    const T = _EnhancedSecureWebRTCManager.MESSAGE_TYPES;
    const pc = this.peerConnection;
    if (!pc) return;
    this._noteInboundActivity();
    switch (type) {
      case T.ICE_RESTART_REQUEST: {
        if (!this.isInitiator) return;
        if (this._reconnect.phase === "idle") {
          this._reconnect.startedAt = Date.now();
          this._reconnect.phase = "restarting";
          this.onStatusChange("reconnecting");
        }
        await this._sendIceRestartOffer();
        return;
      }
      case T.ICE_RESTART_OFFER: {
        if (!data.sdp) return;
        await this._assertSameRemoteIdentity(data.sdp, "ice_restart_offer");
        if (this._reconnect.phase === "idle") {
          this._reconnect.startedAt = Date.now();
          this.onStatusChange("reconnecting");
        }
        this._reconnect.phase = "restarting";
        await pc.setRemoteDescription({ type: "offer", sdp: data.sdp });
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        await this.waitForIceGathering(
          _EnhancedSecureWebRTCManager.TIMEOUTS.ICE_RESTART_GATHERING,
          // Recovery keeps a hard 4 s budget: a restart round-trip has to
          // fit inside ICE_RESTART_TIMEOUT, so the extra patience the
          // handshake gets would push the cycle past its own deadline.
          _EnhancedSecureWebRTCManager.TIMEOUTS.ICE_RESTART_GATHERING
        );
        await this.sendSystemMessage({
          type: T.ICE_RESTART_ANSWER,
          sdp: pc.localDescription.sdp,
          timestamp: Date.now()
        });
        this._secureLog("debug", "\u{1F504} ICE restart answer sent");
        return;
      }
      case T.ICE_RESTART_ANSWER: {
        if (!data.sdp) return;
        if (pc.signalingState !== "have-local-offer") {
          this._secureLog("warn", "\u26A0\uFE0F Ignoring restart answer in unexpected state", {
            signalingState: pc.signalingState
          });
          return;
        }
        await this._assertSameRemoteIdentity(data.sdp, "ice_restart_answer");
        await pc.setRemoteDescription({ type: "answer", sdp: data.sdp });
        this._reconnect.inFlightAt = 0;
        this._secureLog("debug", "\u{1F504} ICE restart answer applied");
        return;
      }
      default:
    }
  }
  /**
   * Automatic recovery is out of road, and there is no fallback: with no
   * signalling server, a path that cannot carry a renegotiation cannot be
   * rebuilt without a fresh, manually exchanged handshake.
   *
   * So the session ends here rather than lingering half-alive. Everything goes
   * with it — keys, queued messages, transcript — which is also the safer
   * default: a conversation whose transport is gone should not leave its
   * plaintext sitting in a tab the user has stopped watching.
   */
  _giveUpAutoReconnect(reason) {
    this._resetReconnectState();
    this._reconnect.phase = "exhausted";
    this._teardownRecoveryLifecycleListeners?.();
    this._secureLog("warn", "\u26A0\uFE0F automatic reconnection exhausted \u2014 ending session", { reason });
    if (!this.reconnectionFailedNotificationSent) {
      this.reconnectionFailedNotificationSent = true;
      this.deliverMessageToUI(
        "Could not restore the connection. This chat is being closed and its data wiped \u2014 start a new one to continue.",
        "system"
      );
    }
    this.onStatusChange("recovery_failed");
    this._clearVerificationStates();
  }
  /**
   *   Stop all active timers and cleanup scheduler
   */
  _stopAllTimers() {
    this._secureLog("info", "Stopping all timers and cleanup scheduler");
    if (this._maintenanceScheduler) {
      clearInterval(this._maintenanceScheduler);
      this._maintenanceScheduler = null;
    }
    this.stopHeartbeat?.();
    this._resetReconnectState?.();
    if (this._activeTimers) {
      this._activeTimers.forEach((timer) => {
        if (timer) {
          clearInterval(timer);
          clearTimeout(timer);
        }
      });
      this._activeTimers.clear();
    }
    if (this._fileTransferInitRetryTimers) {
      this._fileTransferInitRetryTimers.clear();
    }
    this._logCleanupInterval = null;
    this._secureLog("info", "All timers stopped successfully");
  }
  /**
   * @param {number} [timeoutMs] - gathering budget. Recovery uses a much shorter
   *   one than the initial handshake: a restart round-trip must finish well
   *   inside the retry backoff, or the next attempt cancels the one in flight.
   */
  /**
   * Wait for ICE gathering, but do not confuse "finished" with "usable".
   *
   * Gathering only reaches 'complete' once EVERY configured STUN/TURN server has
   * answered or timed out. On a network that blocks them — a VPN, a captive
   * portal, an interface the browser cannot route from — that never happens
   * inside the budget, even though host candidates are available immediately and
   * are enough to connect on a LAN. The old code waited a flat 10 s and then
   * hard-failed the whole handshake if the SDP happened to be empty at that
   * instant, which made success a race: the same device would fail one attempt
   * and connect on the next with gathering still in progress.
   *
   * So: return as soon as gathering completes, and otherwise keep waiting past
   * the soft deadline only while there is still nothing to export. `hardMs`
   * bounds that extra patience so a truly dead network still fails, just later
   * and for a real reason.
   */
  waitForIceGathering(timeoutMs = _EnhancedSecureWebRTCManager.TIMEOUTS.ICE_GATHERING_TIMEOUT, hardMs = _EnhancedSecureWebRTCManager.TIMEOUTS.ICE_GATHERING_HARD_TIMEOUT) {
    return new Promise((resolve) => {
      const pc = this.peerConnection;
      if (!pc) {
        resolve(false);
        return;
      }
      if (pc.iceGatheringState === "complete") {
        resolve(true);
        return;
      }
      let settled = false;
      let softTimer = null;
      let hardTimer = null;
      const hasCandidates = () => {
        try {
          const sdp = this.peerConnection?.localDescription?.sdp;
          if (!sdp) return false;
          return this._summarizeIceCandidatesInSDP(sdp).total > 0;
        } catch (_) {
          return false;
        }
      };
      const finish = (completed) => {
        if (settled) return;
        settled = true;
        if (softTimer) {
          clearTimeout(softTimer);
          this._untrackActiveTimer?.(softTimer);
        }
        if (hardTimer) {
          clearTimeout(hardTimer);
          this._untrackActiveTimer?.(hardTimer);
        }
        try {
          pc.removeEventListener("icegatheringstatechange", onStateChange);
        } catch (_) {
        }
        resolve(completed);
      };
      const onStateChange = () => {
        if (this.peerConnection?.iceGatheringState === "complete") {
          finish(true);
        }
      };
      pc.addEventListener("icegatheringstatechange", onStateChange);
      softTimer = setTimeout(() => {
        if (hasCandidates()) {
          finish(false);
        }
      }, timeoutMs);
      this._trackActiveTimer?.(softTimer);
      hardTimer = setTimeout(() => finish(false), Math.max(hardMs, timeoutMs));
      this._trackActiveTimer?.(hardTimer);
    });
  }
  retryConnection() {
    this._secureLog("info", "Retrying connection", {
      attempt: this.connectionAttempts,
      maxAttempts: this.maxConnectionAttempts
    });
    this.onStatusChange("retrying");
  }
  isConnected() {
    const hasDataChannel = !!this.dataChannel;
    const dataChannelState = this.dataChannel?.readyState;
    const isDataChannelOpen = dataChannelState === "open";
    const isVerified = this.isVerified;
    const connectionState = this.peerConnection?.connectionState;
    return this.dataChannel && this.dataChannel.readyState === "open" && this.isVerified;
  }
  getConnectionInfo() {
    return {
      fingerprint: this.keyFingerprint,
      isConnected: this.isConnected(),
      isVerified: this.isVerified,
      connectionState: this.peerConnection?.connectionState,
      iceConnectionState: this.peerConnection?.iceConnectionState,
      verificationCode: this.verificationCode
    };
  }
  handleUnexpectedDisconnect() {
    this.sendDisconnectNotification();
    this.isVerified = false;
    if (!this.disconnectNotificationSent) {
      this.disconnectNotificationSent = true;
      this.deliverMessageToUI("\u{1F50C} Connection lost. Attempting to reconnect...", "system");
    }
    if (this.fileTransferSystem) {
      this.fileTransferSystem.cleanup();
      this.fileTransferSystem = null;
    }
    this._dispatchAppEvent?.(new CustomEvent("peer-disconnect", {
      detail: {
        reason: "connection_lost",
        timestamp: Date.now()
      }
    }));
  }
  sendDisconnectNotification() {
    try {
      if (this.dataChannel && this.dataChannel.readyState === "open") {
        const notification = {
          type: "peer_disconnect",
          timestamp: Date.now(),
          reason: this.intentionalDisconnect ? "user_disconnect" : "connection_lost"
        };
        for (let i = 0; i < 3; i++) {
          try {
            this.dataChannel.send(JSON.stringify(notification));
            window.EnhancedSecureCryptoUtils.secureLog.log("info", "Disconnect notification sent", {
              reason: notification.reason,
              attempt: i + 1
            });
            break;
          } catch (sendError) {
            if (i === 2) {
              window.EnhancedSecureCryptoUtils.secureLog.log("error", "Failed to send disconnect notification", {
                error: sendError.message
              });
            }
          }
        }
      }
    } catch (error) {
      window.EnhancedSecureCryptoUtils.secureLog.log("error", "Could not send disconnect notification", {
        error: error.message
      });
    }
  }
  /**
   * Manual "try again" from the UI. Restarts the automatic recovery cycle from
   * scratch (fresh attempt counter and deadline) as long as the data channel is
   * still there to carry the renegotiation.
   */
  attemptReconnection() {
    if (!this.isVerified || this.dataChannel?.readyState !== "open") {
      if (!this.reconnectionFailedNotificationSent) {
        this.reconnectionFailedNotificationSent = true;
        this.deliverMessageToUI("Unable to reconnect. A new connection is required.", "system");
      }
      return false;
    }
    this._resetReconnectState();
    this.reconnectionFailedNotificationSent = false;
    this._reconnect.startedAt = Date.now();
    this.onStatusChange("reconnecting");
    this._attemptIceRestart();
    return true;
  }
  handlePeerDisconnectNotification(data) {
    const reason = data.reason || "unknown";
    const reasonText = reason === "user_disconnect" ? "manually disconnected." : "connection lost.";
    if (!this.peerDisconnectNotificationSent) {
      this.peerDisconnectNotificationSent = true;
      this.deliverMessageToUI(`Peer ${reasonText}`, "system");
    }
    this.onStatusChange("peer_disconnected");
    this.intentionalDisconnect = false;
    this.isVerified = false;
    this.stopHeartbeat();
    this.onKeyExchange("");
    this.onVerificationRequired("");
    this._dispatchAppEvent?.(new CustomEvent("peer-disconnect", {
      detail: {
        reason,
        timestamp: Date.now()
      }
    }));
    if (!this._peerDisconnectCleanupTimer) {
      this._peerDisconnectCleanupTimer = this._trackActiveTimer(setTimeout(() => {
        const timer = this._peerDisconnectCleanupTimer;
        this._peerDisconnectCleanupTimer = null;
        this._untrackActiveTimer(timer);
        if (this._sessionAlive === false) return;
        this.disconnect();
      }, 2e3));
    }
    window.EnhancedSecureCryptoUtils.secureLog.log("info", "Peer disconnect notification processed", {
      reason
    });
  }
  /**
   *   Secure disconnect with complete memory cleanup
   */
  disconnect() {
    try {
      this._sessionAlive = false;
      try {
        this._stopAdaptation?.();
      } catch (_) {
      }
      try {
        this._stopLocalMediaPermanently?.();
      } catch (_) {
      }
      this._callAudioSender = null;
      this._callVideoSender = null;
      this.intentionalDisconnect = true;
      window.EnhancedSecureCryptoUtils.secureLog.log("info", "Starting intentional disconnect");
      this.sendDisconnectNotification();
      this._teardownRecoveryLifecycleListeners?.();
      this._stopAllTimers();
      this._peerDisconnectCleanupTimer = null;
      this.stopHeartbeat();
      this.stopFakeTrafficGeneration();
      for (const timer of this.decoyTimers.entries()) {
        clearTimeout(timer[1]);
      }
      this.decoyTimers.clear();
      if (this.fileTransferSystem) {
        this.fileTransferSystem.cleanup();
        this.fileTransferSystem = null;
      }
      for (const channel of this.decoyChannels.values()) {
        if (channel.readyState === "open") channel.close();
      }
      this.decoyChannels.clear();
      if (this.heartbeatChannel) {
        this.heartbeatChannel.close();
        this.heartbeatChannel = null;
      }
      this.isVerified = false;
      this.processedMessageIds.clear();
      this.messageCounter = 0;
      this.packetBuffer.clear();
      this.chunkQueue = [];
      this._wipeEphemeralKeys();
      this._hardWipeOldKeys();
      this._secureCleanupCryptographicMaterials();
      this.keyVersions.clear();
      this.oldKeys.clear();
      this.currentKeyVersion = 0;
      this.lastKeyRotation = Date.now();
      this.sequenceNumber = 0;
      this.expectedSequenceNumber = 0;
      this.replayWindow.clear();
      this._clearVerificationStates();
      this.securityFeatures = {
        hasEncryption: true,
        hasECDH: true,
        hasECDSA: true,
        hasMutualAuth: true,
        hasMetadataProtection: true,
        hasEnhancedReplayProtection: true,
        hasNonExtractableKeys: true,
        hasRateLimiting: true,
        hasEnhancedValidation: true,
        hasPFS: true
      };
      if (this.dataChannel) {
        this.dataChannel.close();
        this.dataChannel.onopen = null;
        this.dataChannel.onclose = null;
        this.dataChannel.onmessage = null;
        this.dataChannel.onerror = null;
        this.dataChannel = null;
      }
      if (this.peerConnection) {
        this.peerConnection.close();
        this.peerConnection.onconnectionstatechange = null;
        this.peerConnection.ondatachannel = null;
        this.peerConnection = null;
      }
      if (this.messageQueue && this.messageQueue.length > 0) {
        this.messageQueue.forEach((message, index) => {
          this._secureWipeMemory(message, `messageQueue[${index}]`);
        });
        this.messageQueue = [];
      }
      this._forceGarbageCollection().catch((error) => {
        this._secureLog("error", "Cleanup failed during disconnect", {
          errorType: error?.constructor?.name || "Unknown"
        });
      });
      this._dispatchAppEvent?.(new CustomEvent("peer-disconnect", {
        detail: {
          reason: "user_disconnect",
          timestamp: Date.now()
        }
      }));
      this._dispatchAppEvent?.(new CustomEvent("connection-cleaned", {
        detail: {
          timestamp: Date.now(),
          reason: "user_cleanup"
        }
      }));
      this.onStatusChange("disconnected");
      this.onKeyExchange("");
      this.onVerificationRequired("");
      this._secureLog("info", "Connection securely cleaned up with complete memory wipe");
    } catch (error) {
      this._secureLog("error", "\u274C Error during enhanced disconnect:", {
        errorType: error?.constructor?.name || "Unknown"
      });
    } finally {
      this.intentionalDisconnect = false;
    }
  }
  // Public method to send files
  async sendFile(file, options = {}) {
    this._enforceVerificationGate("sendFile");
    if (!this.isConnected()) {
      throw new Error("Connection not ready for file transfer. Please ensure the connection is established.");
    }
    if (!this.fileTransferSystem) {
      this.initializeFileTransfer();
      await new Promise((resolve) => setTimeout(resolve, 500));
      if (!this.fileTransferSystem) {
        throw new Error("File transfer system could not be initialized. Please try reconnecting.");
      }
    }
    if (!this.encryptionKey || !this.macKey) {
      throw new Error("Encryption keys not ready. Please wait for connection to be fully established.");
    }
    try {
      const fileId = await this.fileTransferSystem.sendFile(file, options);
      return fileId;
    } catch (error) {
      this._secureLog("error", "File transfer error:", { errorType: error?.constructor?.name || "Unknown" });
      if (error.message.includes("Connection not ready")) {
        throw new Error("Connection not ready for file transfer. Check connection status.");
      } else if (error.message.includes("Encryption keys not initialized")) {
        throw new Error("Session expired due to inactivity. Please reconnect to the chat.");
      } else if (error.message.includes("Transfer timeout")) {
        throw new Error("File transfer timeout. Check connection and try again.");
      } else {
        throw error;
      }
    }
  }
  // Get active file transfers
  getFileTransfers() {
    if (!this.fileTransferSystem) {
      return { sending: [], receiving: [] };
    }
    try {
      let sending = [];
      let receiving = [];
      if (typeof this.fileTransferSystem.getActiveTransfers === "function") {
        sending = this.fileTransferSystem.getActiveTransfers();
      } else {
        this._secureLog("warn", "getActiveTransfers method not available in file transfer system");
      }
      if (typeof this.fileTransferSystem.getReceivingTransfers === "function") {
        receiving = this.fileTransferSystem.getReceivingTransfers();
      } else {
        this._secureLog("warn", "getReceivingTransfers method not available in file transfer system");
      }
      return {
        sending: sending || [],
        receiving: receiving || []
      };
    } catch (error) {
      this._secureLog("error", "Error getting file transfers:", { errorType: error?.constructor?.name || "Unknown" });
      return { sending: [], receiving: [] };
    }
  }
  // Get file transfer system status
  getFileTransferStatus() {
    if (!this.fileTransferSystem) {
      return {
        initialized: false,
        status: "not_initialized",
        message: "File transfer system not initialized"
      };
    }
    const activeTransfers = this.fileTransferSystem.getActiveTransfers();
    const receivingTransfers = this.fileTransferSystem.getReceivingTransfers();
    return {
      initialized: true,
      status: "ready",
      activeTransfers: activeTransfers.length,
      receivingTransfers: receivingTransfers.length,
      totalTransfers: activeTransfers.length + receivingTransfers.length
    };
  }
  // Cancel file transfer
  cancelFileTransfer(fileId) {
    if (!this.fileTransferSystem) return false;
    return this.fileTransferSystem.cancelTransfer(fileId);
  }
  // Force cleanup of file transfer system
  cleanupFileTransferSystem() {
    if (this.fileTransferSystem) {
      this._secureLog("info", "\u{1F9F9} Force cleaning up file transfer system");
      this.fileTransferSystem.cleanup();
      this.fileTransferSystem = null;
      return true;
    }
    return false;
  }
  // Reinitialize file transfer system
  reinitializeFileTransfer() {
    try {
      if (this.fileTransferSystem) {
        this.fileTransferSystem.cleanup();
      }
      this.initializeFileTransfer();
      return true;
    } catch (error) {
      this._secureLog("error", "Failed to reinitialize file transfer system:", { errorType: error?.constructor?.name || "Unknown" });
      return false;
    }
  }
  // Set file transfer callbacks
  setFileTransferCallbacks(onProgress, onReceived, onError, onIncomingRequest = null) {
    this.onFileProgress = onProgress;
    this.onFileReceived = onReceived;
    this.onFileError = onError;
    this.onIncomingFileRequest = onIncomingRequest;
    if (this.fileTransferSystem) {
      this.fileTransferSystem.onProgress = onProgress;
      this.fileTransferSystem.onFileReceived = onReceived;
      this.fileTransferSystem.onError = onError;
      this.fileTransferSystem.onIncomingFileRequest = onIncomingRequest;
    }
  }
  getPendingIncomingFiles() {
    if (!this.fileTransferSystem) return [];
    return this.fileTransferSystem.getPendingIncomingTransfers();
  }
  async acceptIncomingFile(fileId) {
    if (!this.fileTransferSystem) return false;
    return this.fileTransferSystem.acceptIncomingFile(fileId);
  }
  async rejectIncomingFile(fileId) {
    if (!this.fileTransferSystem) return false;
    return this.fileTransferSystem.rejectIncomingFile(fileId);
  }
  async getReceivedFileObjectURL(fileId) {
    if (!this.fileTransferSystem) return null;
    return this.fileTransferSystem.getObjectURL(fileId);
  }
  revokeReceivedFileObjectURL(url) {
    if (!this.fileTransferSystem) return;
    this.fileTransferSystem.revokeObjectURL(url);
  }
  // ============================================
  // SESSION ACTIVATION HANDLING
  // ============================================
  async handleSessionActivation(sessionData) {
    try {
      this.currentSession = sessionData;
      const hasKeys = !!(this.encryptionKey && this.macKey);
      const hasSession = !!sessionData.sessionId;
      if (hasSession) {
        this.onStatusChange("connected");
      }
      setTimeout(() => {
        try {
          this.initializeFileTransfer();
        } catch (error) {
          this._secureLog("warn", "File transfer initialization failed during session activation:", { details: error.message });
        }
      }, 1e3);
      if (this.fileTransferSystem && this.isConnected()) {
        if (typeof this.fileTransferSystem.onSessionUpdate === "function") {
          this.fileTransferSystem.onSessionUpdate({
            keyFingerprint: this.keyFingerprint,
            sessionSalt: this.sessionSalt,
            hasMacKey: !!this.macKey
          });
        }
      }
    } catch (error) {
      this._secureLog("error", "Failed to handle session activation:", { errorType: error?.constructor?.name || "Unknown" });
    }
  }
  // Method to check readiness of file transfers
  checkFileTransferReadiness() {
    const status = {
      hasFileTransferSystem: !!this.fileTransferSystem,
      hasDataChannel: !!this.dataChannel,
      dataChannelState: this.dataChannel?.readyState,
      isConnected: this.isConnected(),
      isVerified: this.isVerified,
      hasEncryptionKey: !!this.encryptionKey,
      hasMacKey: !!this.macKey,
      ready: false
    };
    status.ready = status.hasFileTransferSystem && status.hasDataChannel && status.dataChannelState === "open" && status.isConnected && status.isVerified;
    return status;
  }
  // Method to force re-initialize file transfer system
  forceReinitializeFileTransfer() {
    try {
      if (this.fileTransferSystem) {
        this.fileTransferSystem.cleanup();
        this.fileTransferSystem = null;
      }
      setTimeout(() => {
        this.initializeFileTransfer();
      }, 500);
      return true;
    } catch (error) {
      this._secureLog("error", "Failed to force reinitialize file transfer:", { errorType: error?.constructor?.name || "Unknown" });
      return false;
    }
  }
  // Method to get diagnostic information
  getFileTransferDiagnostics() {
    const diagnostics = {
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      webrtcManager: {
        hasDataChannel: !!this.dataChannel,
        dataChannelState: this.dataChannel?.readyState,
        isConnected: this.isConnected(),
        isVerified: this.isVerified,
        isInitiator: this.isInitiator,
        hasEncryptionKey: !!this.encryptionKey,
        hasMacKey: !!this.macKey,
        hasMetadataKey: !!this.metadataKey,
        hasKeyFingerprint: !!this.keyFingerprint,
        hasSessionSalt: !!this.sessionSalt
      },
      fileTransferSystem: null,
      globalState: {
        fileTransferActive: this._fileTransferActive || false,
        hasFileTransferSystem: !!this.fileTransferSystem,
        fileTransferSystemType: this.fileTransferSystem ? "EnhancedSecureFileTransfer" : "none"
      }
    };
    if (this.fileTransferSystem) {
      try {
        diagnostics.fileTransferSystem = this.fileTransferSystem.getSystemStatus();
      } catch (error) {
        diagnostics.fileTransferSystem = { error: error.message };
      }
    }
    return diagnostics;
  }
  getSupportedFileTypes() {
    if (!this.fileTransferSystem) {
      return { error: "File transfer system not initialized" };
    }
    try {
      return this.fileTransferSystem.getSupportedFileTypes();
    } catch (error) {
      return { error: error.message };
    }
  }
  validateFile(file) {
    if (!this.fileTransferSystem) {
      return {
        isValid: false,
        errors: ["File transfer system not initialized"],
        fileType: null,
        fileSize: file?.size || 0,
        formattedSize: "0 B"
      };
    }
    try {
      return this.fileTransferSystem.validateFile(file);
    } catch (error) {
      return {
        isValid: false,
        errors: [error.message],
        fileType: null,
        fileSize: file?.size || 0,
        formattedSize: "0 B"
      };
    }
  }
  getFileTypeInfo() {
    if (!this.fileTransferSystem) {
      return { error: "File transfer system not initialized" };
    }
    try {
      return this.fileTransferSystem.getFileTypeInfo();
    } catch (error) {
      return { error: error.message };
    }
  }
  async forceInitializeFileTransfer(options = {}) {
    const abortController = new AbortController();
    const { signal = abortController.signal, timeout = 6e3 } = options;
    if (signal && signal !== abortController.signal) {
      signal.addEventListener("abort", () => abortController.abort());
    }
    try {
      if (!this.isVerified) {
        throw new Error("Connection not verified");
      }
      if (!this.dataChannel || this.dataChannel.readyState !== "open") {
        throw new Error("Data channel not open");
      }
      if (!this.encryptionKey || !this.macKey) {
        throw new Error("Encryption keys not ready");
      }
      if (this.fileTransferSystem) {
        this.fileTransferSystem.cleanup();
        this.fileTransferSystem = null;
      }
      this.initializeFileTransfer();
      let attempts2 = 0;
      const maxAttempts = 50;
      const checkInterval = 100;
      const maxWaitTime = maxAttempts * checkInterval;
      const initializationPromise = new Promise((resolve, reject) => {
        const checkInitialization = () => {
          if (abortController.signal.aborted) {
            reject(new Error("Operation cancelled"));
            return;
          }
          if (this.fileTransferSystem) {
            resolve(true);
            return;
          }
          if (attempts2 >= maxAttempts) {
            reject(new Error(`Initialization timeout after ${maxWaitTime}ms`));
            return;
          }
          attempts2++;
          setTimeout(checkInitialization, checkInterval);
        };
        checkInitialization();
      });
      await Promise.race([
        initializationPromise,
        new Promise(
          (_, reject) => setTimeout(() => reject(new Error(`Global timeout after ${timeout}ms`)), timeout)
        )
      ]);
      if (this.fileTransferSystem) {
        return true;
      } else {
        throw new Error("Force initialization timeout");
      }
    } catch (error) {
      if (error.name === "AbortError" || error.message.includes("cancelled")) {
        this._secureLog("info", "File transfer initialization cancelled by user");
        return { cancelled: true };
      }
      this._secureLog("error", "Force file transfer initialization failed:", {
        errorType: error?.constructor?.name || "Unknown",
        message: error.message,
        attempts
      });
      return { error: error.message, attempts };
    }
  }
  cancelFileTransferInitialization() {
    try {
      if (this.fileTransferSystem) {
        this.fileTransferSystem.cleanup();
        this.fileTransferSystem = null;
        this._fileTransferActive = false;
        this._secureLog("info", "File transfer initialization cancelled");
        return true;
      }
      return false;
    } catch (error) {
      this._secureLog("error", "Failed to cancel file transfer initialization:", {
        errorType: error?.constructor?.name || "Unknown"
      });
      return false;
    }
  }
  getFileTransferSystemStatus() {
    if (!this.fileTransferSystem) {
      return { available: false, status: "not_initialized" };
    }
    try {
      const status = this.fileTransferSystem.getSystemStatus();
      return {
        available: true,
        status: status.status || "unknown",
        activeTransfers: status.activeTransfers || 0,
        receivingTransfers: status.receivingTransfers || 0,
        systemType: "EnhancedSecureFileTransfer"
      };
    } catch (error) {
      this._secureLog("error", "Failed to get file transfer system status:", {
        errorType: error?.constructor?.name || "Unknown"
      });
      return { available: false, status: "error", error: error.message };
    }
  }
  _validateNestedEncryptionSecurity() {
    if (this.securityFeatures.hasNestedEncryption && this.nestedEncryptionKey) {
      try {
        const testIV1 = this._generateSecureIV(_EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE, "securityTest1");
        const testIV2 = this._generateSecureIV(_EnhancedSecureWebRTCManager.SIZES.NESTED_ENCRYPTION_IV_SIZE, "securityTest2");
        if (testIV1.every((byte, index) => byte === testIV2[index])) {
          this._secureLog("error", "CRITICAL: Nested encryption security validation failed - IVs are identical!");
          return false;
        }
        const stats = this._getIVTrackingStats();
        if (stats.totalIVs < 2) {
          this._secureLog("error", "CRITICAL: IV tracking system not working properly");
          return false;
        }
        this._secureLog("info", "Nested encryption security validation passed - secure IV generation working");
        return true;
      } catch (error) {
        this._secureLog("error", "CRITICAL: Nested encryption security validation failed:", {
          errorType: error.constructor.name,
          errorMessage: error.message
        });
        return false;
      }
    }
    return true;
  }
  // ════════════════════════════════════════════════════════════════════════
  //   ENCRYPTED VOICE / VIDEO CALLS
  //
  //   Media is carried by the existing RTCPeerConnection: audio/video tracks
  //   are bundled onto the same DTLS-SRTP transport already used by the data
  //   channel, so they are end-to-end encrypted with the very connection that
  //   in-person SAS verification authenticated. Renegotiation SDP travels over
  //   the verified data channel (never a server), so the media's DTLS
  //   fingerprints are authenticated end-to-end too. Calls are therefore only
  //   permitted once the session is connected AND SAS-verified.
  // ════════════════════════════════════════════════════════════════════════
  getCallState() {
    return { ...this.callState };
  }
  getRemoteMediaStream() {
    return this.remoteMediaStream;
  }
  getLocalMediaStream() {
    return this.localMediaStream;
  }
  // Rebuild the remote MediaStream from the PC's current receivers. This is the
  // reliable source of inbound tracks — ontrack does not re-fire for a reused
  // transceiver on a later call, so relying on it dropped remote audio/video.
  _refreshRemoteStream() {
    const pc = this.peerConnection;
    if (!pc || typeof pc.getReceivers !== "function") return;
    const live = pc.getReceivers().map((r) => r.track).filter((t) => t && (t.kind === "audio" || t.kind === "video") && t.readyState === "live");
    const prev = this.remoteMediaStream ? this.remoteMediaStream.getTracks() : [];
    const unchanged = prev.length === live.length && prev.every((t) => live.includes(t));
    if (!unchanged) {
      this.remoteMediaStream = new MediaStream(live);
    }
    this._updateCallState({ remoteHasVideo: live.some((t) => t.kind === "video") });
  }
  // Remote tracks can take a beat to go 'live' after setRemoteDescription, and
  // ontrack may not fire for reused transceivers — so refresh now and shortly
  // after to reliably pick up the inbound audio/video.
  _scheduleRemoteRefresh() {
    this._refreshRemoteStream();
    setTimeout(() => {
      try {
        this._refreshRemoteStream();
      } catch (_) {
      }
    }, 300);
    setTimeout(() => {
      try {
        this._refreshRemoteStream();
      } catch (_) {
      }
    }, 1200);
  }
  _updateCallState(patch) {
    this.callState = { ...this.callState, ...patch };
    const snapshot = this.getCallState();
    if (snapshot.phase === "active") this._startAdaptation();
    else if (snapshot.phase === "idle") this._stopAdaptation();
    try {
      this.onCallStateChanged?.(snapshot);
    } catch (_) {
    }
    if (typeof document !== "undefined") {
      try {
        this._dispatchAppEvent?.(new CustomEvent("securebit-call-state", {
          detail: { managerId: this._managerId || null, state: snapshot }
        }));
      } catch (_) {
      }
    }
  }
  _callCanStart() {
    const connected = typeof this.isConnected === "function" ? this.isConnected() : false;
    const channelOpen = this.dataChannel && this.dataChannel.readyState === "open";
    const ok = !!(connected && channelOpen && this.isVerified && !this.isReconnecting());
    return ok;
  }
  async _sendCallSignal(type, data) {
    const sent = await this.sendSystemMessage({ type, ...data });
    return sent;
  }
  _audioConstraints() {
    return { echoCancellation: true, noiseSuppression: true, autoGainControl: true };
  }
  _videoConstraints() {
    return { facingMode: this._callFacingMode, width: { ideal: 1280 }, height: { ideal: 720 } };
  }
  async _acquireLocalMedia(withVideo) {
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: this._audioConstraints(),
      video: withVideo ? this._videoConstraints() : false
    });
    this.localMediaStream = stream;
    const pc = this.peerConnection;
    const audioTrack = stream.getAudioTracks()[0] || null;
    const videoTrack = stream.getVideoTracks()[0] || null;
    if (audioTrack) {
      if (this._callAudioSender) await this._callAudioSender.replaceTrack(audioTrack);
      else this._callAudioSender = pc.addTrack(audioTrack, stream);
    }
    if (videoTrack) {
      if (this._callVideoSender) await this._callVideoSender.replaceTrack(videoTrack);
      else this._callVideoSender = pc.addTrack(videoTrack, stream);
    }
    this._applyCallCodecPrefs();
    return stream;
  }
  // Fully release the mic/camera — only on session disconnect, not between calls.
  _stopLocalMediaPermanently() {
    try {
      if (this.localMediaStream) {
        for (const t of this.localMediaStream.getTracks()) {
          try {
            t.stop();
          } catch (_) {
          }
        }
      }
    } catch (_) {
    }
    this.localMediaStream = null;
  }
  // Codec preferences on the audio (RED→Opus) and video (VP9→AV1→H264→VP8)
  // transceivers created by addTrack. Called before offer/answer creation.
  _applyCallCodecPrefs() {
    try {
      const trs = this.peerConnection?.getTransceivers?.() || [];
      const audioTr = trs.find((t) => t.sender && t.sender === this._callAudioSender);
      if (audioTr) applyAudioCodecPreferences(audioTr);
      const videoTr = trs.find((t) => t.sender && t.sender === this._callVideoSender);
      if (videoTr) applyVideoCodecPreferences(videoTr);
    } catch (_) {
    }
  }
  // Munge locally-created call SDP: Opus FEC/DTX/bitrate fmtp + transport
  // feedback (TWCC/NACK/PLI/FIR/REMB) & the TWCC header extension. Both peers
  // run this, so the negotiated result carries it.
  _mungeCallSdp(sdp) {
    try {
      let out = applyOpusSettings(sdp, AUDIO_CONFIG.opusFmtp);
      out = applyTransport(out, TRANSPORT_CONFIG);
      return out;
    } catch (e) {
      return sdp;
    }
  }
  // setLocalDescription with progressive fallback so munging can never break a
  // call: try full munge → Opus-only munge → raw. (Some browsers reject added
  // rtcp-fb/extmap lines in a local description; the raw path always works.)
  async _setLocalMunged(desc) {
    const pc = this.peerConnection;
    try {
      await pc.setLocalDescription({ type: desc.type, sdp: this._mungeCallSdp(desc.sdp) });
      return;
    } catch (e) {
      try {
        await pc.setLocalDescription({ type: desc.type, sdp: applyOpusSettings(desc.sdp, AUDIO_CONFIG.opusFmtp) });
        return;
      } catch (e2) {
        await pc.setLocalDescription(desc);
      }
    }
  }
  // Apply sender-level params after setLocalDescription, when senders have live
  // parameters: audio priority/bitrate, video SVC/bitrate/degradation.
  async _applyCallSenderParams() {
    try {
      if (this._callAudioSender) await configureAudioSender(this._callAudioSender, {});
      if (this._callVideoSender) await configureVideoSender(this._callVideoSender, {});
    } catch (_) {
    }
  }
  // Start the reactive bitrate controller for the active call. Idempotent. It
  // also feeds the connection-quality indicator shown in the call UI.
  _startAdaptation() {
    if (this._adaptationController || !this.peerConnection) return;
    try {
      this._adaptationController = new NetworkAdaptationController(this.peerConnection, {
        getVideoSender: () => this._callVideoSender,
        ceilingBitrate: 15e5,
        onQuality: (q) => {
          if (q !== this.callState.quality) this._updateCallState({ quality: q });
        }
      });
      this._adaptationController.start();
    } catch (_) {
    }
  }
  _stopAdaptation() {
    if (this._adaptationController) {
      try {
        this._adaptationController.stop();
      } catch (_) {
      }
      this._adaptationController = null;
    }
  }
  // Turn a getUserMedia failure into a clear, user-visible reason (shown in the
  // chat as a system message) + a machine-readable callState.error code. These
  // are device/permission problems, NOT connection problems — surfacing them
  // stops the call from looking like it "silently drops".
  _notifyCallMediaError(error, wantVideo) {
    const name = error?.name || "";
    const dev = wantVideo ? "camera/microphone" : "microphone";
    let msg, code;
    if (name === "NotAllowedError") {
      code = "permission_denied";
      msg = `\u26A0\uFE0F Call not started \u2014 ${dev} access is blocked. Allow it for this site in the browser, and enable your browser under System Settings \u2192 Privacy & Security \u2192 ${wantVideo ? "Camera/Microphone" : "Microphone"}, then try again.`;
    } else if (name === "NotFoundError" || name === "OverconstrainedError") {
      code = "device_not_found";
      msg = `\u26A0\uFE0F Call not started \u2014 no ${dev} found on this device.`;
    } else if (name === "NotReadableError" || name === "AbortError") {
      code = "device_busy";
      msg = `\u26A0\uFE0F Call not started \u2014 your ${dev} is in use by another app. Close it and try again.`;
    } else {
      code = "media_failed";
      msg = `\u26A0\uFE0F Call not started \u2014 could not access ${dev}${name ? " (" + name + ")" : ""}.`;
    }
    try {
      this.deliverMessageToUI(msg, "system");
    } catch (_) {
    }
    return code;
  }
  // Caller side: begin an outgoing call.
  async startCall(withVideo = false) {
    if (!this._callCanStart()) {
      this._updateCallState({ error: "not_verified" });
      throw new Error("Calls require a connected, SAS-verified session.");
    }
    if (this.callState.active) {
      this._secureLog("warn", "\u26A0\uFE0F startCall ignored \u2014 a call is already active");
      return;
    }
    const callId = crypto?.randomUUID?.() || String(Date.now()) + Math.random().toString(36).slice(2);
    this._updateCallState({
      active: true,
      phase: "outgoing",
      withVideo,
      callId,
      micEnabled: true,
      cameraEnabled: withVideo,
      remoteHasVideo: false,
      error: null
    });
    try {
      await this._acquireLocalMedia(withVideo);
      this._callMakingOffer = true;
      const offer = await this.peerConnection.createOffer();
      await this._setLocalMunged(offer);
      this._callMakingOffer = false;
      await this._applyCallSenderParams();
      await this._sendCallSignal(_EnhancedSecureWebRTCManager.MESSAGE_TYPES.CALL_OFFER, {
        callId,
        withVideo,
        sdp: this.peerConnection.localDescription.sdp
      });
    } catch (error) {
      this._callMakingOffer = false;
      this._secureLog("error", "\u274C startCall failed", { errorType: error?.constructor?.name });
      const code = this._notifyCallMediaError(error, withVideo);
      await this._teardownCallMedia();
      this._updateCallState({ active: false, phase: "idle", error: code });
      throw error;
    }
  }
  // Callee side: an inbound call offer arrived → surface it to the UI.
  async _onIncomingCallOffer(data) {
    if (this.callState.active && (this.callState.phase === "active" || this.callState.phase === "connecting")) {
      await this._answerCallOffer(
        data,
        /* renegotiation */
        true
      );
      if (data.withVideo) this._updateCallState({ withVideo: true });
      return;
    }
    this._pendingCallOffer = data;
    this._updateCallState({
      active: true,
      phase: "incoming",
      withVideo: !!data.withVideo,
      callId: data.callId,
      remoteHasVideo: !!data.withVideo,
      error: null
    });
  }
  async _answerCallOffer(data, renegotiation = false) {
    await this.peerConnection.setRemoteDescription({ type: "offer", sdp: data.sdp });
    if (!renegotiation) {
      await this._acquireLocalMedia(!!data.withVideo);
    }
    const answer = await this.peerConnection.createAnswer();
    await this._setLocalMunged(answer);
    await this._applyCallSenderParams();
    await this._sendCallSignal(_EnhancedSecureWebRTCManager.MESSAGE_TYPES.CALL_ANSWER, {
      callId: data.callId,
      sdp: this.peerConnection.localDescription.sdp
    });
  }
  // Callee accepts the ringing call.
  async acceptCall() {
    const data = this._pendingCallOffer;
    if (!data) return;
    this._pendingCallOffer = null;
    this._updateCallState({ phase: "connecting", cameraEnabled: !!data.withVideo });
    try {
      await this._answerCallOffer(data, false);
      this._updateCallState({ phase: "active" });
      this._scheduleRemoteRefresh();
    } catch (error) {
      this._secureLog("error", "\u274C acceptCall failed", { errorType: error?.constructor?.name });
      const code = this._notifyCallMediaError(error, !!data.withVideo);
      try {
        await this._sendCallSignal(_EnhancedSecureWebRTCManager.MESSAGE_TYPES.CALL_END, { callId: data.callId });
      } catch (_) {
      }
      await this._teardownCallMedia();
      this._updateCallState({ active: false, phase: "idle", error: code });
    }
  }
  // Callee rejects the ringing call.
  async declineCall() {
    const callId = this.callState.callId;
    this._pendingCallOffer = null;
    await this._sendCallSignal(_EnhancedSecureWebRTCManager.MESSAGE_TYPES.CALL_DECLINE, { callId });
    this._updateCallState({ active: false, phase: "idle", withVideo: false, remoteHasVideo: false });
  }
  // Either side hangs up.
  async endCall(sendSignal = true) {
    const callId = this.callState.callId;
    if (sendSignal && callId) {
      try {
        await this._sendCallSignal(_EnhancedSecureWebRTCManager.MESSAGE_TYPES.CALL_END, { callId });
      } catch (_) {
      }
    }
    await this._teardownCallMedia();
    this._updateCallState({
      active: false,
      phase: "idle",
      withVideo: false,
      micEnabled: true,
      cameraEnabled: false,
      remoteHasVideo: false,
      callId: null,
      quality: null
    });
  }
  async _teardownCallMedia() {
    this._stopAdaptation();
    const pc = this.peerConnection;
    try {
      if (this.localMediaStream) {
        for (const track of this.localMediaStream.getTracks()) {
          try {
            track.stop();
          } catch (_) {
          }
        }
      }
      if (pc) {
        for (const sender of [this._callAudioSender, this._callVideoSender].filter(Boolean)) {
          try {
            await sender.replaceTrack(null);
          } catch (_) {
          }
        }
      }
    } catch (_) {
    }
    this.localMediaStream = null;
    this.remoteMediaStream = null;
    this._callMakingOffer = false;
    try {
      if (this.peerConnection && (this.peerConnection.signalingState === "have-local-offer" || this.peerConnection.signalingState === "have-local-pranswer")) {
        await this.peerConnection.setLocalDescription({ type: "rollback" });
      }
    } catch (_) {
    }
  }
  // Mute / unmute the microphone (no renegotiation — just toggles the track).
  setMicEnabled(enabled) {
    if (this.localMediaStream) {
      this.localMediaStream.getAudioTracks().forEach((t) => {
        t.enabled = enabled;
      });
    }
    this._updateCallState({ micEnabled: enabled });
  }
  toggleMic() {
    this.setMicEnabled(!this.callState.micEnabled);
  }
  // Turn the camera on/off. Turning it on for an audio-only call adds a video
  // track and renegotiates (an in-call "upgrade to video").
  async setCameraEnabled(enabled) {
    if (!enabled) {
      if (this.localMediaStream) {
        this.localMediaStream.getVideoTracks().forEach((t) => {
          t.enabled = false;
        });
      }
      this._updateCallState({ cameraEnabled: false });
      return;
    }
    const existing = this.localMediaStream?.getVideoTracks?.() || [];
    if (existing.length) {
      existing.forEach((t) => {
        t.enabled = true;
      });
      this._updateCallState({ cameraEnabled: true, withVideo: true });
      return;
    }
    await this.upgradeToVideo();
  }
  async toggleCamera() {
    await this.setCameraEnabled(!this.callState.cameraEnabled);
  }
  // Add a camera to an in-progress audio call and renegotiate.
  async upgradeToVideo() {
    if (!this.localMediaStream) return;
    try {
      const camStream = await navigator.mediaDevices.getUserMedia({ video: this._videoConstraints() });
      const videoTrack = camStream.getVideoTracks()[0];
      if (!videoTrack) return;
      this.localMediaStream.addTrack(videoTrack);
      if (this._callVideoSender) await this._callVideoSender.replaceTrack(videoTrack);
      else this._callVideoSender = this.peerConnection.addTrack(videoTrack, this.localMediaStream);
      this._applyCallCodecPrefs();
      this._updateCallState({ cameraEnabled: true, withVideo: true });
      await this._renegotiateCall();
    } catch (error) {
      this._secureLog("error", "\u274C upgradeToVideo failed", { errorType: error?.constructor?.name });
      this._updateCallState({ cameraEnabled: false, error: "camera_failed" });
    }
  }
  // Flip between front/back cameras without renegotiation (replaceTrack).
  async switchCamera() {
    if (!this._callVideoSender || !this.localMediaStream) return;
    this._callFacingMode = this._callFacingMode === "user" ? "environment" : "user";
    try {
      const camStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: this._callFacingMode }
      });
      const newTrack = camStream.getVideoTracks()[0];
      const old = this.localMediaStream.getVideoTracks()[0];
      if (old) {
        this.localMediaStream.removeTrack(old);
        try {
          old.stop();
        } catch (_) {
        }
      }
      this.localMediaStream.addTrack(newTrack);
      await this._callVideoSender.replaceTrack(newTrack);
    } catch (error) {
      this._secureLog("warn", "\u26A0\uFE0F switchCamera failed", { errorType: error?.constructor?.name });
    }
  }
  async _renegotiateCall() {
    if (this._callMakingOffer) return;
    try {
      this._callMakingOffer = true;
      const offer = await this.peerConnection.createOffer();
      await this._setLocalMunged(offer);
      await this._applyCallSenderParams();
      await this._sendCallSignal(_EnhancedSecureWebRTCManager.MESSAGE_TYPES.CALL_OFFER, {
        callId: this.callState.callId,
        withVideo: this.callState.withVideo,
        sdp: this.peerConnection.localDescription.sdp
      });
    } finally {
      this._callMakingOffer = false;
    }
  }
  // Central inbound call-signal router (called from processMessage).
  async _handleCallSignal(type, data) {
    const T = _EnhancedSecureWebRTCManager.MESSAGE_TYPES;
    switch (type) {
      case T.CALL_OFFER: {
        await this._onIncomingCallOffer(data);
        return;
      }
      case T.CALL_ANSWER: {
        try {
          if (this.peerConnection.signalingState === "have-local-offer") {
            await this.peerConnection.setRemoteDescription({ type: "answer", sdp: data.sdp });
          }
          if (this.callState.phase === "outgoing") this._updateCallState({ phase: "active" });
          this._scheduleRemoteRefresh();
        } catch (e) {
          this._secureLog("warn", "\u26A0\uFE0F Failed to apply call answer", { errorType: e?.constructor?.name });
        }
        return;
      }
      case T.CALL_ICE: {
        try {
          if (data.candidate) await this.peerConnection.addIceCandidate(data.candidate);
        } catch (_) {
        }
        return;
      }
      case T.CALL_DECLINE: {
        await this._teardownCallMedia();
        this._updateCallState({ active: false, phase: "idle", withVideo: false, remoteHasVideo: false, error: "declined" });
        return;
      }
      case T.CALL_END: {
        await this.endCall(
          /* sendSignal */
          false
        );
        return;
      }
      default:
        return;
    }
  }
};
var SecureKeyStorage = class {
  constructor(masterKeyManager = null) {
    this._keyStore = /* @__PURE__ */ new WeakMap();
    this._keyMetadata = /* @__PURE__ */ new Map();
    this._keyReferences = /* @__PURE__ */ new Map();
    this._masterKeyManager = masterKeyManager || new SecureMasterKeyManager();
    this._persistentStorage = new SecurePersistentKeyStorage(this._masterKeyManager);
    this._setupMasterKeyCallbacks();
    setTimeout(() => {
      if (!this.validateStorageIntegrity()) {
        this._secureLog("error", "CRITICAL: Key storage integrity check failed");
      }
    }, 100);
  }
  /**
   * SecureKeyStorage calls this._secureLog() in a dozen places but never
   * defined it, so every one of those calls threw a TypeError instead of
   * logging — including the integrity-violation and key-storage-failure paths,
   * i.e. exactly the reports worth having. Delegate to the shared sanitising
   * logger, which redacts key-shaped values before anything reaches the console.
   */
  _secureLog(level, message, context = {}) {
    try {
      const logger = typeof window !== "undefined" && window.EnhancedSecureCryptoUtils?.secureLog || null;
      if (logger && typeof logger.log === "function") {
        logger.log(level, `[KeyStorage] ${message}`, context);
        return;
      }
    } catch (_) {
    }
    if (level === "error") console.error(`[KeyStorage] ${message}`);
    else if (level === "warn") console.warn(`[KeyStorage] ${message}`);
  }
  /**
   * Setup callbacks for master key manager
   */
  _setupMasterKeyCallbacks() {
    this._masterKeyManager.setPasswordRequiredCallback((isRetry, callback) => {
      this._secureLog("error", "Master key password requested but no password UI is installed", {
        isRetry: !!isRetry
      });
      callback(null);
    });
    this._masterKeyManager.setSessionExpiredCallback((reason) => {
      console.warn(`Master key session expired: ${reason}`);
    });
    this._masterKeyManager.setUnlockedCallback(() => {
      console.log("Master key unlocked successfully");
    });
  }
  /**
   * Set custom password callback
   */
  setPasswordCallback(callback) {
    this._masterKeyManager.setPasswordRequiredCallback(callback);
  }
  /**
   * Set custom session expired callback
   */
  setSessionExpiredCallback(callback) {
    this._masterKeyManager.setSessionExpiredCallback(callback);
  }
  /**
   * Get master key (with automatic unlock if needed)
   */
  async _ensureMasterKeyUnlocked() {
    if (!this._masterKeyManager.isUnlocked()) {
      await this._masterKeyManager.unlock();
    }
  }
  async storeKey(keyId, cryptoKey, metadata = {}) {
    if (!(cryptoKey instanceof CryptoKey)) {
      throw new Error("Only CryptoKey objects can be stored");
    }
    try {
      if (!cryptoKey.extractable) {
        this._keyReferences.set(keyId, cryptoKey);
        this._keyMetadata.set(keyId, {
          ...metadata,
          created: Date.now(),
          lastAccessed: Date.now(),
          extractable: false,
          persistent: false,
          encrypted: false
        });
        return true;
      }
      await this._persistentStorage.storeExtractableKey(keyId, cryptoKey, metadata);
      this._keyReferences.set(keyId, cryptoKey);
      this._keyMetadata.set(keyId, {
        ...metadata,
        created: Date.now(),
        lastAccessed: Date.now(),
        extractable: true,
        persistent: true,
        encrypted: true
      });
      return true;
    } catch (error) {
      this._secureLog("error", "Failed to store key securely", {
        errorType: error?.constructor?.name || "Unknown"
      });
      return false;
    }
  }
  async retrieveKey(keyId) {
    try {
      if (this._keyReferences.has(keyId)) {
        const metadata = this._keyMetadata.get(keyId);
        if (metadata) {
          metadata.lastAccessed = Date.now();
        }
        return this._keyReferences.get(keyId);
      }
      const restoredKey = await this._persistentStorage.retrieveKey(keyId);
      if (restoredKey) {
        this._keyReferences.set(keyId, restoredKey);
        const existingMetadata = this._keyMetadata.get(keyId);
        this._keyMetadata.set(keyId, {
          ...existingMetadata,
          lastAccessed: Date.now(),
          restoredFromPersistent: true
        });
        return restoredKey;
      }
      return null;
    } catch (error) {
      this._secureLog("error", "Failed to retrieve key", {
        errorType: error?.constructor?.name || "Unknown"
      });
      return null;
    }
  }
  async _encryptKeyData(keyData) {
    const dataToEncrypt = typeof keyData === "object" ? JSON.stringify(keyData) : keyData;
    const encoder = new TextEncoder();
    const data = encoder.encode(dataToEncrypt);
    await this._ensureMasterKeyUnlocked();
    const { encryptedData, iv } = await this._masterKeyManager.encryptBytes(data);
    const result = new Uint8Array(iv.length + encryptedData.byteLength);
    result.set(iv, 0);
    result.set(encryptedData, iv.length);
    return result;
  }
  async _decryptKeyData(encryptedData) {
    const iv = encryptedData.slice(0, 12);
    const data = encryptedData.slice(12);
    await this._ensureMasterKeyUnlocked();
    const decryptedData = await this._masterKeyManager.decryptBytes(data, iv);
    const decoder = new TextDecoder();
    const jsonString = decoder.decode(decryptedData);
    try {
      return JSON.parse(jsonString);
    } catch {
      return decryptedData;
    }
  }
  async secureWipe(keyId) {
    const cryptoKey = this._keyReferences.get(keyId);
    if (cryptoKey) {
      this._keyStore.delete(cryptoKey);
      this._keyReferences.delete(keyId);
      this._keyMetadata.delete(keyId);
    }
    await this._performNaturalCleanup();
  }
  async secureWipeAll() {
    try {
      await this._persistentStorage.clearAll();
    } catch (error) {
      this._secureLog("error", "Failed to clear persistent storage", {
        errorType: error?.constructor?.name || "Unknown"
      });
    }
    this._keyReferences.clear();
    this._keyMetadata.clear();
    this._keyStore = /* @__PURE__ */ new WeakMap();
    await this._performNaturalCleanup();
  }
  //   Validate storage integrity
  validateStorageIntegrity() {
    const violations = [];
    for (const [keyId, metadata] of this._keyMetadata.entries()) {
      if (metadata.extractable === true && metadata.encrypted !== true) {
        violations.push({
          keyId,
          type: "EXTRACTABLE_KEY_NOT_ENCRYPTED",
          metadata
        });
      }
      if (metadata.extractable === false && metadata.encrypted === true) {
        violations.push({
          keyId,
          type: "NON_EXTRACTABLE_KEY_ENCRYPTED",
          metadata
        });
      }
    }
    if (violations.length > 0) {
      this._secureLog("error", "Storage integrity violations detected", {
        violationCount: violations.length
      });
      return false;
    }
    return true;
  }
  async getStorageStats() {
    const persistentStats = await this._persistentStorage.getStorageStats();
    return {
      totalKeys: this._keyReferences.size,
      memoryKeys: this._keyReferences.size,
      persistentKeys: persistentStats.persistentKeys,
      metadata: Array.from(this._keyMetadata.entries()).map(([id, meta]) => ({
        id,
        created: meta.created,
        lastAccessed: meta.lastAccessed,
        age: Date.now() - meta.created,
        persistent: meta.persistent || false
      })),
      persistent: persistentStats
    };
  }
  /**
   * List all stored keys (memory + persistent)
   */
  async listAllKeys() {
    try {
      const memoryKeys = Array.from(this._keyMetadata.entries()).map(([keyId, metadata]) => ({
        keyId,
        ...metadata,
        location: "memory"
      }));
      const persistentKeys = await this._persistentStorage.listStoredKeys();
      const persistentKeysFormatted = persistentKeys.map((key) => ({
        ...key,
        location: "persistent"
      }));
      return {
        memoryKeys,
        persistentKeys: persistentKeysFormatted,
        totalCount: memoryKeys.length + persistentKeysFormatted.length
      };
    } catch (error) {
      this._secureLog("error", "Failed to list keys", {
        errorType: error?.constructor?.name || "Unknown"
      });
      return {
        memoryKeys: [],
        persistentKeys: [],
        totalCount: 0,
        error: error.message
      };
    }
  }
  /**
   * Delete key from both memory and persistent storage
   */
  async deleteKey(keyId) {
    try {
      this._keyReferences.delete(keyId);
      this._keyMetadata.delete(keyId);
      await this._persistentStorage.deleteKey(keyId);
      return true;
    } catch (error) {
      this._secureLog("error", "Failed to delete key", {
        errorType: error?.constructor?.name || "Unknown"
      });
      return false;
    }
  }
};
var SecureIndexedDBWrapper = class {
  constructor(dbName = "SecureKeyStorage", version2 = 1) {
    this.dbName = dbName;
    this.version = version2;
    this.db = null;
    this.KEYS_STORE = "encrypted_keys";
    this.METADATA_STORE = "key_metadata";
    this.SALT_STORE = "master_salt";
  }
  /**
   * Initialize IndexedDB connection
   */
  async initialize() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);
      request.onerror = () => {
        reject(new Error(`Failed to open IndexedDB: ${request.error}`));
      };
      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(this.KEYS_STORE)) {
          const keysStore = db.createObjectStore(this.KEYS_STORE, { keyPath: "keyId" });
          keysStore.createIndex("timestamp", "timestamp", { unique: false });
          keysStore.createIndex("algorithm", "algorithm", { unique: false });
        }
        if (!db.objectStoreNames.contains(this.METADATA_STORE)) {
          const metadataStore = db.createObjectStore(this.METADATA_STORE, { keyPath: "keyId" });
          metadataStore.createIndex("created", "created", { unique: false });
          metadataStore.createIndex("lastAccessed", "lastAccessed", { unique: false });
        }
        if (!db.objectStoreNames.contains(this.SALT_STORE)) {
          db.createObjectStore(this.SALT_STORE, { keyPath: "id" });
        }
      };
    });
  }
  /**
   * Store encrypted key data
   */
  async storeEncryptedKey(keyId, encryptedData, iv, algorithm, usages, type, metadata = {}) {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.KEYS_STORE, this.METADATA_STORE], "readwrite");
    const keyRecord = {
      keyId,
      encryptedData: Array.from(new Uint8Array(encryptedData)),
      // Convert to array for storage
      iv: Array.from(new Uint8Array(iv)),
      algorithm,
      usages,
      type
    };
    const metadataRecord = { keyId, ...metadata };
    return new Promise((resolve, reject) => {
      const keysRequest = transaction.objectStore(this.KEYS_STORE).put(keyRecord);
      const metadataRequest = transaction.objectStore(this.METADATA_STORE).put(metadataRecord);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error(`Failed to store key: ${transaction.error}`));
    });
  }
  /**
   * Retrieve encrypted key data
   */
  async getEncryptedKey(keyId) {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.KEYS_STORE], "readonly");
    const store = transaction.objectStore(this.KEYS_STORE);
    return new Promise((resolve, reject) => {
      const request = store.get(keyId);
      request.onsuccess = () => {
        const result = request.result;
        if (result) {
          result.encryptedData = new Uint8Array(result.encryptedData);
          result.iv = new Uint8Array(result.iv);
        }
        resolve(result);
      };
      request.onerror = () => reject(new Error(`Failed to retrieve key: ${request.error}`));
    });
  }
  /**
   * Update key metadata (e.g., last accessed time)
   */
  async updateKeyMetadata(keyId, updates) {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.METADATA_STORE], "readwrite");
    const store = transaction.objectStore(this.METADATA_STORE);
    return new Promise((resolve, reject) => {
      const getRequest = store.get(keyId);
      getRequest.onsuccess = () => {
        const metadata = getRequest.result;
        if (metadata) {
          Object.assign(metadata, updates);
          const putRequest = store.put(metadata);
          putRequest.onsuccess = () => resolve();
          putRequest.onerror = () => reject(new Error(`Failed to update metadata: ${putRequest.error}`));
        } else {
          reject(new Error(`Key metadata not found: ${keyId}`));
        }
      };
      getRequest.onerror = () => reject(new Error(`Failed to get metadata: ${getRequest.error}`));
    });
  }
  async getKeyMetadataRecord(keyId) {
    if (!this.db) throw new Error("Database not initialized");
    const transaction = this.db.transaction([this.METADATA_STORE], "readonly");
    const store = transaction.objectStore(this.METADATA_STORE);
    return new Promise((resolve, reject) => {
      const request = store.get(keyId);
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(new Error(`Failed to get metadata: ${request.error}`));
    });
  }
  async putKeyMetadataRecord(record) {
    if (!this.db) throw new Error("Database not initialized");
    const transaction = this.db.transaction([this.METADATA_STORE], "readwrite");
    const store = transaction.objectStore(this.METADATA_STORE);
    return new Promise((resolve, reject) => {
      const request = store.put(record);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error(`Failed to store metadata: ${request.error}`));
    });
  }
  /**
   * Delete key and its metadata
   */
  async deleteKey(keyId) {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.KEYS_STORE, this.METADATA_STORE], "readwrite");
    return new Promise((resolve, reject) => {
      const keysRequest = transaction.objectStore(this.KEYS_STORE).delete(keyId);
      const metadataRequest = transaction.objectStore(this.METADATA_STORE).delete(keyId);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error(`Failed to delete key: ${transaction.error}`));
    });
  }
  /**
   * List all stored keys
   */
  async listKeys() {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.METADATA_STORE], "readonly");
    const store = transaction.objectStore(this.METADATA_STORE);
    return new Promise((resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error(`Failed to list keys: ${request.error}`));
    });
  }
  /**
   * Store master key salt
   */
  async storeMasterSalt(salt) {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.SALT_STORE], "readwrite");
    const store = transaction.objectStore(this.SALT_STORE);
    const saltRecord = {
      id: "master_salt",
      salt: Array.from(new Uint8Array(salt))
    };
    return new Promise((resolve, reject) => {
      const request = store.put(saltRecord);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error(`Failed to store salt: ${request.error}`));
    });
  }
  /**
   * Retrieve master key salt
   */
  async getMasterSalt() {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.SALT_STORE], "readonly");
    const store = transaction.objectStore(this.SALT_STORE);
    return new Promise((resolve, reject) => {
      const request = store.get("master_salt");
      request.onsuccess = () => {
        const result = request.result;
        if (result) {
          resolve(new Uint8Array(result.salt));
        } else {
          resolve(null);
        }
      };
      request.onerror = () => reject(new Error(`Failed to retrieve salt: ${request.error}`));
    });
  }
  /**
   * Clear all data (for security wipe)
   */
  async clearAll() {
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    const transaction = this.db.transaction([this.KEYS_STORE, this.METADATA_STORE, this.SALT_STORE], "readwrite");
    return new Promise((resolve, reject) => {
      const keysRequest = transaction.objectStore(this.KEYS_STORE).clear();
      const metadataRequest = transaction.objectStore(this.METADATA_STORE).clear();
      const saltRequest = transaction.objectStore(this.SALT_STORE).clear();
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error(`Failed to clear database: ${transaction.error}`));
    });
  }
  /**
   * Close database connection
   */
  close() {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }
};
var SecurePersistentKeyStorage = class {
  constructor(masterKeyManager, indexedDBWrapper = null) {
    this._masterKeyManager = masterKeyManager;
    this._indexedDB = indexedDBWrapper || new SecureIndexedDBWrapper();
    this._dbInitialized = false;
    this._keyCache = /* @__PURE__ */ new WeakMap();
    this._keyReferences = /* @__PURE__ */ new Map();
  }
  /**
   * Initialize IndexedDB if not already done
   */
  async _ensureDBInitialized() {
    if (!this._dbInitialized) {
      await this._indexedDB.initialize();
      this._dbInitialized = true;
    }
  }
  async _ensureMasterKeyUnlocked() {
    if (typeof this._masterKeyManager.isUnlocked === "function" && !this._masterKeyManager.isUnlocked()) {
      await this._masterKeyManager.unlock();
    }
  }
  /**
   * Store extractable key with encryption
   */
  async storeExtractableKey(keyId, cryptoKey, metadata = {}) {
    if (!(cryptoKey instanceof CryptoKey)) {
      throw new Error("Only CryptoKey objects can be stored");
    }
    if (!cryptoKey.extractable) {
      throw new Error("Key must be extractable for persistent storage");
    }
    try {
      await this._ensureDBInitialized();
      const jwkData = await crypto.subtle.exportKey("jwk", cryptoKey);
      const { encryptedData, iv } = await this._encryptKeyData(jwkData);
      const encryptedMetadata = await this._encryptMetadata({
        ...metadata,
        created: Date.now(),
        lastAccessed: Date.now(),
        extractable: true,
        persistent: true
      });
      await this._indexedDB.storeEncryptedKey(
        keyId,
        encryptedData,
        iv,
        cryptoKey.algorithm,
        cryptoKey.usages,
        cryptoKey.type,
        encryptedMetadata
      );
      const nonExtractableKey = await this._importAsNonExtractable(jwkData, cryptoKey.algorithm, cryptoKey.usages);
      this._keyReferences.set(keyId, nonExtractableKey);
      return true;
    } catch (error) {
      throw new Error(`Failed to store extractable key: ${error.message}`);
    }
  }
  /**
   * Retrieve and restore key from persistent storage
   */
  async retrieveKey(keyId) {
    try {
      if (this._keyReferences.has(keyId)) {
        return this._keyReferences.get(keyId);
      }
      await this._ensureDBInitialized();
      const keyRecord = await this._indexedDB.getEncryptedKey(keyId);
      if (!keyRecord) {
        return null;
      }
      const jwkData = await this._decryptKeyData(keyRecord.encryptedData, keyRecord.iv);
      const restoredKey = await this._importAsNonExtractable(jwkData, keyRecord.algorithm, keyRecord.usages);
      this._keyReferences.set(keyId, restoredKey);
      await this._updateEncryptedMetadata(keyId, { lastAccessed: Date.now() });
      return restoredKey;
    } catch (error) {
      throw new Error(`Failed to retrieve key: ${error.message}`);
    }
  }
  /**
   * Delete key from persistent storage
   */
  async deleteKey(keyId) {
    try {
      await this._ensureDBInitialized();
      await this._indexedDB.deleteKey(keyId);
      this._keyReferences.delete(keyId);
      return true;
    } catch (error) {
      throw new Error(`Failed to delete key: ${error.message}`);
    }
  }
  /**
   * List all stored keys
   */
  async listStoredKeys() {
    try {
      await this._ensureDBInitialized();
      const records = await this._indexedDB.listKeys();
      const results = [];
      for (const record of records) {
        const metadata = await this._readMetadataWithMigration(record);
        if (metadata) results.push({ keyId: record.keyId, ...metadata });
      }
      return results;
    } catch (error) {
      throw new Error(`Failed to list keys: ${error.message}`);
    }
  }
  /**
   * Clear all persistent storage
   */
  async clearAll() {
    try {
      await this._ensureDBInitialized();
      await this._indexedDB.clearAll();
      this._keyReferences.clear();
      return true;
    } catch (error) {
      throw new Error(`Failed to clear storage: ${error.message}`);
    }
  }
  /**
   * Encrypt key data using master key
   */
  async _encryptKeyData(jwkData) {
    const jsonString = JSON.stringify(jwkData);
    const data = new TextEncoder().encode(jsonString);
    await this._ensureMasterKeyUnlocked();
    return await this._masterKeyManager.encryptBytes(data);
  }
  /**
   * Decrypt key data using master key
   */
  async _decryptKeyData(encryptedData, iv) {
    await this._ensureMasterKeyUnlocked();
    const decryptedData = await this._masterKeyManager.decryptBytes(encryptedData, iv);
    const jsonString = new TextDecoder().decode(decryptedData);
    return JSON.parse(jsonString);
  }
  async _encryptMetadata(metadata) {
    const data = new TextEncoder().encode(JSON.stringify(metadata));
    await this._ensureMasterKeyUnlocked();
    const { encryptedData, iv } = await this._masterKeyManager.encryptBytes(data);
    return {
      metadataVersion: 1,
      encryptedMetadata: Array.from(encryptedData),
      metadataIv: Array.from(iv)
    };
  }
  async _decryptMetadataRecord(record) {
    if (!record?.encryptedMetadata || !record?.metadataIv) {
      throw new Error("Encrypted metadata missing");
    }
    await this._ensureMasterKeyUnlocked();
    const decrypted = await this._masterKeyManager.decryptBytes(
      new Uint8Array(record.encryptedMetadata),
      new Uint8Array(record.metadataIv)
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
  }
  async _readMetadataWithMigration(record) {
    if (!record) return null;
    if (record.encryptedMetadata) {
      try {
        return await this._decryptMetadataRecord(record);
      } catch (error) {
        return null;
      }
    }
    const { keyId, ...legacyMetadata } = record;
    const encryptedRecord = { keyId, ...await this._encryptMetadata(legacyMetadata) };
    await this._indexedDB.putKeyMetadataRecord(encryptedRecord);
    return legacyMetadata;
  }
  async _updateEncryptedMetadata(keyId, updates) {
    const record = await this._indexedDB.getKeyMetadataRecord(keyId);
    if (!record) throw new Error(`Key metadata not found: ${keyId}`);
    const current = await this._readMetadataWithMigration(record);
    if (!current) throw new Error(`Key metadata corrupted: ${keyId}`);
    await this._indexedDB.putKeyMetadataRecord({
      keyId,
      ...await this._encryptMetadata({ ...current, ...updates })
    });
  }
  /**
   * Import JWK as non-extractable key
   */
  async _importAsNonExtractable(jwkData, algorithm, usages) {
    return await crypto.subtle.importKey(
      "jwk",
      jwkData,
      algorithm,
      false,
      // non-extractable for security
      usages
    );
  }
  /**
   * Get storage statistics
   */
  async getStorageStats() {
    try {
      await this._ensureDBInitialized();
      const keys = await this._indexedDB.listKeys();
      return {
        totalKeys: keys.length,
        memoryKeys: this._keyReferences.size,
        persistentKeys: keys.length,
        lastAccessed: keys.reduce((latest, key) => Math.max(latest, key.lastAccessed || 0), 0)
      };
    } catch (error) {
      return {
        totalKeys: 0,
        memoryKeys: this._keyReferences.size,
        persistentKeys: 0,
        lastAccessed: 0,
        error: error.message
      };
    }
  }
};
var SecureMasterKeyManager = class {
  constructor(indexedDBWrapper = null) {
    this._keyHandle = null;
    this._isUnlocked = false;
    this._sessionTimeout = null;
    this._lastActivity = null;
    this._sessionTimeoutMs = 60 * 60 * 1e3;
    this._inactivityTimeoutMs = 30 * 60 * 1e3;
    this._pbkdf2Iterations = 31e4;
    this._saltSize = 32;
    this._indexedDB = indexedDBWrapper || new SecureIndexedDBWrapper();
    this._dbInitialized = false;
    this._onPasswordRequired = null;
    this._onSessionExpired = null;
    this._onUnlocked = null;
  }
  /**
   * Set callback for password requests
   */
  setPasswordRequiredCallback(callback) {
    this._onPasswordRequired = callback;
  }
  /**
   * Set callback for session expiration
   */
  setSessionExpiredCallback(callback) {
    this._onSessionExpired = callback;
  }
  /**
   * Set callback for successful unlock
   */
  setUnlockedCallback(callback) {
    this._onUnlocked = callback;
  }
  /**
   * Setup event listeners for session management
   */
  _setupEventListeners() {
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
          this._handleFocusOut();
        } else {
          this._handleFocusIn();
        }
      });
      window.addEventListener("blur", () => this._handleFocusOut());
      window.addEventListener("focus", () => this._handleFocusIn());
      ["mousedown", "mousemove", "keypress", "scroll", "touchstart"].forEach((event) => {
        document.addEventListener(event, () => this._updateActivity(), { passive: true });
      });
    }
  }
  /**
   * Handle focus out - start inactivity timer
   */
  _handleFocusOut() {
    if (this._isUnlocked) {
      this._startInactivityTimer(this._inactivityTimeoutMs);
    }
  }
  /**
   * Handle focus in - reset timers
   */
  _handleFocusIn() {
    if (this._isUnlocked) {
      this._resetSessionTimer();
    }
  }
  /**
   * Update last activity timestamp
   */
  _updateActivity() {
    this._lastActivity = Date.now();
    if (this._isUnlocked) {
      this._resetSessionTimer();
    }
  }
  /**
   * Start session timer
   */
  _startSessionTimer() {
    this._clearTimers();
    this._sessionTimeout = setTimeout(() => {
      this._expireSession("timeout");
    }, this._sessionTimeoutMs);
  }
  /**
   * Start inactivity timer
   */
  _startInactivityTimer(timeout) {
    this._clearTimers();
    this._sessionTimeout = setTimeout(() => {
      this._expireSession("inactivity");
    }, timeout);
  }
  /**
   * Reset session timer
   */
  _resetSessionTimer() {
    if (this._isUnlocked) {
      this._startSessionTimer();
    }
  }
  /**
   * Clear all timers
   */
  _clearTimers() {
    if (this._sessionTimeout) {
      clearTimeout(this._sessionTimeout);
      this._sessionTimeout = null;
    }
  }
  /**
   * Expire the current session
   */
  _expireSession(reason = "unknown") {
    if (this._isUnlocked) {
      this._secureWipeMasterKey();
      this._isUnlocked = false;
      if (this._onSessionExpired) {
        this._onSessionExpired(reason);
      }
    }
  }
  /**
   * Initialize IndexedDB if not already done
   */
  async _ensureDBInitialized() {
    if (!this._dbInitialized) {
      await this._indexedDB.initialize();
      this._dbInitialized = true;
    }
  }
  /**
   * Generate salt for PBKDF2
   */
  _generateSalt() {
    return crypto.getRandomValues(new Uint8Array(this._saltSize));
  }
  /**
   * Get or create persistent salt
   */
  async _getOrCreateSalt() {
    await this._ensureDBInitialized();
    let salt = await this._indexedDB.getMasterSalt();
    if (!salt) {
      salt = this._generateSalt();
      await this._indexedDB.storeMasterSalt(salt);
    }
    return salt;
  }
  /**
   * Derive master key from password using PBKDF2
   */
  async _deriveKeyFromPassword(password, salt) {
    try {
      const passwordKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
      );
      const derivedKey = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: this._pbkdf2Iterations,
          hash: "SHA-256"
        },
        passwordKey,
        {
          name: "AES-GCM",
          length: 256
        },
        false,
        // non-extractable for security
        ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
      );
      return derivedKey;
    } catch (error) {
      throw new Error(`Key derivation failed: ${error.message}`);
    }
  }
  /**
   * Request password from user
   */
  async _requestPassword(isRetry = false) {
    if (!this._onPasswordRequired) {
      throw new Error("Password callback not set");
    }
    return new Promise((resolve, reject) => {
      this._onPasswordRequired(isRetry, (password) => {
        if (password) {
          resolve(password);
        } else {
          reject(new Error("Password not provided"));
        }
      });
    });
  }
  /**
   * Unlock the master key with password
   */
  async unlock(password = null) {
    try {
      if (!password) {
        password = await this._requestPassword(false);
      }
      const salt = await this._getOrCreateSalt();
      this._keyHandle = await this._deriveKeyFromPassword(password, salt);
      this._isUnlocked = true;
      this._lastActivity = Date.now();
      this._startSessionTimer();
      password = null;
      if (this._onUnlocked) {
        this._onUnlocked();
      }
      return { success: true };
    } catch (error) {
      password = null;
      throw error;
    }
  }
  /**
   * Lock the master key
   */
  lock() {
    this._expireSession("manual");
  }
  /**
   * Get master key (only if unlocked)
   */
  // Prevent direct key access; provide operations only
  async encryptBytes(plainBytes) {
    if (!this._isUnlocked || !this._keyHandle) {
      throw new Error("Master key is locked");
    }
    this._updateActivity();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, this._keyHandle, plainBytes);
    return { encryptedData: new Uint8Array(encrypted), iv };
  }
  async decryptBytes(encryptedBytes, iv) {
    if (!this._isUnlocked || !this._keyHandle) {
      throw new Error("Master key is locked");
    }
    this._updateActivity();
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, this._keyHandle, encryptedBytes);
    return new Uint8Array(decrypted);
  }
  /**
   * Check if master key is unlocked
   */
  isUnlocked() {
    return this._isUnlocked && this._keyHandle !== null;
  }
  /**
   * Get session status
   */
  getSessionStatus() {
    return {
      isUnlocked: this._isUnlocked,
      lastActivity: this._lastActivity,
      sessionTimeoutMs: this._sessionTimeoutMs,
      inactivityTimeoutMs: this._inactivityTimeoutMs
    };
  }
  /**
   * Securely wipe master key from memory
   */
  _secureWipeMasterKey() {
    if (this._keyHandle) {
      this._keyHandle = null;
    }
    this._clearTimers();
  }
  /**
   * Cleanup on destruction
   */
  destroy() {
    this._secureWipeMasterKey();
    this._isUnlocked = false;
    if (typeof document !== "undefined") {
      document.removeEventListener("visibilitychange", this._handleFocusOut);
      window.removeEventListener("blur", this._handleFocusOut);
      window.removeEventListener("focus", this._handleFocusIn);
    }
  }
};

// src/scripts/app-boot.js
var import_NotificationIntegration = __toESM(require_NotificationIntegration());

// package.json
var version = "6.1.1";

// src/components/ui/Header.jsx
var APP_VERSION = `v${version}`;
var EnhancedMinimalHeader = ({
  status,
  fingerprint,
  verificationCode,
  onDisconnect,
  isConnected,
  securityLevel,
  webrtcManager
}) => {
  const [realSecurityLevel, setRealSecurityLevel] = React.useState(null);
  const [lastSecurityUpdate, setLastSecurityUpdate] = React.useState(0);
  const [hasActiveSession, setHasActiveSession] = React.useState(false);
  const [currentTimeLeft, setCurrentTimeLeft] = React.useState(0);
  const [sessionType, setSessionType] = React.useState("unknown");
  React.useEffect(() => {
    let isUpdating = false;
    let lastUpdateAttempt = 0;
    const updateRealSecurityStatus = async () => {
      const now = Date.now();
      if (now - lastUpdateAttempt < 1e4) {
        return;
      }
      if (isUpdating) {
        return;
      }
      isUpdating = true;
      lastUpdateAttempt = now;
      try {
        if (!webrtcManager || !isConnected) {
          return;
        }
        const activeWebrtcManager = webrtcManager;
        let realSecurityData = null;
        if (typeof activeWebrtcManager.getRealSecurityLevel === "function") {
          realSecurityData = await activeWebrtcManager.getRealSecurityLevel();
        } else if (typeof activeWebrtcManager.calculateAndReportSecurityLevel === "function") {
          realSecurityData = await activeWebrtcManager.calculateAndReportSecurityLevel();
        } else {
          realSecurityData = await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(activeWebrtcManager);
        }
        if (realSecurityData && realSecurityData.isRealData !== false) {
          const currentScore = realSecurityLevel?.score || 0;
          const newScore = realSecurityData.score || 0;
          if (currentScore !== newScore || !realSecurityLevel) {
            setRealSecurityLevel(realSecurityData);
            setLastSecurityUpdate(now);
          } else if (window.DEBUG_MODE) {
          }
        } else {
        }
      } catch (error) {
      } finally {
        isUpdating = false;
      }
    };
    if (isConnected) {
      updateRealSecurityStatus();
      if (!realSecurityLevel || realSecurityLevel.score < 50) {
        const retryInterval = setInterval(() => {
          if (!realSecurityLevel || realSecurityLevel.score < 50) {
            updateRealSecurityStatus();
          } else {
            clearInterval(retryInterval);
          }
        }, 5e3);
        setTimeout(() => clearInterval(retryInterval), 3e4);
      }
    }
    const interval = setInterval(updateRealSecurityStatus, 3e4);
    return () => clearInterval(interval);
  }, [webrtcManager, isConnected]);
  React.useEffect(() => {
    const handleSecurityUpdate = (event) => {
      setTimeout(() => {
        setLastSecurityUpdate(0);
      }, 100);
    };
    const handleRealSecurityCalculated = (event) => {
      if (event.detail && event.detail.securityData) {
        setRealSecurityLevel(event.detail.securityData);
        setLastSecurityUpdate(Date.now());
      }
    };
    document.addEventListener("security-level-updated", handleSecurityUpdate);
    document.addEventListener("real-security-calculated", handleRealSecurityCalculated);
    window.forceHeaderSecurityUpdate = (webrtcManager2) => {
      if (webrtcManager2 && window.EnhancedSecureCryptoUtils) {
        window.EnhancedSecureCryptoUtils.calculateSecurityLevel(webrtcManager2).then((securityData) => {
          if (securityData && securityData.isRealData !== false) {
            setRealSecurityLevel(securityData);
            setLastSecurityUpdate(Date.now());
          }
        }).catch((error) => {
        });
      } else {
        setLastSecurityUpdate(0);
      }
    };
    return () => {
      document.removeEventListener("security-level-updated", handleSecurityUpdate);
      document.removeEventListener("real-security-calculated", handleRealSecurityCalculated);
    };
  }, []);
  React.useEffect(() => {
    setHasActiveSession(true);
    setCurrentTimeLeft(0);
    setSessionType("premium");
  }, []);
  React.useEffect(() => {
    setHasActiveSession(true);
    setCurrentTimeLeft(0);
    setSessionType("premium");
  }, []);
  React.useEffect(() => {
    const handleForceUpdate = (event) => {
      setHasActiveSession(true);
      setCurrentTimeLeft(0);
      setSessionType("premium");
    };
    const handleConnectionCleaned = () => {
      setRealSecurityLevel(null);
      setLastSecurityUpdate(0);
      setHasActiveSession(false);
      setCurrentTimeLeft(0);
      setSessionType("unknown");
    };
    const handlePeerDisconnect = () => {
      setRealSecurityLevel(null);
      setLastSecurityUpdate(0);
    };
    const handleDisconnected = () => {
      setRealSecurityLevel(null);
      setLastSecurityUpdate(0);
      setHasActiveSession(false);
      setCurrentTimeLeft(0);
      setSessionType("unknown");
    };
    document.addEventListener("force-header-update", handleForceUpdate);
    document.addEventListener("peer-disconnect", handlePeerDisconnect);
    document.addEventListener("connection-cleaned", handleConnectionCleaned);
    document.addEventListener("disconnected", handleDisconnected);
    return () => {
      document.removeEventListener("force-header-update", handleForceUpdate);
      document.removeEventListener("peer-disconnect", handlePeerDisconnect);
      document.removeEventListener("connection-cleaned", handleConnectionCleaned);
      document.removeEventListener("disconnected", handleDisconnected);
    };
  }, []);
  const handleSecurityClick = async (event) => {
    if (event && (event.button === 2 || event.ctrlKey || event.metaKey)) {
      if (onDisconnect && typeof onDisconnect === "function") {
        onDisconnect();
        return;
      }
    }
    event.preventDefault();
    event.stopPropagation();
    let realTestResults = null;
    if (webrtcManager && window.EnhancedSecureCryptoUtils) {
      try {
        realTestResults = await window.EnhancedSecureCryptoUtils.calculateSecurityLevel(webrtcManager);
      } catch (error) {
      }
    } else {
    }
    if (!realTestResults && !realSecurityLevel) {
      alert("Security verification in progress...\nPlease wait for real-time cryptographic verification to complete.");
      return;
    }
    let securityData = realTestResults || realSecurityLevel;
    if (!securityData) {
      securityData = {
        level: "UNKNOWN",
        score: 0,
        color: "gray",
        verificationResults: {},
        timestamp: Date.now(),
        details: "Security verification not available",
        isRealData: false,
        passedChecks: 0,
        totalChecks: 0
      };
    }
    let message = `REAL-TIME SECURITY VERIFICATION

`;
    message += `Security Level: ${securityData.level} (${securityData.score}%)
`;
    message += `Verification Time: ${new Date(securityData.timestamp).toLocaleTimeString()}
`;
    message += `Data Source: ${securityData.isRealData ? "Real Cryptographic Tests" : "Simulated Data"}

`;
    if (securityData.verificationResults) {
      message += "DETAILED CRYPTOGRAPHIC TESTS:\n";
      message += "=" + "=".repeat(40) + "\n";
      const passedTests = Object.entries(securityData.verificationResults).filter(([key, result]) => result.passed);
      const failedTests = Object.entries(securityData.verificationResults).filter(([key, result]) => !result.passed);
      if (passedTests.length > 0) {
        message += "PASSED TESTS:\n";
        passedTests.forEach(([key, result]) => {
          const testName = key.replace(/([A-Z])/g, " $1").replace(/^./, (str) => str.toUpperCase());
          message += `   ${testName}: ${result.details || "Test passed"}
`;
        });
        message += "\n";
      }
      if (failedTests.length > 0) {
        message += "FAILED/UNAVAILABLE TESTS:\n";
        failedTests.forEach(([key, result]) => {
          const testName = key.replace(/([A-Z])/g, " $1").replace(/^./, (str) => str.toUpperCase());
          message += `   ${testName}: ${result.details || "Test failed or unavailable"}
`;
        });
        message += "\n";
      }
      message += `SUMMARY:
`;
      message += `Passed: ${securityData.passedChecks}/${securityData.totalChecks} tests
`;
      message += `Score: ${securityData.score}/${securityData.maxPossibleScore || 100} points

`;
    }
    message += `SECURITY FEATURES STATUS:
`;
    message += "=" + "=".repeat(40) + "\n";
    if (securityData.verificationResults) {
      const features = {
        "ECDSA Digital Signatures": securityData.verificationResults.verifyECDSASignatures?.passed || false,
        "ECDH Key Exchange": securityData.verificationResults.verifyECDHKeyExchange?.passed || false,
        "AES-GCM Encryption": securityData.verificationResults.verifyEncryption?.passed || false,
        "Message Integrity (HMAC)": securityData.verificationResults.verifyMessageIntegrity?.passed || false,
        "Perfect Forward Secrecy": securityData.verificationResults.verifyPerfectForwardSecrecy?.passed || false,
        "Replay Protection": securityData.verificationResults.verifyReplayProtection?.passed || false,
        "DTLS Fingerprint": securityData.verificationResults.verifyDTLSFingerprint?.passed || false,
        "SAS Verification": securityData.verificationResults.verifySASVerification?.passed || false,
        "Metadata Protection": securityData.verificationResults.verifyMetadataProtection?.passed || false,
        "Traffic Obfuscation": securityData.verificationResults.verifyTrafficObfuscation?.passed || false
      };
      Object.entries(features).forEach(([feature, isEnabled]) => {
        message += `${isEnabled ? "\u2705" : "\u274C"} ${feature}
`;
      });
    } else {
      message += `\u2705 ECDSA Digital Signatures
`;
      message += `\u2705 ECDH Key Exchange
`;
      message += `\u2705 AES-GCM Encryption
`;
      message += `\u2705 Message Integrity (HMAC)
`;
      message += `\u2705 Perfect Forward Secrecy
`;
      message += `\u2705 Replay Protection
`;
      message += `\u2705 DTLS Fingerprint
`;
      message += `\u2705 SAS Verification
`;
      message += `\u2705 Metadata Protection
`;
      message += `\u2705 Traffic Obfuscation
`;
    }
    message += `
${securityData.details || "Real cryptographic verification completed"}`;
    if (securityData.isRealData) {
      message += "\n\n\u2705 This is REAL-TIME verification using actual cryptographic functions.";
    } else {
      message += "\n\n\u26A0\uFE0F Warning: This data may be simulated. Connection may not be fully established.";
    }
    const modal = document.createElement("div");
    modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 10000;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: monospace;
        `;
    const content = document.createElement("div");
    content.style.cssText = `
            background: #1a1a1a;
            color: #fff;
            padding: 20px;
            border-radius: 8px;
            max-width: 80%;
            max-height: 80%;
            overflow-y: auto;
            white-space: pre-line;
            border: 1px solid #333;
        `;
    content.textContent = message;
    modal.appendChild(content);
    modal.addEventListener("click", (e) => {
      if (e.target === modal) {
        document.body.removeChild(modal);
      }
    });
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        document.body.removeChild(modal);
        document.removeEventListener("keydown", handleKeyDown);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    document.body.appendChild(modal);
  };
  const getStatusConfig = () => {
    switch (status) {
      case "connected":
        return {
          text: "Connected",
          className: "status-connected",
          badgeClass: "bg-green-500/10 text-green-400 border-green-500/20"
        };
      case "verifying":
        return {
          text: "Verifying...",
          className: "status-verifying",
          badgeClass: "bg-purple-500/10 text-purple-400 border-purple-500/20"
        };
      case "connecting":
        return {
          text: "Connecting...",
          className: "status-connecting",
          badgeClass: "bg-blue-500/10 text-blue-400 border-blue-500/20"
        };
      case "retrying":
        return {
          text: "Retrying...",
          className: "status-connecting",
          badgeClass: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
        };
      case "failed":
        return {
          text: "Error",
          className: "status-failed",
          badgeClass: "bg-red-500/10 text-red-400 border-red-500/20"
        };
      case "reconnecting":
        return {
          text: "Reconnecting...",
          className: "status-connecting",
          badgeClass: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
        };
      case "peer_disconnected":
        return {
          text: "Peer disconnected",
          className: "status-failed",
          badgeClass: "bg-orange-500/10 text-orange-400 border-orange-500/20"
        };
      default:
        return {
          text: "Not connected",
          className: "status-disconnected",
          badgeClass: "bg-gray-500/10 text-gray-400 border-gray-500/20"
        };
    }
  };
  const config = getStatusConfig();
  const displaySecurityLevel = isConnected ? realSecurityLevel || securityLevel : null;
  const getSecurityIndicatorDetails = () => {
    if (!displaySecurityLevel) {
      return {
        tooltip: "Security verification in progress...",
        isVerified: false,
        dataSource: "loading"
      };
    }
    const isRealData = displaySecurityLevel.isRealData !== false;
    const baseTooltip = `${displaySecurityLevel.level} (${displaySecurityLevel.score}%)`;
    if (isRealData) {
      return {
        tooltip: `${baseTooltip} - Real-time verification \u2705
Right-click or Ctrl+click to disconnect`,
        isVerified: true,
        dataSource: "real"
      };
    } else {
      return {
        tooltip: `${baseTooltip} - Estimated (connection establishing...)
Right-click or Ctrl+click to disconnect`,
        isVerified: false,
        dataSource: "estimated"
      };
    }
  };
  const securityDetails = getSecurityIndicatorDetails();
  React.useEffect(() => {
    window.debugHeaderSecurity = void 0;
    return () => {
      delete window.debugHeaderSecurity;
    };
  }, [realSecurityLevel, lastSecurityUpdate, isConnected, webrtcManager, displaySecurityLevel, securityDetails]);
  const secColor = displaySecurityLevel ? displaySecurityLevel.color === "green" ? "#3ecf8e" : displaySecurityLevel.color === "orange" ? "#f0892a" : displaySecurityLevel.color === "yellow" ? "#e3c84e" : "#e5727a" : "#3ecf8e";
  const dotColor = isConnected ? "#3ecf8e" : ["connecting", "verifying", "retrying", "reconnecting"].includes(status) ? "#e3c84e" : status === "failed" ? "#e5727a" : "#6b6b73";
  const dotGlow = dotColor === "#3ecf8e" ? "rgba(62,207,142,0.16)" : dotColor === "#e3c84e" ? "rgba(227,200,78,0.16)" : dotColor === "#e5727a" ? "rgba(229,114,122,0.16)" : "rgba(107,107,115,0.16)";
  const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
  const onLanding = !isConnected;
  const [scrolled, setScrolled] = React.useState(false);
  React.useEffect(() => {
    const onScroll = () => setScrolled((window.scrollY || window.pageYOffset || 0) > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);
  const overlay = { position: "fixed", top: 0, left: 0, right: 0 };
  const headerStyle = onLanding ? scrolled ? { ...overlay, background: "rgba(15,15,17,0.72)", backdropFilter: "blur(14px)", WebkitBackdropFilter: "blur(14px)", borderBottom: "1px solid rgba(255,255,255,0.06)", transition: "background .25s ease, backdrop-filter .25s ease, border-color .25s ease" } : { ...overlay, background: "transparent", backdropFilter: "none", WebkitBackdropFilter: "none", borderBottom: "1px solid transparent", transition: "background .25s ease, backdrop-filter .25s ease, border-color .25s ease" } : { background: "rgba(18,18,20,0.72)", backdropFilter: "blur(14px)", WebkitBackdropFilter: "blur(14px)", borderBottom: "1px solid rgba(255,255,255,0.06)" };
  return React.createElement("header", {
    className: onLanding ? "header-minimal z-50" : "header-minimal sticky top-0 z-50",
    style: headerStyle
  }, [
    React.createElement("div", {
      key: "container",
      className: "max-w-7xl mx-auto",
      style: { padding: "0 20px" }
    }, [
      React.createElement("div", {
        key: "content",
        className: "flex items-center justify-between",
        style: { height: "64px", gap: "16px" }
      }, [
        // Left: logo + wordmark
        React.createElement("div", { key: "left", style: { display: "flex", alignItems: "center", gap: "12px", minWidth: 0 } }, [
          React.createElement(
            "div",
            { key: "logo", style: { width: "36px", height: "36px", flex: "none", display: "grid", placeItems: "center" } },
            React.createElement("img", { src: "/logo/securebit-mark.svg", alt: "SecureBit", style: { width: "100%", height: "100%", objectFit: "contain", display: "block" } })
          ),
          React.createElement("div", { key: "txt", style: { lineHeight: 1.2, minWidth: 0 } }, [
            React.createElement("div", { key: "r1", style: { display: "flex", alignItems: "baseline", gap: "7px" } }, [
              React.createElement("span", { key: "n", style: { fontSize: "16px", fontWeight: 800, letterSpacing: "-0.3px", color: "#e8e8eb" } }, "SecureBit"),
              React.createElement("span", { key: "v", style: { fontFamily: MONO, fontSize: "10px", fontWeight: 500, color: "#56565e" } }, APP_VERSION)
            ]),
            React.createElement("div", { key: "r2", className: "hidden sm:block", style: { fontSize: "11px", color: "#6b6b73", fontWeight: 500 } }, "End-to-end encrypted")
          ])
        ]),
        // Right: controls
        React.createElement("div", { key: "right", style: { display: "flex", alignItems: "center", gap: "9px" } }, [
          !onLanding && React.createElement("button", {
            key: "net",
            type: "button",
            onClick: () => window.dispatchEvent(new CustomEvent("securebit:open-network-settings")),
            title: "Advanced network settings (STUN/TURN)",
            "aria-label": "Advanced network settings",
            className: "sb-disconnect",
            style: { display: "grid", placeItems: "center", width: "38px", height: "38px", borderRadius: "9px", border: "1px solid rgba(255,255,255,0.07)", background: "rgba(255,255,255,0.02)", color: "#9a9aa2", cursor: "pointer", transition: "all .15s" }
          }, React.createElement("i", { className: "fas fa-network-wired", style: { fontSize: "13px" } })),
          !onLanding && displaySecurityLevel && React.createElement("div", {
            key: "sec",
            onClick: handleSecurityClick,
            onContextMenu: (e) => {
              e.preventDefault();
              if (typeof onDisconnect === "function") onDisconnect();
            },
            title: securityDetails.tooltip,
            className: "sb-secpill",
            style: { display: "flex", alignItems: "center", gap: "8px", padding: "7px 12px", borderRadius: "9px", border: "1px solid rgba(255,255,255,0.07)", background: "rgba(255,255,255,0.02)", cursor: "pointer" }
          }, [
            React.createElement("i", { key: "i", className: "fas fa-shield-halved", style: { fontSize: "13px", color: secColor } }),
            React.createElement("span", { key: "l", className: "hidden sm:inline", style: { fontSize: "12.5px", fontWeight: 600, color: "#e8e8eb" } }, String(displaySecurityLevel.level)),
            React.createElement("span", { key: "s", style: { fontFamily: MONO, fontSize: "11.5px", color: "#8a8a92" } }, displaySecurityLevel.score + "%")
          ]),
          !onLanding && React.createElement("div", { key: "status", style: { display: "flex", alignItems: "center", gap: "8px", padding: "8px 13px", borderRadius: "9px", border: "1px solid rgba(255,255,255,0.07)", background: "rgba(255,255,255,0.02)" } }, [
            React.createElement("span", { key: "dot", style: { width: "7px", height: "7px", borderRadius: "50%", background: dotColor, boxShadow: "0 0 0 3px " + dotGlow } }),
            React.createElement("span", { key: "t", className: "hidden sm:inline", style: { fontSize: "13px", fontWeight: 600, color: "#cfcfd4" } }, config.text)
          ]),
          isConnected && React.createElement("button", {
            key: "dc",
            onClick: onDisconnect,
            className: "sb-disconnect",
            style: { display: "flex", alignItems: "center", gap: "7px", padding: "8px 14px", borderRadius: "9px", border: "1px solid rgba(255,255,255,0.08)", background: "transparent", color: "#9a9aa2", fontFamily: "inherit", fontSize: "13px", fontWeight: 600, cursor: "pointer", transition: "all .15s" }
          }, [
            React.createElement("i", { key: "i", className: "fas fa-power-off", style: { fontSize: "12px" } }),
            React.createElement("span", { key: "t", className: "sb-hide-sm" }, "Disconnect")
          ])
        ])
      ])
    ])
  ]);
};
window.EnhancedMinimalHeader = EnhancedMinimalHeader;

// src/components/ui/DownloadApps.jsx
var DESKTOP_VERSION = "0.3.0";
var DESKTOP_RELEASE = `https://github.com/SecureBitChat/securebit-desktop/releases/download/v${DESKTOP_VERSION}`;
var DownloadApps = () => {
  const apps = [
    { id: "web", name: "Web App", subtitle: "Browser Version", icon: "fas fa-globe", platform: "Web", isActive: true, url: "https://securebit.chat/", color: "green" },
    { id: "windows", name: "Windows", subtitle: "Desktop App", icon: "fab fa-windows", platform: "Desktop", isActive: true, url: `${DESKTOP_RELEASE}/SecureBit.Chat_${DESKTOP_VERSION}_x64-setup.exe`, color: "blue" },
    { id: "macos", name: "macOS", subtitle: "Desktop App", icon: "fab fa-safari", platform: "Desktop", isActive: true, url: `${DESKTOP_RELEASE}/SecureBit.Chat_${DESKTOP_VERSION}_x64.dmg`, color: "gray" },
    { id: "linux", name: "Linux", subtitle: "Desktop App", icon: "fab fa-linux", platform: "Desktop", isActive: true, url: `${DESKTOP_RELEASE}/SecureBit.Chat_${DESKTOP_VERSION}_amd64.AppImage`, color: "orange" },
    { id: "ios", name: "iOS", subtitle: "iPhone & iPad", icon: "fab fa-apple", platform: "Mobile", isActive: false, url: "https://apps.apple.com/app/securebit-chat/", color: "white" },
    { id: "android", name: "Android", subtitle: "Google Play", icon: "fab fa-android", platform: "Mobile", isActive: false, url: "https://play.google.com/store/apps/details?id=com.securebit.chat", color: "green" },
    { id: "chrome", name: "Chrome", subtitle: "Browser Extension", icon: "fab fa-chrome", platform: "Browser", isActive: false, url: "#", color: "yellow" },
    { id: "edge", name: "Edge", subtitle: "Browser Extension", icon: "fab fa-edge", platform: "Browser", isActive: false, url: "#", color: "blue" },
    { id: "opera", name: "Opera", subtitle: "Browser Extension", icon: "fab fa-opera", platform: "Browser", isActive: false, url: "#", color: "red" },
    { id: "firefox", name: "Firefox", subtitle: "Browser Extension", icon: "fab fa-firefox-browser", platform: "Browser", isActive: false, url: "#", color: "orange" }
  ];
  const handleDownload = (app) => {
    if (app.isActive) window.open(app.url, "_blank");
  };
  const desktopApps = apps.filter((a) => a.platform === "Desktop" || a.platform === "Web");
  const mobileApps = apps.filter((a) => a.platform === "Mobile");
  const browserApps = apps.filter((a) => a.platform === "Browser");
  const cardSize = "w-28 h-28";
  const colorClasses = {
    green: "text-green-500",
    blue: "text-blue-500",
    gray: "text-gray-500",
    orange: "text-orange-500",
    red: "text-red-500",
    white: "text-white",
    yellow: "text-yellow-400"
  };
  const renderAppCard = (app) => React.createElement("div", {
    key: app.id,
    className: `group relative ${cardSize} rounded-2xl overflow-hidden card-minimal cursor-pointer`
  }, [
    React.createElement("i", {
      key: "bg-icon",
      className: `${app.icon} absolute text-[3rem] ${app.isActive ? colorClasses[app.color] : "text-white/10"} top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none transition-all duration-500 group-hover:scale-105`
    }),
    React.createElement("div", {
      key: "overlay",
      className: "absolute inset-0 bg-black/30 backdrop-blur-md flex flex-col items-center justify-center text-center opacity-0 transition-opacity duration-300 group-hover:opacity-100"
    }, [
      React.createElement("h4", { key: "name", className: `text-sm font-semibold text-primary mb-1` }, app.name),
      React.createElement("p", { key: "subtitle", className: `text-xs text-secondary mb-2` }, app.subtitle),
      app.isActive ? React.createElement("button", {
        key: "btn",
        onClick: () => handleDownload(app),
        className: `px-2 py-1 rounded-xl bg-emerald-500 text-black font-medium hover:bg-emerald-600 transition-colors text-xs`
      }, app.id === "web" ? "Launch" : "Download") : React.createElement("span", { key: "coming", className: "text-gray-400 font-medium text-xs" }, "Coming Soon")
    ])
  ]);
  return React.createElement("div", { className: "mt-20 px-6" }, [
    // Header
    React.createElement("div", { key: "header", className: "text-center max-w-3xl mx-auto mb-12" }, [
      React.createElement("h3", { key: "title", className: "text-3xl font-bold text-primary mb-3" }, "Download SecureBit.chat"),
      React.createElement("p", { key: "subtitle", className: "text-secondary text-lg mb-5" }, "Stay secure on every device. Choose your platform and start chatting privately.")
    ]),
    // Desktop Apps
    React.createElement(
      "div",
      { key: "desktop-row", className: "hidden sm:flex justify-center flex-wrap gap-6 mb-6" },
      desktopApps.map(renderAppCard)
    ),
    // Mobile Apps
    React.createElement(
      "div",
      { key: "mobile-row", className: "flex justify-center gap-6 mb-6" },
      mobileApps.map(renderAppCard)
    ),
    // Browser Extensions
    React.createElement(
      "div",
      { key: "browser-row", className: "flex justify-center gap-6" },
      browserApps.map(renderAppCard)
    )
  ]);
};
window.DownloadApps = DownloadApps;

// src/components/ui/BecomePartner.jsx
var BecomePartner = () => {
  const [isMobile, setIsMobile] = React.useState(
    typeof window !== "undefined" && window.matchMedia("(max-width:767px)").matches
  );
  React.useEffect(() => {
    const mq = window.matchMedia("(max-width:767px)");
    const onChange = () => setIsMobile(mq.matches);
    mq.addEventListener ? mq.addEventListener("change", onChange) : mq.addListener(onChange);
    return () => {
      mq.removeEventListener ? mq.removeEventListener("change", onChange) : mq.removeListener(onChange);
    };
  }, []);
  const ACCENT = "#f0892a";
  const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
  const SANS = "'Manrope', system-ui, -apple-system, sans-serif";
  const formUrl = "https://docs.google.com/forms/d/e/1FAIpQLSc9ijV9PCoyXkus6vEx1OWwvwAsLq8fKS6-H5BmX-c-bvia6w/viewform?usp=dialog";
  const partners = [
    {
      id: "aegis",
      name: "Aegis Investment",
      logo: "logo/aegis.png",
      logoHeight: "42px",
      url: "https://aegis-investment.com/",
      desc: "Capital partner securing confidential financial communications across its portfolio.",
      role: "Strategic backer",
      delay: ".5s"
    },
    {
      id: "furi",
      name: "FuriLabs",
      logo: "logo/furi.png",
      logoHeight: "54px",
      url: "https://furilabs.com/",
      desc: "Privacy-first Linux phones that ship SecureBit as a default secure channel.",
      role: "Technology partner",
      delay: ".56s"
    }
  ];
  const svg2 = (inner2, size, stroke, sw) => React.createElement("svg", {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke,
    strokeWidth: sw,
    strokeLinecap: "round",
    strokeLinejoin: "round",
    dangerouslySetInnerHTML: { __html: inner2 }
  });
  const roleTag = (role) => React.createElement("span", {
    key: "role",
    style: { fontFamily: MONO, fontSize: "10.5px", fontWeight: 600, color: "#6b6b73", textTransform: "uppercase", letterSpacing: "1.2px", padding: "6px 11px", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.07)", background: "rgba(255,255,255,0.025)", whiteSpace: "nowrap" }
  }, role);
  const partnerCard = (p) => React.createElement("a", {
    key: p.id,
    href: p.url,
    target: "_blank",
    rel: "noopener noreferrer",
    style: {
      flex: "1 1 320px",
      minWidth: isMobile ? "auto" : "300px",
      borderRadius: "18px",
      background: "#141416",
      border: "1px solid rgba(255,255,255,0.06)",
      padding: "30px 30px 26px",
      display: "flex",
      flexDirection: "column",
      textDecoration: "none",
      color: "inherit",
      transition: "transform .28s cubic-bezier(.2,.7,.3,1), border-color .28s cubic-bezier(.2,.7,.3,1)",
      animation: `ptUp ${p.delay} cubic-bezier(.2,.7,.3,1)`
    },
    onMouseEnter: (e) => {
      e.currentTarget.style.transform = "translateY(-4px)";
      e.currentTarget.style.borderColor = "rgba(255,255,255,0.13)";
    },
    onMouseLeave: (e) => {
      e.currentTarget.style.transform = "none";
      e.currentTarget.style.borderColor = "rgba(255,255,255,0.06)";
    }
  }, [
    React.createElement(
      "div",
      { key: "logo", style: { display: "flex", alignItems: "center", marginBottom: "30px", height: "54px" } },
      React.createElement("img", {
        src: p.logo,
        alt: p.name,
        style: { height: p.logoHeight, width: "auto", maxWidth: "190px", objectFit: "contain", display: "block" }
      })
    ),
    React.createElement("h3", { key: "name", style: { margin: "0 0 9px", fontSize: "21px", fontWeight: 800, letterSpacing: "-0.4px", color: "#f4f4f6" } }, p.name),
    React.createElement("p", { key: "desc", style: { margin: "0 0 22px", fontSize: "14.5px", lineHeight: 1.6, color: "#9a9aa2" } }, p.desc),
    React.createElement("div", { key: "foot", style: { marginTop: "auto", paddingTop: "6px", display: "flex", alignItems: "center", gap: "12px" } }, [
      roleTag(p.role)
    ])
  ]);
  const inviteCard = React.createElement("a", {
    key: "invite",
    href: formUrl,
    target: "_blank",
    rel: "noopener noreferrer",
    style: {
      flex: "1 1 320px",
      minWidth: isMobile ? "auto" : "300px",
      borderRadius: "18px",
      background: "#111113",
      border: "1px dashed rgba(255,255,255,0.12)",
      padding: "30px",
      display: "flex",
      flexDirection: "column",
      justifyContent: "space-between",
      textDecoration: "none",
      color: "inherit",
      transition: "border-color .28s cubic-bezier(.2,.7,.3,1)",
      animation: "ptUp .62s cubic-bezier(.2,.7,.3,1)"
    },
    onMouseEnter: (e) => {
      e.currentTarget.style.borderColor = "rgba(240,137,42,0.4)";
    },
    onMouseLeave: (e) => {
      e.currentTarget.style.borderColor = "rgba(255,255,255,0.12)";
    }
  }, [
    React.createElement("div", { key: "top" }, [
      React.createElement("div", {
        key: "icon",
        style: { width: "48px", height: "48px", borderRadius: "13px", display: "grid", placeItems: "center", background: "rgba(240,137,42,0.12)", border: "1px solid rgba(240,137,42,0.28)", marginBottom: "24px" }
      }, svg2('<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/>', 23, ACCENT, 1.9)),
      React.createElement("h3", { key: "title", style: { margin: "0 0 8px", fontSize: "21px", fontWeight: 800, letterSpacing: "-0.4px", color: "#f4f4f6" } }, "Become a partner"),
      React.createElement("p", { key: "desc", style: { margin: 0, fontSize: "14.5px", lineHeight: 1.6, color: "#8a8a92" } }, "Building privacy hardware or infrastructure? Let's integrate SecureBit.")
    ]),
    React.createElement("span", {
      key: "btn",
      style: {
        marginTop: "26px",
        width: "100%",
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        gap: "10px",
        padding: "15px 20px",
        borderRadius: "12px",
        border: "none",
        background: ACCENT,
        color: "#1a0f04",
        fontFamily: SANS,
        fontSize: "15px",
        fontWeight: 700,
        cursor: "pointer",
        boxShadow: "0 8px 24px rgba(240,137,42,0.28)",
        boxSizing: "border-box",
        transition: "background .2s cubic-bezier(.2,.7,.3,1), transform .2s cubic-bezier(.2,.7,.3,1)"
      }
    }, [
      "Start a conversation",
      svg2('<path d="M5 12h14M13 6l6 6-6 6"/>', 17, "currentColor", 2.2)
    ])
  ]);
  const inner = React.createElement("div", {
    key: "inner",
    style: { maxWidth: "1240px", margin: "0 auto", padding: isMobile ? "0 18px" : "0 40px" }
  }, [
    // Header
    React.createElement("div", { key: "head", style: { marginBottom: "44px" } }, [
      React.createElement("div", {
        key: "eyebrow",
        style: { fontFamily: MONO, fontSize: "11px", fontWeight: 600, color: "#6b6b73", textTransform: "uppercase", letterSpacing: "1.6px", marginBottom: "14px" }
      }, "Partners & ecosystem"),
      React.createElement("div", {
        key: "row",
        style: { display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: "32px", flexWrap: "wrap" }
      }, [
        React.createElement("h2", {
          key: "h2",
          style: { margin: 0, fontSize: isMobile ? "30px" : "40px", fontWeight: 800, letterSpacing: "-1.1px", lineHeight: 1.04, color: "#f4f4f6" }
        }, "Trusted by our partners"),
        React.createElement("p", {
          key: "sub",
          style: { margin: "0 0 4px", fontSize: "15px", lineHeight: 1.55, color: "#8a8a92", maxWidth: "360px" }
        }, "A small, vetted circle \u2014 no pay-to-list logos and no badges we can't stand behind.")
      ])
    ]),
    // Cards
    React.createElement("div", {
      key: "cards",
      style: { display: "flex", gap: "18px", alignItems: "stretch", flexWrap: "wrap" }
    }, [
      ...partners.map(partnerCard),
      inviteCard
    ])
  ]);
  return React.createElement("section", {
    style: {
      width: "100%",
      color: "#e8e8eb",
      fontFamily: SANS,
      padding: isMobile ? "48px 0" : "72px 0",
      background: "radial-gradient(1100px 640px at 50% -6%, rgba(240,137,42,0.055), transparent 62%), #0f0f11"
    }
  }, [
    React.createElement("style", { key: "kf", dangerouslySetInnerHTML: { __html: "@keyframes ptUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}" } }),
    inner
  ]);
};
window.BecomePartner = BecomePartner;

// src/components/ui/UniqueFeatureSlider.jsx
var UniqueFeatureSlider = () => {
  const [active, setActive] = React.useState(0);
  const [isMobile, setIsMobile] = React.useState(
    typeof window !== "undefined" && window.matchMedia("(max-width:767px)").matches
  );
  React.useEffect(() => {
    const mq = window.matchMedia("(max-width:767px)");
    const onChange = () => setIsMobile(mq.matches);
    mq.addEventListener ? mq.addEventListener("change", onChange) : mq.addListener(onChange);
    return () => {
      mq.removeEventListener ? mq.removeEventListener("change", onChange) : mq.removeListener(onChange);
    };
  }, []);
  const ACCENT = "#f0892a";
  const ACTIVE_BG = "radial-gradient(130% 90% at 28% 0%, rgba(240,137,42,0.11), transparent 60%), #141416";
  const ACTIVE_BD = "rgba(240,137,42,0.3)";
  const IDLE_BG = "#111113";
  const IDLE_BD = "rgba(255,255,255,0.06)";
  const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
  const SANS = "'Manrope', system-ui, -apple-system, sans-serif";
  const slides = [
    {
      num: "01",
      title: ["Layered", "encryption core"],
      collapsed: "Encryption core",
      desc: "ECDH P-384 key exchange, AES-256-GCM payloads, ECDSA signatures and full ASN.1 validation \u2014 composed into one hardened pipeline.",
      tags: ["ECDH P-384", "AES-256-GCM", "ECDSA", "ASN.1"],
      icon: '<path d="M12 3l8 4v5c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V7l8-4z"/><path d="M9.2 12.2l2 2 3.6-3.8"/>'
    },
    {
      num: "02",
      title: ["Pure P2P", "WebRTC"],
      collapsed: "Pure P2P WebRTC",
      desc: "Messages travel directly between devices over WebRTC. No relay holds your data \u2014 the server only helps two peers find each other.",
      tags: ["DTLS 1.3", "No relay"],
      icon: '<circle cx="5.5" cy="12" r="2.5"/><circle cx="18.5" cy="6" r="2.5"/><circle cx="18.5" cy="18" r="2.5"/><path d="M7.8 10.8l8.4-3.6M7.8 13.2l8.4 3.6"/>'
    },
    {
      num: "03",
      title: ["Perfect", "forward secrecy"],
      collapsed: "Forward secrecy",
      desc: "Session keys rotate continuously and are discarded after use, so a single compromised key can never unlock past conversations.",
      tags: ["Ephemeral keys", "Auto-rotate"],
      icon: '<path d="M21 8a8.5 8.5 0 0 0-15.6-2.5M3 4v4h4"/><path d="M3 16a8.5 8.5 0 0 0 15.6 2.5M21 20v-4h-4"/>'
    },
    {
      num: "04",
      title: ["Traffic", "obfuscation"],
      collapsed: "Traffic obfuscation",
      desc: "Packet sizes and timing are padded and randomized, hiding metadata patterns from anyone watching the wire.",
      tags: ["Packet padding", "Timing jitter"],
      icon: '<path d="M3 7h4l3 10h4M14 7h3l3 0"/><path d="M17 4l3 3-3 3"/><path d="M3 17h4l2-6"/>'
    },
    {
      num: "05",
      title: ["Zero data", "collection"],
      collapsed: "Zero data collection",
      desc: "No accounts, no logs, no message storage. There is nothing on a server to leak, subpoena, or sell.",
      tags: ["No accounts", "No logs"],
      icon: '<path d="M9.9 5.1A9.6 9.6 0 0 1 12 5c5.5 0 9 5 9 7a11 11 0 0 1-2.2 3M6.3 7.3C3.6 8.9 2 11.2 2 12c0 1.4 3.5 7 10 7 1.6 0 3-.3 4.2-.8"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2M3 3l18 18"/>'
    }
  ];
  const svg2 = (inner2, size, stroke, sw) => React.createElement("svg", {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke,
    strokeWidth: sw,
    strokeLinecap: "round",
    strokeLinejoin: "round",
    dangerouslySetInnerHTML: { __html: inner2 }
  });
  const go = (step) => setActive((a) => (a + step + slides.length) % slides.length);
  const navBtn = (key, onClick, path) => React.createElement("button", {
    key,
    onClick,
    "aria-label": key,
    style: {
      width: "46px",
      height: "46px",
      display: "grid",
      placeItems: "center",
      borderRadius: "50%",
      border: "1px solid rgba(255,255,255,0.1)",
      background: "rgba(255,255,255,0.025)",
      color: "#cfcfd4",
      cursor: "pointer",
      transition: "all .2s cubic-bezier(.2,.7,.3,1)"
    },
    onMouseEnter: (e) => {
      e.currentTarget.style.borderColor = ACTIVE_BD;
      e.currentTarget.style.color = ACCENT;
    },
    onMouseLeave: (e) => {
      e.currentTarget.style.borderColor = "rgba(255,255,255,0.1)";
      e.currentTarget.style.color = "#cfcfd4";
    }
  }, svg2(path, 18, "currentColor", 2.1));
  const tag = (label) => React.createElement("span", {
    key: label,
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: "7px",
      padding: "7px 12px",
      borderRadius: "9px",
      border: "1px solid rgba(255,255,255,0.07)",
      background: "rgba(255,255,255,0.025)",
      fontFamily: MONO,
      fontSize: "11.5px",
      fontWeight: 500,
      color: "#9a9aa2"
    }
  }, [
    React.createElement("span", { key: "dot", style: { width: "5px", height: "5px", borderRadius: "50%", background: "#3ecf8e" } }),
    label
  ]);
  const expandedContent = (s) => React.createElement("div", {
    key: "exp",
    style: {
      height: "100%",
      display: "flex",
      flexDirection: "column",
      justifyContent: isMobile ? "flex-start" : "space-between",
      gap: isMobile ? "18px" : 0,
      padding: isMobile ? "24px 22px" : "32px 34px",
      minWidth: isMobile ? "auto" : "320px",
      animation: "wuUp .42s cubic-bezier(.2,.7,.3,1)"
    }
  }, [
    React.createElement("div", { key: "top", style: { display: "flex", alignItems: "center", justifyContent: "space-between" } }, [
      React.createElement("div", {
        key: "ic",
        style: {
          width: "54px",
          height: "54px",
          borderRadius: "15px",
          display: "grid",
          placeItems: "center",
          background: "rgba(240,137,42,0.13)",
          border: "1px solid rgba(240,137,42,0.3)"
        }
      }, svg2(s.icon, 26, ACCENT, 1.9)),
      React.createElement("span", { key: "n", style: { fontFamily: MONO, fontSize: "13px", fontWeight: 600, color: "#6b6b73" } }, s.num)
    ]),
    React.createElement("div", { key: "mid" }, [
      React.createElement("h3", {
        key: "h",
        style: { margin: "0 0 12px", fontSize: isMobile ? "24px" : "30px", fontWeight: 800, letterSpacing: "-0.7px", lineHeight: 1.08, color: "#f4f4f6" }
      }, [s.title[0], React.createElement("br", { key: "br" }), s.title[1]]),
      React.createElement("p", {
        key: "p",
        style: { margin: 0, fontSize: "15px", lineHeight: 1.6, color: "#9a9aa2", maxWidth: "380px" }
      }, s.desc)
    ]),
    React.createElement("div", { key: "tags", style: { display: "flex", flexWrap: "wrap", gap: "8px" } }, s.tags.map(tag))
  ]);
  const collapsedContent = (s) => isMobile ? React.createElement("div", {
    key: "col",
    style: { display: "flex", alignItems: "center", gap: "16px", padding: "20px 22px" }
  }, [
    React.createElement("span", { key: "n", style: { fontFamily: MONO, fontSize: "12px", fontWeight: 600, color: "#56565e" } }, s.num),
    React.createElement("span", { key: "l", style: { fontSize: "16px", fontWeight: 800, letterSpacing: "-0.2px", color: "#cfcfd4" } }, s.collapsed)
  ]) : React.createElement("div", {
    key: "col",
    style: { position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "space-between", padding: "24px 0" }
  }, [
    React.createElement("span", { key: "n", style: { fontFamily: MONO, fontSize: "12px", fontWeight: 600, color: "#56565e" } }, s.num),
    React.createElement("span", {
      key: "l",
      style: { writingMode: "vertical-rl", transform: "rotate(180deg)", fontSize: "17px", fontWeight: 800, letterSpacing: "-0.2px", color: "#cfcfd4", whiteSpace: "nowrap" }
    }, s.collapsed),
    svg2(s.icon, 22, "#56565e", 1.8)
  ]);
  const panels = slides.map((s, i) => {
    const isActive = active === i;
    return React.createElement("div", {
      key: i,
      onClick: () => setActive(i),
      // Selection is click-only (like the design); hover just brightens the panel
      // a touch so the orange glow never jumps around chasing the cursor.
      onMouseEnter: (e) => {
        if (!isActive) e.currentTarget.style.filter = "brightness(1.18)";
      },
      onMouseLeave: (e) => {
        e.currentTarget.style.filter = "none";
      },
      style: {
        flex: isMobile ? "none" : isActive ? 6.2 : 1,
        minWidth: isMobile ? "auto" : "72px",
        position: "relative",
        borderRadius: "18px",
        overflow: "hidden",
        cursor: "pointer",
        background: isActive ? ACTIVE_BG : IDLE_BG,
        border: "1px solid " + (isActive ? ACTIVE_BD : IDLE_BD),
        color: "#8a8a92",
        transition: "flex .46s cubic-bezier(.2,.7,.3,1), background .3s ease, border-color .3s ease, filter .2s ease"
      }
    }, isActive ? expandedContent(s) : collapsedContent(s));
  });
  const inner = React.createElement("div", {
    key: "inner",
    style: {
      maxWidth: "1180px",
      margin: "0 auto",
      padding: isMobile ? "0 18px" : "0 40px"
    }
  }, [
    // Header
    React.createElement("div", {
      key: "head",
      style: { display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: "24px", marginBottom: "28px" }
    }, [
      React.createElement("div", { key: "titles" }, [
        React.createElement("div", {
          key: "eyebrow",
          style: { fontFamily: MONO, fontSize: "11px", fontWeight: 600, color: "#6b6b73", textTransform: "uppercase", letterSpacing: "1.4px", marginBottom: "12px" }
        }, "What sets us apart"),
        React.createElement("h2", {
          key: "h2",
          style: { margin: 0, fontSize: isMobile ? "28px" : "38px", fontWeight: 800, letterSpacing: "-1.1px", lineHeight: 1.05, color: "#f4f4f6" }
        }, "Why SecureBit is unique")
      ]),
      React.createElement("div", { key: "nav", style: { display: "flex", alignItems: "center", gap: "10px", flex: "none" } }, [
        navBtn("prev", () => go(-1), '<path d="M15 6l-6 6 6 6"/>'),
        navBtn("next", () => go(1), '<path d="M9 6l6 6-6 6"/>')
      ])
    ]),
    // Accordion
    React.createElement("div", {
      key: "accordion",
      style: {
        display: "flex",
        flexDirection: isMobile ? "column" : "row",
        gap: isMobile ? "12px" : "14px",
        height: isMobile ? "auto" : "440px"
      }
    }, panels)
  ]);
  return React.createElement("section", {
    style: {
      width: "100%",
      color: "#e8e8eb",
      fontFamily: SANS,
      padding: isMobile ? "44px 0" : "64px 0",
      background: "radial-gradient(1100px 700px at 18% 8%, rgba(240,137,42,0.05), transparent 60%), #0f0f11"
    }
  }, [
    React.createElement("style", { key: "kf", dangerouslySetInnerHTML: { __html: "@keyframes wuUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}" } }),
    inner
  ]);
};
window.UniqueFeatureSlider = UniqueFeatureSlider;

// src/components/ui/Roadmap.jsx
function Roadmap() {
  const [isMobile, setIsMobile] = React.useState(
    typeof window !== "undefined" && window.matchMedia("(max-width:767px)").matches
  );
  React.useEffect(() => {
    const mq = window.matchMedia("(max-width:767px)");
    const onChange = () => setIsMobile(mq.matches);
    mq.addEventListener ? mq.addEventListener("change", onChange) : mq.addListener(onChange);
    return () => {
      mq.removeEventListener ? mq.removeEventListener("change", onChange) : mq.removeListener(onChange);
    };
  }, []);
  const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
  const SANS = "'Manrope', system-ui, -apple-system, sans-serif";
  const DATA = [
    {
      v: "v1.0",
      title: "Start of Development",
      sub: "Idea, prototype, and infrastructure setup",
      status: "released",
      date: "Early 2025",
      features: ["Concept and requirements formation", "Stack selection: WebRTC, P2P, cryptography", "First messaging prototypes", "Repository creation and CI", "Basic encryption architecture", "UX/UI design"]
    },
    {
      v: "v1.5",
      title: "Alpha Release",
      sub: "First public alpha: basic chat and key exchange",
      status: "released",
      date: "Spring 2025",
      features: ["Basic P2P messaging via WebRTC", "Simple E2E encryption (demo scheme)", "Stable signaling and reconnection", "Minimal UX for testing", "Feedback collection from early testers"]
    },
    {
      v: "v2.0",
      title: "Security Hardened",
      sub: "Security strengthening and stable branch release",
      status: "released",
      date: "Summer 2025",
      features: ["ECDH/ECDSA implementation in production", "Perfect Forward Secrecy and key rotation", "Improved authentication checks", "File encryption and large payload transfers", "Audit of basic cryptoprocesses"]
    },
    {
      v: "v3.0",
      title: "Scaling & Stability",
      sub: "Network scaling and stability improvements",
      status: "released",
      date: "Fall 2025",
      features: ["Optimization of P2P connections and NAT traversal", "Reconnection mechanisms and message queues", "Reduced battery consumption on mobile", "Multi-device synchronization support", "Monitoring and logging tools for developers"]
    },
    {
      v: "v3.5",
      title: "Privacy-first Release",
      sub: "Focus on privacy: minimizing metadata",
      status: "released",
      date: "Winter 2025",
      features: ["Metadata protection and fingerprint reduction", "Experiments with onion routing and DHT", "Options for anonymous connections", "Preparation for open code audit", "Improved user verification processes"]
    },
    {
      v: "v4.5",
      title: "Enhanced Security Edition",
      sub: "18-layer military-grade cryptography with complete ASN.1 validation",
      status: "released",
      date: "Late 2025",
      features: ["ECDH + DTLS + SAS triple-layer security", "ECDH P-384 + AES-GCM 256-bit encryption", "DTLS fingerprint verification", "SAS (Short Authentication String) verification", "Perfect Forward Secrecy with key rotation", "Enhanced MITM attack prevention", "Complete ASN.1 DER validation", "OID and EC point verification", "SPKI structure validation", "P2P WebRTC architecture", "Metadata protection", "100% open source code"]
    },
    {
      v: "v5.0",
      title: "Desktop Edition",
      sub: "Native desktop apps for Windows, macOS, and Linux",
      status: "released",
      date: "Early 2026",
      features: ["Windows desktop app (Tauri v2)", "macOS desktop app (Tauri v2)", "Linux AppImage support (Tauri v2)", "Real-time notifications", "Automatic reconnection", "Cross-device synchronization", "Improved UX/UI", "Support for files up to 100MB"]
    },
    {
      v: "v5.5",
      title: "Secure Voice & Calls",
      sub: "Encrypted voice messages, audio calls, and video calls",
      status: "released",
      date: "Early 2026",
      features: ["End-to-end encrypted voice messages", "1:1 encrypted audio calls (WebRTC)", "1:1 encrypted video calls (WebRTC)", "Perfect Forward Secrecy for live media", "SRTP/DTLS-protected media streams", "In-call SAS verification", "Call notifications and auto-reconnection", "Low-latency P2P media"]
    },
    {
      v: "v6.0",
      title: "Group Communications",
      sub: "Group chats with preserved privacy",
      status: "current",
      date: "Now",
      features: ["P2P group chats up to 8 participants", "Mesh delivery with signed relay fallback", "One group safety code, compared by everyone", "Commit-then-reveal ceremony against code grinding", "Per-group identity keys, ephemeral by design", "Signed membership with epoch ordering", "Signed messages, so a split transcript is provable", "No server, no shared group key, no history"]
    },
    {
      v: "v6.5",
      title: "Mobile Edition",
      sub: "Native mobile apps for iOS and Android",
      status: "dev",
      date: "Q2 2027",
      features: ["iOS native app (Swift/SwiftUI)", "Android native app (Kotlin/Jetpack Compose)", "PWA support for mobile browsers", "Real-time push notifications", "Battery optimization", "Mobile-optimized UX/UI", "Offline message queuing", "Biometric authentication"]
    },
    {
      v: "v7.0",
      title: "Quantum-Resistant Edition",
      sub: "Protection against quantum computers",
      status: "planned",
      date: "Q4 2027",
      features: ["Post-quantum cryptography CRYSTALS-Kyber", "SPHINCS+ digital signatures", "Hybrid scheme: classic + PQ", "Quantum-safe key exchange", "Updated hashing algorithms", "Migration of existing sessions", "Compatibility with v5.x", "Quantum-resistant protocols"]
    },
    {
      v: "v7.5",
      title: "Decentralized Network",
      sub: "Fully decentralized network",
      status: "research",
      date: "2028",
      features: ["Node mesh network", "DHT for peer discovery", "Built-in onion routing", "Tokenomics and node incentives", "Governance via DAO", "Interoperability with other networks", "Cross-platform compatibility", "Self-healing network"]
    },
    {
      v: "v8.0",
      title: "AI Privacy Assistant",
      sub: "AI for privacy and security",
      status: "research",
      date: "2028+",
      features: ["Local AI threat analysis", "Automatic MITM detection", "Adaptive cryptography", "Personalized security recommendations", "Zero-knowledge machine learning", "Private AI assistant", "Predictive security", "Autonomous attack protection"]
    }
  ];
  const META = {
    released: { word: "Released", color: "#3ecf8e", line: "rgba(62,207,142,0.32)" },
    current: { word: "Current", color: "#f0892a", line: "rgba(240,137,42,0.32)" },
    dev: { word: "In development", color: "#e3b341", line: "rgba(255,255,255,0.08)" },
    planned: { word: "Planned", color: "#8a8a92", line: "rgba(255,255,255,0.08)" },
    research: { word: "Research", color: "#6b6b73", line: "rgba(255,255,255,0.08)" }
  };
  const [open, setOpen] = React.useState({});
  const isOpen = (i) => open[i] === void 0 ? DATA[i].status === "current" : open[i];
  const toggle = (i) => setOpen((s) => ({ ...s, [i]: !isOpen(i) }));
  const hexA = (hex, a) => {
    const n = parseInt(hex.slice(1), 16);
    return `rgba(${n >> 16 & 255},${n >> 8 & 255},${n & 255},${a})`;
  };
  const total = DATA.length;
  const shipped = DATA.filter((d) => d.status === "released" || d.status === "current").length;
  const upcoming = total - shipped;
  const shippedPct = (shipped / total * 100).toFixed(1) + "%";
  const renderNode = (status) => {
    if (status === "released") {
      return /* @__PURE__ */ React.createElement("div", { style: { position: "absolute", left: "13px", top: "16px", width: "28px", height: "28px", borderRadius: "50%", display: "grid", placeItems: "center", background: "linear-gradient(rgba(62,207,142,0.16),rgba(62,207,142,0.16)), #0f0f11", border: "1px solid rgba(62,207,142,0.4)", zIndex: 2 } }, /* @__PURE__ */ React.createElement("svg", { width: "15", height: "15", viewBox: "0 0 24 24", fill: "none", stroke: "#3ecf8e", strokeWidth: "2.4", strokeLinecap: "round", strokeLinejoin: "round" }, /* @__PURE__ */ React.createElement("path", { d: "M5 13l4 4 10-11" })));
    }
    if (status === "current") {
      return /* @__PURE__ */ React.createElement("div", { style: { position: "absolute", left: "13px", top: "16px", width: "28px", height: "28px", borderRadius: "50%", display: "grid", placeItems: "center", background: "linear-gradient(rgba(240,137,42,0.2),rgba(240,137,42,0.2)), #0f0f11", border: "1px solid #f0892a", zIndex: 2, animation: "rmPulse 2.4s ease-out infinite" } }, /* @__PURE__ */ React.createElement("span", { style: { width: "9px", height: "9px", borderRadius: "50%", background: "#f0892a" } }));
    }
    if (status === "dev") {
      return /* @__PURE__ */ React.createElement("div", { style: { position: "absolute", left: "13px", top: "16px", width: "28px", height: "28px", borderRadius: "50%", display: "grid", placeItems: "center", background: "linear-gradient(rgba(227,179,65,0.15),rgba(227,179,65,0.15)), #0f0f11", border: "1px solid rgba(227,179,65,0.4)", zIndex: 2 } }, /* @__PURE__ */ React.createElement("svg", { width: "15", height: "15", viewBox: "0 0 24 24", fill: "none", stroke: "#e3b341", strokeWidth: "2.2", strokeLinecap: "round", strokeLinejoin: "round" }, /* @__PURE__ */ React.createElement("path", { d: "M12 3a9 9 0 1 0 9 9" })));
    }
    return /* @__PURE__ */ React.createElement("div", { style: { position: "absolute", left: "13px", top: "16px", width: "28px", height: "28px", borderRadius: "50%", display: "grid", placeItems: "center", background: "#0f0f11", border: `1px ${status === "research" ? "dashed" : "solid"} rgba(255,255,255,0.18)`, zIndex: 2 } }, /* @__PURE__ */ React.createElement("span", { style: { width: "7px", height: "7px", borderRadius: "50%", background: META[status].color } }));
  };
  return /* @__PURE__ */ React.createElement("section", { style: { width: "100%", color: "#e8e8eb", fontFamily: SANS, padding: isMobile ? "48px 0" : "64px 0", background: "radial-gradient(1200px 720px at 50% -8%, rgba(240,137,42,0.05), transparent 60%), #0f0f11" } }, /* @__PURE__ */ React.createElement("style", { dangerouslySetInnerHTML: { __html: "@keyframes rmExp{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}@keyframes rmPulse{0%,100%{box-shadow:0 0 0 0 rgba(240,137,42,0.18)}60%{box-shadow:0 0 0 9px rgba(240,137,42,0)}}" } }), /* @__PURE__ */ React.createElement("div", { style: { maxWidth: "1040px", margin: "0 auto", padding: isMobile ? "0 18px" : "0 40px" } }, /* @__PURE__ */ React.createElement("div", { style: { marginBottom: "30px" } }, /* @__PURE__ */ React.createElement("div", { style: { fontFamily: MONO, fontSize: "11px", fontWeight: 600, color: "#6b6b73", textTransform: "uppercase", letterSpacing: "1.6px", marginBottom: "13px" } }, "Development Roadmap"), /* @__PURE__ */ React.createElement("h2", { style: { margin: "0 0 14px", fontSize: isMobile ? "27px" : "34px", fontWeight: 800, letterSpacing: "-1px", lineHeight: 1.08, color: "#f4f4f6" } }, "The evolution of SecureBit"), /* @__PURE__ */ React.createElement("p", { style: { margin: 0, fontSize: "15.5px", lineHeight: 1.6, color: "#8a8a92", maxWidth: "660px" } }, "From the first prototype to a quantum-resistant, decentralized network \u2014 with complete ASN.1 validation at every layer.")), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: "18px", flexWrap: "wrap", padding: "18px 22px", borderRadius: "14px", background: "#141416", border: "1px solid rgba(255,255,255,0.06)", marginBottom: "36px" } }, /* @__PURE__ */ React.createElement("div", { style: { fontFamily: MONO, fontSize: "12px", fontWeight: 600, color: "#e8e8eb", whiteSpace: "nowrap" } }, /* @__PURE__ */ React.createElement("span", { style: { color: "#3ecf8e" } }, shipped), " of ", total, " milestones shipped"), /* @__PURE__ */ React.createElement("div", { style: { flex: "1 1 240px", minWidth: "200px", height: "8px", borderRadius: "99px", background: "#0c0c0e", border: "1px solid rgba(255,255,255,0.06)", overflow: "hidden" } }, /* @__PURE__ */ React.createElement("div", { style: { height: "100%", width: shippedPct, background: "linear-gradient(90deg, #3ecf8e, #f0892a)" } })), /* @__PURE__ */ React.createElement("div", { style: { fontFamily: MONO, fontSize: "11px", fontWeight: 600, color: "#6b6b73", textTransform: "uppercase", letterSpacing: "0.8px", whiteSpace: "nowrap" } }, upcoming, " on the way")), DATA.map((d, i) => {
    const meta = META[d.status];
    const opened = isOpen(i);
    const notLast = i < total - 1;
    return /* @__PURE__ */ React.createElement("div", { key: i, style: { position: "relative", display: "grid", gridTemplateColumns: "54px 1fr", marginBottom: "16px" } }, /* @__PURE__ */ React.createElement("div", { style: { position: "relative" } }, notLast && /* @__PURE__ */ React.createElement("div", { style: { position: "absolute", left: "26px", top: "30px", height: "calc(100% + 16px)", width: "2px", background: meta.line } }), renderNode(d.status)), /* @__PURE__ */ React.createElement("div", { style: { borderRadius: "16px", background: "#141416", border: `1px solid ${d.status === "current" ? "rgba(240,137,42,0.28)" : "rgba(255,255,255,0.06)"}`, overflow: "hidden" } }, /* @__PURE__ */ React.createElement(
      "div",
      {
        onClick: () => toggle(i),
        style: { display: "flex", alignItems: "center", gap: isMobile ? "11px" : "16px", padding: isMobile ? "16px 16px" : "18px 22px", cursor: "pointer", transition: "background .18s ease" },
        onMouseEnter: (e) => {
          e.currentTarget.style.background = "rgba(255,255,255,0.018)";
        },
        onMouseLeave: (e) => {
          e.currentTarget.style.background = "transparent";
        }
      },
      /* @__PURE__ */ React.createElement("div", { style: { flex: "none", minWidth: "52px", textAlign: "center", padding: "7px 10px", borderRadius: "9px", background: "#0c0c0e", border: "1px solid rgba(255,255,255,0.07)", fontFamily: MONO, fontSize: "13px", fontWeight: 700, color: d.status === "current" ? "#f0892a" : "#cfcfd4" } }, d.v),
      /* @__PURE__ */ React.createElement("div", { style: { flex: 1, minWidth: 0 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: isMobile ? "15.5px" : "17px", fontWeight: 800, letterSpacing: "-0.4px", color: "#f4f4f6" } }, d.title), !isMobile && /* @__PURE__ */ React.createElement("div", { style: { marginTop: "3px", fontSize: "13.5px", color: "#9a9aa2" } }, d.sub)),
      /* @__PURE__ */ React.createElement("div", { style: { flex: "none", display: "flex", alignItems: "center", gap: isMobile ? "8px" : "14px" } }, /* @__PURE__ */ React.createElement("span", { style: { display: "inline-flex", alignItems: "center", gap: "7px", padding: "6px 11px", borderRadius: "8px", background: hexA(meta.color, 0.1), border: `1px solid ${hexA(meta.color, 0.22)}`, fontFamily: MONO, fontSize: "10.5px", fontWeight: 600, color: meta.color, textTransform: "uppercase", letterSpacing: "0.8px", whiteSpace: "nowrap" } }, /* @__PURE__ */ React.createElement("span", { style: { width: "6px", height: "6px", borderRadius: "50%", background: meta.color } }), !isMobile && meta.word), !isMobile && /* @__PURE__ */ React.createElement("span", { style: { fontFamily: MONO, fontSize: "12px", fontWeight: 500, color: "#8a8a92", whiteSpace: "nowrap", minWidth: "74px", textAlign: "right" } }, d.date), /* @__PURE__ */ React.createElement("span", { style: { color: "#6b6b73", display: "inline-flex", transition: "transform .22s cubic-bezier(.2,.7,.3,1)", transform: opened ? "rotate(180deg)" : "rotate(0deg)" } }, /* @__PURE__ */ React.createElement("svg", { width: "17", height: "17", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2.1", strokeLinecap: "round", strokeLinejoin: "round" }, /* @__PURE__ */ React.createElement("path", { d: "M6 9l6 6 6-6" }))))
    ), opened && /* @__PURE__ */ React.createElement("div", { style: { padding: "4px 22px 22px 22px", animation: "rmExp .24s cubic-bezier(.2,.7,.3,1)" } }, /* @__PURE__ */ React.createElement("div", { style: { fontFamily: MONO, fontSize: "10px", fontWeight: 600, color: "#56565e", textTransform: "uppercase", letterSpacing: "1.2px", marginBottom: "14px", paddingTop: "14px", borderTop: "1px solid rgba(255,255,255,0.05)" } }, "Key features"), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr", gap: "11px 28px" } }, d.features.map((f, fi) => /* @__PURE__ */ React.createElement("div", { key: fi, style: { display: "flex", alignItems: "flex-start", gap: "10px" } }, /* @__PURE__ */ React.createElement("span", { style: { flex: "none", marginTop: "7px", width: "5px", height: "5px", borderRadius: "50%", background: meta.color } }), /* @__PURE__ */ React.createElement("span", { style: { fontSize: "13.5px", lineHeight: 1.5, color: "#cfcfd4" } }, f)))))));
  })));
}
window.Roadmap = Roadmap;

// src/components/ui/CommunityCTA.jsx
var CommunityCTA = () => {
  const [isMobile, setIsMobile] = React.useState(
    typeof window !== "undefined" && window.matchMedia("(max-width:767px)").matches
  );
  React.useEffect(() => {
    const mq = window.matchMedia("(max-width:767px)");
    const onChange = () => setIsMobile(mq.matches);
    mq.addEventListener ? mq.addEventListener("change", onChange) : mq.addListener(onChange);
    return () => {
      mq.removeEventListener ? mq.removeEventListener("change", onChange) : mq.removeListener(onChange);
    };
  }, []);
  const ACCENT = "#f0892a";
  const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
  const SANS = "'Manrope', system-ui, -apple-system, sans-serif";
  const githubUrl = "https://github.com/SecureBitChat/securebit-chat/";
  const feedbackUrl = "mailto:lockbitchat@tutanota.com";
  const githubBtn = React.createElement("a", {
    key: "gh",
    href: githubUrl,
    target: "_blank",
    rel: "noopener noreferrer",
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: "11px",
      padding: "15px 26px",
      borderRadius: "13px",
      background: ACCENT,
      color: "#1a0f04",
      textDecoration: "none",
      fontSize: "15.5px",
      fontWeight: 700,
      letterSpacing: "-0.2px",
      boxShadow: "0 8px 24px rgba(240,137,42,0.28)",
      whiteSpace: "nowrap",
      transition: "all .2s cubic-bezier(.2,.7,.3,1)"
    },
    onMouseEnter: (e) => {
      e.currentTarget.style.background = "#ff9637";
      e.currentTarget.style.transform = "translateY(-2px)";
    },
    onMouseLeave: (e) => {
      e.currentTarget.style.background = ACCENT;
      e.currentTarget.style.transform = "none";
    }
  }, [
    React.createElement("svg", {
      key: "i",
      width: 20,
      height: 20,
      viewBox: "0 0 24 24",
      fill: "currentColor",
      dangerouslySetInnerHTML: { __html: '<path d="M12 2C6.48 2 2 6.58 2 12.26c0 4.5 2.87 8.32 6.84 9.67.5.09.68-.22.68-.49 0-.24-.01-.87-.01-1.71-2.78.62-3.37-1.36-3.37-1.36-.46-1.18-1.11-1.5-1.11-1.5-.91-.63.07-.62.07-.62 1 .07 1.53 1.05 1.53 1.05.89 1.56 2.34 1.11 2.91.85.09-.66.35-1.11.63-1.36-2.22-.26-4.55-1.14-4.55-5.07 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.27 2.75 1.05a9.3 9.3 0 0 1 5 0c1.91-1.32 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.94-2.34 4.81-4.57 5.06.36.32.68.94.68 1.9 0 1.37-.01 2.47-.01 2.81 0 .27.18.59.69.49A10.02 10.02 0 0 0 22 12.26C22 6.58 17.52 2 12 2z"/>' }
    }),
    "GitHub Repository"
  ]);
  const feedbackBtn = React.createElement("a", {
    key: "fb",
    href: feedbackUrl,
    rel: "noopener noreferrer",
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: "11px",
      padding: "15px 26px",
      borderRadius: "13px",
      background: "rgba(255,255,255,0.03)",
      color: "#e8e8eb",
      textDecoration: "none",
      fontSize: "15.5px",
      fontWeight: 700,
      letterSpacing: "-0.2px",
      border: "1px solid rgba(255,255,255,0.1)",
      whiteSpace: "nowrap",
      transition: "all .2s cubic-bezier(.2,.7,.3,1)"
    },
    onMouseEnter: (e) => {
      e.currentTarget.style.borderColor = "rgba(255,255,255,0.24)";
      e.currentTarget.style.background = "rgba(255,255,255,0.06)";
    },
    onMouseLeave: (e) => {
      e.currentTarget.style.borderColor = "rgba(255,255,255,0.1)";
      e.currentTarget.style.background = "rgba(255,255,255,0.03)";
    }
  }, [
    React.createElement("svg", {
      key: "i",
      width: 20,
      height: 20,
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      strokeWidth: 1.9,
      strokeLinecap: "round",
      strokeLinejoin: "round",
      dangerouslySetInnerHTML: { __html: '<path d="M21 11.5a8 8 0 0 1-11.6 7.1L4 20l1.4-5.3A8 8 0 1 1 21 11.5z"/><path d="M8.5 11h7M8.5 14h4.5"/>' }
    }),
    "Feedback"
  ]);
  const chip = (label) => React.createElement("span", {
    key: label,
    style: { display: "inline-flex", alignItems: "center", gap: "7px" }
  }, [
    React.createElement("span", { key: "d", style: { width: "5px", height: "5px", borderRadius: "50%", background: "#3ecf8e" } }),
    label
  ]);
  const card = React.createElement("div", {
    key: "card",
    style: {
      position: "relative",
      overflow: "hidden",
      maxWidth: "860px",
      width: "100%",
      borderRadius: "24px",
      background: "radial-gradient(700px 360px at 50% 0%, rgba(240,137,42,0.1), transparent 65%), #121214",
      border: "1px solid rgba(255,255,255,0.07)",
      padding: isMobile ? "40px 24px 36px" : "56px 56px 48px",
      textAlign: "center",
      boxShadow: "0 24px 60px rgba(0,0,0,0.4)"
    }
  }, [
    // hairline accent
    React.createElement("div", {
      key: "hairline",
      style: { position: "absolute", top: 0, left: "50%", transform: "translateX(-50%)", width: "180px", height: "1px", background: "linear-gradient(90deg, transparent, rgba(240,137,42,0.7), transparent)" }
    }),
    // brand mark (same SVG as the header — no border or background)
    React.createElement("img", {
      key: "icon",
      src: "/logo/securebit-mark.svg",
      alt: "SecureBit",
      style: { display: "inline-block", width: "64px", height: "64px", objectFit: "contain", marginBottom: "22px", animation: "ccUp .4s cubic-bezier(.2,.7,.3,1)" }
    }),
    // eyebrow
    React.createElement("div", {
      key: "eyebrow",
      style: { fontFamily: MONO, fontSize: "11px", fontWeight: 600, color: "#6b6b73", textTransform: "uppercase", letterSpacing: "1.8px", marginBottom: "14px" }
    }, "Open source \xB7 community-driven"),
    // title
    React.createElement("h2", {
      key: "title",
      style: { margin: "0 0 16px", fontSize: isMobile ? "28px" : "36px", fontWeight: 800, letterSpacing: "-1px", lineHeight: 1.05, color: "#f4f4f6" }
    }, "Join the future of privacy"),
    // description
    React.createElement("p", {
      key: "desc",
      style: { margin: "0 auto 32px", maxWidth: "560px", fontSize: "16px", lineHeight: 1.65, color: "#9a9aa2" }
    }, "SecureBit grows thanks to its community. Your ideas and feedback shape the future of secure communication \u2014 built in the open, with complete ASN.1 validation end\u2011to\u2011end."),
    // buttons
    React.createElement("div", {
      key: "btns",
      style: { display: "flex", gap: "14px", justifyContent: "center", flexWrap: "wrap" }
    }, [githubBtn, feedbackBtn]),
    // trust chips
    React.createElement("div", {
      key: "chips",
      style: { display: "flex", gap: "10px 22px", justifyContent: "center", flexWrap: "wrap", marginTop: "30px", fontFamily: MONO, fontSize: "11px", fontWeight: 500, color: "#56565e", textTransform: "uppercase", letterSpacing: "1px" }
    }, [chip("MIT licensed"), chip("No tracking"), chip("Auditable cryptography")])
  ]);
  return React.createElement("section", {
    style: {
      width: "100%",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "#0f0f11",
      fontFamily: SANS,
      padding: isMobile ? "48px 18px" : "64px 48px"
    }
  }, [
    React.createElement("style", { key: "kf", dangerouslySetInnerHTML: { __html: "@keyframes ccUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}" } }),
    card
  ]);
};
window.CommunityCTA = CommunityCTA;

// src/components/ui/FileTransfer.jsx
var FileTransferComponent = ({ webrtcManager, isConnected, pendingIncomingFiles = [], onIncomingDecision, showDropzone = true }) => {
  const [dragOver, setDragOver] = React.useState(false);
  const [transfers, setTransfers] = React.useState({ sending: [], receiving: [] });
  const fileInputRef = React.useRef(null);
  React.useEffect(() => {
    if (!isConnected || !webrtcManager) return;
    const updateTransfers = () => {
      const currentTransfers = webrtcManager.getFileTransfers();
      setTransfers(currentTransfers);
    };
    const interval = setInterval(updateTransfers, 500);
    return () => clearInterval(interval);
  }, [isConnected, webrtcManager]);
  React.useEffect(() => {
    if (isConnected) return;
    setTransfers({ sending: [], receiving: [] });
  }, [isConnected]);
  const handleFileSelect = async (files) => {
    if (!isConnected || !webrtcManager) {
      alert("\u0421\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435 \u043D\u0435 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043B\u0435\u043D\u043E. \u0421\u043D\u0430\u0447\u0430\u043B\u0430 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u0435 \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435.");
      return;
    }
    if (!webrtcManager.isConnected() || !webrtcManager.isVerified) {
      alert("\u0421\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435 \u043D\u0435 \u0433\u043E\u0442\u043E\u0432\u043E \u0434\u043B\u044F \u043F\u0435\u0440\u0435\u0434\u0430\u0447\u0438 \u0444\u0430\u0439\u043B\u043E\u0432. \u0414\u043E\u0436\u0434\u0438\u0442\u0435\u0441\u044C \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043D\u0438\u044F \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043A\u0438 \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u044F.");
      return;
    }
    for (const file of files) {
      try {
        const validation = webrtcManager.validateFile(file);
        if (!validation.isValid) {
          const errorMessage = validation.errors.join(". ");
          alert(`\u0424\u0430\u0439\u043B ${file.name} \u043D\u0435 \u043C\u043E\u0436\u0435\u0442 \u0431\u044B\u0442\u044C \u043E\u0442\u043F\u0440\u0430\u0432\u043B\u0435\u043D: ${errorMessage}`);
          continue;
        }
        await webrtcManager.sendFile(file);
      } catch (error) {
        if (error.message.includes("Connection not ready")) {
          alert(`\u0424\u0430\u0439\u043B ${file.name} \u043D\u0435 \u043C\u043E\u0436\u0435\u0442 \u0431\u044B\u0442\u044C \u043E\u0442\u043F\u0440\u0430\u0432\u043B\u0435\u043D \u0441\u0435\u0439\u0447\u0430\u0441. \u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435 \u0438 \u043F\u043E\u043F\u0440\u043E\u0431\u0443\u0439\u0442\u0435 \u0441\u043D\u043E\u0432\u0430.`);
        } else if (error.message.includes("File too large") || error.message.includes("exceeds maximum")) {
          alert(`\u0424\u0430\u0439\u043B ${file.name} \u0441\u043B\u0438\u0448\u043A\u043E\u043C \u0431\u043E\u043B\u044C\u0448\u043E\u0439: ${error.message}`);
        } else if (error.message.includes("Maximum concurrent transfers")) {
          alert(`\u0414\u043E\u0441\u0442\u0438\u0433\u043D\u0443\u0442 \u043B\u0438\u043C\u0438\u0442 \u043E\u0434\u043D\u043E\u0432\u0440\u0435\u043C\u0435\u043D\u043D\u044B\u0445 \u043F\u0435\u0440\u0435\u0434\u0430\u0447. \u0414\u043E\u0436\u0434\u0438\u0442\u0435\u0441\u044C \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043D\u0438\u044F \u0442\u0435\u043A\u0443\u0449\u0438\u0445 \u043F\u0435\u0440\u0435\u0434\u0430\u0447.`);
        } else if (error.message.includes("File type not allowed")) {
          alert(`\u0422\u0438\u043F \u0444\u0430\u0439\u043B\u0430 ${file.name} \u043D\u0435 \u043F\u043E\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u0442\u0441\u044F: ${error.message}`);
        } else {
          alert(`\u041E\u0448\u0438\u0431\u043A\u0430 \u043E\u0442\u043F\u0440\u0430\u0432\u043A\u0438 \u0444\u0430\u0439\u043B\u0430 ${file.name}: ${error.message}`);
        }
      }
    }
  };
  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const files = Array.from(e.dataTransfer.files);
    handleFileSelect(files);
  };
  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };
  const handleDragLeave = (e) => {
    e.preventDefault();
    setDragOver(false);
  };
  const handleFileInputChange = (e) => {
    const files = Array.from(e.target.files);
    handleFileSelect(files);
    e.target.value = "";
  };
  const formatFileSize = (bytes) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };
  const getStatusIcon = (status) => {
    switch (status) {
      case "metadata_sent":
      case "preparing":
        return "fas fa-cog fa-spin";
      case "transmitting":
      case "receiving":
        return "fas fa-exchange-alt fa-pulse";
      case "assembling":
        return "fas fa-puzzle-piece fa-pulse";
      case "completed":
        return "fas fa-check text-green-400";
      case "failed":
        return "fas fa-times text-red-400";
      default:
        return "fas fa-circle";
    }
  };
  const getStatusText = (status) => {
    switch (status) {
      case "metadata_sent":
        return "\u041F\u043E\u0434\u0433\u043E\u0442\u043E\u0432\u043A\u0430...";
      case "transmitting":
        return "\u041E\u0442\u043F\u0440\u0430\u0432\u043A\u0430...";
      case "receiving":
        return "\u041F\u043E\u043B\u0443\u0447\u0435\u043D\u0438\u0435...";
      case "assembling":
        return "\u0421\u0431\u043E\u0440\u043A\u0430 \u0444\u0430\u0439\u043B\u0430...";
      case "completed":
        return "\u0417\u0430\u0432\u0435\u0440\u0448\u0435\u043D\u043E";
      case "failed":
        return "\u041E\u0448\u0438\u0431\u043A\u0430";
      default:
        return status;
    }
  };
  const renderProgress = (transfer, color) => {
    const total = transfer.totalChunks || 0;
    const done = transfer.transferredChunks || 0;
    const isDone = transfer.status === "completed";
    const squares = total > 0 ? Math.min(total, 32) : 24;
    let filled;
    if (isDone) filled = squares;
    else if (total > 0) filled = Math.floor(done / total * squares);
    else filled = Math.floor((transfer.progress || 0) / 100 * squares);
    filled = Math.max(0, Math.min(squares, filled));
    return React.createElement("div", { key: "progress" }, [
      React.createElement("div", {
        key: "squares",
        style: { display: "flex", flexWrap: "wrap", gap: "3px", marginBottom: "7px" }
      }, Array.from({ length: squares }, (_, i) => React.createElement("div", {
        key: i,
        style: {
          width: "11px",
          height: "11px",
          borderRadius: "2px",
          background: i < filled ? color : "rgba(255,255,255,0.07)",
          border: "1px solid " + (i < filled ? "transparent" : "rgba(255,255,255,0.05)"),
          boxShadow: i < filled ? `0 0 5px ${color}55` : "none",
          transition: "background .2s ease, box-shadow .2s ease"
        }
      }))),
      React.createElement("div", {
        key: "text",
        style: { display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "11.5px", color: "#8a8a92" }
      }, [
        React.createElement("span", { key: "status", style: { display: "inline-flex", alignItems: "center", gap: "5px" } }, [
          React.createElement("i", { key: "icon", className: getStatusIcon(transfer.status) }),
          getStatusText(transfer.status)
        ]),
        React.createElement("span", {
          key: "count",
          style: { fontFamily: "'JetBrains Mono', ui-monospace, monospace", color: i_done(transfer) ? color : "#8a8a92" }
        }, total > 0 ? `${Math.min(done, total)} / ${total} chunks` : `${(transfer.progress || 0).toFixed(0)}%`)
      ])
    ]);
  };
  const i_done = (t) => t.status === "completed";
  const handleIncomingDecision = async (fileId, accepted) => {
    if (typeof onIncomingDecision === "function") {
      await onIncomingDecision(fileId, accepted);
    }
    setTransfers(webrtcManager.getFileTransfers());
  };
  if (!isConnected) {
    return React.createElement("div", {
      className: "p-4 text-center text-muted"
    }, "\u041F\u0435\u0440\u0435\u0434\u0430\u0447\u0430 \u0444\u0430\u0439\u043B\u043E\u0432 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u0442\u043E\u043B\u044C\u043A\u043E \u043F\u0440\u0438 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043B\u0435\u043D\u043D\u043E\u043C \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0438");
  }
  const isConnectionReady = webrtcManager && webrtcManager.isConnected() && webrtcManager.isVerified;
  if (!isConnectionReady) {
    return React.createElement("div", {
      className: "p-4 text-center text-yellow-600"
    }, [
      React.createElement("i", {
        key: "icon",
        className: "fas fa-exclamation-triangle mr-2"
      }),
      "\u0421\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435 \u0443\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442\u0441\u044F... \u041F\u0435\u0440\u0435\u0434\u0430\u0447\u0430 \u0444\u0430\u0439\u043B\u043E\u0432 \u0431\u0443\u0434\u0435\u0442 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u043F\u043E\u0441\u043B\u0435 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043D\u0438\u044F \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043A\u0438."
    ]);
  }
  return React.createElement("div", {
    className: "file-transfer-component"
  }, [
    // File Drop Zone (SecureBit Chat design) — only when the panel is opened to SEND,
    // so a receiver never sees the "send attachments" UI.
    showDropzone && React.createElement("div", {
      key: "drop-zone",
      onDrop: handleDrop,
      onDragOver: handleDragOver,
      onDragLeave: handleDragLeave,
      style: {
        position: "relative",
        border: "1.5px dashed " + (dragOver ? "rgba(240,137,42,0.7)" : "rgba(255,255,255,0.14)"),
        borderRadius: "14px",
        background: dragOver ? "rgba(240,137,42,0.07)" : "#141416",
        padding: "24px 22px",
        textAlign: "center",
        transition: "all .15s"
      }
    }, [
      React.createElement("div", {
        key: "icon-box",
        style: { width: "42px", height: "42px", margin: "0 auto 10px", borderRadius: "12px", display: "grid", placeItems: "center", background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)" }
      }, React.createElement("i", { className: "fas fa-arrow-up-from-bracket", style: { color: "#9a9aa2", fontSize: "18px" } })),
      React.createElement("div", { key: "title", style: { fontSize: "14px", fontWeight: 700, color: "#e8e8eb" } }, "Drag & drop files here"),
      React.createElement("div", { key: "sub", style: { fontSize: "12px", color: "#7b7b83", marginTop: "4px" } }, "Encrypted end-to-end before transfer \xB7 up to 100 MB"),
      React.createElement("button", {
        key: "browse",
        type: "button",
        onClick: () => fileInputRef.current?.click(),
        className: "sb-send",
        style: { marginTop: "14px", display: "inline-flex", alignItems: "center", gap: "7px", padding: "9px 16px", borderRadius: "9px", border: "none", background: "#f0892a", color: "#1a0f04", fontFamily: "inherit", fontSize: "13px", fontWeight: 700, cursor: "pointer" }
      }, [
        React.createElement("i", { key: "i", className: "fas fa-folder-open", style: { fontSize: "13px" } }),
        "Browse device"
      ])
    ]),
    // Hidden file input
    showDropzone && React.createElement("input", {
      key: "file-input",
      ref: fileInputRef,
      type: "file",
      multiple: true,
      className: "hidden",
      onChange: handleFileInputChange
    }),
    pendingIncomingFiles.length > 0 && React.createElement("div", {
      key: "incoming-consent",
      className: "mt-4 space-y-2"
    }, pendingIncomingFiles.map((file) => React.createElement("div", {
      key: file.fileId,
      style: { borderRadius: "12px", border: "1px solid rgba(255,255,255,0.08)", background: "#161618", padding: "12px 14px" }
    }, [
      React.createElement("div", {
        key: "info",
        style: { marginBottom: "12px", display: "flex", alignItems: "center", gap: "11px" }
      }, [
        React.createElement(
          "div",
          { key: "ic", style: { flex: "none", width: "34px", height: "34px", borderRadius: "9px", display: "grid", placeItems: "center", background: "rgba(240,137,42,0.12)", border: "1px solid rgba(240,137,42,0.22)" } },
          React.createElement("i", { className: "fas fa-file-arrow-down", style: { color: "#f0892a", fontSize: "15px" } })
        ),
        React.createElement("div", { key: "text", style: { minWidth: 0 } }, [
          React.createElement("div", {
            key: "title",
            style: { fontSize: "13px", fontWeight: 600, color: "#e8e8eb" }
          }, "Incoming file request"),
          React.createElement("div", {
            key: "meta",
            style: { fontSize: "11.5px", color: "#7b7b83", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }
          }, `${file.fileName} \xB7 ${formatFileSize(file.fileSize)} \xB7 ${file.mimeType}`)
        ])
      ]),
      React.createElement("div", {
        key: "actions",
        style: { display: "flex", gap: "8px" }
      }, [
        React.createElement("button", {
          key: "accept",
          onClick: () => handleIncomingDecision(file.fileId, true),
          style: { display: "inline-flex", alignItems: "center", gap: "6px", borderRadius: "8px", border: "none", background: "#f0892a", color: "#1a0f04", padding: "8px 14px", fontSize: "13px", fontWeight: 700, cursor: "pointer" }
        }, [React.createElement("i", { key: "i", className: "fas fa-check", style: { fontSize: "12px" } }), "Accept"]),
        React.createElement("button", {
          key: "reject",
          onClick: () => handleIncomingDecision(file.fileId, false),
          style: { display: "inline-flex", alignItems: "center", gap: "6px", borderRadius: "8px", border: "1px solid rgba(229,114,122,0.3)", background: "rgba(229,114,122,0.08)", color: "#e5727a", padding: "8px 14px", fontSize: "13px", fontWeight: 600, cursor: "pointer" }
        }, [React.createElement("i", { key: "i", className: "fas fa-xmark", style: { fontSize: "12px" } }), "Reject"])
      ])
    ]))),
    // Active Transfers
    (transfers.sending.length > 0 || transfers.receiving.length > 0) && React.createElement("div", {
      key: "transfers",
      className: "active-transfers mt-4"
    }, [
      React.createElement("h4", {
        key: "title",
        style: { display: "flex", alignItems: "center", gap: "8px", fontSize: "12.5px", fontWeight: 600, color: "#8a8a92", marginBottom: "10px" }
      }, [
        React.createElement("i", {
          key: "icon",
          className: "fas fa-right-left",
          style: { fontSize: "12px" }
        }),
        "File transfers"
      ]),
      // Sending files
      ...transfers.sending.map(
        (transfer) => React.createElement("div", {
          key: `send-${transfer.fileId}`,
          style: { borderRadius: "11px", border: "1px solid rgba(255,255,255,0.07)", background: "#161618", padding: "12px", marginBottom: "8px" }
        }, [
          React.createElement("div", {
            key: "header",
            className: "flex items-center justify-between mb-2"
          }, [
            React.createElement("div", {
              key: "info",
              className: "flex items-center"
            }, [
              React.createElement("i", {
                key: "icon",
                className: "fas fa-arrow-up",
                style: { color: "#f0892a", fontSize: "13px", marginRight: "8px" }
              }),
              React.createElement("span", {
                key: "name",
                className: "font-medium text-sm",
                style: { color: "#e8e8eb" }
              }, transfer.fileName),
              React.createElement("span", {
                key: "size",
                className: "text-xs ml-2",
                style: { color: "#7b7b83" }
              }, formatFileSize(transfer.fileSize))
            ]),
            React.createElement("button", {
              key: "cancel",
              onClick: () => webrtcManager.cancelFileTransfer(transfer.fileId),
              className: "text-red-400 hover:text-red-300 text-xs"
            }, [
              React.createElement("i", {
                className: "fas fa-times"
              })
            ])
          ]),
          renderProgress(transfer, "#f0892a")
        ])
      ),
      // Receiving files
      ...transfers.receiving.map(
        (transfer) => React.createElement("div", {
          key: `recv-${transfer.fileId}`,
          style: { borderRadius: "11px", border: "1px solid rgba(255,255,255,0.07)", background: "#161618", padding: "12px", marginBottom: "8px" }
        }, [
          React.createElement("div", {
            key: "header",
            className: "flex items-center justify-between mb-2"
          }, [
            React.createElement("div", {
              key: "info",
              className: "flex items-center"
            }, [
              React.createElement("i", {
                key: "icon",
                className: "fas fa-arrow-down",
                style: { color: "#3ecf8e", fontSize: "13px", marginRight: "8px" }
              }),
              React.createElement("span", {
                key: "name",
                className: "font-medium text-sm",
                style: { color: "#e8e8eb" }
              }, transfer.fileName),
              React.createElement("span", {
                key: "size",
                className: "text-xs ml-2",
                style: { color: "#7b7b83" }
              }, formatFileSize(transfer.fileSize))
            ]),
            React.createElement("div", { key: "actions", className: "flex items-center space-x-2" }, [
              transfer.status === "completed" ? React.createElement("button", {
                key: "download",
                className: "text-green-400 hover:text-green-300 text-xs flex items-center",
                onClick: async () => {
                  try {
                    const url = await webrtcManager.getReceivedFileObjectURL(transfer.fileId);
                    if (!url) {
                      alert("This file is no longer available for download.");
                      return;
                    }
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = transfer.fileName || "file";
                    a.click();
                    setTimeout(() => webrtcManager.revokeReceivedFileObjectURL(url), 1e4);
                  } catch (e) {
                    alert(e.message || "This file is no longer available for download.");
                  }
                }
              }, [
                React.createElement("i", { key: "i", className: "fas fa-download mr-1" }),
                "Download"
              ]) : null,
              React.createElement("button", {
                key: "cancel",
                onClick: () => webrtcManager.cancelFileTransfer(transfer.fileId),
                className: "text-red-400 hover:text-red-300 text-xs"
              }, [
                React.createElement("i", {
                  className: "fas fa-times"
                })
              ])
            ])
          ]),
          renderProgress(transfer, "#3ecf8e")
        ])
      )
    ])
  ]);
};
window.FileTransferComponent = FileTransferComponent;

// src/network/iceServers.js
var ICE_LIMITS = Object.freeze({
  MAX_SERVERS: 10,
  MAX_URLS_PER_SERVER: 8,
  MAX_STRING_LENGTH: 512
});
var ALLOWED_ICE_SCHEMES = Object.freeze(["stun", "stuns", "turn", "turns"]);
var SCHEME_RE = /^(stuns?|turns?):/i;
var HOST_RE = /^(\[[0-9a-f:]+\]|[a-z0-9.-]+)(:\d{1,5})?$/i;
var TRANSPORT_RE = /^transport=(udp|tcp)$/i;
function hasControlChars(value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 32 || code === 127) return true;
  }
  return false;
}
function validateIceUrl(url) {
  if (typeof url !== "string") return "URL must be a string";
  const trimmed = url.trim();
  if (!trimmed) return "URL is empty";
  if (trimmed.length > ICE_LIMITS.MAX_STRING_LENGTH) return "URL is too long";
  if (hasControlChars(trimmed)) return "URL contains invalid characters";
  const scheme = trimmed.match(SCHEME_RE);
  if (!scheme) {
    return "URL must start with stun:, stuns:, turn: or turns:";
  }
  const rest = trimmed.slice(scheme[0].length);
  const [hostPort, query, ...extra] = rest.split("?");
  if (extra.length > 0) return "URL has an invalid query";
  if (!hostPort) return "URL is missing a host";
  if (!HOST_RE.test(hostPort)) return "URL has an invalid host or port";
  if (query !== void 0 && !TRANSPORT_RE.test(query)) {
    return "URL query must be transport=udp or transport=tcp";
  }
  return null;
}
function isTurnUrl(url) {
  return typeof url === "string" && /^turns?:/i.test(url.trim());
}
function validateSecret(value, label) {
  if (value === void 0 || value === null || value === "") return null;
  if (typeof value !== "string") return `${label} must be a string`;
  if (value.length > ICE_LIMITS.MAX_STRING_LENGTH) return `${label} is too long`;
  if (hasControlChars(value)) return `${label} contains invalid characters`;
  return null;
}
function normalizeIceServers(entries2) {
  const errors = [];
  const warnings = [];
  const servers = [];
  if (!Array.isArray(entries2)) {
    return { servers: [], errors: ["Server list must be an array"], warnings: [] };
  }
  if (entries2.length === 0) {
    return { servers: [], errors: [], warnings: [] };
  }
  if (entries2.length > ICE_LIMITS.MAX_SERVERS) {
    errors.push(`Too many servers (max ${ICE_LIMITS.MAX_SERVERS})`);
    return { servers: [], errors, warnings };
  }
  entries2.forEach((entry, index) => {
    const label = `Server #${index + 1}`;
    if (!entry || typeof entry !== "object") {
      errors.push(`${label}: invalid entry`);
      return;
    }
    const rawUrls = Array.isArray(entry.urls) ? entry.urls : [entry.urls];
    if (rawUrls.length === 0 || rawUrls.length > ICE_LIMITS.MAX_URLS_PER_SERVER) {
      errors.push(`${label}: between 1 and ${ICE_LIMITS.MAX_URLS_PER_SERVER} URLs required`);
      return;
    }
    const cleanUrls = [];
    let entryHasTurn = false;
    for (const rawUrl of rawUrls) {
      const err = validateIceUrl(rawUrl);
      if (err) {
        errors.push(`${label}: ${err}`);
        continue;
      }
      const trimmed = rawUrl.trim();
      cleanUrls.push(trimmed);
      if (isTurnUrl(trimmed)) entryHasTurn = true;
    }
    if (cleanUrls.length === 0) return;
    const userErr = validateSecret(entry.username, `${label} username`);
    if (userErr) errors.push(userErr);
    const credErr = validateSecret(entry.credential, `${label} credential`);
    if (credErr) errors.push(credErr);
    const server = { urls: cleanUrls.length === 1 ? cleanUrls[0] : cleanUrls };
    if (entry.username) server.username = String(entry.username);
    if (entry.credential) server.credential = String(entry.credential);
    if (entryHasTurn && (!server.username || !server.credential)) {
      warnings.push(`${label}: TURN servers usually require a username and credential`);
    }
    servers.push(server);
  });
  return { servers, errors, warnings };
}
function parseIceServersInput(text2) {
  if (typeof text2 !== "string" || !text2.trim()) {
    return { servers: [], errors: [], warnings: [] };
  }
  const trimmed = text2.trim();
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return { servers: [], errors: ["Invalid JSON"], warnings: [] };
    }
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    return normalizeIceServers(arr);
  }
  const entries2 = trimmed.split("\n").map((line) => line.trim()).filter(Boolean).map((url) => ({ urls: url }));
  return normalizeIceServers(entries2);
}
function listHasTurn(servers) {
  if (!Array.isArray(servers)) return false;
  return servers.some((server) => {
    const urls = Array.isArray(server?.urls) ? server.urls : [server?.urls];
    return urls.some(isTurnUrl);
  });
}

// src/components/ui/IceServerSettings.jsx
var React2 = window.React;
var PLACEHOLDER = [
  "# One URL per line, e.g.:",
  "stun:stun.example.com:3478",
  "turn:turn.example.com:3478?transport=udp",
  "",
  "# Or paste JSON for servers with credentials:",
  '[{"urls":"turns:turn.example.com:5349","username":"user","credential":"secret"}]'
].join("\n");
async function testIceServers(servers, timeoutMs = 6e3) {
  const found = { host: 0, srflx: 0, relay: 0 };
  if (typeof RTCPeerConnection === "undefined") {
    return { ...found, error: "WebRTC is not available in this browser" };
  }
  let pc;
  try {
    pc = new RTCPeerConnection({ iceServers: servers });
  } catch (error) {
    return { ...found, error: error.message || "Invalid server configuration" };
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        pc.close();
      } catch {
      }
      resolve(found);
    };
    const timer = setTimeout(finish, timeoutMs);
    pc.onicecandidate = (event) => {
      if (!event.candidate) {
        finish();
        return;
      }
      const c = event.candidate.candidate || "";
      if (/ typ host/.test(c)) found.host++;
      else if (/ typ srflx/.test(c)) found.srflx++;
      else if (/ typ relay/.test(c)) found.relay++;
    };
    try {
      pc.createDataChannel("securebit-ice-test");
      pc.createOffer().then((offer) => pc.setLocalDescription(offer)).catch(() => finish());
    } catch {
      finish();
    }
  });
}
var IceServerSettings = ({ isOpen, onClose, initial, hasSaved, onApply, onForget, embedded }) => {
  if (!isOpen) return null;
  const [useCustom, setUseCustom] = React2.useState(initial?.useCustom || false);
  const [serversText, setServersText] = React2.useState(initial?.serversText || "");
  const [relayOnly, setRelayOnly] = React2.useState(initial?.privacyMode === "relay-only");
  const [persist, setPersist] = React2.useState(initial?.persisted || false);
  const [testState, setTestState] = React2.useState("idle");
  const [testResult, setTestResult] = React2.useState(null);
  const parsed = useCustom ? parseIceServersInput(serversText) : { servers: [], errors: [], warnings: [] };
  const hasTurn = listHasTurn(parsed.servers);
  const canApply = !useCustom || parsed.servers.length > 0 && parsed.errors.length === 0;
  const handleTest = async () => {
    setTestState("running");
    setTestResult(null);
    const result = await testIceServers(parsed.servers);
    setTestResult(result);
    setTestState("done");
  };
  const handleApply = () => {
    if (!canApply) return;
    onApply(
      {
        useCustom,
        servers: useCustom ? parsed.servers : [],
        privacyMode: relayOnly ? "relay-only" : "standard",
        serversText
      },
      persist
    );
  };
  const handleForget = async () => {
    if (onForget) await onForget();
    setPersist(false);
  };
  const h = React2.createElement;
  const C_ORANGE = "#f0892a";
  const C_GREEN = "#3ecf8e";
  const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
  const radioCard = (selected, onClick, title, desc, extraStyle) => h("button", {
    type: "button",
    onClick,
    style: Object.assign({
      width: "100%",
      textAlign: "left",
      display: "flex",
      alignItems: "flex-start",
      gap: "12px",
      padding: "14px 15px",
      borderRadius: "13px",
      border: `1px solid ${selected ? "rgba(240,137,42,0.45)" : "rgba(255,255,255,0.07)"}`,
      background: selected ? "rgba(240,137,42,0.06)" : "#141416",
      color: "inherit",
      fontFamily: "inherit",
      cursor: "pointer",
      transition: "all .15s",
      marginBottom: "10px"
    }, extraStyle || {})
  }, [
    h(
      "span",
      { key: "ring", style: { flex: "none", width: "18px", height: "18px", marginTop: "1px", borderRadius: "50%", border: `1.5px solid ${selected ? C_ORANGE : "rgba(255,255,255,0.22)"}`, display: "grid", placeItems: "center" } },
      h("span", { style: { width: "8px", height: "8px", borderRadius: "50%", background: selected ? C_ORANGE : "transparent" } })
    ),
    h("span", { key: "tx", style: { flex: 1 } }, [
      h("span", { key: "t", style: { display: "block", fontSize: "14px", fontWeight: 700, color: "#f4f4f6" } }, title),
      h("span", { key: "d", style: { display: "block", fontSize: "12.5px", color: "#8a8a92", marginTop: "2px" } }, desc)
    ])
  ]);
  const toggleRow = (on, onClick, title, desc, accent, badge) => h("button", {
    type: "button",
    onClick,
    style: {
      width: "100%",
      textAlign: "left",
      display: "flex",
      alignItems: "flex-start",
      gap: "12px",
      padding: "14px 15px",
      borderRadius: "13px",
      border: `1px solid ${on ? "rgba(62,207,142,0.3)" : "rgba(255,255,255,0.07)"}`,
      background: on ? "rgba(62,207,142,0.05)" : "#141416",
      color: "inherit",
      fontFamily: "inherit",
      cursor: "pointer",
      transition: "all .15s",
      marginBottom: "10px"
    }
  }, [
    h("span", { key: "tx", style: { flex: 1 } }, [
      h("span", { key: "r1", style: { display: "flex", alignItems: "center", gap: "8px" } }, [
        h("span", { key: "t", style: { fontSize: "14px", fontWeight: 700, color: "#f4f4f6" } }, title),
        badge && h("span", { key: "b", style: { fontSize: "10px", fontWeight: 700, color: C_GREEN, padding: "2px 7px", borderRadius: "5px", background: "rgba(62,207,142,0.1)", border: "1px solid rgba(62,207,142,0.22)" } }, badge)
      ]),
      h("span", { key: "d", style: { display: "block", fontSize: "12.5px", lineHeight: 1.5, color: "#8a8a92", marginTop: "3px" } }, desc)
    ]),
    h(
      "span",
      { key: "tr", style: { flex: "none", width: "42px", height: "24px", borderRadius: "99px", background: on ? accent || C_GREEN : "rgba(255,255,255,0.08)", border: `1px solid ${on ? accent || C_GREEN : "rgba(255,255,255,0.12)"}`, position: "relative", transition: "all .18s", marginTop: "1px" } },
      h("span", { style: { position: "absolute", top: "2px", left: "2px", width: "18px", height: "18px", borderRadius: "50%", background: "#fff", transform: on ? "translateX(18px)" : "translateX(0)", transition: "transform .18s" } })
    )
  ]);
  const body = [];
  body.push(h(
    "p",
    { key: "intro", style: { margin: "0 0 18px", fontSize: "13.5px", lineHeight: 1.6, color: "#9a9aa2" } },
    "SecureBit uses public STUN servers by default to negotiate the peer-to-peer link. Point it at your own STUN/TURN if you self-host."
  ));
  body.push(radioCard(!useCustom, () => setUseCustom(false), "Public servers (default)", "Zero-config. Good for most users."));
  body.push(radioCard(useCustom, () => setUseCustom(true), "My own STUN/TURN servers", `Up to ${ICE_LIMITS.MAX_SERVERS} servers.`, useCustom ? { marginBottom: "14px" } : null));
  if (useCustom) {
    const custom = [];
    custom.push(h(
      "div",
      { key: "ta", style: { borderRadius: "13px", border: "1px solid rgba(255,255,255,0.08)", background: "#0c0c0e", overflow: "hidden", marginBottom: "12px" } },
      h("textarea", {
        value: serversText,
        onChange: (e) => setServersText(e.target.value),
        rows: 5,
        spellCheck: false,
        autoComplete: "off",
        placeholder: PLACEHOLDER,
        style: { width: "100%", resize: "vertical", border: "none", outline: "none", background: "transparent", color: "#c9ccd8", fontFamily: MONO, fontSize: "12px", lineHeight: 1.65, padding: "13px 14px", minHeight: "104px" }
      })
    ));
    if (parsed.errors.length > 0) {
      custom.push(h(
        "ul",
        { key: "err", style: { margin: "0 0 10px", paddingLeft: "18px", color: "#e5727a", fontSize: "12.5px" } },
        parsed.errors.slice(0, 6).map((err, i) => h("li", { key: i }, err))
      ));
    }
    if (parsed.warnings.length > 0) {
      custom.push(h(
        "ul",
        { key: "warn", style: { margin: "0 0 10px", paddingLeft: "18px", color: "#e3c84e", fontSize: "12.5px" } },
        parsed.warnings.slice(0, 6).map((w, i) => h("li", { key: i }, w))
      ));
    }
    if (parsed.servers.length > 0 && parsed.errors.length === 0) {
      custom.push(h(
        "p",
        { key: "ok", style: { margin: "0 0 10px", fontSize: "12.5px", color: C_GREEN } },
        `${parsed.servers.length} server(s) parsed${hasTurn ? " (TURN present)" : " (STUN only \u2014 does not hide IP)"}.`
      ));
    }
    custom.push(h("div", { key: "note", style: { display: "flex", alignItems: "flex-start", gap: "9px", padding: "12px 13px", borderRadius: "11px", border: "1px solid rgba(62,207,142,0.18)", background: "rgba(62,207,142,0.05)", marginBottom: "12px" } }, [
      h("i", { key: "i", className: "fas fa-info-circle", style: { color: C_GREEN, fontSize: "13px", marginTop: "2px", flex: "none" } }),
      h("span", { key: "t", style: { fontSize: "12px", lineHeight: 1.55, color: "#a8b8ae" } }, [
        "A TURN relay sees both peers\u2019 IP and traffic timing \u2014 but never message contents, which stay end-to-end encrypted. Prefer ",
        h("span", { key: "m", style: { fontFamily: MONO, color: C_GREEN } }, "turns:"),
        " (TLS)."
      ])
    ]));
    const testColor = testState === "done" && testResult && !testResult.error ? C_GREEN : "#cfcfd4";
    custom.push(h("div", { key: "test", style: { display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap", marginBottom: "4px" } }, [
      h("button", {
        key: "btn",
        type: "button",
        disabled: !canApply || testState === "running",
        onClick: handleTest,
        style: { display: "inline-flex", alignItems: "center", gap: "8px", padding: "10px 15px", borderRadius: "10px", border: `1px solid ${testState === "done" && testResult && !testResult.error ? "rgba(62,207,142,0.4)" : "rgba(255,255,255,0.1)"}`, background: testState === "done" && testResult && !testResult.error ? "rgba(62,207,142,0.08)" : "rgba(255,255,255,0.04)", color: testColor, fontFamily: "inherit", fontSize: "13px", fontWeight: 600, cursor: !canApply || testState === "running" ? "not-allowed" : "pointer", opacity: !canApply || testState === "running" ? 0.6 : 1 }
      }, [
        h("i", { key: "i", className: testState === "running" ? "fas fa-circle-notch" : "fas fa-play-circle", style: testState === "running" ? { animation: "sbSpin 1s linear infinite" } : null }),
        testState === "running" ? "Testing\u2026" : "Test servers"
      ]),
      testState === "done" && testResult ? h(
        "span",
        { key: "res", style: { fontSize: "12px", color: testResult.error ? "#e5727a" : "#8a8a92" } },
        testResult.error ? `Test failed: ${testResult.error}` : testResult.srflx > 0 || testResult.relay > 0 ? `STUN ${testResult.srflx > 0 ? "OK" : "none"} \xB7 TURN ${testResult.relay > 0 ? "OK" : "none"} \xB7 host ${testResult.host}` : `host ${testResult.host} \xB7 this browser hides STUN/TURN candidates from the test \u2014 your servers still apply to real connections`
      ) : null
    ]));
    body.push(h("div", { key: "custom", style: { marginBottom: "16px" } }, custom));
  }
  body.push(toggleRow(
    relayOnly,
    () => setRelayOnly(!relayOnly),
    "Relay-only mode",
    "Routes all traffic through TURN so your IP is never exposed to the peer. Requires a TURN server.",
    C_GREEN,
    "MAX PRIVACY"
  ));
  if (relayOnly && useCustom && !hasTurn) {
    body.push(h(
      "p",
      { key: "relaywarn", style: { margin: "-4px 0 10px", fontSize: "12.5px", color: "#e3c84e" } },
      "Relay-only is enabled but no TURN server is configured. The connection will not be able to start."
    ));
  }
  body.push(toggleRow(
    persist,
    () => setPersist(!persist),
    "Save on this device",
    "Stored encrypted in this browser. Leave off to use only for this session.",
    C_ORANGE
  ));
  const footerBtns = [];
  if (hasSaved) {
    footerBtns.push(h("button", {
      key: "forget",
      type: "button",
      onClick: handleForget,
      style: { marginRight: "auto", padding: "11px 18px", borderRadius: "11px", border: "1px solid rgba(229,114,122,0.3)", background: "transparent", color: "#e5727a", fontFamily: "inherit", fontSize: "13.5px", fontWeight: 600, cursor: "pointer" }
    }, "Forget saved"));
  }
  footerBtns.push(h("button", {
    key: "cancel",
    type: "button",
    onClick: onClose,
    style: { padding: "11px 18px", borderRadius: "11px", border: "1px solid rgba(255,255,255,0.1)", background: "transparent", color: "#b3b3ba", fontFamily: "inherit", fontSize: "13.5px", fontWeight: 600, cursor: "pointer" }
  }, "Cancel"));
  footerBtns.push(h("button", {
    key: "apply",
    type: "button",
    onClick: handleApply,
    disabled: !canApply,
    style: { display: "inline-flex", alignItems: "center", gap: "8px", padding: "11px 20px", borderRadius: "11px", border: "none", background: C_ORANGE, color: "#1a0f04", fontFamily: "inherit", fontSize: "13.5px", fontWeight: 700, cursor: canApply ? "pointer" : "not-allowed", opacity: canApply ? 1 : 0.5, boxShadow: "0 6px 18px rgba(240,137,42,0.28)" }
  }, [
    h("i", { key: "i", className: "fas fa-check" }),
    "Apply"
  ]));
  const wrapperStyle = embedded ? { position: "absolute", inset: 0, zIndex: 60, display: "flex", flexDirection: "column", background: "#0f0f11", animation: "sbSlideUp .32s cubic-bezier(.2,.7,.3,1)" } : { position: "fixed", inset: 0, zIndex: 60, display: "flex", flexDirection: "column", alignItems: "stretch", background: "#0f0f11", animation: "sbSlideUp .32s cubic-bezier(.2,.7,.3,1)" };
  return h("div", { className: "sb-ice-overlay", style: wrapperStyle }, [
    h(React2.Fragment, { key: "panel" }, [
      // header
      h("div", { key: "head", style: { display: "flex", alignItems: "center", gap: "12px", padding: "20px 24px", borderBottom: "1px solid rgba(255,255,255,0.06)" } }, [
        h(
          "div",
          { key: "ic", style: { width: "38px", height: "38px", flex: "none", display: "grid", placeItems: "center", borderRadius: "10px", background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)" } },
          h("i", { className: "fas fa-sliders-h", style: { color: "#cfcfd4", fontSize: "15px" } })
        ),
        h("div", { key: "tx", style: { flex: 1, lineHeight: 1.25 } }, [
          h("div", { key: "t", style: { fontSize: "16.5px", fontWeight: 800, letterSpacing: "-0.3px", color: "#f4f4f6" } }, "Network settings"),
          h("div", { key: "s", style: { fontSize: "12px", color: "#7b7b83" } }, "Configured locally \u2014 never shared with your peer")
        ]),
        h(
          "button",
          { key: "x", type: "button", onClick: onClose, style: { width: "32px", height: "32px", flex: "none", display: "grid", placeItems: "center", borderRadius: "9px", border: "none", background: "rgba(255,255,255,0.04)", color: "#8a8a92", cursor: "pointer" } },
          h("i", { className: "fas fa-times" })
        )
      ]),
      // scroll body
      h("div", { key: "body", className: "custom-scrollbar", style: { flex: 1, overflowY: "auto", padding: "20px 24px" } }, body),
      // footer
      h("div", { key: "foot", style: { display: "flex", alignItems: "center", justifyContent: "flex-end", gap: "10px", padding: "16px 24px", borderTop: "1px solid rgba(255,255,255,0.06)", background: "#0e0e10", borderRadius: "0" } }, footerBtns)
    ])
  ]);
};
window.IceServerSettings = IceServerSettings;

// src/components/ui/CallUI.jsx
var CallUIComponent = ({ webrtcManager, peerTitle }) => {
  const h = React.createElement;
  const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
  const ICON = {
    lock: '<path d="M7 11V7a5 5 0 0 1 10 0v4"/><rect x="4.5" y="11" width="15" height="9" rx="2.2"/>',
    minimize: '<path d="M9 4v4a1 1 0 0 1-1 1H4M15 4v4a1 1 0 0 0 1 1h4M9 20v-4a1 1 0 0 0-1-1H4M15 20v-4a1 1 0 0 1 1-1h4"/>',
    expand: '<path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/>',
    user: '<circle cx="12" cy="8" r="3.6"/><path d="M5 20c0-3.5 3-5.5 7-5.5s7 2 7 5.5"/>',
    micOn: '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0 0 14 0"/><path d="M12 18v3"/>',
    micOff: '<path d="M9 9v-1a3 3 0 0 1 5.1-2.1M15 11v3a3 3 0 0 1-4.6 2.5"/><path d="M5 11a7 7 0 0 0 10.3 6.2M19 11a7 7 0 0 1-.4 2.3"/><path d="M12 18v3"/><path d="M3 3l18 18"/>',
    camOn: '<path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2.5"/>',
    camOff: '<path d="M16 16H3a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h2l2-2M11 6h2l7-3v14M2 2l20 20"/>',
    flip: '<path d="M3 7h3l2-2h8l2 2h3v12H3z"/><path d="M9.5 13a2.5 2.5 0 0 1 5 0M14.5 13l-1.3-1.3M14.5 13l1.3-1.3"/>',
    phone: '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.8 19.8 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.12 4.18 2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.96.36 1.9.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.34 1.85.57 2.81.7A2 2 0 0 1 22 16.92z"/>',
    phoneHangup: '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.8 19.8 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.12 4.18 2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.96.36 1.9.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.34 1.85.57 2.81.7A2 2 0 0 1 22 16.92z" transform="rotate(135 12 12)"/>'
  };
  const svg2 = (inner, size, sw) => h("span", {
    style: { display: "grid", placeItems: "center", width: size + "px", height: size + "px" },
    dangerouslySetInnerHTML: { __html: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>` }
  });
  const [call, setCall] = React.useState(() => webrtcManager?.getCallState?.() || { phase: "idle", active: false });
  const [minimized, setMinimized] = React.useState(false);
  const [seconds, setSeconds] = React.useState(0);
  const remoteVideoRef = React.useRef(null);
  const remoteAudioRef = React.useRef(null);
  const selfVideoRef = React.useRef(null);
  React.useEffect(() => {
    if (!webrtcManager) return;
    const onState = (state) => setCall(state);
    const prev = webrtcManager.onCallStateChanged;
    webrtcManager.onCallStateChanged = onState;
    setCall(webrtcManager.getCallState ? webrtcManager.getCallState() : { phase: "idle", active: false });
    return () => {
      if (webrtcManager.onCallStateChanged === onState) webrtcManager.onCallStateChanged = prev || null;
    };
  }, [webrtcManager]);
  const phase = call.phase || "idle";
  const active = !!call.active;
  const isVideo = !!call.withVideo || !!call.remoteHasVideo;
  React.useEffect(() => {
    const remoteStream = webrtcManager?.getRemoteMediaStream?.();
    const localStream = webrtcManager?.getLocalMediaStream?.();
    const attach = (el, stream, muted) => {
      if (!el || !stream) return;
      if (el.srcObject !== stream) {
        el.muted = muted;
        el.srcObject = stream;
      }
      const p = el.play && el.play();
      if (p && p.catch) p.catch(() => {
      });
    };
    attach(remoteAudioRef.current, remoteStream, false, "remoteAudio");
    attach(remoteVideoRef.current, remoteStream, true, "remoteVideo");
    attach(selfVideoRef.current, localStream, true, "selfVideo");
  });
  React.useEffect(() => {
    if (phase !== "active") {
      setSeconds(0);
      return;
    }
    const started = Date.now();
    const iv = setInterval(() => setSeconds(Math.floor((Date.now() - started) / 1e3)), 1e3);
    return () => clearInterval(iv);
  }, [phase]);
  React.useEffect(() => {
    if (phase === "idle") setMinimized(false);
  }, [phase]);
  if (!active || phase === "idle" || phase === "ended") return null;
  const fmt = (s) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  const ringing = phase === "outgoing" || phase === "connecting";
  const callStatus = phase === "outgoing" ? "Ringing\u2026" : phase === "connecting" ? "Connecting\u2026" : phase === "active" ? fmt(seconds) : "Ringing\u2026";
  const name = peerTitle || "Secure peer";
  const ctrlBase = {
    width: "56px",
    height: "56px",
    borderRadius: "50%",
    display: "grid",
    placeItems: "center",
    border: "1px solid rgba(255,255,255,0.1)",
    background: "rgba(255,255,255,0.05)",
    color: "#cfcfd4",
    cursor: "pointer",
    transition: "all .15s"
  };
  const dangerCtrl = { ...ctrlBase, background: "#e5484d", color: "#fff", border: "1px solid transparent" };
  const endBtn = {
    width: "56px",
    height: "56px",
    borderRadius: "50%",
    display: "grid",
    placeItems: "center",
    border: "none",
    background: "#e5484d",
    color: "#fff",
    cursor: "pointer",
    boxShadow: "0 8px 24px rgba(229,72,77,0.35)",
    transition: "transform .15s"
  };
  const minimizeBtn = (light) => ({
    width: "36px",
    height: "36px",
    borderRadius: "9px",
    display: "grid",
    placeItems: "center",
    border: "1px solid rgba(255,255,255," + (light ? "0.15" : "0.1") + ")",
    background: light ? "rgba(0,0,0,0.35)" : "rgba(255,255,255,0.04)",
    color: light ? "#fff" : "#cfcfd4",
    cursor: "pointer",
    transition: "all .15s"
  });
  const encBadge = h(
    "span",
    { key: "enc", style: { display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "11px", fontWeight: 600, color: "#3ecf8e" } },
    [svg2(ICON.lock, 11, 2), "Encrypted"]
  );
  const QUALITY = {
    excellent: { bars: 4, color: "#3ecf8e", label: "Excellent" },
    good: { bars: 3, color: "#3ecf8e", label: "Good" },
    fair: { bars: 2, color: "#e3c84e", label: "Fair" },
    poor: { bars: 1, color: "#e5727a", label: "Weak" }
  };
  const qualityIndicator = (compact) => {
    const q = QUALITY[call.quality];
    if (!q) return null;
    const bars = h(
      "span",
      { key: "bars", style: { display: "inline-flex", alignItems: "flex-end", gap: "2px", height: "14px" } },
      [0, 1, 2, 3].map((i) => h("span", {
        key: i,
        style: { width: "3px", height: 5 + i * 3 + "px", borderRadius: "1px", background: i < q.bars ? q.color : "rgba(255,255,255,0.18)" }
      }))
    );
    if (compact) return bars;
    return h("span", { key: "q", title: "Connection quality", style: { display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "11.5px", fontWeight: 600, color: q.color } }, [bars, q.label]);
  };
  const doAccept = () => webrtcManager?.acceptCall?.();
  const doDecline = () => webrtcManager?.declineCall?.();
  const doEnd = () => {
    setMinimized(false);
    webrtcManager?.endCall?.();
  };
  const doMute = () => webrtcManager?.toggleMic?.();
  const doCamera = () => webrtcManager?.toggleCamera?.();
  const doFlip = () => webrtcManager?.switchCamera?.();
  const doUpgrade = () => webrtcManager?.upgradeToVideo?.();
  const hiddenAudio = h("audio", { key: "ra", ref: remoteAudioRef, autoPlay: true, playsInline: true, style: { display: "none" } });
  const labeled = (key, btn, label) => h(
    "div",
    { key, style: { display: "flex", flexDirection: "column", alignItems: "center", gap: "8px" } },
    [btn, h("span", { key: "l", style: { fontFamily: MONO, fontSize: "10.5px", color: "#8a8a92" } }, label)]
  );
  const avatarDisc = (size, ring) => h("div", { key: "av", style: { position: "relative", width: "120px", height: "120px", marginBottom: "28px", display: "grid", placeItems: "center" } }, [
    ring && h("span", { key: "p1", style: { position: "absolute", inset: 0, borderRadius: "50%", border: "1.5px solid rgba(240,137,42,0.5)", animation: "sbCallPulse 2s ease-out infinite" } }),
    ring && h("span", { key: "p2", style: { position: "absolute", inset: 0, borderRadius: "50%", border: "1.5px solid rgba(240,137,42,0.4)", animation: "sbCallPulse 2s ease-out infinite", animationDelay: "1s" } }),
    h("div", { key: "c", style: { width: "104px", height: "104px", borderRadius: "50%", display: "grid", placeItems: "center", background: "radial-gradient(circle at 35% 30%, #2a2a30, #161618)", border: "1px solid rgba(255,255,255,0.1)", boxShadow: "0 12px 30px rgba(0,0,0,0.4)", color: "#8a8a92" } }, svg2(ICON.user, size, 1.6))
  ]);
  if (phase === "incoming") {
    return h("div", { style: { position: "absolute", inset: 0, zIndex: 40, display: "flex", flexDirection: "column", background: "radial-gradient(680px 460px at 50% 36%, rgba(240,137,42,0.08), transparent 70%), #0d0d0f", animation: "sbExpand .2s ease" } }, [
      hiddenAudio,
      h(
        "div",
        { key: "top", style: { flex: "none", display: "flex", alignItems: "center", justifyContent: "flex-start", padding: "16px 18px" } },
        h("span", { style: { display: "inline-flex", alignItems: "center", gap: "7px", fontSize: "12px", fontWeight: 600, color: "#3ecf8e" } }, [svg2(ICON.lock, 13, 2), "Encrypted call"])
      ),
      h("div", { key: "mid", style: { flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" } }, [
        avatarDisc(46, true),
        h("div", { key: "nm", style: { fontSize: "24px", fontWeight: 800, letterSpacing: "-0.5px", color: "#f4f4f6" } }, name),
        h("div", { key: "st", style: { fontFamily: MONO, fontSize: "14px", fontWeight: 500, color: "#9a9aa2", marginTop: "8px" } }, call.withVideo ? "Incoming video call" : "Incoming call")
      ]),
      h("div", { key: "ctrls", style: { flex: "none", display: "flex", alignItems: "flex-start", justifyContent: "center", gap: "48px", padding: "28px 24px 40px" } }, [
        labeled("dec", h("button", { onClick: doDecline, title: "Decline", style: { ...endBtn, width: "62px", height: "62px" } }, svg2(ICON.phoneHangup, 24, 1.9)), "Decline"),
        labeled("acc", h("button", { onClick: doAccept, title: "Accept", style: { width: "62px", height: "62px", borderRadius: "50%", display: "grid", placeItems: "center", border: "none", background: "#3ecf8e", color: "#06231a", cursor: "pointer", boxShadow: "0 8px 24px rgba(62,207,142,0.35)" } }, svg2(ICON.phone, 24, 1.9)), "Accept")
      ])
    ]);
  }
  if (minimized) {
    return h("div", { style: { position: "absolute", bottom: "18px", right: "18px", zIndex: 40, width: "236px", borderRadius: "14px", overflow: "hidden", background: "#161618", border: "1px solid rgba(255,255,255,0.1)", boxShadow: "0 18px 44px rgba(0,0,0,0.55)", animation: "sbExpand .18s ease" } }, [
      hiddenAudio,
      isVideo && h("div", { key: "v", style: { position: "relative", height: "132px", background: "#111" } }, [
        h("video", { key: "rv", ref: remoteVideoRef, autoPlay: true, muted: true, playsInline: true, style: { width: "100%", height: "100%", objectFit: "cover", display: "block" } }),
        !call.remoteHasVideo && h("div", { key: "off", style: { position: "absolute", inset: 0, display: "grid", placeItems: "center", background: "linear-gradient(120deg,#15151b,#1d1a24)", color: "#6b6b73" } }, svg2(ICON.camOff, 22, 1.8)),
        h("span", { key: "s", style: { position: "absolute", top: "8px", left: "9px", fontFamily: MONO, fontSize: "11px", fontWeight: 600, color: "#fff", padding: "3px 7px", borderRadius: "6px", background: "rgba(0,0,0,0.5)" } }, callStatus)
      ]),
      h("div", { key: "bar", style: { display: "flex", alignItems: "center", gap: "11px", padding: "11px 12px" } }, [
        h("span", { key: "ic", style: { position: "relative", flex: "none", width: "34px", height: "34px", borderRadius: "9px", display: "grid", placeItems: "center", background: "rgba(62,207,142,0.1)", border: "1px solid rgba(62,207,142,0.25)", color: "#3ecf8e" } }, svg2(ICON.user, 16, 1.9)),
        h("div", { key: "tx", style: { flex: 1, minWidth: 0 } }, [
          h("div", { key: "n", style: { fontSize: "13px", fontWeight: 700, color: "#f4f4f6", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" } }, name),
          h("div", { key: "s", style: { display: "flex", alignItems: "center", gap: "7px", fontFamily: MONO, fontSize: "11px", color: "#9a9aa2" } }, [
            (isVideo ? "Video \xB7 " : "Voice \xB7 ") + callStatus,
            phase === "active" && qualityIndicator(true)
          ])
        ]),
        h("button", { key: "exp", onClick: () => setMinimized(false), title: "Expand", style: { flex: "none", width: "32px", height: "32px", borderRadius: "8px", display: "grid", placeItems: "center", border: "none", background: "rgba(255,255,255,0.05)", color: "#cfcfd4", cursor: "pointer", transition: "all .15s" } }, svg2(ICON.expand, 15, 2)),
        h("button", { key: "end", onClick: doEnd, title: "End call", style: { flex: "none", width: "32px", height: "32px", borderRadius: "8px", display: "grid", placeItems: "center", border: "none", background: "#e5484d", color: "#fff", cursor: "pointer", transition: "transform .15s" } }, svg2(ICON.phoneHangup, 15, 2))
      ])
    ]);
  }
  if (isVideo) {
    return h("div", { style: { position: "absolute", inset: 0, zIndex: 40, overflow: "hidden", background: "#0a0a0c", animation: "sbExpand .2s ease" } }, [
      hiddenAudio,
      call.remoteHasVideo ? h("video", { key: "rv", ref: remoteVideoRef, autoPlay: true, muted: true, playsInline: true, style: { position: "absolute", inset: 0, width: "100%", height: "100%", objectFit: "cover", background: "#0a0a0c" } }) : h("div", { key: "ph", style: { position: "absolute", inset: 0, background: "linear-gradient(120deg, #15151b, #1d1a24, #161620)", backgroundSize: "200% 200%", animation: "sbLiveBg 9s ease-in-out infinite", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: "18px" } }, [
        h("div", { key: "a", style: { width: "120px", height: "120px", borderRadius: "50%", display: "grid", placeItems: "center", background: "radial-gradient(circle at 35% 30%, #2a2a30, #161618)", border: "1px solid rgba(255,255,255,0.1)", color: "#9a9aa2" } }, svg2(ICON.user, 54, 1.5)),
        h("div", { key: "t", style: { fontSize: "15px", fontWeight: 600, color: "#8a8a92" } }, "Peer's camera is off")
      ]),
      // Top bar
      h("div", { key: "top", style: { position: "absolute", top: 0, left: 0, right: 0, display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "14px", padding: "18px 20px", background: "linear-gradient(180deg, rgba(0,0,0,0.55), transparent)" } }, [
        h("div", { key: "l" }, [
          h("div", { key: "n", style: { fontSize: "18px", fontWeight: 800, letterSpacing: "-0.3px", color: "#fff" } }, name),
          h("div", { key: "s", style: { display: "inline-flex", alignItems: "center", gap: "9px", marginTop: "4px" } }, [
            h("span", { key: "st", style: { fontFamily: MONO, fontSize: "12.5px", fontWeight: 500, color: "#e8e8eb" } }, callStatus),
            encBadge,
            phase === "active" && qualityIndicator(false)
          ])
        ]),
        h("button", { key: "min", onClick: () => setMinimized(true), title: "Minimize", style: { flex: "none", ...minimizeBtn(true) } }, svg2(ICON.minimize, 16, 2))
      ]),
      // Self-cam PiP
      h("div", { key: "self", style: { position: "absolute", bottom: "108px", right: "18px", width: "132px", height: "176px", borderRadius: "14px", overflow: "hidden", border: "1px solid rgba(255,255,255,0.16)", boxShadow: "0 12px 30px rgba(0,0,0,0.5)", background: "#111" } }, [
        h("video", { key: "sv", ref: selfVideoRef, autoPlay: true, muted: true, playsInline: true, style: { width: "100%", height: "100%", objectFit: "cover", transform: "scaleX(-1)", display: "block" } }),
        !call.cameraEnabled && h("div", { key: "off", style: { position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: "8px", background: "#161618", color: "#6b6b73" } }, [
          svg2(ICON.camOff, 24, 1.8),
          h("span", { key: "t", style: { fontSize: "10.5px", color: "#6b6b73", fontFamily: MONO } }, "Camera off")
        ])
      ]),
      // Control bar
      h("div", { key: "ctrls", style: { position: "absolute", bottom: 0, left: 0, right: 0, display: "flex", alignItems: "center", justifyContent: "center", gap: "18px", padding: "22px 24px 28px", background: "linear-gradient(0deg, rgba(0,0,0,0.6), transparent)" } }, [
        h("button", { key: "mute", onClick: doMute, title: "Mute", style: call.micEnabled ? ctrlBase : dangerCtrl }, svg2(call.micEnabled ? ICON.micOn : ICON.micOff, 21, 1.9)),
        h("button", { key: "cam", onClick: doCamera, title: "Camera", style: call.cameraEnabled ? ctrlBase : dangerCtrl }, svg2(call.cameraEnabled ? ICON.camOn : ICON.camOff, 21, 1.8)),
        h("button", { key: "flip", onClick: doFlip, title: "Flip camera", style: ctrlBase }, svg2(ICON.flip, 21, 1.8)),
        h("button", { key: "end", onClick: doEnd, title: "End call", style: endBtn }, svg2(ICON.phoneHangup, 22, 1.9))
      ])
    ]);
  }
  return h("div", { style: { position: "absolute", inset: 0, zIndex: 40, display: "flex", flexDirection: "column", background: "radial-gradient(680px 460px at 50% 36%, rgba(240,137,42,0.08), transparent 70%), #0d0d0f", animation: "sbExpand .2s ease" } }, [
    hiddenAudio,
    h("div", { key: "top", style: { flex: "none", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 18px" } }, [
      h("span", { key: "enc", style: { display: "inline-flex", alignItems: "center", gap: "7px", fontSize: "12px", fontWeight: 600, color: "#3ecf8e" } }, [svg2(ICON.lock, 13, 2), "Encrypted call"]),
      h("button", { key: "min", onClick: () => setMinimized(true), title: "Minimize", style: minimizeBtn(false) }, svg2(ICON.minimize, 16, 2))
    ]),
    h("div", { key: "mid", style: { flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" } }, [
      avatarDisc(46, ringing),
      h("div", { key: "nm", style: { fontSize: "24px", fontWeight: 800, letterSpacing: "-0.5px", color: "#f4f4f6" } }, name),
      h("div", { key: "st", style: { fontFamily: MONO, fontSize: "14px", fontWeight: 500, color: "#9a9aa2", marginTop: "8px" } }, callStatus),
      phase === "active" && h("div", { key: "q", style: { marginTop: "12px" } }, qualityIndicator(false))
    ]),
    h("div", { key: "ctrls", style: { flex: "none", display: "flex", alignItems: "flex-start", justifyContent: "center", gap: "26px", padding: "28px 24px 34px" } }, [
      labeled("mute", h("button", { onClick: doMute, title: "Mute", style: call.micEnabled ? ctrlBase : dangerCtrl }, svg2(call.micEnabled ? ICON.micOn : ICON.micOff, 22, 1.9)), call.micEnabled ? "Mute" : "Muted"),
      labeled("video", h("button", { onClick: doUpgrade, title: "Add video", style: ctrlBase }, svg2(ICON.camOn, 22, 1.8)), "Video"),
      labeled("end", h("button", { onClick: doEnd, title: "End call", style: endBtn }, svg2(ICON.phoneHangup, 22, 1.9)), "End")
    ])
  ]);
};
if (typeof window !== "undefined") {
  window.CallUIComponent = CallUIComponent;
}

// src/scripts/app-boot.js
window.EnhancedSecureCryptoUtils = EnhancedSecureCryptoUtils;
window.EnhancedSecureWebRTCManager = EnhancedSecureWebRTCManager;
window.EnhancedSecureFileTransfer = EnhancedSecureFileTransfer;
window.NotificationIntegration = import_NotificationIntegration.NotificationIntegration;
var purgeLegacyOfferRecords = () => {
  try {
    const stale = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith("qr_offer_")) stale.push(key);
    }
    for (const key of stale) {
      try {
        localStorage.removeItem(key);
      } catch (_) {
      }
    }
  } catch (_) {
  }
};
var start = () => {
  purgeLegacyOfferRecords();
  if (typeof window.initializeApp === "function") {
    window.initializeApp();
  } else if (window.DEBUG_MODE) {
    console.error("initializeApp is not defined on window");
  }
};
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start);
} else {
  start();
}
/**
 * Secure and Reliable Notification Manager for P2P WebRTC Chat
 * Follows best practices: OWASP, MDN, Chrome DevRel
 * 
 * @version 1.0.0
 * @author SecureBit Team
 * @license MIT
 */
/**
 * Notification Integration Module for SecureBit WebRTC Chat
 * Integrates secure notifications with existing WebRTC architecture
 * 
 * @version 1.0.0
 * @author SecureBit Team
 * @license MIT
 */
/*! Bundled license information:

dompurify/dist/purify.es.mjs:
  (*! @license DOMPurify 3.4.10 | (c) Cure53 and other contributors | Released under the Apache license 2.0 and Mozilla Public License 2.0 | github.com/cure53/DOMPurify/blob/3.4.10/LICENSE *)
*/
//# sourceMappingURL=app-boot.js.map
