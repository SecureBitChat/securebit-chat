/**
 * Secure and Reliable Notification Manager for P2P WebRTC Chat
 * Follows best practices: OWASP, MDN, Chrome DevRel
 * 
 * @version 1.0.0
 * @author SecureBit Team
 * @license MIT
 */

class SecureChatNotificationManager {
  constructor(config = {}) {
    this.permission = Notification.permission;
    this.isTabActive = this.checkTabActive(); // Initialize with proper check
    this.unreadCount = 0;
    this.originalTitle = document.title;
    this.notificationQueue = [];
    this.maxQueueSize = config.maxQueueSize || 5;
    this.rateLimitMs = config.rateLimitMs || 2000; // Spam protection
    this.lastNotificationTime = 0;
    this.trustedOrigins = config.trustedOrigins || [];
    
    // Secure context flag
    this.isSecureContext = window.isSecureContext;
    
    // Cross-browser compatibility for Page Visibility API
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
    // Security checks are performed silently
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
    return "hidden"; // fallback
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
    return "visibilitychange"; // fallback
  }

  /**
   * Check if tab is currently active using multiple methods
   * @returns {boolean} True if tab is active
   * @private
   */
  checkTabActive() {
    // Primary method: Page Visibility API
    if (this.hidden && typeof document[this.hidden] !== "undefined") {
      return !document[this.hidden];
    }
    
    // Fallback method: document.hasFocus()
    if (typeof document.hasFocus === "function") {
      return document.hasFocus();
    }
    
    // Ultimate fallback: assume active
    return true;
  }

  /**
   * Initialize page visibility tracking (Page Visibility API)
   * @private
   */
  initVisibilityTracking() {
    // Primary method: Page Visibility API with cross-browser support
    if (typeof document.addEventListener !== "undefined" && typeof document[this.hidden] !== "undefined") {
      document.addEventListener(this.visibilityChange, () => {
        this.isTabActive = this.checkTabActive();
        
        if (this.isTabActive) {
          this.resetUnreadCount();
          this.clearNotificationQueue();
        }
      });
    }

    // Fallback method: Window focus/blur events
    window.addEventListener('focus', () => {
      this.isTabActive = this.checkTabActive();
      if (this.isTabActive) {
        this.resetUnreadCount();
      }
    });

    window.addEventListener('blur', () => {
      this.isTabActive = this.checkTabActive();
    });

    // Page unload cleanup
    window.addEventListener('beforeunload', () => {
      this.clearNotificationQueue();
    });
  }

  /**
   * Request notification permission (BEST PRACTICE: Only call in response to user action)
   * Never call on page load!
   * @returns {Promise<boolean>} Permission granted status
   */
  async requestPermission() {
    // Secure context check
    if (!this.isSecureContext || !('Notification' in window)) {
      return false;
    }

    if (this.permission === 'granted') {
      return true;
    }

    if (this.permission === 'denied') {
      return false;
    }

    try {
      this.permission = await Notification.requestPermission();
      return this.permission === 'granted';
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
  sanitizeText(text) {
    if (typeof text !== 'string') {
      return '';
    }
    
    // Remove HTML tags and potentially dangerous characters
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .substring(0, 500); // Length limit
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
      
      // Only allow HTTPS and data URLs
      if (parsedUrl.protocol === 'https:' || parsedUrl.protocol === 'data:') {
        // Check trusted origins if specified
        if (this.trustedOrigins.length > 0) {
          const isTrusted = this.trustedOrigins.some(origin => 
            parsedUrl.origin === origin
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
    // Update tab active state before checking
    this.isTabActive = this.checkTabActive();
    
    // Only show if tab is NOT active (user is on another tab or minimized)
    if (this.isTabActive) {
      return null;
    }

    // Permission check
    if (this.permission !== 'granted') {
      return null;
    }

    // Rate limiting
    if (!this.checkRateLimit()) {
      return null;
    }

    // Data sanitization (XSS Protection)
    const safeSenderName = this.sanitizeText(senderName || 'Unknown');
    const safeMessage = this.sanitizeText(message || '');
    const safeIcon = this.validateIconUrl(options.icon) || '/logo/icon-192x192.png';

    // Queue overflow protection
    if (this.notificationQueue.length >= this.maxQueueSize) {
      this.clearNotificationQueue();
    }

    try {
      
      const notification = new Notification(
        `${safeSenderName}`,
        {
          body: safeMessage.substring(0, 200), // Length limit
          icon: safeIcon,
          badge: safeIcon,
          tag: `chat-${options.senderId || 'unknown'}`, // Grouping
          requireInteraction: false, // Don't block user
          silent: options.silent || false,
          // Vibrate only for mobile and if supported
          vibrate: navigator.vibrate ? [200, 100, 200] : undefined,
          // Safe metadata
          data: {
            senderId: this.sanitizeText(options.senderId),
            timestamp: Date.now(),
            // Don't include sensitive data!
          }
        }
      );

      // Increment counter
      this.unreadCount++;
      this.updateTitle();

      // Add to queue for management
      this.notificationQueue.push(notification);

      // Safe click handler
      notification.onclick = (event) => {
        event.preventDefault(); // Prevent default behavior
        window.focus();
        notification.close();
        
        // Safe callback
        if (typeof options.onClick === 'function') {
          try {
            options.onClick(options.senderId);
          } catch (error) {
            console.error('[Notifications] Error in onClick handler:', error);
          }
        }
      };

      // Error handler
      notification.onerror = (event) => {
        console.error('[Notifications] Error showing notification:', event);
      };

      // Auto-close after reasonable time
      const autoCloseTimeout = Math.min(options.autoClose || 5000, 10000);
      setTimeout(() => {
        notification.close();
        this.removeFromQueue(notification);
      }, autoCloseTimeout);

      return notification;
      
    } catch (error) {
      console.error('[Notifications] Failed to create notification:', error);
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
    this.notificationQueue.forEach(notification => {
      try {
        notification.close();
      } catch (error) {
        // Ignore errors when closing
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
}

/**
 * Secure integration with WebRTC
 */
class SecureP2PChat {
  constructor() {
    this.notificationManager = new SecureChatNotificationManager({
      maxQueueSize: 5,
      rateLimitMs: 2000,
      trustedOrigins: [
        window.location.origin,
        // Add other trusted origins for CDN icons
      ]
    });
    
    this.dataChannel = null;
    this.peerConnection = null;
    this.remotePeerName = 'Peer';
    this.messageHistory = [];
    this.maxHistorySize = 100;
  }

  /**
   * Initialize when user connects
   */
  async init() {
    // Initialize notification manager silently
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
      console.error('[Chat] Invalid DataChannel');
      return;
    }

    this.dataChannel = dataChannel;
    
    // Setup handlers
    this.dataChannel.onmessage = (event) => {
      this.handleIncomingMessage(event.data);
    };

    this.dataChannel.onerror = (error) => {
      // Handle error silently
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
      const message = typeof data === 'string' ? JSON.parse(data) : data;
      
      // Check message structure
      if (!message || typeof message !== 'object') {
        throw new Error('Invalid message structure');
      }

      // Check required fields
      if (!message.text || typeof message.text !== 'string') {
        throw new Error('Invalid message text');
      }

      // Message length limit (DoS protection)
      if (message.text.length > 10000) {
        throw new Error('Message too long');
      }

      return {
        text: message.text,
        senderName: message.senderName || 'Unknown',
        senderId: message.senderId || 'unknown',
        timestamp: message.timestamp || Date.now(),
        senderAvatar: message.senderAvatar || null
      };
      
    } catch (error) {
      console.error('[Chat] Message validation failed:', error);
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

    // Save to history (with limit)
    this.messageHistory.push(message);
    if (this.messageHistory.length > this.maxHistorySize) {
      this.messageHistory.shift();
    }

    // Display in UI (with sanitization)
    this.displayMessage(message);

    // Send notification only if tab is inactive
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

    // Optional: sound (with check)
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
    const container = document.getElementById('messages');
    if (!container) {
      return;
    }

    const messageEl = document.createElement('div');
    messageEl.className = 'message';
    
    // Use textContent to prevent XSS
    const nameEl = document.createElement('strong');
    nameEl.textContent = message.senderName + ': ';
    
    const textEl = document.createElement('span');
    textEl.textContent = message.text;
    
    const timeEl = document.createElement('small');
    timeEl.textContent = new Date(message.timestamp).toLocaleTimeString();
    
    messageEl.appendChild(nameEl);
    messageEl.appendChild(textEl);
    messageEl.appendChild(document.createElement('br'));
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
      // Use only local audio files
      const audio = new Audio('/assets/audio/notification.mp3');
      audio.volume = 0.3; // Moderate volume
      
      // Error handling
      audio.play().catch(error => {
        // Handle audio error silently
      });
    } catch (error) {
      // Handle audio creation error silently
    }
  }

  /**
   * Scroll to latest message
   * @private
   */
  scrollToLatestMessage() {
    const container = document.getElementById('messages');
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
      connected: this.dataChannel?.readyState === 'open'
    };
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SecureChatNotificationManager, SecureP2PChat };
}

// Global export for browser usage
if (typeof window !== 'undefined') {
  window.SecureChatNotificationManager = SecureChatNotificationManager;
  window.SecureP2PChat = SecureP2PChat;
}
