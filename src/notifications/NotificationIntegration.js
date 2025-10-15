/**
 * Notification Integration Module for SecureBit WebRTC Chat
 * Integrates secure notifications with existing WebRTC architecture
 * 
 * @version 1.0.0
 * @author SecureBit Team
 * @license MIT
 */

import { SecureChatNotificationManager } from './SecureNotificationManager.js';

class NotificationIntegration {
  constructor(webrtcManager) {
    this.webrtcManager = webrtcManager;
    this.notificationManager = new SecureChatNotificationManager({
      maxQueueSize: 10,
      rateLimitMs: 1000, // Reduced from 2000ms to 1000ms
      trustedOrigins: [
        window.location.origin,
        // Add other trusted origins for CDN icons
      ]
    });
    
    this.isInitialized = false;
    this.originalOnMessage = null;
    this.originalOnStatusChange = null;
    this.processedMessages = new Set(); // Track processed messages to avoid duplicates
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

      // Store original callbacks
      this.originalOnMessage = this.webrtcManager.onMessage;
      this.originalOnStatusChange = this.webrtcManager.onStatusChange;


      // Wrap the original onMessage callback
      this.webrtcManager.onMessage = (message, type) => {
        this.handleIncomingMessage(message, type);
        
        // Call original callback if it exists
        if (this.originalOnMessage) {
          this.originalOnMessage(message, type);
        }
      };

      // Wrap the original onStatusChange callback
      this.webrtcManager.onStatusChange = (status) => {
        this.handleStatusChange(status);
        
        // Call original callback if it exists
        if (this.originalOnStatusChange) {
          this.originalOnStatusChange(status);
        }
      };

      // Also hook into the deliverMessageToUI method if it exists
      if (this.webrtcManager.deliverMessageToUI) {
        this.originalDeliverMessageToUI = this.webrtcManager.deliverMessageToUI.bind(this.webrtcManager);
        this.webrtcManager.deliverMessageToUI = (message, type) => {
          this.handleIncomingMessage(message, type);
          this.originalDeliverMessageToUI(message, type);
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
  handleIncomingMessage(message, type) {
    try {
      // Create a unique key for this message to avoid duplicates
      const messageKey = `${type}:${typeof message === 'string' ? message : JSON.stringify(message)}`;
      
      // Skip if we've already processed this message
      if (this.processedMessages.has(messageKey)) {
        return;
      }
      
      // Mark message as processed
      this.processedMessages.add(messageKey);
      
      // Clean up old processed messages (keep only last 100)
      if (this.processedMessages.size > 100) {
        const messagesArray = Array.from(this.processedMessages);
        this.processedMessages.clear();
        messagesArray.slice(-50).forEach(msg => this.processedMessages.add(msg));
      }
      
      
      // Only process chat messages, not system messages
      if (type === 'system' || type === 'file-transfer' || type === 'heartbeat') {
        return;
      }

      // Extract message information
      const messageInfo = this.extractMessageInfo(message, type);
      if (!messageInfo) {
        return;
      }

      // Send notification
      const notificationResult = this.notificationManager.notify(
        messageInfo.senderName,
        messageInfo.text,
        {
          icon: messageInfo.senderAvatar,
          senderId: messageInfo.senderId,
          onClick: (senderId) => {
            this.focusChatWindow();
          }
        }
      );

    } catch (error) {
      // Handle error silently
    }
  }

  /**
   * Handle status changes
   * @param {string} status - Connection status
   * @private
   */
  handleStatusChange(status) {
    try {
      // Clear notifications when connection is lost
      if (status === 'disconnected' || status === 'failed') {
        this.notificationManager.clearNotificationQueue();
        this.notificationManager.resetUnreadCount();
      }
    } catch (error) {
      // Handle error silently
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

      // Handle different message formats
      if (typeof message === 'string') {
        try {
          messageData = JSON.parse(message);
        } catch (e) {
          // Plain text message
          return {
            senderName: 'Peer',
            text: message,
            senderId: 'peer',
            senderAvatar: null
          };
        }
      }

      // Handle structured message data
      if (typeof messageData === 'object' && messageData !== null) {
        return {
          senderName: messageData.senderName || messageData.name || 'Peer',
          text: messageData.text || messageData.message || messageData.content || '',
          senderId: messageData.senderId || messageData.id || 'peer',
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
      
      // Scroll to bottom of messages if container exists
      const messagesContainer = document.getElementById('messages');
      if (messagesContainer) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
      }
    } catch (error) {
      // Handle error silently
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
        // Restore original callbacks
        if (this.originalOnMessage) {
          this.webrtcManager.onMessage = this.originalOnMessage;
        }
        if (this.originalOnStatusChange) {
          this.webrtcManager.onStatusChange = this.originalOnStatusChange;
        }
        if (this.originalDeliverMessageToUI) {
          this.webrtcManager.deliverMessageToUI = this.originalDeliverMessageToUI;
        }

        // Clear notifications
        this.clearNotifications();

        this.isInitialized = false;
      }
    } catch (error) {
      // Handle error silently
    }
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { NotificationIntegration };
}

// Global export for browser usage
if (typeof window !== 'undefined') {
  window.NotificationIntegration = NotificationIntegration;
}
