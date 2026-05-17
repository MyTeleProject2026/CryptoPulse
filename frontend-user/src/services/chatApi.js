// frontend-user/src/services/chatApi.js
import io from "socket.io-client";

let socket = null;
let isConnected = false;

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "https://cryptopulse-4rhe.onrender.com";

export const chatApi = {
  // Connect to socket server
  connect: (userId, name, token) => {
    if (socket && isConnected) {
      return socket;
    }

    socket = io(API_BASE_URL, {
      transports: ["websocket", "polling"],
      withCredentials: true,
    });

    socket.on("connect", () => {
      console.log("Socket connected");
      isConnected = true;
      
      socket.emit("authenticate", {
        userId: userId,
        role: "user",
        name: name,
        token: token
      });
    });

    socket.on("disconnect", () => {
      console.log("Socket disconnected");
      isConnected = false;
    });

    return socket;
  },

  // Disconnect socket
  disconnect: () => {
    if (socket) {
      socket.disconnect();
      socket = null;
      isConnected = false;
    }
  },

  // Get socket instance
  getSocket: () => socket,

  // Check if connected
  isConnected: () => isConnected,

  // Send message
  sendMessage: (conversationId, message) => {
    if (socket && isConnected) {
      socket.emit("send_message", { conversationId, message });
    }
  },

  // ✅ ADD THIS FUNCTION - Get messages for a conversation
  getMessages: (conversationId) => {
    if (socket && isConnected) {
      console.log("Requesting messages for conversation:", conversationId);
      socket.emit("get_messages", { conversationId });
    }
  },

  // Mark messages as read
  markRead: (conversationId) => {
    if (socket && isConnected) {
      socket.emit("mark_read", { conversationId });
    }
  },

  // Get conversations
  getConversations: () => {
    if (socket && isConnected) {
      socket.emit("get_conversations");
    }
  },

  // Event listeners
  onNewMessage: (callback) => {
    if (socket) {
      socket.on("new_message", callback);
    }
  },

  onMessagesLoaded: (callback) => {
    if (socket) {
      socket.on("messages_loaded", callback);
    }
  },

  onUserConversations: (callback) => {
    if (socket) {
      socket.on("user_conversations", callback);
    }
  },

  onMessageSent: (callback) => {
    if (socket) {
      socket.on("message_sent", callback);
    }
  },

  off: (event) => {
    if (socket) {
      socket.off(event);
    }
  },
};
