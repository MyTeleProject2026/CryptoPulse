import io from "socket.io-client";

let socket = null;
let isConnected = false;

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "https://cryptopulse-4rhe.onrender.com";

export const adminChatApi = {
  connect: (adminId, adminName, token) => {
    if (socket && isConnected) return socket;

    socket = io(API_BASE_URL, {
      transports: ["websocket", "polling"],
      withCredentials: true,
    });

    socket.on("connect", () => {
      console.log("Admin socket connected");
      isConnected = true;
      socket.emit("authenticate", {
        userId: adminId,
        role: "admin",
        name: adminName,
        token: token
      });
    });

    socket.on("disconnect", () => {
      console.log("Admin socket disconnected");
      isConnected = false;
    });

    return socket;
  },

  disconnect: () => {
    if (socket) {
      socket.disconnect();
      socket = null;
      isConnected = false;
    }
  },

  getSocket: () => socket,
  isConnected: () => isConnected,
 
  getMessages: (conversationId) => {
    if (socket && isConnected) {
      socket.emit("get_messages", { conversationId });
    }
  },

  sendMessage: (conversationId, message) => {
    if (socket && isConnected) {
      socket.emit("send_message", { conversationId, message });
    }
  },

  deleteMessage: (conversationId, messageId) => {
    if (socket && isConnected) {
      socket.emit("delete_message", { conversationId, messageId });
    }
  },

  markRead: (conversationId) => {
    if (socket && isConnected) {
      socket.emit("mark_read", { conversationId });
    }
  },

  onNewMessage: (callback) => {
    if (socket) socket.on("new_message", callback);
  },

  onAdminConversations: (callback) => {
    if (socket) socket.on("admin_conversations", callback);
  },

  onMessagesLoaded: (callback) => {
    if (socket) socket.on("messages_loaded", callback);
  },

  onMessageDeleted: (callback) => {
    if (socket) socket.on("message_deleted", callback);
  },

  onMessageSent: (callback) => {
    if (socket) socket.on("message_sent", callback);
  },

  off: (event) => {
    if (socket) socket.off(event);
  },
};
