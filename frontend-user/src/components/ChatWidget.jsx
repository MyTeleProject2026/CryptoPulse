// frontend-user/src/components/ChatWidget.jsx
import { useState, useEffect, useRef, useCallback } from "react";
import { MessageCircle, X, Send, Minimize2, Maximize2 } from "lucide-react";
import { chatApi } from "../services/chatApi";

function formatTime(date) {
  if (!date) return "";
  const d = new Date(date);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export default function ChatWidget({ userId, userName }) {
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [messages, setMessages] = useState([]);
  const [conversations, setConversations] = useState([]);
  const [activeConversation, setActiveConversation] = useState(null);
  const [inputMessage, setInputMessage] = useState("");
  const [unreadCount, setUnreadCount] = useState(0);
  const [isConnected, setIsConnected] = useState(false);

  const messagesEndRef = useRef(null);
  const socketRef = useRef(null);

  // Scroll to bottom of messages
  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  // Connect to socket when component mounts
  useEffect(() => {
    if (!userId) return;

    const token = localStorage.getItem("userToken") || localStorage.getItem("token") || "";
    
    const socket = chatApi.connect(userId, userName, token);
    socketRef.current = socket;
    setIsConnected(true);

    // Listen for new messages
    chatApi.onNewMessage((data) => {
      if (data.conversationId === activeConversation?.id) {
        setMessages((prev) => [...prev, {
          id: data.id,
          message: data.message,
          senderType: data.senderType,
          createdAt: data.createdAt
        }]);
        scrollToBottom();
      }
      
      // Update unread count
      if (data.senderType === "admin") {
        setUnreadCount((prev) => prev + 1);
      }
      
      // Refresh conversations
      chatApi.getConversations();
    });

    // Load conversations
    chatApi.onUserConversations((data) => {
      setConversations(data.conversations || []);
      
      // Calculate total unread
      const totalUnread = (data.conversations || []).reduce((sum, conv) => sum + (conv.unread_user || 0), 0);
      setUnreadCount(totalUnread);
      
      // If no active conversation and has conversations, load first one
      if (!activeConversation && data.conversations?.length > 0) {
        setActiveConversation(data.conversations[0]);
        chatApi.getMessages(data.conversations[0].id);
        chatApi.markRead(data.conversations[0].id);
      }
    });

    // Load messages
    chatApi.onMessagesLoaded((data) => {
      setMessages(data.messages || []);
      scrollToBottom();
    });

    // Get initial conversations
    chatApi.getConversations();

    return () => {
      chatApi.off("new_message");
      chatApi.off("user_conversations");
      chatApi.off("messages_loaded");
    };
  }, [userId, userName]);

  const handleSendMessage = () => {
    if (!inputMessage.trim()) return;
    
    chatApi.sendMessage(activeConversation?.id, inputMessage.trim());
    setInputMessage("");
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleOpen = () => {
    setIsOpen(true);
    setIsMinimized(false);
    
    // Mark messages as read when opening
    if (activeConversation?.id) {
      chatApi.markRead(activeConversation.id);
      setUnreadCount(0);
    }
  };

  const handleSelectConversation = (conversation) => {
    setActiveConversation(conversation);
    chatApi.getMessages(conversation.id);
    chatApi.markRead(conversation.id);
    setUnreadCount(0);
  };

  if (!isOpen) {
    return (
      <button
        onClick={handleOpen}
        className="fixed bottom-20 right-4 z-50 flex h-14 w-14 items-center justify-center rounded-full bg-lime-400 text-black shadow-lg transition hover:bg-lime-300 md:bottom-6"
      >
        {unreadCount > 0 && (
          <span className="absolute -right-1 -top-1 flex h-5 w-5 items-center justify-center rounded-full bg-red-500 text-xs text-white">
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
        <MessageCircle size={24} />
      </button>
    );
  }

  return (
    <div className="fixed bottom-0 right-0 z-50 flex flex-col w-full max-w-md bg-[#0a0e1a] border border-white/10 rounded-t-2xl shadow-2xl md:bottom-4 md:right-4 md:rounded-2xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/10 bg-[#111111] px-4 py-3">
        <div className="flex items-center gap-2">
          <MessageCircle size={18} className="text-lime-400" />
          <span className="font-semibold text-white">Support Chat</span>
          {isConnected && (
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsMinimized(!isMinimized)}
            className="rounded p-1 text-slate-400 hover:text-white"
          >
            {isMinimized ? <Maximize2 size={16} /> : <Minimize2 size={16} />}
          </button>
          <button
            onClick={() => setIsOpen(false)}
            className="rounded p-1 text-slate-400 hover:text-white"
          >
            <X size={18} />
          </button>
        </div>
      </div>

      {!isMinimized && (
        <>
          {/* Conversations List */}
          {conversations.length > 0 && (
            <div className="border-b border-white/10 bg-[#0f0f0f] px-2 py-2 overflow-x-auto">
              <div className="flex gap-2">
                {conversations.map((conv) => (
                  <button
                    key={conv.id}
                    onClick={() => handleSelectConversation(conv)}
                    className={`rounded-full px-3 py-1.5 text-xs whitespace-nowrap transition ${
                      activeConversation?.id === conv.id
                        ? "bg-lime-400 text-black"
                        : "border border-white/10 bg-white/5 text-slate-300"
                    }`}
                  >
                    Chat #{conv.id}
                    {conv.unread_user > 0 && (
                      <span className="ml-1.5 rounded-full bg-red-500 px-1.5 py-0.5 text-[9px] text-white">
                        {conv.unread_user}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Messages Area */}
          <div className="h-96 overflow-y-auto p-4 space-y-3">
            {messages.length === 0 ? (
              <div className="flex h-full items-center justify-center text-center text-sm text-slate-400">
                <div>
                  <p>No messages yet.</p>
                  <p className="mt-1 text-xs">Send a message to our support team!</p>
                </div>
              </div>
            ) : (
              messages.map((msg) => (
                <div
                  key={msg.id}
                  className={`flex ${msg.senderType === "user" ? "justify-end" : "justify-start"}`}
                >
                  <div
                    className={`max-w-[80%] rounded-2xl px-4 py-2 ${
                      msg.senderType === "user"
                        ? "bg-lime-400 text-black"
                        : "bg-[#1a1e2a] text-white"
                    }`}
                  >
                    <p className="text-sm break-words">{msg.message}</p>
                    <p className={`mt-1 text-[10px] ${msg.senderType === "user" ? "text-black/60" : "text-slate-400"}`}>
                      {formatTime(msg.created_at || msg.createdAt)}
                    </p>
                  </div>
                </div>
              ))
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input Area */}
          <div className="border-t border-white/10 bg-[#111111] p-3">
            <div className="flex gap-2">
              <textarea
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyDown={handleKeyPress}
                placeholder="Type your message..."
                className="flex-1 resize-none rounded-xl border border-white/10 bg-[#0a0e1a] px-3 py-2 text-sm text-white outline-none focus:border-lime-400"
                rows={1}
                style={{ minHeight: "40px", maxHeight: "100px" }}
              />
              <button
                onClick={handleSendMessage}
                disabled={!inputMessage.trim()}
                className="flex h-10 w-10 items-center justify-center rounded-xl bg-lime-400 text-black transition hover:bg-lime-300 disabled:opacity-50"
              >
                <Send size={18} />
              </button>
            </div>
            <p className="mt-2 text-center text-[10px] text-slate-500">
              Our team typically responds within a few hours
            </p>
          </div>
        </>
      )}
    </div>
  );
}
