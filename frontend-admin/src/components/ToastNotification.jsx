// frontend-admin/src/components/ToastNotification.jsx
import { useState, useEffect, createContext, useContext, useCallback } from "react";
import { X, CheckCircle, AlertCircle, Info, AlertTriangle } from "lucide-react";

const TOAST_DURATION = 5000;

// Toast Context
const ToastContext = createContext(null);

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((message, type = "info") => {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, message, type }]);
    
    setTimeout(() => {
      setToasts((prev) => prev.filter((toast) => toast.id !== id));
    }, TOAST_DURATION);
    
    return id;
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ addToast, removeToast, toasts }}>
      {children}
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error("useToast must be used within ToastProvider");
  }
  return context;
}

// Individual Toast Component
function ToastItem({ toast, onClose }) {
  useEffect(() => {
    const timer = setTimeout(() => {
      onClose();
    }, TOAST_DURATION);
    return () => clearTimeout(timer);
  }, [onClose]);

  const icons = {
    success: <CheckCircle size={18} className="text-emerald-400" />,
    error: <AlertCircle size={18} className="text-red-400" />,
    warning: <AlertTriangle size={18} className="text-amber-400" />,
    info: <Info size={18} className="text-lime-400" />,
  };

  const bgColors = {
    success: "bg-emerald-500/10 border-emerald-500/20",
    error: "bg-red-500/10 border-red-500/20",
    warning: "bg-amber-500/10 border-amber-500/20",
    info: "bg-lime-500/10 border-lime-500/20",
  };

  return (
    <div className={`flex items-center gap-3 rounded-xl border p-3 shadow-lg animate-slide-in ${bgColors[toast.type]}`}>
      {icons[toast.type]}
      <span className="text-sm text-white">{toast.message}</span>
      <button onClick={onClose} className="ml-2 text-slate-400 hover:text-white transition-colors">
        <X size={14} />
      </button>
    </div>
  );
}

// Toast Container Component
export function ToastContainer() {
  const { toasts, removeToast } = useToast();

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} onClose={() => removeToast(toast.id)} />
      ))}
    </div>
  );
}

// Simple standalone functions for non-React usage (optional)
let globalAddToast = null;
export function setGlobalToastHandler(handler) {
  globalAddToast = handler;
}
export function addToast(message, type = "info") {
  if (globalAddToast) {
    globalAddToast(message, type);
  } else {
    console.warn("Toast not initialized. Wrap your app in ToastProvider");
  }
}
