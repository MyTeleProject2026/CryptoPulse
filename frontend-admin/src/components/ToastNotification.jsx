import { useState, useEffect } from "react";
import { X, CheckCircle, AlertCircle, Info, AlertTriangle } from "lucide-react";

const TOAST_DURATION = 5000;

export default function ToastContainer() {
  const { toasts, removeToast } = useToast();
  
  if (toasts.length === 0) return null;
  
  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
      {toasts.map((toast) => (
        <Toast key={toast.id} toast={toast} onClose={() => removeToast(toast.id)} />
      ))}
    </div>
  );
}

function Toast({ toast, onClose }) {
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
    info: <Info size={18} className="text-cyan-400" />,
  };
  
  const bgColors = {
    success: "bg-emerald-500/10 border-emerald-500/20",
    error: "bg-red-500/10 border-red-500/20",
    warning: "bg-amber-500/10 border-amber-500/20",
    info: "bg-cyan-500/10 border-cyan-500/20",
  };
  
  return (
    <div className={`flex items-center gap-3 rounded-xl border p-3 shadow-lg ${bgColors[toast.type]}`}>
      {icons[toast.type]}
      <span className="text-sm text-white">{toast.message}</span>
      <button onClick={onClose} className="ml-2 text-slate-400 hover:text-white">
        <X size={14} />
      </button>
    </div>
  );
}

// Toast Hook
let toastId = 0;
const listeners = new Set();
let toasts = [];

function notifyListeners() {
  listeners.forEach((listener) => listener([...toasts]));
}

function addToast(message, type = "info") {
  const id = ++toastId;
  toasts.push({ id, message, type });
  notifyListeners();
  
  setTimeout(() => {
    removeToast(id);
  }, TOAST_DURATION);
  
  return id;
}

function removeToast(id) {
  toasts = toasts.filter((t) => t.id !== id);
  notifyListeners();
}

export function useToast() {
  const [localToasts, setLocalToasts] = useState([]);
  
  useEffect(() => {
    const listener = (newToasts) => {
      setLocalToasts(newToasts);
    };
    listeners.add(listener);
    
    return () => {
      listeners.delete(listener);
    };
  }, []);
  
  return {
    toasts: localToasts,
    addToast,
    removeToast,
    ToastContainer,
  };
}
