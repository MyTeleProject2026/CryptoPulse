import { useState, useEffect } from "react";
import { X, Target, Trophy } from "lucide-react";

export default function TargetModal({ isOpen, onClose, onSetTarget, currentTarget, currentProfit, isLoading }) {
  const [targetAmount, setTargetAmount] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (isOpen) {
      setTargetAmount(currentTarget || "");
      setError("");
    }
  }, [isOpen, currentTarget]);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    const amount = Number(targetAmount);
    
    if (!targetAmount || isNaN(amount)) {
      setError("Please enter a valid amount");
      return;
    }
    
    if (amount <= 0) {
      setError("Target amount must be greater than 0");
      return;
    }
    
    if (amount < 10) {
      setError("Minimum target amount is 10 USDT");
      return;
    }

    try {
      await onSetTarget(amount);
      setTargetAmount("");
      onClose();
    } catch (err) {
      setError(err.message || "Failed to set target");
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
      <div className="relative w-full max-w-md rounded-2xl border border-white/10 bg-gradient-to-b from-slate-900 to-slate-950 p-6 shadow-2xl">
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-slate-400 transition hover:text-white"
        >
          <X size={20} />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <Target className="h-6 w-6 text-lime-400" />
          <h2 className="text-xl font-bold text-white">Set Your Profit Target</h2>
        </div>

        <p className="text-sm text-slate-400 mb-2">
          Set a profit target to track your trading goals.
        </p>

        {currentProfit !== undefined && (
          <div className="mb-4 rounded-xl border border-lime-500/20 bg-lime-500/10 p-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-300">Current Profit:</span>
              <span className="text-lg font-bold text-lime-400">{currentProfit?.toFixed(2) || 0} USDT</span>
            </div>
          </div>
        )}

        {currentTarget && currentTarget > 0 && (
          <div className="mb-4 rounded-xl border border-white/10 bg-slate-800/50 p-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-300">Current Target:</span>
              <span className="text-lg font-bold text-cyan-400">{currentTarget} USDT</span>
            </div>
            <div className="mt-2 h-2 w-full rounded-full bg-slate-700">
              <div 
                className="h-2 rounded-full bg-lime-400 transition-all"
                style={{ width: `${Math.min(100, (currentProfit / currentTarget) * 100)}%` }}
              />
            </div>
            <p className="mt-2 text-xs text-slate-400">
              {((currentProfit / currentTarget) * 100).toFixed(1)}% achieved
            </p>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <label className="mb-2 block text-sm text-slate-300">
            Target Amount (USDT)
          </label>
          <input
            type="number"
            min="10"
            step="10"
            value={targetAmount}
            onChange={(e) => setTargetAmount(e.target.value)}
            placeholder="Enter target amount in USDT"
            className="w-full rounded-xl border border-white/10 bg-slate-800 px-4 py-3 text-white placeholder:text-slate-500 focus:border-lime-400 focus:outline-none"
          />
          
          <p className="mt-2 text-xs text-slate-500">
            Minimum target: 10 USDT. You can update your target anytime.
          </p>

          {error && (
            <div className="mt-3 rounded-lg border border-red-500/20 bg-red-500/10 p-2 text-sm text-red-300">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="mt-4 w-full rounded-xl bg-gradient-to-r from-lime-400 to-lime-500 py-3 font-semibold text-black transition hover:from-lime-300 hover:to-lime-400 disabled:opacity-50"
          >
            {isLoading ? "Setting Target..." : "Set Target"}
          </button>
        </form>

        <div className="mt-4 rounded-xl border border-white/10 bg-slate-800/30 p-3">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Trophy size={14} className="text-lime-400" />
            <span>Why set a target?</span>
          </div>
          <p className="mt-1 text-xs text-slate-500">
            Once you achieve your target, you can withdraw your profits freely without restrictions.
          </p>
        </div>
      </div>
    </div>
  );
}
