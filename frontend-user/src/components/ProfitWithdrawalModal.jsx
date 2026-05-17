import { useState, useEffect } from "react";
import { X, AlertTriangle, DollarSign } from "lucide-react";
export default function ProfitWithdrawalModal({ 
  isOpen, 
  onClose, 
  onSubmit, 
  maxAmount, 
  minAmount,
  currentProfit,
  currentTarget,
  isLoading 
}) {
  const [amount, setAmount] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (isOpen) {
      setAmount("");
      setError("");
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const maxWithdrawable = Math.min(maxAmount, currentProfit || 0);
  const minWithdrawable = minAmount || 10;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    const withdrawAmount = Number(amount);
    
    if (!amount || isNaN(withdrawAmount)) {
      setError("Please enter a valid amount");
      return;
    }
    
    if (withdrawAmount < minWithdrawable) {
      setError(`Minimum withdrawal amount is ${minWithdrawable} USDT`);
      return;
    }
    
    if (withdrawAmount > maxWithdrawable) {
      setError(`Maximum withdrawal amount is ${maxWithdrawable} USDT`);
      return;
    }
    
    if (currentProfit !== undefined && withdrawAmount > currentProfit) {
      setError(`You only have ${currentProfit?.toFixed(2)} USDT in profits`);
      return;
    }

    try {
      await onSubmit(withdrawAmount);
      setAmount("");
      onClose();
    } catch (err) {
      setError(err.message || "Failed to process withdrawal");
    }
  };

  const progress = currentTarget && currentTarget > 0 
    ? ((currentProfit / currentTarget) * 100).toFixed(1)
    : 0;

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
          <DollarSign className="h-6 w-6 text-lime-400" />
          <h2 className="text-xl font-bold text-white">Withdraw Profit</h2>
        </div>

        <div className="mb-4 rounded-xl border border-white/10 bg-slate-800/30 p-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <div className="text-xs text-slate-500">Available Profit</div>
              <div className="text-lg font-bold text-lime-400">
                {currentProfit?.toFixed(2) || 0} USDT
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-500">Target Progress</div>
              <div className="text-lg font-bold text-cyan-400">{progress}%</div>
            </div>
          </div>
          <div className="mt-2 h-1.5 w-full rounded-full bg-slate-700">
            <div 
              className="h-1.5 rounded-full bg-lime-400 transition-all"
              style={{ width: `${Math.min(100, progress)}%` }}
            />
          </div>
        </div>

        <div className="mb-4 rounded-xl border border-amber-500/20 bg-amber-500/10 p-3">
          <div className="flex items-start gap-2">
            <AlertCircle size={16} className="mt-0.5 text-amber-400" />
            <div className="text-xs text-amber-300">
              You are withdrawing from your profits before achieving your target.
              Your remaining profit will continue to grow toward your goal.
            </div>
          </div>
        </div>

        <div className="mb-4 flex justify-between text-sm">
          <span className="text-slate-400">Min: {minWithdrawable} USDT</span>
          <span className="text-slate-400">Max: {maxWithdrawable} USDT</span>
        </div>

        <form onSubmit={handleSubmit}>
          <label className="mb-2 block text-sm text-slate-300">
            Withdrawal Amount (USDT)
          </label>
          <input
            type="number"
            min={minWithdrawable}
            max={maxWithdrawable}
            step="1"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            placeholder={`Enter amount between ${minWithdrawable} and ${maxWithdrawable} USDT`}
            className="w-full rounded-xl border border-white/10 bg-slate-800 px-4 py-3 text-white placeholder:text-slate-500 focus:border-lime-400 focus:outline-none"
          />

          {error && (
            <div className="mt-3 rounded-lg border border-red-500/20 bg-red-500/10 p-2 text-sm text-red-300">
              {error}
            </div>
          )}

          <div className="mt-4 grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setAmount(Math.floor(maxWithdrawable * 0.25).toString())}
              className="rounded-lg border border-white/10 bg-slate-800 py-2 text-sm text-white transition hover:bg-slate-700"
            >
              25%
            </button>
            <button
              type="button"
              onClick={() => setAmount(Math.floor(maxWithdrawable * 0.5).toString())}
              className="rounded-lg border border-white/10 bg-slate-800 py-2 text-sm text-white transition hover:bg-slate-700"
            >
              50%
            </button>
            <button
              type="button"
              onClick={() => setAmount(Math.floor(maxWithdrawable * 0.75).toString())}
              className="rounded-lg border border-white/10 bg-slate-800 py-2 text-sm text-white transition hover:bg-slate-700"
            >
              75%
            </button>
            <button
              type="button"
              onClick={() => setAmount(maxWithdrawable.toString())}
              className="rounded-lg border border-white/10 bg-slate-800 py-2 text-sm text-white transition hover:bg-slate-700"
            >
              Max
            </button>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="mt-4 w-full rounded-xl bg-gradient-to-r from-lime-400 to-lime-500 py-3 font-semibold text-black transition hover:from-lime-300 hover:to-lime-400 disabled:opacity-50"
          >
            {isLoading ? "Processing..." : "Withdraw Profit"}
          </button>
        </form>

        <p className="mt-4 text-center text-xs text-slate-500">
          Withdrawal requests are reviewed by admin and typically processed within 24 hours.
        </p>
      </div>
    </div>
  );
}
