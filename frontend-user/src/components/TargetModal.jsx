import { useState, useEffect } from "react";
import { Target, X, TrendingUp, CheckCircle } from "lucide-react";
// ✅ ADD THIS IMPORT - Missing in CryptoPulse
import { userApi } from "../services/api";
// ✅ ADD THIS IMPORT - Missing in CryptoPulse
import { useNotification } from "../hooks/useNotification";

export default function TargetModal({ isOpen, onClose, onSetTarget, requiredFor = "trade" }) {
  // ✅ ADD THIS - Missing token handling in CryptoPulse
  const token =
    localStorage.getItem("userToken") ||
    localStorage.getItem("token") ||
    localStorage.getItem("accessToken") ||
    "";

  // ✅ ADD THIS - Missing useNotification hook
  const { showSuccess, showError } = useNotification();

  const [targetAmount, setTargetAmount] = useState("");
  // ✅ ADD THIS - Missing loading state
  const [loading, setLoading] = useState(false);
  // ✅ ADD THIS - Missing checking state
  const [checking, setChecking] = useState(true);
  // ✅ ADD THIS - Missing existing target state
  const [existingTarget, setExistingTarget] = useState(null);
  // ✅ ADD THIS - Missing success screen state
  const [showSuccessScreen, setShowSuccessScreen] = useState(false);
  // ✅ ADD THIS - Missing new target form state
  const [showNewTargetForm, setShowNewTargetForm] = useState(false);

  // ✅ ADD THIS - Check existing target when modal opens
  useEffect(() => {
    if (isOpen && token) {
      checkExistingTarget();
    }
  }, [isOpen, token]);

  // ✅ ADD THIS - Function to check existing target
  async function checkExistingTarget() {
    try {
      setChecking(true);
      const res = await userApi.getUserTarget(token);
      if (res.data?.success && res.data.data.hasTarget) {
        setExistingTarget(res.data.data.target);
      } else {
        setExistingTarget(null);
      }
    } catch (err) {
      console.error("Failed to check target:", err);
    } finally {
      setChecking(false);
    }
  }

  // ✅ ADD THIS - Function to set target
  async function handleSetTarget() {
    const amount = Number(targetAmount);
    if (!amount || amount <= 0) {
      showError("Please enter a valid target amount");
      return;
    }

    if (amount < 10) {
      showError("Minimum target amount is 10 USDT");
      return;
    }

    try {
      setLoading(true);
      const res = await userApi.setUserTarget({ targetAmount: amount }, token);
      if (res.data?.success) {
        setShowSuccessScreen(true);
        setTimeout(() => {
          onSetTarget?.(amount);
          onClose();
          setShowSuccessScreen(false);
          setTargetAmount("");
          setShowNewTargetForm(false);
        }, 2000);
      }
    } catch (err) {
      showError(err.response?.data?.message || "Failed to set target");
    } finally {
      setLoading(false);
    }
  }

  // ✅ ADD THIS - Function to set new target after achievement
  async function handleSetNewTarget() {
    const amount = Number(targetAmount);
    if (!amount || amount <= 0) {
      showError("Please enter a valid target amount");
      return;
    }

    if (amount < 10) {
      showError("Minimum target amount is 10 USDT");
      return;
    }

    try {
      setLoading(true);
      const res = await userApi.setUserTarget({ targetAmount: amount }, token);
      if (res.data?.success) {
        setShowSuccessScreen(true);
        setTimeout(() => {
          onSetTarget?.(amount);
          onClose();
          setShowSuccessScreen(false);
          setTargetAmount("");
          setShowNewTargetForm(false);
        }, 2000);
      }
    } catch (err) {
      showError(err.response?.data?.message || "Failed to set new target");
    } finally {
      setLoading(false);
    }
  }

  // ✅ ADD THIS - Reset and close function
  function resetAndClose() {
    setTargetAmount("");
    setShowSuccessScreen(false);
    setShowNewTargetForm(false);
    onClose();
  }

  if (!isOpen) return null;

  // ✅ ADD THIS - Calculate progress
  const currentProfit = Number(existingTarget?.current_profit || 0);
  const targetTotal = Number(existingTarget?.target_amount || 0);
  const progressPercent = targetTotal > 0 ? (currentProfit / targetTotal) * 100 : 0;
  const isTargetAchieved = existingTarget?.status === 'achieved' || (targetTotal > 0 && currentProfit >= targetTotal);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
      <div className="relative w-full max-w-md rounded-2xl border border-white/10 bg-gradient-to-b from-slate-900 to-slate-950 p-6 shadow-2xl">
        <button
          onClick={resetAndClose}
          className="absolute right-4 top-4 text-slate-400 transition hover:text-white"
        >
          <X size={20} />
        </button>

        {showSuccessScreen ? (
          <div className="text-center py-8">
            <div className="flex justify-center mb-4">
              <div className="flex h-16 w-16 items-center justify-center rounded-full bg-emerald-500/20">
                <CheckCircle size={32} className="text-emerald-400" />
              </div>
            </div>
            <h2 className="text-xl font-bold text-white">Target Set!</h2>
            <p className="mt-2 text-slate-400">
              Your goal is set. Start trading to achieve it!
            </p>
          </div>
        ) : checking ? (
          <div className="py-8 text-center text-slate-400">Loading...</div>
        ) : existingTarget && !showNewTargetForm ? (
          <div className="space-y-4">
            <div className="flex items-center gap-3 mb-2">
              <Target className="h-6 w-6 text-lime-400" />
              <h2 className="text-xl font-bold text-white">Your Active Goal</h2>
            </div>

            <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-4">
              <div className="text-sm text-slate-400">Your Active Goal</div>
              <div className="mt-1 text-2xl font-bold text-cyan-300">
                {targetTotal.toFixed(2)} USDT
              </div>
              <div className="mt-2 text-sm text-slate-400">
                Current Profit: {currentProfit.toFixed(2)} USDT
              </div>
              <div className="mt-3">
                <div className="flex justify-between text-xs text-slate-400 mb-1">
                  <span>Progress</span>
                  <span>{progressPercent.toFixed(1)}%</span>
                </div>
                <div className="h-2 rounded-full bg-white/10 overflow-hidden">
                  <div
                    className="h-full bg-cyan-400 rounded-full transition-all"
                    style={{ width: `${Math.min(100, progressPercent)}%` }}
                  />
                </div>
              </div>
            </div>

            {isTargetAchieved && (
              <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-4">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle size={18} className="text-emerald-400" />
                  <span className="text-sm font-semibold text-emerald-300">Target Achieved!</span>
                </div>
                <p className="text-sm text-slate-300 mb-3">
                  Congratulations! You've reached your goal!
                </p>
                <button
                  onClick={() => {
                    setShowNewTargetForm(true);
                    setTargetAmount("");
                  }}
                  className="w-full rounded-lg border border-emerald-500/30 bg-emerald-500/10 py-2 text-sm font-semibold text-emerald-300 hover:bg-emerald-500/20 transition"
                >
                  Set New Target →
                </button>
              </div>
            )}

            <button
              onClick={resetAndClose}
              className="w-full rounded-xl bg-cyan-500 py-3 font-semibold text-black hover:bg-cyan-400"
            >
              Continue to {requiredFor === "trade" ? "Trade" : "Funds"}
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center gap-3 mb-2">
              <Target className="h-6 w-6 text-lime-400" />
              <h2 className="text-xl font-bold text-white">
                {showNewTargetForm ? "Set New Target" : "Set Your Target"}
              </h2>
            </div>

            <p className="text-sm text-slate-400">
              {showNewTargetForm 
                ? "Set a new profit target to continue trading. Your previous goal has been achieved!"
                : "Set a profit target you want to achieve. Once set, you can start trading. Your profits will automatically count toward your goal."
              }
            </p>

            <div>
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
            </div>

            <div className="flex gap-3">
              {[100, 500, 1000, 5000].map((preset) => (
                <button
                  key={preset}
                  type="button"
                  onClick={() => setTargetAmount(String(preset))}
                  className="flex-1 rounded-xl border border-white/10 bg-white/5 py-2 text-sm text-white hover:bg-white/10"
                >
                  {preset}
                </button>
              ))}
            </div>

            <button
              onClick={showNewTargetForm ? handleSetNewTarget : handleSetTarget}
              disabled={loading}
              className="mt-4 w-full rounded-xl bg-gradient-to-r from-lime-400 to-lime-500 py-3 font-semibold text-black transition hover:from-lime-300 hover:to-lime-400 disabled:opacity-50"
            >
              {loading ? "Setting..." : (showNewTargetForm ? "Set New Target" : "Set Target")}
            </button>

            <div className="mt-4 rounded-xl border border-white/10 bg-slate-800/30 p-3">
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <TrendingUp size={14} className="text-lime-400" />
                <span>Why set a target?</span>
              </div>
              <p className="mt-1 text-xs text-slate-500">
                Once you achieve your target, you can withdraw your profits freely without restrictions.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
