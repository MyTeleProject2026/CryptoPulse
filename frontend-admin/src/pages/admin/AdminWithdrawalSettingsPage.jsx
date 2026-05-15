import { useEffect, useState } from "react";
import { RefreshCw, Save, TrendingUp } from "lucide-react";
import { adminApi, getApiErrorMessage } from "../../services/api";
// ✅ FIXED: Import toast notification correctly (instead of useToast)
import { addToast, ToastContainer } from "../../components/ToastNotification";

export default function AdminWithdrawalSettingsPage() {
  const token = localStorage.getItem("adminToken") || localStorage.getItem("admin_token") || "";
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [settings, setSettings] = useState({
    min_withdrawal_from_profit: 10,
    max_withdrawal_from_profit: 1000,
    allow_withdrawal_before_target: true,
    restriction_message: "⚠️ Target not achieved yet. You can only withdraw from your profits. Minimum 10 USDT, Maximum 1000 USDT per request."
  });
  
  async function loadSettings() {
    try {
      setLoading(true);
      const res = await adminApi.getWithdrawalSettings(token);
      if (res.data?.success) {
        setSettings(res.data.data);
      }
      // ✅ ADDED: Toast notification for load success
      addToast("Withdrawal settings loaded", "success");
    } catch (err) {
      const errorMsg = getApiErrorMessage(err);
      // ✅ ADDED: Toast notification for error
      addToast(errorMsg, "error");
    } finally {
      setLoading(false);
    }
  }
  
  async function handleSave() {
    try {
      setSaving(true);
      await adminApi.updateWithdrawalSettings(settings, token);
      const successMsg = "Withdrawal settings updated successfully";
      // ✅ ADDED: Toast notification for save success
      addToast(successMsg, "success");
    } catch (err) {
      const errorMsg = getApiErrorMessage(err);
      // ✅ ADDED: Toast notification for error
      addToast(errorMsg, "error");
    } finally {
      setSaving(false);
    }
  }
  
  useEffect(() => {
    loadSettings();
  }, []);
  
  if (loading) {
    return <div className="rounded-2xl border border-white/10 bg-[#0f0f0f] p-5">Loading settings...</div>;
  }
  
  return (
    <div className="space-y-5">
      {/* ✅ ADDED: Toast Container (already present, keeping it) */}
      <ToastContainer />
      
      <section className="rounded-[28px] border border-white/10 bg-[radial-gradient(circle_at_top_right,rgba(163,230,53,0.10),transparent_18%),linear-gradient(180deg,#0a0a0a_0%,#050505_100%)] p-5 shadow-xl">
        <div>
          <p className="text-[10px] uppercase tracking-[0.32em] text-lime-300">Platform Controls</p>
          <h1 className="mt-2 text-2xl font-bold text-white">Profit Withdrawal Settings</h1>
          <p className="mt-2 text-sm text-slate-400">Configure withdrawal limits for users who haven't achieved their target yet.</p>
        </div>
      </section>
      
      <div className="rounded-2xl border border-white/10 bg-[#0f0f0f] p-5 shadow-xl">
        <h2 className="text-lg font-semibold text-white">Withdrawal Limits</h2>
        <p className="mt-1 text-sm text-slate-400">Users can only withdraw from profits until target is achieved</p>
        
        <div className="mt-5 space-y-4">
          <div>
            <label className="block text-sm text-slate-300 mb-2">Minimum Withdrawal (USDT)</label>
            <input
              type="number"
              min="1"
              value={settings.min_withdrawal_from_profit}
              onChange={(e) => setSettings({...settings, min_withdrawal_from_profit: Number(e.target.value)})}
              className="w-full rounded-xl border border-white/10 bg-black px-4 py-3 text-white focus:outline-none focus:border-lime-400"
            />
            <p className="mt-1 text-xs text-slate-500">Minimum amount users can withdraw per request</p>
          </div>
          
          <div>
            <label className="block text-sm text-slate-300 mb-2">Maximum Withdrawal per Request (USDT)</label>
            <input
              type="number"
              min="1"
              value={settings.max_withdrawal_from_profit}
              onChange={(e) => setSettings({...settings, max_withdrawal_from_profit: Number(e.target.value)})}
              className="w-full rounded-xl border border-white/10 bg-black px-4 py-3 text-white focus:outline-none focus:border-lime-400"
            />
            <p className="mt-1 text-xs text-slate-500">Maximum amount users can withdraw in a single request</p>
          </div>
          
          <div className="flex items-center gap-3">
            <input
              type="checkbox"
              checked={settings.allow_withdrawal_before_target}
              onChange={(e) => setSettings({...settings, allow_withdrawal_before_target: e.target.checked})}
              className="h-4 w-4 rounded border-white/10 bg-black text-lime-400 focus:ring-lime-400"
            />
            <label className="text-sm text-slate-300">Allow withdrawals before target achieved</label>
          </div>
          
          <div>
            <label className="block text-sm text-slate-300 mb-2">Warning Message</label>
            <textarea
              rows={4}
              value={settings.restriction_message}
              onChange={(e) => setSettings({...settings, restriction_message: e.target.value})}
              className="w-full rounded-xl border border-white/10 bg-black px-4 py-3 text-white focus:outline-none focus:border-lime-400"
              placeholder="Enter message shown to users when trying to withdraw before target"
            />
            <p className="mt-1 text-xs text-slate-500">This message will appear in the profit withdrawal modal</p>
          </div>
          
          <button
            onClick={handleSave}
            disabled={saving}
            className="w-full rounded-xl bg-lime-400 px-4 py-3 font-semibold text-black transition hover:bg-lime-300 disabled:opacity-50"
          >
            <Save size={16} className="inline mr-2" />
            {saving ? "Saving..." : "Save Settings"}
          </button>
        </div>
      </div>
      
      <div className="rounded-2xl border border-white/10 bg-[#0f0f0f] p-5 shadow-xl">
        <h2 className="text-lg font-semibold text-white">Current Configuration Preview</h2>
        <div className="mt-4 space-y-3">
          <div className="flex justify-between items-center border-b border-white/10 pb-2">
            <span className="text-slate-400">Min Withdrawal:</span>
            <span className="text-white font-semibold">{settings.min_withdrawal_from_profit} USDT</span>
          </div>
          <div className="flex justify-between items-center border-b border-white/10 pb-2">
            <span className="text-slate-400">Max Withdrawal per Request:</span>
            <span className="text-white font-semibold">{settings.max_withdrawal_from_profit} USDT</span>
          </div>
          <div className="flex justify-between items-center border-b border-white/10 pb-2">
            <span className="text-slate-400">Allow Withdrawals Before Target:</span>
            <span className={settings.allow_withdrawal_before_target ? "text-emerald-400" : "text-red-400"}>
              {settings.allow_withdrawal_before_target ? "Enabled" : "Disabled"}
            </span>
          </div>
          <div className="mt-3 rounded-xl border border-lime-500/20 bg-lime-500/10 p-3">
            <p className="text-xs text-lime-300">⚠️ Warning Message Preview:</p>
            <p className="text-sm text-slate-300 mt-1">{settings.restriction_message}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
