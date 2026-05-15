import { useEffect, useState } from "react";
import { RefreshCw, CheckCircle, XCircle, Clock } from "lucide-react";
import { adminApi, getApiErrorMessage } from "../../services/api";
import useToast from "../../components/ToastNotification";

function formatMoney(value) {
  const num = Number(value || 0);
  if (!Number.isFinite(num)) return "0.00";
  return num.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function formatDateTime(value) {
  if (!value) return "--";
  const date = new Date(value);
  if (isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function getStatusClass(status) {
  const value = String(status || "").toLowerCase();
  if (value === "pending") return "bg-amber-500/10 text-amber-300 border border-amber-500/20";
  if (value === "approved") return "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20";
  if (value === "rejected") return "bg-rose-500/10 text-rose-300 border border-rose-500/20";
  return "bg-slate-500/10 text-slate-300";
}

function getStatusIcon(status) {
  const value = String(status || "").toLowerCase();
  if (value === "pending") return <Clock size={14} className="text-amber-400" />;
  if (value === "approved") return <CheckCircle size={14} className="text-emerald-400" />;
  if (value === "rejected") return <XCircle size={14} className="text-rose-400" />;
  return null;
}

export default function AdminProfitWithdrawalRequestsPage() {
  const token = localStorage.getItem("adminToken") || localStorage.getItem("admin_token") || "";
  const { addToast, ToastContainer } = useToast();
  
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [actionId, setActionId] = useState(null);
  const [filter, setFilter] = useState("all");
  
  async function loadRequests() {
    try {
      setRefreshing(true);
      const res = await adminApi.getProfitWithdrawalRequests(token);
      setRequests(Array.isArray(res.data?.data) ? res.data.data : []);
    } catch (err) {
      addToast(getApiErrorMessage(err), "error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }
  
  async function handleApprove(id) {
    const confirmed = window.confirm("Approve this profit withdrawal request? The amount will be deducted from user's balance.");
    if (!confirmed) return;
    
    try {
      setActionId(id);
      await adminApi.approveProfitWithdrawal(id, token);
      addToast("Withdrawal approved successfully", "success");
      await loadRequests();
    } catch (err) {
      addToast(getApiErrorMessage(err), "error");
    } finally {
      setActionId(null);
    }
  }
  
  async function handleReject(id) {
    const confirmed = window.confirm("Reject this profit withdrawal request?");
    if (!confirmed) return;
    
    try {
      setActionId(id);
      await adminApi.rejectProfitWithdrawal(id, token);
      addToast("Withdrawal rejected", "info");
      await loadRequests();
    } catch (err) {
      addToast(getApiErrorMessage(err), "error");
    } finally {
      setActionId(null);
    }
  }
  
  useEffect(() => {
    loadRequests();
    const interval = setInterval(loadRequests, 15000);
    return () => clearInterval(interval);
  }, []);
  
  const filteredRequests = requests.filter(req => {
    if (filter === "all") return true;
    return req.status === filter;
  });
  
  const stats = {
    total: requests.length,
    pending: requests.filter(r => r.status === "pending").length,
    approved: requests.filter(r => r.status === "approved").length,
    rejected: requests.filter(r => r.status === "rejected").length,
    totalAmount: requests.reduce((sum, r) => sum + Number(r.amount || 0), 0),
  };
  
  if (loading) {
    return <div className="rounded-2xl border border-white/10 bg-[#0f0f0f] p-5">Loading withdrawal requests...</div>;
  }
  
  return (
    <div className="space-y-5">
      <ToastContainer />
      
      <section className="rounded-[28px] border border-white/10 bg-[radial-gradient(circle_at_top_right,rgba(163,230,53,0.10),transparent_18%),linear-gradient(180deg,#0a0a0a_0%,#050505_100%)] p-5 shadow-xl">
        <div>
          <p className="text-[10px] uppercase tracking-[0.32em] text-lime-300">Profit Withdrawals</p>
          <h1 className="mt-2 text-2xl font-bold text-white">Profit Withdrawal Requests</h1>
          <p className="mt-2 text-sm text-slate-400">Users requesting to withdraw from their profits before target is achieved.</p>
        </div>
      </section>
      
      {/* Stats Cards */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <div className="rounded-xl border border-white/10 bg-[#0f0f0f] p-4 text-center shadow-lg">
          <div className="text-2xl font-bold text-white">{stats.total}</div>
          <div className="text-xs text-slate-400">Total Requests</div>
        </div>
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-4 text-center shadow-lg">
          <div className="text-2xl font-bold text-amber-300">{stats.pending}</div>
          <div className="text-xs text-slate-400">Pending</div>
        </div>
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-4 text-center shadow-lg">
          <div className="text-2xl font-bold text-emerald-300">{stats.approved}</div>
          <div className="text-xs text-slate-400">Approved</div>
        </div>
        <div className="rounded-xl border border-rose-500/20 bg-rose-500/10 p-4 text-center shadow-lg">
          <div className="text-2xl font-bold text-rose-300">{stats.rejected}</div>
          <div className="text-xs text-slate-400">Rejected</div>
        </div>
        <div className="rounded-xl border border-lime-500/20 bg-lime-500/10 p-4 text-center shadow-lg">
          <div className="text-2xl font-bold text-lime-300">{formatMoney(stats.totalAmount)} USDT</div>
          <div className="text-xs text-slate-400">Total Amount</div>
        </div>
      </div>
      
      {/* Filter Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-white/10 pb-3">
        {["all", "pending", "approved", "rejected"].map((tab) => (
          <button
            key={tab}
            onClick={() => setFilter(tab)}
            className={`rounded-full px-4 py-1.5 text-xs font-semibold transition ${
              filter === tab
                ? "bg-lime-400 text-black"
                : "border border-white/10 bg-[#0f0f0f] text-slate-300 hover:bg-white/5"
            }`}
          >
            {tab.toUpperCase()} {tab === "all" ? `(${stats.total})` : tab === "pending" ? `(${stats.pending})` : tab === "approved" ? `(${stats.approved})` : `(${stats.rejected})`}
          </button>
        ))}
      </div>
      
      {/* Refresh Button */}
      <div className="flex justify-end">
        <button onClick={loadRequests} className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-4 py-2 text-xs text-white transition hover:bg-white/5">
          <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>
      
      {/* Requests List */}
      <div className="space-y-3">
        {filteredRequests.length === 0 ? (
          <div className="rounded-2xl border border-white/10 bg-[#0f0f0f] p-8 text-center text-slate-400">
            No withdrawal requests found.
          </div>
        ) : (
          filteredRequests.map((req) => (
            <div key={req.id} className="rounded-2xl border border-white/10 bg-[#0f0f0f] p-4 shadow-lg transition hover:border-lime-500/30">
              <div className="flex flex-wrap justify-between items-start gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-lg font-semibold text-white">#{req.id}</span>
                    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ${getStatusClass(req.status)}`}>
                      {getStatusIcon(req.status)}
                      {req.status}
                    </span>
                  </div>
                  
                  <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                    <div>
                      <div className="text-xs text-slate-500">User</div>
                      <div className="text-sm text-white font-medium">{req.name || req.email || "-"}</div>
                      <div className="text-xs text-slate-400">UID: {req.uid || "-"}</div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500">User ID</div>
                      <div className="text-sm text-white">#{req.user_id}</div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500">Requested Amount</div>
                      <div className="text-lg font-bold text-lime-300">{formatMoney(req.amount)} USDT</div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500">Current Profit</div>
                      <div className="text-sm text-emerald-300">{formatMoney(req.current_profit || 0)} USDT</div>
                    </div>
                  </div>
                  
                  <div className="mt-3 flex flex-wrap gap-4 text-xs text-slate-500">
                    <span>Requested: {formatDateTime(req.created_at)}</span>
                    {req.updated_at && req.updated_at !== req.created_at && (
                      <span>Updated: {formatDateTime(req.updated_at)}</span>
                    )}
                  </div>
                </div>
                
                {req.status === "pending" && (
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleApprove(req.id)}
                      disabled={actionId === req.id}
                      className="rounded-xl bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-300 transition hover:bg-emerald-500/20 disabled:opacity-50"
                    >
                      {actionId === req.id ? "Processing..." : "Approve"}
                    </button>
                    <button
                      onClick={() => handleReject(req.id)}
                      disabled={actionId === req.id}
                      className="rounded-xl bg-rose-500/10 px-4 py-2 text-sm font-semibold text-rose-300 transition hover:bg-rose-500/20 disabled:opacity-50"
                    >
                      {actionId === req.id ? "Processing..." : "Reject"}
                    </button>
                  </div>
                )}
              </div>
              
              {req.admin_note && (
                <div className="mt-3 rounded-lg border border-white/10 bg-black/30 p-2">
                  <div className="text-xs text-slate-500">Admin Note:</div>
                  <div className="text-sm text-slate-300">{req.admin_note}</div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
