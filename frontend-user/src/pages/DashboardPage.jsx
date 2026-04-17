import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  RefreshCw,
  Eye,
  Bell,
  Wallet,
} from "lucide-react";
import { userApi, marketApi } from "../services/api";
import NewsSlider from "../components/NewsSlider";

function formatMoney(value) {
  const num = Number(value || 0);
  if (!Number.isFinite(num)) return "0.00";
  return num.toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

function formatPrice(value) {
  const num = Number(value || 0);
  if (!Number.isFinite(num)) return "0.00";
  return num.toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 6,
  });
}

function formatMarketCap(value) {
  const num = Number(value || 0);
  if (!Number.isFinite(num)) return "0";
  if (num >= 1_000_000_000) return `$${(num / 1_000_000_000).toFixed(2)}B`;
  if (num >= 1_000_000) return `$${(num / 1_000_000).toFixed(2)}M`;
  return `$${num.toFixed(2)}`;
}

function MarketRow({ item }) {
  const positive = Number(item.priceChangePercent || 0) >= 0;

  return (
    <div className="flex items-center justify-between gap-2 rounded-[20px] border border-white/10 bg-[#090909] px-3 py-2.5 sm:px-4">
      <div className="flex min-w-0 items-center gap-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#16213d] text-[11px] font-bold text-white">
          {String(item.symbol || "").replace("USDT", "").slice(0, 3)}
        </div>

        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-white">
            {String(item.symbol || "").replace("USDT", "")} / USDT
          </div>
          <div className="truncate text-[10px] text-slate-500 sm:text-[11px]">
            {formatMarketCap(item.volume)}
          </div>
        </div>
      </div>

      <div className="text-right">
        <div className="text-sm font-semibold text-white">
          {formatPrice(item.lastPrice || item.price)}
        </div>
        <div className="mt-0.5 text-[10px] text-slate-500 sm:text-[11px]">
          ${formatPrice(item.lastPrice || item.price)}
        </div>
      </div>

      <div
        className={`min-w-[74px] rounded-xl px-2.5 py-2 text-center text-xs font-semibold sm:min-w-[82px] sm:text-sm ${
          positive
            ? "bg-emerald-500/90 text-white"
            : "bg-rose-500/90 text-white"
        }`}
      >
        {positive ? "+" : ""}
        {Number(item.priceChangePercent || 0).toFixed(2)}%
      </div>
    </div>
  );
}

function SquareAction({ label, sub, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded-[22px] border border-white/10 bg-[#080808] p-3.5 text-left shadow-[0_14px_30px_rgba(0,0,0,0.18)] transition hover:bg-[#0d0d0d]"
    >
      <div className="text-[11px] text-slate-400">{label}</div>
      <div className="mt-1.5 text-lg font-semibold text-white">{sub}</div>
    </button>
  );
}

export default function DashboardPage() {
  const navigate = useNavigate();

  const token =
    localStorage.getItem("userToken") ||
    localStorage.getItem("token") ||
    localStorage.getItem("accessToken") ||
    "";

  const [wallet, setWallet] = useState({
    balance: 0,
    user: null,
    walletLabel: "Main Wallet",
  });
  const [markets, setMarkets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  async function loadData(silent = false) {
    try {
      if (!silent) setLoading(true);
      else setRefreshing(true);

      const [walletRes, marketRes] = await Promise.all([
        userApi.getWalletSummary(token),
        marketApi.home(),
      ]);

      setWallet(
        walletRes?.data?.data || {
          balance: 0,
          user: null,
          walletLabel: "Main Wallet",
        }
      );

      setMarkets(Array.isArray(marketRes?.data?.data) ? marketRes.data.data : []);
    } catch {
      // keep UI stable
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadData();

    const interval = setInterval(() => {
      loadData(true);
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  const topMarkets = useMemo(() => markets.slice(0, 6), [markets]);

  if (loading) {
    return (
      <div className="space-y-5 bg-black px-3 pb-24 pt-3 sm:px-6 xl:pb-8">
        <div className="rounded-[30px] border border-white/10 bg-[#0a0a0a] p-5 text-sm text-slate-400">
          Loading dashboard...
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5 bg-black px-2 pb-24 pt-3 sm:px-5 xl:pb-8">
      <section className="rounded-[30px] border border-white/10 bg-[radial-gradient(circle_at_top_right,rgba(16,185,129,0.16),transparent_18%),linear-gradient(180deg,#050505_0%,#000000_100%)] p-4 shadow-[0_18px_60px_rgba(0,0,0,0.4)] sm:p-5">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xl font-bold text-white sm:text-2xl">
              Exchange
            </div>
            <div className="mt-0.5 text-[11px] text-slate-500">
              Overview of your account and market activity
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => navigate("/assets")}
              className="flex h-11 w-11 items-center justify-center rounded-full border border-white/10 bg-white/[0.03] text-white"
              title="Assets"
            >
              <Wallet size={18} />
            </button>

            <button
              type="button"
              onClick={() => navigate("/transactions")}
              className="flex h-11 w-11 items-center justify-center rounded-full border border-white/10 bg-white/[0.03] text-white"
              title="Transactions"
            >
              <Bell size={18} />
            </button>
          </div>
        </div>

        <div className="mt-4 rounded-[28px] border border-white/10 bg-[radial-gradient(circle_at_top_right,rgba(16,185,129,0.12),transparent_18%),linear-gradient(180deg,#050505_0%,#000000_100%)] p-4 sm:p-5">
          <div className="flex items-center justify-between">
            <div className="rounded-full border border-white/10 bg-white/[0.04] px-4 py-2.5 text-base font-semibold text-white">
              CryptoPulse
            </div>

            <button
              type="button"
              onClick={() => loadData(true)}
              className="flex h-11 w-11 items-center justify-center rounded-full border border-white/10 bg-white/[0.03] text-white"
            >
              <RefreshCw size={17} className={refreshing ? "animate-spin" : ""} />
            </button>
          </div>

          <div className="mt-8">
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <span>Est total value</span>
              <Eye size={14} />
            </div>

            <div className="mt-2 flex items-end gap-2">
              <div className="text-[34px] font-bold tracking-tight text-white sm:text-[42px]">
                {formatMoney(wallet.balance)}
              </div>
              <div className="mb-1 text-[18px] font-semibold text-white sm:text-[22px]">
                USD
              </div>
            </div>

            <button
              type="button"
              onClick={() => navigate("/transactions")}
              className="mt-3 inline-flex items-center gap-2 text-sm text-slate-400"
            >
              <span>Today&apos;s PnL $0.00 (0.00%)</span>
              <span>›</span>
            </button>
          </div>

          <div className="mt-6 grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => navigate("/deposit")}
              className="rounded-full bg-lime-400 px-4 py-4 text-center font-semibold text-black"
            >
              <div className="text-lg">Deposit</div>
              <div className="text-lg">crypto</div>
            </button>

            <button
              type="button"
              onClick={() => navigate("/trade")}
              className="rounded-full bg-lime-400 px-4 py-4 text-center text-lg font-semibold text-black"
            >
              Trading
            </button>
          </div>
        </div>
      </section>

      <NewsSlider />

      <section className="space-y-4">
        <div className="flex items-center gap-4 px-1 text-sm text-slate-400">
          <button type="button" className="text-slate-400">Favorites</button>
          <button
            type="button"
            className="rounded-full bg-white/[0.08] px-4 py-2 text-sm text-white"
          >
            Hot
          </button>
          <button type="button" className="text-slate-400">New</button>
          <button type="button" className="text-slate-400">DEX</button>
        </div>

        <div className="space-y-2.5">
          {topMarkets.map((item) => (
            <MarketRow key={item.symbol} item={item} />
          ))}
        </div>
      </section>

      <section className="grid grid-cols-2 gap-3">
        <SquareAction
          label="Assets"
          sub={`$${formatMoney(wallet.balance)}`}
          onClick={() => navigate("/assets")}
        />
        <SquareAction
          label="Deposit"
          sub="Add funds"
          onClick={() => navigate("/deposit")}
        />
        <SquareAction
          label="Loan"
          sub="Request"
          onClick={() => navigate("/loan")}
        />
        <SquareAction
          label="Profile"
          sub="Account"
          onClick={() => navigate("/profile")}
        />
      </section>
    </div>
  );
}