import { STATUS_LABELS } from "../lib/api";

const STYLES = {
  BOOKED: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  CANCELLED: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
  ASSIGNED: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
  IN_SERVICE: "bg-orange-600/10 text-orange-500 border-orange-600/30",
  READY_TO_TEST: "bg-purple-500/10 text-purple-400 border-purple-500/30",
  QA_DONE: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  BILLED: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  PAID: "bg-green-500/10 text-green-400 border-green-500/30",
};

export const StatusPill = ({ status, testid }) => (
  <span
    data-testid={testid || `status-pill-${status?.toLowerCase()}`}
    className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 font-mono text-[10px] uppercase tracking-[0.15em] font-bold ${STYLES[status] || "bg-zinc-800 text-zinc-300 border-zinc-700"}`}
  >
    <span className={`w-1.5 h-1.5 rounded-full ${status === "IN_SERVICE" ? "bg-orange-500 animate-live-pulse" : "bg-current"}`} />
    {STATUS_LABELS[status] || status}
  </span>
);
