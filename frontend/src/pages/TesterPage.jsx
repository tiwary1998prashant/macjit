import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useGarageWS } from "../hooks/useWebSocket";
import api from "../lib/api";
import { StatusPill } from "../components/StatusPill";
import { NotificationBell } from "../components/NotificationBell";
import { LogOut, CheckCheck, XCircle, ClipboardList } from "lucide-react";
import MacJitLogo from "../components/MacJitLogo";
import { toast } from "sonner";

export default function TesterPage() {
  const { user, token, logout } = useAuth();
  const [bookings, setBookings] = useState([]);
  const [tick, setTick] = useState(0);
  const [failFor, setFailFor] = useState(null);
  const [failReasons, setFailReasons] = useState([]);
  const [failNotes, setFailNotes] = useState("");

  const load = () => api.get("/bookings").then((r) => setBookings(r.data));
  useEffect(() => { load(); }, []);
  useGarageWS(token, (e) => { if (e.type !== "connected") { toast(e.type.replace(/_/g, " "), { description: e.data?.plate_number || "" }); load(); setTick((t) => t + 1); } });

  const queue = bookings.filter((b) => b.status === "READY_TO_TEST");
  const recent = bookings.filter((b) => ["QA_DONE", "BILLED", "PAID"].includes(b.status)).slice(0, 5);

  const passQA = async (id) => { await api.post(`/bookings/${id}/qa-done`); toast.success("Marked QA Done"); load(); };
  const reasonOptions = ["Engine noise", "Brake issue", "Oil leak", "Electrical issue", "Road test failed", "Part fitting issue", "Cleaning pending", "Other"];

  const toggleReason = (reason) => {
    setFailReasons((items) => items.includes(reason) ? items.filter((x) => x !== reason) : [...items, reason]);
  };

  const failQA = async () => {
    if (!failFor) return;
    if (failReasons.length === 0) return toast.error("Select at least one fail reason");
    await api.post(`/bookings/${failFor.id}/qa-fail`, { reasons: failReasons, notes: failNotes });
    toast.success("QA failed and sent back to mechanic");
    setFailFor(null);
    setFailReasons([]);
    setFailNotes("");
    load();
  };

  return (
    <div className="dark min-h-screen bg-zinc-950 text-zinc-100">
      <header className="sticky top-0 z-20 bg-zinc-950/90 backdrop-blur-xl border-b border-zinc-800">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <MacJitLogo size={32} />
            <div>
              <p className="font-display font-black text-lg tracking-tighter">MACJIT <span className="text-orange-500">/ TESTER</span></p>
              <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">{user?.name}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <a href="/employee" data-testid="hr-link" className="border border-zinc-800 hover:border-orange-500 hover:text-orange-500 text-zinc-300 font-mono text-[10px] uppercase tracking-widest px-3 py-2 transition-colors">HR</a>
            <NotificationBell refreshKey={tick} />
            <button data-testid="logout-btn" onClick={logout} className="p-2 hover:bg-zinc-800 rounded-full"><LogOut className="w-4 h-4" /></button>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8 space-y-8">
        <section>
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mb-3">Awaiting QA · {queue.length}</p>
          <div className="space-y-3">
            {queue.length === 0 && <div className="border border-dashed border-zinc-800 p-12 text-center"><p className="font-display font-black text-xl uppercase">Queue empty</p><p className="text-zinc-500 text-sm mt-1">Bikes will appear here once mechanics finish.</p></div>}
            {queue.map((b) => (
              <div key={b.id} data-testid={`test-row-${b.id}`} className="border border-zinc-800 bg-zinc-900/40 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">{b.id.slice(0, 8)}</p>
                  <p className="font-display font-black text-2xl tracking-tighter">{b.plate_number}</p>
                  <p className="font-mono text-sm text-zinc-400">{b.car_make} {b.car_model} · by {b.mechanic_name} · {b.bay_name}</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button data-testid={`qa-fail-btn-${b.id}`} onClick={() => setFailFor(b)} className="border border-red-500/60 text-red-400 hover:bg-red-500 hover:text-black font-display font-black uppercase tracking-widest px-5 py-3 flex items-center gap-2 transition-all">
                    <XCircle className="w-5 h-5" /> Fail / Reject
                  </button>
                  <button data-testid={`qa-done-btn-${b.id}`} onClick={() => passQA(b.id)} className="bg-emerald-500 hover:bg-emerald-400 text-black font-display font-black uppercase tracking-widest px-6 py-3 flex items-center gap-2 border-b-4 border-emerald-700 active:translate-y-1 active:border-b-0 transition-all">
                    <CheckCheck className="w-5 h-5" /> QA Done
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section>
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-3">Recently passed</p>
          <div className="space-y-2">
            {recent.map((b) => (
              <div key={b.id} className="border border-zinc-800/50 bg-zinc-900/20 p-4 flex items-center justify-between">
                <div>
                  <p className="font-display font-bold">{b.plate_number}</p>
                  <p className="font-mono text-xs text-zinc-500">{b.customer_name}</p>
                </div>
                <StatusPill status={b.status} />
              </div>
            ))}
          </div>
        </section>
      </main>

      {failFor && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur grid place-items-center p-4" data-testid="qa-fail-modal">
          <div className="w-full max-w-lg bg-zinc-950 border border-red-500/50 p-6">
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-center gap-3">
                <ClipboardList className="w-6 h-6 text-red-400" />
                <div>
                  <h3 className="font-display font-black text-2xl uppercase tracking-tight">Fail QA</h3>
                  <p className="font-mono text-xs text-zinc-500">{failFor.plate_number} · send back to mechanic</p>
                </div>
              </div>
              <button onClick={() => setFailFor(null)} className="text-zinc-500 hover:text-white">Close</button>
            </div>
            <div className="mt-6 grid sm:grid-cols-2 gap-2">
              {reasonOptions.map((reason) => (
                <label key={reason} className={`border px-3 py-2 font-mono text-xs cursor-pointer ${failReasons.includes(reason) ? "border-red-500 bg-red-500/10 text-red-300" : "border-zinc-800 text-zinc-400"}`}>
                  <input type="checkbox" className="mr-2" checked={failReasons.includes(reason)} onChange={() => toggleReason(reason)} />
                  {reason}
                </label>
              ))}
            </div>
            <textarea
              data-testid="qa-fail-notes"
              value={failNotes}
              onChange={(e) => setFailNotes(e.target.value)}
              rows={4}
              placeholder="Add tester notes for mechanic..."
              className="mt-4 w-full bg-black border border-zinc-800 px-3 py-3 font-mono text-sm text-white focus:border-red-500 outline-none resize-none"
            />
            <button data-testid="qa-fail-submit" onClick={failQA} className="mt-4 w-full bg-red-500 hover:bg-red-400 text-black font-display font-black uppercase tracking-widest py-3">
              Reject and send back
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
