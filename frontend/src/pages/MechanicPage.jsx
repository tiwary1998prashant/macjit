import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useGarageWS } from "../hooks/useWebSocket";
import api from "../lib/api";
import { StatusPill } from "../components/StatusPill";
import { NotificationBell } from "../components/NotificationBell";
import { LogOut, Wrench, Search, Plus, Minus, AlertTriangle, Play, Check, X, Trash2 } from "lucide-react";
import MacJitLogo from "../components/MacJitLogo";
import { toast } from "sonner";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "../components/ui/dialog";

export default function MechanicPage() {
  const { user, token, logout } = useAuth();
  const [bookings, setBookings] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [inventory, setInventory] = useState([]);
  const [search, setSearch] = useState("");
  const [tick, setTick] = useState(0);

  const load = async () => {
    const [b, inv] = await Promise.all([api.get("/bookings"), api.get("/inventory")]);
    setBookings(b.data); setInventory(inv.data);
    if (!activeId && b.data.length > 0) {
      const inProg = b.data.find((x) => x.status === "IN_SERVICE") || b.data.find((x) => x.status === "ASSIGNED");
      if (inProg) setActiveId(inProg.id);
    }
  };
  useEffect(() => { load(); }, []);
  useGarageWS(token, (e) => {
    if (e.type === "connected") return;
    toast(e.type.replace(/_/g, " "), { description: e.data?.plate_number || "" });
    load(); setTick((t) => t + 1);
  });

  const active = bookings.find((b) => b.id === activeId);
  const queue = bookings.filter((b) => ["ASSIGNED", "IN_SERVICE"].includes(b.status));

  const start = async () => { await api.post(`/bookings/${active.id}/start`); toast.success("Service started · live stream on"); load(); };
  const finish = async () => {
    const r = await api.post(`/bookings/${active.id}/finish`);
    const nxt = r.data?.next_booking_id;
    if (nxt) {
      toast.success(`Sent to QA · next: ${r.data.next_booking_plate}`);
      setActiveId(nxt);
    } else {
      toast.success("Sent to QA · no more in queue");
      setActiveId(null);
    }
    load();
  };
  const addItem = async (id) => { try { await api.post(`/bookings/${active.id}/items`, { inventory_id: id, qty: 1 }); load(); } catch (e) { toast.error("Out of stock"); } };
  const removeItem = async (id) => { await api.delete(`/bookings/${active.id}/items/${id}`); load(); };

  const filtered = inventory.filter((i) => i.name.toLowerCase().includes(search.toLowerCase()) && i.stock > 0);
  const total = active?.items?.reduce((s, i) => s + i.subtotal, 0) || 0;

  return (
    <div className="dark min-h-screen bg-zinc-950 text-zinc-100">
      <header className="sticky top-0 z-20 bg-zinc-950/90 backdrop-blur-xl border-b border-zinc-800">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <MacJitLogo size={32} />
            <div>
              <p className="font-display font-black text-lg tracking-tighter">MACJIT <span className="text-orange-500">/ MECHANIC</span></p>
              <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">{user?.name} · {active?.bay_name || "No bay"}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <a href="/employee" data-testid="hr-link" className="border border-zinc-800 hover:border-orange-500 hover:text-orange-500 text-zinc-300 font-mono text-[10px] uppercase tracking-widest px-3 py-2 transition-colors">HR</a>
            <NotificationBell refreshKey={tick} />
            <button data-testid="logout-btn" onClick={logout} className="p-2 hover:bg-zinc-800 rounded-full"><LogOut className="w-4 h-4" /></button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-6 grid lg:grid-cols-3 gap-6">
        <aside className="lg:col-span-1 space-y-3">
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">My queue ({queue.length})</p>
          {queue.length === 0 && <p className="text-sm text-zinc-500 border border-dashed border-zinc-800 p-6 text-center">No assigned bikes</p>}
          {queue.map((b) => (
            <button
              key={b.id} data-testid={`queue-${b.id}`} onClick={() => setActiveId(b.id)}
              className={`w-full text-left border ${activeId === b.id ? "border-orange-500 bg-orange-500/5" : "border-zinc-800 bg-zinc-900/40 hover:border-zinc-700"} p-4 transition-colors`}
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="font-display font-bold text-base">{b.plate_number}</p>
                  <p className="font-mono text-xs text-zinc-400">{b.car_make} {b.car_model}</p>
                </div>
                <StatusPill status={b.status} />
              </div>
              <p className="font-mono text-[10px] text-zinc-500 mt-2 uppercase">{b.service_type} · {b.bay_name}</p>
              {b.estimated_start_at && (
                <p className="font-mono text-[10px] text-orange-500 mt-1">
                  ETA {new Date(b.estimated_start_at).toLocaleString([], { hour: "2-digit", minute: "2-digit", month: "short", day: "numeric" })}
                </p>
              )}
            </button>
          ))}
        </aside>

        <section className="lg:col-span-2 space-y-6">
          {!active ? (
            <div className="border border-dashed border-zinc-800 p-16 text-center">
              <Wrench className="w-10 h-10 text-zinc-700 mx-auto mb-3" />
              <p className="font-display font-black text-xl uppercase">Select a bike from queue</p>
            </div>
          ) : (
            <>
              <div className="border border-zinc-800 bg-zinc-900/40 p-6">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Active job</p>
                    <h2 className="font-display font-black text-3xl tracking-tighter">{active.plate_number}</h2>
                    <p className="font-mono text-sm text-zinc-400">{active.car_make} {active.car_model} · {active.customer_name}</p>
                  </div>
                  <StatusPill status={active.status} />
                </div>

                {active.status === "ASSIGNED" && (
                  <button data-testid="mechanic-start-btn" onClick={start} className="mt-5 w-full bg-emerald-500 hover:bg-emerald-400 text-black font-display font-black uppercase tracking-[0.3em] text-lg py-6 border-b-4 border-emerald-700 active:translate-y-1 active:border-b-0 transition-all flex items-center justify-center gap-2">
                    <Play className="w-5 h-5 fill-black" /> Start Service
                  </button>
                )}
                {active.status === "IN_SERVICE" && (
                  <button data-testid="mechanic-finish-btn" onClick={finish} className="mt-5 w-full bg-black hover:bg-zinc-900 border border-zinc-800 text-white font-display font-black uppercase tracking-[0.3em] text-lg py-6 transition-colors flex items-center justify-center gap-2">
                    <Check className="w-5 h-5" /> Finish · Send to QA
                  </button>
                )}
              </div>

              {active.status === "IN_SERVICE" && (
                <>
                  <div className="border border-zinc-800 bg-zinc-900/40 p-6">
                    <div className="flex items-center justify-between mb-3">
                      <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Parts cart · ₹{total}</p>
                      <ApprovalDialog booking={active} onDone={load} />
                    </div>
                    <div className="space-y-2 mb-4">
                      {(!active.items || active.items.length === 0) && <p className="text-sm text-zinc-500">No parts added yet</p>}
                      {active.items?.map((it) => (
                        <div key={it.inventory_id} className="flex items-center justify-between bg-zinc-950 border border-zinc-800 px-3 py-2">
                          <div>
                            <p className="text-sm font-bold">{it.name}</p>
                            <p className="font-mono text-[10px] text-zinc-500">{it.sku} × {it.qty} · ₹{it.subtotal}</p>
                          </div>
                          <button data-testid={`remove-item-${it.inventory_id}`} onClick={() => removeItem(it.inventory_id)} className="p-1 hover:bg-zinc-800 text-red-400"><X className="w-4 h-4" /></button>
                        </div>
                      ))}
                    </div>
                    <div className="relative mb-3">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                      <input data-testid="inventory-search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search parts (oil, brake, filter...)" className="w-full bg-zinc-950 border border-zinc-800 pl-10 pr-3 py-2.5 font-mono text-sm focus:border-orange-500 outline-none" />
                    </div>
                    <div className="space-y-1 max-h-72 overflow-y-auto">
                      {filtered.slice(0, 12).map((i) => (
                        <div key={i.id} className="flex items-center justify-between bg-zinc-950 border border-zinc-800 px-3 py-2 hover:border-zinc-700">
                          <div>
                            <p className="text-sm font-bold">{i.name}</p>
                            <p className="font-mono text-[10px] text-zinc-500">{i.sku} · ₹{i.price} · stock {i.stock}</p>
                          </div>
                          <button data-testid={`add-item-${i.id}`} onClick={() => addItem(i.id)} className="bg-orange-500 hover:bg-orange-400 text-black p-2 transition-colors"><Plus className="w-4 h-4" /></button>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </>
          )}
        </section>
      </main>
    </div>
  );
}

const ApprovalDialog = ({ booking, onDone }) => {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [cost, setCost] = useState("");
  const submit = async () => {
    if (!reason) return toast.error("Reason required");
    await api.post(`/bookings/${booking.id}/request-approval`, { reason, extra_cost: parseFloat(cost) || 0 });
    toast.success("Approval requested"); onDone(); setOpen(false);
  };
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <button data-testid="request-approval-btn" className="border border-orange-600/40 bg-orange-600/10 hover:bg-orange-600/20 text-orange-500 font-mono text-[10px] uppercase tracking-widest font-bold px-3 py-1.5 flex items-center gap-1 transition-colors">
          <AlertTriangle className="w-3 h-3" /> Heavy Work
        </button>
      </DialogTrigger>
      <DialogContent className="bg-zinc-950 border-zinc-800">
        <DialogHeader><DialogTitle className="font-display uppercase">Request customer approval</DialogTitle></DialogHeader>
        <textarea data-testid="approval-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (e.g., engine block needs replacement)" rows={3} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
        <input data-testid="approval-cost" value={cost} onChange={(e) => setCost(e.target.value)} type="number" placeholder="Extra cost ₹" className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
        <button data-testid="approval-send" onClick={submit} className="bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest py-3">Send for Approval</button>
      </DialogContent>
    </Dialog>
  );
};
