import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useGarageWS } from "../hooks/useWebSocket";
import api from "../lib/api";
import { StatusPill } from "../components/StatusPill";
import { StatCard } from "../components/StatCard";
import { NotificationBell } from "../components/NotificationBell";
import { LogOut, Wrench, Plus, IndianRupee } from "lucide-react";
import MacJitLogo from "../components/MacJitLogo";
import { toast } from "sonner";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "../components/ui/dialog";

export default function ReceptionPage() {
  const { user, token, logout } = useAuth();
  const [bookings, setBookings] = useState([]);
  const [customers, setCustomers] = useState([]);
  const [mechanics, setMechanics] = useState([]);
  const [bays, setBays] = useState([]);
  const [stats, setStats] = useState({});
  const [services, setServices] = useState([]);
  const [tick, setTick] = useState(0);

  const load = async () => {
    const [b, c, m, ba, s, sv] = await Promise.all([
      api.get("/bookings"),
      api.get("/users/by-role/customer"),
      api.get("/users/by-role/mechanic"),
      api.get("/bays"),
      api.get("/admin/stats"),
      api.get("/services/active"),
    ]);
    setBookings(b.data); setCustomers(c.data); setMechanics(m.data); setBays(ba.data); setStats(s.data); setServices(sv.data);
  };

  useEffect(() => { load(); }, []);
  useGarageWS(token, (e) => {
    if (e.type === "connected") return;
    toast(e.type.replace(/_/g, " "), { description: e.data?.plate_number || "" });
    load(); setTick((t) => t + 1);
  });

  return (
    <div className="dark min-h-screen bg-zinc-950 text-zinc-100">
      <Header user={user} onLogout={logout} tick={tick} />
      <main className="max-w-7xl mx-auto px-6 py-8 space-y-6">
        <div className="border border-zinc-800 bg-orange-500/5 px-4 py-2 flex items-center gap-2">
          <span className="w-1.5 h-1.5 bg-orange-500 rounded-full animate-live-pulse" />
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500">Auto-allocation active · 1h 45m slots · 8:00 → 18:00</p>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-zinc-800">
          <StatCard testid="stat-today-serviced" label="Today serviced" value={stats.today_serviced || 0} sub="paid jobs" accent />
          <StatCard testid="stat-today-revenue" label="Today revenue" value={`₹${stats.today_revenue || 0}`} />
          <StatCard testid="stat-active-bays" label="Active bays" value={stats.active_bays || 0} />
          <StatCard testid="stat-total-bookings" label="Total bookings" value={stats.total_bookings || 0} />
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          <NewBookingCard customers={customers} services={services} onCreated={load} />
          <div className="lg:col-span-2 border border-zinc-800 bg-zinc-900/40 p-6">
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-4">Live queue</p>
            <div className="space-y-3 max-h-[640px] overflow-y-auto">
              {bookings.length === 0 && <p className="text-sm text-zinc-500">No bookings yet</p>}
              {bookings.map((b) => (
                <BookingRow key={b.id} b={b} mechanics={mechanics} bays={bays} onUpdate={load} />
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

const Header = ({ user, onLogout, tick }) => (
  <header className="sticky top-0 z-20 bg-zinc-950/90 backdrop-blur-xl border-b border-zinc-800">
    <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <MacJitLogo size={32} />
        <div>
          <p className="font-display font-black text-lg tracking-tighter">MACJIT <span className="text-orange-500">/ RECEPTION</span></p>
          <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">{user?.name}</p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <a href="/employee" data-testid="hr-link" className="border border-zinc-800 hover:border-orange-500 hover:text-orange-500 text-zinc-300 font-mono text-[10px] uppercase tracking-widest px-3 py-2 transition-colors">HR</a>
        <NotificationBell refreshKey={tick} />
        <button data-testid="logout-btn" onClick={onLogout} className="p-2 hover:bg-zinc-800 rounded-full"><LogOut className="w-4 h-4" /></button>
      </div>
    </div>
  </header>
);

const NewBookingCard = ({ customers, services = [], onCreated }) => {
  const [form, setForm] = useState({ customer_name: "", customer_phone: "", car_make: "", car_model: "", plate_number: "", service_type: "general", notes: "" });
  const [busy, setBusy] = useState(false);
  const visibleServices = services.filter((s) => s.key !== "ac-service");
  const submit = async (e) => {
    e.preventDefault(); setBusy(true);
    try {
      await api.post("/bookings", form);
      toast.success("Booking created · auto-assigned");
      onCreated();
      setForm({ customer_name: "", customer_phone: "", car_make: "", car_model: "", plate_number: "", service_type: "general", notes: "" });
    } catch (err) { toast.error(err.response?.data?.detail || "Failed"); }
    finally { setBusy(false); }
  };
  const upd = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  return (
    <div className="border border-zinc-800 bg-zinc-900/40 p-6">
      <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mb-1">+ Walk-in</p>
      <h3 className="font-display font-black text-xl uppercase mb-4">New Booking</h3>
      <form onSubmit={submit} className="space-y-3">
        <input data-testid="booking-cust-name" required placeholder="Customer name" value={form.customer_name} onChange={(e) => upd("customer_name", e.target.value)} className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2.5 font-mono text-sm focus:border-orange-500 outline-none" />
        <input data-testid="booking-cust-phone" required placeholder="+91 phone (auto-creates account)" value={form.customer_phone} onChange={(e) => upd("customer_phone", e.target.value)} className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2.5 font-mono text-sm focus:border-orange-500 outline-none" />
        <input data-testid="booking-make" required placeholder="Bike make (Royal Enfield)" value={form.car_make} onChange={(e) => upd("car_make", e.target.value)} className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2.5 font-mono text-sm focus:border-orange-500 outline-none" />
        <input data-testid="booking-model" required placeholder="Model (Meteor 350)" value={form.car_model} onChange={(e) => upd("car_model", e.target.value)} className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2.5 font-mono text-sm focus:border-orange-500 outline-none" />
        <input data-testid="booking-plate" required placeholder="Plate (KA-05-MN-2024)" value={form.plate_number} onChange={(e) => upd("plate_number", e.target.value.toUpperCase())} className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2.5 font-mono text-sm focus:border-orange-500 outline-none" />
        <Select value={form.service_type} onValueChange={(v) => upd("service_type", v)}>
          <SelectTrigger data-testid="booking-service" className="bg-zinc-950 border-zinc-800"><SelectValue placeholder="Select service" /></SelectTrigger>
          <SelectContent>
            {visibleServices.length > 0 ? visibleServices.map((s) => {
              const h = s.duration_min >= 60 ? `${Math.floor(s.duration_min/60)}h${s.duration_min%60 > 0 ? " " + s.duration_min%60 + "m" : ""}` : `${s.duration_min}m`;
              return <SelectItem key={s.key} value={s.key}>{s.name} · {h} · ₹{s.base_price}</SelectItem>;
            }) : (
              <>
                <SelectItem value="general">General Service · 2h</SelectItem>
                <SelectItem value="oil-change">Oil & Filter Change · 45m</SelectItem>
                <SelectItem value="full-service">Full Service · 3h 30m</SelectItem>
                <SelectItem value="alignment">Wheel Alignment & Balancing · 1h</SelectItem>
                <SelectItem value="brake">Brake Service · 1h 15m</SelectItem>
                <SelectItem value="engine">Engine Repair / Diagnostics · 4h</SelectItem>
              </>
            )}
          </SelectContent>
        </Select>
        <textarea placeholder="Notes" value={form.notes} onChange={(e) => upd("notes", e.target.value)} className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2.5 font-mono text-sm" rows={2} />
        <button data-testid="booking-submit" type="submit" disabled={busy} className="w-full bg-orange-500 hover:bg-orange-400 disabled:opacity-50 text-black font-display font-black uppercase tracking-widest py-3 transition-colors">
          {busy ? "Creating..." : "Create + Auto-Assign"}
        </button>
      </form>
    </div>
  );
};

const BookingRow = ({ b, mechanics, bays, onUpdate }) => {
  const reassign = async () => { await api.post(`/bookings/${b.id}/auto-assign`); toast.success("Re-assigned"); onUpdate(); };
  const generateBill = async () => { await api.post(`/bookings/${b.id}/bill`); toast.success("Bill generated"); onUpdate(); };
  const collectPayment = async () => { await api.post(`/bookings/${b.id}/pay`); toast.success("Payment collected"); onUpdate(); };

  const eta = b.estimated_start_at ? new Date(b.estimated_start_at) : null;
  const etaEnd = b.estimated_end_at ? new Date(b.estimated_end_at) : null;
  const fmtTime = (d) => d?.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

  return (
    <div data-testid={`booking-row-${b.id}`} className="border border-zinc-800 bg-zinc-950/60 p-4 hover:border-zinc-700 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1">
          <p className="font-mono text-[10px] text-zinc-500 uppercase tracking-widest">{b.id.slice(0, 8)}</p>
          <p className="font-display font-bold text-lg">{b.plate_number} <span className="text-zinc-500 text-sm font-normal">{b.car_make} {b.car_model}</span></p>
          <p className="font-mono text-xs text-zinc-400">{b.customer_name} · {b.service_type}{b.bay_name ? ` · ${b.bay_name}` : ""}{b.mechanic_name ? ` · ${b.mechanic_name}` : ""}</p>
          {eta && (
            <p className="font-mono text-[10px] text-orange-500 mt-1">
              ETA {fmtTime(eta)}{etaEnd ? ` → ${fmtTime(etaEnd)}` : ""}
              {b.auto_assigned && <span className="ml-2 px-1.5 py-0.5 bg-orange-500/10 border border-orange-500/30 uppercase tracking-widest">Auto</span>}
            </p>
          )}
        </div>
        <StatusPill status={b.status} />
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {["BOOKED", "ASSIGNED"].includes(b.status) && (
          <button data-testid={`reassign-btn-${b.id}`} onClick={reassign} className="border border-zinc-700 hover:border-orange-500 hover:text-orange-500 text-zinc-300 font-mono text-xs uppercase tracking-widest px-4 py-2 transition-colors">↻ Re-assign</button>
        )}
        {b.status === "QA_DONE" && (
          <button data-testid={`bill-btn-${b.id}`} onClick={generateBill} className="bg-orange-500 hover:bg-orange-400 text-black font-mono text-xs uppercase tracking-widest font-bold px-4 py-2 transition-colors">Generate Bill</button>
        )}
        {b.status === "BILLED" && !b.paid && (
          <button data-testid={`collect-btn-${b.id}`} onClick={collectPayment} className="bg-emerald-500 hover:bg-emerald-400 text-black font-mono text-xs uppercase tracking-widest font-bold px-4 py-2 transition-colors flex items-center gap-1"><IndianRupee className="w-3 h-3" />Collect ₹{b.bill_amount}</button>
        )}
        {b.status === "BILLED" && b.payment_link && (
          <a href={b.payment_link} target="_blank" rel="noreferrer" className="border border-zinc-700 hover:border-orange-500 text-zinc-300 font-mono text-xs uppercase tracking-widest px-4 py-2 transition-colors">View Pay Link</a>
        )}
      </div>
    </div>
  );
};
