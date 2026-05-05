import { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import api from "../lib/api";
import { StatusPill } from "../components/StatusPill";
import { Timeline } from "../components/Timeline";
import { Wrench, AlertTriangle, IndianRupee, ExternalLink, User, Phone, Search, MessageCircle, ArrowLeft, Bike, RotateCcw } from "lucide-react";
import MacJitLogo from "../components/MacJitLogo";
import { toast } from "sonner";
import Marquee from "react-fast-marquee";

/**
 * PUBLIC bike tracker — no login, no account.
 * Customer enters their bike plate number and sees:
 *   - active booking + live status & timeline
 *   - bill (if generated) + Pay Now
 *   - "Send bill on WhatsApp" button (uses Twilio)
 *   - approval prompt (if mechanic raised one)
 */
export default function CustomerPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const nav = useNavigate();
  const initial = (searchParams.get("plate") || "").toUpperCase();

  const [plate, setPlate] = useState(initial);
  const [data, setData] = useState(null);   // { active, history, invoice_url }
  const [busy, setBusy] = useState(false);
  const [searched, setSearched] = useState(false);

  const lookup = async (p = plate) => {
    const q = (p || "").trim().toUpperCase();
    if (!q) return toast.error("Enter your bike number");
    setBusy(true); setSearched(true);
    try {
      const r = await api.get("/track", { params: { plate: q } });
      setData(r.data);
      setSearchParams({ plate: q });
    } catch (err) {
      setData(null);
      toast.error(err.response?.data?.detail || "Could not find any booking for that bike");
    } finally { setBusy(false); }
  };

  // Auto-lookup if a plate was provided in the URL.
  useEffect(() => { if (initial) lookup(initial); /* eslint-disable-next-line */ }, []);

  // Refresh every 15s while a booking is being viewed and not yet PAID.
  useEffect(() => {
    if (!data?.active || data.active.status === "PAID") return;
    const t = setInterval(() => lookup(plate), 15000);
    return () => clearInterval(t);
    // eslint-disable-next-line
  }, [data?.active?.id]);

  const active = data?.active;

  const approve = async () => {
    setBusy(true);
    try {
      await api.post(`/bookings/${active.id}/approve`, { plate_number: active.plate_number });
      toast.success("Approved — your mechanic can continue.");
      lookup(plate);
    } catch (err) {
      toast.error(err.response?.data?.detail || "Could not approve");
    } finally { setBusy(false); }
  };

  const sendWhatsappBill = async () => {
    setBusy(true);
    try {
      const r = await api.post(`/track/${active.id}/send-bill`, { plate_number: active.plate_number });
      toast.success(`Bill sent on WhatsApp to ${r.data.sent_to}`);
    } catch (err) {
      toast.error(err.response?.data?.detail || "Could not send bill");
    } finally { setBusy(false); }
  };

  const reopen = async (booking) => {
    setBusy(true);
    try {
      const r = await api.post(`/track/${booking.id}/reopen`, {
        plate_number: booking.plate_number,
        customer_phone: booking.customer_phone,
        problem: "Follow-up visit within 7 days",
      });
      toast.success("Follow-up booking created");
      setPlate(r.data.booking.plate_number);
      lookup(r.data.booking.plate_number);
    } catch (err) {
      toast.error(err.response?.data?.detail || "Could not reopen this service");
    } finally { setBusy(false); }
  };

  const canReopen = (booking) => {
    if (!booking || !["PAID", "QA_DONE", "BILLED"].includes(booking.status)) return false;
    const raw = booking.paid_at || booking.qa_done_at || booking.finished_at || booking.created_at;
    if (!raw) return false;
    return Date.now() - new Date(raw).getTime() <= 7 * 24 * 60 * 60 * 1000;
  };

  return (
    <div className="min-h-screen bg-zinc-100 text-zinc-900">
      <div className="bg-black text-orange-500 py-1.5">
        <Marquee speed={40} gradient={false}>
          <span className="font-mono text-[10px] uppercase tracking-[0.3em] mx-8">TRACK YOUR BIKE · NO LOGIN · WHATSAPP BILL · LIVE STATUS · YOUR BIKE OUR PRIORITY ·</span>
          <span className="font-mono text-[10px] uppercase tracking-[0.3em] mx-8">TRACK YOUR BIKE · NO LOGIN · WHATSAPP BILL · LIVE STATUS · YOUR BIKE OUR PRIORITY ·</span>
        </Marquee>
      </div>

      <header className="sticky top-0 z-20 bg-white/80 backdrop-blur-xl border-b border-zinc-200">
        <div className="max-w-3xl mx-auto px-5 py-4 flex items-center justify-between">
          <button onClick={() => nav("/")} className="flex items-center gap-2 group">
            <MacJitLogo size={32} />
            <span className="font-display font-black text-lg tracking-tighter group-hover:text-orange-500">MACJIT</span>
          </button>
          <button onClick={() => nav("/")} className="flex items-center gap-1 font-mono text-[10px] uppercase tracking-widest text-zinc-500 hover:text-orange-500">
            <ArrowLeft className="w-3 h-3" /> Home
          </button>
        </div>
      </header>

      <main className="max-w-3xl mx-auto px-5 py-8 space-y-8 pb-20">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Track your service</p>
          <h1 className="font-display font-black text-4xl sm:text-5xl tracking-tighter mt-1">Bike Tracker</h1>
          <p className="font-mono text-xs text-zinc-500 mt-2">Enter the number plate of the bike you dropped off.</p>
        </div>

        <form
          onSubmit={(e) => { e.preventDefault(); lookup(); }}
          className="bg-white border border-zinc-200 p-5 flex flex-col sm:flex-row gap-3 shadow-sm"
        >
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
            <input
              data-testid="plate-input"
              autoFocus
              placeholder="e.g. KA-05-MN-2024"
              value={plate}
              onChange={(e) => setPlate(e.target.value.toUpperCase())}
              className="w-full bg-zinc-50 border border-zinc-200 pl-10 pr-4 py-3 font-mono text-base focus:border-orange-500 focus:outline-none uppercase tracking-wide"
            />
          </div>
          <button
            data-testid="plate-search"
            disabled={busy}
            className="bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest px-6 py-3 transition-colors disabled:opacity-50"
          >
            {busy ? "Looking..." : "Track →"}
          </button>
        </form>

        {searched && !active && !busy && (
          <div data-testid="no-booking" className="border border-dashed border-zinc-300 p-12 text-center bg-white">
            <Wrench className="w-10 h-10 text-zinc-400 mx-auto mb-3" />
            <p className="font-display font-black text-xl uppercase">No booking found</p>
            <p className="text-sm text-zinc-500 mt-1">Double-check the plate number, or visit the reception desk.</p>
          </div>
        )}

        {active && (
          <>
            <section className="bg-white border border-zinc-200 p-6 shadow-[0_8px_32px_rgba(0,0,0,0.04)]" data-testid="active-booking-card">
              <div className="flex items-start justify-between gap-4 mb-4">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Booking for</p>
                  <h2 className="font-display font-black text-2xl mt-0.5">{active.car_make} {active.car_model}</h2>
                  <p className="font-mono text-sm text-zinc-600 mt-0.5">{active.plate_number} · {active.service_type}</p>
                  <p className="font-mono text-xs text-zinc-500 mt-1">Customer: {active.customer_name}</p>
                </div>
                <StatusPill status={active.status} testid="customer-status-pill" />
              </div>

              {active.garage_presence_status === "NOT_IN_GARAGE" && active.status === "BOOKED" && (
                <div data-testid="not-in-garage-banner" className="mt-4 border border-blue-200 bg-blue-50 p-4 flex gap-3">
                  <Bike className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-display font-black uppercase text-blue-950">Booked, not in garage yet</p>
                    <p className="font-mono text-xs text-blue-800 mt-1">
                      Drop your bike on or before {active.drop_deadline_at ? new Date(active.drop_deadline_at).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "your slot time"}.
                      If it is not dropped by then, this booking auto-cancels.
                    </p>
                  </div>
                </div>
              )}

              {(active.mechanic_name || active.bay_name) && (
                <div className="mt-3 pt-3 border-t border-zinc-100 grid grid-cols-2 gap-4 font-mono text-sm">
                  <div data-testid="assigned-mechanic">
                    <p className="text-[10px] uppercase tracking-widest text-zinc-500 flex items-center gap-1"><User className="w-3 h-3"/>Mechanic</p>
                    <p className="font-bold">{active.mechanic_name || "—"}</p>
                    {active.mechanic_phone && (
                      <a href={`tel:${active.mechanic_phone}`} className="text-[11px] text-orange-600 flex items-center gap-1 mt-0.5">
                        <Phone className="w-3 h-3"/>{active.mechanic_phone}
                      </a>
                    )}
                  </div>
                  <div>
                    <p className="text-[10px] uppercase tracking-widest text-zinc-500">Service Bay</p>
                    <p className="font-bold">{active.bay_name || "—"}</p>
                  </div>
                  {active.tester_name && (
                    <div data-testid="assigned-tester">
                      <p className="text-[10px] uppercase tracking-widest text-zinc-500 flex items-center gap-1"><User className="w-3 h-3"/>QA Tester</p>
                      <p className="font-bold">{active.tester_name}</p>
                    </div>
                  )}
                </div>
              )}

              {active.estimated_start_at && active.status !== "PAID" && (
                <div data-testid="eta-banner" className="mt-3 bg-black text-white p-3 flex items-center justify-between">
                  <div>
                    <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500">Estimated slot</p>
                    <p className="font-display font-bold text-sm">
                      {new Date(active.estimated_start_at).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" })}
                      {" → "}
                      {active.estimated_end_at && new Date(active.estimated_end_at).toLocaleString([], { hour: "2-digit", minute: "2-digit" })}
                    </p>
                  </div>
                </div>
              )}
            </section>

            {active.approval_pending && (
              <section data-testid="approval-card" className="bg-yellow-50 border-2 border-orange-500 p-6">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-6 h-6 text-yellow-700 flex-shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <h3 className="font-display font-black text-lg uppercase">Approval needed</h3>
                    <p className="text-sm mt-1">{active.approval_reason}</p>
                    <p className="font-mono text-sm font-bold mt-2">Extra cost: ₹{active.extra_cost}</p>
                    <button
                      data-testid="approve-work-btn"
                      onClick={approve}
                      disabled={busy}
                      className="mt-4 bg-black hover:bg-zinc-800 text-white font-display font-black uppercase tracking-widest px-6 py-3 transition-colors disabled:opacity-50"
                    >Approve →</button>
                  </div>
                </div>
              </section>
            )}

            {active.status === "BILLED" && !active.paid && (() => {
              const billItems = active.items || [];
              const itemsSum = billItems.reduce((s, i) => s + (i.subtotal || 0), 0);
              const billTotal = Number(active.bill_amount || 0);
              const sub = Number(active.subtotal || billTotal + Number(active.discount || 0));
              const base = Math.max(0, sub - itemsSum - Number(active.extra_cost || 0));
              const svc = String(active.service_type || "service").replace(/-/g, " ");
              return (
                <section data-testid="payment-card" className="bg-black text-white p-6">
                  <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500">Service breakdown</p>
                  <div className="mt-3 divide-y divide-white/15 font-mono text-sm text-white" data-testid="customer-bill-breakdown">
                    <div className="flex justify-between py-2 text-white">
                      <span className="capitalize">{svc} — base</span>
                      <span className="font-bold">₹{base}</span>
                    </div>
                    {billItems.map((it) => (
                      <div key={it.inventory_id || it.name} className="flex justify-between py-2 text-white">
                        <span>{it.name} <span className="text-zinc-300">× {it.qty}</span></span>
                        <span className="font-bold">₹{it.subtotal}</span>
                      </div>
                    ))}
                    {Number(active.extra_cost || 0) > 0 && (
                      <div className="flex justify-between py-2 text-white">
                        <span>Heavy work</span>
                        <span className="font-bold">₹{active.extra_cost}</span>
                      </div>
                    )}
                    <div className="flex justify-between py-2 text-zinc-200">
                      <span>Subtotal</span>
                      <span className="font-bold">₹{sub}</span>
                    </div>
                    {Number(active.discount || 0) > 0 && (
                      <div className="flex justify-between py-2 text-emerald-300">
                        <span>{active.loyalty_tier || ""} loyalty ({active.discount_pct || 0}%)</span>
                        <span className="font-bold">−₹{active.discount}</span>
                      </div>
                    )}
                  </div>

                  <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mt-5">Total due</p>
                  <div className="flex items-baseline gap-1 mt-1">
                    <IndianRupee className="w-7 h-7 text-orange-500" />
                    <span className="font-display font-black text-5xl tracking-tighter">{billTotal}</span>
                  </div>
                  <div className="flex flex-wrap gap-3 mt-5">
                    <a
                      data-testid="pay-bill-btn"
                      href={`/pay/${active.id}?plate=${encodeURIComponent(active.plate_number || "")}`}
                      className="inline-flex items-center gap-2 bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest px-6 py-3 transition-colors"
                    >Pay Now <ExternalLink className="w-4 h-4" /></a>
                    <a
                      data-testid="download-invoice-billed"
                      href={`/api/invoices/${active.id}.pdf`}
                      target="_blank" rel="noreferrer"
                      className="inline-flex items-center gap-2 border border-white/30 hover:border-orange-500 hover:text-orange-500 text-white font-display font-black uppercase tracking-widest px-6 py-3 transition-colors"
                    >Download Invoice <ExternalLink className="w-4 h-4" /></a>
                    <button
                      data-testid="send-whatsapp-bill"
                      onClick={sendWhatsappBill}
                      disabled={busy}
                      className="inline-flex items-center gap-2 border border-white/30 hover:border-orange-500 hover:text-orange-500 text-white font-display font-black uppercase tracking-widest px-6 py-3 transition-colors disabled:opacity-50"
                    ><MessageCircle className="w-4 h-4" /> Send bill on WhatsApp</button>
                  </div>
                </section>
              );
            })()}

            {active.paid && (
              <div data-testid="thanks-card" className="bg-emerald-500 text-white p-8 text-center">
                <p className="font-mono text-[10px] uppercase tracking-[0.3em]">Thank you for visiting</p>
                <p className="font-display font-black text-3xl mt-1 tracking-tighter">Drive safe! 🏁</p>
                <a
                  data-testid="download-invoice-paid"
                  href={`/api/invoices/${active.id}.pdf`}
                  target="_blank" rel="noreferrer"
                  className="mt-4 inline-flex items-center gap-2 bg-black text-orange-500 font-display font-black uppercase tracking-widest px-5 py-3"
                >Download Invoice <ExternalLink className="w-3 h-3"/></a>
                {canReopen(active) && (
                  <button
                    onClick={() => reopen(active)}
                    disabled={busy}
                    className="mt-3 ml-2 inline-flex items-center gap-2 bg-white text-emerald-700 font-display font-black uppercase tracking-widest px-5 py-3 disabled:opacity-50"
                  >
                    <RotateCcw className="w-3 h-3" /> Reopen within 7 days
                  </button>
                )}
              </div>
            )}

            {active.status === "CANCELLED" && (
              <section className="bg-zinc-900 text-white p-6" data-testid="cancelled-booking-card">
                <p className="font-display font-black text-xl uppercase">Booking cancelled</p>
                <p className="font-mono text-xs text-zinc-400 mt-2">{active.cancel_reason || "This booking is no longer active."}</p>
              </section>
            )}

            <section className="bg-white border border-zinc-200 p-6">
              <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-4">Service progress</p>
              <Timeline status={active.status} light />
            </section>

            {active.items && active.items.length > 0 && (
              <section className="bg-white border border-zinc-200 p-6">
                <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-4">Parts used</p>
                {active.items.map((it) => (
                  <div key={it.inventory_id} className="flex justify-between py-2 border-b border-zinc-100 last:border-0">
                    <div>
                      <p className="font-bold text-sm">{it.name}</p>
                      <p className="font-mono text-[10px] text-zinc-500">{it.sku} × {it.qty}</p>
                    </div>
                    <p className="font-mono font-bold">₹{it.subtotal}</p>
                  </div>
                ))}
              </section>
            )}

            {data?.history?.length > 1 && (
              <section className="bg-white border border-zinc-200 p-6">
                <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-4">Past visits</p>
                <ul className="divide-y divide-zinc-100">
                  {data.history.filter((b) => b.id !== active.id).slice(0, 5).map((b) => (
                    <li key={b.id} className="py-2 flex items-center justify-between text-sm">
                      <div>
                        <p className="font-bold">{b.service_type}</p>
                        <p className="font-mono text-[10px] text-zinc-500">{new Date(b.created_at).toLocaleDateString()}</p>
                      </div>
                      <div className="text-right">
                        <span className="font-mono text-xs">{b.paid ? `₹${b.bill_amount}` : b.status}</span>
                        {canReopen(b) && (
                          <button onClick={() => reopen(b)} className="block mt-1 font-mono text-[10px] uppercase tracking-widest text-orange-600 hover:text-orange-500">
                            Reopen
                          </button>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </>
        )}
      </main>
    </div>
  );
}
