import { useEffect, useMemo, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useGarageWS } from "../hooks/useWebSocket";
import api from "../lib/api";
import { NotificationBell } from "../components/NotificationBell";
import { StatCard } from "../components/StatCard";
import { LogOut, Wrench, Search, Plus, Minus, ShoppingCart, IndianRupee, X, Receipt, Undo2, ChevronLeft, ChevronRight } from "lucide-react";
import MacJitLogo from "../components/MacJitLogo";
import { toast } from "sonner";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../components/ui/dialog";

const PAGE_SIZE = 12;

export default function ShopPage() {
  const { user, token, logout } = useAuth();
  const [inventory, setInventory] = useState([]);
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("all");
  const [page, setPage] = useState(1);
  const [cart, setCart] = useState([]); // [{id, name, sku, price, qty, stock}]
  const [customer, setCustomer] = useState({ name: "", phone: "" });
              {/* Fitting & GST */}
              <div className="border border-zinc-800 bg-zinc-900/20 p-3 space-y-2">
                <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">Fitting Charge & GST</p>
                <div className="flex gap-2">
                  <div className="flex-1">
                    <label className="font-mono text-[10px] text-zinc-500 block mb-1">Fitting (₹)</label>
                    <input type="number" min="0" step="1" value={fittingCharge} onChange={(e) => setFittingCharge(e.target.value)} placeholder="0" className="w-full bg-zinc-950 border border-zinc-800 px-2 py-1.5 font-mono text-sm text-zinc-100 focus:border-orange-500 outline-none" />
                  </div>
                  <div className="flex-1">
                    <label className="font-mono text-[10px] text-zinc-500 block mb-1">GST %</label>
                    <input type="number" min="0" max="100" step="0.5" value={gstPercent} onChange={(e) => setGstPercent(e.target.value)} placeholder="0" className="w-full bg-zinc-950 border border-zinc-800 px-2 py-1.5 font-mono text-sm text-zinc-100 focus:border-orange-500 outline-none" />
                  </div>
                </div>
              </div>
  const [paymentMethod, setPaymentMethod] = useState("cash");
  const [sales, setSales] = useState([]);
  const [stats, setStats] = useState({});
  const [refunds, setRefunds] = useState([]);
  const [tick, setTick] = useState(0);
  const [lastSale, setLastSale] = useState(null);
  const [refundFor, setRefundFor] = useState(null); // sale obj or null
  const [refundReason, setRefundReason] = useState("");
  const [fittingCharge, setFittingCharge] = useState(0);
  const [gstPercent, setGstPercent] = useState(0);
  const [saleSearch, setSaleSearch] = useState("");
  const [salePage, setSalePage] = useState(1);

  const load = async () => {
    const [inv, sl, st, rf] = await Promise.all([
      api.get("/inventory"), api.get("/shop/sales"), api.get("/shop/stats"),
      api.get("/shop/refunds").catch(() => ({ data: [] })),
    ]);
    setInventory(inv.data); setSales(sl.data); setStats(st.data); setRefunds(rf.data);
  };
  useEffect(() => { load(); }, []);
  useGarageWS(token, (e) => {
    if (e.type === "SHOP_SALE" || e.type === "SHOP_PAYMENT_RECEIVED" || (e.type || "").startsWith("REFUND_")) { load(); setTick((t) => t + 1); if (e.type === "SHOP_PAYMENT_RECEIVED") { toast.success("Payment received! Invoice sent to customer via WhatsApp."); } }
  });

  const categories = useMemo(() => {
    const set = new Set();
    inventory.forEach((i) => { if (i.category) set.add(i.category); });
    return ["all", ...Array.from(set).sort()];
  }, [inventory]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return inventory.filter((i) =>
      i.stock > 0
      && (category === "all" || (i.category || "") === category)
      && (i.name.toLowerCase().includes(q) || i.sku.toLowerCase().includes(q) || (i.category || "").toLowerCase().includes(q))
    );
  }, [inventory, search, category]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pageItems = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);
  useEffect(() => { setPage(1); }, [search, category]);

  const cartSubtotal = cart.reduce((s, c) => s + c.price * c.qty, 0);
  const cartFitting = parseFloat(fittingCharge) || 0;
  const cartGstPct = parseFloat(gstPercent) || 0;
  const cartGstAmt = Math.round((cartSubtotal + cartFitting) * cartGstPct) / 100;
  const cartTotal = cartSubtotal + cartFitting + cartGstAmt;

  const refundsBySale = useMemo(() => {
    const m = {};
    refunds.forEach((r) => { m[r.sale_id] = r; });
    return m;
  }, [refunds]);

  const SALE_PAGE_SIZE = 10;
  const filteredSales = useMemo(() => {
    const q = saleSearch.trim().toLowerCase();
    if (!q) return sales;
    return sales.filter((s) =>
      (s.customer_name || "").toLowerCase().includes(q) ||
      (s.customer_phone || "").includes(q) ||
      s.id.toLowerCase().includes(q)
    );
  }, [sales, saleSearch]);
  const saleTotalPages = Math.max(1, Math.ceil(filteredSales.length / SALE_PAGE_SIZE));
  const safeSalePage = Math.min(salePage, saleTotalPages);
  const pagedSales = filteredSales.slice((safeSalePage - 1) * SALE_PAGE_SIZE, safeSalePage * SALE_PAGE_SIZE);

  const addToCart = (it) => {
    setCart((prev) => {
      const found = prev.find((p) => p.id === it.id);
      if (found) {
        if (found.qty >= it.stock) { toast.error("No more stock"); return prev; }
        return prev.map((p) => p.id === it.id ? { ...p, qty: p.qty + 1 } : p);
      }
      return [...prev, { id: it.id, name: it.name, sku: it.sku, price: it.price, qty: 1, stock: it.stock }];
    });
  };
  const decQty = (id) => setCart((prev) => prev.flatMap((p) => p.id === id ? (p.qty > 1 ? [{ ...p, qty: p.qty - 1 }] : []) : [p]));
  const removeFromCart = (id) => setCart((prev) => prev.filter((p) => p.id !== id));

  const checkout = async () => {
    if (cart.length === 0) return toast.error("Cart is empty");
    try {
      const r = await api.post("/shop/sales", {
        customer_name: customer.name,
        customer_phone: customer.phone,
        items: cart.map((c) => ({ inventory_id: c.id, qty: c.qty })),
        payment_method: paymentMethod,
          fitting_charge: cartFitting,
          gst_percent: cartGstPct,
      });
      toast.success(`Sale ₹${r.data.total} ${paymentMethod === "cash" ? "received" : "link sent"}`);
      setLastSale(r.data);
      setCart([]); setCustomer({ name: "", phone: "" });
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Checkout failed"); }
  };

  const submitRefund = async () => {
    if (!refundFor) return;
    if (!refundReason.trim()) return toast.error("Please give a reason");
    try {
      await api.post("/shop/refunds", { sale_id: refundFor.id, reason: refundReason.trim() });
      toast.success("Refund request sent to admin for approval");
      setRefundFor(null); setRefundReason("");
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to raise refund"); }
  };

  const refundBadge = (status) => {
    if (!status) return null;
    const map = {
      PENDING: "bg-yellow-500/10 border-yellow-500/30 text-yellow-400",
      APPROVED: "bg-blue-500/10 border-blue-500/30 text-blue-400",
      REJECTED: "bg-zinc-700 text-zinc-400 border-zinc-600",
    };
    return <span className={`font-mono text-[10px] uppercase tracking-widest px-2 py-0.5 border ${map[status] || ""}`}>Refund {status}</span>;
  };

  return (
    <div className="dark min-h-screen bg-zinc-950 text-zinc-100">
      <header className="sticky top-0 z-20 bg-zinc-950/90 backdrop-blur-xl border-b border-zinc-800">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <MacJitLogo size={32} />
            <div>
              <p className="font-display font-black text-lg tracking-tighter">MACJIT <span className="text-orange-500">/ SHOP</span></p>
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

      <main className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-zinc-800">
          <StatCard testid="shop-stat-today" label="Today sales" value={stats.today_count || 0} accent />
          <StatCard testid="shop-stat-revenue" label="Today revenue" value={`₹${stats.today_revenue || 0}`} />
          <StatCard testid="shop-stat-pending" label="Unpaid" value={stats.pending_count || 0} sub="awaiting payment" />
          <StatCard testid="shop-stat-total" label="All-time" value={stats.total_sales || 0} sub="counter sales" />
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Catalog */}
          <div className="lg:col-span-2 border border-zinc-800 bg-zinc-900/40 p-6">
            <div className="flex flex-col sm:flex-row gap-2 mb-3">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                <input data-testid="shop-search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search parts (SKU, name, category)..." className="w-full bg-zinc-950 border border-zinc-800 pl-10 pr-3 py-2.5 font-mono text-sm focus:border-orange-500 outline-none" />
              </div>
              <select
                data-testid="shop-category"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="bg-zinc-950 border border-zinc-800 px-3 py-2.5 font-mono text-sm focus:border-orange-500 outline-none uppercase tracking-widest"
              >
                {categories.map((c) => (
                  <option key={c} value={c}>{c === "all" ? "All categories" : c}</option>
                ))}
              </select>
            </div>
            <div className="grid sm:grid-cols-2 gap-2">
              {pageItems.map((i) => (
                <button key={i.id} data-testid={`shop-item-${i.id}`} onClick={() => addToCart(i)} className="text-left bg-zinc-950 border border-zinc-800 hover:border-orange-500 transition-colors p-3 flex items-center justify-between">
                  <div>
                    <p className="font-display font-bold text-sm">{i.name}</p>
                    <p className="font-mono text-[10px] text-zinc-500">{i.sku} · {i.category} · stock {i.stock}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-display font-black">₹{i.price}</span>
                    <span className="bg-orange-500 text-black p-1.5"><Plus className="w-3 h-3" /></span>
                  </div>
                </button>
              ))}
              {filtered.length === 0 && <p className="text-sm text-zinc-500 col-span-2">No matching items</p>}
            </div>

            {/* Pagination */}
            {filtered.length > PAGE_SIZE && (
              <div className="mt-4 flex items-center justify-between border-t border-zinc-800 pt-3" data-testid="shop-pagination">
                <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">
                  {(safePage - 1) * PAGE_SIZE + 1}–{Math.min(safePage * PAGE_SIZE, filtered.length)} of {filtered.length}
                </p>
                <div className="flex items-center gap-1">
                  <button data-testid="page-prev" disabled={safePage <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))} className="p-2 border border-zinc-800 hover:border-orange-500 hover:text-orange-500 disabled:opacity-30 disabled:cursor-not-allowed"><ChevronLeft className="w-3.5 h-3.5" /></button>
                  <span className="font-mono text-xs px-3">Page {safePage} / {totalPages}</span>
                  <button data-testid="page-next" disabled={safePage >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))} className="p-2 border border-zinc-800 hover:border-orange-500 hover:text-orange-500 disabled:opacity-30 disabled:cursor-not-allowed"><ChevronRight className="w-3.5 h-3.5" /></button>
                </div>
              </div>
            )}
          </div>

          {/* Cart */}
          <aside className="border border-zinc-800 bg-zinc-900/40 p-6 sticky top-24 self-start">
            <div className="flex items-center gap-2 mb-3">
              <ShoppingCart className="w-4 h-4 text-orange-500" />
              <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500">Cart · {cart.length}</p>
            </div>
            {cart.length === 0 ? (
              <p className="text-sm text-zinc-500 mb-4">Click items to add</p>
            ) : (
              <div className="space-y-2 mb-4 max-h-72 overflow-y-auto">
                {cart.map((c) => (
                  <div key={c.id} data-testid={`cart-item-${c.id}`} className="bg-zinc-950 border border-zinc-800 px-3 py-2 flex items-center justify-between">
                    <div className="flex-1">
                      <p className="text-sm font-bold truncate">{c.name}</p>
                      <p className="font-mono text-[10px] text-zinc-500">₹{c.price} × {c.qty}</p>
                    </div>
                    <div className="flex items-center gap-1">
                      <button data-testid={`cart-dec-${c.id}`} onClick={() => decQty(c.id)} className="p-1 hover:bg-zinc-800"><Minus className="w-3 h-3" /></button>
                      <span className="font-mono text-sm w-5 text-center">{c.qty}</span>
                      <button data-testid={`cart-inc-${c.id}`} onClick={() => addToCart({ ...c, stock: c.stock })} className="p-1 hover:bg-zinc-800"><Plus className="w-3 h-3" /></button>
                      <button data-testid={`cart-remove-${c.id}`} onClick={() => removeFromCart(c.id)} className="p-1 hover:bg-red-500/10 text-red-400"><X className="w-3 h-3" /></button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="border-t border-zinc-800 pt-3 mb-3">
              <input data-testid="shop-customer-name" placeholder="Customer name (optional)" value={customer.name} onChange={(e) => setCustomer({ ...customer, name: e.target.value })} className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2 font-mono text-sm mb-2" />
              <input data-testid="shop-customer-phone" placeholder="Phone (for SMS bill)" value={customer.phone} onChange={(e) => setCustomer({ ...customer, phone: e.target.value })} className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2 font-mono text-sm" />
            </div>

            <div className="flex gap-2 mb-3">
              <button data-testid="pay-cash" onClick={() => setPaymentMethod("cash")} className={`flex-1 font-mono text-[10px] uppercase tracking-widest font-bold py-2 ${paymentMethod === "cash" ? "bg-orange-500 text-black" : "bg-zinc-950 border border-zinc-800 text-zinc-400"}`}>Cash</button>
              <button data-testid="pay-rzp" onClick={() => setPaymentMethod("razorpay")} className={`flex-1 font-mono text-[10px] uppercase tracking-widest font-bold py-2 ${paymentMethod === "razorpay" ? "bg-orange-500 text-black" : "bg-zinc-950 border border-zinc-800 text-zinc-400"}`}>Razorpay Link</button>
            </div>

            <div className="flex items-baseline justify-between mb-3">
              <span className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">Total</span>
              <span className="font-display font-black text-3xl text-orange-500 flex items-center"><IndianRupee className="w-6 h-6" />{cartTotal}</span>
            </div>
            <button data-testid="checkout-btn" onClick={checkout} disabled={cart.length === 0} className="w-full bg-orange-500 hover:bg-orange-400 disabled:opacity-30 disabled:cursor-not-allowed text-black font-display font-black uppercase tracking-widest py-4 transition-colors">Checkout · {paymentMethod === "cash" ? "Collect Cash" : "Send Pay Link"}</button>

            {lastSale && (
              <div data-testid="last-sale" className="mt-4 bg-emerald-500/10 border border-emerald-500/30 p-3">
                <p className="font-mono text-[10px] uppercase tracking-widest text-emerald-400 flex items-center gap-1"><Receipt className="w-3 h-3" />Last Sale</p>
                <p className="font-display font-bold mt-1">#{lastSale.id.slice(0, 8)} · ₹{lastSale.total}</p>
                {lastSale.payment_link && <a href={lastSale.payment_link} target="_blank" rel="noreferrer" className="text-xs text-orange-500 underline">Open Razorpay link</a>}
              </div>
            )}
          </aside>
        </div>

        {/* Recent sales + refund actions */}
        <div className="border border-zinc-800 bg-zinc-900/40 p-6">
          <div className="flex items-center justify-between flex-wrap gap-3 mb-3">
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Counter sales ({filteredSales.length})</p>
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500 pointer-events-none" />
              <input
                type="text"
                value={saleSearch}
                onChange={(e) => { setSaleSearch(e.target.value); setSalePage(1); }}
                placeholder="Search customer / phone / ID…"
                className="bg-zinc-950 border border-zinc-700 pl-7 pr-3 py-1.5 font-mono text-xs text-zinc-100 focus:border-orange-500 outline-none w-56"
              />
              {saleSearch && (
                <button onClick={() => { setSaleSearch(""); setSalePage(1); }} className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300">
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>
          <div className="space-y-2">
            {pagedSales.map((s) => {
              const r = refundsBySale[s.id];
              const status = r?.status || s.refund_status;
              const daysSince = (Date.now() - new Date(s.created_at).getTime()) / (1000 * 60 * 60 * 24);
              const canRefund = s.paid && !status && daysSince <= 5;
              return (
                <div key={s.id} className="bg-zinc-950 border border-zinc-800 p-3 flex items-center justify-between flex-wrap gap-2">
                  <div>
                    <p className="font-display font-bold">{s.customer_name} <span className="text-zinc-500 font-normal text-xs">· {s.items.length} item(s) · #{s.id.slice(0,8)}</span></p>
                    <p className="font-mono text-[10px] text-zinc-500">{new Date(s.created_at).toLocaleString()} · {s.payment_method}</p>
                  </div>
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="font-display font-bold">₹{s.total}</span>
                    <span className={`font-mono text-[10px] uppercase tracking-widest px-2 py-0.5 ${s.paid ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400" : "bg-orange-600/10 border border-orange-600/30 text-orange-500"}`}>{s.paid ? "Paid" : "Unpaid"}</span>
                    {refundBadge(status)}
                    {!s.paid && <button data-testid={`mark-paid-${s.id}`} onClick={async () => { await api.post(`/shop/sales/${s.id}/pay`); load(); }} className="bg-emerald-500 hover:bg-emerald-400 text-black font-mono text-[10px] uppercase tracking-widest font-bold px-2 py-1">Mark Paid</button>}
                    {canRefund && (
                      <button
                        data-testid={`refund-${s.id}`}
                        onClick={() => { setRefundFor(s); setRefundReason(""); }}
                        className="border border-yellow-500/50 hover:bg-yellow-500/10 text-yellow-400 font-mono text-[10px] uppercase tracking-widest font-bold px-2 py-1 flex items-center gap-1"
                      ><Undo2 className="w-3 h-3" /> Refund</button>
                    )}
                  </div>
                </div>
              );
            })}
            {filteredSales.length === 0 && (
              <p className="text-sm text-zinc-500">{saleSearch ? "No sales match your search." : "No counter sales yet."}</p>
            )}
          </div>
          {saleTotalPages > 1 && (
            <div className="flex items-center justify-between mt-4 pt-3 border-t border-zinc-800">
              <span className="font-mono text-[10px] text-zinc-500">Page {safeSalePage} of {saleTotalPages}</span>
              <div className="flex gap-1">
                <button onClick={() => setSalePage((p) => Math.max(1, p - 1))} disabled={safeSalePage === 1}
                  className="p-1.5 border border-zinc-700 text-zinc-400 hover:text-white hover:border-zinc-500 disabled:opacity-30 disabled:cursor-not-allowed">
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>
                {Array.from({ length: saleTotalPages }, (_, i) => i + 1).map((n) => (
                  <button key={n} onClick={() => setSalePage(n)}
                    className={`px-2.5 py-1 font-mono text-[10px] border ${n === safeSalePage ? "bg-orange-500 border-orange-500 text-black font-bold" : "border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-white"}`}>
                    {n}
                  </button>
                ))}
                <button onClick={() => setSalePage((p) => Math.min(saleTotalPages, p + 1))} disabled={safeSalePage === saleTotalPages}
                  className="p-1.5 border border-zinc-700 text-zinc-400 hover:text-white hover:border-zinc-500 disabled:opacity-30 disabled:cursor-not-allowed">
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Refund dialog */}
      <Dialog open={!!refundFor} onOpenChange={(v) => { if (!v) { setRefundFor(null); setRefundReason(""); } }}>
        <DialogContent className="bg-zinc-950 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="font-display uppercase">Raise refund request</DialogTitle>
          </DialogHeader>
          {refundFor && (
            <div className="space-y-3">
              <div className="bg-zinc-900 border border-zinc-800 p-3">
                <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">Sale</p>
                <p className="font-display font-bold">#{refundFor.id.slice(0, 8)} · ₹{refundFor.total}</p>
                <p className="font-mono text-[10px] text-zinc-500">{refundFor.customer_name} · {refundFor.items.length} item(s)</p>
                <ul className="mt-2 space-y-0.5 text-xs text-zinc-300">
                  {refundFor.items.map((it, idx) => (
                    <li key={idx}>· {it.name} × {it.qty} <span className="text-zinc-500">(₹{it.subtotal})</span></li>
                  ))}
                </ul>
              </div>
              <textarea
                data-testid="refund-reason"
                value={refundReason}
                onChange={(e) => setRefundReason(e.target.value)}
                placeholder="Reason (e.g. customer returned defective part)"
                rows={3}
                className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm focus:border-orange-500 outline-none"
              />
              <p className="text-xs text-zinc-500">Admin must approve before stock is restored. The customer will see the refund once approved.</p>
              <div className="flex gap-2">
                <button onClick={() => setRefundFor(null)} className="flex-1 border border-zinc-700 text-zinc-300 font-mono text-xs uppercase tracking-widest py-2.5">Cancel</button>
                <button data-testid="refund-submit" onClick={submitRefund} className="flex-1 bg-yellow-500 hover:bg-yellow-400 text-black font-display font-black uppercase tracking-widest py-2.5">Send for approval</button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
