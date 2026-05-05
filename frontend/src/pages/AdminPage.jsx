import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useGarageWS } from "../hooks/useWebSocket";
import api from "../lib/api";
import { StatusPill } from "../components/StatusPill";
import { StatCard } from "../components/StatCard";
import { NotificationBell } from "../components/NotificationBell";
import { LogOut, Wrench, AlertTriangle, PackageX, Clock, Plus, Trash, Upload, FileSpreadsheet, Mail, ReceiptText, Undo2, Search, Check, X as XIcon, ShoppingCart, Wrench as WrenchIcon, ExternalLink, ChevronLeft, ChevronRight } from "lucide-react";
import MacJitLogo from "../components/MacJitLogo";
import { toast } from "sonner";
import { LineChart, Line, XAxis, YAxis, ResponsiveContainer, CartesianGrid, Tooltip } from "recharts";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "../components/ui/dialog";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../components/ui/tabs";

export default function AdminPage() {
  const { user, token, logout } = useAuth();
  const [stats, setStats] = useState({});
  const [bookings, setBookings] = useState([]);
  const [inventory, setInventory] = useState([]);
  const [alerts, setAlerts] = useState({ low_stock: [], out_of_stock: [], fifo: [] });
  const [bSearch, setBSearch] = useState("");
  const [bPage, setBPage] = useState(1);
  const [tick, setTick] = useState(0);

  const load = async () => {
    const [s, b, inv, a] = await Promise.all([
      api.get("/admin/stats"), api.get("/bookings"), api.get("/inventory"), api.get("/inventory/alerts"),
    ]);
    setStats(s.data); setBookings(b.data); setInventory(inv.data); setAlerts(a.data);
  };
  useEffect(() => { load(); }, []);
  useGarageWS(token, (e) => { if (e.type !== "connected") { load(); setTick((t) => t + 1); } });

  return (
    <div className="dark min-h-screen bg-zinc-950 text-zinc-100">
      <header className="sticky top-0 z-20 bg-zinc-950/90 backdrop-blur-xl border-b border-zinc-800">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <MacJitLogo size={32} />
            <div>
              <p className="font-display font-black text-lg tracking-tighter">MACJIT <span className="text-orange-500">/ ADMIN</span></p>
              <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">{user?.name}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <NotificationBell refreshKey={tick} />
            <button data-testid="logout-btn" onClick={logout} className="p-2 hover:bg-zinc-800 rounded-full"><LogOut className="w-4 h-4" /></button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-6">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-px bg-zinc-800">
          <StatCard testid="admin-stat-serviced" label="Today serviced" value={stats.today_serviced || 0} accent />
          <StatCard testid="admin-stat-revenue" label="Today revenue" value={`₹${stats.today_revenue || 0}`} sub="paid bills" />
          <StatCard testid="admin-stat-active" label="Active bays" value={stats.active_bays || 0} sub="in service" />
          <StatCard testid="admin-stat-low" label="Low + Out stock" value={(stats.low_stock_count || 0) + (stats.out_of_stock_count || 0)} sub="needs attention" />
        </div>

        <Tabs defaultValue="overview" className="w-full">
          <TabsList className="bg-zinc-900 border border-zinc-800 rounded-none p-0 flex-wrap h-auto">
            <TabsTrigger data-testid="tab-overview" value="overview" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Overview</TabsTrigger>
            <TabsTrigger data-testid="tab-inventory" value="inventory" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Inventory</TabsTrigger>
            <TabsTrigger data-testid="tab-bookings" value="bookings" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Bookings</TabsTrigger>
            <TabsTrigger data-testid="tab-transactions" value="transactions" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Transactions</TabsTrigger>
            <TabsTrigger data-testid="tab-refunds" value="refunds" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Refunds</TabsTrigger>
            <TabsTrigger data-testid="tab-services" value="services" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Services</TabsTrigger>
            <TabsTrigger data-testid="tab-customers" value="customers" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Customers</TabsTrigger>
            <TabsTrigger data-testid="tab-staff" value="staff" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Staff</TabsTrigger>
            <TabsTrigger data-testid="tab-enquiries" value="enquiries" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Enquiries</TabsTrigger>
            <TabsTrigger data-testid="tab-hr" value="hr" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">HR</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="mt-6 grid lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 border border-zinc-800 bg-zinc-900/40 p-6">
              <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-4">7-day revenue & service velocity</p>
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={stats.last_7_days || []}>
                    <CartesianGrid stroke="#27272a" strokeDasharray="3 3" />
                    <XAxis dataKey="date" stroke="#71717a" fontSize={11} tickFormatter={(d) => d?.slice(5)} />
                    <YAxis stroke="#71717a" fontSize={11} />
                    <Tooltip contentStyle={{ background: "#09090b", border: "1px solid #27272a" }} />
                    <Line type="monotone" dataKey="revenue" stroke="#facc15" strokeWidth={2} dot={{ fill: "#facc15" }} />
                    <Line type="monotone" dataKey="serviced" stroke="#22c55e" strokeWidth={2} dot={{ fill: "#22c55e" }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div className="border border-zinc-800 bg-zinc-900/40 p-6 space-y-4" data-testid="inventory-alert-list">
              <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Inventory alerts</p>
              {alerts.fifo?.length > 0 && (
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-widest text-blue-400 mb-2 flex items-center gap-1"><Clock className="w-3 h-3" />FIFO · use first</p>
                  {alerts.fifo.map((f) => (
                    <div key={f.id} className="text-xs bg-blue-500/5 border border-blue-500/20 p-2 mb-1">
                      <p className="font-bold">{f.use_first}</p>
                      <p className="font-mono text-[10px] text-zinc-500">stocked {new Date(f.stocked_at).toLocaleDateString()}</p>
                    </div>
                  ))}
                </div>
              )}
              {alerts.out_of_stock?.length > 0 && (
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-widest text-red-400 mb-2 flex items-center gap-1"><PackageX className="w-3 h-3" />Out of stock</p>
                  {alerts.out_of_stock.map((i) => (
                    <div key={i.id} className="text-xs bg-red-500/5 border border-red-500/20 p-2 mb-1">
                      <p className="font-bold">{i.name}</p>
                      <p className="font-mono text-[10px] text-zinc-500">{i.sku}</p>
                    </div>
                  ))}
                </div>
              )}
              {alerts.low_stock?.length > 0 && (
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-widest text-orange-500 mb-2 flex items-center gap-1"><AlertTriangle className="w-3 h-3" />Low stock</p>
                  {alerts.low_stock.map((i) => (
                    <div key={i.id} className="text-xs bg-orange-600/5 border border-orange-600/20 p-2 mb-1">
                      <p className="font-bold">{i.name}</p>
                      <p className="font-mono text-[10px] text-zinc-500">{i.stock} left · threshold {i.low_stock_threshold}</p>
                    </div>
                  ))}
                </div>
              )}
              {!alerts.fifo?.length && !alerts.out_of_stock?.length && !alerts.low_stock?.length && (
                <p className="text-sm text-zinc-500">All inventory healthy ✓</p>
              )}
            </div>
          </TabsContent>

          <TabsContent value="inventory" className="mt-6">
            <InventoryTab inventory={inventory} onChange={load} />
          </TabsContent>

          <TabsContent value="bookings" className="mt-6">
            {(() => {
              const BPS = 10;
              const q = bSearch.trim().toLowerCase();
              const fb = q ? bookings.filter(b => (b.plate_number||"").toLowerCase().includes(q)||(b.customer_name||"").toLowerCase().includes(q)||(b.service_type||"").toLowerCase().includes(q)) : bookings;
              const bTotal = Math.max(1, Math.ceil(fb.length / BPS));
              const bSafe = Math.min(bPage, bTotal);
              const bPaged = fb.slice((bSafe-1)*BPS, bSafe*BPS);
              return (
                <div className="border border-zinc-800 bg-zinc-900/40 p-6">
                  <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
                    <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Bookings · {fb.length}</p>
                    <div className="relative">
                      <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500 pointer-events-none" />
                      <input value={bSearch} onChange={e=>{setBSearch(e.target.value);setBPage(1);}} placeholder="Plate / customer / service…" className="bg-zinc-950 border border-zinc-700 pl-7 pr-3 py-1.5 font-mono text-xs text-zinc-100 focus:border-orange-500 outline-none w-52" />
                      {bSearch && <button onClick={()=>{setBSearch("");setBPage(1);}} className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"><XIcon className="w-3 h-3"/></button>}
                    </div>
                  </div>
                  <div className="space-y-2">
                    {bPaged.map((b) => (
                      <div key={b.id} className="flex items-center justify-between border-b border-zinc-800 py-3 last:border-0">
                        <div>
                          <p className="font-display font-bold">{b.plate_number} <span className="text-zinc-500 text-sm font-normal">· {b.customer_name}</span></p>
                          <p className="font-mono text-xs text-zinc-500">{b.car_make} {b.car_model} · {b.service_type}{b.bay_name ? ` · ${b.bay_name}` : ""}{b.mechanic_name ? ` · ${b.mechanic_name}` : ""}{b.bill_amount ? ` · ₹${b.bill_amount}` : ""}</p>
                        </div>
                        <StatusPill status={b.status} />
                      </div>
                    ))}
                    {fb.length === 0 && <p className="text-sm text-zinc-500 py-4">{bSearch ? "No bookings match." : "No bookings yet."}</p>}
                  </div>
                  {bTotal > 1 && (
                    <div className="flex items-center justify-between mt-4 pt-3 border-t border-zinc-800">
                      <span className="font-mono text-[10px] text-zinc-500">Page {bSafe} of {bTotal}</span>
                      <div className="flex gap-1">
                        <button onClick={()=>setBPage(p=>Math.max(1,p-1))} disabled={bSafe===1} className="p-1.5 border border-zinc-700 text-zinc-400 hover:text-white disabled:opacity-30"><ChevronLeft className="w-3.5 h-3.5"/></button>
                        {Array.from({length:bTotal},(_,i)=>i+1).map(n=>(
                          <button key={n} onClick={()=>setBPage(n)} className={`px-2.5 py-1 font-mono text-[10px] border ${n===bSafe?"bg-orange-500 border-orange-500 text-black font-bold":"border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}>{n}</button>
                        ))}
                        <button onClick={()=>setBPage(p=>Math.min(bTotal,p+1))} disabled={bSafe===bTotal} className="p-1.5 border border-zinc-700 text-zinc-400 hover:text-white disabled:opacity-30"><ChevronRight className="w-3.5 h-3.5"/></button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })()}
          </TabsContent>

          <TabsContent value="transactions" className="mt-6"><TransactionsTab /></TabsContent>
          <TabsContent value="refunds" className="mt-6"><RefundsTab onChange={load} /></TabsContent>
          <TabsContent value="services" className="mt-6"><ServicesTab /></TabsContent>
          <TabsContent value="customers" className="mt-6"><CustomersTab /></TabsContent>
          <TabsContent value="staff" className="mt-6"><StaffTab /></TabsContent>
          <TabsContent value="enquiries" className="mt-6"><EnquiriesTab /></TabsContent>
          <TabsContent value="hr" className="mt-6"><HRAdminTab /></TabsContent>
        </Tabs>
      </main>
    </div>
  );
}

const InventoryTab = ({ inventory, onChange }) => {
  const [invSearch, setInvSearch] = useState("");
  const [invPage, setInvPage] = useState(1);
  const INV_PS = 10;
  const filtInv = invSearch.trim() ? inventory.filter(i => (i.name||"").toLowerCase().includes(invSearch.toLowerCase())||(i.sku||"").toLowerCase().includes(invSearch.toLowerCase())||(i.category||"").toLowerCase().includes(invSearch.toLowerCase())) : inventory;
  const invTotal = Math.max(1, Math.ceil(filtInv.length / INV_PS));
  const invSafe = Math.min(invPage, invTotal);
  const invPaged = filtInv.slice((invSafe-1)*INV_PS, invSafe*INV_PS);
  return (
    <div className="border border-zinc-800 bg-zinc-900/40 p-6">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
        <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Stock · {filtInv.length} items</p>
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500 pointer-events-none"/>
            <input value={invSearch} onChange={e=>{setInvSearch(e.target.value);setInvPage(1);}} placeholder="Name / SKU / category…" className="bg-zinc-950 border border-zinc-700 pl-7 pr-3 py-1.5 font-mono text-xs text-zinc-100 focus:border-orange-500 outline-none w-48"/>
            {invSearch && <button onClick={()=>{setInvSearch("");setInvPage(1);}} className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"><XIcon className="w-3 h-3"/></button>}
          </div>
          <BulkUploadInventory onDone={onChange} />
          <AddInventoryDialog onDone={onChange} />
        </div>
      </div>
      <div className="space-y-2">
        {invPaged.map((i) => {
          const isOut = i.stock <= 0;
          const isLow = !isOut && i.stock <= (i.low_stock_threshold || 5);
          return (
            <div key={i.id} data-testid={`inv-row-${i.id}`} className="flex items-center justify-between bg-zinc-950 border border-zinc-800 px-4 py-3">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <p className="font-bold">{i.name}</p>
                  {isOut && <span className="bg-red-500/10 border border-red-500/30 text-red-400 font-mono text-[10px] uppercase tracking-widest px-2 py-0.5">Out</span>}
                  {isLow && <span className="bg-orange-600/10 border border-orange-600/30 text-orange-500 font-mono text-[10px] uppercase tracking-widest px-2 py-0.5">Low</span>}
                </div>
                <p className="font-mono text-[10px] text-zinc-500">{i.sku} · {i.category} · ₹{i.price} · stocked {i.stocked_at ? new Date(i.stocked_at).toLocaleDateString() : "—"}</p>
              </div>
              <div className="flex items-center gap-3">
                <span className="font-mono font-bold">{i.stock}</span>
                <button data-testid={`inv-del-${i.id}`} onClick={async () => { await api.delete(`/inventory/${i.id}`); toast.success("Removed"); onChange(); }} className="p-2 hover:bg-red-500/10 text-red-400"><Trash className="w-4 h-4" /></button>
              </div>
            </div>
          );
        })}
        {filtInv.length === 0 && <p className="text-sm text-zinc-500 py-4">{invSearch ? "No items match." : "No inventory yet."}</p>}
      </div>
      {invTotal > 1 && (
        <div className="flex items-center justify-between mt-4 pt-3 border-t border-zinc-800">
          <span className="font-mono text-[10px] text-zinc-500">Page {invSafe} of {invTotal}</span>
          <div className="flex gap-1">
            <button onClick={()=>setInvPage(p=>Math.max(1,p-1))} disabled={invSafe===1} className="p-1.5 border border-zinc-700 text-zinc-400 hover:text-white disabled:opacity-30"><ChevronLeft className="w-3.5 h-3.5"/></button>
            {Array.from({length:invTotal},(_,i)=>i+1).map(n=>(
              <button key={n} onClick={()=>setInvPage(n)} className={`px-2.5 py-1 font-mono text-[10px] border ${n===invSafe?"bg-orange-500 border-orange-500 text-black font-bold":"border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}>{n}</button>
            ))}
            <button onClick={()=>setInvPage(p=>Math.min(invTotal,p+1))} disabled={invSafe===invTotal} className="p-1.5 border border-zinc-700 text-zinc-400 hover:text-white disabled:opacity-30"><ChevronRight className="w-3.5 h-3.5"/></button>
          </div>
        </div>
      )}
    </div>
  );
};

const BulkUploadInventory = ({ onDone }) => {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  const downloadTemplate = () => {
    const csv = "name,sku,category,price,stock,low_stock_threshold\nEngine Oil 5W-30 4L,OIL-NEW-4L,Lubricants,2400,10,5\nBrake Pad Front (Bosch),BRK-PAD-FRT-NEW,Brakes,1850,6,3\n";
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "macjit-inventory-template.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  const upload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true); setResult(null);
    const fd = new FormData();
    fd.append("file", file);
    try {
      const r = await api.post("/inventory/bulk-upload", fd, { headers: { "Content-Type": "multipart/form-data" } });
      setResult(r.data);
      toast.success(`Added ${r.data.added}, updated ${r.data.updated}`);
      onDone();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Upload failed");
    } finally {
      setBusy(false);
      e.target.value = "";
    }
  };

  return (
    <Dialog open={open} onOpenChange={(v) => { setOpen(v); if (!v) setResult(null); }}>
      <DialogTrigger asChild>
        <button data-testid="bulk-upload-btn" className="border border-orange-500 text-orange-500 hover:bg-orange-500/10 font-mono text-xs uppercase tracking-widest font-bold px-3 py-1.5 flex items-center gap-1 transition-colors">
          <Upload className="w-3 h-3" /> Bulk Upload
        </button>
      </DialogTrigger>
      <DialogContent className="bg-zinc-950 border-zinc-800 max-w-lg">
        <DialogHeader><DialogTitle className="font-display uppercase">Bulk inventory upload</DialogTitle></DialogHeader>
        <div className="space-y-4">
          <p className="font-mono text-xs text-zinc-400">
            Upload a <span className="text-orange-500">.csv</span> or <span className="text-orange-500">.xlsx</span> file with these columns:
          </p>
          <div className="bg-zinc-900 border border-zinc-800 p-3 font-mono text-[11px] text-zinc-300">
            name, sku, category, price, stock, low_stock_threshold
          </div>
          <p className="font-mono text-[10px] text-zinc-500">
            If a SKU already exists, its stock will be <span className="text-orange-500">incremented</span> and details updated.
          </p>

          <button data-testid="dl-template-btn" onClick={downloadTemplate} className="w-full border border-zinc-700 hover:border-orange-500 text-zinc-300 hover:text-orange-500 font-mono text-xs uppercase tracking-widest py-2.5 flex items-center justify-center gap-2">
            <FileSpreadsheet className="w-3.5 h-3.5" /> Download CSV template
          </button>

          <label data-testid="file-pick-label" className="block border-2 border-dashed border-zinc-700 hover:border-orange-500 p-8 text-center cursor-pointer transition-colors">
            <Upload className="w-8 h-8 text-zinc-500 mx-auto mb-2" />
            <p className="font-mono text-xs text-zinc-300">{busy ? "Uploading..." : "Click to choose .csv or .xlsx"}</p>
            <input data-testid="bulk-file-input" type="file" accept=".csv,.xlsx,.xls" onChange={upload} disabled={busy} className="hidden" />
          </label>

          {result && (
            <div data-testid="bulk-result" className="bg-zinc-900 border border-zinc-800 p-4 space-y-1 font-mono text-xs">
              <p className="text-emerald-400">✓ Added: {result.added}</p>
              <p className="text-orange-400">↻ Updated (existing SKU): {result.updated}</p>
              <p className="text-zinc-400">Total rows: {result.total_rows}</p>
              {result.errors?.length > 0 && (
                <div className="mt-2 pt-2 border-t border-zinc-800">
                  <p className="text-red-400 mb-1">Errors ({result.errors.length}):</p>
                  {result.errors.slice(0, 5).map((er, i) => (
                    <p key={i} className="text-[10px] text-red-300">Row {er.row}: {er.error}</p>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};


const AddInventoryDialog = ({ onDone }) => {
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ name: "", sku: "", category: "", price: "", stock: "", low_stock_threshold: "5" });
  const u = (k, v) => setF({ ...f, [k]: v });
  const submit = async () => {
    try {
      await api.post("/inventory", { ...f, price: parseFloat(f.price), stock: parseInt(f.stock), low_stock_threshold: parseInt(f.low_stock_threshold) });
      toast.success("Item added"); onDone(); setOpen(false);
      setF({ name: "", sku: "", category: "", price: "", stock: "", low_stock_threshold: "5" });
    } catch (e) { toast.error("Failed"); }
  };
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <button data-testid="add-inventory-btn" className="bg-orange-500 hover:bg-orange-400 text-black font-mono text-xs uppercase tracking-widest font-bold px-3 py-1.5 flex items-center gap-1 transition-colors">
          <Plus className="w-3 h-3" /> Add Item
        </button>
      </DialogTrigger>
      <DialogContent className="bg-zinc-950 border-zinc-800">
        <DialogHeader><DialogTitle className="font-display uppercase">Add inventory item</DialogTitle></DialogHeader>
        <div className="space-y-2">
          {[["name", "Name"], ["sku", "SKU"], ["category", "Category"], ["price", "Price (₹)"], ["stock", "Stock qty"], ["low_stock_threshold", "Low stock threshold"]].map(([k, lbl]) => (
            <input key={k} data-testid={`inv-input-${k}`} placeholder={lbl} value={f[k]} onChange={(e) => u(k, e.target.value)} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
          ))}
          <button data-testid="inv-submit" onClick={submit} className="w-full bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest py-3">Add</button>
        </div>
      </DialogContent>
    </Dialog>
  );
};

const CustomersTab = () => {
  const [list, setList] = useState([]);
  const [sel, setSel] = useState(null);
  const [hist, setHist] = useState(null);
  const [custPage, setCustPage] = useState(1);
  const custTotal = Math.max(1, Math.ceil(list.length / 10));
  useEffect(() => { api.get("/customers").then((r) => setList(r.data)); }, []);
  const open = async (c) => {
    setSel(c);
    const r = await api.get(`/customers/${c.id}/history`);
    setHist(r.data);
  };
  const tierColor = (t) => ({ GOLD: "bg-orange-600 text-black", SILVER: "bg-zinc-300 text-black", BRONZE: "bg-orange-700 text-white" }[t] || "bg-zinc-700 text-white");
  return (
    <div className="grid lg:grid-cols-2 gap-6">
      <div className="border border-zinc-800 bg-zinc-900/40 p-6">
        <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-4">All customers · {list.length}</p>
        <div className="space-y-2">
          {list.slice((custPage-1)*10, custPage*10).map((c) => (
            <button key={c.id} data-testid={`customer-${c.id}`} onClick={() => open(c)} className={`w-full text-left border ${sel?.id === c.id ? "border-orange-500" : "border-zinc-800"} bg-zinc-950 hover:border-zinc-600 px-4 py-3 transition-colors`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-display font-bold">{c.name}</p>
                  <p className="font-mono text-[10px] text-zinc-500">{c.phone || c.username}</p>
                </div>
                <span className={`font-mono text-[10px] uppercase tracking-widest px-2 py-0.5 ${tierColor(c.loyalty_tier || "BRONZE")}`}>{c.loyalty_tier || "BRONZE"}</span>
              </div>
            </button>
          ))}
        </div>
        {custTotal > 1 && (
          <div className="flex items-center justify-between mt-3 pt-3 border-t border-zinc-800">
            <span className="font-mono text-[10px] text-zinc-500">Page {Math.min(custPage,custTotal)} of {custTotal}</span>
            <div className="flex gap-1">
              <button onClick={()=>setCustPage(p=>Math.max(1,p-1))} disabled={custPage<=1} className="p-1.5 border border-zinc-700 text-zinc-400 hover:text-white disabled:opacity-30"><ChevronLeft className="w-3.5 h-3.5"/></button>
              {Array.from({length:custTotal},(_,i)=>i+1).map(n=>(
                <button key={n} onClick={()=>setCustPage(n)} className={`px-2.5 py-1 font-mono text-[10px] border ${n===Math.min(custPage,custTotal)?"bg-orange-500 border-orange-500 text-black font-bold":"border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}>{n}</button>
              ))}
              <button onClick={()=>setCustPage(p=>Math.min(custTotal,p+1))} disabled={custPage>=custTotal} className="p-1.5 border border-zinc-700 text-zinc-400 hover:text-white disabled:opacity-30"><ChevronRight className="w-3.5 h-3.5"/></button>
            </div>
          </div>
        )}
      </div>
      <div className="border border-zinc-800 bg-zinc-900/40 p-6">
        {!hist ? (
          <p className="text-sm text-zinc-500">Select a customer to view history</p>
        ) : (
          <>
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Customer</p>
            <h3 className="font-display font-black text-2xl">{hist.customer.name}</h3>
            <p className="font-mono text-xs text-zinc-400">{hist.customer.phone}</p>
            <div className="grid grid-cols-3 gap-px bg-zinc-800 mt-4 mb-4">
              <div className="bg-zinc-950 p-3"><p className="font-mono text-[10px] text-zinc-500 uppercase tracking-widest">Total spent</p><p className="font-display font-black text-xl text-orange-500">₹{hist.total_spent}</p></div>
              <div className="bg-zinc-950 p-3"><p className="font-mono text-[10px] text-zinc-500 uppercase tracking-widest">Tier</p><p className="font-display font-black text-xl">{hist.loyalty_tier}</p></div>
              <div className="bg-zinc-950 p-3"><p className="font-mono text-[10px] text-zinc-500 uppercase tracking-widest">Discount</p><p className="font-display font-black text-xl text-emerald-400">{hist.discount_pct}%</p></div>
            </div>
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-2">Bookings · {hist.bookings.length}</p>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {hist.bookings.map((b) => (
                <div key={b.id} className="bg-zinc-950 border border-zinc-800 px-3 py-2 flex items-center justify-between">
                  <div>
                    <p className="font-display font-bold text-sm">{b.plate_number} <span className="font-normal text-zinc-500">· {b.service_type}</span></p>
                    <p className="font-mono text-[10px] text-zinc-500">{new Date(b.created_at).toLocaleDateString()}{b.bill_amount ? ` · ₹${b.bill_amount}` : ""}</p>
                  </div>
                  <StatusPill status={b.status} />
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
};

const EnquiriesTab = () => {
  const [list, setList] = useState([]);
  const [enqPage, setEnqPage] = useState(1);
  const ENQ_PS = 8;
  const load = () => api.get("/enquiries").then((r) => setList(r.data)).catch(() => {});
  useEffect(() => { load(); }, []);

  const setStatus = async (id, status) => {
    try { await api.patch(`/enquiries/${id}`, { status }); toast.success("Updated"); load(); }
    catch (e) { toast.error("Failed"); }
  };

  return (
    <div className="border border-zinc-800 bg-zinc-900/40 p-6">
      <div className="flex items-center justify-between mb-4">
        <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Enquiries · {list.length} total</p>
        <Mail className="w-4 h-4 text-orange-500" />
      </div>
      {list.length === 0 ? (
        <p className="font-mono text-xs text-zinc-500 text-center py-8">No enquiries yet. They'll appear here when customers fill the landing-page form.</p>
      ) : (
        <>
        <div className="space-y-2">
          {list.slice((enqPage-1)*ENQ_PS, enqPage*ENQ_PS).map((e) => (
            <div key={e.id} data-testid={`enq-row-${e.id}`} className="bg-zinc-950 border border-zinc-800 p-4">
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                  <p className="font-display font-bold">{e.name} <span className="text-zinc-500 font-mono text-xs ml-2">{e.phone}</span></p>
                  {e.email && <p className="font-mono text-[11px] text-zinc-500">{e.email}</p>}
                  <p className="font-mono text-xs text-zinc-300 mt-1">
                    {(e.car_make || "—") + " " + (e.car_model || "")}
                    {e.service_interest && <span className="text-orange-500"> · {e.service_interest}</span>}
                  </p>
                  {e.message && <p className="text-sm text-zinc-400 mt-2 italic">"{e.message}"</p>}
                </div>
                <div className="flex flex-col items-end gap-2">
                  <span className={`font-mono text-[10px] uppercase tracking-widest px-2 py-0.5 border ${e.status === "new" ? "bg-orange-500/10 border-orange-500/40 text-orange-500" : e.status === "contacted" ? "bg-blue-500/10 border-blue-500/40 text-blue-400" : "bg-zinc-700/30 border-zinc-700 text-zinc-400"}`}>{e.status}</span>
                  <p className="font-mono text-[10px] text-zinc-500">{e.created_at ? new Date(e.created_at).toLocaleString() : ""}</p>
                </div>
              </div>
              <div className="flex items-center gap-2 mt-3 pt-3 border-t border-zinc-800">
                <a href={`tel:${e.phone}`} className="font-mono text-[10px] uppercase tracking-widest text-orange-500 hover:text-orange-400">→ Call</a>
                <span className="text-zinc-700">·</span>
                <a href={`https://wa.me/${(e.phone || "").replace(/[^0-9]/g, "")}`} target="_blank" rel="noopener noreferrer" className="font-mono text-[10px] uppercase tracking-widest text-emerald-500 hover:text-emerald-400">→ WhatsApp</a>
                <span className="flex-1" />
                {e.status !== "contacted" && <button data-testid={`enq-contacted-${e.id}`} onClick={() => setStatus(e.id, "contacted")} className="font-mono text-[10px] uppercase tracking-widest text-blue-400 hover:text-blue-300">Mark contacted</button>}
                {e.status !== "closed" && <button data-testid={`enq-close-${e.id}`} onClick={() => setStatus(e.id, "closed")} className="font-mono text-[10px] uppercase tracking-widest text-zinc-500 hover:text-zinc-300">Close</button>}
              </div>
            </div>
          ))}
        </div>
        {Math.ceil(list.length/ENQ_PS) > 1 && (
          <div className="flex items-center justify-between mt-4 pt-3 border-t border-zinc-800">
            <span className="font-mono text-[10px] text-zinc-500">Page {Math.min(enqPage,Math.ceil(list.length/ENQ_PS))} of {Math.ceil(list.length/ENQ_PS)}</span>
            <div className="flex gap-1">
              <button onClick={()=>setEnqPage(p=>Math.max(1,p-1))} disabled={enqPage<=1} className="p-1.5 border border-zinc-700 text-zinc-400 hover:text-white disabled:opacity-30"><ChevronLeft className="w-3.5 h-3.5"/></button>
              {Array.from({length:Math.ceil(list.length/ENQ_PS)},(_,i)=>i+1).map(n=>(
                <button key={n} onClick={()=>setEnqPage(n)} className={`px-2.5 py-1 font-mono text-[10px] border ${n===Math.min(enqPage,Math.ceil(list.length/ENQ_PS))?"bg-orange-500 border-orange-500 text-black font-bold":"border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}>{n}</button>
              ))}
              <button onClick={()=>setEnqPage(p=>Math.min(Math.ceil(list.length/ENQ_PS),p+1))} disabled={enqPage>=Math.ceil(list.length/ENQ_PS)} className="p-1.5 border border-zinc-700 text-zinc-400 hover:text-white disabled:opacity-30"><ChevronRight className="w-3.5 h-3.5"/></button>
            </div>
          </div>
        )}
        </>
      )}
    </div>
  );
};


const StaffTab = () => {
  const { user: me } = useAuth();
  const [list, setList] = useState([]);
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ name: "", phone: "", role: "mechanic", password: "" });
  const load = () => api.get("/admin/staff").then((r) => setList(r.data));
  useEffect(() => { load(); }, []);

  const create = async () => {
    if (!f.name || !f.phone) return toast.error("Name + phone required");
    if (f.password && f.password.length < 6) return toast.error("Password must be at least 6 characters");
    try {
      const r = await api.post("/admin/staff", f);
      toast.success(`Created ${f.name} — initial password: ${r.data.initial_password}`);
      load(); setOpen(false); setF({ name: "", phone: "", role: "mechanic", password: "" });
    } catch (e) { toast.error(e.response?.data?.detail || "Failed"); }
  };

  const remove = async (s) => {
    if (s.id === me?.id) return toast.error("You can't remove your own account");
    if (!window.confirm(`Remove ${s.name} (${s.role})? This cannot be undone.`)) return;
    try {
      await api.delete(`/admin/staff/${s.id}`);
      toast.success(`Removed ${s.name}`);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed"); }
  };

  const resetPwd = async (s) => {
    if (!window.confirm(`Reset password for ${s.name}? They will be forced to set a new one on next login.`)) return;
    try {
      const r = await api.post(`/admin/staff/${s.id}/reset-password`);
      toast.success(`New temp password for ${s.name}: ${r.data.initial_password}`);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed"); }
  };

  return (
    <div className="border border-zinc-800 bg-zinc-900/40 p-6">
      <div className="flex items-center justify-between mb-4">
        <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Employees · {list.length}</p>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <button data-testid="add-staff-btn" className="bg-orange-500 hover:bg-orange-400 text-black font-mono text-xs uppercase tracking-widest font-bold px-3 py-1.5 flex items-center gap-1"><Plus className="w-3 h-3" />Add Employee</button>
          </DialogTrigger>
          <DialogContent className="bg-zinc-950 border-zinc-800 space-y-2">
            <DialogHeader><DialogTitle className="font-display uppercase">Onboard new employee</DialogTitle></DialogHeader>
            <input data-testid="staff-name" placeholder="Full name" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
            <input data-testid="staff-phone" placeholder="Phone (e.g. 9876543210)" value={f.phone} onChange={(e) => setF({ ...f, phone: e.target.value })} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
            <select data-testid="staff-role" value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm">
              <option value="mechanic">Mechanic</option>
              <option value="reception">Reception</option>
              <option value="tester">Tester</option>
              <option value="shopkeeper">Shopkeeper</option>
              <option value="admin">Admin</option>
            </select>
            <input data-testid="staff-password" placeholder="Initial password (leave blank to auto-generate)"
              value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })}
              className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
            <p className="font-mono text-[10px] text-zinc-500">
              The employee signs in with their phone + this password. They will be forced to set a new password on first login.
              The initial password stays visible to you here until they change it. We also text it to them automatically.
            </p>
            <button data-testid="staff-submit" onClick={create} className="w-full bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest py-3">Create employee</button>
          </DialogContent>
        </Dialog>
      </div>
      <div className="space-y-2">
        {list.map((s) => (
          <div key={s.id} data-testid={`staff-row-${s.id}`} className="bg-zinc-950 border border-zinc-800 px-4 py-3 flex items-center justify-between gap-3">
            <div className="min-w-0">
              <p className="font-display font-bold truncate">{s.name} {s.id === me?.id && <span className="font-mono text-[10px] text-orange-500 ml-1">(you)</span>}</p>
              <p className="font-mono text-[10px] text-zinc-500 truncate">{s.phone || s.username} · {s.role}</p>
              {s.must_reset_password && s.initial_password && (
                <p className="font-mono text-[10px] text-orange-400 mt-1">
                  Initial password (share with employee): <span className="text-white font-bold">{s.initial_password}</span>
                </p>
              )}
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <span className={`font-mono text-[10px] uppercase tracking-widest px-2 py-0.5 border ${s.active === false ? "border-red-500/40 text-red-400" : "border-emerald-500/40 text-emerald-400"}`}>
                {s.active === false ? "Inactive" : "Active"}
              </span>
              <button
                data-testid={`reset-pwd-${s.id}`}
                onClick={() => resetPwd(s)}
                title="Reset password"
                className="text-zinc-500 hover:text-orange-500 font-mono text-[10px] uppercase tracking-widest border border-zinc-800 hover:border-orange-500 px-2 py-1"
              >Reset pwd</button>
              {s.id !== me?.id && (
                <button
                  data-testid={`remove-staff-${s.id}`}
                  onClick={() => remove(s)}
                  title={`Remove ${s.name}`}
                  className="text-red-400 hover:text-red-300 p-1.5 border border-zinc-800 hover:border-red-500"
                ><Trash className="w-3.5 h-3.5" /></button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};


const HRAdminTab = () => {
  const [pending, setPending] = useState([]);
  const [holidays, setHolidays] = useState([]);
  const [staff, setStaff] = useState([]);
  const [holForm, setHolForm] = useState({ date: "", name: "", type: "public" });
  const [bonusOpen, setBonusOpen] = useState(false);
  const [bonusForm, setBonusForm] = useState({ user_id: "", amount: "", reason: "", event_type: "bonus" });
  const [profOpen, setProfOpen] = useState(false);
  const [profForm, setProfForm] = useState({ user_id: "", monthly_salary: "", designation: "" });

  const load = async () => {
    const [l, h, s] = await Promise.all([
      api.get("/hr/leaves?status=pending"), api.get("/hr/holidays"), api.get("/admin/staff")
    ]);
    setPending(l.data); setHolidays(h.data); setStaff(s.data);
  };
  useEffect(() => { load(); }, []);

  const decide = async (id, decision) => {
    await api.patch(`/hr/leaves/${id}`, { decision, note: "" });
    toast.success(decision); load();
  };
  const addHol = async () => {
    if (!holForm.date || !holForm.name) return toast.error("Date + name");
    await api.post("/hr/holidays", holForm); toast.success("Holiday added");
    setHolForm({ date: "", name: "", type: "public" }); load();
  };
  const delHol = async (id) => { await api.delete(`/hr/holidays/${id}`); load(); };
  const submitBonus = async () => {
    if (!bonusForm.user_id || !bonusForm.amount) return toast.error("Pick employee + amount");
    await api.post("/hr/payroll/event", { ...bonusForm, amount: parseFloat(bonusForm.amount) });
    toast.success("Posted"); setBonusOpen(false);
    setBonusForm({ user_id: "", amount: "", reason: "", event_type: "bonus" });
  };
  const saveProf = async () => {
    if (!profForm.user_id) return;
    await api.patch(`/hr/profile/${profForm.user_id}`, {
      monthly_salary: parseFloat(profForm.monthly_salary) || 0,
      designation: profForm.designation,
      leave_balance: { casual: 12, earned: 15, sick: 8 }
    });
    toast.success("Profile saved"); setProfOpen(false);
    setProfForm({ user_id: "", monthly_salary: "", designation: "" });
  };

  return (
    <div className="space-y-6">
      <div className="grid lg:grid-cols-2 gap-6">
        <div className="border border-zinc-800 bg-zinc-900/40 p-6">
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mb-4">Pending leave approvals · {pending.length}</p>
          {pending.length === 0 && <p className="text-sm text-zinc-500">All caught up ✓</p>}
          <div className="space-y-2">
            {pending.map((l) => (
              <div key={l.id} data-testid={`pending-leave-${l.id}`} className="bg-zinc-950 border border-zinc-800 p-3">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <p className="font-display font-bold">{l.user_name} <span className="text-zinc-500 font-normal text-xs">· {l.user_role}</span></p>
                    <p className="font-mono text-xs text-zinc-400 capitalize">{l.leave_type} · {l.start_date} → {l.end_date}</p>
                    <p className="text-xs text-zinc-500 mt-1">{l.reason}</p>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button data-testid={`approve-${l.id}`} onClick={() => decide(l.id, "approved")} className="bg-emerald-500 hover:bg-emerald-400 text-black font-mono text-[10px] uppercase tracking-widest font-bold px-3 py-1.5">Approve</button>
                  <button data-testid={`reject-${l.id}`} onClick={() => decide(l.id, "rejected")} className="bg-red-500 hover:bg-red-400 text-white font-mono text-[10px] uppercase tracking-widest font-bold px-3 py-1.5">Reject</button>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="border border-zinc-800 bg-zinc-900/40 p-6">
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mb-4">Holidays</p>
          <div className="grid grid-cols-3 gap-2 mb-3">
            <input data-testid="hol-date" type="date" value={holForm.date} onChange={(e) => setHolForm({ ...holForm, date: e.target.value })} className="bg-zinc-900 border border-zinc-800 px-2 py-2 font-mono text-xs" />
            <input data-testid="hol-name" placeholder="Name" value={holForm.name} onChange={(e) => setHolForm({ ...holForm, name: e.target.value })} className="bg-zinc-900 border border-zinc-800 px-2 py-2 font-mono text-xs" />
            <button data-testid="hol-add" onClick={addHol} className="bg-orange-500 hover:bg-orange-400 text-black font-mono text-[10px] uppercase tracking-widest font-bold">Add</button>
          </div>
          <div className="space-y-1">
            {holidays.map((h) => (
              <div key={h.id} className="bg-zinc-950 border border-zinc-800 p-2 flex items-center justify-between text-sm">
                <span><span className="font-mono text-xs text-orange-500">{h.date}</span> · {h.name}</span>
                <button onClick={() => delHol(h.id)} className="text-red-400 hover:text-red-300 font-mono text-[10px] uppercase">delete</button>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="border border-zinc-800 bg-zinc-900/40 p-6">
        <div className="flex items-center justify-between mb-4">
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500">Salary & bonus actions</p>
          <div className="flex gap-2">
            <Dialog open={profOpen} onOpenChange={setProfOpen}>
              <DialogTrigger asChild><button data-testid="set-salary-btn" className="border border-zinc-700 hover:border-orange-500 hover:text-orange-500 text-zinc-300 font-mono text-[10px] uppercase tracking-widest px-3 py-1.5">Set Salary</button></DialogTrigger>
              <DialogContent className="bg-zinc-950 border-zinc-800">
                <DialogHeader><DialogTitle className="font-display uppercase">Edit employee profile</DialogTitle></DialogHeader>
                <select value={profForm.user_id} onChange={(e) => setProfForm({ ...profForm, user_id: e.target.value })} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm">
                  <option value="">Select employee</option>
                  {staff.filter((s) => s.role !== "admin").map((s) => <option key={s.id} value={s.id}>{s.name} · {s.role}</option>)}
                </select>
                <input placeholder="Monthly salary (₹)" type="number" value={profForm.monthly_salary} onChange={(e) => setProfForm({ ...profForm, monthly_salary: e.target.value })} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
                <input placeholder="Designation" value={profForm.designation} onChange={(e) => setProfForm({ ...profForm, designation: e.target.value })} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
                <button onClick={saveProf} className="w-full bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest py-3">Save</button>
              </DialogContent>
            </Dialog>
            <Dialog open={bonusOpen} onOpenChange={setBonusOpen}>
              <DialogTrigger asChild><button data-testid="award-bonus-btn" className="bg-emerald-500 hover:bg-emerald-400 text-black font-mono text-[10px] uppercase tracking-widest font-bold px-3 py-1.5">+ Bonus / Payroll</button></DialogTrigger>
              <DialogContent className="bg-zinc-950 border-zinc-800">
                <DialogHeader><DialogTitle className="font-display uppercase">Post payroll event</DialogTitle></DialogHeader>
                <select data-testid="bonus-user" value={bonusForm.user_id} onChange={(e) => setBonusForm({ ...bonusForm, user_id: e.target.value })} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm">
                  <option value="">Select employee</option>
                  {staff.filter((s) => s.role !== "admin").map((s) => <option key={s.id} value={s.id}>{s.name} · {s.role}</option>)}
                </select>
                <select data-testid="bonus-type" value={bonusForm.event_type} onChange={(e) => setBonusForm({ ...bonusForm, event_type: e.target.value })} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm">
                  <option value="bonus">Bonus</option>
                  <option value="extra_work">Extra Work</option>
                  <option value="salary_credited">Salary Credited</option>
                </select>
                <input data-testid="bonus-amount" type="number" placeholder="Amount (₹)" value={bonusForm.amount} onChange={(e) => setBonusForm({ ...bonusForm, amount: e.target.value })} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
                <input data-testid="bonus-reason" placeholder="Reason / note" value={bonusForm.reason} onChange={(e) => setBonusForm({ ...bonusForm, reason: e.target.value })} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
                <button data-testid="bonus-submit" onClick={submitBonus} className="w-full bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest py-3">Post Event</button>
              </DialogContent>
            </Dialog>
          </div>
        </div>
        <p className="text-xs text-zinc-500">Use these actions to set monthly salary, post bonus, mark extra-work, or record salary credited. Employee gets an in-app notification + WebSocket push.</p>
      </div>
    </div>
  );
};



// ---------- Transactions tab (Paytm-style unified history) ----------

const ServicesTab = () => {
  const [services, setServices] = useState([]);
  const [form, setForm] = useState({ key: "", name: "", duration_min: 60, base_price: 800, active: true });
  const [editing, setEditing] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const r = await api.get("/services");
    setServices(r.data);
  };
  useEffect(() => { load(); }, []);

  const fmtDuration = (min) => {
    if (!min) return "—";
    const h = Math.floor(min / 60), m = min % 60;
    return h > 0 ? `${h}h${m > 0 ? " " + m + "m" : ""}` : `${m}m`;
  };

  const submit = async (e) => {
    e.preventDefault(); setBusy(true);
    try {
      if (editing) {
        await api.patch(`/services/${editing.id}`, { name: form.name, duration_min: parseInt(form.duration_min), base_price: parseFloat(form.base_price), active: form.active });
        toast.success("Service updated");
      } else {
        await api.post("/services", { ...form, duration_min: parseInt(form.duration_min), base_price: parseFloat(form.base_price) });
        toast.success("Service created");
      }
      setEditing(null); setForm({ key: "", name: "", duration_min: 60, base_price: 800, active: true });
      load();
    } catch (err) { toast.error(err.response?.data?.detail || "Failed"); }
    finally { setBusy(false); }
  };

  const startEdit = (s) => {
    setEditing(s);
    setForm({ key: s.key, name: s.name, duration_min: s.duration_min, base_price: s.base_price, active: s.active });
  };

  const deleteService = async (id) => {
    if (!window.confirm("Delete this service?")) return;
    await api.delete(`/services/${id}`);
    toast.success("Deleted");
    load();
  };

  const toggleActive = async (s) => {
    await api.patch(`/services/${s.id}`, { active: !s.active });
    load();
  };

  return (
    <div className="grid lg:grid-cols-3 gap-6">
      {/* Form */}
      <div className="border border-zinc-800 bg-zinc-900/40 p-6">
        <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mb-1">{editing ? "Edit service" : "Add service"}</p>
        <form onSubmit={submit} className="space-y-3 mt-3">
          {!editing && (
            <input required placeholder="Key (e.g. oil-change)" value={form.key} onChange={(e) => setForm(f => ({ ...f, key: e.target.value.toLowerCase().replace(/\s+/g, "-") }))}
              className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2 font-mono text-sm text-zinc-100 focus:border-orange-500 outline-none" />
          )}
          <input required placeholder="Display name (e.g. Oil & Filter Change)" value={form.name} onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))}
            className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2 font-mono text-sm text-zinc-100 focus:border-orange-500 outline-none" />
          <div className="flex gap-2">
            <div className="flex-1">
              <label className="font-mono text-[10px] text-zinc-500 block mb-1">Duration (min)</label>
              <input required type="number" min="1" value={form.duration_min} onChange={(e) => setForm(f => ({ ...f, duration_min: e.target.value }))}
                className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2 font-mono text-sm text-zinc-100 focus:border-orange-500 outline-none" />
            </div>
            <div className="flex-1">
              <label className="font-mono text-[10px] text-zinc-500 block mb-1">Base price (₹)</label>
              <input required type="number" min="0" step="0.01" value={form.base_price} onChange={(e) => setForm(f => ({ ...f, base_price: e.target.value }))}
                className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2 font-mono text-sm text-zinc-100 focus:border-orange-500 outline-none" />
            </div>
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={form.active} onChange={(e) => setForm(f => ({ ...f, active: e.target.checked }))} className="accent-orange-500" />
            <span className="font-mono text-xs text-zinc-400">Active (visible in booking)</span>
          </label>
          <div className="flex gap-2">
            <button type="submit" disabled={busy} className="flex-1 bg-orange-500 hover:bg-orange-400 disabled:opacity-50 text-black font-mono text-xs uppercase tracking-widest font-bold py-2">
              {busy ? "Saving..." : editing ? "Update" : "Add Service"}
            </button>
            {editing && (
              <button type="button" onClick={() => { setEditing(null); setForm({ key: "", name: "", duration_min: 60, base_price: 800, active: true }); }}
                className="px-4 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 font-mono text-xs">Cancel</button>
            )}
          </div>
        </form>
      </div>

      {/* List */}
      <div className="lg:col-span-2 border border-zinc-800 bg-zinc-900/40 p-6">
        <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-4">Garage Services ({services.length})</p>
        <div className="space-y-2">
          {services.map((s) => (
            <div key={s.id} className={`flex items-center justify-between border px-4 py-3 ${s.active ? "border-zinc-800 bg-zinc-950" : "border-zinc-800/40 bg-zinc-950/40 opacity-60"}`}>
              <div>
                <p className="font-bold text-sm">{s.name}</p>
                <p className="font-mono text-[10px] text-zinc-500">{s.key} · {fmtDuration(s.duration_min)} · ₹{s.base_price}</p>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => toggleActive(s)} className={`font-mono text-[10px] uppercase tracking-widest px-2 py-1 border ${s.active ? "border-green-700 text-green-400 hover:bg-green-900/20" : "border-zinc-700 text-zinc-500 hover:bg-zinc-800"}`}>
                  {s.active ? "Active" : "Inactive"}
                </button>
                <button onClick={() => startEdit(s)} className="p-1.5 hover:bg-zinc-800 rounded text-zinc-400 hover:text-orange-400">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                </button>
                <button onClick={() => deleteService(s.id)} className="p-1.5 hover:bg-zinc-800 rounded text-zinc-400 hover:text-red-400">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

const TransactionsTab = () => {
  const [type, setType] = useState("all");
  const [q, setQ] = useState("");
  const [period, setPeriod] = useState(""); // today | week | month | custom | ""
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [data, setData] = useState({ transactions: [], total_amount: 0, count: 0, service_count: 0, shop_count: 0, refund_count: 0, refund_amount: 0 });
  const [loading, setLoading] = useState(false);
  const [sel, setSel] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      let url = `/admin/transactions?type=${type}&q=${encodeURIComponent(q)}`;
      if (period && period !== "custom") url += `&period=${period}`;
      if (period === "custom" && dateFrom) url += `&date_from=${dateFrom}`;
      if (period === "custom" && dateTo) url += `&date_to=${dateTo}`;
      const r = await api.get(url);
      setData(r.data);
    } catch (e) { toast.error("Failed to load transactions"); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [type, period]);

  const fmtTime = (s) => {
    if (!s) return "—";
    const d = new Date(s);
    return d.toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" });
  };
  const groupByDate = () => {
    const groups = {};
    (data.transactions || []).forEach((t) => {
      const k = (t.ts || "").slice(0, 10) || "Unknown";
      if (!groups[k]) groups[k] = [];
      groups[k].push(t);
    });
    return Object.entries(groups);
  };

  return (
    <div className="space-y-4">
      {/* Header summary */}
      <div className="border border-zinc-800 bg-zinc-900/40 p-6">
        <div className="flex flex-wrap items-end justify-between gap-3 mb-4">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Net revenue (after refunds)</p>
            <p className="font-display font-black text-3xl text-orange-500">₹{Math.round(data.total_amount || 0).toLocaleString("en-IN")}</p>
            <p className="font-mono text-[10px] text-zinc-500">
              {data.count} txns · {data.service_count} service · {data.shop_count} shop
              {data.refund_count > 0 && (
                <span className="text-red-400"> · {data.refund_count} refunds (−₹{Math.round(data.refund_amount || 0).toLocaleString("en-IN")})</span>
              )}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex bg-zinc-950 border border-zinc-800">
              {[["all", "All"], ["service", "Services"], ["shop", "Shop"]].map(([v, lbl]) => (
                <button
                  key={v}
                  data-testid={`txn-filter-${v}`}
                  onClick={() => setType(v)}
                  className={`px-4 py-2 font-mono text-[10px] uppercase tracking-widest font-bold transition-colors ${type === v ? "bg-orange-500 text-black" : "text-zinc-400 hover:text-orange-500"}`}
                >{lbl}</button>
              ))}
            </div>
            {/* Date period filters */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex bg-zinc-950 border border-zinc-800">
                {[["", "All Time"], ["today", "Today"], ["week", "7 Days"], ["month", "30 Days"], ["custom", "Custom"]].map(([v, lbl]) => (
                  <button key={v} onClick={() => { setPeriod(v); if (v !== "custom") { setDateFrom(""); setDateTo(""); }}}
                    className={`px-3 py-1.5 font-mono text-[10px] uppercase tracking-widest font-bold transition-colors ${period === v ? "bg-orange-500 text-black" : "text-zinc-400 hover:text-orange-500"}`}
                  >{lbl}</button>
                ))}
              </div>
              {period === "custom" && (
                <div className="flex items-center gap-1">
                  <input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)}
                    className="bg-zinc-950 border border-zinc-800 px-2 py-1.5 font-mono text-xs text-zinc-100 focus:border-orange-500 outline-none" />
                  <span className="text-zinc-500 text-xs">→</span>
                  <input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)}
                    className="bg-zinc-950 border border-zinc-800 px-2 py-1.5 font-mono text-xs text-zinc-100 focus:border-orange-500 outline-none" />
                  <button onClick={load} className="bg-orange-500 hover:bg-orange-400 text-black font-mono text-[10px] uppercase tracking-widest font-bold px-2 py-1.5">Go</button>
                </div>
              )}
            </div>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500" />
              <input
                data-testid="txn-search"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") load(); }}
                placeholder="Customer, plate, item…"
                className="bg-zinc-950 border border-zinc-800 pl-9 pr-3 py-2 font-mono text-xs focus:border-orange-500 outline-none w-64"
              />
            </div>
            <button data-testid="txn-search-btn" onClick={load} className="bg-orange-500 hover:bg-orange-400 text-black font-mono text-[10px] uppercase tracking-widest font-bold px-3 py-2">Search</button>
          </div>
        </div>

        {loading && <p className="text-sm text-zinc-500">Loading…</p>}
        {!loading && data.transactions.length === 0 && (
          <p className="text-sm text-zinc-500">No transactions match the filter.</p>
        )}

        {/* Paytm-style date-grouped list */}
        <div className="space-y-5">
          {groupByDate().map(([date, items]) => (
            <div key={date}>
              <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500 mb-2 px-1">
                {date === "Unknown" ? "Unknown" : new Date(date).toLocaleDateString("en-IN", { weekday: "short", day: "numeric", month: "short", year: "numeric" })}
              </p>
              <div className="divide-y divide-zinc-800 border border-zinc-800 bg-zinc-950">
                {items.map((t) => (
                  <button
                    key={`${t.kind}-${t.id}`}
                    data-testid={`txn-${t.kind}-${t.id}`}
                    onClick={() => setSel(t)}
                    className="w-full text-left px-4 py-3 hover:bg-zinc-900 transition-colors flex items-center gap-4"
                  >
                    <div className={`w-10 h-10 flex items-center justify-center ${
                      t.kind === "service" ? "bg-orange-500/10 text-orange-500" :
                      t.kind === "refund" ? "bg-red-500/10 text-red-400" :
                      "bg-blue-500/10 text-blue-400"
                    }`}>
                      {t.kind === "service" ? <WrenchIcon className="w-4 h-4" /> :
                       t.kind === "refund" ? <Undo2 className="w-4 h-4" /> :
                       <ShoppingCart className="w-4 h-4" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-display font-bold truncate">{t.customer_name}</p>
                      <p className="font-mono text-[10px] text-zinc-500 truncate uppercase">
                        {t.kind} · {t.title}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className={`font-display font-black ${t.amount < 0 ? "text-red-400" : "text-emerald-400"}`}>
                        {t.amount < 0 ? "− " : "+ "}₹{Math.abs(Math.round(t.amount)).toLocaleString("en-IN")}
                      </p>
                      <p className="font-mono text-[10px] text-zinc-500">{fmtTime(t.ts).split(", ").pop()} · {t.method}</p>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Detail dialog */}
      <Dialog open={!!sel} onOpenChange={(v) => { if (!v) setSel(null); }}>
        <DialogContent className="bg-zinc-950 border-zinc-800 max-w-lg">
          <DialogHeader>
            <DialogTitle className="font-display uppercase flex items-center gap-2">
              {sel?.kind === "service" ? <WrenchIcon className="w-4 h-4 text-orange-500" /> : <ShoppingCart className="w-4 h-4 text-blue-400" />}
              Transaction · #{sel?.ref}
            </DialogTitle>
          </DialogHeader>
          {sel && (
            <div className="space-y-3 text-sm">
              <div className="bg-zinc-900 border border-zinc-800 p-4">
                <p className={`font-display font-black text-3xl ${sel.amount < 0 ? "text-red-400" : "text-emerald-400"}`}>
                  {sel.amount < 0 ? "− " : ""}₹{Math.abs(Math.round(sel.amount)).toLocaleString("en-IN")}
                </p>
                <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500 mt-1">{sel.method} · {fmtTime(sel.ts)}</p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">Customer</p>
                  <p className="font-bold">{sel.customer_name}</p>
                  <p className="font-mono text-[10px] text-zinc-500">{sel.customer_phone || "—"}</p>
                </div>
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">Type</p>
                  <p className="font-bold uppercase">{sel.kind}</p>
                  <p className="font-mono text-[10px] text-zinc-500">{sel.title}</p>
                </div>
              </div>
              {sel.kind === "service" && sel.extra && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">Mechanic</p>
                    <p className="text-sm">{sel.extra.mechanic}</p>
                  </div>
                  <div>
                    <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">Bay</p>
                    <p className="text-sm">{sel.extra.bay}</p>
                  </div>
                </div>
              )}
              {sel.kind === "shop" && sel.extra?.refund_status && (
                <div className="bg-yellow-500/10 border border-yellow-500/30 p-2">
                  <p className="font-mono text-[10px] uppercase tracking-widest text-yellow-400">
                    Refund {sel.extra.refund_status}
                    {sel.extra.refunded_amount ? ` · ₹${Math.round(sel.extra.refunded_amount)}` : ""}
                  </p>
                </div>
              )}
              {sel.items?.length > 0 && (
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500 mb-1">Items ({sel.items.length})</p>
                  <ul className="bg-zinc-900 border border-zinc-800 divide-y divide-zinc-800 text-xs">
                    {sel.items.map((it, i) => (
                      <li key={i} className="flex items-center justify-between px-3 py-2">
                        <span>{it.name} <span className="text-zinc-500">× {it.qty}</span></span>
                        <span className="font-bold">₹{Math.round(it.subtotal || it.price * it.qty)}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {sel.invoice_url && (
                <a href={sel.invoice_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest px-4 py-2 text-xs">
                  <ReceiptText className="w-3.5 h-3.5" /> Open invoice <ExternalLink className="w-3 h-3" />
                </a>
              )}
              {sel.extra?.razorpay_payment_id && (
                <p className="font-mono text-[10px] text-zinc-500">Razorpay ref: {sel.extra.razorpay_payment_id}</p>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};

// ---------- Refunds tab (admin approval queue) ----------
const RefundsTab = ({ onChange }) => {
  const [list, setList] = useState([]);
  const [filter, setFilter] = useState("PENDING");
  const [decideOn, setDecideOn] = useState(null); // {refund, decision}
  const [note, setNote] = useState("");

  const load = async () => {
    try {
      const r = await api.get(`/admin/refunds${filter !== "ALL" ? `?status=${filter}` : ""}`);
      setList(r.data);
    } catch (e) { toast.error("Failed to load refunds"); }
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [filter]);

  const submit = async () => {
    if (!decideOn) return;
    try {
      await api.post(`/admin/refunds/${decideOn.refund.id}/decision`, { decision: decideOn.decision, note });
      toast.success(`Refund ${decideOn.decision}`);
      setDecideOn(null); setNote("");
      load();
      if (onChange) onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed"); }
  };

  const badge = (status) => {
    const map = {
      PENDING: "bg-yellow-500/10 border-yellow-500/30 text-yellow-400",
      APPROVED: "bg-emerald-500/10 border-emerald-500/30 text-emerald-400",
      REJECTED: "bg-zinc-700 text-zinc-400 border-zinc-600",
    };
    return <span className={`font-mono text-[10px] uppercase tracking-widest px-2 py-0.5 border ${map[status]}`}>{status}</span>;
  };

  return (
    <div className="border border-zinc-800 bg-zinc-900/40 p-6">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
        <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">Refund requests · {list.length}</p>
        <div className="flex bg-zinc-950 border border-zinc-800">
          {["PENDING", "APPROVED", "REJECTED", "ALL"].map((f) => (
            <button
              key={f}
              data-testid={`refund-filter-${f}`}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 font-mono text-[10px] uppercase tracking-widest font-bold ${filter === f ? "bg-orange-500 text-black" : "text-zinc-400 hover:text-orange-500"}`}
            >{f}</button>
          ))}
        </div>
      </div>

      {list.length === 0 && <p className="text-sm text-zinc-500">No refund requests in this view.</p>}

      <div className="space-y-2">
        {list.map((r) => (
          <div key={r.id} data-testid={`refund-row-${r.id}`} className="bg-zinc-950 border border-zinc-800 p-4">
            <div className="flex items-center justify-between flex-wrap gap-2 mb-2">
              <div>
                <p className="font-display font-bold">
                  ₹{Math.round(r.amount)} · {r.customer_name || "Walk-in"}
                  <span className="ml-2">{badge(r.status)}</span>
                </p>
                <p className="font-mono text-[10px] text-zinc-500">
                  Sale #{r.sale_id.slice(0, 8)} · raised by {r.raised_by_name} · {new Date(r.raised_at).toLocaleString()}
                </p>
              </div>
              {r.status === "PENDING" ? (
                <div className="flex gap-2">
                  <button data-testid={`refund-approve-${r.id}`} onClick={() => { setDecideOn({ refund: r, decision: "approved" }); setNote(""); }} className="bg-emerald-500 hover:bg-emerald-400 text-black font-mono text-[10px] uppercase tracking-widest font-bold px-3 py-1.5 flex items-center gap-1"><Check className="w-3 h-3" /> Approve</button>
                  <button data-testid={`refund-reject-${r.id}`} onClick={() => { setDecideOn({ refund: r, decision: "rejected" }); setNote(""); }} className="border border-red-500/50 hover:bg-red-500/10 text-red-400 font-mono text-[10px] uppercase tracking-widest font-bold px-3 py-1.5 flex items-center gap-1"><XIcon className="w-3 h-3" /> Reject</button>
                </div>
              ) : (
                r.decided_by_name && (
                  <p className="font-mono text-[10px] text-zinc-500">
                    by {r.decided_by_name} · {new Date(r.decided_at).toLocaleString()}
                  </p>
                )
              )}
            </div>
            <p className="text-xs text-zinc-300 italic mb-2">"{r.reason}"</p>
            {r.decision_note && <p className="text-xs text-zinc-400">Admin note: {r.decision_note}</p>}
            <div className="bg-zinc-900 border border-zinc-800 mt-2">
              {(r.items || []).map((it, idx) => (
                <div key={idx} className="flex items-center justify-between px-3 py-1.5 text-xs border-b border-zinc-800 last:border-0">
                  <span>{it.name} <span className="text-zinc-500">({it.sku})</span> × {it.qty}</span>
                  <span className="font-bold">₹{Math.round(it.subtotal || it.price * it.qty)}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      <Dialog open={!!decideOn} onOpenChange={(v) => { if (!v) { setDecideOn(null); setNote(""); } }}>
        <DialogContent className="bg-zinc-950 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="font-display uppercase flex items-center gap-2">
              <Undo2 className="w-4 h-4 text-orange-500" />
              {decideOn?.decision === "approved" ? "Approve refund" : "Reject refund"}
            </DialogTitle>
          </DialogHeader>
          {decideOn && (
            <div className="space-y-3">
              <div className="bg-zinc-900 border border-zinc-800 p-3">
                <p className="font-display font-bold">₹{Math.round(decideOn.refund.amount)} · {decideOn.refund.customer_name || "Walk-in"}</p>
                <p className="font-mono text-[10px] text-zinc-500">Reason: "{decideOn.refund.reason}"</p>
              </div>
              <textarea data-testid="refund-decision-note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Internal note (optional)" rows={3} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm focus:border-orange-500 outline-none" />
              {decideOn.decision === "approved" && (
                <p className="text-xs text-emerald-400">Approving will restock the items and mark the sale as refunded.</p>
              )}
              <div className="flex gap-2">
                <button onClick={() => setDecideOn(null)} className="flex-1 border border-zinc-700 text-zinc-300 font-mono text-xs uppercase tracking-widest py-2.5">Cancel</button>
                <button
                  data-testid="refund-decision-submit"
                  onClick={submit}
                  className={`flex-1 font-display font-black uppercase tracking-widest py-2.5 ${decideOn.decision === "approved" ? "bg-emerald-500 hover:bg-emerald-400 text-black" : "bg-red-500 hover:bg-red-400 text-white"}`}
                >Confirm</button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};
