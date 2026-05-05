import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useGarageWS } from "../hooks/useWebSocket";
import api from "../lib/api";
import { NotificationBell } from "../components/NotificationBell";
import { LogOut, Wrench, Calendar as CalIcon, Clock, IndianRupee, Plus, ArrowRight } from "lucide-react";
import MacJitLogo from "../components/MacJitLogo";
import { toast } from "sonner";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "../components/ui/dialog";
import { Calendar } from "../components/ui/calendar";

export default function EmployeePage() {
  const { user, token, logout } = useAuth();
  const [profile, setProfile] = useState(null);
  const [leaves, setLeaves] = useState([]);
  const [attendance, setAttendance] = useState([]);
  const [holidays, setHolidays] = useState([]);
  const [tick, setTick] = useState(0);

  const load = async () => {
    const [p, l, a, h] = await Promise.all([
      api.get("/hr/profile/me"), api.get("/hr/leaves/me"),
      api.get("/hr/attendance/me"), api.get("/hr/holidays")
    ]);
    setProfile(p.data); setLeaves(l.data); setAttendance(a.data); setHolidays(h.data);
  };
  useEffect(() => { load(); }, []);
  useGarageWS(token, (e) => {
    if (e.type === "connected") return;
    if (e.type.startsWith("LEAVE_") || e.type.startsWith("PAYROLL_")) {
      toast(e.type.replace(/_/g, " "));
      load(); setTick((t) => t + 1);
    }
  });

  const punch = async () => { await api.post("/hr/attendance/punch"); toast.success("Punched"); load(); };
  const today = new Date().toISOString().slice(0, 10);
  const todayPunch = attendance.find((a) => a.date === today);

  return (
    <div className="dark min-h-screen bg-zinc-950 text-zinc-100">
      <header className="sticky top-0 z-20 bg-zinc-950/90 backdrop-blur-xl border-b border-zinc-800">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <MacJitLogo size={32} />
            <div>
              <p className="font-display font-black text-lg tracking-tighter">MACJIT <span className="text-orange-500">/ EMPLOYEE</span></p>
              <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">{user?.name} · {user?.role}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <a href={`/${user?.role}`} className="border border-zinc-800 hover:border-orange-500 hover:text-orange-500 text-zinc-300 font-mono text-[10px] uppercase tracking-widest px-3 py-2 transition-colors flex items-center gap-1">Operations <ArrowRight className="w-3 h-3" /></a>
            <NotificationBell refreshKey={tick} />
            <button data-testid="logout-btn" onClick={logout} className="p-2 hover:bg-zinc-800 rounded-full"><LogOut className="w-4 h-4" /></button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-6">
        {profile && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-zinc-800">
            <div data-testid="emp-stat-salary" className="bg-zinc-950 p-5 border-orange-600/40 border">
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">Monthly salary</p>
              <p className="font-display font-black text-3xl text-orange-500 mt-1">{profile.profile?.monthly_salary ? `₹${profile.profile.monthly_salary}` : "—"}</p>
              <p className="font-mono text-xs text-zinc-400 mt-1">{profile.profile?.designation || "Designation TBD"}</p>
            </div>
            <div data-testid="emp-stat-attendance" className="bg-zinc-950 p-5">
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">Today</p>
              <p className="font-display font-black text-3xl text-white mt-1">{todayPunch ? (todayPunch.punch_out ? "Out" : "In") : "—"}</p>
              <button data-testid="punch-btn" onClick={punch} className="mt-2 bg-orange-500 hover:bg-orange-400 text-black font-mono text-[10px] uppercase tracking-widest px-3 py-1.5">Punch {todayPunch && !todayPunch.punch_out ? "Out" : "In"}</button>
            </div>
            <div className="bg-zinc-950 p-5">
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">Leaves used</p>
              <p className="font-display font-black text-3xl text-white mt-1">{Object.values(profile.leave_used || {}).reduce((a, b) => a + b, 0)}</p>
              <p className="font-mono text-xs text-zinc-400 mt-1">days this year</p>
            </div>
            <div className="bg-zinc-950 p-5">
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">Casual + Earned</p>
              <p className="font-display font-black text-3xl text-emerald-400 mt-1">{(profile.leave_balance?.casual || 0) + (profile.leave_balance?.earned || 0)}</p>
              <p className="font-mono text-xs text-zinc-400 mt-1">balance left</p>
            </div>
          </div>
        )}

        <Tabs defaultValue="leaves">
          <TabsList className="bg-zinc-900 border border-zinc-800 rounded-none p-0">
            <TabsTrigger data-testid="emp-tab-leaves" value="leaves" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Leaves</TabsTrigger>
            <TabsTrigger data-testid="emp-tab-attendance" value="attendance" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Attendance</TabsTrigger>
            <TabsTrigger data-testid="emp-tab-holidays" value="holidays" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Holidays</TabsTrigger>
            <TabsTrigger data-testid="emp-tab-payroll" value="payroll" className="rounded-none data-[state=active]:bg-orange-500 data-[state=active]:text-black font-mono text-xs uppercase tracking-widest">Payroll</TabsTrigger>
          </TabsList>

          <TabsContent value="leaves" className="mt-6">
            <div className="grid lg:grid-cols-3 gap-6">
              <ApplyLeaveCard onDone={load} balance={profile?.leave_balance} />
              <div className="lg:col-span-2 border border-zinc-800 bg-zinc-900/40 p-6">
                <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-4">My leave applications</p>
                {leaves.length === 0 && <p className="text-sm text-zinc-500">No applications yet</p>}
                <div className="space-y-2">
                  {leaves.map((l) => (
                    <div key={l.id} data-testid={`leave-${l.id}`} className="bg-zinc-950 border border-zinc-800 p-3 flex items-center justify-between">
                      <div>
                        <p className="font-display font-bold capitalize">{l.leave_type} · {l.start_date} → {l.end_date}</p>
                        <p className="font-mono text-xs text-zinc-500">{l.reason}{l.decision_note ? ` · note: ${l.decision_note}` : ""}</p>
                      </div>
                      <span className={`font-mono text-[10px] uppercase tracking-widest px-2 py-1 ${
                        l.status === "APPROVED" ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400" :
                        l.status === "REJECTED" ? "bg-red-500/10 border border-red-500/30 text-red-400" :
                        "bg-orange-600/10 border border-orange-600/30 text-orange-500"
                      }`}>{l.status}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="attendance" className="mt-6">
            <div className="border border-zinc-800 bg-zinc-900/40 p-6">
              <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-4">Last 60 days</p>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {attendance.map((a) => (
                  <div key={a.id} className="bg-zinc-950 border border-zinc-800 p-3">
                    <p className="font-mono text-xs font-bold">{a.date}</p>
                    <p className="font-mono text-[10px] text-zinc-500">In {a.punch_in ? a.punch_in.slice(11, 16) : "—"} · Out {a.punch_out ? a.punch_out.slice(11, 16) : "—"}</p>
                  </div>
                ))}
                {attendance.length === 0 && <p className="text-sm text-zinc-500">No records</p>}
              </div>
            </div>
          </TabsContent>

          <TabsContent value="holidays" className="mt-6">
            <div className="grid md:grid-cols-2 gap-6">
              <div className="border border-zinc-800 bg-zinc-900/40 p-6">
                <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-4">Calendar</p>
                <Calendar
                  mode="multiple"
                  selected={holidays.map((h) => new Date(h.date))}
                  modifiers={{ holiday: holidays.map((h) => new Date(h.date)) }}
                  modifiersClassNames={{ holiday: "bg-orange-500/30 text-yellow-100 font-bold" }}
                  className="rounded-md border-0"
                />
              </div>
              <div className="border border-zinc-800 bg-zinc-900/40 p-6">
                <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-4">Upcoming</p>
                <div className="space-y-2">
                  {holidays.length === 0 && <p className="text-sm text-zinc-500">No holidays defined yet</p>}
                  {holidays.map((h) => (
                    <div key={h.id} className="bg-zinc-950 border border-zinc-800 p-3 flex items-center gap-3">
                      <CalIcon className="w-4 h-4 text-orange-500" />
                      <div>
                        <p className="font-bold">{h.name}</p>
                        <p className="font-mono text-[10px] text-zinc-500">{h.date} · {h.type}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="payroll" className="mt-6">
            <div className="border border-zinc-800 bg-zinc-900/40 p-6">
              <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500 mb-4">Salary · bonus · extra-work history</p>
              {(!profile?.timeline || profile.timeline.length === 0) && <p className="text-sm text-zinc-500">No payroll events yet</p>}
              <div className="space-y-2">
                {profile?.timeline?.map((p) => (
                  <div key={p.id} className="bg-zinc-950 border border-zinc-800 p-4 flex items-center justify-between">
                    <div>
                      <p className="font-mono text-[10px] uppercase tracking-widest text-orange-500">{p.event_type.replace("_", " ")}</p>
                      <p className="font-display font-bold">{p.reason}</p>
                      <p className="font-mono text-[10px] text-zinc-500">{new Date(p.ts).toLocaleString()} · by {p.by}</p>
                    </div>
                    <div className="flex items-center gap-1 font-display font-black text-2xl text-emerald-400">
                      <IndianRupee className="w-5 h-5" />{p.amount}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}

const ApplyLeaveCard = ({ onDone, balance }) => {
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ leave_type: "casual", start_date: "", end_date: "", reason: "" });
  const submit = async () => {
    if (!f.start_date || !f.end_date) return toast.error("Pick dates");
    try { await api.post("/hr/leaves", f); toast.success("Submitted"); onDone(); setOpen(false); setF({ leave_type: "casual", start_date: "", end_date: "", reason: "" }); }
    catch (e) { toast.error("Failed"); }
  };
  return (
    <div className="border border-zinc-800 bg-zinc-900/40 p-6">
      <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mb-1">+ Apply</p>
      <h3 className="font-display font-black text-xl uppercase mb-4">Leave Request</h3>
      {balance && (
        <div className="grid grid-cols-3 gap-2 mb-4">
          {Object.entries(balance).map(([k, v]) => (
            <div key={k} className="bg-zinc-950 border border-zinc-800 p-2 text-center">
              <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">{k}</p>
              <p className="font-display font-black text-lg">{v}</p>
            </div>
          ))}
        </div>
      )}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogTrigger asChild>
          <button data-testid="apply-leave-btn" className="w-full bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest py-3 flex items-center justify-center gap-2"><Plus className="w-4 h-4" />Apply for Leave</button>
        </DialogTrigger>
        <DialogContent className="bg-zinc-950 border-zinc-800">
          <DialogHeader><DialogTitle className="font-display uppercase">New leave request</DialogTitle></DialogHeader>
          <select data-testid="leave-type" value={f.leave_type} onChange={(e) => setF({ ...f, leave_type: e.target.value })} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm">
            <option value="casual">Casual</option>
            <option value="earned">Earned</option>
            <option value="sick">Sick</option>
            <option value="unpaid">Unpaid</option>
          </select>
          <div className="grid grid-cols-2 gap-2">
            <input data-testid="leave-start" type="date" value={f.start_date} onChange={(e) => setF({ ...f, start_date: e.target.value })} className="bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
            <input data-testid="leave-end" type="date" value={f.end_date} onChange={(e) => setF({ ...f, end_date: e.target.value })} className="bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
          </div>
          <textarea data-testid="leave-reason" value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })} placeholder="Reason" rows={3} className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 font-mono text-sm" />
          <button data-testid="leave-submit" onClick={submit} className="w-full bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest py-3">Submit</button>
        </DialogContent>
      </Dialog>
    </div>
  );
};
