import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { Zap, Phone, Lock, ArrowLeft, KeyRound, Wrench, Gauge, ShieldCheck, ArrowRight } from "lucide-react";
import MacJitLogo from "../components/MacJitLogo";
import { toast } from "sonner";

/**
 * Terminal login only (phone + password). Customers do NOT log in — they track
 * their booking with their bike plate number on the public /track page.
 *
 * If the crew account still has the initial password set by the admin,
 * we force a one-time password reset before letting them into the dashboard.
 */
export default function LoginPage() {
  const { login, changePassword } = useAuth();
  const nav = useNavigate();

  const [phone, setPhone] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  // force-reset modal state
  const [forceReset, setForceReset] = useState(null); // { user }
  const [newPwd, setNewPwd] = useState("");
  const [confirmPwd, setConfirmPwd] = useState("");

  const formatPhone = (value) => {
    const trimmed = value.trim();
    if (!trimmed) return "";
    if (trimmed.startsWith("+")) return trimmed.replace(/[^\d+]/g, "");
    const digits = trimmed.replace(/\D/g, "");
    if (!digits) return "";
    if (digits.startsWith("91") && digits.length > 10) return `+${digits.slice(0, 12)}`;
    return `+91${digits.slice(0, 10)}`;
  };

  const submit = async (e) => {
    e?.preventDefault();
    if (!phone || !password) return toast.error("Enter your phone and password");
    setBusy(true);
    try {
      const { user, mustReset } = await login(phone.trim(), password);
      if (mustReset) {
        setForceReset({ user });
        toast.message("Set a new password to continue");
      } else {
        toast.success(`Welcome, ${user.name}`);
        nav(`/${user.role}`);
      }
    } catch (err) {
      toast.error(err.response?.data?.detail || "Login failed");
    } finally { setBusy(false); }
  };

  const submitNewPassword = async (e) => {
    e?.preventDefault();
    if (newPwd.length < 6) return toast.error("New password must be at least 6 characters");
    if (newPwd !== confirmPwd) return toast.error("Passwords do not match");
    setBusy(true);
    try {
      await changePassword(password, newPwd);
      toast.success("Password updated");
      const u = forceReset?.user;
      setForceReset(null);
      if (u) nav(`/${u.role}`);
    } catch (err) {
      toast.error(err.response?.data?.detail || "Could not update password");
    } finally { setBusy(false); }
  };

  return (
    <div className="min-h-screen bg-black grid-bg text-white overflow-hidden">
      <div className="min-h-screen max-w-7xl mx-auto grid lg:grid-cols-12">
        <section className="lg:col-span-7 relative min-h-[46vh] lg:min-h-screen flex flex-col justify-between p-6 sm:p-10">
          <img
            src="https://images.unsplash.com/photo-1568772585407-9361f9bf3a87?auto=format&fit=crop&w=1400&q=80"
            className="absolute inset-0 w-full h-full object-cover opacity-35"
            alt=""
          />
          <div className="absolute inset-0 bg-gradient-to-r from-black via-black/75 to-black/20" />
          <div className="relative">
            <button onClick={() => nav("/")} data-testid="back-home" className="inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-zinc-400 hover:text-orange-500 mb-10">
              <ArrowLeft className="w-3 h-3" /> Home
            </button>
            <div className="flex items-center gap-3 mb-10">
              <MacJitLogo size={44} />
              <div className="leading-none">
                <span className="font-display font-black text-2xl tracking-tighter text-white block"><span>MAC</span><span className="text-orange-500">JIT</span></span>
                <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-orange-500/90">Mechanic Just In Time</span>
              </div>
            </div>
            <p className="font-mono text-[10px] uppercase tracking-[0.35em] text-orange-500 mb-4">Workshop Control Room</p>
            <h1 className="font-display font-black text-6xl sm:text-7xl xl:text-8xl tracking-tighter leading-[0.88] uppercase">
              Terminal<br /><span className="text-orange-500">Ignition.</span>
            </h1>
            <p className="text-zinc-300 mt-7 max-w-xl font-mono text-sm leading-relaxed">
              Sign in to assign bays, move jobs, approve bills, manage parts, and keep every bike moving through the floor.
            </p>
          </div>
          <div className="relative grid sm:grid-cols-3 gap-px bg-white/10">
            {[
              { icon: Gauge, label: "Live bays", value: "Synced" },
              { icon: Wrench, label: "Jobs", value: "Queued" },
              { icon: ShieldCheck, label: "Access", value: "Secured" },
            ].map(({ icon: Icon, label, value }) => (
              <div key={label} className="bg-black/70 backdrop-blur p-4">
                <Icon className="w-4 h-4 text-orange-500 mb-3" />
                <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-zinc-500">{label}</p>
                <p className="font-display font-black uppercase tracking-tight">{value}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="lg:col-span-5 flex items-center p-6 sm:p-10 bg-zinc-950">
          <div className="w-full max-w-md mx-auto">
            <div className="border border-zinc-800 bg-black p-6 sm:p-8 shadow-2xl shadow-orange-500/5">
              <div className="flex items-center justify-between gap-4 mb-8">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mb-2">Terminal sign in</p>
                  <h2 className="font-display font-black text-3xl text-white tracking-tight uppercase">Crew Access</h2>
                </div>
                <div className="w-12 h-12 bg-orange-500 text-black grid place-items-center">
                  <KeyRound className="w-6 h-6" />
                </div>
              </div>

              <form onSubmit={submit} className="space-y-4">
                <div>
                  <label className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">Registered phone</label>
                  <div className="relative mt-2">
                    <Phone className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                    <input
                      data-testid="login-phone"
                      placeholder="+91..."
                      value={phone}
                      onChange={(e) => setPhone(formatPhone(e.target.value))}
                      required
                      inputMode="tel"
                      className="w-full bg-zinc-950 border border-zinc-800 pl-10 pr-4 py-3 font-mono text-white focus:border-orange-500 focus:outline-none"
                    />
                  </div>
                </div>
                <div>
                  <label className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">Password</label>
                  <div className="relative mt-2">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                    <input
                      data-testid="login-password"
                      type="password"
                      placeholder="Workshop password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      className="w-full bg-zinc-950 border border-zinc-800 pl-10 pr-4 py-3 font-mono text-white focus:border-orange-500 focus:outline-none"
                    />
                  </div>
                </div>
                <button data-testid="login-submit" disabled={busy}
                  className="w-full bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest py-4 transition-colors disabled:opacity-50 flex items-center justify-center gap-2">
                  {busy ? "Starting console..." : <>Open Terminal <ArrowRight className="w-4 h-4" /></>}
                </button>
              </form>

              <div className="mt-8 pt-6 border-t border-zinc-800">
                <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">
                  Admin-created crew accounts only. Customers use
                  <button onClick={() => nav("/track")} className="text-orange-500 hover:text-orange-400 ml-1">
                    /track
                  </button>.
                </p>
              </div>
            </div>
            <div className="mt-4 flex items-center gap-2 text-zinc-600 font-mono text-[10px] uppercase tracking-[0.2em] flex-wrap">
              <span className="flex items-center gap-2"><Zap className="w-3 h-3 text-orange-500" />macjit.com</span><span>/</span>
              <span>hello@macjit.com</span><span>/</span><span>+91 93534 01156</span>
            </div>
          </div>
        </section>
      </div>

      {/* Force-reset modal */}
      {forceReset && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur grid place-items-center p-4" data-testid="force-reset-modal">
          <form onSubmit={submitNewPassword}
            className="w-full max-w-md bg-zinc-950 border border-orange-500/50 p-8 space-y-4">
            <div className="flex items-center gap-3">
              <KeyRound className="w-6 h-6 text-orange-500" />
              <h3 className="font-display font-black text-2xl text-white tracking-tight uppercase">Set a new password</h3>
            </div>
            <p className="font-mono text-xs text-zinc-400">
              You're using the temporary password your admin set. Choose a new password to continue.
            </p>
            <input
              data-testid="new-password"
              type="password" placeholder="New password (min 6 chars)" value={newPwd}
              onChange={(e) => setNewPwd(e.target.value)} required minLength={6}
              className="w-full bg-zinc-900 border border-zinc-800 px-4 py-3 font-mono text-white focus:border-orange-500 focus:outline-none"
            />
            <input
              data-testid="confirm-password"
              type="password" placeholder="Confirm new password" value={confirmPwd}
              onChange={(e) => setConfirmPwd(e.target.value)} required minLength={6}
              className="w-full bg-zinc-900 border border-zinc-800 px-4 py-3 font-mono text-white focus:border-orange-500 focus:outline-none"
            />
            <button disabled={busy} data-testid="submit-new-password"
              className="w-full bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest py-3 transition-colors disabled:opacity-50">
              {busy ? "Saving..." : "Update Password →"}
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
