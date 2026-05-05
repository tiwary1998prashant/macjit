import { useEffect, useState } from "react";
import { Download, X } from "lucide-react";

/**
 * PWAInstallBanner — shows a small install prompt when the browser fires
 * `beforeinstallprompt`.
 * Hides itself permanently after dismiss.
 */
export default function PWAInstallBanner() {
  const [evt, setEvt] = useState(null);
  const [hidden, setHidden] = useState(() => localStorage.getItem("macjit_pwa_dismissed") === "1");

  useEffect(() => {
    const onPrompt = (e) => { e.preventDefault(); setEvt(e); };
    window.addEventListener("beforeinstallprompt", onPrompt);
    return () => window.removeEventListener("beforeinstallprompt", onPrompt);
  }, []);

  if (!evt || hidden) return null;

  const install = async () => {
    try {
      evt.prompt();
      const choice = await evt.userChoice;
      if (choice.outcome === "accepted") localStorage.setItem("macjit_pwa_dismissed", "1");
    } catch {}
    setEvt(null);
  };

  const dismiss = () => {
    localStorage.setItem("macjit_pwa_dismissed", "1");
    setHidden(true);
  };

  return (
    <div data-testid="pwa-install-banner" className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 bg-zinc-900 border border-orange-500 shadow-2xl shadow-orange-500/20 px-4 py-3 flex items-center gap-3 max-w-md">
      <Download className="w-5 h-5 text-orange-500 flex-shrink-0" />
      <div className="flex-1 min-w-0">
        <p className="font-display font-bold text-sm text-white">Install MacJit Terminal</p>
        <p className="font-mono text-[10px] text-zinc-400">Faster workshop access · home-screen icon</p>
      </div>
      <button data-testid="pwa-install-btn" onClick={install} className="bg-orange-500 hover:bg-orange-400 text-black font-mono text-[11px] uppercase tracking-widest font-bold px-3 py-2">Install</button>
      <button data-testid="pwa-dismiss-btn" onClick={dismiss} className="text-zinc-500 hover:text-white p-1"><X className="w-4 h-4" /></button>
    </div>
  );
}
