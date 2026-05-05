export const StatCard = ({ label, value, sub, accent = false, testid }) => (
  <div
    data-testid={testid}
    className={`relative border ${accent ? "border-orange-600/40 bg-orange-600/5" : "border-zinc-800 bg-zinc-900/40"} p-6 rounded-none overflow-hidden`}
  >
    <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">{label}</p>
    <p className={`font-display font-black text-4xl mt-2 ${accent ? "text-orange-500" : "text-white"}`}>{value}</p>
    {sub && <p className="text-xs text-zinc-400 mt-1 font-mono">{sub}</p>}
  </div>
);
