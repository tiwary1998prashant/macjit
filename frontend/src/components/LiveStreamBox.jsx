import { Radio } from "lucide-react";

export const LiveStreamBox = ({ active, plate }) => (
  <div data-testid="live-stream-box" className="relative aspect-video bg-black rounded-xl overflow-hidden border border-zinc-800">
    {active ? (
      <>
        <img
          src="https://images.unsplash.com/photo-1636761358783-209512dccd98?crop=entropy&cs=srgb&fm=jpg&q=85&w=1200"
          alt="Live mechanic stream"
          className="w-full h-full object-cover opacity-90"
        />
        <div className="absolute inset-0 scanline" />
        <div className="absolute top-3 left-3 flex items-center gap-2 bg-black/70 backdrop-blur-md px-3 py-1.5 rounded-full">
          <span className="w-2 h-2 rounded-full bg-red-500 animate-live-pulse" />
          <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-white font-bold">LIVE</span>
        </div>
        <div className="absolute bottom-3 left-3 right-3 flex items-end justify-between">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-300">Service in progress</p>
            <p className="font-display font-black text-2xl text-white">{plate}</p>
          </div>
          <div className="bg-orange-500 text-black px-3 py-1 font-mono text-[10px] uppercase tracking-widest font-bold">
            CAM-01
          </div>
        </div>
      </>
    ) : (
      <div className="w-full h-full flex flex-col items-center justify-center bg-zinc-950 grid-bg">
        <Radio className="w-10 h-10 text-zinc-700 mb-3" />
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-zinc-600">Stream offline</p>
        <p className="text-zinc-500 text-sm mt-1">Live feed begins when mechanic starts service</p>
      </div>
    )}
  </div>
);
