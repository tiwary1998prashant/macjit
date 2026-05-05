import { STATUS_LABELS, STATUS_ORDER } from "../lib/api";
import { Check, Wrench, Clock } from "lucide-react";

export const Timeline = ({ status, light = false }) => {
  const idx = STATUS_ORDER.indexOf(status);
  const baseLine = light ? "border-zinc-200" : "border-zinc-800";
  const txtMuted = light ? "text-zinc-500" : "text-zinc-500";
  const txtActive = light ? "text-zinc-900" : "text-white";

  return (
    <ol data-testid="service-timeline" className={`relative border-l-2 ${baseLine} ml-3 space-y-6`}>
      {STATUS_ORDER.map((s, i) => {
        const done = i < idx;
        const active = i === idx;
        return (
          <li key={s} className="ml-6">
            <span
              className={`absolute -left-[11px] flex items-center justify-center w-5 h-5 rounded-full ring-4 ${
                light ? "ring-white" : "ring-zinc-950"
              } ${done ? "bg-emerald-500" : active ? "bg-orange-500" : light ? "bg-zinc-300" : "bg-zinc-700"}`}
            >
              {done ? <Check className="w-3 h-3 text-white" /> : active ? <Wrench className="w-3 h-3 text-black" /> : <Clock className={`w-3 h-3 ${light ? "text-zinc-500" : "text-zinc-400"}`} />}
            </span>
            <h4 className={`font-display font-bold text-sm uppercase tracking-wider ${active || done ? txtActive : txtMuted}`}>{STATUS_LABELS[s]}</h4>
            <p className={`text-xs font-mono ${active ? "text-orange-500" : txtMuted}`}>
              {done ? "Completed" : active ? "In progress" : "Pending"}
            </p>
          </li>
        );
      })}
    </ol>
  );
};
