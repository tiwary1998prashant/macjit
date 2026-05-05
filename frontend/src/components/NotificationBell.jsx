import { useEffect, useState } from "react";
import { Bell } from "lucide-react";
import { Popover, PopoverTrigger, PopoverContent } from "./ui/popover";
import api from "../lib/api";

export const NotificationBell = ({ refreshKey, light = false }) => {
  const [items, setItems] = useState([]);
  const unread = items.filter((n) => !n.read).length;

  const load = () => api.get("/notifications/me").then((r) => setItems(r.data)).catch(() => {});

  useEffect(() => { load(); }, [refreshKey]);

  const onOpen = (open) => {
    if (open) {
      items.filter((n) => !n.read).forEach((n) => api.post(`/notifications/${n.id}/read`).catch(() => {}));
      setTimeout(load, 400);
    }
  };

  return (
    <Popover onOpenChange={onOpen}>
      <PopoverTrigger asChild>
        <button data-testid="notification-bell" className={`relative p-2 rounded-full ${light ? "hover:bg-zinc-100" : "hover:bg-zinc-800"} transition-colors`}>
          <Bell className={`w-5 h-5 ${light ? "text-zinc-700" : "text-zinc-300"}`} />
          {unread > 0 && (
            <span data-testid="notification-count" className="absolute -top-0.5 -right-0.5 bg-red-500 text-white text-[10px] font-bold w-4 h-4 rounded-full flex items-center justify-center">
              {unread > 9 ? "9+" : unread}
            </span>
          )}
        </button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-0 bg-zinc-950 border-zinc-800">
        <div className="p-3 border-b border-zinc-800">
          <p className="font-display font-black text-sm uppercase tracking-wider text-white">Notifications</p>
        </div>
        <div className="max-h-80 overflow-y-auto">
          {items.length === 0 && <p className="p-4 text-xs text-zinc-500">No notifications yet</p>}
          {items.map((n) => (
            <div key={n.id} data-testid={`notif-${n.event_type}`} className={`p-3 border-b border-zinc-900 ${!n.read ? "bg-orange-600/5" : ""}`}>
              <p className="font-mono text-[10px] uppercase tracking-widest text-orange-500">{n.event_type.replace(/_/g, " ")}</p>
              <p className="text-sm text-white mt-0.5">{n.body}</p>
              <p className="text-[10px] text-zinc-500 font-mono mt-1">{new Date(n.ts).toLocaleString()}</p>
            </div>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  );
};
