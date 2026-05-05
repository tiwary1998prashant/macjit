import { useEffect, useRef, useState } from "react";
import { wsUrl } from "../lib/api";

export const useGarageWS = (token, onEvent) => {
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const handlerRef = useRef(onEvent);
  handlerRef.current = onEvent;

  useEffect(() => {
    if (!token) return;
    let stop = false;
    let retryTimer;

    const connect = () => {
      if (stop) return;
      const ws = new WebSocket(wsUrl(token));
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          if (handlerRef.current) handlerRef.current(data);
        } catch (_) {}
      };
      ws.onclose = () => {
        setConnected(false);
        if (!stop) retryTimer = setTimeout(connect, 2000);
      };
      ws.onerror = () => { try { ws.close(); } catch (_) {} };
    };
    connect();
    return () => {
      stop = true;
      clearTimeout(retryTimer);
      try { wsRef.current?.close(); } catch (_) {}
    };
  }, [token]);

  return { connected };
};
