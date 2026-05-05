import { createContext, useContext, useEffect, useState } from "react";
import api from "../lib/api";

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem("mm_token"));
  const [mustReset, setMustReset] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) { setLoading(false); return; }
    api.get("/auth/me").then((r) => setUser(r.data)).catch(() => {
      localStorage.removeItem("mm_token"); setToken(null);
    }).finally(() => setLoading(false));
  }, [token]);

  // Staff-only login: phone + password.
  const login = async (phone, password) => {
    const r = await api.post("/auth/login", { phone, password });
    localStorage.setItem("mm_token", r.data.token);
    setToken(r.data.token);
    setUser(r.data.user);
    setMustReset(!!r.data.must_reset_password);
    return { user: r.data.user, mustReset: !!r.data.must_reset_password };
  };

  const changePassword = async (oldPassword, newPassword) => {
    await api.post("/auth/change-password", { old_password: oldPassword, new_password: newPassword });
    setMustReset(false);
  };

  const logout = () => {
    localStorage.removeItem("mm_token");
    setToken(null); setUser(null); setMustReset(false);
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, mustReset, login, logout, changePassword }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);

if (typeof window !== "undefined" && "serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  });
}
