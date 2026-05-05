import axios from "axios";

const API_BASE = process.env.REACT_APP_API_BASE || "";
const configuredBackendUrl = process.env.REACT_APP_BACKEND_URL || "";

export const BACKEND_URL = configuredBackendUrl || API_BASE.replace(/\/api\/?$/, "");
export const API = API_BASE || `${BACKEND_URL}/api`;

const api = axios.create({ baseURL: API });

api.interceptors.request.use((cfg) => {
  const token = localStorage.getItem("mm_token");
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

export default api;

export const wsUrl = (token) => {
  if (!BACKEND_URL) {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    return `${proto}://${window.location.host}/api/ws/${token}`;
  }
  const proto = BACKEND_URL.startsWith("https") ? "wss" : "ws";
  const host = BACKEND_URL.replace(/^https?:\/\//, "");
  return `${proto}://${host}/api/ws/${token}`;
};

export const STATUS_LABELS = {
  BOOKED: "Booked",
  CANCELLED: "Cancelled",
  ASSIGNED: "Assigned",
  IN_SERVICE: "In Service",
  READY_TO_TEST: "Ready to Test",
  QA_DONE: "QA Done",
  BILLED: "Billed",
  PAID: "Paid",
};

export const STATUS_ORDER = ["BOOKED", "ASSIGNED", "IN_SERVICE", "READY_TO_TEST", "QA_DONE", "BILLED", "PAID"];
