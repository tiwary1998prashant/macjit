import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import LoginPage from "./pages/LoginPage";
import LandingPage from "./pages/LandingPage";
import CheckoutPage from "./pages/CheckoutPage";
import CustomerPage from "./pages/CustomerPage";
import ReceptionPage from "./pages/ReceptionPage";
import MechanicPage from "./pages/MechanicPage";
import TesterPage from "./pages/TesterPage";
import AdminPage from "./pages/AdminPage";
import EmployeePage from "./pages/EmployeePage";
import ShopPage from "./pages/ShopPage";
import { Toaster } from "./components/ui/sonner";
import PWAInstallBanner from "./components/PWAInstallBanner";

const RoleRoute = ({ role, children }) => {
  const { user, loading } = useAuth();
  if (loading) return <div className="min-h-screen bg-zinc-950 grid place-items-center text-zinc-400 font-mono text-xs">Loading...</div>;
  if (!user) return <Navigate to="/terminal" replace />;
  if (user.role !== role) return <Navigate to={`/${user.role}`} replace />;
  return children;
};

const EmployeeRoute = ({ children }) => {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user) return <Navigate to="/terminal" replace />;
  if (!["mechanic", "reception", "tester", "admin", "shopkeeper"].includes(user.role)) return <Navigate to={`/${user.role}`} replace />;
  return children;
};

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          {/* Public customer-facing tracker — no login. */}
          <Route path="/track" element={<CustomerPage />} />
          <Route path="/login" element={<Navigate to="/track" replace />} />
          <Route path="/customer" element={<Navigate to="/track" replace />} />
          {/* Terminal sign-in. */}
          <Route path="/terminal" element={<LoginPage />} />
          <Route path="/staff" element={<Navigate to="/terminal" replace />} />
          <Route path="/pay/:bookingId" element={<CheckoutPage />} />
          <Route path="/reception" element={<RoleRoute role="reception"><ReceptionPage /></RoleRoute>} />
          <Route path="/mechanic" element={<RoleRoute role="mechanic"><MechanicPage /></RoleRoute>} />
          <Route path="/tester" element={<RoleRoute role="tester"><TesterPage /></RoleRoute>} />
          <Route path="/admin" element={<RoleRoute role="admin"><AdminPage /></RoleRoute>} />
          <Route path="/shopkeeper" element={<RoleRoute role="shopkeeper"><ShopPage /></RoleRoute>} />
          <Route path="/shop" element={<EmployeeRoute><ShopPage /></EmployeeRoute>} />
          <Route path="/employee" element={<EmployeeRoute><EmployeePage /></EmployeeRoute>} />
        </Routes>
        <Toaster theme="dark" position="top-right" />
        <PWAInstallBanner />
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
