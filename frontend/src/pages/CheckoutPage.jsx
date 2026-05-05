import { useEffect, useState } from "react";
import { useParams, useNavigate, useSearchParams } from "react-router-dom";
import api from "../lib/api";
import { Wrench, Check, ShieldCheck, IndianRupee, ExternalLink, Lock, Sparkles } from "lucide-react";
import MacJitLogo from "../components/MacJitLogo";
import { toast } from "sonner";

export default function CheckoutPage() {
  const { bookingId } = useParams();
  const [search] = useSearchParams();
  const plate = (search.get("plate") || "").trim();
  const nav = useNavigate();
  const [booking, setBooking] = useState(null);
  const [busy, setBusy] = useState(false);
  const [paid, setPaid] = useState(false);

  useEffect(() => {
    if (!plate) {
      toast.error("Open this bill from the Track page");
      nav("/track");
      return;
    }
    api.get(`/track/booking/${bookingId}`, { params: { plate } }).then((r) => {
      setBooking(r.data);
      if (r.data.paid) setPaid(true);
    }).catch(() => toast.error("Booking not found"));
  }, [bookingId, plate, nav]);

  const loadRazorpay = () =>
    new Promise((resolve) => {
      if (window.Razorpay) return resolve(true);
      const s = document.createElement("script");
      s.src = "https://checkout.razorpay.com/v1/checkout.js";
      s.onload = () => resolve(true);
      s.onerror = () => resolve(false);
      document.body.appendChild(s);
    });

  const payNow = async () => {
    setBusy(true);
    try {
      const ok = await loadRazorpay();
      if (!ok) throw new Error("Could not load Razorpay. Check your internet connection.");

      // 1. Ask backend to create a real Razorpay Order
      const orderRes = await api.post(`/bookings/${bookingId}/razorpay/order`, { plate_number: plate });
      const order = orderRes.data;

      // 2. Open Razorpay Checkout modal
      await new Promise((resolve, reject) => {
        const rzp = new window.Razorpay({
          key: order.key_id,
          amount: order.amount,
          currency: order.currency,
          name: order.name,
          description: order.description,
          order_id: order.order_id,
          prefill: order.prefill,
          theme: { color: "#F26A21" },
          modal: {
            ondismiss: () => {
              setBusy(false);
              reject(new Error("Payment cancelled"));
            },
          },
          handler: async (resp) => {
            try {
              // 3. Verify the signature server-side BEFORE marking paid
              await api.post(`/bookings/${bookingId}/razorpay/verify`, {
                razorpay_payment_id: resp.razorpay_payment_id,
                razorpay_order_id: resp.razorpay_order_id,
                razorpay_signature: resp.razorpay_signature,
                plate_number: plate,
              });
              setPaid(true);
              toast.success("Payment received · Thank you!");
              resolve();
            } catch (err) {
              toast.error(err.response?.data?.detail || "Payment verification failed");
              reject(err);
            }
          },
        });
        rzp.on("payment.failed", (resp) => {
          toast.error(resp.error?.description || "Payment failed");
          reject(new Error("Payment failed"));
        });
        rzp.open();
      });
    } catch (e) {
      if (e.message !== "Payment cancelled" && e.message !== "Payment failed") {
        toast.error(e.response?.data?.detail || e.message || "Payment failed — please try again");
      }
    } finally {
      setBusy(false);
    }
  };

  if (!booking) {
    return <div className="min-h-screen bg-zinc-50 grid place-items-center font-mono text-sm text-zinc-500">Loading bill...</div>;
  }

  const items = booking.items || [];
  const itemsTotal = items.reduce((s, i) => s + (i.subtotal || 0), 0);
  const billAmount = Number(booking.bill_amount || 0);
  const subtotal = Number(booking.subtotal || billAmount + Number(booking.discount || 0));
  const baseCharge = Math.max(0, subtotal - itemsTotal - Number(booking.extra_cost || 0));
  const serviceLabel = String(booking.service_type || "service").replace(/-/g, " ");

  return (
    <div className="min-h-screen bg-gradient-to-b from-white via-zinc-50 to-zinc-100">
      {/* Header */}
      <header className="border-b border-zinc-200">
        <div className="max-w-2xl mx-auto px-6 py-5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <MacJitLogo size={32} />
            <span className="font-display font-black tracking-tighter">MACJIT</span>
          </div>
          <div className="flex items-center gap-1.5 text-zinc-500">
            <Lock className="w-3 h-3" />
            <span className="font-mono text-[10px] uppercase tracking-widest">Secure checkout</span>
          </div>
        </div>
      </header>

      <main className="max-w-2xl mx-auto px-6 py-10">
        {paid ? (
          <div className="text-center py-12">
            <div className="w-20 h-20 mx-auto rounded-full bg-emerald-500 flex items-center justify-center mb-6 animate-bounce">
              <Check className="w-10 h-10 text-white" strokeWidth={3} />
            </div>
            <h1 className="font-display font-black text-4xl tracking-tighter">Payment received</h1>
            <p className="text-zinc-600 mt-3 font-mono text-sm">Thank you for visiting MacJit.<br />Drive safe! 🏁</p>
            <div className="mt-8 inline-block bg-black text-white p-6 text-left">
              <p className="font-mono text-[10px] uppercase tracking-widest text-orange-500">Receipt</p>
              <p className="font-display font-black text-2xl tracking-tighter mt-1">#{bookingId.slice(0, 8).toUpperCase()}</p>
              <p className="font-mono text-sm text-zinc-300 mt-2">{booking.plate_number} · ₹{booking.bill_amount}</p>
              <p className="font-mono text-[10px] text-zinc-500 mt-1">{new Date().toLocaleString()}</p>
            </div>
            <button onClick={() => nav("/")} className="mt-10 font-mono text-[11px] uppercase tracking-widest text-zinc-500 hover:text-black underline underline-offset-8">← Back to MacJit</button>
          </div>
        ) : (
          <>
            <div className="mb-2 flex items-center gap-2">
              <span className="bg-orange-500 text-black font-mono text-[10px] uppercase tracking-widest font-bold px-2 py-0.5">Bill</span>
              <span className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">#{bookingId.slice(0, 8).toUpperCase()}</span>
            </div>
            <h1 className="font-display font-black text-5xl tracking-tighter">Pay for service</h1>
            <p className="text-zinc-500 mt-1 font-mono text-sm">{booking.car_make} {booking.car_model} · {booking.plate_number}</p>

            {/* Bill breakdown */}
            <div className="mt-8 bg-white border border-zinc-200 shadow-sm" data-testid="bill-breakdown">
              <div className="p-6">
                <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500 mb-4">Service breakdown</p>
                <div className="flex justify-between py-2">
                  <span className="text-sm capitalize">{serviceLabel} — base</span>
                  <span className="font-mono">₹{baseCharge}</span>
                </div>
                {items.map((it) => (
                  <div key={it.inventory_id || it.name} className="flex justify-between py-2 text-sm">
                    <span>{it.name} <span className="text-zinc-400">× {it.qty}</span></span>
                    <span className="font-mono">₹{it.subtotal}</span>
                  </div>
                ))}
                {Number(booking.extra_cost || 0) > 0 && (
                  <div className="flex justify-between py-2 text-sm">
                    <span>Heavy work</span>
                    <span className="font-mono">₹{booking.extra_cost}</span>
                  </div>
                )}
                <div className="border-t border-zinc-200 mt-3 pt-3 flex justify-between text-sm">
                  <span className="text-zinc-500">Subtotal</span>
                  <span className="font-mono">₹{subtotal}</span>
                </div>
                {Number(booking.discount || 0) > 0 && (
                  <div className="flex justify-between text-sm text-emerald-600">
                    <span className="flex items-center gap-1"><Sparkles className="w-3 h-3" />{booking.loyalty_tier || ""} loyalty discount ({booking.discount_pct || 0}%)</span>
                    <span className="font-mono">−₹{booking.discount}</span>
                  </div>
                )}
              </div>
              <div className="bg-black text-white p-6 flex items-end justify-between">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-400">Total payable</p>
                  <p className="font-display font-black text-5xl tracking-tighter mt-1 flex items-center"><IndianRupee className="w-9 h-9 text-orange-500" />{billAmount}</p>
                </div>
                <ShieldCheck className="w-10 h-10 text-orange-500" />
              </div>
            </div>

            {/* Pay button */}
            <button
              data-testid="checkout-pay-btn"
              onClick={payNow}
              disabled={busy}
              className="w-full mt-6 bg-orange-500 hover:bg-orange-400 disabled:opacity-50 text-black font-display font-black uppercase tracking-widest py-5 transition-colors flex items-center justify-center gap-2 text-lg border-b-4 border-orange-700 active:translate-y-1 active:border-b-0"
            >
              {busy ? "Processing..." : <>Pay ₹{booking.bill_amount} now <ExternalLink className="w-5 h-5" /></>}
            </button>

            <p className="mt-4 text-center font-mono text-[10px] uppercase tracking-widest text-zinc-500">Razorpay · UPI · Cards · Netbanking · Wallets</p>

            {/* Trust badges */}
            <div className="mt-8 grid grid-cols-3 gap-px bg-zinc-200 border border-zinc-200">
              <div className="bg-white p-4 text-center"><Lock className="w-4 h-4 mx-auto text-zinc-700" /><p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500 mt-2">256-bit SSL</p></div>
              <div className="bg-white p-4 text-center"><ShieldCheck className="w-4 h-4 mx-auto text-zinc-700" /><p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500 mt-2">PCI DSS</p></div>
              <div className="bg-white p-4 text-center"><Check className="w-4 h-4 mx-auto text-zinc-700" /><p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500 mt-2">RBI Compliant</p></div>
            </div>

            <p className="mt-8 text-center text-xs text-zinc-400 font-mono">Powered by MacJit · Razorpay</p>
          </>
        )}
      </main>
    </div>
  );
}
