import { useState, useCallback, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Wrench, Zap, Radio, Clock, ShieldCheck, ShoppingCart, ArrowRight, Phone, MapPin, Sparkles, Mail, Send, X } from "lucide-react";
import MacJitLogo from "../components/MacJitLogo";
import Marquee from "react-fast-marquee";
import { toast } from "sonner";
import { useAuth } from "../context/AuthContext";
import api from "../lib/api";

const SERVICES = [
  { name: "Oil & Filter Change", price: 400, duration: "30m", desc: "Engine oil flush · oil & air filter · chain lube top-up" },
  { name: "General Service", price: 1500, duration: "2h", desc: "30-point check · tyre pressure · adjustments · cleaning" },
  { name: "Chain & Sprocket", price: 800, duration: "1h", desc: "Chain tension · sprocket wear check · full lube service" },
  { name: "Wheel Truing & Balancing", price: 600, duration: "45m", desc: "Spoke tension · rim truing · dynamic wheel balance" },
  { name: "Brake Service", price: 900, duration: "1h", desc: "Brake shoe / disc pad · fluid bleed · cable adjustment" },
  { name: "Full Service", price: 3000, duration: "3h 30m", desc: "Engine, brakes, chain, electrics, tyres, wash & polish" },
  { name: "Engine Repair", price: 4500, duration: "4h", desc: "Diagnostics · valve clearance · part replacement" },
];

const STEPS = [
  { n: "01", t: "Walk in / Phone", d: "Drop your bike at reception. We capture only your name + phone." },
  { n: "02", t: "Auto-Allocated", d: "Mechanic & bay assigned automatically. ETA sent to you instantly." },
  { n: "03", t: "Watch Live", d: "Open the link on your phone. See your bike being serviced — live." },
  { n: "04", t: "Approve & Pay", d: "Approve heavy work in one tap. Pay via UPI / cash. Done." },
];

const INITIAL_TORQUE_MESSAGE = {
  from: "bot",
  text: "Hi, I am Torque from MacJit. Tell me what your bike is doing - unusual noise, brake issue, oil service, chain problem, anything. I will help like your workshop mechanic.",
};

export default function LandingPage() {
  const nav = useNavigate();
  const { user } = useAuth();
  const [chatOpen, setChatOpen] = useState(false);
  const goTrack = () => nav(user ? `/${user.role}` : "/track");
  const goStaff = () => nav("/terminal");

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      {/* Top ticker */}
      <div className="bg-orange-500 text-black py-1.5 border-b-2 border-black">
        <Marquee speed={50} gradient={false}>
          <span className="font-mono text-[11px] uppercase tracking-[0.3em] mx-8 font-bold">LIVE GARAGE OPS / TRACK YOUR BIKE / BOOK WITH TORQUE / OPEN 8AM TO 6PM /</span>
          <span className="font-mono text-[11px] uppercase tracking-[0.3em] mx-8 font-bold">LIVE GARAGE OPS / TRACK YOUR BIKE / BOOK WITH TORQUE / OPEN 8AM TO 6PM /</span>
        </Marquee>
      </div>

      {/* Nav */}
      <nav className="sticky top-0 z-30 bg-zinc-950/85 backdrop-blur-xl border-b border-zinc-900">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <MacJitLogo size={36} />
            <div className="leading-none">
              <span className="font-display font-black text-xl tracking-tighter block"><span className="text-white">MAC</span><span className="text-orange-500">JIT</span></span>
              <span className="font-mono text-[9px] uppercase tracking-[0.24em] text-orange-500/80">Mechanic Just In Time</span>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-8 font-mono text-[11px] uppercase tracking-[0.2em] text-zinc-400">
            <a href="#services" className="hover:text-orange-500">Services</a>
            <a href="#how" className="hover:text-orange-500">How it works</a>
            <a href="#enquiry" className="hover:text-orange-500">Enquire</a>
            <button type="button" onClick={goStaff} className="hover:text-orange-500 uppercase tracking-[0.2em]">Terminal</button>
            <a href="#contact" className="hover:text-orange-500">Contact</a>
          </div>
          <div className="flex items-center gap-2">
            <button data-testid="nav-track" onClick={goTrack} className="bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-[0.16em] text-xs sm:text-sm px-3.5 sm:px-4 py-2.5 transition-colors flex items-center gap-2 shadow-[0_8px_30px_rgba(249,115,22,0.22)]">
              {user ? "Dashboard" : "Track Bike"} <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative grid-bg overflow-hidden reveal-up">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(249,115,22,0.18),transparent_35%),radial-gradient(circle_at_80%_0%,rgba(251,146,60,0.14),transparent_30%)] pointer-events-none" />
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-zinc-950 pointer-events-none" />
        <div className="max-w-7xl mx-auto px-6 py-16 sm:py-20 lg:py-28 grid lg:grid-cols-12 gap-8 items-end relative">
          <div className="lg:col-span-7">
            <div className="inline-flex items-center gap-2 border border-orange-500/40 bg-orange-500/5 px-3 py-1.5 mb-8">
              <span className="w-1.5 h-1.5 bg-orange-500 rounded-full animate-live-pulse" />
              <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500">LIVE — 3 BAYS RUNNING</p>
            </div>
            <h1 className="font-display font-black text-5xl sm:text-7xl lg:text-8xl tracking-tighter leading-[0.92] uppercase">
              Precision<br /><span className="text-orange-500">bike care</span><br />without waiting.
            </h1>
            <p className="mt-6 sm:mt-8 text-zinc-300 font-mono text-sm sm:text-base max-w-xl leading-relaxed">
              Book with Torque, drop your bike before the slot, and follow every stage from your phone. Cleaner booking, sharper workshop flow, no guessing.
            </p>
            <div className="mt-10 flex flex-wrap items-center gap-4">
              <button data-testid="hero-book" onClick={() => setChatOpen(true)} className="interactive-lift bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-[0.16em] text-xs sm:text-sm px-6 sm:px-7 py-3.5 sm:py-4 transition-colors flex items-center gap-2 border-b-4 border-orange-700 active:translate-y-1 active:border-b-0 shadow-[0_14px_40px_rgba(249,115,22,0.26)]">
                Book with Torque <ArrowRight className="w-4 h-4" />
              </button>
              <button onClick={goTrack} className="font-mono text-[11px] uppercase tracking-[0.2em] text-zinc-300 hover:text-orange-500 underline underline-offset-8 decoration-orange-500">Track bike</button>
            </div>
            <div className="mt-12 flex flex-wrap gap-x-10 gap-y-3 font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">
              <span className="flex items-center gap-2"><Zap className="w-3 h-3 text-orange-500" />Auto-allocated mechanic</span>
              <span className="flex items-center gap-2"><Radio className="w-3 h-3 text-orange-500" />WhatsApp + SMS milestones</span>
              <span className="flex items-center gap-2"><ShieldCheck className="w-3 h-3 text-orange-500" />QA tested before pickup</span>
            </div>
          </div>
          <div className="lg:col-span-5">
            <div className="relative rounded-sm overflow-hidden border border-zinc-800 shadow-[0_20px_60px_rgba(0,0,0,0.5)]">
              <img
                src="https://images.unsplash.com/photo-1558618666-fcd25c85cd64?auto=format&fit=crop&w=1200&q=80"
                alt="Bike Workshop"
                className="w-full aspect-[4/5] object-cover"
                onError={(e) => { e.currentTarget.src = "https://images.unsplash.com/photo-1609630875171-b1321377ee65?auto=format&fit=crop&w=1200&q=80"; }}
              />
              <div className="absolute inset-0 scanline" />
              <div className="absolute top-4 left-4 flex items-center gap-2 bg-black/80 backdrop-blur px-3 py-1.5">
                <span className="w-2 h-2 bg-orange-500 rounded-full animate-live-pulse" />
                <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-white font-bold">BAY-01 LIVE</span>
              </div>
              <div className="absolute -bottom-6 -left-1 sm:-left-6 bg-orange-500 text-black p-4 sm:p-5 max-w-[72%] sm:max-w-[60%]">
                <p className="font-mono text-[10px] uppercase tracking-[0.2em]">Currently servicing</p>
                <p className="font-display font-black text-2xl tracking-tighter mt-1">KA-05-MN-2024</p>
                <p className="font-mono text-[10px] mt-1">Royal Enfield Classic 350 · 47% done</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Stats strip */}
      <section className="border-y border-zinc-900 bg-zinc-950 reveal-up reveal-delay-1">
        <div className="max-w-7xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-px bg-zinc-900">
          {[
            { n: "1,400+", l: "Bikes serviced" },
            { n: "98.6%", l: "On-time delivery" },
            { n: "4.9★", l: "Rider rating" },
            { n: "8AM–6PM", l: "Open daily" },
          ].map((s) => (
            <div key={s.l} className="bg-zinc-950 p-6 sm:p-8 hover-soft">
              <p className="font-display font-black text-4xl text-orange-500 tracking-tighter">{s.n}</p>
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500 mt-2">{s.l}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Services */}
      <section id="services" className="max-w-7xl mx-auto px-6 py-20 reveal-up reveal-delay-2">
        <div className="grid lg:grid-cols-12 gap-8 mb-12">
          <div className="lg:col-span-5">
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mb-2">01 — Services</p>
            <h2 className="font-display font-black text-5xl lg:text-6xl tracking-tighter uppercase">Pick what your<br />bike needs.</h2>
          </div>
          <p className="lg:col-span-6 lg:col-start-7 text-zinc-400 font-mono text-sm self-end">
            Transparent base pricing. Parts billed at MRP. No surprise add-ons. SILVER & GOLD members get up to 10% off the entire bill, automatically.
          </p>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-px bg-zinc-900">
          {SERVICES.map((s, i) => (
            <div key={s.name} data-testid={`service-${s.name.toLowerCase().replace(/ /g, '-')}`} className="bg-zinc-950 p-7 hover:bg-orange-500/5 group transition-colors hover-soft">
              <div className="flex items-start justify-between mb-6">
                <span className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-500">/{(i + 1).toString().padStart(2, "0")}</span>
                <span className="bg-zinc-900 text-orange-500 font-mono text-[10px] uppercase tracking-widest px-2 py-1"><Clock className="w-3 h-3 inline mr-1" />{s.duration}</span>
              </div>
              <h3 className="font-display font-black text-2xl tracking-tight mb-2 group-hover:text-orange-500 transition-colors">{s.name}</h3>
              <p className="text-zinc-500 text-sm mb-6">{s.desc}</p>
              <p className="font-display font-black text-4xl tracking-tighter">₹{s.price}<span className="text-zinc-600 text-sm font-mono ml-2">starting</span></p>
            </div>
          ))}
          <div className="bg-gradient-to-br from-orange-500 to-orange-400 text-black p-7 flex flex-col justify-between">
            <div>
              <Sparkles className="w-7 h-7 mb-4" />
              <h3 className="font-display font-black text-2xl tracking-tight mb-2">Loyalty rewards</h3>
              <p className="text-sm mb-2">Spend ₹10k → SILVER (5% off)</p>
              <p className="text-sm">Spend ₹25k → GOLD (10% off)</p>
            </div>
              <button onClick={() => setChatOpen(true)} className="interactive-lift mt-6 bg-black text-orange-500 font-display font-black uppercase tracking-widest py-3 self-start px-5 hover:bg-zinc-900 transition-colors flex items-center gap-2 shadow-lg">Book now <ArrowRight className="w-3 h-3" /></button>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="bg-zinc-900/40 border-y border-zinc-900 reveal-up">
        <div className="max-w-7xl mx-auto px-6 py-20">
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mb-2">02 — Process</p>
          <h2 className="font-display font-black text-5xl lg:text-6xl tracking-tighter uppercase mb-16">From keys in<br />to keys back.</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-px bg-zinc-800">
            {STEPS.map((s) => (
              <div key={s.n} className="bg-zinc-950 p-8 relative overflow-hidden hover-soft">
                <span className="font-display font-black text-[120px] leading-none tracking-tighter text-orange-500/10 absolute -top-4 -right-2 select-none">{s.n}</span>
                <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 relative">Step {s.n}</p>
                <h3 className="font-display font-black text-2xl tracking-tight mt-3 relative">{s.t}</h3>
                <p className="text-zinc-400 text-sm mt-2 relative">{s.d}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Shop teaser */}
      <section id="shop" className="max-w-7xl mx-auto px-6 py-20 grid lg:grid-cols-2 gap-12 items-center reveal-up reveal-delay-1">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mb-2">03 — Shop</p>
          <h2 className="font-display font-black text-5xl lg:text-6xl tracking-tighter uppercase">Parts &<br />accessories.</h2>
          <p className="text-zinc-400 font-mono text-sm mt-6 max-w-md">
            Walk-in counter for genuine engine oil, brake shoes, filters, tyres, chains and lubricants. Same stock the workshop uses. Cash or UPI.
          </p>
          <button onClick={goTrack} className="interactive-lift mt-8 border border-orange-500 text-orange-500 hover:bg-orange-500 hover:text-black font-display font-black uppercase tracking-widest px-6 py-3 transition-colors flex items-center gap-2">
            <ShoppingCart className="w-4 h-4" /> Browse parts
          </button>
        </div>
        <div className="grid grid-cols-2 gap-px bg-zinc-900 border border-zinc-800">
          {[
            { n: "Engine Oil 1L", p: 350, c: "Motul" },
            { n: "Brake Shoe Set", p: 420, c: "OEM" },
            { n: "Air Filter", p: 280, c: "Genuine" },
            { n: "Spark Plug", p: 150, c: "NGK" },
          ].map((it) => (
            <div key={it.n} className="bg-zinc-950 p-5 hover-soft">
              <p className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">{it.c}</p>
              <p className="font-display font-bold mt-1">{it.n}</p>
              <p className="font-display font-black text-2xl text-orange-500 mt-3">₹{it.p}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Testimonial */}
      <section className="bg-orange-500 text-black reveal-up">
        <div className="max-w-5xl mx-auto px-6 py-20">
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] mb-6">/ what riders say</p>
          <p className="font-display font-black text-3xl lg:text-5xl tracking-tighter leading-tight">
            "Dropped my Royal Enfield Classic 350 on the way to office. Got SMS milestones every step — assigned to mechanic, started, ready, billed. Picked it up after work. <span className="bg-black text-orange-500 px-2">Game changer.</span>"
          </p>
          <div className="mt-8 flex items-center gap-3">
            <div className="w-10 h-10 bg-black flex items-center justify-center text-orange-500 font-display font-black">A</div>
            <div>
              <p className="font-display font-black">Aarav Sharma</p>
              <p className="font-mono text-[10px] uppercase tracking-widest">GOLD member · 11 services</p>
            </div>
          </div>
        </div>
      </section>

      {/* Enquiry */}
      <section id="enquiry" className="max-w-7xl mx-auto px-6 py-24 reveal-up reveal-delay-1">
        <div className="grid lg:grid-cols-12 gap-10">
          <div className="lg:col-span-5">
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mb-2">/ Talk to us</p>
            <h2 className="font-display font-black text-5xl lg:text-6xl tracking-tighter uppercase">Send an<br /><span className="text-orange-500">enquiry.</span></h2>
            <p className="text-zinc-400 font-mono text-sm mt-6 leading-relaxed">Quick quotes, pickup options, fleet rates, anything else. Our team replies within working hours.</p>
            <div className="mt-8 space-y-3">
              <a href="tel:+919353401156" className="flex items-center gap-3 group">
                <div className="w-10 h-10 border border-zinc-800 group-hover:border-orange-500 grid place-items-center"><Phone className="w-4 h-4 text-orange-500" /></div>
                <div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">Call</p><p className="font-display font-bold">+91 93534 01156</p></div>
              </a>
              <a href="mailto:hello@macjit.com" className="flex items-center gap-3 group">
                <div className="w-10 h-10 border border-zinc-800 group-hover:border-orange-500 grid place-items-center"><Mail className="w-4 h-4 text-orange-500" /></div>
                <div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">Email</p><p className="font-display font-bold">hello@macjit.com</p></div>
              </a>
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 border border-zinc-800 grid place-items-center"><MapPin className="w-4 h-4 text-orange-500" /></div>
                <div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">Visit</p><p className="font-display font-bold">Varthur, Bangalore — 560087</p></div>
              </div>
            </div>
          </div>
          <div className="lg:col-span-7">
            <EnquiryForm />
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="max-w-7xl mx-auto px-6 py-20 sm:py-24 text-center reveal-up">
        <h2 className="font-display font-black text-6xl lg:text-8xl tracking-tighter uppercase">Ready when<br /><span className="text-orange-500">you are.</span></h2>
        <button onClick={() => setChatOpen(true)} className="interactive-lift mt-10 bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest px-7 sm:px-8 py-4 sm:py-5 text-base sm:text-lg transition-colors inline-flex items-center gap-2 border-b-4 border-orange-700 active:translate-y-1 active:border-b-0 shadow-[0_16px_44px_rgba(249,115,22,0.26)]">
          Ask Torque <ArrowRight className="w-5 h-5" />
        </button>
      </section>

      <ServiceChatbot open={chatOpen} setOpen={setChatOpen} />

      {/* Workshop gallery */}
      <section className="max-w-7xl mx-auto px-6 pb-20 reveal-up reveal-delay-2">
        <div className="grid lg:grid-cols-12 gap-8 mb-8">
          <div className="lg:col-span-5">
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-orange-500 mb-2">04 — Workshop moments</p>
            <h2 className="font-display font-black text-4xl lg:text-5xl tracking-tighter uppercase">Real garage.<br />Real care.</h2>
          </div>
          <p className="lg:col-span-6 lg:col-start-7 text-zinc-400 font-mono text-sm self-end">
            From diagnostics to final road test, every bike is handled with a consistent quality checklist and mechanic-level attention.
          </p>
        </div>
        <div className="grid md:grid-cols-3 gap-4">
          {[
            "https://images.unsplash.com/photo-1625047509168-a7026f36de04?auto=format&fit=crop&w=1200&q=80",
            "https://images.unsplash.com/photo-1558981806-ec527fa84c39?auto=format&fit=crop&w=1200&q=80",
            "https://images.unsplash.com/photo-1580310614729-ccd69652491d?auto=format&fit=crop&w=1200&q=80",
          ].map((img, idx) => (
            <div key={img} className="relative overflow-hidden border border-zinc-800 bg-zinc-900 group rounded-sm">
              <img
                src={img}
                alt={`MacJit workshop scene ${idx + 1}`}
                className="h-64 w-full object-cover group-hover:scale-105 transition-transform duration-500"
                onError={(e) => { e.currentTarget.src = "https://images.unsplash.com/photo-1609630875171-b1321377ee65?auto=format&fit=crop&w=1200&q=80"; }}
              />
              <div className="absolute inset-0 bg-gradient-to-t from-black/70 via-black/20 to-transparent" />
            </div>
          ))}
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-4 sm:gap-6 font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-600">
          <span className="flex items-center gap-2"><ShieldCheck className="w-3 h-3 text-orange-500" />Trained technicians only</span>
          <span className="flex items-center gap-2"><Wrench className="w-3 h-3 text-orange-500" />Genuine & OEM parts</span>
          <span className="flex items-center gap-2"><Zap className="w-3 h-3 text-orange-500" />Road-tested before delivery</span>
        </div>
      </section>

      {/* Footer */}
      <footer id="contact" className="border-t border-zinc-900 bg-black">
        <div className="max-w-7xl mx-auto px-6 py-12 grid md:grid-cols-4 gap-8">
          <div>
            <div className="flex items-center gap-3 mb-3">
              <MacJitLogo size={32} />
              <span className="font-display font-black text-xl tracking-tighter"><span className="text-white">MAC</span><span className="text-orange-500">JIT</span></span>
            </div>
            <p className="font-mono text-xs text-zinc-500">Mechanic Just In Time.<br />Async bike-garage operations.</p>
            <p className="font-mono text-[10px] text-zinc-600 mt-3">macjit.com</p>
          </div>
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-600 mb-3">Visit</p>
            <p className="font-mono text-xs text-zinc-300 flex items-start gap-2"><MapPin className="w-3 h-3 mt-1 text-orange-500" />Varthur,<br />Bangalore — 560087</p>
          </div>
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-600 mb-3">Contact</p>
            <a href="tel:+919353401156" className="font-mono text-xs text-zinc-300 flex items-center gap-2 hover:text-orange-500"><Phone className="w-3 h-3 text-orange-500" />+91 93534 01156</a>
            <a href="mailto:hello@macjit.com" className="font-mono text-xs text-zinc-300 flex items-center gap-2 hover:text-orange-500 mt-1"><Mail className="w-3 h-3 text-orange-500" />hello@macjit.com</a>
            <p className="font-mono text-xs text-zinc-500 mt-2">8:00 AM — 6:00 PM</p>
          </div>
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-600 mb-3">Quick links</p>
            <a href="#services" className="block font-mono text-xs text-zinc-400 hover:text-orange-500">Services</a>
            <a href="#how" className="block font-mono text-xs text-zinc-400 hover:text-orange-500 mt-1">How it works</a>
            <a href="#enquiry" className="block font-mono text-xs text-zinc-400 hover:text-orange-500 mt-1">Send enquiry</a>
            <button
              type="button"
              data-testid="footer-terminal-link"
              onClick={goStaff}
              className="block font-mono text-xs text-zinc-400 hover:text-orange-500 mt-1 text-left"
            >
              Terminal
            </button>
          </div>
        </div>
        <div className="border-t border-zinc-900 py-4 flex flex-wrap items-center justify-between gap-2 max-w-7xl mx-auto px-6">
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-zinc-600">© 2026 MacJit · macjit.com · All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}

function ServiceChatbot({ open, setOpen }) {
  const nav = useNavigate();
  const chatScrollRef = useRef(null);
  const [busy, setBusy] = useState(false);
  const [input, setInput] = useState("");
  const [stage, setStage] = useState("problem");
  const [pendingEditField, setPendingEditField] = useState("");
  const [messages, setMessages] = useState([INITIAL_TORQUE_MESSAGE]);
  const [details, setDetails] = useState({
    customer_name: "",
    customer_phone: "",
    plate_number: "",
    car_model: "",
    problem: "",
    service_type: "",
    known_service: false,
    preferred_slot: "",
    diagnosis_notes: {
      mechanic_feedback: "",
      duration: "",
      self_test: "",
    },
  });

  const resetChat = useCallback(() => {
    setBusy(false);
    setInput("");
    setStage("problem");
    setMessages([INITIAL_TORQUE_MESSAGE]);
    setDetails({
      customer_name: "",
      customer_phone: "",
      plate_number: "",
      car_model: "",
      problem: "",
      service_type: "",
      known_service: false,
      preferred_slot: "",
      diagnosis_notes: {
        mechanic_feedback: "",
        duration: "",
        self_test: "",
      },
    });
    setPendingEditField("");
  }, []);

  useEffect(() => {
    if (!open) return;
    const node = chatScrollRef.current;
    if (!node) return;
    node.scrollTop = node.scrollHeight;
  }, [messages, open, stage]);

  const formatPhone = (value) => {
    const trimmed = value.trim();
    if (!trimmed) return "";
    if (trimmed.startsWith("+")) return trimmed.replace(/[^\d+]/g, "");
    const digits = trimmed.replace(/\D/g, "");
    if (!digits) return "";
    if (digits.startsWith("91") && digits.length > 10) return `+${digits.slice(0, 12)}`;
    return `+91${digits.slice(0, 10)}`;
  };

  const isGreeting = useCallback((text) => {
    const normalized = (text || "").toLowerCase().trim();
    if (!normalized) return false;
    const greetingWords = ["hi", "hello", "hey", "hii", "good morning", "good afternoon", "good evening", "namaste"];
    return greetingWords.some((word) => normalized === word || normalized.startsWith(`${word} `));
  }, []);

  const askingBikeNumber = useCallback((text) => {
    const normalized = (text || "").toLowerCase();
    return /bike number|vehicle number|plate number|registration number|rc number|number plate/.test(normalized);
  }, []);

  const normalizePlate = (value) => value.toUpperCase().replace(/[\s-]+/g, "");

  const isValidIndianBikeNumber = useCallback((plate) => {
    const normalized = normalizePlate(plate);
    const standardPattern = /^[A-Z]{2}\d{1,2}[A-Z]{1,3}\d{4}$/;
    const bhPattern = /^\d{2}BH\d{4}[A-Z]{1,2}$/;
    return standardPattern.test(normalized) || bhPattern.test(normalized);
  }, []);

  const formatPlateForDisplay = (plate) => {
    const normalized = normalizePlate(plate);
    const bhMatch = normalized.match(/^(\d{2})(BH)(\d{4})([A-Z]{1,2})$/);
    if (bhMatch) return `${bhMatch[1]} ${bhMatch[2]} ${bhMatch[3]} ${bhMatch[4]}`;
    const standardMatch = normalized.match(/^([A-Z]{2})(\d{1,2})([A-Z]{1,3})(\d{4})$/);
    if (standardMatch) return `${standardMatch[1]}-${standardMatch[2]}-${standardMatch[3]}-${standardMatch[4]}`;
    return normalized;
  };

  const detectService = useCallback((text) => {
    const p = (text || "").toLowerCase();
    if (p.includes("oil") || p.includes("filter")) return "oil-change";
    if (p.includes("brake")) return "brake";
    if (p.includes("chain") || p.includes("sprocket")) return "chain-sprocket";
    if (p.includes("engine") || p.includes("noise") || p.includes("start")) return "engine";
    if (p.includes("full") || p.includes("complete") || p.includes("general service") || p.includes("service")) return "general";
    if (p.includes("wheel") || p.includes("align") || p.includes("balance")) return "alignment";
    return "";
  }, []);

  const detectEditField = useCallback((text) => {
    const normalized = (text || "").toLowerCase();
    const wantsUpdate = /wrong|update|change|correct|edit|mistake|typo/.test(normalized);
    if (!wantsUpdate) return "";
    if (/bike number|vehicle number|plate|registration|rc/.test(normalized)) return "plate_number";
    if (/phone|mobile|contact/.test(normalized)) return "customer_phone";
    if (/name/.test(normalized)) return "customer_name";
    if (/model|bike model/.test(normalized)) return "car_model";
    if (/issue|problem|noise|complaint/.test(normalized)) return "problem";
    return "";
  }, []);

  const promptForField = (field) => {
    if (field === "plate_number") return "No problem. Please send the correct bike number (example: KA-05-MN-2024).";
    if (field === "customer_phone") return "Sure, please send the correct phone number.";
    if (field === "customer_name") return "Sure, please send the correct name.";
    if (field === "car_model") return "Sure, please send the correct bike model.";
    if (field === "problem") return "Got it. Please tell me the correct issue in detail.";
    return "Tell me what you want to update.";
  };

  const nextSlots = useCallback(() => {
    const base = new Date();
    const slots = [];
    for (let day = 0; day < 3; day += 1) {
      [10, 12, 14, 16].forEach((hour) => {
        const d = new Date(base);
        d.setDate(base.getDate() + day);
        d.setHours(hour, 0, 0, 0);
        if (d > base) slots.push(d);
      });
    }
    return slots.slice(0, 5);
  }, []);

  const push = (from, text) => setMessages((items) => [...items, { from, text }]);

  const submitBooking = async (slotIso) => {
    setBusy(true);
    try {
      const payload = {
        customer_name: details.customer_name,
        customer_phone: details.customer_phone,
        plate_number: details.plate_number,
        problem: `${details.problem}\nMechanic feedback: ${details.diagnosis_notes.mechanic_feedback || "not shared"}\nDuration: ${details.diagnosis_notes.duration || "not shared"}\nSelf test: ${details.diagnosis_notes.self_test || "not shared"}`,
        service_type: details.service_type || "diagnostic-check",
        known_service: true,
        preferred_slot: slotIso,
        car_make: "Bike",
        car_model: details.car_model || "Bike",
      };
      const r = await api.post("/public/bookings", payload);
      push("bot", `Booking confirmed for ${r.data.booking.plate_number}. Drop your bike on or before ${new Date(r.data.booking.drop_deadline_at).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}.`);
      push("bot", "You can track it now from the bike tracker.");
      setStage("done");
      toast.success("Booking confirmed");
    } catch (err) {
      toast.error(err.response?.data?.detail || "Could not book this slot");
    } finally {
      setBusy(false);
    }
  };

  const handleSend = async (e) => {
    e?.preventDefault();
    const text = input.trim();
    if (!text || busy) return;
    setInput("");
    push("user", text);

    if (pendingEditField) {
      if (pendingEditField === "plate_number") {
        if (!isValidIndianBikeNumber(text)) {
          push("bot", "That still looks incorrect. Please send a valid bike number like KA-05-MN-2024 or 21 BH 1234 AA.");
          return;
        }
        setDetails((d) => ({ ...d, plate_number: formatPlateForDisplay(text) }));
      } else if (pendingEditField === "customer_phone") {
        const phone = formatPhone(text);
        if (!phone || phone.length < 10) {
          push("bot", "Please send a valid phone number with country code or 10 digits.");
          return;
        }
        setDetails((d) => ({ ...d, customer_phone: phone }));
      } else {
        setDetails((d) => ({ ...d, [pendingEditField]: text }));
      }
      setPendingEditField("");
      push("bot", "Done, I have updated it. Continue from where we stopped.");
      return;
    }

    const fieldToEdit = detectEditField(text);
    if (fieldToEdit) {
      setPendingEditField(fieldToEdit);
      push("bot", promptForField(fieldToEdit));
      return;
    }

    try {
      const historyForAi = [...messages, { from: "user", text }];
      const ai = await api.post("/public/torque-chat", {
        message: text,
        history: historyForAi,
        stage,
        details,
      });
      const payload = ai.data || {};
      const updates = payload.field_updates || {};

      setDetails((d) => {
        const next = { ...d };
        if (updates.customer_name) next.customer_name = String(updates.customer_name).trim();
        if (updates.customer_phone) next.customer_phone = formatPhone(String(updates.customer_phone));
        if (updates.plate_number) {
          const rawPlate = String(updates.plate_number);
          next.plate_number = isValidIndianBikeNumber(rawPlate) ? formatPlateForDisplay(rawPlate) : d.plate_number;
        }
        if (updates.car_model) next.car_model = String(updates.car_model).trim();
        if (updates.problem) next.problem = String(updates.problem).trim();
        if (updates.service_type) next.service_type = String(updates.service_type).trim();
        if (next.problem && !next.service_type) next.service_type = detectService(next.problem) || "diagnostic-check";
        if (next.service_type) next.known_service = true;
        return next;
      });

      push("bot", payload.reply || "Tell me a bit more and I will guide you.");
      const nextStage = payload.next_stage || stage;
      setStage(nextStage);
    } catch (err) {
      push("bot", "I could not process that now. Please repeat in short, I will help.");
    }
  };

  const slotOptions = nextSlots();

  return (
    <>
      <button
        type="button"
        onClick={() => {
          if (stage === "done") resetChat();
          setOpen(true);
        }}
        data-testid="macjit-chatbot-open"
        className="fixed bottom-5 right-5 z-40 bg-orange-500 hover:bg-orange-400 text-black shadow-2xl border-b-4 border-orange-700 active:translate-y-1 active:border-b-0 px-4 py-3 flex items-center gap-2.5"
      >
        <Wrench className="w-4 h-4" />
        <span className="font-display font-black uppercase tracking-[0.18em] text-xs">Ask Torque</span>
      </button>

      {open && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-end sm:items-center justify-center p-3" data-testid="macjit-chatbot">
          <div className="w-full max-w-xl bg-zinc-950 border border-orange-500/40 shadow-2xl h-[min(88vh,680px)] flex flex-col rounded-sm">
            <div className="sticky top-0 bg-zinc-950 border-b border-zinc-800 p-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-orange-500 text-black grid place-items-center">
                  <Wrench className="w-5 h-5" />
                </div>
                <div>
                  <p className="font-display font-black uppercase tracking-tight text-white">Torque</p>
                  <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-zinc-500">Problem reader / Slot booker</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={resetChat}
                  className="px-2.5 py-1 border border-zinc-800 text-[10px] font-mono uppercase tracking-wider text-zinc-300 hover:text-orange-500 hover:border-orange-500/40"
                >
                  New chat
                </button>
                <button onClick={() => setOpen(false)} className="w-9 h-9 border border-zinc-800 grid place-items-center text-zinc-400 hover:text-orange-500">
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div ref={chatScrollRef} className="p-4 flex-1 min-h-0 overflow-y-auto space-y-3 bg-black">
              {messages.map((m, idx) => (
                <div key={idx} className={`flex ${m.from === "user" ? "justify-end" : "justify-start"}`}>
                  <div className={`max-w-[85%] px-4 py-3 text-sm leading-relaxed ${m.from === "user" ? "bg-orange-500 text-black" : "bg-zinc-900 text-zinc-100 border border-zinc-800"}`}>
                    <p className="font-mono whitespace-pre-wrap break-words">{m.text}</p>
                  </div>
                </div>
              ))}
              {stage === "slot" && (
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-2">
                  {slotOptions.map((slot) => (
                    <button
                      type="button"
                      key={slot.toISOString()}
                      disabled={busy}
                      onClick={() => submitBooking(slot.toISOString())}
                      className="border border-orange-500/50 bg-orange-500/10 hover:bg-orange-500 hover:text-black text-orange-300 px-3 py-2 text-left"
                    >
                      <span className="block font-display font-black text-sm">{slot.toLocaleDateString([], { weekday: "short" })}</span>
                      <span className="block font-mono text-[10px] uppercase tracking-widest">{slot.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                    </button>
                  ))}
                </div>
              )}
              {stage === "done" && details.known_service && (
                <button
                  onClick={() => nav(`/track?plate=${encodeURIComponent(details.plate_number)}`)}
                  className="w-full bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest px-5 py-3"
                >
                  Track bike now
                </button>
              )}
            </div>
            <form onSubmit={handleSend} className="border-t border-zinc-800 p-3 flex gap-2 bg-zinc-950 shrink-0">
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                disabled={busy}
                placeholder="Type your reply..."
                className="flex-1 bg-black border border-zinc-800 px-3 py-3 font-mono text-sm text-white focus:border-orange-500 outline-none disabled:opacity-50"
              />
              <button disabled={busy} className="bg-orange-500 hover:bg-orange-400 text-black font-display font-black uppercase tracking-widest px-5 disabled:opacity-50">
                Send
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  );
}

function EnquiryForm() {
  const [form, setForm] = useState({ name: "", phone: "", email: "", car_make: "", car_model: "", service_interest: "", message: "" });
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const formatPhone = (value) => {
    const trimmed = value.trim();
    if (!trimmed) return "";
    if (trimmed.startsWith("+")) return trimmed.replace(/[^\d+]/g, "");
    const digits = trimmed.replace(/\D/g, "");
    if (!digits) return "";
    if (digits.startsWith("91") && digits.length > 10) return `+${digits.slice(0, 12)}`;
    return `+91${digits.slice(0, 10)}`;
  };
  const upd = (k, v) => setForm((f) => ({ ...f, [k]: k === "phone" ? formatPhone(v) : v }));

  const submit = async (e) => {
    e.preventDefault();
    if (!form.name || !form.phone) return toast.error("Name and phone are required");
    setBusy(true);
    try {
      await api.post("/enquiries", form);
      toast.success("Enquiry sent — we'll get back to you shortly.");
      setDone(true);
      setForm({ name: "", phone: "", email: "", car_make: "", car_model: "", service_interest: "", message: "" });
    } catch (err) {
      toast.error(err.response?.data?.detail || "Failed to send enquiry");
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return (
      <div data-testid="enquiry-success" className="border border-orange-500/40 bg-orange-500/5 p-10 text-center">
        <Sparkles className="w-8 h-8 text-orange-500 mx-auto" />
        <p className="font-display font-black text-3xl uppercase tracking-tighter mt-4">Thanks, {/* */}we'll call you back!</p>
        <p className="font-mono text-xs text-zinc-400 mt-3">Our team will reach out on the number you provided within working hours.</p>
        <button onClick={() => setDone(false)} className="mt-6 font-mono text-[11px] uppercase tracking-widest text-orange-500 hover:text-orange-400">Send another</button>
      </div>
    );
  }

  return (
    <form onSubmit={submit} data-testid="enquiry-form" className="border border-zinc-800 bg-zinc-900/40 p-6 lg:p-8 grid grid-cols-1 sm:grid-cols-2 gap-3">
      <input data-testid="enq-name" required placeholder="Your name *" value={form.name} onChange={(e) => upd("name", e.target.value)} className="bg-zinc-950 border border-zinc-800 px-3 py-3 font-mono text-sm focus:border-orange-500 outline-none" />
      <input data-testid="enq-phone" required placeholder="Phone *" value={form.phone} onChange={(e) => upd("phone", e.target.value)} className="bg-zinc-950 border border-zinc-800 px-3 py-3 font-mono text-sm focus:border-orange-500 outline-none" />
      <input data-testid="enq-email" type="email" placeholder="Email" value={form.email} onChange={(e) => upd("email", e.target.value)} className="bg-zinc-950 border border-zinc-800 px-3 py-3 font-mono text-sm focus:border-orange-500 outline-none sm:col-span-2" />
      <input data-testid="enq-make" placeholder="Bike make (e.g. Royal Enfield)" value={form.car_make} onChange={(e) => upd("car_make", e.target.value)} className="bg-zinc-950 border border-zinc-800 px-3 py-3 font-mono text-sm focus:border-orange-500 outline-none" />
      <input data-testid="enq-model" placeholder="Model (e.g. Meteor 350)" value={form.car_model} onChange={(e) => upd("car_model", e.target.value)} className="bg-zinc-950 border border-zinc-800 px-3 py-3 font-mono text-sm focus:border-orange-500 outline-none" />
      <select data-testid="enq-service" value={form.service_interest} onChange={(e) => upd("service_interest", e.target.value)} className="bg-zinc-950 border border-zinc-800 px-3 py-3 font-mono text-sm focus:border-orange-500 outline-none sm:col-span-2 text-zinc-300">
        <option value="">Service of interest...</option>
        <option value="oil-change">Oil & Filter Change</option>
        <option value="general">General Service</option>
        <option value="chain-sprocket">Chain & Sprocket Service</option>
        <option value="alignment">Wheel Truing & Balancing</option>
        <option value="brake">Brake Service</option>
        <option value="full-service">Full Service</option>
        <option value="engine">Engine Repair / Diagnostics</option>
        <option value="other">Other</option>
      </select>
      <textarea data-testid="enq-message" placeholder="Anything else we should know?" value={form.message} onChange={(e) => upd("message", e.target.value)} rows={3} className="bg-zinc-950 border border-zinc-800 px-3 py-3 font-mono text-sm focus:border-orange-500 outline-none sm:col-span-2 resize-none" />
      <button type="submit" disabled={busy} data-testid="enq-submit" className="sm:col-span-2 bg-orange-500 hover:bg-orange-400 disabled:opacity-50 text-black font-display font-black uppercase tracking-widest py-3 transition-colors flex items-center justify-center gap-2">
        {busy ? "Sending…" : <><Send className="w-4 h-4" /> Send enquiry</>}
      </button>
    </form>
  );
}
