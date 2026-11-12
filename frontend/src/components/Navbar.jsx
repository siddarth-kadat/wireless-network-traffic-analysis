import React from 'react';
import { Menu, Bell, LogOut, Radio, Database, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { getBackendStatus } from '../services/api';
import { useNavigate, useLocation } from 'react-router-dom';

const ROUTE_TITLES = {
  '/': 'Overview Dashboard',
  '/upload': 'PCAP Ingestion Station',
  '/traffic-logs': 'Traffic Log Explorer',
  '/alerts': 'Security Alerts Triage',
  '/detections': 'Detection Results',
  '/rules': 'Deterministic Rules',
  '/batches': 'Processing Batches & Diagnostics',
  '/reports': 'Executive Reports',
  '/users': 'Stakeholder User Management',
  '/settings': 'System Settings & Telemetry',
};

export default function Navbar({ onMenuToggle }) {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const isLive = getBackendStatus();

  const currentTitle = ROUTE_TITLES[location.pathname] || 'Cybersecurity SOC Console';

  return (
    <header className="sticky top-0 z-30 h-16 bg-slate-950/90 backdrop-blur-md border-b border-slate-800 px-4 md:px-6 flex items-center justify-between">
      {/* Left: Mobile Toggle & Page Breadcrumb */}
      <div className="flex items-center gap-4">
        <button
          onClick={onMenuToggle}
          className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-900 lg:hidden"
          aria-label="Toggle navigation menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2">
          <span className="text-xs uppercase font-mono tracking-wider text-slate-500 hidden sm:inline">
            SOC Console &gt;
          </span>
          <h2 className="text-sm font-bold text-white tracking-tight">{currentTitle}</h2>
        </div>
      </div>

      {/* Right: Monitoring State, Backend Mode Pill, Notifications, User Menu */}
      <div className="flex items-center gap-3">
        {/* Backend API Connectivity Pill (Strictly accurate labeling) */}
        <div
          title={
            isLive
              ? 'FastAPI Backend is online & communicating'
              : 'Backend is offline or endpoints pending. Displaying verified local demonstration datasets.'
          }
          className={`flex items-center gap-2 px-2.5 py-1 rounded-full text-[11px] font-mono border ${
            isLive
              ? 'bg-emerald-950/50 text-emerald-400 border-emerald-800'
              : 'bg-amber-950/50 text-amber-300 border-amber-800'
          }`}
        >
          <span className={`w-2 h-2 rounded-full ${isLive ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
          <span className="font-semibold tracking-wide">
            {isLive ? 'BACKEND API: LIVE' : 'DEMO MODE: OFFLINE DATASET'}
          </span>
        </div>

        {/* Quick Alerts Bell */}
        <button
          onClick={() => navigate('/alerts')}
          className="p-2 rounded-lg text-slate-400 hover:text-amber-400 hover:bg-slate-900 relative transition"
          title="Inspect Security Alerts"
        >
          <Bell className="w-4 h-4" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-rose-500 rounded-full" />
        </button>

        {/* User Pill / Role */}
        <div className="hidden md:flex items-center gap-2 pl-2 border-l border-slate-800 text-xs">
          <div className="text-right">
            <p className="font-semibold text-white leading-none">{user?.full_name || user?.username}</p>
            <p className="text-[10px] text-cyan-400 font-mono mt-0.5">{user?.role}</p>
          </div>
        </div>

        {/* User Logout */}
        <button
          onClick={logout}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-rose-400 hover:bg-slate-900 border border-transparent hover:border-slate-800 transition"
          title="Sign out of SOC console"
        >
          <LogOut className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Sign Out</span>
        </button>
      </div>
    </header>
  );
}
