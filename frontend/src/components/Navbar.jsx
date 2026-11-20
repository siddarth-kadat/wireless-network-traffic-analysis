import React from 'react';
import {
  Search,
  UploadCloud,
  Bell,
  Radio,
  LogOut,
  PanelLeft,
  Menu,
  Activity,
  Shield,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { getBackendStatus } from '../services/api';
import { useNavigate } from 'react-router-dom';

export default function Navbar({
  onMobileToggle,
  onDesktopToggle,
  isSidebarCollapsed,
}) {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();
  const isLive = getBackendStatus();

  return (
    <header className="sticky top-0 z-30 h-16 bg-white border-b border-border px-4 md:px-6 flex items-center justify-between gap-4 select-none">
      {/* Left: Sidebar Toggle, Brand Icon & Telemetry Pill */}
      <div className="flex items-center gap-3">
        {/* Mobile Hamburger Button */}
        <button
          onClick={onMobileToggle}
          className="lg:hidden p-2 rounded-md hover:bg-subtle text-secondary border border-border"
          aria-label="Open navigation menu"
          title="Open menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        {/* Desktop Sidebar Toggle Button */}
        <button
          onClick={onDesktopToggle}
          className="hidden lg:flex p-2 rounded-md hover:bg-subtle text-secondary border border-border/80 transition"
          aria-label="Toggle sidebar width"
          title={isSidebarCollapsed ? 'Expand sidebar (Ctrl+B)' : 'Collapse sidebar (Ctrl+B)'}
        >
          <PanelLeft className="w-4 h-4 text-secondary" />
        </button>

        {/* Brand Home Link */}
        <div
          onClick={() => navigate('/')}
          className="flex items-center gap-2.5 cursor-pointer group"
          title="NetWatch - Network Security Monitoring Dashboard"
        >
          <div className="w-8 h-8 rounded-md bg-primary/10 border border-primary/30 flex items-center justify-center text-primary transition group-hover:bg-primary group-hover:text-white">
            <Radio className="w-4 h-4" />
          </div>
          <div className="leading-tight">
            <div className="flex items-center gap-1.5">
              <span className="text-base font-extrabold text-secondary tracking-tight">NetWatch</span>
              <span className="text-border">/</span>
              <span className="text-[11px] font-bold text-muted tracking-wider uppercase">Console</span>
            </div>
          </div>
        </div>

        {/* Live Pipeline Telemetry Pill */}
        <button
          onClick={() => navigate('/engine-status')}
          className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-subtle hover:bg-primary/10 border border-border hover:border-primary/30 text-secondary text-xs font-semibold transition"
          title="View Four-Engine Processing Pipeline Status"
        >
          <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
          <span>4/4 Engines Nominal</span>
        </button>
      </div>

      {/* Center: Command / Search Bar */}
      <div className="hidden md:flex items-center flex-1 max-w-md mx-2">
        <div className="relative w-full">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            placeholder="Search captures, IP addresses, detection rules..."
            className="w-full pl-10 pr-12 py-2 bg-white hover:bg-subtle/50 focus:bg-white border border-border rounded-md text-sm text-secondary placeholder-muted focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition font-sans"
          />
          <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded bg-subtle border border-border text-[11px] font-mono font-medium text-muted">
            Ctrl+K
          </kbd>
        </div>
      </div>

      {/* Right: Actions, Alerts, and Profile */}
      <div className="flex items-center gap-2.5 sm:gap-3">
        {/* Upload PCAP CTA */}
        <button
          onClick={() => navigate('/upload')}
          className="flex items-center gap-2 px-3.5 py-2 rounded-md bg-primary hover:bg-primary-hover active:bg-primary text-white text-xs sm:text-sm font-semibold transition shadow-2xs"
          title="Upload and process capture file"
        >
          <UploadCloud className="w-4 h-4" />
          <span className="hidden sm:inline">Upload PCAP</span>
        </button>

        {/* Alert Management Pill */}
        <button
          onClick={() => navigate('/alerts')}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-white hover:bg-subtle border border-border text-secondary text-xs font-bold transition shadow-2xs"
          title="Inspect Alert Management Queue"
        >
          <Bell className="w-4 h-4 text-tertiary" />
          <span className="text-secondary hidden xs:inline">4 Alerts</span>
        </button>

        {/* User Profile Summary */}
        <div className="flex items-center gap-2.5 pl-2.5 border-l border-border">
          <div
            className="w-8 h-8 rounded-full bg-secondary text-white flex items-center justify-center text-xs font-bold"
            title={`${user?.full_name || 'Alex Rivera'} (${isAdmin ? 'Network Administrator' : 'Security Analyst'})`}
          >
            {user?.username?.substring(0, 2).toUpperCase() || 'AR'}
          </div>
          <div className="hidden xl:block text-left leading-tight max-w-[130px]">
            <p className="text-xs font-bold text-secondary truncate">{user?.full_name || 'Alex Rivera'}</p>
            <p className="text-[11px] text-muted font-medium truncate">
              {isAdmin ? 'Network Administrator' : 'Security Analyst'}
            </p>
          </div>

          <button
            onClick={logout}
            className="p-1.5 text-muted hover:text-error hover:bg-subtle rounded-md transition"
            title="Log out"
            aria-label="Log out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
}
