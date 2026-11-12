import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  ShieldAlert,
  LayoutDashboard,
  UploadCloud,
  FileText,
  AlertTriangle,
  Search,
  Sliders,
  Layers,
  FileBarChart,
  Users,
  Settings,
  ChevronRight,
  ShieldCheck,
  RefreshCw,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import StatusBadge from './StatusBadge';

export default function Sidebar({ isOpen, onClose }) {
  const { user, isAdmin, switchRole } = useAuth();

  const navItems = [
    {
      group: 'SOC Operations',
      items: [
        { path: '/', label: 'Overview Dashboard', icon: LayoutDashboard },
        { path: '/upload', label: 'PCAP Ingestion Station', icon: UploadCloud },
        { path: '/traffic-logs', label: 'Traffic Log Explorer', icon: FileText },
      ],
    },
    {
      group: 'Threat Detection & Triage',
      items: [
        { path: '/alerts', label: 'Security Alerts Triage', icon: AlertTriangle },
        { path: '/detections', label: 'Detection Results', icon: Search },
        { path: '/rules', label: 'Deterministic Rules', icon: Sliders },
      ],
    },
    {
      group: 'System & Administration',
      items: [
        { path: '/batches', label: 'Processing Batches', icon: Layers },
        { path: '/reports', label: 'Executive Reports', icon: FileBarChart },
        ...(isAdmin
          ? [{ path: '/users', label: 'User Management', icon: Users }]
          : []),
        { path: '/settings', label: 'System & Telemetry', icon: Settings },
      ],
    },
  ];

  const handleToggleRole = () => {
    if (isAdmin) {
      switchRole('Security Analyst');
    } else {
      switchRole('Network Administrator');
    }
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={onClose}
        />
      )}

      <aside
        className={`fixed top-0 bottom-0 left-0 z-40 w-64 bg-slate-950 border-r border-slate-800/80 flex flex-col transition-transform duration-300 ease-in-out lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="text-sm font-bold tracking-wider uppercase text-white flex items-center gap-1.5">
                <span>W-NTAAS</span>
                <span className="text-[10px] px-1.5 py-0.2 bg-cyan-950 border border-cyan-800 text-cyan-400 rounded">
                  SOC
                </span>
              </div>
              <p className="text-[11px] text-slate-400">Wireless Traffic Analyzer</p>
            </div>
          </div>
        </div>

        {/* Navigation Sections */}
        <div className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
          {navItems.map((group) => (
            <div key={group.group} className="space-y-1">
              <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                {group.group}
              </div>
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    onClick={() => onClose && onClose()}
                    className={({ isActive }) =>
                      `flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all group ${
                        isActive
                          ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-semibold'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                      }`
                    }
                  >
                    <Icon className="w-4 h-4 transition-transform group-hover:scale-110" />
                    <span className="flex-1">{item.label}</span>
                    <ChevronRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </NavLink>
                );
              })}
            </div>
          ))}
        </div>

        {/* User Session Footer & Quick Switcher */}
        <div className="p-3 border-t border-slate-800/80 bg-slate-900/40">
          <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-full bg-cyan-900/50 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-bold text-xs">
                  {user?.username?.charAt(0).toUpperCase() || 'U'}
                </div>
                <div className="overflow-hidden">
                  <p className="text-xs font-semibold text-white truncate">{user?.full_name || user?.username}</p>
                  <StatusBadge value={user?.role} type="role" size="small" showDot={false} />
                </div>
              </div>
            </div>

            <button
              onClick={handleToggleRole}
              title="Quickly switch stakeholder perspective for demonstration"
              className="mt-1 w-full py-1.5 px-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] font-mono flex items-center justify-center gap-1.5 transition"
            >
              <RefreshCw className="w-3 h-3 text-cyan-400" />
              <span>Switch to {isAdmin ? 'Analyst' : 'Admin'}</span>
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}
