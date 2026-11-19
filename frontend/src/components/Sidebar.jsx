import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  UploadCloud,
  FileText,
  Layers,
  Search,
  AlertTriangle,
  Sliders,
  FileBarChart,
  Users,
  Settings,
  Radio,
  RefreshCw,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Sidebar({ isOpen, onClose }) {
  const { user, isAdmin, switchRole } = useAuth();

  const navItems = [
    {
      group: 'OVERVIEW',
      items: [
        { path: '/', label: 'Overview', icon: LayoutDashboard },
      ],
    },
    {
      group: 'NETWORK MONITORING',
      items: [
        { path: '/upload', label: 'PCAP Ingestion', icon: UploadCloud },
        { path: '/traffic-logs', label: 'Traffic Explorer', icon: FileText },
        { path: '/batches', label: 'Processing Batches', icon: Layers },
      ],
    },
    {
      group: 'THREAT DETECTION',
      items: [
        { path: '/detections', label: 'Detections', icon: Search },
        { path: '/alerts', label: 'Alerts Triage', icon: AlertTriangle, badge: '4' },
        { path: '/rules', label: 'Rules Engine', icon: Sliders },
      ],
    },
    {
      group: 'ADMINISTRATION',
      items: [
        { path: '/reports', label: 'Reports', icon: FileBarChart },
        ...(isAdmin
          ? [{ path: '/users', label: 'Users', icon: Users }]
          : []),
        { path: '/settings', label: 'Settings', icon: Settings },
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
          className="fixed inset-0 z-40 bg-secondary/30 backdrop-blur-xs lg:hidden"
          onClick={onClose}
        />
      )}

      <aside
        className={`fixed top-0 bottom-0 left-0 z-40 w-56 bg-white border-r border-border flex flex-col transition-transform duration-200 ease-in-out lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="p-4 border-b border-border">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-md bg-primary flex items-center justify-center text-white">
              <Radio className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-extrabold tracking-tight text-secondary">
                W-NTASSOC <span className="text-[10px] text-primary font-bold">v2.4</span>
              </div>
              <div className="text-[10px] text-muted font-medium">SOC Analytics Engine</div>
            </div>
          </div>

          {/* 4-Engine Mini Status Box */}
          <div className="mt-3 p-2 rounded-md bg-subtle border border-border">
            <div className="flex items-center justify-between text-[10px] font-bold text-muted uppercase tracking-wider mb-1">
              <span>Engines</span>
              <span className="text-primary">All Active</span>
            </div>
            <div className="grid grid-cols-4 gap-1 text-[9px] font-mono text-center">
              <span className="px-1 py-0.5 rounded bg-white border border-border text-primary font-bold" title="E1: Log Processing Engine">E1:OK</span>
              <span className="px-1 py-0.5 rounded bg-white border border-border text-primary font-bold" title="E2: Suspicious Pattern Detection">E2:ACT</span>
              <span className="px-1 py-0.5 rounded bg-white border border-border text-primary font-bold" title="E3: Log & Alert Storage">E3:SYNC</span>
              <span className="px-1 py-0.5 rounded bg-white border border-border text-tertiary font-bold" title="E4: Alert Generation">E4:RDY</span>
            </div>
          </div>
        </div>

        {/* Navigation Link Groups */}
        <nav className="flex-1 px-3 py-4 space-y-5 overflow-y-auto">
          {navItems.map((group) => (
            <div key={group.group}>
              <p className="px-3 text-[11px] font-bold text-secondary uppercase tracking-wider mb-1.5">
                {group.group}
              </p>
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  return (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      onClick={onClose}
                      className={({ isActive }) =>
                        `flex items-center justify-between px-3 py-2 rounded-md text-xs font-semibold transition ${
                          isActive
                            ? 'bg-subtle text-primary border-l-3 border-primary'
                            : 'text-muted hover:text-secondary hover:bg-subtle/60'
                        }`
                      }
                    >
                      <div className="flex items-center gap-2.5">
                        <Icon className="w-4 h-4 flex-shrink-0" />
                        <span>{item.label}</span>
                      </div>
                      {item.badge && (
                        <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-tertiary text-white">
                          {item.badge}
                        </span>
                      )}
                    </NavLink>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Role Switcher & Telemetry Box */}
        <div className="p-3 border-t border-border bg-white space-y-2">
          <div className="p-2 rounded-md bg-subtle border border-border text-[11px]">
            <div className="flex items-center justify-between mb-1">
              <span className="text-muted font-medium">Active Persona</span>
              <span className="font-bold text-secondary text-[10px] uppercase">
                {isAdmin ? 'Admin' : 'Analyst'}
              </span>
            </div>
            <p className="text-secondary font-bold truncate">{user?.full_name || 'Alex Rivera'}</p>
            <button
              onClick={handleToggleRole}
              className="mt-2 w-full flex items-center justify-center gap-1.5 py-1.5 px-2 bg-white hover:bg-subtle border border-border rounded-md text-[11px] font-semibold text-secondary transition"
            >
              <RefreshCw className="w-3 h-3 text-primary" />
              <span>Switch to {isAdmin ? 'Analyst' : 'Admin'}</span>
            </button>
          </div>

          <div className="flex items-center justify-between text-[10px] font-mono text-muted px-1">
            <span className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-primary" />
              API: 24ms
            </span>
            <span>SQLite: Sync</span>
          </div>
        </div>
      </aside>
    </>
  );
}
