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
  ChevronLeft,
  ChevronRight,
  Cpu,
  X,
  Shield,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Sidebar({
  isOpen,
  onClose,
  isCollapsed = false,
  onToggleCollapse,
}) {
  const { user, isAdmin, switchRole } = useAuth();

  const navItems = [
    {
      group: 'Overview',
      items: [
        {
          path: '/',
          label: 'Dashboard',
          description: 'Network Security Monitoring Dashboard',
          icon: LayoutDashboard,
        },
      ],
    },
    {
      group: 'Network Monitoring',
      items: [
        {
          path: '/upload',
          label: 'PCAP File Upload',
          description: 'Ingest and parse PCAP/PCAPNG capture files',
          icon: UploadCloud,
        },
        {
          path: '/traffic-logs',
          label: 'Traffic Explorer',
          description: 'Network Traffic Explorer and extracted records',
          icon: FileText,
        },
        {
          path: '/batches',
          label: 'Processing Batches',
          description: 'Processing History and capture audit log',
          icon: Layers,
        },
      ],
    },
    {
      group: 'Threat Detection',
      items: [
        {
          path: '/detections',
          label: 'Detection Results',
          description: 'Evaluations and vector breach outcomes',
          icon: Search,
        },
        {
          path: '/alerts',
          label: 'Alert Management',
          description: 'Incident triage and response queue',
          icon: AlertTriangle,
          badge: '4',
        },
        {
          path: '/rules',
          label: 'Detection Rules',
          description: 'Deterministic detection policies and signatures',
          icon: Sliders,
        },
      ],
    },
    {
      group: 'System',
      items: [
        {
          path: '/engine-status',
          label: 'Engine Status',
          description: 'Four-Engine Processing Pipeline health',
          icon: Cpu,
        },
        {
          path: '/system-logs',
          label: 'System Logs',
          description: 'System error audits and compliance reports',
          icon: FileBarChart,
        },
        {
          path: '/settings',
          label: 'Settings',
          description: 'System configuration and engine settings',
          icon: Settings,
        },
        ...(isAdmin
          ? [
              {
                path: '/users',
                label: 'User Management',
                description: 'User access control and accounts',
                icon: Users,
              },
            ]
          : []),
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
      {/* Mobile Drawer Backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-secondary/40 backdrop-blur-xs lg:hidden transition-opacity"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`bg-white border-r border-border flex flex-col transition-all duration-300 ease-in-out select-none
          /* Mobile styles: slide-in fixed drawer */
          fixed inset-y-0 left-0 z-50 w-64 shadow-2xl lg:shadow-none
          lg:static lg:h-screen lg:sticky lg:top-0
          ${isOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
          /* Desktop collapsed vs expanded width */
          ${isCollapsed ? 'lg:w-20' : 'lg:w-64'}
        `}
      >
        {/* Brand Header */}
        <div className="p-4 border-b border-border flex items-center justify-between gap-3 min-h-[72px]">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="w-9 h-9 rounded-md bg-primary flex-shrink-0 flex items-center justify-center text-white shadow-sm">
              <Radio className="w-5 h-5" />
            </div>

            {/* Title & Subtitle (hidden when collapsed on desktop) */}
            <div className={`overflow-hidden transition-opacity duration-200 ${isCollapsed ? 'lg:hidden' : 'block'}`}>
              <h2 className="text-base font-extrabold tracking-tight text-secondary leading-tight truncate">
                NetWatch
              </h2>
              <p className="text-[11px] text-muted font-medium truncate leading-none mt-0.5">
                Wireless Network Security Monitoring
              </p>
            </div>
          </div>

          {/* Mobile Close Button */}
          <button
            onClick={onClose}
            className="lg:hidden p-1.5 text-muted hover:text-secondary rounded-md hover:bg-subtle transition"
            aria-label="Close menu"
          >
            <X className="w-5 h-5" />
          </button>

          {/* Desktop Collapse Toggle Button (in header) */}
          <button
            onClick={onToggleCollapse}
            className={`hidden lg:flex p-1.5 rounded-md text-muted hover:text-secondary hover:bg-subtle border border-border/60 transition ${
              isCollapsed ? 'mx-auto' : ''
            }`}
            title={isCollapsed ? 'Expand sidebar (Ctrl+B)' : 'Collapse sidebar (Ctrl+B)'}
            aria-label="Toggle sidebar collapse"
          >
            {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* 4-Engine Mini Status Indicator */}
        <div className="p-3 border-b border-border bg-subtle/50">
          {!isCollapsed ? (
            <div className="p-2.5 rounded-md bg-white border border-border shadow-2xs">
              <div className="flex items-center justify-between text-[10px] font-bold text-muted uppercase tracking-wider mb-1.5">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                  <span>Pipeline</span>
                </span>
                <span className="text-primary font-bold">4/4 Online</span>
              </div>
              <div className="grid grid-cols-4 gap-1 text-[9px] font-mono text-center">
                <span
                  className="px-1 py-0.5 rounded bg-subtle border border-border text-primary font-bold hover:bg-primary/10 transition cursor-help"
                  title="E1 - Packet Processing: Reads and extracts information from captured network packets"
                >
                  E1:OK
                </span>
                <span
                  className="px-1 py-0.5 rounded bg-subtle border border-border text-secondary font-bold hover:bg-secondary/10 transition cursor-help"
                  title="E2 - Suspicious Activity Detection: Evaluates network traffic against configured detection rules"
                >
                  E2:ACT
                </span>
                <span
                  className="px-1 py-0.5 rounded bg-subtle border border-border text-muted font-bold hover:bg-muted/10 transition cursor-help"
                  title="E3 - Log and Alert Storage: Stores traffic records, detection results and alerts"
                >
                  E3:SYNC
                </span>
                <span
                  className="px-1 py-0.5 rounded bg-subtle border border-border text-tertiary font-bold hover:bg-tertiary/10 transition cursor-help"
                  title="E4 - Alert Generation: Generates structured alerts from detected suspicious patterns"
                >
                  E4:RDY
                </span>
              </div>
            </div>
          ) : (
            <div
              className="flex justify-center cursor-help py-1"
              title="Four-Engine Processing Pipeline: E1-OK, E2-ACT, E3-SYNC, E4-RDY (All Online)"
            >
              <div className="flex flex-col items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                <span className="text-[9px] font-mono font-bold text-primary">4/4</span>
              </div>
            </div>
          )}
        </div>

        {/* Navigation Link Groups */}
        <nav className="flex-1 px-3 py-4 space-y-5 overflow-y-auto overflow-x-hidden">
          {navItems.map((group) => (
            <div key={group.group}>
              {/* Group Title (hidden when collapsed) */}
              <p
                className={`px-3 text-[11px] font-bold text-muted uppercase tracking-wider mb-1.5 transition-opacity duration-200 ${
                  isCollapsed ? 'lg:hidden' : 'block'
                }`}
              >
                {group.group}
              </p>

              <div className="space-y-1">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  return (
                    <div key={item.path} className="relative group">
                      <NavLink
                        to={item.path}
                        onClick={onClose}
                        className={({ isActive }) =>
                          `flex items-center gap-3 px-3 py-2 rounded-md text-xs font-semibold transition ${
                            isCollapsed ? 'lg:justify-center lg:px-2' : 'justify-between'
                          } ${
                            isActive
                              ? 'bg-primary/10 text-primary border-l-4 border-primary font-bold'
                              : 'text-muted hover:text-secondary hover:bg-subtle'
                          }`
                        }
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <Icon className="w-4 h-4 flex-shrink-0" />
                          <span className={`truncate ${isCollapsed ? 'lg:hidden' : 'block'}`}>
                            {item.label}
                          </span>
                        </div>

                        {/* Badge (when expanded) */}
                        {item.badge && !isCollapsed && (
                          <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-tertiary text-white flex-shrink-0">
                            {item.badge}
                          </span>
                        )}
                      </NavLink>

                      {/* Tooltip on hover (visible only in collapsed desktop mode) */}
                      {isCollapsed && (
                        <div className="hidden lg:group-hover:flex absolute left-full top-1/2 -translate-y-1/2 ml-3 px-3 py-2 rounded-md bg-secondary text-white text-xs font-semibold whitespace-nowrap shadow-xl z-50 pointer-events-none items-center gap-2 border border-border/30">
                          <span>{item.label}</span>
                          {item.badge && (
                            <span className="px-1.5 py-0.5 rounded-full bg-tertiary text-white text-[10px] font-bold">
                              {item.badge}
                            </span>
                          )}
                          <span className="text-[10px] text-white/70 border-l border-white/20 pl-2 font-normal">
                            {item.description}
                          </span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Persona Switcher & Desktop Expand Button at Bottom */}
        <div className="p-3 border-t border-border bg-white space-y-2">
          {!isCollapsed ? (
            <div className="p-2.5 rounded-md bg-subtle border border-border text-[11px] space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-muted font-medium">Logged in Persona:</span>
                <span className="font-bold text-secondary text-[10px] uppercase px-1.5 py-0.5 rounded bg-white border border-border">
                  {isAdmin ? 'Admin' : 'Analyst'}
                </span>
              </div>
              <p className="text-secondary font-bold truncate">{user?.full_name || 'Alex Rivera'}</p>
              <button
                onClick={handleToggleRole}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 px-2 bg-white hover:bg-subtle border border-border rounded-md text-[11px] font-semibold text-secondary transition shadow-2xs"
                title="Switch test role between Administrator and Analyst"
              >
                <RefreshCw className="w-3 h-3 text-primary" />
                <span>Switch to {isAdmin ? 'Analyst' : 'Admin'}</span>
              </button>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-2">
              <button
                onClick={handleToggleRole}
                className="w-8 h-8 rounded-full bg-subtle hover:bg-primary/10 border border-border flex items-center justify-center text-secondary transition"
                title={`Active persona: ${isAdmin ? 'Admin' : 'Analyst'}. Click to switch.`}
              >
                <RefreshCw className="w-3.5 h-3.5 text-primary" />
              </button>
              <button
                onClick={onToggleCollapse}
                className="hidden lg:flex w-8 h-8 rounded-md bg-subtle hover:bg-white border border-border items-center justify-center text-muted hover:text-secondary transition"
                title="Expand sidebar"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* System Telemetry Micro-Pill */}
          {!isCollapsed && (
            <div className="flex items-center justify-between text-[10px] font-mono text-muted px-1 pt-1">
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                API: Nominal
              </span>
              <span>SQLite E3: WAL</span>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}
