import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import Navbar from '../components/Navbar';

export default function SOCLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-white text-secondary flex flex-col font-sans">
      {/* Top Promotional / Telemetry Notice Banner */}
      <div className="bg-secondary text-white text-xs py-2 px-4 flex items-center justify-between sm:justify-center gap-3">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
          <span className="font-semibold tracking-wide">SYSTEM LIVE:</span>
          <span className="text-border">E1-E4 Engine Pipelines Active</span>
        </div>
        <div className="hidden md:flex items-center gap-2">
          <span className="text-border">|</span>
          <span className="text-white/80">Deterministic Rules Evaluator Online</span>
        </div>
      </div>

      {/* Top Navbar */}
      <Navbar onMenuToggle={() => setSidebarOpen((prev) => !prev)} />

      {/* Main Container */}
      <div className="flex flex-1 min-w-0">
        {/* Collapsible Responsive Sidebar */}
        <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

        {/* Content Area offset by sidebar width (w-56) */}
        <div className="flex-1 lg:pl-56 flex flex-col min-w-0 bg-[#FAFCFD]">
          <main className="flex-1 p-6 md:p-8 max-w-7xl w-full mx-auto animate-fadeIn">
            <Outlet />
          </main>

          <footer className="py-5 px-6 border-t border-border bg-white text-center text-xs text-muted">
            <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
              <span className="font-bold text-secondary tracking-tight">
                Wireless Network Traffic Analysis &amp; Alerting System
              </span>
              <span className="text-muted text-[13px]">
                Built for Network Administrators &amp; Security Analysts &bull; Backlinko Clean Growth System
              </span>
            </div>
          </footer>
        </div>
      </div>
    </div>
  );
}
