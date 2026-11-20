import React, { useState, useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import Navbar from '../components/Navbar';

export default function SOCLayout() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return localStorage.getItem('netwatch_sidebar_collapsed') === 'true';
    } catch {
      return false;
    }
  });

  const toggleSidebarCollapse = () => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem('netwatch_sidebar_collapsed', String(next));
      } catch {
        // Ignore storage exceptions
      }
      return next;
    });
  };

  // Keyboard shortcut Ctrl+B / Cmd+B to toggle sidebar collapse
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
        e.preventDefault();
        toggleSidebarCollapse();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <div className="min-h-screen bg-[#FAFCFD] text-secondary flex flex-col font-sans">
      {/* Top Telemetry Notice Banner */}
      <div className="bg-secondary text-white text-xs py-1.5 px-4 flex items-center justify-between sm:justify-center gap-3 select-none">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
          <span className="font-semibold tracking-wide">System Status: Operational</span>
        </div>
        <div className="hidden md:flex items-center gap-2">
          <span className="text-border">|</span>
          <span className="text-white/80">Four-Engine Processing Pipeline Active</span>
        </div>
      </div>

      {/* Top Navbar */}
      <Navbar
        onMobileToggle={() => setMobileOpen((prev) => !prev)}
        onDesktopToggle={toggleSidebarCollapse}
        isSidebarCollapsed={sidebarCollapsed}
      />

      {/* Main Layout Container (Sidebar + Content as Direct Flex Siblings) */}
      <div className="flex flex-1 min-w-0 relative">
        {/* Collapsible Sidebar */}
        <Sidebar
          isOpen={mobileOpen}
          onClose={() => setMobileOpen(false)}
          isCollapsed={sidebarCollapsed}
          onToggleCollapse={toggleSidebarCollapse}
        />

        {/* Content Area (Automatically adjusts width without any overlap) */}
        <div className="flex-1 flex flex-col min-w-0 overflow-x-hidden">
          <main className="flex-1 p-4 md:p-6 lg:p-8 max-w-7xl w-full mx-auto animate-fadeIn">
            <Outlet />
          </main>

          <footer className="py-5 px-6 border-t border-border bg-white text-center text-xs text-muted mt-auto">
            <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
              <span className="font-bold text-secondary tracking-tight">
                NetWatch &mdash; Wireless Network Traffic Analysis and Alerting System
              </span>
              <span className="text-muted text-[13px]">
                Built for Network Administrators &amp; Security Analysts &bull; SOC Enterprise Architecture
              </span>
            </div>
          </footer>
        </div>
      </div>
    </div>
  );
}
