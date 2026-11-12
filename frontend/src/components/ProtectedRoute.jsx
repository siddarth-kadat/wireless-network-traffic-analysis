import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldAlert } from 'lucide-react';

export default function ProtectedRoute({ children, requiredRole }) {
  const { user, loading, isAuthenticated } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center gap-3 text-slate-400">
        <span className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
        <p className="text-xs font-mono">Authenticating SOC Session...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRole && user?.role !== requiredRole) {
    return (
      <div className="p-8 max-w-2xl mx-auto my-12 soc-card text-center space-y-4 border-rose-500/30">
        <div className="w-12 h-12 mx-auto rounded-full bg-rose-500/10 flex items-center justify-center text-rose-400">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <h2 className="text-lg font-bold text-white">Access Denied: Restricted Stakeholder Area</h2>
        <p className="text-sm text-slate-400">
          This section requires <span className="text-cyan-400 font-semibold">{requiredRole}</span> privileges.
          Your current session is active as <span className="text-amber-400 font-semibold">{user?.role}</span>.
        </p>
        <p className="text-xs text-slate-500 font-mono">
          You can use the role switcher in the bottom-left sidebar to view this administrative page.
        </p>
      </div>
    );
  }

  return children;
}
