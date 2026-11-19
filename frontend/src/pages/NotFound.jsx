import React from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, ArrowLeft, Home } from 'lucide-react';

export default function NotFound() {
  const navigate = useNavigate();

  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center p-6 text-center space-y-5">
      <div className="w-16 h-16 rounded-full bg-error/10 border border-error/20 flex items-center justify-center text-error">
        <AlertTriangle className="w-8 h-8" />
      </div>

      <div className="space-y-1.5">
        <h1 className="text-3xl font-extrabold text-secondary tracking-tight">404: Page Not Found</h1>
        <p className="text-sm text-muted max-w-md mx-auto">
          The requested console route is not reachable on this monitoring interface.
        </p>
      </div>

      <div className="flex items-center gap-3 pt-2">
        <button
          onClick={() => navigate(-1)}
          className="py-2 px-4 rounded-md bg-white hover:bg-subtle border border-border text-secondary text-xs font-bold flex items-center gap-2 transition"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Go Back</span>
        </button>
        <button
          onClick={() => navigate('/')}
          className="py-2 px-4 rounded-md bg-primary hover:bg-primary-hover text-white font-bold text-xs flex items-center gap-2 transition"
        >
          <Home className="w-4 h-4" />
          <span>Return to Dashboard</span>
        </button>
      </div>
    </div>
  );
}
