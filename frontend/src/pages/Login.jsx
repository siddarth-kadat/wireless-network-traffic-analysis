import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Lock, User, Radio, ArrowRight } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = location.state?.from?.pathname || '/';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);

    try {
      await login(username, password);
      navigate(from, { replace: true });
    } catch (err) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleQuickLogin = async (demoUsername, demoPassword) => {
    setUsername(demoUsername);
    setPassword(demoPassword);
    setError('');
    setIsSubmitting(true);
    try {
      await login(demoUsername, demoPassword);
      navigate(from, { replace: true });
    } catch (err) {
      setError(err.message || 'Quick login failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-white flex flex-col justify-center items-center p-6 relative overflow-hidden font-sans">
      <div className="w-full max-w-md space-y-6 z-10">
        {/* Brand Header */}
        <div className="text-center space-y-3">
          <div className="w-14 h-14 mx-auto rounded-md bg-primary flex items-center justify-center text-white">
            <Radio className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-secondary">
              NetWatch
            </h1>
            <p className="text-sm font-semibold text-primary mt-0.5">
              Wireless Network Security Monitoring
            </p>
            <p className="text-xs text-muted mt-1">
              Wireless Network Traffic Analysis and Alerting System
            </p>
          </div>
        </div>

        {/* Login Card */}
        <div className="bg-white p-8 space-y-6 border border-border rounded-md shadow-card">
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="p-3.5 rounded-md bg-error/10 border border-error/20 text-xs text-error font-medium">
                {error}
              </div>
            )}

            <div className="space-y-1.5">
              <label className="text-xs font-bold uppercase tracking-wider text-secondary">
                Stakeholder Username
              </label>
              <div className="relative">
                <User className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-muted" />
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin or analyst"
                  className="w-full pl-10 pr-3 py-2.5 bg-white border border-border rounded-md text-sm text-secondary placeholder-muted focus:outline-none focus:border-primary font-sans"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold uppercase tracking-wider text-secondary">
                Secure Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-muted" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="admin123 or analyst123"
                  className="w-full pl-10 pr-3 py-2.5 bg-white border border-border rounded-md text-sm text-secondary placeholder-muted focus:outline-none focus:border-primary font-sans"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-3 px-4 bg-primary hover:bg-primary-hover active:bg-primary text-white font-bold rounded-md text-sm flex items-center justify-center gap-2 transition"
            >
              <span>{isSubmitting ? 'Authenticating...' : 'Sign In to Console'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          {/* Quick Demo Login Selection */}
          <div className="pt-4 border-t border-border space-y-2.5">
            <span className="text-xs font-bold text-muted uppercase tracking-wider block text-center">
              One-Click Demo Authentication
            </span>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => handleQuickLogin('admin', 'admin123')}
                className="p-2.5 rounded-md bg-subtle hover:bg-subtle/80 border border-border text-left transition"
              >
                <div className="text-xs font-bold text-secondary">Network Administrator</div>
                <div className="text-[11px] text-muted font-mono">admin / admin123</div>
              </button>
              <button
                type="button"
                onClick={() => handleQuickLogin('analyst', 'analyst123')}
                className="p-2.5 rounded-md bg-subtle hover:bg-subtle/80 border border-border text-left transition"
              >
                <div className="text-xs font-bold text-secondary">Security Analyst</div>
                <div className="text-[11px] text-muted font-mono">analyst / analyst123</div>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
