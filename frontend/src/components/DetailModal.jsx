import React, { useEffect } from 'react';
import { X, Copy, Check } from 'lucide-react';

export default function DetailModal({
  isOpen,
  onClose,
  title = 'Entity Inspection',
  subtitle = '',
  badge = null,
  actions = null,
  children,
  rawJson = null,
}) {
  const [copied, setCopied] = React.useState(false);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleCopy = () => {
    if (!rawJson) return;
    navigator.clipboard.writeText(JSON.stringify(rawJson, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
      <div
        className="soc-card w-full max-w-3xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl border border-slate-700/80 animate-scaleUp"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 flex items-start justify-between gap-4 bg-slate-900/60">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-bold text-white tracking-tight">{title}</h2>
              {badge}
            </div>
            {subtitle && <p className="text-xs text-slate-400 font-mono">{subtitle}</p>}
          </div>
          <div className="flex items-center gap-2">
            {rawJson && (
              <button
                onClick={handleCopy}
                title="Copy raw JSON payload"
                className="p-1.5 rounded text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            )}
            <button
              onClick={onClose}
              className="p-1.5 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-sm text-slate-300">
          {children}

          {rawJson && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-semibold text-slate-400 uppercase tracking-wider">
                <span>Raw Entity Contract / JSON Payload</span>
                <span>{copied ? 'Copied!' : 'Click copy above'}</span>
              </div>
              <pre className="p-4 bg-slate-950/90 border border-slate-800 rounded-lg text-xs font-mono text-cyan-300 overflow-x-auto max-h-60">
                {JSON.stringify(rawJson, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        {actions && (
          <div className="p-4 border-t border-slate-800 bg-slate-900/40 flex items-center justify-end gap-3">
            {actions}
          </div>
        )}
      </div>
    </div>
  );
}

