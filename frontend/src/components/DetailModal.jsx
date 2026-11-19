import React from 'react';
import { X, Copy, Check } from 'lucide-react';

export default function DetailModal({
  isOpen,
  onClose,
  title,
  subtitle,
  data,
  children,
}) {
  const [copied, setCopied] = React.useState(false);

  if (!isOpen) return null;

  const handleCopy = () => {
    if (!data) return;
    navigator.clipboard.writeText(
      typeof data === 'string' ? data : JSON.stringify(data, null, 2)
    );
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-secondary/40 backdrop-blur-xs animate-fadeIn">
      <div className="bg-white border border-border rounded-md shadow-card w-full max-w-2xl max-h-[85vh] flex flex-col overflow-hidden animate-scaleUp">
        {/* Header */}
        <div className="p-5 border-b border-border flex items-center justify-between gap-4 bg-subtle/40">
          <div>
            <h3 className="text-base font-extrabold text-secondary tracking-tight">
              {title || 'Entity Details'}
            </h3>
            {subtitle && (
              <p className="text-xs text-muted font-medium mt-0.5">{subtitle}</p>
            )}
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-muted hover:text-secondary hover:bg-subtle rounded-md transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-4 text-xs font-sans">
          {children}

          {data && (
            <div className="mt-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-secondary uppercase tracking-wider">
                  Raw Entity Payload (JSON)
                </span>
                <button
                  onClick={handleCopy}
                  className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-md border border-border bg-white hover:bg-subtle text-secondary transition"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-primary" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-muted" />
                      <span>Copy Payload</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="p-4 rounded-md bg-[#0F172A] border border-border text-emerald-400 font-mono text-xs overflow-x-auto leading-relaxed">
                {typeof data === 'string' ? data : JSON.stringify(data, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-border bg-subtle/40 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-white hover:bg-subtle border border-border text-secondary text-xs font-bold rounded-md transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
