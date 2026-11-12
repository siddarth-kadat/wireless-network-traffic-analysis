import React from 'react';
import { AlertTriangle, Clock, ArrowRight } from 'lucide-react';
import StatusBadge from './StatusBadge';

export default function AlertCard({ alert, onInspect, onAcknowledge }) {
  if (!alert) return null;

  return (
    <div className="soc-card p-4 hover:border-slate-600 transition flex flex-col justify-between gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <StatusBadge value={alert.severity} type="severity" size="small" />
            <StatusBadge value={alert.status} type="status" size="small" />
            <span className="text-[11px] font-mono text-slate-500">{alert.alert_id}</span>
          </div>
          <h4 className="text-sm font-semibold text-white pt-1">{alert.alert_type}</h4>
          <p className="text-xs text-slate-400 line-clamp-2">{alert.message}</p>
        </div>
      </div>

      <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-500 font-mono">
        <div className="flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5 text-slate-400" />
          <span>{new Date(alert.generated_at).toLocaleTimeString()}</span>
        </div>
        <div className="flex items-center gap-2">
          {alert.status === 'NEW' && onAcknowledge && (
            <button
              onClick={() => onAcknowledge(alert.alert_id)}
              className="text-[11px] text-cyan-400 hover:text-cyan-300 font-sans px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-800"
            >
              Ack
            </button>
          )}
          {onInspect && (
            <button
              onClick={() => onInspect(alert)}
              className="flex items-center gap-1 text-[11px] text-slate-300 hover:text-white font-sans"
            >
              <span>Inspect</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
