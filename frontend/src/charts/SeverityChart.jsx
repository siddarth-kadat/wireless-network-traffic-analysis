import React from 'react';

export default function SeverityChart({ counts = null }) {
  const critical = counts?.CRITICAL ?? 4;
  const high = counts?.HIGH ?? 11;
  const medium = counts?.MEDIUM ?? 15;
  const low = counts?.LOW ?? 12;
  const total = critical + high + medium + low;

  const pCrit = ((critical / total) * 100).toFixed(1);
  const pHigh = ((high / total) * 100).toFixed(1);
  const pMed = ((medium / total) * 100).toFixed(1);
  const pLow = ((low / total) * 100).toFixed(1);

  return (
    <div className="bg-white border border-border rounded-md p-6 space-y-4 flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-error" />
              <h4 className="text-base font-extrabold text-secondary tracking-tight">
                Alert Severity Distribution
              </h4>
            </div>
            <p className="text-xs text-muted font-normal mt-0.5">
              Classified by E4 Alert Generation rule thresholds
            </p>
          </div>
          <span className="text-xs text-muted font-bold">
            Total {total} alerts
          </span>
        </div>

        {/* Multi-segment Horizontal Progress Bar */}
        <div className="mt-4 w-full h-3 rounded-full overflow-hidden flex bg-subtle">
          <div style={{ width: `${pCrit}%` }} className="bg-error" title={`Critical: ${critical}`} />
          <div style={{ width: `${pHigh}%` }} className="bg-tertiary" title={`High: ${high}`} />
          <div style={{ width: `${pMed}%` }} className="bg-amber-500" title={`Medium: ${medium}`} />
          <div style={{ width: `${pLow}%` }} className="bg-primary" title={`Low: ${low}`} />
        </div>

        {/* 4 Colored Metric Blocks */}
        <div className="mt-4 grid grid-cols-4 gap-3 text-center">
          <div className="p-3 rounded-md bg-error/5 border border-error/20">
            <span className="text-[10px] uppercase font-bold text-error block">CRITICAL</span>
            <span className="text-xl font-extrabold text-error">{critical}</span>
          </div>
          <div className="p-3 rounded-md bg-tertiary/5 border border-tertiary/20">
            <span className="text-[10px] uppercase font-bold text-tertiary block">HIGH</span>
            <span className="text-xl font-extrabold text-tertiary">{high}</span>
          </div>
          <div className="p-3 rounded-md bg-amber-500/5 border border-amber-500/20">
            <span className="text-[10px] uppercase font-bold text-amber-700 block">MEDIUM</span>
            <span className="text-xl font-extrabold text-amber-700">{medium}</span>
          </div>
          <div className="p-3 rounded-md bg-primary/5 border border-primary/20">
            <span className="text-[10px] uppercase font-bold text-primary block">LOW</span>
            <span className="text-xl font-extrabold text-primary">{low}</span>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="pt-3 border-t border-border flex items-center justify-between text-xs text-muted">
        <span>Active Escaped Incidents: <strong className="text-secondary">0</strong></span>
        <span>Auto-Triage Rate: <strong className="text-primary font-bold">92%</strong></span>
      </div>
    </div>
  );
}
