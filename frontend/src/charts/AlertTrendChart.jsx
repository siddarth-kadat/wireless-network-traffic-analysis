import React from 'react';

export default function AlertTrendChart() {
  const trends = [
    { label: '802.11 Deauth Flood (0x00C0 Reason 7)', hits: 142, max: 150, color: 'bg-error' },
    { label: 'SSID Beacon Spoofing / Randomization', hits: 89, max: 150, color: 'bg-primary' },
    { label: 'Evil Twin / Karma AP Rogue Probe', hits: 54, max: 150, color: 'bg-secondary' },
    { label: 'Unregistered Rogue BSSID on Corp Vlan', hits: 41, max: 150, color: 'bg-tertiary' },
    { label: 'Key Reinstallation / 4-Way Handshake Tampering', hits: 22, max: 150, color: 'bg-muted' },
  ];

  return (
    <div className="bg-white border border-border rounded-md p-6 space-y-4 flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-primary" />
              <h4 className="text-base font-extrabold text-secondary tracking-tight">
                Suspicious Activity Trends (E2 Engine)
              </h4>
            </div>
            <p className="text-xs text-muted font-normal mt-0.5">
              Signature heuristic hits aggregated from wireless frame dissector
            </p>
          </div>
          <span className="text-xs text-muted font-bold">
            Top 5 Vectors
          </span>
        </div>

        {/* 5 Horizontal Hit Meters */}
        <div className="mt-4 space-y-3">
          {trends.map((t) => (
            <div key={t.label} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-secondary font-medium truncate">{t.label}</span>
                <span className="text-secondary font-bold ml-2">{t.hits} hits</span>
              </div>
              <div className="w-full h-2 bg-subtle rounded-full overflow-hidden">
                <div
                  className={`h-full ${t.color} rounded-full transition-all duration-300`}
                  style={{ width: `${(t.hits / t.max) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Footer */}
      <div className="pt-3 border-t border-border flex items-center justify-between text-xs text-muted">
        <span>Engine Detection Interval: <strong className="text-secondary">500ms sliding window</strong></span>
        <span className="text-primary hover:text-primary-hover cursor-pointer font-bold">
          Configure Heuristic Weights &rarr;
        </span>
      </div>
    </div>
  );
}
