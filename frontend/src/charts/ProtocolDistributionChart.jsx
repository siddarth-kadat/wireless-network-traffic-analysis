import React from 'react';
import PlotlyChart from '../components/common/PlotlyChart';

export default function ProtocolDistributionChart({ height = 240 }) {
  const protocols = [
    { label: '802.11 Mgmt/Deauth', pct: 42, color: '#00BC98' },
    { label: 'TCP Streams', pct: 31, color: '#000000' },
    { label: 'UDP Broadcasts', pct: 18, color: '#424348' },
    { label: 'ARP Requests', pct: 6, color: '#FF6A2A' },
    { label: 'ICMP Control', pct: 3, color: '#D92D20' },
  ];

  const traces = [
    {
      labels: protocols.map((p) => p.label),
      values: protocols.map((p) => p.pct),
      type: 'pie',
      hole: 0.65,
      marker: {
        colors: protocols.map((p) => p.color),
        line: { color: '#ffffff', width: 2 },
      },
      textinfo: 'none',
      hoverinfo: 'label+percent',
    },
  ];

  const layout = {
    height: 180,
    margin: { t: 5, r: 5, b: 5, l: 5 },
    showlegend: false,
    annotations: [
      {
        font: { size: 14, color: '#000000', family: 'Inter, sans-serif', weight: 'bold' },
        showarrow: false,
        text: '100%<br><span style="font-size:10px;color:#424348;font-weight:600">DECODED</span>',
        x: 0.5,
        y: 0.5,
      },
    ],
  };

  return (
    <div className="bg-white border border-border rounded-md p-6 space-y-3 flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-secondary" />
              <h4 className="text-base font-extrabold text-secondary tracking-tight">
                Protocol Distribution
              </h4>
            </div>
            <p className="text-xs text-muted font-normal mt-0.5">
              L2 Management frames vs Encapsulated Transport payload
            </p>
          </div>
          <span className="px-2.5 py-1 rounded-full bg-primary/10 text-primary border border-primary/20 text-xs font-bold">
            Scapy E1 Dissector
          </span>
        </div>

        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 items-center gap-4">
          {/* Donut Plot */}
          <div className="flex justify-center">
            <PlotlyChart data={traces} layout={layout} style={{ width: '100%', height: '180px' }} />
          </div>

          {/* Right Clean Legend */}
          <div className="space-y-2 text-xs">
            {protocols.map((p) => (
              <div key={p.label} className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 truncate">
                  <span className="w-2.5 h-2.5 rounded-xs flex-shrink-0" style={{ backgroundColor: p.color }} />
                  <span className="text-xs text-muted truncate font-medium">{p.label}</span>
                </div>
                <span className="text-xs font-bold text-secondary">{p.pct}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom Diagnostics Strip */}
      <div className="pt-3 border-t border-border flex items-center justify-between text-xs text-muted">
        <span>Beacon Interval: <strong className="text-secondary">102.4ms</strong></span>
        <span>FCS Valid: <strong className="text-primary font-bold">99.88%</strong></span>
      </div>
    </div>
  );
}
