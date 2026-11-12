import React from 'react';
import PlotlyChart from '../components/common/PlotlyChart';

export default function ProtocolDistributionChart({ counts = null, height = 300 }) {
  const labels = counts ? Object.keys(counts) : [
    '802.11 Deauth',
    '802.11 Beacon',
    '802.11 Probe',
    'TCP / TLS',
    'UDP / DNS',
    'ARP / Broadcast',
  ];
  const values = counts ? Object.values(counts) : [450, 890, 620, 1150, 780, 210];

  const colors = [
    '#EF4444', // Red (Deauth)
    '#00E5FF', // Cyan (Beacon)
    '#38BDF8', // Sky (Probe)
    '#6366F1', // Indigo (TCP)
    '#10B981', // Emerald (UDP)
    '#F59E0B', // Amber (ARP)
  ];

  const traces = [
    {
      labels,
      values,
      type: 'pie',
      hole: 0.58,
      marker: {
        colors,
        line: { color: '#0F172A', width: 2 },
      },
      textinfo: 'percent',
      textposition: 'inside',
      hoverinfo: 'label+value+percent',
      hovertemplate: '<b>%{label}</b><br>Packets: %{value}<br>Ratio: %{percent}<extra></extra>',
    },
  ];

  const layout = {
    height,
    margin: { t: 20, r: 20, b: 20, l: 20 },
    showlegend: true,
    legend: {
      orientation: 'v',
      x: 1.02,
      y: 0.5,
      font: { color: '#94A3B8', size: 10 },
    },
    annotations: [
      {
        font: { size: 12, color: '#94A3B8', family: 'monospace' },
        showarrow: false,
        text: 'PROTOCOLS',
        x: 0.5,
        y: 0.5,
      },
    ],
  };

  return (
    <div className="soc-card p-4 space-y-2">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
          Wireless & Transport Protocols
        </h4>
        <span className="text-[11px] font-mono text-slate-500">Distribution</span>
      </div>
      <PlotlyChart data={traces} layout={layout} />
    </div>
  );
}
