import React from 'react';
import PlotlyChart from '../components/common/PlotlyChart';

export default function SeverityChart({ counts = null, height = 260 }) {
  const severities = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const values = counts
    ? severities.map((s) => counts[s] || 0)
    : [1, 2, 4, 3, 2];

  const colors = [
    '#64748B', // INFO (Slate)
    '#38BDF8', // LOW (Sky)
    '#F59E0B', // MEDIUM (Amber)
    '#F97316', // HIGH (Orange)
    '#EF4444', // CRITICAL (Red)
  ];

  const traces = [
    {
      y: severities,
      x: values,
      type: 'bar',
      orientation: 'h',
      marker: {
        color: colors,
        line: { color: '#0F172A', width: 1 },
      },
      text: values.map((v) => (v > 0 ? String(v) : '')),
      textposition: 'outside',
      textfont: { color: '#F1F5F9', size: 10, family: 'monospace' },
      hovertemplate: '<b>%{y}</b>: %{x} alerts<extra></extra>',
    },
  ];

  const layout = {
    height,
    margin: { t: 20, r: 35, b: 25, l: 70 },
    xaxis: {
      showgrid: true,
      gridcolor: '#1E293B',
      tickfont: { color: '#94A3B8', size: 10 },
      dtick: 1,
    },
    yaxis: {
      tickfont: { color: '#F1F5F9', size: 10, weight: 'bold' },
    },
  };

  return (
    <div className="soc-card p-4 space-y-2">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
          Alert Severity Distribution
        </h4>
        <span className="text-[11px] font-mono text-rose-400">SOC Triage</span>
      </div>
      <PlotlyChart data={traces} layout={layout} />
    </div>
  );
}
