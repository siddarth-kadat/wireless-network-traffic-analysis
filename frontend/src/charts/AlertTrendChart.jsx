import React from 'react';
import PlotlyChart from '../components/common/PlotlyChart';

export default function AlertTrendChart({ height = 260 }) {
  const times = ['08:00', '09:00', '10:00', '11:00', '12:00', '13:00', '14:00'];
  const critical = [0, 0, 1, 3, 0, 1, 0];
  const high = [1, 0, 2, 4, 1, 0, 1];
  const medium = [0, 2, 1, 1, 3, 2, 1];

  const traces = [
    {
      x: times,
      y: critical,
      name: 'Critical',
      type: 'bar',
      marker: { color: '#EF4444' },
    },
    {
      x: times,
      y: high,
      name: 'High',
      type: 'bar',
      marker: { color: '#F97316' },
    },
    {
      x: times,
      y: medium,
      name: 'Medium',
      type: 'bar',
      marker: { color: '#F59E0B' },
    },
  ];

  const layout = {
    height,
    barmode: 'stack',
    margin: { t: 25, r: 25, b: 35, l: 35 },
    xaxis: {
      showgrid: false,
      tickfont: { color: '#94A3B8', size: 10 },
    },
    yaxis: {
      showgrid: true,
      gridcolor: '#1E293B',
      tickfont: { color: '#94A3B8', size: 10 },
      dtick: 1,
    },
    legend: {
      orientation: 'h',
      x: 0,
      y: 1.15,
      font: { color: '#94A3B8', size: 10 },
    },
  };

  return (
    <div className="soc-card p-4 space-y-2">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
          Alert Frequency Trend (Hourly)
        </h4>
        <span className="text-[11px] font-mono text-slate-500">Incident Volume</span>
      </div>
      <PlotlyChart data={traces} layout={layout} />
    </div>
  );
}
