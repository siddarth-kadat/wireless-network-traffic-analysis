import React from 'react';
import PlotlyChart from '../components/common/PlotlyChart';
import { getBackendStatus } from '../services/api';

export default function TrafficChart({ data = null, height = 300 }) {
  const isLive = getBackendStatus();

  // Baseline timeseries
  const timestamps = data?.timestamps || [
    '10:00:00', '10:05:00', '10:10:00', '10:15:00', '10:20:00',
    '10:25:00', '10:30:00', '10:35:00', '10:40:00', '10:45:00',
    '10:50:00', '10:55:00', '11:00:00'
  ];
  const packetRates = data?.packetRates || [120, 145, 132, 580, 890, 420, 180, 210, 340, 290, 195, 230, 210];
  const byteRates = data?.byteRates || [15, 18, 17, 72, 110, 52, 22, 26, 42, 36, 24, 28, 26];

  const traces = [
    {
      x: timestamps,
      y: packetRates,
      name: 'Packets / sec',
      type: 'scatter',
      mode: 'lines+markers',
      line: { color: '#00E5FF', width: 2, shape: 'spline' },
      fill: 'tozeroy',
      fillcolor: 'rgba(0, 229, 255, 0.08)',
      marker: { size: 5, color: '#00E5FF' },
    },
    {
      x: timestamps,
      y: byteRates,
      name: 'Throughput (KB/s)',
      yaxis: 'y2',
      type: 'scatter',
      mode: 'lines',
      line: { color: '#818CF8', width: 2, dash: 'dot', shape: 'spline' },
    },
  ];

  const layout = {
    height,
    margin: { t: 25, r: 45, b: 35, l: 45 },
    xaxis: {
      title: 'Time Window (UTC)',
      showgrid: true,
      gridcolor: '#1E293B',
      tickfont: { color: '#94A3B8', size: 10 },
      titlefont: { color: '#94A3B8', size: 11 },
    },
    yaxis: {
      title: 'Packets / Sec',
      showgrid: true,
      gridcolor: '#1E293B',
      tickfont: { color: '#00E5FF', size: 10 },
      titlefont: { color: '#00E5FF', size: 11 },
    },
    yaxis2: {
      title: 'KB / Sec',
      overlaying: 'y',
      side: 'right',
      showgrid: false,
      tickfont: { color: '#818CF8', size: 10 },
      titlefont: { color: '#818CF8', size: 11 },
    },
    legend: {
      orientation: 'h',
      x: 0,
      y: 1.15,
      font: { color: '#94A3B8', size: 11 },
    },
  };

  return (
    <div className="soc-card p-4 space-y-2">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
          Temporal Network Traffic Rate
        </h4>
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
          isLive ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800' : 'bg-slate-900 text-slate-400 border-slate-700'
        }`}>
          {isLive ? 'Live Stream' : 'Sample Telemetry'}
        </span>
      </div>
      <PlotlyChart data={traces} layout={layout} />
    </div>
  );
}
