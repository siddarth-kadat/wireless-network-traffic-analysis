import React from 'react';
import PlotlyChart from '../components/common/PlotlyChart';

export default function TrafficChart({ height = 240 }) {
  const timestamps = [
    '08:00 UTC', '10:00 UTC', '12:00 UTC', '14:00 (PEAK)', '16:00 UTC', '18:00 UTC', '20:00 UTC'
  ];

  // 5.0 GHz high-throughput band
  const band5GHz = [45, 52, 78, 124.6, 85, 62, 58];
  // 2.4 GHz legacy IoT band
  const band24GHz = [28, 32, 35, 58, 42, 36, 31];

  const traces = [
    {
      x: timestamps,
      y: band5GHz,
      name: '5.0 GHz (802.11ac/ax)',
      type: 'scatter',
      mode: 'lines',
      line: { color: '#00BC98', width: 2.5, shape: 'spline' },
      fill: 'tozeroy',
      fillcolor: 'rgba(0, 188, 152, 0.12)',
    },
    {
      x: timestamps,
      y: band24GHz,
      name: '2.4 GHz (legacy/IoT)',
      type: 'scatter',
      mode: 'lines',
      line: { color: '#424348', width: 2, dash: 'dot', shape: 'spline' },
      fill: 'tozeroy',
      fillcolor: 'rgba(66, 67, 72, 0.06)',
    },
  ];

  const layout = {
    height,
    margin: { t: 15, r: 20, b: 30, l: 35 },
    showlegend: false,
    xaxis: {
      showgrid: true,
      gridcolor: '#EEF2F7',
      tickfont: { color: '#424348', size: 10 },
    },
    yaxis: {
      showgrid: true,
      gridcolor: '#EEF2F7',
      tickfont: { color: '#424348', size: 10 },
      ticksuffix: 'k',
    },
  };

  return (
    <div className="bg-white border border-border rounded-md p-6 space-y-3 flex flex-col justify-between">
      <div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-primary" />
              <h4 className="text-base font-extrabold text-secondary tracking-tight">
                Network Traffic Over Time
              </h4>
            </div>
            <p className="text-xs text-muted font-normal mt-0.5">
              Live packet ingress distribution broken down by 2.4 GHz vs 5.0 GHz wireless spectrum
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="px-2.5 py-1 rounded-full bg-primary/10 text-primary border border-primary/20 font-bold">
              5.0 GHz (802.11ac)
            </span>
            <span className="px-2.5 py-1 rounded-full bg-subtle text-secondary border border-border font-medium">
              2.4 GHz (IoT)
            </span>
            <span className="px-2.5 py-1 rounded-full bg-secondary text-white font-bold">
              Peak: 124.6k pkt/s
            </span>
          </div>
        </div>

        <div className="mt-4">
          <PlotlyChart data={traces} layout={layout} style={{ width: '100%', height: `${height}px` }} />
        </div>
      </div>

      <div className="pt-3 border-t border-border flex items-center justify-between text-xs text-muted">
        <span>Channel Width: 20/40/80 MHz Adaptive</span>
        <span className="text-secondary font-bold">Throughput: 98.4 Mbps Avg</span>
      </div>
    </div>
  );
}
