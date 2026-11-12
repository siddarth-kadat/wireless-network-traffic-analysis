import React from 'react';
import createPlotlyComponent from 'react-plotly.js/factory';
import Plotly from 'plotly.js-dist-min';

const Plot = createPlotlyComponent(Plotly);

/**
 * Reusable SOC Plotly Chart Wrapper.
 * Injects dark cybersecurity theme styling, responsive auto-resizing,
 * and high-contrast accessibility.
 */
export default function PlotlyChart({
  data = [],
  layout = {},
  config = {},
  style = { width: '100%', height: '320px' },
  className = '',
}) {
  // Default dark theme styling conforming to SOC guidelines
  const defaultLayout = {
    autosize: true,
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    font: {
      family: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      color: '#94A3B8',
      size: 11,
    },
    margin: { t: 30, r: 20, b: 40, l: 50, pad: 4 },
    xaxis: {
      gridcolor: 'rgba(148, 163, 184, 0.08)',
      zerolinecolor: 'rgba(148, 163, 184, 0.15)',
      tickfont: { color: '#64748B', size: 10 },
      showline: false,
    },
    yaxis: {
      gridcolor: 'rgba(148, 163, 184, 0.08)',
      zerolinecolor: 'rgba(148, 163, 184, 0.15)',
      tickfont: { color: '#64748B', size: 10 },
      showline: false,
    },
    legend: {
      font: { color: '#94A3B8', size: 10 },
      orientation: 'h',
      y: -0.2,
      x: 0,
      bgcolor: 'transparent',
    },
    hoverlabel: {
      bgcolor: '#0F172A',
      bordercolor: '#00E5FF',
      font: { color: '#F8FAFC', family: 'monospace', size: 12 },
    },
    ...layout,
  };

  const defaultConfig = {
    responsive: true,
    displayModeBar: false,
    displaylogo: false,
    ...config,
  };

  return (
    <div className={`plotly-chart-container ${className}`} style={{ width: '100%', minHeight: '200px' }}>
      <Plot
        data={data}
        layout={defaultLayout}
        config={defaultConfig}
        style={style}
        useResizeHandler={true}
      />
    </div>
  );
}

