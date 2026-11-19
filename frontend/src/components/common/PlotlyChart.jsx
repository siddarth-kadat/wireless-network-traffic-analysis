import React from 'react';
import createPlotlyComponent from 'react-plotly.js/factory';
import Plotly from 'plotly.js-dist-min';

const Plot = createPlotlyComponent(Plotly);

/**
 * Reusable Backlinko Clean Growth Plotly Chart Wrapper.
 * Injects clean, content-first typography, teal accents, and flat styling.
 */
export default function PlotlyChart({
  data = [],
  layout = {},
  config = {},
  style = { width: '100%', height: '280px' },
  className = '',
}) {
  const defaultLayout = {
    autosize: true,
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    font: {
      family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      color: '#424348',
      size: 12,
    },
    margin: { t: 25, r: 20, b: 35, l: 45, pad: 4 },
    xaxis: {
      gridcolor: '#EEF2F7',
      zerolinecolor: '#CED4DA',
      tickfont: { color: '#424348', size: 11 },
      showline: false,
    },
    yaxis: {
      gridcolor: '#EEF2F7',
      zerolinecolor: '#CED4DA',
      tickfont: { color: '#424348', size: 11 },
      showline: false,
    },
    legend: {
      font: { color: '#000000', size: 11 },
      orientation: 'h',
      y: -0.2,
      x: 0,
      bgcolor: 'transparent',
    },
    hoverlabel: {
      bgcolor: '#000000',
      bordercolor: '#00BC98',
      font: { color: '#FFFFFF', size: 12, family: 'Inter, sans-serif' },
    },
  };

  const defaultConfig = {
    displayModeBar: false,
    responsive: true,
  };

  const mergedLayout = {
    ...defaultLayout,
    ...layout,
    xaxis: { ...defaultLayout.xaxis, ...(layout.xaxis || {}) },
    yaxis: { ...defaultLayout.yaxis, ...(layout.yaxis || {}) },
    legend: { ...defaultLayout.legend, ...(layout.legend || {}) },
    hoverlabel: { ...defaultLayout.hoverlabel, ...(layout.hoverlabel || {}) },
  };

  return (
    <div className={`w-full ${className}`}>
      <Plot
        data={data}
        layout={mergedLayout}
        config={{ ...defaultConfig, ...config }}
        style={style}
        useResizeHandler
      />
    </div>
  );
}
