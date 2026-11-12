import React from 'react';

export default function MetricCard({
  title,
  value,
  subtext,
  icon: Icon,
  variant = 'default', // 'critical' | 'warning' | 'info' | 'success' | 'default'
  onClick,
}) {
  const borderVariants = {
    critical: 'border-l-4 border-l-rose-500',
    warning: 'border-l-4 border-l-amber-500',
    info: 'border-l-4 border-l-cyan-500',
    success: 'border-l-4 border-l-emerald-500',
    default: 'border-l-4 border-l-slate-600',
  };

  const iconVariants = {
    critical: 'text-rose-400 bg-rose-500/10',
    warning: 'text-amber-400 bg-amber-500/10',
    info: 'text-cyan-400 bg-cyan-500/10',
    success: 'text-emerald-400 bg-emerald-500/10',
    default: 'text-slate-300 bg-slate-800',
  };

  return (
    <div
      onClick={onClick}
      className={`soc-card flex items-center justify-between p-5 transition-all duration-200 hover:border-slate-600 ${
        borderVariants[variant] || borderVariants.default
      } ${onClick ? 'cursor-pointer hover:bg-slate-800/40' : ''}`}
    >
      <div className="space-y-1">
        <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</p>
        <p className="text-2xl font-bold tracking-tight text-white font-mono">{value}</p>
        {subtext && <p className="text-xs text-slate-400">{subtext}</p>}
      </div>
      {Icon && (
        <div className={`p-3 rounded-lg flex items-center justify-center ${iconVariants[variant] || iconVariants.default}`}>
          <Icon className="w-6 h-6" />
        </div>
      )}
    </div>
  );
}

