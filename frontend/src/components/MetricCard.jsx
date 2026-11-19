import React from 'react';

export default function MetricCard({
  title,
  value,
  subtext,
  footnote,
  icon: Icon,
  variant = 'default', // 'critical' | 'warning' | 'info' | 'success' | 'default'
  onClick,
}) {
  const borderVariants = {
    critical: 'border-error/40 hover:border-error',
    warning: 'border-tertiary/40 hover:border-tertiary',
    info: 'border-border hover:border-muted',
    success: 'border-primary/40 hover:border-primary',
    default: 'border-border hover:border-muted',
  };

  const iconVariants = {
    critical: 'text-error bg-error/10',
    warning: 'text-tertiary bg-tertiary/10',
    info: 'text-primary bg-primary/10',
    success: 'text-primary bg-primary/10',
    default: 'text-muted bg-subtle',
  };

  const titleVariants = {
    critical: 'text-error',
    warning: 'text-tertiary',
    info: 'text-muted',
    success: 'text-primary',
    default: 'text-muted',
  };

  const valueVariants = {
    critical: 'text-error',
    warning: 'text-secondary',
    info: 'text-secondary',
    success: 'text-secondary',
    default: 'text-secondary',
  };

  return (
    <div
      onClick={onClick}
      className={`bg-white border rounded-md p-5 flex flex-col justify-between transition-all duration-150 ${
        borderVariants[variant] || borderVariants.default
      } ${onClick ? 'cursor-pointer hover:bg-subtle/30' : ''}`}
    >
      <div>
        <div className="flex items-center justify-between gap-2">
          <p className={`text-xs font-bold uppercase tracking-wider ${titleVariants[variant] || 'text-muted'}`}>
            {title}
          </p>
          {Icon && (
            <div className={`p-2 rounded-md ${iconVariants[variant] || iconVariants.default}`}>
              <Icon className="w-4 h-4" />
            </div>
          )}
        </div>

        <div className="mt-3">
          <span className={`text-3xl font-extrabold tracking-tight ${valueVariants[variant] || 'text-secondary'}`}>
            {value}
          </span>
        </div>

        {subtext && (
          <p className="mt-1 text-xs text-muted font-medium">
            {subtext}
          </p>
        )}
      </div>

      {footnote && (
        <div className="mt-4 pt-3 border-t border-border flex items-center justify-between text-[11px] text-muted">
          <span>{footnote}</span>
        </div>
      )}
    </div>
  );
}
