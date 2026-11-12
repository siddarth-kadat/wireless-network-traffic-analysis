import React from 'react';

/**
 * StatusBadge
 * High-clarity SOC badge for Severity, Processing Status, Role, and Boolean states.
 */
export default function StatusBadge({ value, type = 'status', size = 'normal', showDot = true }) {
  if (value === undefined || value === null) {
    return <span className="soc-badge soc-badge-neutral">N/A</span>;
  }

  const raw = String(value).toUpperCase().trim();
  let badgeClass = 'soc-badge-neutral';
  let dotClass = 'bg-slate-400';
  let label = String(value);

  if (type === 'severity' || ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(raw)) {
    switch (raw) {
      case 'CRITICAL':
        badgeClass = 'soc-badge-critical';
        dotClass = 'bg-rose-500 animate-pulse';
        label = 'CRITICAL';
        break;
      case 'HIGH':
        badgeClass = 'soc-badge-high';
        dotClass = 'bg-amber-500';
        label = 'HIGH';
        break;
      case 'MEDIUM':
        badgeClass = 'soc-badge-medium';
        dotClass = 'bg-yellow-500';
        label = 'MEDIUM';
        break;
      case 'LOW':
        badgeClass = 'soc-badge-low';
        dotClass = 'bg-sky-400';
        label = 'LOW';
        break;
      case 'INFO':
      default:
        badgeClass = 'soc-badge-info';
        dotClass = 'bg-slate-400';
        label = 'INFO';
        break;
    }
  } else if (type === 'role') {
    if (raw.includes('ADMIN')) {
      badgeClass = 'soc-badge-info';
      dotClass = 'bg-cyan-400';
      label = 'Administrator';
    } else {
      badgeClass = 'soc-badge-neutral';
      dotClass = 'bg-indigo-400';
      label = 'Security Analyst';
    }
  } else if (type === 'boolean' || typeof value === 'boolean') {
    if (value === true || raw === 'TRUE' || raw === 'ENABLED' || raw === 'ACTIVE') {
      badgeClass = 'soc-badge-success';
      dotClass = 'bg-emerald-400';
      label = 'Active';
    } else {
      badgeClass = 'soc-badge-neutral';
      dotClass = 'bg-slate-500';
      label = 'Disabled';
    }
  } else {
    // General processing and alert status
    switch (raw) {
      case 'NEW':
        badgeClass = 'soc-badge-critical';
        dotClass = 'bg-rose-500 animate-pulse';
        label = 'NEW';
        break;
      case 'ACKNOWLEDGED':
      case 'IN_PROGRESS':
      case 'PROCESSING':
        badgeClass = 'soc-badge-info';
        dotClass = 'bg-sky-400';
        label = raw.replace('_', ' ');
        break;
      case 'RESOLVED':
      case 'SUCCESS':
        badgeClass = 'soc-badge-success';
        dotClass = 'bg-emerald-400';
        label = raw;
        break;
      case 'PARTIAL_SUCCESS':
        badgeClass = 'soc-badge-medium';
        dotClass = 'bg-amber-400';
        label = 'PARTIAL SUCCESS';
        break;
      case 'FAILED':
      case 'ERROR':
        badgeClass = 'soc-badge-critical';
        dotClass = 'bg-rose-500';
        label = 'FAILED';
        break;
      default:
        badgeClass = 'soc-badge-neutral';
        dotClass = 'bg-slate-400';
        label = raw;
        break;
    }
  }

  const sizeClass = size === 'small' ? 'soc-badge-sm' : '';

  return (
    <span className={`soc-badge ${badgeClass} ${sizeClass}`}>
      {showDot && <span className={`soc-badge-dot ${dotClass}`} />}
      {label}
    </span>
  );
}
