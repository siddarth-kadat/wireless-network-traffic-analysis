import React from 'react';

/**
 * StatusBadge
 * Backlinko Clean Growth badge for Severity, Processing Status, Role, and Boolean states.
 */
export default function StatusBadge({ value, type = 'status', size = 'normal', showDot = true }) {
  if (value === undefined || value === null) {
    return <span className="soc-badge soc-badge-neutral">N/A</span>;
  }

  const raw = String(value).toUpperCase().trim();
  let badgeClass = 'soc-badge-neutral';
  let dotClass = 'bg-muted';
  let label = String(value);

  if (type === 'severity' || ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(raw)) {
    switch (raw) {
      case 'CRITICAL':
        badgeClass = 'soc-badge-critical';
        dotClass = 'bg-error animate-pulse';
        label = 'CRITICAL';
        break;
      case 'HIGH':
        badgeClass = 'soc-badge-high';
        dotClass = 'bg-tertiary';
        label = 'HIGH';
        break;
      case 'MEDIUM':
        badgeClass = 'soc-badge-medium';
        dotClass = 'bg-amber-600';
        label = 'MEDIUM';
        break;
      case 'LOW':
        badgeClass = 'soc-badge-low';
        dotClass = 'bg-primary';
        label = 'LOW';
        break;
      case 'INFO':
      default:
        badgeClass = 'soc-badge-info';
        dotClass = 'bg-muted';
        label = 'INFO';
        break;
    }
  } else if (type === 'role') {
    if (raw.includes('ADMIN')) {
      badgeClass = 'soc-badge-low';
      dotClass = 'bg-primary';
      label = 'Network Administrator';
    } else {
      badgeClass = 'soc-badge-info';
      dotClass = 'bg-muted';
      label = 'Security Analyst';
    }
  } else if (type === 'boolean' || typeof value === 'boolean') {
    if (value === true || raw === 'TRUE' || raw === 'ENABLED' || raw === 'ACTIVE') {
      badgeClass = 'soc-badge-success';
      dotClass = 'bg-primary';
      label = 'Active';
    } else {
      badgeClass = 'soc-badge-neutral';
      dotClass = 'bg-muted';
      label = 'Disabled';
    }
  } else {
    // General processing and alert status
    switch (raw) {
      case 'NEW':
        badgeClass = 'soc-badge-critical';
        dotClass = 'bg-error animate-pulse';
        label = 'NEW';
        break;
      case 'TRIAGED':
      case 'INVESTIGATING':
      case 'ACKNOWLEDGED':
      case 'IN_PROGRESS':
        badgeClass = 'soc-badge-low';
        dotClass = 'bg-primary';
        label = raw.replace('_', ' ');
        break;
      case 'ESCALATED':
        badgeClass = 'soc-badge-high';
        dotClass = 'bg-tertiary';
        label = 'ESCALATED';
        break;
      case 'RESOLVED':
      case 'SUCCESS':
      case 'COMPLETED':
        badgeClass = 'soc-badge-success';
        dotClass = 'bg-primary';
        label = 'COMPLETED';
        break;
      case 'FAILED':
      case 'ERROR':
        badgeClass = 'soc-badge-critical';
        dotClass = 'bg-error';
        label = 'FAILED';
        break;
      case 'PROCESSING':
      case 'PENDING':
        badgeClass = 'soc-badge-medium';
        dotClass = 'bg-amber-500 animate-spin';
        label = raw;
        break;
      default:
        badgeClass = 'soc-badge-neutral';
        dotClass = 'bg-muted';
        label = raw;
        break;
    }
  }

  const isSmall = size === 'small' || size === 'sm';

  return (
    <span
      className={`soc-badge ${badgeClass} ${
        isSmall ? 'soc-badge-sm' : ''
      } transition-colors duration-150 inline-flex items-center gap-1.5`}
    >
      {showDot && <span className={`soc-badge-dot ${dotClass}`} />}
      <span>{label}</span>
    </span>
  );
}
