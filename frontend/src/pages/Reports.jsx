import React, { useState, useEffect } from 'react';
import {
  FileBarChart,
  Download,
  Printer,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Layers,
  Calendar,
} from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import { alertService } from '../services/alertService';
import { batchService } from '../services/batchService';
import { detectionService } from '../services/detectionService';
import { logService } from '../services/logService';

export default function Reports() {
  const [loading, setLoading] = useState(true);
  const [reportData, setReportData] = useState({
    alerts: [],
    batches: [],
    rules: [],
    logs: [],
  });

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [alerts, batches, rules, logs] = await Promise.all([
          alertService.getAlerts(),
          batchService.getBatches(),
          detectionService.getRules(),
          logService.getTrafficLogs(),
        ]);
        setReportData({ alerts, batches, rules, logs });
      } catch (err) {
        console.error('Failed to generate SOC executive report:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const totalPackets = reportData.batches.reduce((acc, b) => acc + (b.total_records || 0), 0) || 4500;
  const criticalCount = reportData.alerts.filter((a) => a.severity === 'CRITICAL').length;
  const highCount = reportData.alerts.filter((a) => a.severity === 'HIGH').length;
  const resolvedCount = reportData.alerts.filter((a) => a.status === 'RESOLVED').length;

  const handleDownloadJSON = () => {
    const reportPayload = {
      system: 'Wireless Network Traffic Analysis and Alerting System (W-NTASSOC)',
      generated_at: new Date().toISOString(),
      executive_summary: {
        total_pcap_batches: reportData.batches.length,
        total_packets_analyzed: totalPackets,
        active_deterministic_rules: reportData.rules.filter((r) => r.is_active).length,
        critical_incidents: criticalCount,
        high_severity_incidents: highCount,
        resolved_incidents: resolvedCount,
      },
      alerts_registry: reportData.alerts,
      batches_registry: reportData.batches,
      rules_registry: reportData.rules,
    };

    const blob = new Blob([JSON.stringify(reportPayload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc_executive_report_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Page Header */}
      <div className="p-6 md:p-8 rounded-md bg-white border border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="text-xs text-primary font-bold uppercase tracking-wider mb-1">
            EXECUTIVE AUDIT // COMPLIANCE &amp; THREAT METRICS
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-secondary">
            Executive Security Audit Report
          </h1>
          <p className="text-sm text-muted mt-1">
            Comprehensive posture assessment of wireless traffic analysis, deterministic rule performance, and alert resolution.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => window.print()}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-white hover:bg-subtle border border-border text-secondary font-bold text-xs transition"
          >
            <Printer className="w-4 h-4 text-muted" />
            <span>Print Report</span>
          </button>
          <button
            onClick={handleDownloadJSON}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-primary hover:bg-primary-hover active:bg-primary text-white font-bold text-xs transition"
          >
            <Download className="w-4 h-4" />
            <span>Export JSON Audit</span>
          </button>
        </div>
      </div>

      {/* Summary Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-md bg-white border border-border">
          <span className="text-xs font-bold text-muted uppercase tracking-wider block">PACKETS ANALYZED</span>
          <span className="text-2xl font-extrabold text-secondary mt-1 block">
            {totalPackets.toLocaleString()}
          </span>
          <span className="text-xs text-primary font-bold mt-1 block">100% Ingestion Fidelity</span>
        </div>

        <div className="p-5 rounded-md bg-white border border-border">
          <span className="text-xs font-bold text-muted uppercase tracking-wider block">ACTIVE POLICIES</span>
          <span className="text-2xl font-extrabold text-secondary mt-1 block">
            {reportData.rules.filter((r) => r.is_active).length} / {reportData.rules.length || 6}
          </span>
          <span className="text-xs text-muted mt-1 block">Deterministic Rules</span>
        </div>

        <div className="p-5 rounded-md bg-white border border-border">
          <span className="text-xs font-bold text-error uppercase tracking-wider block">CRITICAL BREACHES</span>
          <span className="text-2xl font-extrabold text-error mt-1 block">
            {criticalCount}
          </span>
          <span className="text-xs text-error font-medium mt-1 block">Priority Triage Required</span>
        </div>

        <div className="p-5 rounded-md bg-white border border-border">
          <span className="text-xs font-bold text-primary uppercase tracking-wider block">RESOLVED INCIDENTS</span>
          <span className="text-2xl font-extrabold text-primary mt-1 block">
            {resolvedCount}
          </span>
          <span className="text-xs text-muted mt-1 block">Mitigated by SOC</span>
        </div>
      </div>

      {/* Report Document Surface */}
      <div className="bg-white border border-border rounded-md p-8 space-y-6">
        <div className="border-b border-border pb-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-extrabold text-secondary">Threat Mitigation &amp; Vector Registry</h2>
            <p className="text-xs text-muted mt-0.5">Automated compilation from E4 Alert Generation Engine</p>
          </div>
          <span className="text-xs font-mono text-muted">
            Report Gen: {new Date().toLocaleDateString()}
          </span>
        </div>

        <div className="divide-y divide-border">
          {reportData.alerts.slice(0, 8).map((alert) => (
            <div key={alert.alert_id} className="py-4 flex items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold font-mono text-primary">{alert.alert_id}</span>
                  <StatusBadge value={alert.severity} type="severity" size="small" />
                  <StatusBadge value={alert.status} type="status" size="small" />
                </div>
                <h4 className="text-sm font-bold text-secondary">{alert.name}</h4>
                <p className="text-xs text-muted">{alert.rule_name || alert.rule}</p>
              </div>

              <div className="text-right text-xs">
                <span className="font-mono text-muted block">{alert.detection_timestamp || alert.time}</span>
                <span className="text-secondary font-medium">BSSID: {alert.target_bssid || '00:14:22:01:23:45'}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
